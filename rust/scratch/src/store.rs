//! `ScratchStore` — SQLite-metadata + gzip-file-payload scratch store, port of
//! `utils/scratch_store.py`. See the crate docs for the contract.
//!
//! Concurrency: one `Mutex<Connection>` (Python uses
//! `check_same_thread=False` + GIL-serialized statements + busy_timeout). A
//! poisoned mutex is taken over (`into_inner`) — a panic elsewhere must not
//! permanently wedge the store; SQLite itself is the consistency boundary.
//!
//! Cross-compatibility: the DDL, WAL dance, busy_timeout, opaque-id format,
//! payload naming (`<id>.json.gz`), and column meanings are byte-compatible
//! with the Python store, so both implementations can operate the same
//! workspace `scratch.db` (verified by `examples/pycompat.rs`).

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use flate2::read::MultiGzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use nix::unistd::{geteuid, Gid, Uid};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::config::ScratchConfig;
use crate::projection::{apply_projection, compile_regex};

/// Stored as `content_type` (parity with the Python store).
pub const CONTENT_TYPE: &str = "application/json+gzip";
pub const SCHEMA_VERSION: i64 = 1;

/// Byte-identical DDL to the Python store (`_init_table`) — whichever side
/// creates a db first, the other must be able to use it untouched.
const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS scratch_entries (
    id              TEXT PRIMARY KEY,
    agent_id        TEXT NOT NULL,
    chat_id         TEXT,
    tool_id         TEXT NOT NULL,
    created_at      REAL NOT NULL,
    expires_at      REAL NOT NULL,
    content_type    TEXT NOT NULL,
    byte_count      INTEGER NOT NULL,
    sha256          TEXT NOT NULL,
    payload_path    TEXT NOT NULL,
    schema_version  INTEGER NOT NULL
)
"#;

pub type Result<T> = std::result::Result<T, ScratchError>;

#[derive(Debug)]
pub enum ScratchError {
    Io(std::io::Error),
    Db(rusqlite::Error),
    Json(serde_json::Error),
    Entropy(String),
}

impl fmt::Display for ScratchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScratchError::Io(e) => write!(f, "scratch io error: {e}"),
            ScratchError::Db(e) => write!(f, "scratch db error: {e}"),
            ScratchError::Json(e) => write!(f, "scratch json error: {e}"),
            ScratchError::Entropy(e) => write!(f, "scratch entropy error: {e}"),
        }
    }
}

impl std::error::Error for ScratchError {}

impl From<std::io::Error> for ScratchError {
    fn from(e: std::io::Error) -> Self {
        ScratchError::Io(e)
    }
}
impl From<rusqlite::Error> for ScratchError {
    fn from(e: rusqlite::Error) -> Self {
        ScratchError::Db(e)
    }
}
impl From<serde_json::Error> for ScratchError {
    fn from(e: serde_json::Error) -> Self {
        ScratchError::Json(e)
    }
}

/// Retrieve projection options — the keyword args of the Python `retrieve()`.
/// `offset`/`limit` of 0 mean unset; negative paging (a Python slice quirk)
/// is unsupported.
#[derive(Debug, Clone, Default)]
pub struct RetrieveOpts {
    pub offset: usize,
    pub limit: usize,
    pub filter_pattern: Option<String>,
    pub regex_pattern: Option<String>,
    pub fields: Option<String>,
    pub context_lines: usize,
}

/// What `store()` hands back — the same keys the Python store's envelope
/// carries (`scratch_ref`, `stored_bytes`, `original_bytes`, `truncated`,
/// `expires_at`, `tool_id`). `to_envelope()` emits it as the model-facing
/// JSON the projection layer would.
#[derive(Debug, Clone)]
pub struct StoreReceipt {
    pub scratch_ref: String,
    pub stored_bytes: usize,
    pub original_bytes: usize,
    pub truncated: bool,
    pub expires_at: f64,
    pub tool_id: String,
}

impl StoreReceipt {
    pub fn to_envelope(&self) -> Value {
        json!({
            "scratch_ref": self.scratch_ref,
            "stored_bytes": self.stored_bytes,
            "original_bytes": self.original_bytes,
            "truncated": self.truncated,
            "expires_at": self.expires_at,
            "tool_id": self.tool_id,
        })
    }
}

pub struct ScratchStore {
    conn: Mutex<Connection>,
    pub data_dir: PathBuf,
    pub db_path: PathBuf,
    config: ScratchConfig,
}

impl ScratchStore {
    /// Open (creating as needed) the store at explicit paths — the port of
    /// `ScratchStore(db_path, data_dir)`.
    pub fn open(db_path: &Path, data_dir: &Path, config: ScratchConfig) -> Result<Self> {
        // --- data dir (0700) ------------------------------------------------
        fs::create_dir_all(data_dir)?;
        repair_ownership_if_needed(db_path, data_dir);
        // SECURITY: open() may run as root over paths the (non-root)
        // workspace owner controls, so permissions are set through an
        // O_NOFOLLOW descriptor (fchmod), never by path. A symlinked data
        // dir is allowed (e.g. pointed at a bigger disk) but never chmodded
        // through: a planted `scratch-data -> /etc` must not get /etc 0700.
        match open_nofollow(data_dir, true).and_then(|d| d.set_permissions(fs::Permissions::from_mode(0o700))) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(nix::libc::ELOOP) => eprintln!(
                "[scratch] data dir {} is a symlink; leaving its target's permissions alone",
                data_dir.display()
            ),
            // best-effort: non-POSIX fs or not owner — python's
            // `except OSError: pass`
            Err(e) => eprintln!("[scratch] data-dir chmod 0700 skipped: {e}"),
        }

        // --- sqlite ---------------------------------------------------------
        // scratch.db holds per-agent metadata (agent/tool/chat ids, sizes,
        // hashes) — it must not be world-readable. Create or chmod it 0600
        // through an O_NOFOLLOW descriptor BEFORE sqlite touches it (no
        // world-readable window on a fresh file), and open it with
        // SQLITE_OPEN_NOFOLLOW: a symlinked scratch.db is refused outright
        // — following it as root would chmod (and write a schema into)
        // whatever the link points at. Divergence: the python store follows.
        prepare_db_file(db_path)?;
        let mut conn = Connection::open_with_flags(
            db_path,
            OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        conn.busy_timeout(Duration::from_millis(10_000))?;
        set_wal(&conn)?;
        // Python wraps table creation in `with self.conn:` — one transaction.
        let tx = conn.transaction()?;
        tx.execute_batch(SCHEMA_SQL)?;
        tx.execute(
            "CREATE INDEX IF NOT EXISTS idx_scratch_agent \
             ON scratch_entries(agent_id, created_at DESC)",
            [],
        )?;
        tx.execute(
            "CREATE INDEX IF NOT EXISTS idx_scratch_expiry \
             ON scratch_entries(expires_at)",
            [],
        )?;
        tx.commit()?;

        Ok(Self {
            conn: Mutex::new(conn),
            data_dir: data_dir.to_path_buf(),
            db_path: db_path.to_path_buf(),
            config,
        })
    }

    /// Env-default construction: `$WORKSPACE_ROOT/scratch.db` + `scratch-data`
    /// with env-backed config (python's bare `ScratchStore()` default; the
    /// python falls back to `/var/lib/daharness` via resolve_workspace_root —
    /// lane-specific plumbing that stays out of the library; callers with a
    /// deb workspace set WORKSPACE_ROOT).
    pub fn open_default() -> Result<Self> {
        let root = PathBuf::from(std::env::var("WORKSPACE_ROOT").unwrap_or_else(|_| ".".into()));
        Self::open(
            &root.join("scratch.db"),
            &root.join("scratch-data"),
            ScratchConfig::from_env(),
        )
    }

    /// Persist a tool result and return a scratch reference receipt.
    ///
    /// The envelope (`receipt.to_envelope()`) is what the projection layer
    /// returns to the model when `result_mode` is digest/page — it carries
    /// the opaque reference plus the retrieval instruction.
    pub fn store(
        &self,
        result: &Value,
        agent_id: &str,
        tool_id: &str,
        chat_id: Option<&str>,
    ) -> Result<StoreReceipt> {
        self.cleanup_expired()?;

        // Serialize (python: json.dumps(..., default=str, ensure_ascii=False);
        // serde_json always emits raw UTF-8 and cannot embed arbitrary objects).
        let mut raw = serde_json::to_string(result)?.into_bytes();
        let original_bytes = raw.len();
        let mut truncated = false;
        if original_bytes > self.config.max_payload_bytes {
            // Truncate the serialized form — last resort. The projection
            // layer's digest should prevent this in practice, but the store
            // must never OOM the box on a pathologically large result.
            // Python slices raw bytes (possibly mid-codepoint, which later
            // fails UTF-8 decode); we floor to a UTF-8 boundary — either way
            // the JSON no longer parses, so retrieval reports "corrupted".
            let mut cap = self.config.max_payload_bytes;
            while cap > 0 && (raw[cap] & 0xC0) == 0x80 {
                // mid-codepoint: walk back to the char boundary (a
                // continuation byte can never start a UTF-8 sequence)
                cap -= 1;
            }
            raw.truncate(cap);
            truncated = true;
        }

        // gzip level 6, matching `gzip.compress(raw, compresslevel=6)`.
        let mut enc = GzEncoder::new(Vec::with_capacity(raw.len() / 2), Compression::new(6));
        enc.write_all(&raw)?;
        let compressed = enc.finish()?;

        let sha = hex(&Sha256::digest(&compressed));

        // Generate an unguessable ID (python: secrets.token_hex(8)).
        let scratch_id = random_hex_id()?;
        let ref_ = format!("scratch:{scratch_id}");

        // Write the payload atomically OUTSIDE the DB lock: another agent's
        // store() must not wait through our serialize-gzip-fsync window (the
        // old order held the Mutex across fsync, serializing all writers on
        // one kernel sync). Temp file is created mode 0600 directly.
        let payload_path = self.data_dir.join(format!("{scratch_id}.json.gz"));
        let tmp_path = self.data_dir.join(format!(".{scratch_id}.tmp"));
        let payload_write: std::io::Result<()> = (|| {
            let mut fh = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp_path)?;
            fh.write_all(&compressed)?;
            fh.sync_all()?;
            drop(fh);
            fs::rename(&tmp_path, &payload_path)
        })();
        if let Err(e) = payload_write {
            // temp left behind only if open/write failed before rename
            let _ = fs::remove_file(&tmp_path);
            return Err(e.into());
        }

        let mut conn = lock(&self.conn);

        // Per-agent cap: evict oldest entries for this agent until within
        // budget. Divergence: python evicts before writing the payload; here
        // the payload is already on disk (written outside the lock above),
        // so disk use can briefly exceed the cap by this one entry.
        enforce_agent_cap(&mut conn, agent_id, self.config.max_agent_bytes, &self.data_dir)?;

        let now = now_secs();
        let expires_at = now + self.config.ttl_hours * 3600.0;

        let tx = conn.transaction()?;
        let insert = tx.execute(
            "INSERT INTO scratch_entries \
                 (id, agent_id, chat_id, tool_id, created_at, expires_at, \
                  content_type, byte_count, sha256, payload_path, schema_version) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                scratch_id,
                agent_id,
                chat_id,
                tool_id,
                now,
                expires_at,
                CONTENT_TYPE,
                compressed.len() as i64,
                sha,
                payload_path.to_string_lossy(),
                SCHEMA_VERSION,
            ],
        );
        let committed = insert.and_then(|_| tx.commit());
        if let Err(e) = committed {
            // row absent (rolled back) → the renamed payload would leak with
            // no reference pointing at it; unlink best-effort.
            let _ = fs::remove_file(&payload_path);
            return Err(e.into());
        }

        Ok(StoreReceipt {
            scratch_ref: ref_,
            stored_bytes: compressed.len(),
            original_bytes,
            truncated,
            expires_at,
            tool_id: tool_id.to_string(),
        })
    }

    /// Retrieve a stored result by reference. Returns the model-facing
    /// envelope as a `Value` — every terminal condition is an envelope
    /// (python never raises from retrieve, it returns `status: error`); only
    /// infrastructure failures (`Result::Err`) raise. Unknown ref, wrong
    /// agent, and expired all yield distinct documented envelopes.
    pub fn retrieve(&self, scratch_ref: &str, agent_id: &str, opts: RetrieveOpts) -> Result<Value> {
        let scratch_id = match parse_ref(scratch_ref) {
            Some(id) => id.to_string(),
            None => {
                return Ok(error_envelope(format!(
                    "invalid scratch reference {}; expected 'scratch:<hex>'",
                    py_repr(scratch_ref)
                )))
            }
        };

        let row = {
            let conn = lock(&self.conn);
            conn.query_row(
                "SELECT tool_id, expires_at FROM scratch_entries \
                 WHERE id = ?1 AND agent_id = ?2",
                params![scratch_id, agent_id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, f64>(1)?)),
            )
            .optional()?
        };
        let Some((tool_id, expires_at)) = row else {
            // Same envelope for unknown / expired / other-agent (no leak).
            return Ok(error_envelope(format!(
                "scratch reference {} not found, expired, or not owned by this agent",
                py_repr(scratch_ref)
            )));
        };

        let now = now_secs();
        if now > expires_at {
            let mut conn = lock(&self.conn);
            delete_entry(&mut conn, &scratch_id, &self.data_dir)?;
            return Ok(error_envelope(format!(
                "scratch reference {} has expired",
                py_repr(scratch_ref)
            )));
        }

        // The payload path is DERIVED from the store's data dir + the row id
        // — the payload_path column is written for observability but never
        // trusted for I/O: a tampered row must not redirect reads/unlinks to
        // an arbitrary file (e.g. one owned by root).
        let Some(payload_path) = payload_file(&self.data_dir, &scratch_id) else {
            return Ok(error_envelope(format!(
                "invalid scratch reference {}; expected 'scratch:<hex>'",
                py_repr(scratch_ref)
            )));
        };
        if !payload_path.is_file() {
            let mut conn = lock(&self.conn);
            delete_entry(&mut conn, &scratch_id, &self.data_dir)?;
            return Ok(error_envelope(format!(
                "scratch payload file missing for {}",
                py_repr(scratch_ref)
            )));
        }

        // Decompress + deserialize (MultiGzDecoder matches python gzip.open's
        // multistream tolerance, e.g. trailing empty members).
        let mut result: Value = match read_json_payload(&payload_path) {
            Ok(v) => v,
            Err(e) => {
                return Ok(error_envelope(format!(
                    "scratch payload corrupted for {}: {e}",
                    py_repr(scratch_ref)
                )))
            }
        };

        // Apply field selection first (reduces work for filter/regex).
        if let Some(fields) = &opts.fields {
            let wanted: std::collections::HashSet<&str> = fields
                .split(',')
                .map(str::trim)
                .filter(|f| !f.is_empty())
                .collect();
            if let Some(map) = result.as_object_mut() {
                // Unknown field names are silently dropped.
                map.retain(|k, _| wanted.contains(k.as_str()));
            }
            // Non-object payloads pass through (python would raise; guard
            // documented in the crate divergences).
        }

        // Apply paging / filtering / regex if requested.
        let projection_requested = opts.offset != 0
            || opts.limit != 0
            || opts.filter_pattern.is_some()
            || opts.regex_pattern.is_some();
        if projection_requested {
            if let Some(pattern) = &opts.regex_pattern {
                match compile_regex(pattern) {
                    // python quirk preserved: an invalid regex surfaces as
                    // the error dict INSIDE the ok envelope's "result" field.
                    Err(msg) => result = error_envelope(msg),
                    Ok(re) => {
                        if let Some(map) = result.as_object_mut() {
                            apply_projection(
                                map,
                                opts.offset,
                                opts.limit,
                                opts.filter_pattern.as_deref(),
                                Some(&re),
                                opts.context_lines,
                                self.config.grep_min_chars,
                            );
                        }
                    }
                }
            } else if let Some(map) = result.as_object_mut() {
                apply_projection(
                    map,
                    opts.offset,
                    opts.limit,
                    opts.filter_pattern.as_deref(),
                    None,
                    opts.context_lines,
                    self.config.grep_min_chars,
                );
            }
        }

        Ok(json!({
            "status": "ok",
            "scratch_ref": scratch_ref,
            "tool_id": tool_id,
            "result": result,
        }))
    }

    /// List recent scratch entries for an agent (metadata only, no payloads).
    /// Rows are the python envelope dicts: `scratch_ref`, `tool_id`,
    /// `created_at`, `expires_at`, `stored_bytes`.
    pub fn list_entries(&self, agent_id: &str, limit: usize) -> Result<Vec<Value>> {
        let conn = lock(&self.conn);
        let mut stmt = conn.prepare(
            "SELECT id, tool_id, created_at, expires_at, byte_count \
             FROM scratch_entries WHERE agent_id = ?1 \
             ORDER BY created_at DESC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![agent_id, limit as i64], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, f64>(2)?,
                    r.get::<_, f64>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows
            .into_iter()
            .map(|(id, tool_id, created_at, expires_at, stored_bytes)| {
                json!({
                    "scratch_ref": format!("scratch:{id}"),
                    "tool_id": tool_id,
                    "created_at": created_at,
                    "expires_at": expires_at,
                    "stored_bytes": stored_bytes,
                })
            })
            .collect())
    }

    /// Return store statistics (global or per-agent) — the python `stats()`
    /// envelope: `entries`, `stored_bytes`, `ttl_hours`, `data_dir`.
    pub fn stats(&self, agent_id: Option<&str>) -> Result<Value> {
        let (count, bytes) = {
            let conn = lock(&self.conn);
            match agent_id {
                Some(a) => conn.query_row(
                    "SELECT COUNT(*), COALESCE(SUM(byte_count),0) \
                     FROM scratch_entries WHERE agent_id = ?1",
                    params![a],
                    |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
                )?,
                None => conn.query_row(
                    "SELECT COUNT(*), COALESCE(SUM(byte_count),0) FROM scratch_entries",
                    [],
                    |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
                )?,
            }
        };
        Ok(json!({
            "entries": count,
            "stored_bytes": bytes,
            "ttl_hours": self.config.ttl_hours,
            "data_dir": self.data_dir.to_string_lossy(),
        }))
    }

    /// Public cleanup: delete expired entries. Returns count removed.
    pub fn cleanup_expired(&self) -> Result<usize> {
        let mut conn = lock(&self.conn);
        cleanup_expired_locked(&mut conn, now_secs(), &self.data_dir)
    }
}

// ---------------------------------------------------------------- helpers --

/// Open `path` itself (never a symlink's target): ELOOP when it is a link.
fn open_nofollow(path: &Path, dir: bool) -> std::io::Result<fs::File> {
    let mut flags = nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC;
    if dir {
        flags |= nix::libc::O_DIRECTORY;
    }
    OpenOptions::new().read(true).custom_flags(flags).open(path)
}

/// Create `scratch.db` 0600 (O_EXCL|O_NOFOLLOW) or fchmod an existing one
/// to 0600 through an O_NOFOLLOW descriptor. A symlink is a hard error; a
/// chmod we aren't allowed to do (not owner) is logged and left to sqlite.
fn prepare_db_file(db_path: &Path) -> Result<()> {
    let created = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(db_path);
    let file = match created {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => match open_nofollow(db_path, false) {
            Ok(f) => f,
            Err(e) if e.raw_os_error() == Some(nix::libc::ELOOP) => {
                return Err(ScratchError::Io(std::io::Error::other(format!(
                    "refusing to open {}: it is a symlink",
                    db_path.display()
                ))))
            }
            Err(e) => {
                // e.g. root-owned db under a non-root run: the root guard
                // already warned; let sqlite report the real failure.
                eprintln!("[scratch] db-file chmod 0600 skipped: {e}");
                return Ok(());
            }
        },
        Err(e) => return Err(e.into()),
    };
    if !file.metadata()?.file_type().is_file() {
        return Err(ScratchError::Io(std::io::Error::other(format!(
            "refusing to open {}: not a regular file",
            db_path.display()
        ))));
    }
    if let Err(e) = file.set_permissions(fs::Permissions::from_mode(0o600)) {
        eprintln!("[scratch] db-file chmod 0600 skipped: {e}");
    }
    Ok(())
}

/// fs::read → MultiGzDecoder → UTF-8 → JSON, errors flattened into one
/// Display string for the "corrupted" envelope (python catches OSError /
/// JSONDecodeError / BadGzipFile into the same envelope).
fn read_json_payload(path: &Path) -> std::result::Result<Value, String> {
    let compressed = fs::read(path).map_err(|e| e.to_string())?;
    let mut raw: Vec<u8> = Vec::new();
    std::io::Read::read_to_end(
        &mut MultiGzDecoder::new(std::io::Cursor::new(compressed)),
        &mut raw,
    )
    .map_err(|e| e.to_string())?;
    let s = String::from_utf8(raw).map_err(|e| e.to_string())?;
    serde_json::from_str(&s).map_err(|e| e.to_string())
}

fn lock(m: &Mutex<Connection>) -> MutexGuard<'_, Connection> {
    // A panic elsewhere while holding the lock must not permanently wedge
    // the store; take the poisoned guard (SQLite recovers, the Connection
    // holds no invariants of ours).
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

fn random_hex_id() -> Result<String> {
    let mut buf = [0u8; 8];
    getrandom::getrandom(&mut buf).map_err(|e| ScratchError::Entropy(e.to_string()))?;
    Ok(hex(&buf))
}

/// Extract the hex ID from a `scratch:<hex>` reference — mirrors `_parse_ref`
/// (lowercase hex only, non-empty).
pub fn parse_ref(ref_str: &str) -> Option<&str> {
    let id = ref_str.strip_prefix("scratch:")?;
    if valid_scratch_id(id) {
        Some(id)
    } else {
        None
    }
}

/// A scratch row id the filesystem layer will act on: non-empty lowercase
/// hex. Rows carry a `payload_path` TEXT column for observability, but it is
/// never trusted — every read/unlink derives the file from `data_dir + id`,
/// so a tampered row cannot redirect retrieve/cleanup/cap-evict at an
/// arbitrary (possibly root-owned) path.
fn valid_scratch_id(id: &str) -> bool {
    !id.is_empty() && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn payload_file(data_dir: &Path, id: &str) -> Option<PathBuf> {
    if !valid_scratch_id(id) {
        return None;
    }
    Some(data_dir.join(format!("{id}.json.gz")))
}

fn error_envelope(msg: String) -> Value {
    json!({ "status": "error", "error": msg })
}

/// Python `repr()` for error strings: single-quoted normally, double-quoted
/// when the value contains a quote and no double quote.
fn py_repr(s: &str) -> String {
    if s.contains('\'') && !s.contains('"') {
        format!("\"{s}\"")
    } else {
        format!("'{s}'")
    }
}

fn delete_entry(conn: &mut Connection, id: &str, data_dir: &Path) -> Result<()> {
    // Payload unlink is best-effort (python: `except OSError: pass`) — the
    // metadata row going away is what makes the entry dead; a leaked file is
    // orphaned bytes and never blocks dispatch. The path is derived from the
    // id, never taken from the row.
    if let Some(payload_path) = payload_file(data_dir, id) {
        if payload_path.is_file() {
            let _ = fs::remove_file(payload_path);
        }
    }
    let tx = conn.transaction()?;
    tx.execute("DELETE FROM scratch_entries WHERE id = ?1", params![id])?;
    tx.commit()?;
    Ok(())
}

fn cleanup_expired_locked(conn: &mut Connection, now: f64, data_dir: &Path) -> Result<usize> {
    let ids: Vec<String> = {
        let mut stmt = conn.prepare(
            "SELECT id FROM scratch_entries WHERE expires_at < ?1",
        )?;
        let rows = stmt
            .query_map(params![now], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        rows
    };
    for id in &ids {
        delete_entry(conn, id, data_dir)?;
    }
    Ok(ids.len())
}

/// Evict oldest entries for an agent until within the per-agent cap —
/// mirrors `_enforce_agent_cap` (check at loop top, subtract, delete).
fn enforce_agent_cap(
    conn: &mut Connection,
    agent_id: &str,
    max_agent_bytes: usize,
    data_dir: &Path,
) -> Result<()> {
    let total: i64 = conn.query_row(
        "SELECT COALESCE(SUM(byte_count),0) FROM scratch_entries WHERE agent_id = ?1",
        params![agent_id],
        |r| r.get(0),
    )?;
    if total <= max_agent_bytes as i64 {
        return Ok(());
    }
    let rows: Vec<(String, i64)> = {
        let mut stmt = conn.prepare(
            "SELECT id, byte_count FROM scratch_entries \
             WHERE agent_id = ?1 ORDER BY created_at ASC",
        )?;
        let rows = stmt
            .query_map(params![agent_id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        rows
    };
    let mut total = total;
    for (id, byte_count) in rows {
        if total <= max_agent_bytes as i64 {
            break;
        }
        total -= byte_count;
        delete_entry(conn, &id, data_dir)?;
    }
    Ok(())
}

/// Tolerant WAL conversion — port of `utils/scratch_store._set_wal` (see
/// fleet_scheduler._set_wal): the first converter can hit SQLITE_BUSY outside
/// busy-handler coverage, and a mode readback is the acceptance test.
fn set_wal(conn: &Connection) -> Result<()> {
    fn readback_is_wal(conn: &Connection) -> bool {
        conn.query_row("PRAGMA journal_mode", [], |r| r.get::<_, String>(0))
            .map(|m| m.eq_ignore_ascii_case("wal"))
            .unwrap_or(false)
    }
    for attempt in 0..3u8 {
        match conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get::<_, String>(0)) {
            Ok(_) => return Ok(()),
            Err(_) => {
                if readback_is_wal(conn) {
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(50 * (attempt as u64 + 1)));
            }
        }
    }
    if readback_is_wal(conn) {
        return Ok(());
    }
    // Surface the real error — the db is truly not WAL.
    conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get::<_, String>(0))?;
    Ok(())
}

// ------------------------------------------------------- root guard --------

/// Chown scratch DB + WAL + SHM + data dir back to the workspace owner.
///
/// Port of `_repair_ownership_if_needed`: when root-created files from a
/// prior root run outlive it, the next NON-root run gets "attempt to write a
/// readonly database" because WAL mode needs write access to `scratch.db`,
/// `-wal`, and `-shm`. The python repair shells `chown` out; the port calls
/// the syscalls directly via nix (no PATH dependency, no timeout dance).
/// Never raises — a failed repair logs and lets the caller proceed (the
/// projection layer degrades gracefully to field-capping without scratch).
///
/// SECURITY: this runs as root over paths the (non-root) workspace owner
/// controls. Every operation is no-follow: `lchown` for the top-level files,
/// and the data-dir walk is descriptor-relative (`openat(O_NOFOLLOW |
/// O_DIRECTORY)` + `fchownat(AT_SYMLINK_NOFOLLOW)`), so a planted symlink —
/// or a directory swapped for one mid-walk — can only ever get the LINK
/// chowned, never its target. (A path-based walk that follows links would
/// let the workspace owner aim root's chown at e.g. /etc/shadow.) Python's
/// `chown -R` is likewise no-follow during recursion (implicit -P).
fn repair_ownership_if_needed(db_path: &Path, data_dir: &Path) {
    fn uid_of(path: &Path) -> Option<(u32, u32)> {
        let st = nix::sys::stat::stat(path).ok()?; // OSError → nothing to say
        Some((st.st_uid, st.st_gid))
    }
    /// lstat: owner of the path itself, never a link target.
    fn luid_of(path: &Path) -> Option<u32> {
        nix::sys::stat::lstat(path).ok().map(|st| st.st_uid)
    }

    // Target owner = the UID of the workspace root dir (python stat's
    // resolve_workspace_root(); the db lives at <root>/scratch.db, so the db's
    // parent is the same directory).
    let Some(workspace_root) = db_path.parent() else {
        return;
    };
    let Some((target_uid, target_gid)) = uid_of(workspace_root) else {
        return; // can't stat workspace — nothing to do
    };
    if target_uid == 0 {
        // Workspace root-owned: no mismatch to fix.
        return;
    }

    let is_root = geteuid().is_root();
    let stem = db_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("scratch");
    let files: Vec<PathBuf> = vec![
        db_path.to_path_buf(),
        db_path.with_file_name(format!("{stem}.db-wal")),
        db_path.with_file_name(format!("{stem}.db-shm")),
        data_dir.to_path_buf(),
    ];

    let needs_repair = files.iter().any(|f| luid_of(f) == Some(0));
    if !needs_repair {
        return;
    }

    if !is_root {
        eprintln!(
            "[scratch] warning: {} and/or WAL/SHM/scratch-data files are root-owned but the \
             framework is running as non-root (uid={}). SQLite WAL mode needs write access to \
             all three DB files; scratch storage will degrade. Fix: run once as root to trigger \
             the auto-repair, or run: sudo chown -R {target_uid}:{target_gid} {db} {data}/",
            db_path.display(),
            geteuid().as_raw(),
            db = db_path.display(),
            data = data_dir.display(),
        );
        return;
    }

    let (uid, gid) = (Uid::from_raw(target_uid), Gid::from_raw(target_gid));
    // Top-level db files: lchown — a symlinked scratch.db gets the link
    // re-owned, never the file it points at.
    for f in &files[..3] {
        if luid_of(f).is_some() {
            let _ = std::os::unix::fs::lchown(f, Some(target_uid), Some(target_gid));
        }
    }
    chown_tree_nofollow(data_dir, uid, gid);
    eprintln!(
        "[scratch] Root guard: chowned scratch DB + WAL + SHM + data dir back to \
         uid={target_uid} (workspace owner). A prior root run had root-owned these files, \
         which would make the next non-root run fail with 'readonly database'."
    );
}

/// Max directory depth the repair walk descends (scratch-data is flat in
/// practice; the cap only bounds a hostile deep tree).
const CHOWN_MAX_DEPTH: usize = 32;

fn nofollow_dir_flags() -> nix::fcntl::OFlag {
    use nix::fcntl::OFlag;
    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC
}

/// Descriptor-relative, symlink-proof recursive chown of `root`.
/// A symlinked `root` is refused outright (O_NOFOLLOW open fails); entries
/// are re-owned with AT_SYMLINK_NOFOLLOW and only descended into when an
/// O_NOFOLLOW|O_DIRECTORY `openat` succeeds — i.e. it is a real directory at
/// the moment we open it, so a swap-to-symlink race fails closed.
fn chown_tree_nofollow(root: &Path, uid: Uid, gid: Gid) {
    use nix::dir::Dir;
    use nix::sys::stat::Mode;
    use std::os::fd::AsRawFd;

    let dir = match Dir::open(root, nofollow_dir_flags(), Mode::empty()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!(
                "[scratch] Root guard: not walking {} ({e}); refusing to follow a symlinked or \
                 non-directory data dir",
                root.display()
            );
            return;
        }
    };
    let _ = nix::unistd::fchown(dir.as_raw_fd(), Some(uid), Some(gid));
    chown_dir_entries(dir, uid, gid, 0);
}

fn chown_dir_entries(mut dir: nix::dir::Dir, uid: Uid, gid: Gid, depth: usize) {
    use nix::dir::Dir;
    use nix::fcntl::AtFlags;
    use nix::sys::stat::Mode;
    use std::os::fd::AsRawFd;

    if depth >= CHOWN_MAX_DEPTH {
        return;
    }
    let fd = dir.as_raw_fd();
    // Collect names first: the iterator borrows the Dir mutably.
    let names: Vec<std::ffi::CString> = dir
        .iter()
        .flatten()
        .map(|e| e.file_name().to_owned())
        .filter(|n| n.as_bytes() != b"." && n.as_bytes() != b"..")
        .collect();
    for name in names {
        // best-effort, mirror python's debug-swallowed chown failures
        let _ = nix::unistd::fchownat(
            Some(fd),
            name.as_c_str(),
            Some(uid),
            Some(gid),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        );
        if let Ok(sub) = Dir::openat(Some(fd), name.as_c_str(), nofollow_dir_flags(), Mode::empty()) {
            chown_dir_entries(sub, uid, gid, depth + 1);
        }
    }
}

// ----------------------------------------------------------------- tests ----

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::Duration;

    fn test_store(config: ScratchConfig) -> (tempfile::TempDir, ScratchStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ScratchStore::open(
            &dir.path().join("scratch.db"),
            &dir.path().join("scratch-data"),
            config,
        )
        .expect("open store");
        (dir, store)
    }

    /// High-entropy hex pad so gzip can't compress test payloads below caps.
    fn random_pad(bytes: usize) -> String {
        let mut buf = vec![0u8; bytes];
        getrandom::getrandom(&mut buf).unwrap();
        hex(&buf)
    }

    fn cfg(ttl_hours: f64, max_payload: usize, max_agent: usize) -> ScratchConfig {
        ScratchConfig::new(ttl_hours, max_payload, max_agent, 200)
    }

    #[test]
    fn parse_ref_accepts_lowercase_hex_and_rejects_the_rest() {
        assert_eq!(parse_ref("scratch:0123abcdef"), Some("0123abcdef"));
        assert_eq!(parse_ref("scratch:ABCDEF"), None); // uppercase denied
        assert_eq!(parse_ref("scratch:"), None);
        assert_eq!(parse_ref("scratch:xyz"), None);
        assert_eq!(parse_ref(":0123"), None);
        assert_eq!(parse_ref("scratch:123 g"), None);
    }

    #[test]
    fn cleanup_ignores_tampered_payload_paths() {
        // A row's payload_path column is observability only — retrieve and
        // cleanup derive the payload file from data_dir + row id, so a
        // tampered row must never delete an arbitrary file (e.g. root-owned).
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ScratchStore::open(
            &dir.path().join("scratch.db"),
            &dir.path().join("scratch-data"),
            cfg(24.0, 1024 * 1024, 1024 * 1024),
        )
        .expect("open store");
        let receipt = store
            .store(&json!({"pad": random_pad(900)}), "agent-a", "t", None)
            .expect("store");
        let id = receipt.scratch_ref.trim_start_matches("scratch:").to_string();

        // Tamper: point the row's payload_path at an innocent bystander and
        // force expiry in one UPDATE.
        let victim = dir.path().join("victim.json.gz");
        std::fs::write(&victim, b"do not delete").unwrap();
        {
            let conn = lock(&store.conn);
            conn.execute(
                "UPDATE scratch_entries SET payload_path = ?1, expires_at = 0 \
                 WHERE id = ?2",
                params![victim.to_string_lossy(), id],
            )
            .unwrap();
        }

        let removed = store.cleanup_expired().unwrap();
        assert_eq!(removed, 1);
        assert!(victim.is_file(), "tampered path must never be deleted");
        let derived = store.data_dir.join(format!("{id}.json.gz"));
        assert!(
            !derived.is_file(),
            "the derived payload file must be gone instead"
        );
        let env = store
            .retrieve(&receipt.scratch_ref, "agent-a", RetrieveOpts::default())
            .unwrap();
        assert_eq!(env["status"], "error");
        assert!(env["error"].as_str().unwrap().contains("not found"));
    }

    #[test]
    fn db_file_is_chmodded_0600() {
        let (_d, store) = test_store(cfg(24.0, 1024, 1024));
        let mode = std::fs::metadata(&store.db_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "scratch.db must not be world-readable");
    }

    #[test]
    fn store_retrieve_roundtrip_preserves_structure() {
        let (_d, store) = test_store(cfg(24.0, 1024, 1024));
        let payload = json!({
            "rows": [{"port": 80, "state": "open"}, {"port": 443, "state": "open"}],
            "meta": {"agent": "a1", "notes": "scratch: round-trip"}
        });
        let receipt = store
            .store(&payload, "agent-a", "nmap_status", None)
            .expect("store");
        assert!(receipt.scratch_ref.starts_with("scratch:"));
        assert_eq!(parse_ref(&receipt.scratch_ref).unwrap().len(), 16);
        assert_eq!(receipt.tool_id, "nmap_status");
        assert!(!receipt.truncated);
        assert!(receipt.expires_at > now_secs() + 23.0 * 3600.0);

        let env = store
            .retrieve(&receipt.scratch_ref, "agent-a", RetrieveOpts::default())
            .expect("retrieve");
        assert_eq!(env["status"], "ok");
        assert_eq!(env["scratch_ref"], receipt.scratch_ref.as_str());
        assert_eq!(env["tool_id"], "nmap_status");
        assert_eq!(env["result"], payload);
    }

    #[test]
    fn wrong_agent_gets_the_not_found_envelope() {
        let (_d, store) = test_store(cfg(24.0, 1024, 1024));
        let receipt = store
            .store(&json!({"k": "v"}), "agent-a", "t", None)
            .expect("store");
        let env = store
            .retrieve(&receipt.scratch_ref, "agent-b", RetrieveOpts::default())
            .expect("retrieve");
        assert_eq!(
            env["error"],
            json!(format!(
                "scratch reference '{}' not found, expired, or not owned by this agent",
                receipt.scratch_ref
            ))
        );
    }

    #[test]
    fn invalid_refs_get_invalid_ref_envelope() {
        let (_d, store) = test_store(cfg(24.0, 1024, 1024));
        for bad in [
            "",
            "scratch:",
            "scratch:XYZ",
            "foo:abc",
            "scratch:ABCDEF0123456789",
        ] {
            let env = store
                .retrieve(bad, "agent-a", RetrieveOpts::default())
                .expect("retrieve");
            assert_eq!(env["status"], "error", "ref {bad:?}");
            let want = format!("invalid scratch reference {}", py_repr(bad));
            assert!(
                env["error"].as_str().unwrap_or_default().starts_with(&want),
                "ref {bad:?} → {}",
                env["error"]
            );
        }
    }

    #[test]
    fn expiry_lazily_deletes_and_reports_expired() {
        let (_d, store) = test_store(cfg(0.0002, 1024, 1024)); // ~0.72 s
        let receipt = store
            .store(&json!({"k": "v"}), "agent-a", "t", None)
            .expect("store");
        let dir_entries = || fs::read_dir(&store.data_dir).unwrap().count();
        assert_eq!(dir_entries(), 1, "payload file exists pre-expiry");

        std::thread::sleep(Duration::from_millis(800));
        let env = store
            .retrieve(&receipt.scratch_ref, "agent-a", RetrieveOpts::default())
            .expect("retrieve");
        assert_eq!(
            env["error"],
            json!(format!(
                "scratch reference '{}' has expired",
                receipt.scratch_ref
            ))
        );
        // Row + payload are gone (lazy delete on retrieve).
        assert_eq!(store.list_entries("agent-a", 10).unwrap().len(), 0);
        assert_eq!(dir_entries(), 0);
    }

    #[test]
    fn agent_cap_evicts_oldest_first() {
        let (_d, store) = test_store(cfg(24.0, 1024, 900));
        let mut first_ref = String::new();
        let mut last_ref = String::new();
        let mut last_stored = 0usize;
        for i in 0..5 {
            // ~600 hex chars ≈ 470+ compressed bytes per entry, so five
            // entries exceed the 900-byte agent cap.
            let payload = json!({"pad": format!("{i}-{}", random_pad(300))});
            let r = store
                .store(&payload, "agent-a", &format!("t{i}"), None)
                .expect("store");
            if i == 0 {
                first_ref = r.scratch_ref.clone();
            }
            last_ref = r.scratch_ref;
            last_stored = r.stored_bytes;
        }
        let stats = store.stats(Some("agent-a")).unwrap();
        // Python enforces the cap BEFORE the INSERT (pre-insert eviction),
        // so a fresh store may overshoot the cap by its own entry until the
        // next store's eviction trims it back. Assert that window, not a
        // hard ≤ 900 (which python itself does not guarantee).
        assert!(
            stats["stored_bytes"].as_i64().unwrap() <= (900 + last_stored) as i64,
            "cap enforced: {stats}"
        );
        // Oldest evicted, newest survives.
        let env = store
            .retrieve(&first_ref, "agent-a", RetrieveOpts::default())
            .unwrap();
        assert!(
            env["error"].as_str().unwrap_or_default().contains("not found"),
            "oldest should be evicted: {env}"
        );
        let env = store
            .retrieve(&last_ref, "agent-a", RetrieveOpts::default())
            .unwrap();
        assert_eq!(env["status"], "ok", "{env}");
    }

    #[test]
    fn per_entry_cap_truncates_and_retrieve_reports_corrupted() {
        let (_d, store) = test_store(cfg(24.0, 64, 1 << 20));
        let big = json!({"k": "x".repeat(400)}); // serialized ≈ 406 bytes > cap 64
        let r = store.store(&big, "agent-a", "t", None).expect("store");
        assert!(r.truncated);
        assert!(r.original_bytes > 64);
        // Truncated JSON is broken JSON → corrupted envelope (python parity:
        // raw byte truncation there breaks UTF-8/JSON the same way).
        let env = store
            .retrieve(&r.scratch_ref, "agent-a", RetrieveOpts::default())
            .unwrap();
        assert_eq!(env["status"], "error");
        assert!(env["error"].as_str().unwrap_or_default().starts_with(&format!(
            "scratch payload corrupted for '{}'",
            r.scratch_ref
        )));
    }

    #[test]
    fn payload_files_are_0600_and_dir_is_0700() {
        let (_d, store) = test_store(cfg(24.0, 1024, 1024));
        let r = store
            .store(&json!({"k": format!("pad-{}", "y".repeat(500))}), "agent-a", "t", None)
            .unwrap();
        let id = parse_ref(&r.scratch_ref).unwrap();
        let payload = store.data_dir.join(format!("{id}.json.gz"));
        let mode = fs::metadata(&payload).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let mode_dir = fs::metadata(&store.data_dir).unwrap().permissions().mode();
        assert_eq!(mode_dir & 0o777, 0o700);
        // No temp files left behind after the rename.
        assert!(!store.data_dir.join(format!(".{id}.tmp")).exists());
    }

    #[test]
    fn tampered_payload_reports_corrupted() {
        let (_d, store) = test_store(cfg(24.0, 1024, 1024));
        let r = store
            .store(&json!({"k": format!("pad-{}", "z".repeat(500))}), "agent-a", "t", None)
            .unwrap();
        let path = store
            .data_dir
            .join(format!("{}.json.gz", parse_ref(&r.scratch_ref).unwrap()));
        let mut bytes = fs::read(&path).unwrap();
        // Flip a byte inside the DEFLATE stream (skip the gzip magic).
        bytes[10] ^= 0xff;
        fs::write(&path, &bytes).unwrap();
        let env = store
            .retrieve(&r.scratch_ref, "agent-a", RetrieveOpts::default())
            .unwrap();
        assert_eq!(env["status"], "error");
        assert!(
            env["error"].as_str().unwrap_or_default().contains("corrupted")
        );
    }

    #[test]
    fn fields_selection_drops_unknown_names() {
        let (_d, store) = test_store(cfg(24.0, 1024, 1024));
        let r = store
            .store(&json!({"a": 1, "b": 2, "c": 3}), "agent-a", "t", None)
            .unwrap();
        let env = store
            .retrieve(
                &r.scratch_ref,
                "agent-a",
                RetrieveOpts {
                    fields: Some("a , c,zzz".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        let res = env["result"].as_object().unwrap();
        assert_eq!(res.len(), 2);
        assert!(res.contains_key("a") && res.contains_key("c"));
        assert!(!res.contains_key("b") && !res.contains_key("zzz"));
    }

    #[test]
    fn projection_flags_meta_and_filters() {
        let (_d, store) = test_store(cfg(24.0, 1024 * 1024, 1024 * 1024));
        let text = "entry one\ncsrf token: abc\nentry two\ncsrf token: def\n".repeat(30);
        let r = store
            .store(
                &json!({"body": text, "rows": ["csrf", "authz", "csrf2"]}),
                "agent-a",
                "t",
                None,
            )
            .unwrap();
        let env = store
            .retrieve(
                &r.scratch_ref,
                "agent-a",
                RetrieveOpts {
                    filter_pattern: Some("csrf".into()),
                    context_lines: 1,
                    ..Default::default()
                },
            )
            .unwrap();
        let res = env["result"].as_object().unwrap();
        assert_eq!(res["rows"], json!(["csrf", "csrf2"]));
        assert!(res["body"].as_str().unwrap().contains("csrf token: abc"));
        let meta = &res["_scratch_projection"];
        assert_eq!(meta["filter"], "csrf");
        assert_eq!(meta["context_lines"], json!(1));
        assert!(meta["grepped_keys"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str() == Some("body")));
    }

    #[test]
    fn regex_projection_reports_invalid_pattern_inside_the_ok_envelope() {
        // Python quirk preserved: compile failure replaces the "result" field
        // with the error dict while the OUTER envelope stays "ok".
        let (_d, store) = test_store(cfg(24.0, 1024, 1024));
        let r = store
            .store(&json!({"k": "v"}), "agent-a", "t", None)
            .unwrap();
        let env = store
            .retrieve(
                &r.scratch_ref,
                "agent-a",
                RetrieveOpts {
                    regex_pattern: Some("csrf(".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(env["status"], "ok", "{env}");
        assert_eq!(env["result"]["status"], "error");
        assert!(env["result"]["error"]
            .as_str()
            .unwrap()
            .starts_with("invalid regex pattern 'csrf(':"));
    }

    #[test]
    fn multistream_gzip_payload_still_retrieves() {
        // The python reader (gzip.open) tolerates multi-member streams (some
        // writers append trailing empty members); the Rust MultiGzDecoder must
        // too. Hand-craft one: valid member + appended empty member.
        let (_d, store) = test_store(cfg(24.0, 1024, 1024));
        let r = store
            .store(&json!({"k": format!("pad-{}", "w".repeat(300))}), "agent-a", "t", None)
            .unwrap();
        let path = store
            .data_dir
            .join(format!("{}.json.gz", parse_ref(&r.scratch_ref).unwrap()));
        let valid = fs::read(&path).unwrap();
        let mut empty_member = Vec::new();
        {
            let mut enc = GzEncoder::new(&mut empty_member, Compression::new(6));
            enc.write_all(b"").unwrap();
            enc.finish().unwrap();
        }
        fs::write(&path, [valid, empty_member].concat()).unwrap();
        let env = store
            .retrieve(&r.scratch_ref, "agent-a", RetrieveOpts::default())
            .unwrap();
        assert_eq!(env["status"], "ok", "{env}");
    }

    #[test]
    fn list_entries_orders_desc_and_respects_limit() {
        let (_d, store) = test_store(cfg(24.0, 1024, 1024));
        for i in 0..3 {
            store
                .store(
                    &json!({"i": i, "p": format!("{i}-{}", "q".repeat(50))}),
                    "agent-a",
                    &format!("t{i}"),
                    None,
                )
                .unwrap();
            std::thread::sleep(Duration::from_millis(10)); // distinct created_at
        }
        let rows = store.list_entries("agent-a", 3).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["tool_id"], "t2");
        assert_eq!(rows[2]["tool_id"], "t0");
        let rows = store.list_entries("agent-a", 1).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["tool_id"], "t2");
        // Other agents don't see them.
        assert_eq!(store.list_entries("agent-b", 10).unwrap().len(), 0);
    }

    #[test]
    fn stats_shapes_match_python() {
        let (_d, store) = test_store(cfg(24.0, 1024, 1024));
        store
            .store(&json!({"k": format!("p{}", "r".repeat(80))}), "agent-a", "t", None)
            .unwrap();
        let stats = store.stats(Some("agent-a")).unwrap();
        assert_eq!(stats["entries"], json!(1));
        assert!(stats["stored_bytes"].as_i64().unwrap() > 0);
        assert_eq!(stats["ttl_hours"], json!(24.0));
        assert!(stats["data_dir"].as_str().unwrap().ends_with("scratch-data"));
        let global = store.stats(None).unwrap();
        assert_eq!(global["entries"], json!(1));
    }

    #[test]
    fn wal_mode_is_active_on_a_fresh_db() {
        let (_d, store) = test_store(cfg(24.0, 1024, 1024));
        let mode: String = lock(&store.conn)
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode.to_ascii_lowercase(), "wal");
    }

    #[test]
    fn cleanup_expired_public_counts_removed() {
        // TTL of 1 millisecond — entries expire between store and cleanup.
        let (_d, store) = test_store(cfg(1.0 / 3_600_000.0, 1024, 1024));
        store
            .store(&json!({"k": "v"}), "agent-a", "t", None)
            .unwrap();
        std::thread::sleep(Duration::from_millis(20));
        let removed = store.cleanup_expired().unwrap();
        assert_eq!(removed, 1);
        assert_eq!(store.list_entries("agent-a", 10).unwrap().len(), 0);
    }

    #[test]
    fn non_object_payloads_pass_projection_untouched() {
        let (_d, store) = test_store(cfg(24.0, 1024, 1024));
        let r = store
            .store(&json!(["csrf", "plain"]), "agent-a", "t", None)
            .unwrap();
        let env = store
            .retrieve(
                &r.scratch_ref,
                "agent-a",
                RetrieveOpts {
                    filter_pattern: Some("csrf".into()),
                    fields: Some("csrf".into()), // python would raise here
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(env["status"], "ok");
        assert_eq!(env["result"], json!(["csrf", "plain"]));
    }

    #[test]
    fn chown_walk_never_follows_symlinks() {
        // Exercises the real attack: the (non-root) workspace owner plants
        // symlinks inside scratch-data pointing at root-owned files; a root
        // repair run must re-own the LINKS and real entries, never targets.
        // Needs root to chown to a foreign uid — skipped (passes) otherwise;
        // run `sudo -E cargo test chown_walk` to exercise it.
        use std::os::unix::fs::{symlink, MetadataExt};
        if !geteuid().is_root() {
            eprintln!("skipping chown_walk_never_follows_symlinks: needs root");
            return;
        }
        let (uid, gid) = (Uid::from_raw(4242), Gid::from_raw(4242));
        let d = tempfile::tempdir().unwrap();
        let data = d.path().join("scratch-data");
        let outside = d.path().join("outside"); // stands in for /etc
        fs::create_dir_all(data.join("sub")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("shadow"), b"x").unwrap();
        fs::write(data.join("sub").join("abc.json.gz"), b"y").unwrap();
        symlink(&outside, data.join("evil-dir")).unwrap();
        symlink(outside.join("shadow"), data.join("evil-file")).unwrap();

        chown_tree_nofollow(&data, uid, gid);

        let owner = |p: &Path| fs::symlink_metadata(p).unwrap().uid();
        // Real entries re-owned (including nested) ...
        assert_eq!(owner(&data), 4242);
        assert_eq!(owner(&data.join("sub")), 4242);
        assert_eq!(owner(&data.join("sub").join("abc.json.gz")), 4242);
        // ... the links themselves re-owned ...
        assert_eq!(owner(&data.join("evil-dir")), 4242);
        assert_eq!(owner(&data.join("evil-file")), 4242);
        // ... and NOTHING behind them touched.
        assert_eq!(owner(&outside), 0);
        assert_eq!(owner(&outside.join("shadow")), 0);

        // A symlinked data dir itself is refused outright.
        let linked = d.path().join("linked-data");
        symlink(&outside, &linked).unwrap();
        chown_tree_nofollow(&linked, uid, gid);
        assert_eq!(owner(&outside), 0);
        assert_eq!(owner(&outside.join("shadow")), 0);
    }

    #[test]
    fn symlinked_db_is_refused_and_target_untouched() {
        use std::os::unix::fs::symlink;
        let d = tempfile::tempdir().unwrap();
        let victim = d.path().join("victim-passwd");
        fs::write(&victim, b"root:x:0:0::/root:/bin/sh\n").unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o644)).unwrap();
        symlink(&victim, d.path().join("scratch.db")).unwrap();

        let err = ScratchStore::open(
            &d.path().join("scratch.db"),
            &d.path().join("scratch-data"),
            cfg(24.0, 1024, 1024),
        )
        .err()
        .expect("a symlinked scratch.db must be refused");
        assert!(err.to_string().contains("symlink"), "{err}");
        let mode = fs::metadata(&victim).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "the link target must keep its permissions");
        assert_eq!(fs::read(&victim).unwrap(), b"root:x:0:0::/root:/bin/sh\n");
    }

    #[test]
    fn symlinked_data_dir_target_is_not_chmodded() {
        use std::os::unix::fs::symlink;
        let d = tempfile::tempdir().unwrap();
        let outside = d.path().join("bigdisk");
        fs::create_dir(&outside).unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o755)).unwrap();
        symlink(&outside, d.path().join("scratch-data")).unwrap();

        let store = ScratchStore::open(
            &d.path().join("scratch.db"),
            &d.path().join("scratch-data"),
            cfg(24.0, 1024, 1024),
        )
        .expect("a symlinked data dir is allowed");
        let mode = fs::metadata(&outside).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "must not chmod through the link");
        // and the store still works through it
        let r = store.store(&json!({"k": "v"}), "a", "t", None).unwrap();
        assert_eq!(store.retrieve(&r.scratch_ref, "a", RetrieveOpts::default()).unwrap()["status"], "ok");
    }

    #[test]
    fn existing_world_readable_db_is_tightened_to_0600() {
        let d = tempfile::tempdir().unwrap();
        let db = d.path().join("scratch.db");
        drop(ScratchStore::open(&db, &d.path().join("scratch-data"), cfg(24.0, 1024, 1024)).unwrap());
        fs::set_permissions(&db, fs::Permissions::from_mode(0o644)).unwrap();
        let store = ScratchStore::open(&db, &d.path().join("scratch-data"), cfg(24.0, 1024, 1024)).unwrap();
        assert_eq!(fs::metadata(&store.db_path).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
