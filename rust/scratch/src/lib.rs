//! dadeb scratch store — Rust port of `utils/scratch_store.py` (milestone 5).
//!
//! The scratch store is durable, ownership-scoped storage for raw tool
//! results: NOT vector memory (no embeddings) and NOT the findings store (no
//! lifecycle). The model retrieves from it by opaque reference when it needs
//! the full (or filtered/paged) output of a prior tool call.
//!
//! # Contract (mirrors the Python store)
//!
//! - **Storage**: `scratch.db` (SQLite metadata, WAL, chmodded 0600) +
//!   `scratch-data/` (gzip-compressed JSON payloads, level 6; 0700 dir,
//!   0600 files). The `-wal`/`-shm` sidecars are chmodded 0600 too —
//!   re-hardened on every mutating/read hot path, because a re-opened WAL
//!   db re-mints them at its first statement, not at open() itself.
//!   Symlinked sidecars are refused at open (sqlite follows them); a
//!   non-regular main db file (planted FIFO) is refused without hanging.
//! - **IDs**: opaque random `scratch:<16-hex>`, never sequential — a guess
//!   from another chat cannot leak data.
//! - **Ownership**: every entry is scoped to `agent_id`; a valid-looking ref
//!   from the wrong agent returns the same "not found, expired, or not owned
//!   by this agent" envelope as a truly unknown ref (no existence leak).
//! - **Persistence**: entries survive a framework restart (on-disk).
//! - **TTL**: 24h default (`SCRATCH_TTL_HOURS`); cleanup runs on every
//!   `store()`; expired/missing-file entries are lazily deleted on retrieve.
//! - **Caps**: per-entry 256 MiB (`SCRATCH_MAX_PAYLOAD_MB`), per-agent 1 GiB
//!   (`SCRATCH_MAX_AGENT_MB`); per-entry oversize stores truncated with a
//!   stated policy, per-agent oversize evicts oldest-first.
//! - **Atomic writes**: payload goes temp → fsync → rename (outside the store
//!   lock — concurrent `store()` calls don't queue on one fsync), then the
//!   metadata row commits; a crash never leaves a torn entry.
//! - **Payload paths are derived, never trusted**: rows carry the
//!   `payload_path` column for observability, but every read/unlink derives
//!   the file from `data_dir` + row id, so a tampered row can't redirect
//!   retrieval/cleanup at an arbitrary file.
//! - **Schema**: identical DDL + WAL + busy_timeout as the Python store, so
//!   both implementations can operate the same workspace (verified against a
//!   Python-written db via [`crate::store::ScratchStore::retrieve`]; see
//!   `examples/pycompat.rs` for the round-trip probe).
//!
//! # Module map (mirrors `utils/scratch_store.py`)
//!
//! - [`config`] — env-backed knobs (module constants in Python)
//! - [`projection`] — the generic filter/regex/paging/grep fallback
//!   (`_apply_projection` and friends)
//! - [`store`] — `ScratchStore` itself: open/WAL/schema, store, retrieve,
//!   list/stats, cleanup, cap eviction, root guard
//!
//! # Documented divergences from the Python
//!
//! Everything behavioral is kept byte-for-byte where it reaches a model or
//! the database; divergences are structural and documented per-site:
//! malformed env values warn + default (Python raises at import), paging
//! offsets are `usize` (Python's negative-slice semantics are dropped), the
//! root guard chowns natively instead of spawning `chown` subprocesses, and
//! JSON is emitted compactly (Python `json.dumps` adds separators — payload
//! bytes differ slightly; sha256 is per-store so nothing couples).

pub mod config;
pub mod projection;
pub mod store;

pub use config::ScratchConfig;
pub use projection::{apply_projection, compile_regex, grep_string};
pub use store::{parse_ref, RetrieveOpts, ScratchError, ScratchStore, StoreReceipt};
