"""Analysis snapshot cache — reuse exact results for expensive deterministic tools.

Inspired by REA's AnalysisSnapshotCache (morluto/rea): a snapshot retains
successful analysis results for later queries.  An exact repeat query — same
target bytes, operation, and settings — reuses the stored result instead of
re-paying the analysis cost.

Applicability (deliberately narrow):

- **Deterministic tools only.** The cached result must be a pure function of
  (target content, operation, settings).  r2 static analysis qualifies
  (``aaa; pdf @ 0x401000`` on these bytes yields these bytes of output,
  forever).  Live scanners (nmap, ffuf, masscan) explicitly do NOT qualify —
  their results are observations of a changing world, and serving a stale
  "port 3306 open" verdict as fresh intel is worse than paying the scan cost
  twice.  Their job-log lane already persists results per job_id, which is
  the scanner-appropriate memoization.
- **Successful results only.** Errors (timeouts, missing plugins, launch
  failures) are never cached — a cached failure is a lie about the next
  attempt.  REA's failures carry per-call diagnostics and remediation; ours
  must stay fresh for the same reason.

Identity is content-keyed: the cache key incorporates the sha256 of the
target bytes, so re-analysis happens automatically whenever the binary
changes.  There is no invalidation problem for a read-only lane — only
"the bytes changed", which the key handles by construction.

Storage: SQLite (WAL) at ``run/analysis_snapshots.db`` (inside the
gitignored ``run/`` tree so container lanes share it).  The store mirrors
``utils/scratch_store.py`` conventions: root-ownership repair, busy_timeout,
idempotent schema init.  A per-target entry cap and TTL bound growth.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from constants import resolve_workspace_root

logger = logging.getLogger(__name__)

# TTL hours (env override). Analysis output for unchanged bytes never goes
# stale, so the TTL exists purely to bound disk growth, not freshness.
_TTL_HOURS = float(os.getenv("SNAPSHOT_TTL_HOURS", "168"))  # default 7 days
# Per-target entry cap (env override). One hot binary exploring 40 verbs
# should never grow past this; new inserts evict the oldest.
_MAX_ENTRIES_PER_TARGET = int(os.getenv("SNAPSHOT_MAX_ENTRIES", "200"))

# sha256 fingerprint memo: (abs_path, mtime_ns, size) -> digest.  Hashing a
# 40MB binary on every call would itself cost real time; this memo makes
# repeat calls against an unchanged file O(1).
_sha_memo: Dict[Tuple[str, int, int], str] = {}
_SHA_MEMO_MAX = 64


def default_db_path() -> Path:
    """Default snapshot DB location: <workspace>/run/analysis_snapshots.db."""
    root = resolve_workspace_root()
    run_dir = root / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir / "analysis_snapshots.db"


class SnapshotStore:
    """Content-keyed cache of successful analysis results.

    Thread-safe enough for framework use: one connection with
    ``check_same_thread=False`` + busy_timeout (same pattern as
    ScratchStore).  Construction is cheap and the schema init is idempotent.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = str(db_path or default_db_path())
        self._repair_ownership_if_needed()
        self.conn = sqlite3.connect(self.db_path, timeout=10.0,
                                    check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA busy_timeout=10000")
        for _attempt in range(5):
            try:
                mode = self.conn.execute("PRAGMA journal_mode").fetchone()[0]
                if str(mode).lower() != "wal":
                    self.conn.execute("PRAGMA journal_mode=WAL")
                break
            except sqlite3.OperationalError:
                time.sleep(0.05 * (_attempt + 1))
        self._init_table()

    def _repair_ownership_if_needed(self) -> None:
        """Best-effort chown of a root-owned DB back to the workspace owner.

        Mirrors utils/scratch_store.py: a prior root run (masscan/packetcraft)
        leaves run/analysis_snapshots.db root-owned, and WAL mode then fails
        for non-root processes.  When running AS root, chown back; otherwise
        warn once.  Never raises.
        """
        db_p = Path(self.db_path)
        try:
            ws_stat = resolve_workspace_root().stat()
            target_uid, target_gid = ws_stat.st_uid, ws_stat.st_gid
        except OSError:
            return
        if target_uid == 0:
            return
        needs_repair = False
        for f in (db_p, db_p.with_name(db_p.name + "-wal"),
                  db_p.with_name(db_p.name + "-shm")):
            try:
                if f.exists() and f.stat().st_uid == 0:
                    needs_repair = True
                    break
            except OSError:
                pass
        if not needs_repair:
            return
        if os.geteuid() == 0:
            try:
                import subprocess
                for f in (db_p, db_p.with_name(db_p.name + "-wal"),
                          db_p.with_name(db_p.name + "-shm")):
                    if f.exists():
                        subprocess.run(
                            ["chown", f"{target_uid}:{target_gid}", str(f)],
                            check=False, capture_output=True, timeout=5,
                        )
            except Exception:
                pass
        else:
            logger.warning(
                "[snapshots] %s is root-owned but the framework runs as "
                "uid=%d; snapshot caching will fail writes until repaired "
                "(run once as root or chown manually).",
                db_p, os.geteuid(),
            )

    def _init_table(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS snapshots (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                cache_key   TEXT NOT NULL,
                content_key TEXT NOT NULL,
                op_key      TEXT NOT NULL,
                target_sig  TEXT NOT NULL,
                result      TEXT NOT NULL,
                created_at  REAL NOT NULL,
                hits        INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        self.conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_snap_key "
            "ON snapshots(cache_key)"
        )
        self.conn.commit()

    # -- read ---------------------------------------------------------------

    def lookup(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Return the cached result dict for ``cache_key``, or None.

        A hit bumps the ``hits`` counter (purely observational).  Returns a
        fresh dict each call — callers may mutate freely.
        """
        row = self.conn.execute(
            "SELECT id, result FROM snapshots WHERE cache_key = ?",
            (cache_key,),
        ).fetchone()
        if row is None:
            return None
        try:
            with self.conn:
                self.conn.execute(
                    "UPDATE snapshots SET hits = hits + 1 WHERE id = ?",
                    (row["id"],),
                )
        except sqlite3.Error:
            pass  # hit counting is observational, never fatal
        try:
            return json.loads(row["result"])
        except (ValueError, TypeError):
            return None

    # -- write --------------------------------------------------------------

    def put(
        self,
        cache_key: str,
        content_key: str,
        op_key: str,
        target_sig: str,
        result: Dict[str, Any],
    ) -> bool:
        """Store a successful result under ``cache_key``.

        Uses INSERT OR REPLACE so a re-computed result overwrites cleanly.
        Enforces the per-target entry cap by evicting the oldest rows with
        the same ``content_key``.  Returns True when stored.
        """
        try:
            payload = json.dumps(result, default=str)
            with self.conn:
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO snapshots
                        (cache_key, content_key, op_key, target_sig,
                         result, created_at, hits)
                    VALUES (?, ?, ?, ?, ?, ?, 0)
                    """,
                    (cache_key, content_key, op_key, target_sig,
                     payload, time.time()),
                )
                self._enforce_cap(content_key)
            return True
        except sqlite3.Error as exc:
            logger.warning("[snapshots] store failed for key=%s: %s",
                           op_key, exc)
            return False

    def _enforce_cap(self, content_key: str) -> None:
        """Evict the oldest rows beyond the per-target cap (call inside tx)."""
        cur = self.conn.execute(
            "SELECT COUNT(*) FROM snapshots WHERE content_key = ?",
            (content_key,),
        )
        excess = cur.fetchone()[0] - _MAX_ENTRIES_PER_TARGET
        if excess > 0:
            self.conn.execute(
                """
                DELETE FROM snapshots WHERE id IN (
                    SELECT id FROM snapshots WHERE content_key = ?
                    ORDER BY created_at ASC LIMIT ?
                )
                """,
                (content_key, excess),
            )

    def purge_expired(self) -> int:
        """Delete rows past TTL. Called opportunistically on put()/stats()."""
        cutoff = time.time() - _TTL_HOURS * 3600
        try:
            with self.conn:
                cur = self.conn.execute(
                    "DELETE FROM snapshots WHERE created_at < ?", (cutoff,)
                )
                return cur.rowcount
        except sqlite3.Error:
            return 0

    def stats(self) -> Dict[str, Any]:
        """Observed cache statistics (for the doctor/health surface)."""
        try:
            row = self.conn.execute(
                """
                SELECT COUNT(*) AS entries,
                       COALESCE(SUM(hits), 0) AS hits,
                       COALESCE(SUM(CASE WHEN created_at < ? THEN 1 ELSE 0 END), 0)
                           AS expired
                FROM snapshots
                """,
                (time.time() - _TTL_HOURS * 3600,),
            ).fetchone()
            return {
                "entries": row["entries"],
                "hits": row["hits"],
                "expired": row["expired"],
                "ttl_hours": _TTL_HOURS,
                "max_entries_per_target": _MAX_ENTRIES_PER_TARGET,
            }
        except sqlite3.Error:
            return {"entries": 0, "hits": 0, "expired": 0, "error": True}

    def clear(self) -> int:
        """Wipe all snapshots (operator/debug). Returns rows deleted."""
        try:
            with self.conn:
                cur = self.conn.execute("DELETE FROM snapshots")
                return cur.rowcount
        except sqlite3.Error:
            return 0

    def close(self) -> None:
        try:
            self.conn.close()
        except sqlite3.Error:
            pass


# --- singleton -------------------------------------------------------------

_store: Optional[SnapshotStore] = None


def get_snapshot_store() -> SnapshotStore:
    """Process-wide singleton (mirrors scratch_store.get_store)."""
    global _store
    if _store is None:
        _store = SnapshotStore()
    return _store


# --- key helpers -----------------------------------------------------------

def sha256_of_file(
    path: str, st: Optional[os.stat_result] = None
) -> Optional[str]:
    """SHA-256 of a file's bytes, memoized on (path, mtime_ns, size).

    Returns None when the file cannot be read.  The memo makes repeat calls
    against an unchanged file O(1); 64 entries bound its memory use.
    """
    try:
        st = st if st is not None else os.stat(path)
        memo_key = (os.path.abspath(path), st.st_mtime_ns, st.st_size)
        cached = _sha_memo.get(memo_key)
        if cached is not None:
            return cached
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        digest = h.hexdigest()
        if len(_sha_memo) >= _SHA_MEMO_MAX:
            _sha_memo.clear()  # crude but bounded; re-hash cost is rare
        _sha_memo[memo_key] = digest
        return digest
    except OSError:
        return None


def build_cache_key(content_key: str, op_key: str) -> str:
    """Deterministic cache key: sha256(content_key + '|' + op_key)."""
    return hashlib.sha256(f"{content_key}|{op_key}".encode()).hexdigest()