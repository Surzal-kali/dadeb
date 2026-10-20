"""Scratch store: durable, ownership-scoped storage for raw tool results.

The scratch store is the **raw evidence layer** — the durable home for full
tool outputs that are too large to enter the model's context window.  It is
NOT vector memory (no embeddings, no semantic recall) and NOT the findings
store (no reportable evidence lifecycle).  It is a deterministic,
reference-keyed store the model retrieves from via ``scratch_search`` when
it needs the full or filtered output of a prior tool call.

Design (see RFC 2026-10-01):
    scratch.db         metadata, ownership, expiry, indexes
    scratch-data/      compressed JSON payloads (0700 dir, 0600 files)

IDs are opaque random values (``scratch:<16-hex>``), never sequential, so a
guess from another chat cannot leak data.  Every entry is scoped to its
originating ``agent_id``; a valid-looking ref from the wrong agent returns
"not found", not the payload.

Persistence: entries survive a framework restart (on-disk).  TTL-based
expiry (default 24h, env ``SCRATCH_TTL_HOURS``) bounds disk growth; a
cleanup sweep runs on every ``store()`` call and is also safe to call
standalone.  The payload is written to a temp file, fsynced, atomically
renamed, then the metadata row is committed — a crash never leaves a
torn entry.

Per-entry cap: ``SCRATCH_MAX_PAYLOAD_MB`` (default 256).  Per-agent cap:
``SCRATCH_MAX_AGENT_MB`` (default 1024).  Both are soft-enforced at store
time; a result exceeding the per-entry cap is stored truncated with a
stated policy (the model is told what was dropped).
"""

from __future__ import annotations

import gzip
import json
import os
import re
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from constants import resolve_workspace_root

_DEFAULT_ROOT = resolve_workspace_root()
_DEFAULT_DB = _DEFAULT_ROOT / "scratch.db"
_DEFAULT_DATA_DIR = _DEFAULT_ROOT / "scratch-data"

_TTL_HOURS = float(os.getenv("SCRATCH_TTL_HOURS", "24"))
_MAX_PAYLOAD_BYTES = int(os.getenv("SCRATCH_MAX_PAYLOAD_MB", "256")) * 1024 * 1024
_MAX_AGENT_BYTES = int(os.getenv("SCRATCH_MAX_AGENT_MB", "1024")) * 1024 * 1024

_SCHEMA_VERSION = 1


class ScratchStore:
    """SQLite-metadata + compressed-file-payload scratch store.

    Thread-safe (one connection, ``check_same_thread=False`` + busy_timeout).
    Safe to construct lazily / per-call; the connection is cheap and the
    schema init is idempotent.
    """

    def __init__(
        self,
        db_path: str = str(_DEFAULT_DB),
        data_dir: str = str(_DEFAULT_DATA_DIR),
    ):
        self.db_path = db_path
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # --- Root guard: repair ownership corrupted by a prior root run. ---
        # When the framework runs as root (masscan/packetcraft need it), every
        # file the process creates — including scratch.db, scratch.db-wal,
        # scratch.db-shm, and scratch-data/*.json.gz — becomes root-owned.
        # The NEXT non-root run then gets "attempt to write a readonly
        # database" because SQLite WAL mode needs write access to all three
        # DB files, and the projection layer silently degrades to uncapped
        # passthrough (the context-blowup root cause we hit on 2026-10-03).
        #
        # Fix (mirrors bootstrap.py's ZAP root guard): when we're root, chown
        # the DB files + data dir back to the user who owns the workspace
        # root BEFORE opening the connection.  If we're NOT root and the
        # files are root-owned (a prior root run corrupted them), warn loudly
        # — the operator needs to chown manually or restart as root once to
        # trigger the repair.
        self._repair_ownership_if_needed()

        try:
            os.chmod(self.data_dir, 0o700)
        except OSError:
            pass  # non-POSIX or not owner — best-effort

        self.conn = sqlite3.connect(db_path, timeout=10.0, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA busy_timeout=10000")
        self.conn.execute("PRAGMA journal_mode=WAL")
        self._init_table()

    def _repair_ownership_if_needed(self) -> None:
        """Chown scratch DB + WAL + SHM + data dir back to the workspace owner.

        Runs at construction time.  When the framework is root, root-created
        files (scratch.db, -wal, -shm, scratch-data/) are chowned back to the
        user who owns the WORKSPACE_ROOT directory.  When the framework is
        NOT root but the files are root-owned (corrupted by a prior root run),
        a warning is logged — the non-root process can't chown, so the
        operator must either restart as root (which triggers this repair) or
        chown manually.  Silent on success; never raises (a failed chown is
        logged but doesn't block the store — the projection layer degrades
        gracefully to field-capping without scratch).
        """
        import logging

        log = logging.getLogger(__name__)
        db_p = Path(self.db_path)
        workspace_root = resolve_workspace_root()

        # Determine the target owner: the UID of the workspace root dir.
        try:
            ws_stat = workspace_root.stat()
            target_uid = ws_stat.st_uid
            target_gid = ws_stat.st_gid
        except OSError:
            return  # can't stat workspace — nothing to do

        if target_uid == 0:
            # Workspace is root-owned (e.g. /opt/framework) — no mismatch to
            # fix; root running on a root-owned workspace is consistent.
            return

        is_root = os.geteuid() == 0
        files_to_check = [
            db_p,
            db_p.with_suffix(".db-wal"),
            db_p.with_suffix(".db-shm"),
            self.data_dir,
        ]

        needs_repair = False
        for f in files_to_check:
            try:
                if f.exists() and f.stat().st_uid == 0:
                    needs_repair = True
                    break
            except OSError:
                pass

        if not needs_repair:
            return

        if not is_root:
            log.warning(
                "[scratch] %s and/or WAL/SHM files are root-owned but the "
                "framework is running as non-root (uid=%d). SQLite WAL mode "
                "needs write access to all three DB files. The projection "
                "layer will degrade to field-capping without scratch storage "
                "(context may blow up on large results). Fix: run once as "
                "root to trigger the auto-repair, or run: sudo chown -R "
                "%d:%d %s %s/",
                db_p, os.geteuid(), target_uid, target_gid, db_p, self.data_dir,
            )
            return

        # We're root and the files are root-owned but the workspace owner is
        # non-root — chown everything back.
        import subprocess

        chown_spec = f"{target_uid}:{target_gid}"
        for f in files_to_check:
            if f.exists():
                try:
                    subprocess.run(
                        ["chown", chown_spec, str(f)],
                        check=False, capture_output=True, timeout=5,
                    )
                except Exception:
                    pass  # best-effort; projection degrades gracefully

        # Also chown the data dir contents (compressed payloads).
        try:
            subprocess.run(
                ["chown", "-R", chown_spec, str(self.data_dir)],
                check=False, capture_output=True, timeout=10,
            )
        except Exception:
            pass

        log.info(
            "[scratch] Root guard: chowned scratch DB + WAL + SHM + data dir "
            "back to uid=%d (workspace owner). A prior root run had "
            "root-owned these files, which would make the next non-root run "
            "fail with 'readonly database'.",
            target_uid,
        )

    def _init_table(self) -> None:
        self.conn.execute(
            """
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
            """
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scratch_agent "
            "ON scratch_entries(agent_id, created_at DESC)"
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scratch_expiry "
            "ON scratch_entries(expires_at)"
        )
        self.conn.commit()

    # -- store --------------------------------------------------------------

    def store(
        self,
        result: Dict[str, Any],
        *,
        agent_id: str,
        tool_id: str,
        chat_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Persist a tool result and return a scratch reference envelope.

        The envelope is what the projection layer returns to the model when
        ``result_mode`` is ``digest`` or ``page`` — it carries the opaque
        reference plus the retrieval instruction.

        Returns ``{"scratch_ref": "scratch:...", "stored_bytes": N, ...}``.
        """
        self._cleanup_expired()

        # Serialize + compress the payload.
        raw_json = json.dumps(result, default=str, ensure_ascii=False).encode("utf-8")
        truncated = False
        original_bytes = len(raw_json)

        if len(raw_json) > _MAX_PAYLOAD_BYTES:
            # Truncate the serialized form — last resort.  The projection
            # layer's digest should prevent this in practice, but the store
            # must never OOM the box on a pathologically large result.
            raw_json = raw_json[:_MAX_PAYLOAD_BYTES]
            truncated = True

        compressed = gzip.compress(raw_json, compresslevel=6)

        # Per-agent cap: evict oldest entries for this agent until within budget.
        self._enforce_agent_cap(agent_id)

        # Generate an unguessable ID.
        scratch_id = secrets.token_hex(8)  # 16 hex chars
        ref = f"scratch:{scratch_id}"

        # Write the payload atomically: temp → fsync → rename.
        payload_filename = f"{scratch_id}.json.gz"
        payload_path = self.data_dir / payload_filename
        tmp_path = self.data_dir / f".{scratch_id}.tmp"

        with open(tmp_path, "wb") as fh:
            fh.write(compressed)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, payload_path)

        # Compute sha256 for integrity verification.
        import hashlib
        sha = hashlib.sha256(compressed).hexdigest()

        now = time.time()
        expires_at = now + _TTL_HOURS * 3600

        with self.conn:
            self.conn.execute(
                """
                INSERT INTO scratch_entries
                    (id, agent_id, chat_id, tool_id, created_at, expires_at,
                     content_type, byte_count, sha256, payload_path, schema_version)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scratch_id,
                    agent_id,
                    chat_id,
                    tool_id,
                    now,
                    expires_at,
                    "application/json+gzip",
                    len(compressed),
                    sha,
                    str(payload_path),
                    _SCHEMA_VERSION,
                ),
            )

        return {
            "scratch_ref": ref,
            "stored_bytes": len(compressed),
            "original_bytes": original_bytes,
            "truncated": truncated,
            "expires_at": expires_at,
            "tool_id": tool_id,
        }

    # -- retrieve -----------------------------------------------------------

    def retrieve(
        self,
        scratch_ref: str,
        *,
        agent_id: str,
        offset: int = 0,
        limit: int = 0,
        filter_pattern: Optional[str] = None,
        regex_pattern: Optional[str] = None,
        fields: Optional[str] = None,
        context_lines: int = 0,
    ) -> Dict[str, Any]:
        """Retrieve a stored result by reference.

        Returns the full payload (optionally paged/filtered) or an error
        envelope if the ref is unknown, expired, or belongs to a different
        agent.

        Args:
            scratch_ref: The ``scratch:<id>`` reference from a prior store.
            agent_id: The agent that owns the entry (ownership check).
            offset: Skip the first N items in a list-bearing result.
            limit: Return at most N items (0 = no limit, but the raw payload
                is still the full stored result).
            filter_pattern: Case-insensitive substring filter applied to
                list items AND long string fields (line-based grep —
                matching lines are returned, non-matching dropped).  When
                ``context_lines`` > 0, that many adjacent lines are kept
                around each match for readability.
            regex_pattern: Python regex applied to string fields
                (line-based).  Takes precedence over ``filter_pattern`` for
                string fields; list items are matched with ``re.search``.
                Invalid regex returns an error envelope.
            fields: Comma-separated field names to select (drops everything
                else).  Useful for web results where the model only needs
                ``body_head`` + ``http_status``, not the full cookie/header
                envelope.  Unknown field names are silently dropped.
            context_lines: Number of context lines to include before/after
                each grep match in string fields (``-A``/``-B`` combined,
                like ``grep -C``).  Default 0 = matches only.
        """
        scratch_id = self._parse_ref(scratch_ref)
        if scratch_id is None:
            return {
                "status": "error",
                "error": f"invalid scratch reference {scratch_ref!r}; expected 'scratch:<hex>'",
            }

        row = self.conn.execute(
            "SELECT * FROM scratch_entries WHERE id = ? AND agent_id = ?",
            (scratch_id, agent_id),
        ).fetchone()

        if row is None:
            # Check whether it exists for another agent (don't leak that fact).
            return {
                "status": "error",
                "error": (
                    f"scratch reference {scratch_ref!r} not found, expired, "
                    f"or not owned by this agent"
                ),
            }

        # Check expiry.
        if time.time() > row["expires_at"]:
            self._delete_entry(row)
            return {
                "status": "error",
                "error": f"scratch reference {scratch_ref!r} has expired",
            }

        payload_path = Path(row["payload_path"])
        if not payload_path.is_file():
            self._delete_entry(row)
            return {
                "status": "error",
                "error": f"scratch payload file missing for {scratch_ref!r}",
            }

        # Decompress + deserialize.
        try:
            with gzip.open(payload_path, "rb") as fh:
                raw = fh.read()
            result = json.loads(raw.decode("utf-8"))
        except (OSError, json.JSONDecodeError, gzip.BadGzipFile) as exc:
            return {
                "status": "error",
                "error": f"scratch payload corrupted for {scratch_ref!r}: {exc}",
            }

        # Apply field selection first (reduces work for filter/regex).
        if fields:
            wanted = {f.strip() for f in fields.split(",") if f.strip()}
            result = {k: v for k, v in result.items() if k in wanted}

        # Apply paging / filtering / regex if requested.
        if offset or limit or filter_pattern or regex_pattern:
            result = self._apply_projection(
                result, offset=offset, limit=limit,
                filter_pattern=filter_pattern, regex_pattern=regex_pattern,
                context_lines=context_lines,
            )

        return {
            "status": "ok",
            "scratch_ref": scratch_ref,
            "tool_id": row["tool_id"],
            "result": result,
        }

    # -- metadata (for listing / cleanup) -----------------------------------

    def list_entries(
        self, agent_id: str, limit: int = 20
    ) -> List[Dict[str, Any]]:
        """List recent scratch entries for an agent (metadata only, no payloads)."""
        rows = self.conn.execute(
            "SELECT id, tool_id, created_at, expires_at, byte_count "
            "FROM scratch_entries WHERE agent_id = ? "
            "ORDER BY created_at DESC LIMIT ?",
            (agent_id, limit),
        ).fetchall()
        return [
            {
                "scratch_ref": f"scratch:{r['id']}",
                "tool_id": r["tool_id"],
                "created_at": r["created_at"],
                "expires_at": r["expires_at"],
                "stored_bytes": r["byte_count"],
            }
            for r in rows
        ]

    def stats(self, agent_id: Optional[str] = None) -> Dict[str, Any]:
        """Return store statistics (global or per-agent)."""
        if agent_id:
            row = self.conn.execute(
                "SELECT COUNT(*) as count, COALESCE(SUM(byte_count),0) as bytes "
                "FROM scratch_entries WHERE agent_id = ?",
                (agent_id,),
            ).fetchone()
        else:
            row = self.conn.execute(
                "SELECT COUNT(*) as count, COALESCE(SUM(byte_count),0) as bytes "
                "FROM scratch_entries"
            ).fetchone()
        return {
            "entries": row["count"],
            "stored_bytes": row["bytes"],
            "ttl_hours": _TTL_HOURS,
            "data_dir": str(self.data_dir),
        }

    # -- cleanup ------------------------------------------------------------

    def cleanup_expired(self) -> int:
        """Public cleanup: delete expired entries. Returns count removed."""
        return self._cleanup_expired()

    def _cleanup_expired(self) -> int:
        """Delete entries past their expiry. Returns count removed."""
        now = time.time()
        rows = self.conn.execute(
            "SELECT * FROM scratch_entries WHERE expires_at < ?",
            (now,),
        ).fetchall()
        for row in rows:
            self._delete_entry(row)
        return len(rows)

    def _delete_entry(self, row: sqlite3.Row) -> None:
        """Delete one entry's metadata + payload file."""
        try:
            payload_path = Path(row["payload_path"])
            if payload_path.is_file():
                payload_path.unlink()
        except OSError:
            pass
        with self.conn:
            self.conn.execute(
                "DELETE FROM scratch_entries WHERE id = ?", (row["id"],)
            )

    def _enforce_agent_cap(self, agent_id: str) -> None:
        """Evict oldest entries for an agent until within the per-agent cap."""
        row = self.conn.execute(
            "SELECT COALESCE(SUM(byte_count),0) as total "
            "FROM scratch_entries WHERE agent_id = ?",
            (agent_id,),
        ).fetchone()
        total = row["total"] or 0
        if total <= _MAX_AGENT_BYTES:
            return
        # Evict oldest until within budget.
        rows = self.conn.execute(
            "SELECT * FROM scratch_entries WHERE agent_id = ? "
            "ORDER BY created_at ASC",
            (agent_id,),
        ).fetchall()
        for row in rows:
            if total <= _MAX_AGENT_BYTES:
                break
            total -= row["byte_count"]
            self._delete_entry(row)

    # -- projection helpers -------------------------------------------------

    def _apply_projection(
        self,
        result: Dict[str, Any],
        *,
        offset: int,
        limit: int,
        filter_pattern: Optional[str],
        regex_pattern: Optional[str] = None,
        context_lines: int = 0,
    ) -> Dict[str, Any]:
        """Apply paging/filtering/regex to a retrieved result.

        This is the generic fallback projection — it operates on the
        deserialized JSON structure.  Three field types are handled:

        - **List fields** (``open_ports``, ``rows``, ``recent_lines``):
          paged and filtered.  ``filter_pattern`` is a case-insensitive
          substring match; ``regex_pattern`` uses ``re.search``.
        - **Long string fields** (``body_head``, ``body``, ``log_text``):
          line-based grep.  Only matching lines are returned (plus
          ``context_lines`` adjacent lines when > 0).  This is the fix for
          web results — the model can pull just the CSRF lines out of a
          40KB HTML blob instead of getting a truncated first-16KB chunk.
        - **Short strings / non-list, non-string**: returned as-is.

        Tool-family digest adapters can produce richer projections, but this
        fallback ensures every stored result is retrievable without a custom
        adapter.
        """
        if not isinstance(result, dict):
            return result

        pattern_lower = filter_pattern.lower() if filter_pattern else None
        compiled_re = None
        if regex_pattern:
            try:
                compiled_re = re.compile(regex_pattern, re.IGNORECASE)
            except re.error as exc:
                return {
                    "status": "error",
                    "error": f"invalid regex pattern {regex_pattern!r}: {exc}",
                }

        paged_keys: List[str] = []
        grepped_keys: List[str] = []
        out = {}

        # Threshold for treating a string as grepable text vs. a short scalar.
        # Strings under this length are returned as-is (no point grepping 3
        # lines).  Tunable via env for edge cases.
        grep_threshold = int(os.getenv("SCRATCH_GREP_MIN_CHARS", "200"))

        for key, value in result.items():
            if isinstance(value, list) and (offset or limit or pattern_lower or compiled_re):
                filtered = value
                if pattern_lower:
                    filtered = [
                        item for item in filtered
                        if self._item_matches(item, pattern_lower)
                    ]
                elif compiled_re:
                    filtered = [
                        item for item in filtered
                        if self._item_matches_regex(item, compiled_re)
                    ]
                total = len(filtered)
                if offset:
                    filtered = filtered[offset:]
                if limit and limit > 0:
                    filtered = filtered[:limit]
                out[key] = filtered
                if offset or (limit and total > limit):
                    paged_keys.append(key)
            elif isinstance(value, str) and (pattern_lower or compiled_re) and len(value) >= grep_threshold:
                grepped = self._grep_string(value, pattern_lower, compiled_re, context_lines)
                out[key] = grepped
                grepped_keys.append(key)
            else:
                out[key] = value

        meta: Dict[str, Any] = {}
        if paged_keys:
            meta["paged_keys"] = paged_keys
            meta["offset"] = offset
            meta["limit"] = limit
        if grepped_keys:
            meta["grepped_keys"] = grepped_keys
            meta["filter"] = filter_pattern or regex_pattern
            meta["context_lines"] = context_lines
        if paged_keys or grepped_keys:
            meta["note"] = (
                "list fields were paged/filtered; text fields were grep-filtered "
                "to matching lines. Use offset/limit for more list items, "
                "or adjust filter/regex for different text matches."
            )
        if meta:
            out["_scratch_projection"] = meta

        return out

    @staticmethod
    def _item_matches(item: Any, pattern_lower: str) -> bool:
        """Case-insensitive substring match on a list item (str or dict)."""
        if isinstance(item, str):
            return pattern_lower in item.lower()
        if isinstance(item, dict):
            return any(
                pattern_lower in str(v).lower() for v in item.values()
            )
        return pattern_lower in str(item).lower()

    @staticmethod
    def _item_matches_regex(item: Any, compiled_re: "re.Pattern[str]") -> bool:
        """Regex match on a list item (str or dict)."""
        if isinstance(item, str):
            return compiled_re.search(item) is not None
        if isinstance(item, dict):
            return any(compiled_re.search(str(v)) is not None for v in item.values())
        return compiled_re.search(str(item)) is not None

    @staticmethod
    def _grep_string(
        text: str,
        pattern_lower: Optional[str],
        compiled_re: Optional["re.Pattern[str]"],
        context_lines: int,
    ) -> str:
        """Line-based grep on a long string field.

        Returns matching lines joined with ``\\n``.  When ``context_lines``
        > 0, includes that many lines before/after each match (``grep -C``
        semantics).  When no lines match, returns a short "no matches"
        note so the caller knows the filter ran but found nothing (vs. the
        filter silently doing nothing).
        """
        lines = text.split("\n")
        match_indices: List[int] = []
        for i, line in enumerate(lines):
            if compiled_re:
                if compiled_re.search(line):
                    match_indices.append(i)
            elif pattern_lower:
                if pattern_lower in line.lower():
                    match_indices.append(i)

        if not match_indices:
            return f"[no lines matched filter: {pattern_lower or (compiled_re.pattern if compiled_re else '')!r}]"

        if context_lines <= 0:
            return "\n".join(lines[i] for i in match_indices)

        # Build a set of indices to include (match ± context), preserving order.
        include: set = set()
        for idx in match_indices:
            lo = max(0, idx - context_lines)
            hi = min(len(lines) - 1, idx + context_lines)
            include.update(range(lo, hi + 1))

        result_lines: List[str] = []
        prev = -2
        for i in sorted(include):
            if i - prev > 1 and result_lines:
                result_lines.append("...")
            result_lines.append(lines[i])
            prev = i
        return "\n".join(result_lines)

    @staticmethod
    def _parse_ref(ref: str) -> Optional[str]:
        """Extract the hex ID from a ``scratch:<hex>`` reference."""
        if not isinstance(ref, str):
            return None
        if not ref.startswith("scratch:"):
            return None
        scratch_id = ref[len("scratch:"):]
        if not scratch_id or not all(c in "0123456789abcdef" for c in scratch_id):
            return None
        return scratch_id

    def close(self) -> None:
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# --- Module-level singleton (lazy) -----------------------------------------

_store: Optional[ScratchStore] = None


def get_store() -> ScratchStore:
    """Return the process-wide scratch store singleton."""
    global _store
    if _store is None:
        _store = ScratchStore()
    return _store