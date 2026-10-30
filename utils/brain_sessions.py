"""Durable agent→Brain-session resolution (Phase 0 substrate).

``daharness/executor.py:_resolve_brain_session`` keeps `_brain_session_map`
in gateway process memory: a restart re-mints ints, so the SAME agent id
can land on a DIFFERENT Brain session int after a restart. In-process
dispatchers (REPL, kernel, Brain) never share the map at all — the same
agent id resolves differently per process.

That maps cleanly onto scratch-store conventions: one SQLite table,
agent-scoped rows, deterministic, cheap. The map is keyed by (workspace,
agent_id); distinct workspaces (deb lane vs git checkout vs tests) get
disjoint int spaces.

Wire compat: the Brain protocol carries session_id as a C int via
``FrameworkEvent.session_id``. This module only manages the assignment
agent_id -> stable int; it knows nothing about sockets. Small ints
starting at 1 (``"0"`` short-circuits to 0 upstream, so 0 stays the
shared session forever — do not change that).

Degraded-fallback int space (2026-10-29): a lane whose store is broken
still resolves (dispatch must not break over observability) via a
process-local mint. Those ints used to be plain ascending ints,
indistinguishable from durable-store ints — a cross-lane collision:
with lane A degraded, agent X minted fallback int 7 while the healthy
map had already durably assigned 7 to agent Y, so X's calls landed in
Y's Brain-side session instances (shared stateful handles). The wire
pins the value to an int, so the fix namespaces the SPACE, not the
format: fallback ints come from a high per-instance-random band
(``_FALLBACK_BAND_BASE + token + n``) that durable ints (ascending
from 1) cannot realistically reach. Cross-agent collision is gone in
both directions; the honest cost, stated plainly: a degraded lane
loses cross-lane session continuity for agents it mints during the
outage (its int means nothing to a store-resolved lane), and degraded
mints evaporate on restart — exactly the pre-Phase-0 behavior the
fallback was meant to preserve, minus the collision.
"""

from __future__ import annotations

import os
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from constants import resolve_workspace_root

_DEFAULT_ROOT = resolve_workspace_root()
_DEFAULT_DB = _DEFAULT_ROOT / "run" / "brain_sessions.db"

# Degraded fallback band (module docstring). Base keeps the band above any
# plausible durable space; randbits(28) + base stays below 2**30, far under
# the C-int wire ceiling (2**31 - 1). Two degraded instances collide only
# if their random tokens coincide AND the same counter slot meets the same
# agent — negligible; a durable space reaches the band only past 100M
# agents in ONE workspace.
_FALLBACK_BAND_BASE = 100_000_000


def _set_wal(c: sqlite3.Connection) -> None:
    """Tolerate the first-converter WAL race (see fleet_scheduler._set_wal).

    The delete→WAL conversion can return SQLITE_BUSY immediately — the
    busy handler does not cover journal-mode conversion — and losing the
    race means the winner already converted, so a mode readback is the
    acceptance test. Only surface the error if the db is truly not WAL.
    """
    for attempt in range(3):
        try:
            c.execute("PRAGMA journal_mode=WAL")
            return
        except sqlite3.OperationalError:
            row = c.execute("PRAGMA journal_mode").fetchone()
            if row is not None and (row[0] or "").lower() == "wal":
                return
            time.sleep(0.05 * (attempt + 1))
    row = c.execute("PRAGMA journal_mode").fetchone()
    if row is None or (row[0] or "").lower() != "wal":
        c.execute("PRAGMA journal_mode=WAL")  # surface the real error


class BrainSessionMap:
    """SQLite-backed (agent_id, workspace) -> stable Brain session int.

    One connection, ``check_same_thread=False`` + busy_timeout, WAL — the
    gateway / executor / Brain lanes hit it concurrently. Failures never
    break dispatch: on any store error the resolver degrades to a
    process-local fallback (the pre-existing behavior) and reports why.

    Degraded-fallback ints are namespaced in a high per-instance-random
    band (module docstring) — never equal to a durable-store int, so a
    degraded lane cannot route onto another agent's Brain session.
    """

    def __init__(self, db_path: str = str(_DEFAULT_DB)):
        self.db_path = str(db_path)
        self._fallback_lock = threading.RLock()  # reentrant: resolve() holds it while minting a slot
        self._fallback_map: dict[str, int] = {}
        self._fallback_next = 0
        self._fallback_failures = 0
        # Per-instance random offset into the fallback band: one instance
        # keeps one space across its (possibly repeating) store failures.
        self._fallback_token = secrets.randbits(28)
        self.workspace = str(_DEFAULT_ROOT)
        # The whole construction degrades, not just the connect: an
        # unwritable parent (root-owned deb tree fallback, full disk) can
        # make the mkdir itself raise BEFORE sqlite3 is ever called.
        try:
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA busy_timeout=10000")
            _set_wal(self.conn)
            self._init_table()
            self.degraded = False
        except (sqlite3.Error, OSError) as exc:
            # run/ unwritable (root-owned deb tree with no /var/lib path
            # resolved, disk full, ...), un-openable path — degrade to
            # process-local.
            self.conn = None
            self.degraded = True
            self.degraded_reason = f"brain session store unavailable: {exc}"

    def _init_table(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS brain_sessions (
                agent_id    TEXT NOT NULL,
                workspace   TEXT NOT NULL,
                session_int INTEGER NOT NULL,
                created_at  REAL NOT NULL,
                last_seen   REAL NOT NULL,
                PRIMARY KEY (workspace, agent_id)
            )
            """
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_bs_last_seen ON brain_sessions(last_seen)"
        )
        self.conn.commit()

    # -- resolution ----------------------------------------------------------

    def resolve(self, agent_id: str) -> int:
        """Return the stable int for ``agent_id``, assigning the next slot
        on first sight. ``"0"`` (the shared session) is handled upstream by
        the executor and never reaches the store."""
        key = str(agent_id or "0")
        if key == "0":
            return 0
        if self.conn is not None:
            try:
                return self._resolve_in_store(key)
            except sqlite3.Error as exc:
                # Degradation: the store can fail not just at construction
                # (the constructor already degrades on that) but later — a
                # DB deleted/unmounted/read-only-flipped mid-process. Mark
                # the instance degraded so doctor/telemetry sees it, then
                # fall through to the fallback mapping.
                self.degraded = True
                self.degraded_reason = f"brain session store failed on resolve: {exc}"
                with self._fallback_lock:
                    self._fallback_failures += 1
                    first = self._fallback_failures == 1
                if first:
                    import logging

                    logging.getLogger(__name__).warning(
                        "[brain_sessions] store failed (%s); falling back to "
                        "process-local mapping for this process", exc,
                    )
        return self._resolve_in_fallback(key)

    def _resolve_in_store(self, key: str) -> int:
        now = time.time()
        for attempt in range(2):
            row = self.conn.execute(
                "SELECT session_int FROM brain_sessions "
                "WHERE workspace = ? AND agent_id = ?",
                (self.workspace, key),
            ).fetchone()
            if row is not None:
                self.conn.execute(
                    "UPDATE brain_sessions SET last_seen = ? "
                    "WHERE workspace = ? AND agent_id = ?",
                    (now, self.workspace, key),
                )
                self.conn.commit()
                return int(row["session_int"])
            try:
                with self.conn:
                    self.conn.execute(
                        "INSERT INTO brain_sessions "
                        "(agent_id, workspace, session_int, created_at, last_seen) "
                        "VALUES (?, ?, "
                        "COALESCE((SELECT MAX(session_int) FROM brain_sessions "
                        "WHERE workspace = ?), 0) + 1, ?, ?)",
                        (key, self.workspace, self.workspace, now, now),
                    )
                row = self.conn.execute(
                    "SELECT session_int FROM brain_sessions "
                    "WHERE workspace = ? AND agent_id = ?",
                    (self.workspace, key),
                ).fetchone()
                if row is not None:
                    return int(row["session_int"])
            except sqlite3.IntegrityError:
                continue  # concurrent first-sight — retry the SELECT
            except sqlite3.Error:
                # e.g. read-only DB: the UPDATE above already raised; the
                # outer loop retries once, then the caller degrades.
                raise
        raise sqlite3.InternalError("brain session slot assignment failed twice")

    def _fallback_next_slot(self) -> int:
        with self._fallback_lock:
            self._fallback_next += 1
            return _FALLBACK_BAND_BASE + self._fallback_token + self._fallback_next

    def _resolve_in_fallback(self, key: str) -> int:
        with self._fallback_lock:
            got = self._fallback_map.get(key)
            if got is not None:
                return got
            slot = self._fallback_next_slot()
            self._fallback_map[key] = slot
            return slot

    # -- introspection / lifecycle -------------------------------------------

    def list_sessions(self) -> dict[str, Any]:
        """Diagnostics for framework_doctor: known agents + slot usage."""
        if self.conn is None:
            return {
                "degraded": True,
                "degraded_reason": getattr(self, "degraded_reason", ""),
                "fallback_band_base": _FALLBACK_BAND_BASE,
                "agents": {k: v for k, v in sorted(self._fallback_map.items())},
            }
        rows = self.conn.execute(
            "SELECT agent_id, session_int, created_at, last_seen "
            "FROM brain_sessions WHERE workspace = ? ORDER BY session_int",
            (self.workspace,),
        ).fetchall()
        return {
            "degraded": False,
            "db": self.db_path,
            "agents": [
                {
                    "agent_id": r["agent_id"],
                    "session_int": r["session_int"],
                    "created_at": r["created_at"],
                    "last_seen": r["last_seen"],
                }
                for r in rows
            ],
        }

    def close(self) -> None:
        if self.conn is not None:
            self.conn.close()


# --- Module-level singleton (lazy) -------------------------------------------

_map: BrainSessionMap | None = None


def get_brain_session_map() -> BrainSessionMap:
    """Return the process-wide BrainSessionMap singleton.

    Env ``BRAIN_SESSIONS_DB`` overrides the path (tests use this to point
    at a tmp file and to reset the singleton for isolation).
    """
    global _map
    override = os.getenv("BRAIN_SESSIONS_DB", "").strip()
    if override:
        return BrainSessionMap(db_path=override)
    if _map is None:
        _map = BrainSessionMap()
    return _map