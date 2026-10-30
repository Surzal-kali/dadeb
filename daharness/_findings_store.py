"""Internal store-IO lane for :mod:`daharness.findings`.

DDL building blocks, SQLite connection/WAL/ownership setup, and the SQL
write/read helpers behind :class:`daharness.findings.FindingStore`.  Private
module — import from the facade instead; nothing here is part of the public
API.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from pathlib import Path
from uuid import uuid4

from constants import resolve_workspace_root

from .models import Finding

logger = logging.getLogger(__name__)

# -- DDL -------------------------------------------------------------------

FINDINGS_TABLE_DDL = """
            CREATE TABLE IF NOT EXISTS findings (
                id          TEXT PRIMARY KEY,
                title       TEXT NOT NULL,
                severity    TEXT NOT NULL,
                cwe         TEXT,
                asset       TEXT NOT NULL,
                evidence    TEXT,
                repro       TEXT,
                tool_chain  TEXT,
                memory_ref  TEXT,
                ts          TEXT NOT NULL
            )
            """

# A Finding records a conclusion; an Unknown records an explicit "I don't
# know yet" — an unprobed service, a credential not yet validated against
# other services, an ambiguous result, a scope question.  Same DB, separate
# table, so render_findings stays a conclusions report and the ledger never
# pollutes it.
UNKNOWNS_TABLE_DDL = """
            CREATE TABLE IF NOT EXISTS unknowns (
                id          TEXT PRIMARY KEY,
                question    TEXT NOT NULL,
                domain      TEXT NOT NULL DEFAULT 'general',
                asset       TEXT,
                context     TEXT,
                opened_by   TEXT,
                resolution  TEXT,
                resolved_by TEXT,
                status      TEXT NOT NULL DEFAULT 'open',
                ts          TEXT NOT NULL,
                closed_ts   TEXT
            )
            """

# ALTER TABLE ... ADD COLUMN is idempotent-safe: the existing columns are
# checked first and only the missing ones are added.  This lets the store
# work on both fresh databases and ones with legacy schema.
FINDINGS_MIGRATIONS = [
    ("status", "TEXT NOT NULL DEFAULT 'open'"),
    ("superseded_by", "TEXT"),
    ("closed_by", "TEXT"),
    ("closed_reason", "TEXT"),
    ("closed_ts", "TEXT"),
]

# Tables owned by utils.sessions.DatabaseManager, minted by the facade's
# ensure_ids_db preflight.
TARGETS_TABLE_DDL = """CREATE TABLE IF NOT EXISTS targets
            (id INTEGER PRIMARY KEY, ip_address TEXT, port INTEGER, status TEXT)"""

SESSIONS_TABLE_DDL = """CREATE TABLE IF NOT EXISTS sessions
            (id INTEGER PRIMARY KEY, target_id INTEGER, payload TEXT, status TEXT,
             start_time DATETIME, end_time DATETIME, note TEXT,
             FOREIGN KEY(target_id) REFERENCES targets(id))"""

NOTES_TABLE_DDL = """CREATE TABLE IF NOT EXISTS notes
            (id INTEGER PRIMARY KEY, target_id INTEGER, note TEXT,
             FOREIGN KEY(target_id) REFERENCES targets(id))"""

FINDING_INSERT_SQL = """
                        INSERT INTO findings
                            (id, title, severity, cwe, asset, evidence, repro,
                             tool_chain, memory_ref, ts, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')
                        """

FINDING_REOPEN_SQL = """
                    UPDATE findings
                    SET status = 'open', superseded_by = NULL,
                        closed_by = NULL, closed_reason = NULL,
                        closed_ts = NULL
                    WHERE id = ?
                    """

FINDING_CLOSE_SQL = """
                    UPDATE findings
                    SET status = ?, superseded_by = ?, closed_by = ?,
                        closed_reason = ?, closed_ts = ?
                    WHERE id = ?
                    """

VALID_FINDING_STATUSES = {"open", "closed", "superseded", "false_positive", "duplicate"}


def init_findings_tables(conn: sqlite3.Connection) -> None:
    """Create the findings + unknowns tables and apply lifecycle migrations."""
    conn.execute(FINDINGS_TABLE_DDL)
    conn.execute(UNKNOWNS_TABLE_DDL)
    existing_cols = {
        row[1]
        for row in conn.execute("PRAGMA table_info(findings)").fetchall()
    }
    for col_name, col_def in FINDINGS_MIGRATIONS:
        if col_name not in existing_cols:
            conn.execute(
                f"ALTER TABLE findings ADD COLUMN {col_name} {col_def}"
            )
    conn.commit()


def repair_db_ownership(db_path: str) -> None:
    """Chown ids.db + WAL + SHM back to the workspace owner.

    Mirrors utils/scratch_store.py and utils/cookie_jar.py.  When the
    framework runs as root, SQLite creates ids.db, ids.db-wal, and
    ids.db-shm as root-owned.  WAL mode needs write access to all three
    DB files; a subsequent non-root run can't write the WAL/SHM sidecars
    and gets "database is locked" instead of a clean permission error.

    ids.db is shared with utils/sessions.py and
    auxiliaries/framework_status.py — fixing it here covers all three
    callers since they open the same physical file.
    """
    db_p = Path(db_path)
    workspace_root = resolve_workspace_root()

    try:
        ws_stat = workspace_root.stat()
        target_uid = ws_stat.st_uid
        target_gid = ws_stat.st_gid
    except OSError:
        return

    if target_uid == 0:
        return  # workspace is root-owned; consistent

    is_root = os.geteuid() == 0
    files_to_check = [
        db_p,
        db_p.with_name(db_p.name + "-wal"),
        db_p.with_name(db_p.name + "-shm"),
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
        logger.warning(
            "[findings] %s and/or WAL/SHM files are root-owned but "
            "the framework is running as non-root (uid=%d). SQLite WAL "
            "mode needs write access to all three DB files. The findings "
            "store will fail with 'database is locked' on writes. Fix: "
            "run once as root to trigger the auto-repair, or run: "
            "sudo chown %d:%d %s %s-wal %s-shm",
            db_p, os.geteuid(), target_uid, target_gid, db_p, db_p, db_p,
        )
        return

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
                logging.getLogger(__name__).debug(
                    "swallowed exception in repair_db_ownership", exc_info=True)
    logger.info(
        "[findings] Root guard: chowned ids.db + WAL + SHM back to "
        "uid=%d (workspace owner). A prior root run had root-owned "
        "these files, which would make the next non-root run fail with "
        "'database is locked'.",
        target_uid,
    )


def mint_finding(
    conn: sqlite3.Connection,
    *,
    title: str,
    severity: str,
    asset: str,
    cwe: str | None,
    evidence: dict | None,
    repro: list[str] | None,
    tool_chain: list[str] | None,
    memory_ref: str | None,
    ts: str,
) -> Finding:
    """Insert a finding, recounting/retrying on a concurrent-ID collision."""
    # Concurrent adds (gateway + secretary + MCP clients all share
    # ids.db) can compute the same F-id; the PRIMARY KEY turns that
    # into a loud IntegrityError instead of a duplicate. Recount and
    # retry so the caller just gets their finding, slightly later.
    last_exc: BaseException | None = None
    for _attempt in range(10):
        cur = conn.execute("SELECT COUNT(*) FROM findings")
        finding_id = f"F-{cur.fetchone()[0] + 1:03d}"
        finding = Finding(
            id=finding_id,
            title=title,
            severity=severity,
            cwe=cwe,
            asset=asset,
            evidence=evidence or {},
            repro=repro or [],
            tool_chain=tool_chain or [],
            memory_ref=memory_ref,
            ts=ts,
        )
        try:
            with conn:  # atomic INSERT + commit
                conn.execute(
                    FINDING_INSERT_SQL,
                    (
                        finding.id,
                        finding.title,
                        finding.severity,
                        finding.cwe,
                        finding.asset,
                        json.dumps(finding.evidence),
                        json.dumps(finding.repro),
                        json.dumps(finding.tool_chain),
                        finding.memory_ref,
                        finding.ts,
                    ),
                )
            return finding
        except sqlite3.IntegrityError:
            finding.id = f"F-{uuid4()}"  # lost the id race - generate a new one and retry
        except sqlite3.OperationalError as exc:
            last_exc = exc  # e.g. 'database is locked' after busy_timeout
    if last_exc:
        raise last_exc
    raise RuntimeError("could not assign a unique finding ID after 3 attempts")


def row_to_finding(row: sqlite3.Row) -> Finding:
    return Finding(
        id=row["id"],
        title=row["title"],
        severity=row["severity"],
        cwe=row["cwe"],
        asset=row["asset"],
        evidence=json.loads(row["evidence"] or "{}"),
        repro=json.loads(row["repro"] or "[]"),
        tool_chain=json.loads(row["tool_chain"] or "[]"),
        memory_ref=row["memory_ref"],
        ts=row["ts"],
        status=row["status"] if "status" in row.keys() else "open",
        superseded_by=row["superseded_by"] if "superseded_by" in row.keys() else None,
        closed_by=row["closed_by"] if "closed_by" in row.keys() else None,
        closed_reason=row["closed_reason"] if "closed_reason" in row.keys() else None,
        closed_ts=row["closed_ts"] if "closed_ts" in row.keys() else None,
    )


def set_finding_lifecycle(
    conn: sqlite3.Connection,
    finding_id: str,
    status: str,
    superseded_by: str | None,
    closed_by: str | None,
    closed_reason: str | None,
    ts: str,
) -> None:
    """Persist a lifecycle transition (open branch clears the audit trail)."""
    with conn:
        if status == "open":
            # Reopening: clear the closure audit trail so we don't
            # overwrite the original closed_ts with the reopen time
            # and leave dangling closed_by / superseded_by pointers.
            conn.execute(FINDING_REOPEN_SQL, (finding_id,))
        else:
            conn.execute(
                FINDING_CLOSE_SQL,
                (status, superseded_by, closed_by, closed_reason, ts, finding_id),
            )


def supersede_chain(conn: sqlite3.Connection, finding_id: str) -> set:
    """Return the set of all IDs that ``finding_id`` is superseded by
    (transitively), for circular-chain detection."""
    seen = set()
    current = finding_id
    while current:
        if current in seen:
            break  # already detected a cycle in the existing chain
        seen.add(current)
        row = conn.execute(
            "SELECT superseded_by FROM findings WHERE id = ?", (current,)
        ).fetchone()
        current = row["superseded_by"] if row else None
    return seen