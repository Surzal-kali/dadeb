"""SQLite-backed findings store — the single source of truth for reported findings.

The store lives in ``ids.db`` (the same SQLite database used by
:class:`utils.sessions.DatabaseManager`).  Findings are written by the
``report_finding`` framework tool and read by ``render_findings``.  The full
Finding objects never enter the secretary model's context — only short
one-line pointers are stored in vector memory via ``remember_text``.

The markdown renderer in :meth:`FindingStore.render_markdown` doubles as a
bug-bounty submission draft and lab documentation, all from the same data.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from uuid import uuid4
from .models import Finding, Unknown
from constants import resolve_workspace_root

_DEFAULT_DB = str(Path(__file__).resolve().parent.parent / "ids.db")

logger = logging.getLogger(__name__)


def ensure_ids_db(db_path: str | None = None) -> Path:
    """Lazily create ``ids.db`` with every table owned by both
    :class:`~daharness.findings.FindingStore` and
    :class:`utils.sessions.DatabaseManager`.

    On a fresh checkout the file does not exist and nothing instantiates the
    two stores at boot time, so the first ``report_finding`` call (or worse,
    a ``framework_health`` probe) is what discovers the gap.  This function
    opens the database (creating it on first touch), runs every
    ``CREATE TABLE IF NOT EXISTS`` + migration in one short transaction, and
    returns the resolved path.  Idempotent — calling it on an existing DB is
    a no-op beyond the PRAGMA checks.

    Callers:
    - :meth:`FrameworkLoader.launch_all` (bootstrap preflight, right before
      the wordlist preflight)
    - ``framework_health`` (so the health probe reports the DB as up instead
      of "not found" on a fresh install)
    """
    path = Path(db_path) if db_path else Path(resolve_workspace_root()) / "ids.db"
    path.parent.mkdir(parents=True, exist_ok=True)

    # FindingStore handles WAL setup + ownership repair + the findings table
    # + lifecycle migrations; its __init__ already does all of this.  We
    # instantiate it (which creates/migrates the findings table) and then
    # add the targets/sessions/notes tables owned by DatabaseManager.
    store = FindingStore(str(path))
    try:
        conn = store.conn
        conn.execute(
            """CREATE TABLE IF NOT EXISTS targets
            (id INTEGER PRIMARY KEY, ip_address TEXT, port INTEGER, status TEXT)"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS sessions
            (id INTEGER PRIMARY KEY, target_id INTEGER, payload TEXT, status TEXT,
             start_time DATETIME, end_time DATETIME, note TEXT,
             FOREIGN KEY(target_id) REFERENCES targets(id))"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS notes
            (id INTEGER PRIMARY KEY, target_id INTEGER, note TEXT,
             FOREIGN KEY(target_id) REFERENCES targets(id))"""
        )
        conn.commit()
    finally:
        store.close()

    logger.info("[db] ids.db ready at %s", path)
    return path


class FindingStore:
    """Append-only findings store backed by a SQLite table in ``ids.db``."""

    def __init__(self, db_path: str = _DEFAULT_DB):
        self.db_path = db_path
        # Root guard (mirrors utils/scratch_store.py + utils/cookie_jar.py):
        # chown the DB + WAL + SHM files back to the workspace owner BEFORE
        # opening the connection.  A prior root run (bootstrap/IPython for
        # masscan/packetcraft) leaves these root-owned; WAL mode needs write
        # access to all three files, and a non-root process that can't write
        # the WAL/SHM sidecars gets "database is locked" instead of a clean
        # permission error.  ids.db is shared with utils/sessions.py and
        # auxiliaries/framework_status.py, so fixing it here covers all three.
        self._repair_ownership_if_needed()
        self.conn = sqlite3.connect(db_path, timeout=10.0)
        self.conn.row_factory = sqlite3.Row
        # busy_timeout FIRST so every later statement (including the WAL
        # pragma and table init) waits on locks instead of erroring out.
        self.conn.execute("PRAGMA busy_timeout=10000")
        # WAL: readers don't block the writer and vice versa across
        # processes (gateway, secretary, MCP clients all share ids.db).
        # Switching INTO wal mode requires the global write lock, so under
        # concurrent connects the pragma itself can raise 'database is
        # locked'. It only needs to happen once per database file: skip it
        # when the file is already WAL, and retry the connect loop below
        # otherwise.
        # Cold-start note: on a brand-new file every concurrent connect
        # sees non-WAL mode and races on the journal_mode pragma, which
        # needs an exclusive lock that busy_timeout does NOT cover. So the
        # whole setup retries; only the first process ever flips the file
        # into WAL, after which every later connect skips the pragma.
        for _attempt in range(5):
            try:
                mode = self.conn.execute("PRAGMA journal_mode").fetchone()[0]
                if str(mode).lower() != "wal":
                    self.conn.execute("PRAGMA journal_mode=WAL")
                self._init_table()
                break
            except sqlite3.OperationalError:
                if _attempt == 4:
                    raise
                self.conn.rollback()
                time.sleep(0.05 * (_attempt + 1))

    def _repair_ownership_if_needed(self) -> None:
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
        import logging
        log = logging.getLogger(__name__)
        db_p = Path(self.db_path)
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
            log.warning(
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
                    pass
        log.info(
            "[findings] Root guard: chowned ids.db + WAL + SHM back to "
            "uid=%d (workspace owner). A prior root run had root-owned "
            "these files, which would make the next non-root run fail with "
            "'database is locked'.",
            target_uid,
        )

    def _init_table(self) -> None:
        self.conn.execute(
            """
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
        )
        # --- unknown ledger (open questions, REA-style) -------------------
        # A Finding records a conclusion; an Unknown records an explicit "I
        # don't know yet" — an unprobed service, a credential not yet
        # validated against other services, an ambiguous result, a scope
        # question.  Same DB, separate table, so render_findings stays a
        # conclusions report and the ledger never pollutes it.
        self.conn.execute(
            """
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
        )
        # --- migrations: add lifecycle columns to pre-existing tables ---
        # ALTER TABLE ... ADD COLUMN is idempotent-safe: we check the existing
        # columns first and only add the ones that are missing.  This lets the
        # store work on both fresh databases and ones with legacy schema.
        existing_cols = {
            row[1]
            for row in self.conn.execute("PRAGMA table_info(findings)").fetchall()
        }
        migrations = [
            ("status", "TEXT NOT NULL DEFAULT 'open'"),
            ("superseded_by", "TEXT"),
            ("closed_by", "TEXT"),
            ("closed_reason", "TEXT"),
            ("closed_ts", "TEXT"),
        ]
        for col_name, col_def in migrations:
            if col_name not in existing_cols:
                self.conn.execute(
                    f"ALTER TABLE findings ADD COLUMN {col_name} {col_def}"
                )
        self.conn.commit()

    # -- unknown ledger (open questions) -----------------------------------

    _VALID_UNKNOWN_DOMAINS = {
        "recon", "web", "creds", "enum", "postex", "scope", "general",
    }
    _VALID_UNKNOWN_STATUSES = {"open", "resolved", "wontfix", "promoted"}

    def add_unknown(
        self,
        question: str,
        domain: str = "general",
        asset: str = "",
        context: str = "",
        opened_by: str = "",
    ) -> Unknown:
        """Record an open question and return the minted Unknown (U-001 style id)."""
        domain = (domain or "general").strip().lower()
        if domain not in self._VALID_UNKNOWN_DOMAINS:
            raise ValueError(
                f"Invalid domain {domain!r}. Must be one of: "
                f"{', '.join(sorted(self._VALID_UNKNOWN_DOMAINS))}"
            )
        ts = datetime.now(timezone.utc).isoformat()

        # Same lost-id race handling as findings.add: concurrent writers
        # (gateway + secretary + MCP clients share ids.db) can compute the
        # same U-id; the PRIMARY KEY turns that into a loud IntegrityError
        # and we recount/retry.
        last_exc: Optional[BaseException] = None
        unknown: Optional[Unknown] = None
        for _attempt in range(10):
            cur = self.conn.execute("SELECT COUNT(*) FROM unknowns")
            unknown_id = f"U-{cur.fetchone()[0] + 1:03d}"
            unknown = Unknown(
                id=unknown_id,
                question=question,
                domain=domain,
                asset=asset or "",
                context=context or "",
                opened_by=opened_by or "",
                ts=ts,
            )
            try:
                with self.conn:  # atomic INSERT + commit
                    self.conn.execute(
                        """
                        INSERT INTO unknowns
                            (id, question, domain, asset, context, opened_by,
                             resolution, resolved_by, status, ts, closed_ts)
                        VALUES (?, ?, ?, ?, ?, ?, '', '', 'open', ?, '')
                        """,
                        (
                            unknown.id,
                            unknown.question,
                            unknown.domain,
                            unknown.asset,
                            unknown.context,
                            unknown.opened_by,
                            unknown.ts,
                        ),
                    )
                return unknown
            except sqlite3.IntegrityError:
                unknown.id = f"U-{uuid4()}"  # lost the id race - retry
            except sqlite3.OperationalError as exc:
                last_exc = exc  # e.g. 'database is locked' after busy_timeout
        if last_exc:
            raise last_exc
        raise RuntimeError("could not assign a unique unknown ID after retries")

    @staticmethod
    def _row_to_unknown(row) -> Unknown:
        return Unknown(
            id=row["id"],
            question=row["question"],
            domain=row["domain"],
            asset=row["asset"] or "",
            context=row["context"] or "",
            opened_by=row["opened_by"] or "",
            resolution=row["resolution"] or "",
            resolved_by=row["resolved_by"] or "",
            status=row["status"],
            ts=row["ts"],
            closed_ts=row["closed_ts"] or "",
        )

    def unknowns(
        self,
        status: Optional[str] = None,
        domain: Optional[str] = None,
        asset: Optional[str] = None,
        include_closed: bool = True,
    ) -> List[Unknown]:
        """List unknowns, oldest first, optionally filtered.

        ``include_closed=False`` returns only open unknowns — the "what
        haven't we answered yet" view.  Statuses: open|resolved|wontfix|promoted.
        """
        rows = self.conn.execute(
            "SELECT * FROM unknowns ORDER BY CAST(SUBSTR(id, 3) AS INTEGER) ASC"
        ).fetchall()
        items = [self._row_to_unknown(r) for r in rows]
        if status:
            items = [u for u in items if u.status == status]
        if domain:
            items = [u for u in items if u.domain == domain.lower()]
        if asset:
            items = [u for u in items if asset.lower() in u.asset.lower()]
        if not include_closed:
            items = [u for u in items if u.status == "open"]
        return items

    def get_unknown(self, unknown_id: str) -> Optional[Unknown]:
        row = self.conn.execute(
            "SELECT * FROM unknowns WHERE id = ?", (unknown_id,)
        ).fetchone()
        return self._row_to_unknown(row) if row else None

    def unknown_count(self) -> int:
        cur = self.conn.execute("SELECT COUNT(*) FROM unknowns")
        return cur.fetchone()[0]

    def resolve_unknown(
        self,
        unknown_id: str,
        status: str,
        resolution: str = "",
        resolved_by: str = "",
    ) -> Optional[Unknown]:
        """Resolve/close an unknown.

        status: resolved (answered), wontfix (never pursuing), promoted
        (answered AND became a finding — pass the finding ID via ``resolved_by``
        so the report can link them).
        """
        status = (status or "").strip().lower()
        if status not in self._VALID_UNKNOWN_STATUSES:
            raise ValueError(
                f"Invalid status {status!r}. Must be one of: "
                f"{', '.join(sorted(self._VALID_UNKNOWN_STATUSES))}"
            )
        if status == "promoted" and not resolved_by:
            raise ValueError("promoted requires resolved_by (the finding ID it became)")
        closed_ts = datetime.now(timezone.utc).isoformat()
        with self.conn:
            cur = self.conn.execute(
                """
                UPDATE unknowns
                SET status = ?, resolution = ?, resolved_by = ?, closed_ts = ?
                WHERE id = ?
                """,
                (status, resolution, resolved_by, closed_ts, unknown_id),
            )
            if cur.rowcount == 0:
                return None
        return self.get_unknown(unknown_id)

    # -- write --------------------------------------------------------------

    def add(
        self,
        title: str,
        severity: str,
        asset: str,
        cwe: Optional[str] = None,
        evidence: Optional[dict] = None,
        repro: Optional[List[str]] = None,
        tool_chain: Optional[List[str]] = None,
        memory_ref: Optional[str] = None,
    ) -> Finding:
        """Append a finding, auto-assigning an incremental ID and timestamp."""
        ts = datetime.now(timezone.utc).isoformat()

        # Concurrent adds (gateway + secretary + MCP clients all share
        # ids.db) can compute the same F-id; the PRIMARY KEY turns that
        # into a loud IntegrityError instead of a duplicate. Recount and
        # retry so the caller just gets their finding, slightly later.
        last_exc: Optional[BaseException] = None
        for _attempt in range(10):
            cur = self.conn.execute("SELECT COUNT(*) FROM findings")
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
                with self.conn:  # atomic INSERT + commit
                    self.conn.execute(
                        """
                        INSERT INTO findings
                            (id, title, severity, cwe, asset, evidence, repro,
                             tool_chain, memory_ref, ts, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')
                        """,
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

    # -- read ---------------------------------------------------------------

    def all(self) -> List[Finding]:
        """Return all findings, oldest first (numeric ID order)."""
        # Sort by the integer portion of the ID (F-001 → 1, F-1000 → 1000)
        # so F-1000 doesn't sort before F-999 as it would lexicographically.
        rows = self.conn.execute(
            "SELECT * FROM findings ORDER BY CAST(SUBSTR(id, 3) AS INTEGER) ASC"
        ).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def get(self, finding_id: str) -> Optional[Finding]:
        row = self.conn.execute(
            "SELECT * FROM findings WHERE id = ?", (finding_id,)
        ).fetchone()
        return self._row_to_finding(row) if row else None

    # -- lifecycle (close / supersede / reopen) ----------------------------

    _VALID_STATUSES = {"open", "closed", "superseded", "false_positive", "duplicate"}

    def update_status(
        self,
        finding_id: str,
        status: str,
        closed_by: Optional[str] = None,
        closed_reason: Optional[str] = None,
        superseded_by: Optional[str] = None,
    ) -> Optional[Finding]:
        """Update the lifecycle status of a finding.

        Args:
            finding_id: The finding ID (e.g. ``F-008``).
            status: One of open|closed|superseded|false_positive|duplicate.
            closed_by: Who/what closed it (agent name, role, etc.).
            closed_reason: Free-text explanation.
            superseded_by: When status is "superseded", the ID of the
                replacement finding.  The target finding must exist.

        Returns the updated :class:`Finding`, or ``None`` if not found.
        Raises ``ValueError`` for an invalid status or bad supersede target.
        """
        if status not in self._VALID_STATUSES:
            raise ValueError(
                f"Invalid status {status!r}. Must be one of: "
                f"{', '.join(sorted(self._VALID_STATUSES))}"
            )

        finding = self.get(finding_id)
        if finding is None:
            return None

        # Validate supersede / duplicate target
        if status == "superseded":
            if not superseded_by:
                raise ValueError("superseded_by is required when status is 'superseded'")
        if status in ("superseded", "duplicate") and superseded_by:
            replacement = self.get(superseded_by)
            if replacement is None:
                raise ValueError(f"Target finding {superseded_by} does not exist")
            if superseded_by == finding_id:
                raise ValueError("A finding cannot reference itself")

        # Prevent circular supersede chains
        if superseded_by and superseded_by != finding_id:
            chain = self._supersede_chain(superseded_by)
            if finding_id in chain:
                raise ValueError(
                    f"Circular supersede: {superseded_by} is itself superseded "
                    f"(directly or transitively) by {finding_id}"
                )

        ts = datetime.now(timezone.utc).isoformat()
        with self.conn:
            if status == "open":
                # Reopening: clear the closure audit trail so we don't
                # overwrite the original closed_ts with the reopen time
                # and leave dangling closed_by / superseded_by pointers.
                self.conn.execute(
                    """
                    UPDATE findings
                    SET status = 'open', superseded_by = NULL,
                        closed_by = NULL, closed_reason = NULL,
                        closed_ts = NULL
                    WHERE id = ?
                    """,
                    (finding_id,),
                )
            else:
                self.conn.execute(
                    """
                    UPDATE findings
                    SET status = ?, superseded_by = ?, closed_by = ?,
                        closed_reason = ?, closed_ts = ?
                    WHERE id = ?
                    """,
                    (status, superseded_by, closed_by, closed_reason, ts, finding_id),
                )
        return self.get(finding_id)

    def supersede(
        self,
        old_id: str,
        new_id: str,
        closed_by: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> dict:
        """Mark ``old_id`` as superseded by ``new_id``.

        This is the common case: an agent reports a refined/corrected finding
        and wants to close the older one with a pointer to the replacement.
        Both findings must already exist in the store.

        Returns ``{old: Finding, new: Finding}`` as dicts for convenience.
        """
        old = self.get(old_id)
        if old is None:
            raise ValueError(f"Finding {old_id} not found")
        new = self.get(new_id)
        if new is None:
            raise ValueError(f"Finding {new_id} not found")
        if old_id == new_id:
            raise ValueError("A finding cannot supersede itself")

        updated = self.update_status(
            old_id,
            status="superseded",
            closed_by=closed_by,
            closed_reason=reason or f"Superseded by {new_id}",
            superseded_by=new_id,
        )
        return {"old": updated, "new": new}

    def _supersede_chain(self, finding_id: str) -> set:
        """Return the set of all IDs that ``finding_id`` is superseded by
        (transitively), for circular-chain detection."""
        seen = set()
        current = finding_id
        while current:
            if current in seen:
                break  # already detected a cycle in the existing chain
            seen.add(current)
            row = self.conn.execute(
                "SELECT superseded_by FROM findings WHERE id = ?", (current,)
            ).fetchone()
            current = row["superseded_by"] if row else None
        return seen

    # -- read (with status awareness) ---------------------------------------

    def count(self) -> int:
        cur = self.conn.execute("SELECT COUNT(*) FROM findings")
        return cur.fetchone()[0]

    # -- render -------------------------------------------------------------

    def render_markdown(
        self,
        severity: Optional[str] = None,
        asset: Optional[str] = None,
        status: Optional[str] = None,
        include_closed: bool = True,
    ) -> str:
        """Render findings as a markdown report.

        Optionally filter by severity (e.g. ``"P1"``), asset substring, or
        status (e.g. ``"open"``).  When ``include_closed`` is ``False``,
        only open findings are shown regardless of the ``status`` filter —
        useful for a "current state" report that hides superseded / false
        positive / duplicate entries.

        The output is suitable as a bug-bounty submission draft or lab
        documentation.
        """
        findings = self.all()
        if severity:
            findings = [f for f in findings if f.severity == severity]
        if asset:
            findings = [f for f in findings if asset.lower() in f.asset.lower()]
        if status:
            findings = [f for f in findings if f.status == status]
        if not include_closed:
            findings = [f for f in findings if f.status == "open"]

        # Open questions from the unknown ledger — fetched up front so the
        # appendix can render even when no findings exist (early-days
        # engagement: nothing confirmed yet, but threads are already open).
        try:
            open_unknowns = self.unknowns(include_closed=False)
        except Exception:
            open_unknowns = []

        if not findings and not open_unknowns:
            return "_(no findings reported yet)_"

        if not findings:
            # Nothing confirmed yet, but the ledger has open threads — render
            # the report with the appendix instead of a bare no-findings line.
            lines = ["# Findings Report (no findings reported yet)", ""]
        else:
            # Status breakdown for the header
            open_count = sum(1 for f in findings if f.status == "open")
            closed_count = len(findings) - open_count
            header = f"# Findings Report ({len(findings)} finding(s)"
            if closed_count:
                header += f", {open_count} open / {closed_count} closed"
            header += ")"
            lines = [header, ""]

            # Summary table
            lines.append("| ID | Title | Severity | CWE | Asset | Status |")
            lines.append("|---|---|---|---|---|---|")
            for f in findings:
                status_cell = f.status
                if f.superseded_by:
                    status_cell += f" → {f.superseded_by}"
                lines.append(
                    f"| {f.id} | {f.title} | {f.severity} | {f.cwe or '—'} | {f.asset} | {status_cell} |"
                )
            lines.append("")

        for f in findings:
            status_tag = f" [{f.status}]" if f.status != "open" else ""
            lines.append(f"## {f.id}: {f.title} ({f.severity}){status_tag}")
            lines.append("")
            lines.append(f"**Asset:** {f.asset}")
            lines.append(f"**CWE:** {f.cwe or '—'}")
            lines.append(f"**Timestamp:** {f.ts}")
            if f.memory_ref:
                lines.append(f"**Memory ref:** {f.memory_ref}")
            if f.status != "open":
                lines.append(f"**Status:** {f.status}")
                if f.superseded_by:
                    lines.append(f"**Superseded by:** {f.superseded_by}")
                if f.closed_by:
                    lines.append(f"**Closed by:** {f.closed_by}")
                if f.closed_reason:
                    lines.append(f"**Closure reason:** {f.closed_reason}")
                if f.closed_ts:
                    lines.append(f"**Closed at:** {f.closed_ts}")
            lines.append("")

            if f.evidence:
                lines.append("### Evidence")
                lines.append("")
                for key in ("request", "response", "excerpt"):
                    val = f.evidence.get(key)
                    if val:
                        lines.append(f"**{key.title()}:**")
                        lines.append(f"```")
                        lines.append(val)
                        lines.append("```")
                        lines.append("")

            if f.repro:
                lines.append("### Reproduction")
                lines.append("")
                for i, step in enumerate(f.repro, 1):
                    lines.append(f"{i}. {step}")
                lines.append("")

            if f.tool_chain:
                lines.append("### Tool Chain")
                lines.append("")
                lines.append(" → ".join(f.tool_chain))
                lines.append("")

            lines.append("---")
            lines.append("")

        # --- Open questions (unknown ledger) --------------------------------
        # Findings are conclusions; the ledger holds what the investigation
        # has NOT answered yet.  An appendix (not inline) so the report stays
        # a findings report — but unresolved threads are never silently
        # dropped because render_findings is the canonical handoff document.
        # ``open_unknowns`` was fetched before the findings block above so it
        # also renders when there are no findings yet.
        if open_unknowns:
            lines.append("## Open questions (unresolved)")
            lines.append("")
            lines.append("Threads the investigation has not closed:")
            lines.append("")
            for u in open_unknowns:
                asset_bit = f" — {u.asset}" if u.asset else ""
                lines.append(f"- **{u.id}** ({u.domain}){asset_bit}: {u.question}")
                if u.context:
                    lines.append(f"  - context: {u.context}")
            lines.append("")

        return "\n".join(lines)

    def write_markdown(
        self,
        output_dir: Optional[Path] = None,
        severity: Optional[str] = None,
        asset: Optional[str] = None,
        status: Optional[str] = None,
        include_closed: bool = True,
    ) -> Path:
        """Render findings to markdown AND persist the report to disk.

        Writes a timestamped ``.md`` file under ``output_dir`` (defaults to
        ``<workspace_root>/findings_md/``).  Each call produces a new file so
        successive snapshots don't clobber each other.  Returns the path to
        the written file.

        The output dir is created if it doesn't exist.  Filters work the
        same as :meth:`render_markdown`.
        """
        md = self.render_markdown(
            severity=severity, asset=asset, status=status,
            include_closed=include_closed,
        )

        if output_dir is None:
            output_dir = Path(__file__).resolve().parent.parent / "findings_md"
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        parts = [ts]
        if severity:
            parts.append(severity)
        if asset:
            parts.append(asset.replace("/", "_").replace(" ", "_"))
        filename = "findings_" + "-".join(parts) + ".md"
        out_path = output_dir / filename
        out_path.write_text(md, encoding="utf-8")
        return out_path

    # -- internals ----------------------------------------------------------

    @staticmethod
    def _row_to_finding(row: sqlite3.Row) -> Finding:
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

    def close(self) -> None:
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
