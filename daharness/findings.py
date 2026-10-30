"""SQLite-backed findings store — the single source of truth for reported findings.

The store lives in ``ids.db`` (the same SQLite database used by
:class:`utils.sessions.DatabaseManager`).  Findings are written by the
``report_finding`` framework tool and read by ``render_findings``.  The full
Finding objects never enter the secretary model's context — only short
one-line pointers are stored in vector memory via ``remember_text``.

The markdown renderer in :meth:`FindingStore.render_markdown` doubles as a
bug-bounty submission draft and lab documentation, all from the same data.

Internal logic is split downward into private siblings next to this module
(:mod:`daharness._findings_store` — DDL/connection/SQL write lane,
:mod:`daharness._findings_ledger` — unknowns ledger,
:mod:`daharness._findings_render` — markdown shaping).  This module remains
the only public import surface.
"""

from __future__ import annotations

import logging
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

from constants import resolve_workspace_root

from . import _findings_ledger as _ledger
from . import _findings_render as _render
from . import _findings_store as _store
from .models import Finding, Unknown

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
        conn.execute(_store.TARGETS_TABLE_DDL)
        conn.execute(_store.SESSIONS_TABLE_DDL)
        conn.execute(_store.NOTES_TABLE_DDL)
        conn.commit()
    finally:
        store.close()

    logger.info("[db] ids.db ready at %s", path)
    return path


class FindingStore:
    """Append-only findings store backed by a SQLite table in ``ids.db``."""

    _VALID_STATUSES = _store.VALID_FINDING_STATUSES
    _VALID_UNKNOWN_DOMAINS = _ledger.VALID_UNKNOWN_DOMAINS
    _VALID_UNKNOWN_STATUSES = _ledger.VALID_UNKNOWN_STATUSES

    def __init__(self, db_path: str | None = None):
        # Workspace-resolved default (never tree-relative: a hardcoded
        # __file__-derived path wrote ids.db INTO the deb package tree —
        # untracked residue that survives a purge; 2026-10-20 VM incident).
        if db_path is None:
            db_path = str(Path(resolve_workspace_root()) / "ids.db")
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

        See :func:`daharness._findings_store.repair_db_ownership` — the
        mechanics and rationale live there (mirrors utils/scratch_store.py
        and utils/cookie_jar.py).
        """
        _store.repair_db_ownership(self.db_path)

    def _init_table(self) -> None:
        """Create the findings + unknowns tables and apply lifecycle migrations.

        The DDL/migration building blocks live in
        :mod:`daharness._findings_store`.
        """
        _store.init_findings_tables(self.conn)

    # -- unknown ledger (open questions) -----------------------------------

    def add_unknown(
        self,
        question: str,
        domain: str = "general",
        asset: str = "",
        context: str = "",
        opened_by: str = "",
    ) -> Unknown:
        """Record an open question and return the minted Unknown (U-001 style id)."""
        domain = _ledger.normalize_unknown_domain(domain)
        return _ledger.mint_unknown(
            self.conn,
            question=question,
            domain=domain,
            asset=asset,
            context=context,
            opened_by=opened_by,
            ts=datetime.now(timezone.utc).isoformat(),
        )

    @staticmethod
    def _row_to_unknown(row) -> Unknown:
        return _ledger.row_to_unknown(row)

    def unknowns(
        self,
        status: str | None = None,
        domain: str | None = None,
        asset: str | None = None,
        include_closed: bool = True,
    ) -> list[Unknown]:
        """List unknowns, oldest first, optionally filtered.

        ``include_closed=False`` returns only open unknowns — the "what
        haven't we answered yet" view.  Statuses: open|resolved|wontfix|promoted.
        """
        rows = self.conn.execute(
            "SELECT * FROM unknowns ORDER BY CAST(SUBSTR(id, 3) AS INTEGER) ASC"
        ).fetchall()
        items = [_ledger.row_to_unknown(r) for r in rows]
        return _ledger.filter_unknowns(
            items, status=status, domain=domain, asset=asset,
            include_closed=include_closed,
        )

    def get_unknown(self, unknown_id: str) -> Unknown | None:
        return _ledger.load_unknown(self.conn, unknown_id)

    def unknown_count(self) -> int:
        cur = self.conn.execute("SELECT COUNT(*) FROM unknowns")
        return cur.fetchone()[0]

    def resolve_unknown(
        self,
        unknown_id: str,
        status: str,
        resolution: str = "",
        resolved_by: str = "",
    ) -> Unknown | None:
        """Resolve/close an unknown.

        status: resolved (answered), wontfix (never pursuing), promoted
        (answered AND became a finding — pass the finding ID via ``resolved_by``
        so the report can link them).
        """
        status = _ledger.validate_unknown_status(status, resolved_by)
        closed_ts = datetime.now(timezone.utc).isoformat()
        if not _ledger.close_unknown(
            self.conn, unknown_id, status, resolution, resolved_by, closed_ts
        ):
            return None
        return self.get_unknown(unknown_id)

    # -- write --------------------------------------------------------------

    def add(
        self,
        title: str,
        severity: str,
        asset: str,
        cwe: str | None = None,
        evidence: dict | None = None,
        repro: list[str] | None = None,
        tool_chain: list[str] | None = None,
        memory_ref: str | None = None,
    ) -> Finding:
        """Append a finding, auto-assigning an incremental ID and timestamp."""
        ts = datetime.now(timezone.utc).isoformat()
        return _store.mint_finding(
            self.conn,
            title=title,
            severity=severity,
            asset=asset,
            cwe=cwe,
            evidence=evidence,
            repro=repro,
            tool_chain=tool_chain,
            memory_ref=memory_ref,
            ts=ts,
        )

    # -- read ---------------------------------------------------------------

    def all(self) -> list[Finding]:
        """Return all findings, oldest first (numeric ID order)."""
        # Sort by the integer portion of the ID (F-001 → 1, F-1000 → 1000)
        # so F-1000 doesn't sort before F-999 as it would lexicographically.
        rows = self.conn.execute(
            "SELECT * FROM findings ORDER BY CAST(SUBSTR(id, 3) AS INTEGER) ASC"
        ).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def get(self, finding_id: str) -> Finding | None:
        row = self.conn.execute(
            "SELECT * FROM findings WHERE id = ?", (finding_id,)
        ).fetchone()
        return self._row_to_finding(row) if row else None

    # -- lifecycle (close / supersede / reopen) ----------------------------

    def update_status(
        self,
        finding_id: str,
        status: str,
        closed_by: str | None = None,
        closed_reason: str | None = None,
        superseded_by: str | None = None,
    ) -> Finding | None:
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
        _store.set_finding_lifecycle(
            self.conn, finding_id, status, superseded_by, closed_by, closed_reason, ts
        )
        return self.get(finding_id)

    def supersede(
        self,
        old_id: str,
        new_id: str,
        closed_by: str | None = None,
        reason: str | None = None,
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
        return _store.supersede_chain(self.conn, finding_id)

    # -- read (with status awareness) ---------------------------------------

    def count(self) -> int:
        cur = self.conn.execute("SELECT COUNT(*) FROM findings")
        return cur.fetchone()[0]

    # -- render -------------------------------------------------------------

    def render_markdown(
        self,
        severity: str | None = None,
        asset: str | None = None,
        status: str | None = None,
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

        # Open questions from the unknown ledger — fetched up front so the
        # appendix can render even when no findings exist (early-days
        # engagement: nothing confirmed yet, but threads are already open).
        try:
            open_unknowns = self.unknowns(include_closed=False)
        except Exception:
            open_unknowns = []

        return _render.render_findings_markdown(
            findings,
            open_unknowns,
            severity=severity,
            asset=asset,
            status=status,
            include_closed=include_closed,
        )

    def write_markdown(
        self,
        output_dir: Path | None = None,
        severity: str | None = None,
        asset: str | None = None,
        status: str | None = None,
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
        filename = _render.report_filename(ts, severity, asset)
        out_path = output_dir / filename
        out_path.write_text(md, encoding="utf-8")
        return out_path

    # -- internals ----------------------------------------------------------

    @staticmethod
    def _row_to_finding(row: sqlite3.Row) -> Finding:
        return _store.row_to_finding(row)

    def close(self) -> None:
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()