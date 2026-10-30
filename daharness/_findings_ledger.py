"""Internal unknowns-ledger lane for :mod:`daharness.findings`.

Open-questions storage: domain/status validation, row shaping, the
lost-id-race mint loop, and the resolve/close update behind
:class:`daharness.findings.FindingStore`'s ledger methods.  Private module —
import from the facade instead; nothing here is part of the public API.
"""

from __future__ import annotations

import sqlite3
from uuid import uuid4

from .models import Unknown

VALID_UNKNOWN_DOMAINS = {
    "recon", "web", "creds", "enum", "postex", "scope", "general",
}
VALID_UNKNOWN_STATUSES = {"open", "resolved", "wontfix", "promoted"}

UNKNOWNS_INSERT_SQL = """
                        INSERT INTO unknowns
                            (id, question, domain, asset, context, opened_by,
                             resolution, resolved_by, status, ts, closed_ts)
                        VALUES (?, ?, ?, ?, ?, ?, '', '', 'open', ?, '')
                        """

UNKNOWNS_RESOLVE_SQL = """
                UPDATE unknowns
                SET status = ?, resolution = ?, resolved_by = ?, closed_ts = ?
                WHERE id = ?
                """


def normalize_unknown_domain(domain: str) -> str:
    """Normalize + validate a ledger domain; raises ``ValueError`` on a bad one."""
    domain = (domain or "general").strip().lower()
    if domain not in VALID_UNKNOWN_DOMAINS:
        raise ValueError(
            f"Invalid domain {domain!r}. Must be one of: "
            f"{', '.join(sorted(VALID_UNKNOWN_DOMAINS))}"
        )
    return domain


def validate_unknown_status(status: str, resolved_by: str) -> str:
    """Normalize + validate a ledger status; ``promoted`` requires ``resolved_by``.

    Raises ``ValueError`` on an invalid status or a promoted close without
    the finding ID it became.  Returns the normalized status.
    """
    status = (status or "").strip().lower()
    if status not in VALID_UNKNOWN_STATUSES:
        raise ValueError(
            f"Invalid status {status!r}. Must be one of: "
            f"{', '.join(sorted(VALID_UNKNOWN_STATUSES))}"
        )
    if status == "promoted" and not resolved_by:
        raise ValueError("promoted requires resolved_by (the finding ID it became)")
    return status


def row_to_unknown(row) -> Unknown:
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


def filter_unknowns(
    items: list[Unknown],
    status: str | None,
    domain: str | None,
    asset: str | None,
    include_closed: bool,
) -> list[Unknown]:
    """Apply the optional unknowns() filters to already-loaded items."""
    if status:
        items = [u for u in items if u.status == status]
    if domain:
        items = [u for u in items if u.domain == domain.lower()]
    if asset:
        items = [u for u in items if asset.lower() in u.asset.lower()]
    if not include_closed:
        items = [u for u in items if u.status == "open"]
    return items


def mint_unknown(
    conn: sqlite3.Connection,
    *,
    question: str,
    domain: str,
    asset: str,
    context: str,
    opened_by: str,
    ts: str,
) -> Unknown:
    """Insert a new unknown, recounting/retrying on a concurrent-ID collision."""
    # Same lost-id race handling as findings.add: concurrent writers
    # (gateway + secretary + MCP clients share ids.db) can compute the
    # same U-id; the PRIMARY KEY turns that into a loud IntegrityError
    # and we recount/retry.
    last_exc: BaseException | None = None
    for _attempt in range(10):
        cur = conn.execute("SELECT COUNT(*) FROM unknowns")
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
            with conn:  # atomic INSERT + commit
                conn.execute(
                    UNKNOWNS_INSERT_SQL,
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


def load_unknown(conn: sqlite3.Connection, unknown_id: str) -> Unknown | None:
    row = conn.execute(
        "SELECT * FROM unknowns WHERE id = ?", (unknown_id,)
    ).fetchone()
    return row_to_unknown(row) if row else None


def close_unknown(
    conn: sqlite3.Connection,
    unknown_id: str,
    status: str,
    resolution: str,
    resolved_by: str,
    closed_ts: str,
) -> bool:
    """Apply a resolve/close transition; returns whether the row existed."""
    with conn:
        cur = conn.execute(
            UNKNOWNS_RESOLVE_SQL,
            (status, resolution, resolved_by, closed_ts, unknown_id),
        )
        return cur.rowcount != 0