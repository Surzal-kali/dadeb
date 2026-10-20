"""Journal: the append-only what-happened spine (Postgres lane, schema
``journal``; see dockered/postgres/init/002_schemas.sql).

One row per tool dispatch across every lane. The journal records WHAT
happened (findings record conclusions; evidence records open questions) and
is the reconstruction source when a session outlives its context: report
writing, resuming after a week, and scope-compliance queries
(``what_touched``) all read this.

Residency rules (2026-10-19 operator decision):
- Mid-engage scrubbing is a self-own — the reuse sweep is the point of
  credential rows. Material (args including secrets, scratch payloads) is
  stored as-is and bounded by TTL + engagement purge, NOT by editing.
- ``handle``-shaped parameters are the one redaction: they are pointers into
  a process-local SessionManager, meaningless after the process is gone —
  stored as ``{"$sessref": session_id}`` instead of a live handle.
- Tiny result digests (first scalar leaves of the result tree) keep the
  journal meaningful after material expires; the full payload lives in the
  scratch store behind its own TTL.

Append-only is structural, not aspirational: lanes authenticate with
INSERT/SELECT-only roles; the retention sweep and engagement purge run as
SECURITY DEFINER owner functions (only the operator's role may purge).

Postgres absent → journaling is skipped silently (this lane is additive and
must never break a tool).
"""

from __future__ import annotations

import json
import logging
import re
import secrets
import time
from typing import Any, Dict, Optional

from utils import engagement

logger = logging.getLogger(__name__)

# Lazy sweep piggyback: run the retention sweep at most this often (the
# scratch-store/cookie-jar purge-on-mutation pattern, with a throttle).
_SWEEP_MIN_INTERVAL_S = 300.0
_last_sweep = 0.0


def _should_sweep() -> bool:
    global _last_sweep
    if time.monotonic() - _last_sweep < _SWEEP_MIN_INTERVAL_S:
        return False
    _last_sweep = time.monotonic()
    return True


# ─── Arg normalization ────────────────────────────────────────────────────────

_SESSREF_KEYS = re.compile(r"(^|_)handle$|^session_id$", re.IGNORECASE)


def _redact_args(args: Dict[str, Any], session_id: str) -> Dict[str, Any]:
    """Single redaction pass: session-handle pointers become refs.

    Everything else — including credential material — stays verbatim per the
    residency decision; the TTL/purge machinery bounds it. Handles are
    pointers into a process-local SessionManager (scratch-store-class caveat:
    they mean nothing to another process), so storing a live handle value in
    the permanent spine buys nothing; the session_id ref is what survives.
    """
    out: Dict[str, Any] = {}
    for key, value in (args or {}).items():
        if isinstance(value, str) and _SESSREF_KEYS.search(key):
            out[key] = {"$sessref": session_id}
        elif isinstance(value, dict):
            out[key] = _redact_args(value, session_id)
        elif isinstance(value, list):
            out[key] = [
                _redact_args(v, session_id) if isinstance(v, dict) else v for v in value
            ]
        else:
            out[key] = value
    return out


def result_digest(result: Any, max_chars: int = 200) -> str:
    """A tiny, self-contained summary of a tool result — first scalar per
    branch of the tree, capped. The journal's permanence answer: status +
    key scalars survive material expiry, full payload stays in scratch."""
    leaves: list[str] = []

    def _walk(obj: Any, depth: int) -> None:
        if len(leaves) >= 6 or depth > 4:
            return
        if isinstance(obj, dict):
            for k, v in sorted(obj.items()):
                if k in ("result", "stdout"):  # transport wrappers' bulk fields
                    continue
                _walk(v, depth + 1)
        elif isinstance(obj, (list, tuple)):
            if obj and not isinstance(obj[0], (dict, list, tuple)):
                leaves.append(str(obj[0])[:40])
        elif isinstance(obj, (str, int, float, bool)) and obj != "":
            s = str(obj)
            leaves.append(s[:60])

    _walk(result, 0)
    digest = " | ".join(leaves)[:max_chars]
    return digest or "no-scalar-summary"


# ─── Write path ───────────────────────────────────────────────────────────────


def write_dispatch(
    *,
    tool_id: str,
    status: str,
    lane: str,
    args: Optional[Dict[str, Any]] = None,
    session_id: str = "0",
    duration_s: Optional[float] = None,
    result_mode: Optional[str] = None,
    scratch_ref: Optional[str] = None,
    result: Any = None,
    approval_path: Optional[str] = None,
    scope_verdict: Optional[str] = None,
    envelope_meta: Optional[Dict[str, Any]] = None,
) -> Optional[int]:
    """Insert one dispatch row. Returns the entry_id, or None when skipped
    (Postgres down, unarmed+unregistered, or write failure — all silent).

    ``status``: ok|error|timeout|budget_exhausted. Never raises.
    """
    conn = engagement.connect()
    if conn is None:
        return None

    engagement_slug = engagement.current_slug()
    redacted = _redact_args(args or {}, str(session_id))
    digest = result_digest(result) if result is not None else None
    entry_id: Optional[int] = None

    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO journal.entries
                    (engagement, lane, tool_id, args, scope_verdict,
                     approval_path, status, duration_s, result_mode,
                     scratch_ref, result_digest, envelope_meta)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                RETURNING entry_id
                """,
                (
                    engagement_slug, lane, tool_id,
                    json.dumps(redacted, default=str),
                    scope_verdict, approval_path, status, duration_s,
                    result_mode, scratch_ref, digest,
                    json.dumps(envelope_meta, default=str) if envelope_meta else None,
                ),
            )
            entry_id = int(cur.fetchone()[0])
        conn.commit()
    except Exception as exc:
        logger.debug("[journal] dispatch write skipped for %s: %s", tool_id, exc)
        try:
            conn.rollback()
        except Exception:
            pass
        return None

    if _should_sweep():
        gone = engagement.sweep()
        if gone >= 0:
            _last_sweep = time.monotonic()
    return entry_id


def new_run_ref() -> str:
    """Opaque per-dispatch correlation ref (``jr:<16hex>``) — scratch-store
    ID discipline: unguessable, so a cross-engagement guess can't correlate
    payloads it shouldn't see. Carried in envelope_meta, not the PK."""
    return f"jr:{secrets.token_hex(8)}"


from constants import framework_tool  # noqa: E402  (decorator for the read tool)


@framework_tool(
    "Search the dispatch journal for every tool run whose arguments mention "
    "a target — the scope-compliance / no-double-work query. Ground yourself "
    "BEFORE re-running anything: 'have we already scanned / logged into / "
    "dispatched against this host (or path, or domain)?' Returns matching "
    "journal entries (timestamp, lane, tool, status, engagement, digest). "
    "Read-only. Also answers target-mention questions like 'did we ever "
    "touch 10.10.10.50' or 'which runs referenced /admin'.",
    tags=["infra", "recon.scope"],
)
def what_touched(
    target: str,
    since_hours: Optional[float] = None,
    limit: int = 100,
) -> str:
    """Every journal row whose args mention ``target`` — the scope-compliance
    query. GIN-indexed containment search over args — the journal is the
    append-only spine of every lane's dispatches. Read-only + best-effort:
    returns a prose-formatted listing (empty string when the DB lane is
    down).

    Args:
        target: Host/IP/path/domain substring to search for, e.g.
            "10.10.10.50" or "/admin" or "blue.htb".
        since_hours: Optional recency window (e.g. 24 = last 24h only).
        limit: Max rows to return (default 100).
    """
    conn = engagement.connect()
    if conn is None:
        return (
            "Journal lane unavailable (Postgres down) — cannot answer "
            f"what_touched({target!r}) right now."
        )
    q = f"%{target}%"
    sql = (
        "SELECT entry_id, ts, lane, tool_id, status, duration_s, "
        "       result_digest, engagement "
        "FROM journal.entries "
        "WHERE args::text ILIKE %s"
    )
    params: list = [q]
    if since_hours is not None:
        sql += " AND ts > now() - (%s || ' hours')::interval"
        params.append(str(since_hours))
    sql += " ORDER BY ts DESC LIMIT %s"
    params.append(limit)
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
    except Exception as exc:
        logger.debug("[journal] what_touched failed: %s", exc)
        try:
            conn.rollback()
        except Exception:
            pass
        return f"Journal query failed: {exc}"

    if not rows:
        return f"No journal entries mention {target!r}."
    lines: list = []
    for (entry_id, ts, lane, tool_id, status, duration_s, digest, eng) in rows:
        when = ts.strftime("%m-%d %H:%M") if ts else "?"
        lines.append(
            f"#{entry_id} [{when}] {lane}/{tool_id} {status}"
            + (f" ({eng})" if eng else "")
            + (f" {duration_s:.1f}s" if duration_s else "")
            + (f" | {digest}" if digest else "")
        )
    header = f"{len(rows)} journal entr"
    header += "y" if len(rows) == 1 else "ies"
    header += f" mentioning {target!r}:" if len(rows) != 1 else f" mentioning {target!r}:"
    return header + "\n" + "\n".join(lines)