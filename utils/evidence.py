"""Evidence ledger — the unknowns table, promoted (2026-10-19 design).

A finding records a *conclusion*; an evidence entry records an explicit
open item the investigation noticed but hasn't answered yet: a recovered
credential not yet validated against other services, an unprobed service,
an ambiguous result, a scope question. Phase 1 stores locally in SQLite
(mirroring the Postgres ``evidence`` schema in
``dockered/postgres/init/002_schemas.sql``); the Postgres lane takes over
when psycopg + the postgres container are up.

The headline is the credential-reuse sweep made mechanical: every recovered
credential gets EXACTLY ONE validation attempt per service — the standing
runbook rule (AGENTS.md "Credential-Reuse Sweep") is enforced as a unique
constraint on ``(entry_id, service, target)``, not as prose. A second
attempt is refused with the re-mint guidance; re-acquiring a credential is
cheap, brute-forcing isn't.

Retention (residency decision, 2026-10-19): mid-engage scrubbing is a
self-own — the reuse sweep needs the credential material hot. So credential
entries carry the 24h engagement floor by default (``ttl_hours`` override
available), scope questions never expire (safety-adjacent state), other
opens fade on a week. Expired OPEN entries are deleted by the lazy sweep;
expired resolved entries keep the skeleton and drop nothing (small text
rows). Engagement stamping: rows carry the armed slug from
``utils.engagement.current_slug()`` so a future purge pulls the cobweb.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from constants import resolve_workspace_root

logger = logging.getLogger(__name__)

_KINDS = ("credential", "service", "ambiguity", "scope_question", "observation")
_OPEN_STATUSES = ("open", "promoted", "resolved", "wontfix")
_OUTCOMES = ("hit", "miss", "error", "undecided")

_CRED_TTL_H = float(os.getenv("EVIDENCE_CRED_TTL_HOURS", "24"))
_OTHER_TTL_H = float(os.getenv("EVIDENCE_OPEN_TTL_HOURS", str(7 * 24)))


def _db_path() -> str:
    root = resolve_workspace_root()
    return str(root / "evidence" / "evidence.db")


class EvidenceError(Exception):
    """Raised for ledger-contract violations (duplicate attempt, unresolved
    promotion). The Brain/in-process wrappers surface it as a Failed result
    so the secretary reads it as a refusal, not a silent nothing."""


class EvidenceStore:
    """SQLite backing store for the evidence ledger (WAL, busy-timeout,
    idempotent schema — scratch-store conventions, single cached conn)."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or _db_path()
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA busy_timeout=10000")
        self.conn.execute("PRAGMA journal_mode=WAL")
        self._init_tables()

    def _init_tables(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence_entries (
                entry_id     TEXT PRIMARY KEY,
                ts           REAL NOT NULL,
                engagement   TEXT,
                agent_id     TEXT NOT NULL DEFAULT 'unknown',
                kind         TEXT NOT NULL,
                status       TEXT NOT NULL DEFAULT 'open',
                source       TEXT,
                summary      TEXT NOT NULL,
                content      TEXT NOT NULL DEFAULT '{}',
                scratch_ref  TEXT,
                related_journal TEXT,
                resolved_by  TEXT,
                resolution   TEXT,
                closed_ts    REAL,
                expires_at   REAL
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence_attempts (
                attempt_id   TEXT PRIMARY KEY,
                entry_id     TEXT NOT NULL,
                service      TEXT NOT NULL,
                target       TEXT NOT NULL,
                outcome      TEXT NOT NULL,
                note         TEXT,
                ts           REAL NOT NULL,
                UNIQUE (entry_id, service, target)
            )
            """
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_evidence_kind_status "
            "ON evidence_entries(kind, status, ts DESC)"
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_evidence_engagement "
            "ON evidence_entries(engagement, ts DESC)"
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_attempts_entry "
            "ON evidence_attempts(entry_id)"
        )
        self.conn.commit()

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _ttl_for_kind(kind: str) -> Optional[float]:
        """Default per-kind TTL (hours): credential 24h floor, scope
        questions never, everything else EVIDENCE_OPEN_TTL_HOURS."""
        if kind == "scope_question":
            return None
        if kind == "credential":
            return _CRED_TTL_H
        return _OTHER_TTL_H

    def _sweep(self) -> int:
        """Delete expired OPEN entries; leave resolved skeletons intact.
        Best-effort — called on mutations (purge-on-mutation pattern)."""
        try:
            with self.conn:
                cur = self.conn.execute(
                    "DELETE FROM evidence_entries "
                    "WHERE status = 'open' AND expires_at IS NOT NULL "
                    "AND expires_at < ?",
                    (time.time(),),
                )
                return cur.rowcount
        except sqlite3.Error:
            return 0

    def _get(self, entry_id: str) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM evidence_entries WHERE entry_id = ?",
            (entry_id,),
        ).fetchone()

    # -- record / attempt / resolve ------------------------------------------

    def record(
        self,
        kind: str,
        summary: str,
        *,
        agent_id: str = "secretary",
        source: str = "",
        content: Optional[Dict[str, Any]] = None,
        scratch_ref: str = "",
        related_journal: str = "",
        ttl_hours: Optional[float] = None,
        engagement: Optional[str] = None,
    ) -> Dict[str, Any]:
        if kind not in _KINDS:
            raise EvidenceError(
                f"unknown kind {kind!r}; expected one of {', '.join(_KINDS)}"
            )
        summary = (summary or "").strip()
        if not summary:
            raise EvidenceError("summary must not be empty")

        if engagement is None:
            from utils.engagement import current_slug
            engagement = current_slug()
        if not engagement:
            raise EvidenceError("engagement must not be empty")

        if ttl_hours is None:
            ttl = self._ttl_for_kind(kind)
        elif ttl_hours <= 0:
            ttl = None
        else:
            ttl = ttl_hours

        entry_id = f"evid:{secrets.token_hex(8)}"
        now = time.time()
        expires_at = now + ttl * 3600 if ttl else None

        with self.conn:
            self.conn.execute(
                """
                INSERT INTO evidence_entries
                    (entry_id, ts, engagement, agent_id, kind, status, source,
                     summary, content, scratch_ref, related_journal, expires_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    entry_id, now, engagement, agent_id, kind, "open",
                    source, summary,
                    json.dumps(content or {}, default=str),
                    scratch_ref or None, related_journal or None, expires_at,
                ),
            )
        self._sweep()
        entry = self._get(entry_id)
        if entry is None:
            # The record was born expired (sub-second TTL override) and the
            # post-insert sweep collected it — honest outcome: acknowledged,
            # immediately collected. Never crash the caller over it.
            return {
                "entry_id": entry_id,
                "expires_at": expires_at,
                "status": "collected",
                "ttl_note": "born expired — collected at insert by the retention sweep",
            }
        out = dict(entry)
        out["ttl_note"] = (
            f"material expires in {ttl:.0f}h" if ttl else "engagement-bound (never expires)"
        )
        return out

    def add_attempt(
        self,
        entry_id: str,
        service: str,
        target: str,
        outcome: str,
        *,
        note: str = "",
    ) -> Dict[str, Any]:
        """Record ONE credential validation attempt. The UNIQUE
        (entry_id, service, target) constraint is the runbook: a second
        attempt against the same service raises with the re-mint guidance
        instead of letting brute-forcing masquerade as validation."""
        if outcome not in _OUTCOMES:
            raise EvidenceError(
                f"unknown outcome {outcome!r}; expected one of {', '.join(_OUTCOMES)}"
            )
        row = self._get(entry_id)
        if row is None:
            raise EvidenceError(f"evidence entry {entry_id!r} not found")
        if row["status"] != "open":
            raise EvidenceError(
                f"evidence entry {entry_id!r} is {row['status']!r}, not open"
            )
        service = (service or "").strip().lower()
        target = (target or "").strip()
        if not service or not target:
            raise EvidenceError("service and target are required")

        existing = self.conn.execute(
            "SELECT attempt_id, outcome FROM evidence_attempts "
            "WHERE entry_id = ? AND service = ? AND target = ?",
            (entry_id, service, target),
        ).fetchone()
        if existing is not None:
            raise EvidenceError(
                f"validation already attempted: {existing['attempt_id']} "
                f"({service}@{target} -> {existing['outcome']}). Runbook: ONE "
                "attempt per service — to re-test, re-mint a fresh evidence "
                "entry (re-acquisition is cheap); do not brute-force."
            )

        attempt_id = f"att:{secrets.token_hex(8)}"
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO evidence_attempts
                    (attempt_id, entry_id, service, target, outcome, note, ts)
                VALUES (?,?,?,?,?,?,?)
                """,
                (attempt_id, entry_id, service, target, outcome, note or None, time.time()),
            )
        return {
            "attempt_id": attempt_id,
            "entry_id": entry_id,
            "service": service,
            "target": target,
            "outcome": outcome,
            "credential_reuse_hit": outcome == "hit",
        }

    def resolve(
        self,
        entry_id: str,
        status: str,
        resolution: str = "",
        resolved_by: str = "",
    ) -> Dict[str, Any]:
        if status not in ("resolved", "wontfix", "promoted"):
            raise EvidenceError(
                f"cannot resolve to {status!r}; expected resolved|wontfix|promoted"
            )
        row = self._get(entry_id)
        if row is None:
            raise EvidenceError(f"evidence entry {entry_id!r} not found")
        if status == "promoted" and not resolved_by:
            raise EvidenceError(
                "promoted requires resolved_by (the finding ID that answered it)"
            )
        with self.conn:
            self.conn.execute(
                "UPDATE evidence_entries SET status = ?, resolution = ?, "
                "resolved_by = ?, closed_ts = ? WHERE entry_id = ?",
                (status, resolution or "", resolved_by or "", time.time(), entry_id),
            )
        return dict(self._get(entry_id))

    # -- queries --------------------------------------------------------------

    def list_open(
        self,
        kind: str = "",
        engagement: str = "",
        include_covered: bool = True,
    ) -> List[Dict[str, Any]]:
        """Open entries with their validation-attempt coverage (the reuse-
        sweep view: which recovered creds still owe which services)."""
        sql = "SELECT * FROM evidence_entries WHERE status = 'open'"
        params: List[Any] = []
        if kind:
            sql += " AND kind = ?"
            params.append(kind)
        if engagement:
            sql += " AND engagement = ?"
            params.append(engagement)
        sql += " ORDER BY ts DESC"
        rows = [dict(r) for r in self.conn.execute(sql, params).fetchall()]
        if not include_covered:
            rows = [r for r in rows if not self._attempts(r["entry_id"])]
        for r in rows:
            for k in ("content",):
                try:
                    r[k] = json.loads(r[k] or "{}")
                except json.JSONDecodeError:
                    r[k] = {}
            r["attempts"] = self._attempts(r["entry_id"])
        return rows

    def _attempts(self, entry_id: str) -> List[Dict[str, Any]]:
        return [
            dict(r)
            for r in self.conn.execute(
                "SELECT * FROM evidence_attempts WHERE entry_id = ? ORDER BY ts",
                (entry_id,),
            ).fetchall()
        ]

    def get(self, entry_id: str) -> Dict[str, Any]:
        row = self._get(entry_id)
        if row is None:
            raise EvidenceError(f"evidence entry {entry_id!r} not found")
        out = dict(row)
        out["content"] = json.loads(out.get("content") or "{}")
        out["attempts"] = self._attempts(entry_id)
        return out

    def stats(self) -> Dict[str, Any]:
        by_kind: Dict[str, int] = {}
        for r in self.conn.execute(
            "SELECT kind, count(*) AS n FROM evidence_entries "
            "WHERE status = 'open' GROUP BY kind"
        ):
            by_kind[r["kind"]] = r["n"]
        pending_attempts = self.conn.execute(
            "SELECT count(*) AS n FROM evidence_entries e WHERE e.status='open' "
            "AND e.kind='credential' AND NOT EXISTS "
            "(SELECT 1 FROM evidence_attempts a WHERE a.entry_id = e.entry_id)"
        ).fetchone()["n"]
        return {
            "open_by_kind": by_kind,
            "credentials_without_any_attempt": pending_attempts,
            "db": self.db_path,
        }

    def purge_engagement(self, slug: str) -> int:
        """Operator-side cobweb pull for the SQLite phase-1 lane (the PG lane
        does this via engagement.purge() under the operator role)."""
        with self.conn:
            self.conn.execute(
                "DELETE FROM evidence_attempts WHERE entry_id IN "
                "(SELECT entry_id FROM evidence_entries WHERE engagement = ?)",
                (slug,),
            )
            cur = self.conn.execute(
                "DELETE FROM evidence_entries WHERE engagement = ?", (slug,)
            )
            return cur.rowcount

    def close(self) -> None:
        try:
            self.conn.close()
        except sqlite3.Error:
            pass


_STORE: Optional[EvidenceStore] = None


def get_store() -> EvidenceStore:
    """Process singleton (house convention; lazy so tests can redirect the
    DB path per-call via env before first use)."""
    global _STORE
    if _STORE is None:
        _STORE = EvidenceStore()
    return _STORE


# ---------------------------------------------------------------------------
# Framework tools (discovery: utils/ is in ALLOWED_TOOL_ROOTS; no argparse at
# module level → dynamic pass only. BRAIN_SCAN_DIRS excludes utils/, so these
# dispatch via in-process fallback — harmless: state is on disk).
# ---------------------------------------------------------------------------

from constants import framework_tool  # noqa: E402


@framework_tool(
    "Record an OPEN ITEM in the evidence ledger — the promoted unknown "
    "ledger. Use whenever the investigation notices work it cannot finish "
    "this turn: a credential recovered but not yet validated against other "
    "services (kind=credential — then run the reuse sweep: ONE attempt per "
    "service via add_validation_attempt), an unprobed port/service "
    "(kind=service), an ambiguous or contradictory result (kind=ambiguity), "
    "a scope question about a found host (kind=scope_question), or a raw "
    "fact worth pinning (kind=observation). Unlike a finding, this is not a "
    "conclusion — it is a durable, typed reminder with its own attempt "
    "ledger. Credential material stays hot for the 24h engagement floor by "
    "default; scope questions never expire.",
    tags=["infra"],
    next_hints=[
        "add_validation_attempt — credential-reuse sweep: ONE attempt per service",
        "list_open_evidence — review open items + attempt coverage",
        "report_finding — when the item graduates to a conclusion (then resolve_evidence with status=promoted)",
    ],
)
def record_evidence(
    kind: str,
    summary: str,
    asset: str = "",
    content_json: str = "",
    source: str = "",
    scratch_ref: str = "",
    ttl_hours: float = -1.0,
) -> str:
    """Record an open item in the evidence ledger.

    Args:
        kind: credential | service | ambiguity | scope_question | observation.
        summary: One readable line, e.g. "NTLM hash for svc_sql recovered from secretsdump".
        asset: Related host/URL/endpoint, if any.
        content_json: Optional JSON object with the typed material, e.g.
            {"username": "svc_sql", "ntlm": "<hash>", "origin": "mysql@10.0.0.5"}.
            Stored as-is per the residency decision (no mid-engage scrubbing).
        source: What produced this (tool name or "operator").
        scratch_ref: Scratch reference to the full payload, if stored.
        ttl_hours: Retention override; <=0 applies the per-kind default
            (credential 24h, scope_question never, others 7d).
    """
    content: Dict[str, Any] = {}
    if content_json:
        try:
            parsed = json.loads(content_json)
            if not isinstance(parsed, dict):
                raise ValueError("content_json must be a JSON object")
            content = parsed
        except (json.JSONDecodeError, ValueError) as exc:
            return f"Error: content_json is not a valid JSON object: {exc}"
    if asset:
        content.setdefault("asset", asset)

    try:
        entry = get_store().record(
            kind, summary, source=source, content=content,
            scratch_ref=scratch_ref,
            ttl_hours=None if ttl_hours < 0 else ttl_hours,
        )
    except EvidenceError as exc:
        return f"Error: {exc}"

    tail = (
        "Reuse-sweep reminder: try this credential ONCE against each other "
        "reachable service (add_validation_attempt)."
        if kind == "credential" else ""
    )
    return (
        f"Evidence {entry['entry_id']} recorded ({kind}, open): {summary}. "
        f"{entry['ttl_note']}. {tail}".strip()
    )


@framework_tool(
    "Record ONE credential validation attempt against a service — the "
    "credential-reuse sweep, enforced. After recovering a credential, try it "
    "exactly ONCE per reachable service (ssh, smb, ftp, http-basic, "
    "http-form, mysql, postgres, winrm, ...) and journal the outcome here: "
    "hit | miss | error | undecided. A second attempt against the same "
    "(entry, service, target) is REFUSED — that is brute-forcing, not "
    "validation; re-mint a fresh evidence entry to legitimately re-test. "
    "Reuse hits (outcome=hit) are P2/P3 findings in their own right: report "
    "them via report_finding and resolve the entry as promoted.",
    tags=["infra", "net.services"],
    next_hints=[
        "list_open_evidence — which credentials still owe services an attempt",
        "report_finding — credential-reuse hits are findings (P2/P3)",
    ],
)
def add_validation_attempt(
    evidence_id: str,
    service: str,
    target: str,
    outcome: str,
    note: str = "",
) -> str:
    """Journal one credential validation attempt.

    Args:
        evidence_id: The evidence entry id (evid:<hex>).
        service: ssh | smb | ftp | http-basic | http-form | mysql | postgres | winrm | ...
        target: host:port or URL the credential was tried against.
        outcome: hit | miss | error | undecided.
        note: Optional context (e.g. "svc_sql@10.0.0.8 - NTLM refused").
    """
    try:
        result = get_store().add_attempt(
            evidence_id, service, target, outcome, note=note
        )
    except EvidenceError as exc:
        return f"Error: {exc}"
    if result["credential_reuse_hit"]:
        return (
            f"REUSE HIT: {service}@{target} accepted the credential from "
            f"{evidence_id} (attempt {result['attempt_id']}). This is a "
            "finding in its own right — report_finding (P2/P3), then "
            "resolve_evidence with status=promoted."
        )
    return (
        f"Attempt recorded: {result['attempt_id']} — {service}@{target} -> "
        f"{outcome}. One failure means 'not reused here'; move to the next "
        "service, do not retry."
    )


@framework_tool(
    "List OPEN items in the evidence ledger with their validation-attempt "
    "coverage — the reuse-sweep worklist. For kind=credential, each entry "
    "shows which (service, target) pairs were already attempted exactly "
    "once; a credential with zero attempts is the highest-priority next "
    "action. Optionally filter by kind.",
    tags=["infra"],
    next_hints=["add_validation_attempt", "resolve_evidence"],
)
def list_open_evidence(kind: str = "", engagement: str = "") -> str:
    """List open evidence entries (plus attempt coverage).

    Args:
        kind: Optional filter (credential|service|ambiguity|scope_question|observation).
        engagement: Optional filter by engagement slug.
    """
    store = get_store()
    try:
        rows = store.list_open(kind=kind or "", engagement=engagement or "")
    except EvidenceError as exc:
        return f"Error: {exc}"
    if not rows:
        stats = store.stats()
        return f"No open evidence items. {stats}"
    lines = []
    for r in rows:
        attempts = r.get("attempts") or []
        att = (
            "; ".join(
                f"{a['service']}@{a['target']}={a['outcome']}" for a in attempts
            )
            or "no attempts yet"
        )
        eng = f" [{r['engagement']}]" if r.get("engagement") else ""
        lines.append(
            f"{r['entry_id']} {r['kind']}{eng}: {r['summary']} — attempts: {att}"
        )
    return f"{len(rows)} open item(s):\n" + "\n".join(lines)


@framework_tool(
    "Resolve an evidence entry: resolved (answered), wontfix (deliberately "
    "dropped), or promoted (graduated into a finding — resolved_by must "
    "carry the finding ID, mirroring the unknown-ledger contract). Resolved "
    "entries keep their skeleton and attempt ledger for reconciliation; "
    "only the operator purges engagement material.",
    tags=["infra"],
    next_hints=["list_open_evidence", "render_findings"],
)
def resolve_evidence(
    evidence_id: str,
    status: str,
    resolution: str = "",
    resolved_by: str = "",
) -> str:
    """Close an evidence entry.

    Args:
        evidence_id: The evidence entry id (evid:<hex>).
        status: resolved | wontfix | promoted.
        resolution: The answer / closing note.
        resolved_by: Required for promoted — the finding ID.
    """
    try:
        row = get_store().resolve(evidence_id, status, resolution, resolved_by)
    except EvidenceError as exc:
        return f"Error: {exc}"
    return (
        f"Evidence {evidence_id} -> {status}"
        + (f" (by {row['resolved_by']})" if row.get("resolved_by") else "")
        + "."
    )