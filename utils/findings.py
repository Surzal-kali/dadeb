"""Framework tools for reporting and reviewing security findings.

``report_finding`` is the terminal action for any tool chain — it mints a
structured :class:`daharness.models.Finding` in the SQLite findings store and
stores a lightweight one-line pointer in vector memory so the secretary can
recall that the finding *exists* later without bloating its context with the
full evidence payload.

``render_findings`` reads the findings store and returns a markdown report
suitable as a bug-bounty submission draft or lab documentation.  The secretary
can call it mid-session to review what has been found so far.
"""

from __future__ import annotations

import time
from uuid import uuid4
from typing import Dict, List, Optional

from constants import framework_tool
from daharness.findings import FindingStore
from utils.memory_tools import remember_text


@framework_tool(
    "Report a structured security finding. This is the TERMINAL action for "
    "any tool chain — call it after you have gathered evidence. Provide a "
    "title, severity (P1 critical / P2 high / P3 medium / P4 info), the asset "
    "affected, and any evidence (request, response, excerpt), reproduction "
    "steps, and the list of tools used in this chain. The finding is stored "
    "persistently and a short pointer is saved to memory so it can be "
    "recalled later. Returns a brief confirmation with the finding ID.",
    next_hints=["list_unknowns — sweep open questions from the ledger (e.g. creds recovered but not yet validated against other services) before continuing deeper", "render_findings"],
)
def report_finding(
    title: str,
    severity: str,
    asset: str,
    cwe: str = "",
    evidence_request: str = "",
    evidence_response: str = "",
    evidence_excerpt: str = "",
    repro: str = "",
    tool_chain: str = "",
) -> str:
    """Report a finding to the findings store.

    Args:
        title: Short summary, e.g. "SQL Injection in /login".
        severity: P1 (critical), P2 (high), P3 (medium), P4 (info).
        asset: The affected host/URL/endpoint.
        cwe: CWE identifier, e.g. "CWE-89". Leave empty if unknown.
        evidence_request: The HTTP request or command that triggered it.
        evidence_response: The relevant response output.
        evidence_excerpt: A short excerpt highlighting the issue.
        repro: Reproduction steps, one per line.
        tool_chain: Tools used in this chain, comma-separated
            (e.g. "nmap, zap_open_url, zap_alerts").
    """
    evidence: Dict[str, str] = {}
    if evidence_request:
        evidence["request"] = evidence_request
    if evidence_response:
        evidence["response"] = evidence_response
    if evidence_excerpt:
        evidence["excerpt"] = evidence_excerpt

    repro_list: List[str] = (
        [s.strip() for s in repro.split("\n") if s.strip()] if repro else []
    )
    if isinstance(tool_chain, list):tool_chain = ",".join(str(s).strip() for s in tool_chain if str(s).strip())
    chain_list: List[str] = (
        [s.strip() for s in tool_chain.split(",") if s.strip()] if tool_chain else []
    )

    store = FindingStore()
    try:
        # Pre-generate a memory_id so we can store it as memory_ref.
        memory_id = f"finding-{int(time.time())}-{uuid4().hex[:6]}"
        pointer = f"{severity} {title} on {asset}"
        if cwe:
            pointer += f" ({cwe})"

        # Store a one-line pointer in vector memory — NOT the full finding.
        try:
            remember_text(text=pointer, namespace="findings", memory_id=memory_id)
        except Exception as exc:
            # Memory write failure is non-fatal — the finding is still stored.
            memory_id = None

        finding = store.add(
            title=title,
            severity=severity,
            asset=asset,
            cwe=cwe or None,
            evidence=evidence,
            repro=repro_list,
            tool_chain=chain_list,
            memory_ref=memory_id,
        )
        return (
            f"Finding {finding.id} reported: {title} ({severity}) on {asset}. "
            f"Use render_findings to review all findings."
        )
    finally:
        store.close()



# ---------------------------------------------------------------------------
# Unknown ledger — explicit "we don't know yet" records.
# ---------------------------------------------------------------------------

@framework_tool(
    "Record an OPEN QUESTION in the unknown ledger — something the "
    "investigation has noticed but not answered. Use this whenever you spot "
    "work you cannot finish this turn: an unprobed open port, a credential "
    "recovered but not yet validated against other services, an ambiguous "
    "tool result, a scope question about a found host. Unlike a finding, an "
    "unknown is not a conclusion — it is a durable reminder so the thread is "
    "never dropped across restarts or agent handoffs. Pass a one-sentence "
    "question, a domain (recon|web|creds|enum|postex|scope|general), an "
    "optional asset, and context on what was tried. Returns an unknown ID "
    "(U-001 style). List with list_unknowns, close with resolve_unknown.",
    next_hints=["list_unknowns"],
)
def record_unknown(
    question: str,
    domain: str = "general",
    asset: str = "",
    context: str = "",
    tool_chain: str = "",
) -> str:
    """Record an open question in the unknown ledger.

    Args:
        question: What is not known yet, one sentence, e.g.
            "Port 3306 open on 10.0.0.5 — unprobed".
        domain: Investigation area — recon|web|creds|enum|postex|scope|general.
        asset: Related host/URL/endpoint, if any.
        context: How this arose / what was already tried.
        tool_chain: Tools used in this chain, comma-separated (audit trail).
    """
    store = FindingStore()
    try:
        opened_by = (
            ",".join(s.strip() for s in tool_chain.split(",") if s.strip())
            if isinstance(tool_chain, str) else ""
        )
        unknown = store.add_unknown(
            question=question,
            domain=domain,
            asset=asset,
            context=context,
            opened_by=opened_by,
        )
        return (
            f"Unknown {unknown.id} recorded ({unknown.domain}): "
            f"{unknown.question}. Use list_unknowns to review open questions; "
            "resolve_unknown to close one when answered."
        )
    except ValueError as e:
        return f"Error: {e}"
    finally:
        store.close()


@framework_tool(
    "List recorded unknowns — the durable open-questions ledger. Returns a "
    "compact list (ID, domain, status, question, asset). Filter by status "
    "(open|resolved|wontfix|promoted — default 'open'), by domain "
    "(recon|web|creds|...), or by asset substring; pass include_closed=true "
    "to see everything regardless of status. Use this at the start of a turn "
    "to re-anchor on threads the investigation dropped, and before wrapping "
    "up to see what remains. Unknowns persist across restarts.",
    next_hints=["record_unknown", "resolve_unknown", "render_findings"],
)
def list_unknowns(
    status: str = "open",
    domain: str = "",
    asset: str = "",
    include_closed: bool = False,
) -> str:
    """List unknowns from the ledger as compact lines.

    Args:
        status: Filter by lifecycle status (open|resolved|wontfix|promoted).
            Empty string = no status filter. Ignored when include_closed=true.
        domain: Filter to one domain (recon|web|creds|enum|postex|scope|general).
        asset: Filter to unknowns whose asset contains this substring.
        include_closed: When true, show all statuses (overrides status filter).
    """
    store = FindingStore()
    try:
        # include_closed=true overrides any status filter (all statuses shown).
        items = store.unknowns(
            status=None if include_closed else (status or None),
            domain=domain or None,
            asset=asset or None,
            include_closed=include_closed,
        )
        if not items:
            return (
                "(no unknowns"
                + (f" with status={status}" if status and not include_closed else "")
                + " recorded — the ledger is empty or filters matched nothing)"
            )
        lines = [f"{len(items)} unknown(s):", ""]
        for u in items:
            lines.append(
                f"- {u.id} [{u.status}] ({u.domain}) {u.question}"
                + (f" — asset: {u.asset}" if u.asset else "")
            )
            if u.context:
                lines.append(f"    context: {u.context}")
            if u.status in ("resolved", "promoted", "wontfix"):
                lines.append(
                    f"    resolved: {u.resolution or '-'}"
                    + (f" (via {u.resolved_by})" if u.resolved_by else "")
                )
        lines.append("")
        lines.append(
            "Work unknowns down turn-by-turn; resolve_unknown closes each "
            "one (status=resolved|wontfix|promoted — promoted links the "
            "finding ID it became)."
        )
        return "\n".join(lines)
    finally:
        store.close()


@framework_tool(
    "Resolve an unknown — close the loop on a ledger question. Pass the "
    "unknown ID (e.g. U-003) and a status: 'resolved' (answered, provide "
    "the answer in resolution), 'wontfix' (deliberately not pursuing), or "
    "'promoted' (the question became a finding — pass resolved_by= the "
    "finding ID, e.g. F-012) so render_findings-style reports can link the "
    "chain. Optionally record who/what resolved it. Returns the updated "
    "unknown.",
    next_hints=["list_unknowns"],
)
def resolve_unknown(
    unknown_id: str,
    status: str,
    resolution: str = "",
    resolved_by: str = "",
) -> str:
    """Resolve an unknown in the ledger.

    Args:
        unknown_id: The unknown ID, e.g. "U-003".
        status: resolved | wontfix | promoted.
        resolution: The answer or outcome, free text.
        resolved_by: Finding ID for promoted (e.g. F-012); otherwise the
            agent/tool chain that closed it.
    """
    store = FindingStore()
    try:
        updated = store.resolve_unknown(
            unknown_id=unknown_id,
            status=status,
            resolution=resolution or None,
            resolved_by=resolved_by or None,
        )
        if updated is None:
            return f"Unknown {unknown_id} not found. Use list_unknowns to see all unknowns and their IDs."
        return (
            f"Unknown {unknown_id} marked '{updated.status}'."
            + (f" Resolution: {updated.resolution}." if updated.resolution else "")
            + (f" Resolved by: {updated.resolved_by}." if updated.resolved_by else "")
            + " Use list_unknowns to review the remaining open questions."
        )
    except ValueError as e:
        return f"Error: {e}"
    finally:
        store.close()


@framework_tool(
    "Render all reported findings as a markdown report. Optionally filter by "
    "severity (P1/P2/P3/P4) or asset substring. Useful for reviewing progress "
    "mid-session or generating a submission draft at the end of an engagement. "
    "The report is also written to a timestamped .md file under findings_md/ "
    "so it persists outside the database. Pass status='open' (or "
    "include_closed=False) to render only the current state — open "
    "findings with closed/duplicate/false-positive/superseded entries "
    "hidden, which is the 'current state only' report."
)
def render_findings(
    severity: str = "",
    asset: str = "",
    status: str = "",
    include_closed: bool = True,
) -> str:
    """Render findings from the store as a markdown report.

    Args:
        severity: Filter to a specific severity (P1/P2/P3/P4). Empty = all.
        asset: Filter to findings whose asset contains this substring. Empty = all.
        status: Filter to a specific lifecycle status
                (open|closed|superseded|false_positive|duplicate). Empty = all.
        include_closed: When False, only 'open' findings are shown
                        regardless of status — the 'current state' report.
    """
    store = FindingStore()
    try:
        md = store.render_markdown(
            severity=severity or None,
            asset=asset or None,
            status=status or None,
            include_closed=include_closed,
        )
        out_path = store.write_markdown(
            severity=severity or None,
            asset=asset or None,
            status=status or None,
            include_closed=include_closed,
        )
        return (
            f"{md}\n\n"
            f"_Report written to: {out_path}_"
        )
    finally:
        store.close()


# ---------------------------------------------------------------------------
# Finding lifecycle tools — close, supersede, reopen.
# ---------------------------------------------------------------------------

@framework_tool(
    "Close or update the status of a previously reported finding. Use this "
    "when a finding turns out to be a false positive, a duplicate of another "
    "finding, or simply resolved/no longer relevant. Pass the finding ID "
    "(e.g. F-008) and one of: closed, false_positive, duplicate, open (to "
    "reopen). For status='duplicate', pass duplicate_of with the ID of the "
    "canonical finding it duplicates so the report can link them. Optionally "
    "provide a reason and your agent/role name so other agents can see who "
    "closed it and why. Returns the updated finding.",
    next_hints=["render_findings"],
)
def close_finding(
    finding_id: str,
    status: str,
    reason: str = "",
    closed_by: str = "",
    duplicate_of: str = "",
) -> str:
    """Close or change the status of a finding.

    Args:
        finding_id: The finding ID, e.g. "F-008".
        status: New status — one of: closed, false_positive, duplicate, open.
        reason: Free-text explanation for the closure.
        closed_by: Agent name or role that closed it (for audit trail).
        duplicate_of: When status is 'duplicate', the ID of the canonical
                      finding this one duplicates (e.g. "F-003"). Stored as
                      the superseded_by pointer so the report links them.
    """
    store = FindingStore()
    try:
        if status == "duplicate":
            supersede_target = duplicate_of or None
        else:
            supersede_target = None
        updated = store.update_status(
            finding_id=finding_id,
            status=status,
            closed_by=closed_by or None,
            closed_reason=reason or None,
            superseded_by=supersede_target,
        )
        if updated is None:
            return f"Finding {finding_id} not found. Use render_findings to see all findings and their IDs."
        return (
            f"Finding {finding_id} status updated to '{updated.status}'. "
            + (f"Reason: {updated.closed_reason}. " if updated.closed_reason else "")
            + (f"Closed by: {updated.closed_by}. " if updated.closed_by else "")
            + "Use render_findings to see the updated report."
        )
    except ValueError as e:
        return f"Error: {e}"
    finally:
        store.close()


@framework_tool(
    "Mark an older finding as superseded by a newer, more accurate one. This "
    "is the standard workflow when an agent reports a refined or corrected "
    "finding — call supersede_finding to close the old one and point to the "
    "replacement. Both findings must already exist (report_finding for the "
    "new one first, then supersede_finding). Pass old_id (the finding to "
    "close), new_id (the replacement), and optionally a reason and your "
    "agent name. Returns both findings with their updated statuses.",
    next_hints=["render_findings"],
)
def supersede_finding(
    old_id: str,
    new_id: str,
    reason: str = "",
    closed_by: str = "",
) -> str:
    """Mark old_id as superseded by new_id.

    Args:
        old_id: The finding to close (e.g. "F-008").
        new_id: The replacement finding (e.g. "F-015").
        reason: Why the old finding is being superseded.
        closed_by: Agent name or role performing the supersede.
    """
    store = FindingStore()
    try:
        result = store.supersede(
            old_id=old_id,
            new_id=new_id,
            closed_by=closed_by or None,
            reason=reason or None,
        )
        old = result["old"]
        new = result["new"]
        return (
            f"Finding {old_id} superseded by {new_id}. "
            f"Old: '{old.title}' → status={old.status}. "
            f"New: '{new.title}' → status={new.status}. "
            "Use render_findings to see the updated report."
        )
    except ValueError as e:
        return f"Error: {e}"
    finally:
        store.close()
