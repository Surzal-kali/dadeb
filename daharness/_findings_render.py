"""Internal report-rendering lane for :mod:`daharness.findings`.

Pure markdown shaping for :meth:`daharness.findings.FindingStore.render_markdown`
plus the timestamped report filename builder used by ``write_markdown``.
Takes already-loaded Finding/Unknown objects and returns strings — no
database access.  Private module — import from the facade instead; nothing
here is part of the public API.
"""

from __future__ import annotations

from .models import Finding, Unknown


def render_findings_markdown(
    findings: list[Finding],
    open_unknowns: list[Unknown],
    *,
    severity: str | None = None,
    asset: str | None = None,
    status: str | None = None,
    include_closed: bool = True,
) -> str:
    """Shape loaded findings + open unknowns into the markdown report.

    Optionally filter by severity (e.g. ``"P1"``), asset substring, or
    status (e.g. ``"open"``).  When ``include_closed`` is ``False``,
    only open findings are shown regardless of the ``status`` filter —
    useful for a "current state" report that hides superseded / false
    positive / duplicate entries.
    """
    if severity:
        findings = [f for f in findings if f.severity == severity]
    if asset:
        findings = [f for f in findings if asset.lower() in f.asset.lower()]
    if status:
        findings = [f for f in findings if f.status == status]
    if not include_closed:
        findings = [f for f in findings if f.status == "open"]

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


def report_filename(ts: str, severity: str | None, asset: str | None) -> str:
    """Build the timestamped markdown filename for a written report."""
    parts = [ts]
    if severity:
        parts.append(severity)
    if asset:
        parts.append(asset.replace("/", "_").replace(" ", "_"))
    return "findings_" + "-".join(parts) + ".md"