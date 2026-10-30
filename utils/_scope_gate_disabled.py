"""Operator tool-disable list for the armed scope (carved from utils/scope_gate.py).

The scope gate governs WIRE TRAFFIC (check_scan/check_send resolve target
hosts/IPs against the manifest). Cracking and other offline compute have
no target IP, so the traffic gate never sees them. The disabled_tools
list is the operator's blunt brake: a tool_id (or family prefix) the
model may not dispatch while the scope is armed. Applies only while
armed — disarmed = lab = unrestricted stays the standing posture. Same
armed-state file, same mtime-checked state read, same atomic state
write, same operator-only authority: no model lane can write it.

Prefix matching mirrors TOOL_BUDGET_TERMINAL_ALLOWLIST:
  trailing-dot family prefix  ("payloads.hash_crack.")  → kills the family
  bare stem, no dot           ("...run_john")           → exact tool_id only

State I/O (``_load_state`` / ``_write_state``) stays on the facade
(``utils.scope_gate``) and is imported at CALL time inside each
state-touching function — the codebase's standard seam (see
payloads/burp_fleet.py's ``from utils.scope_gate import check_scan``) — so
the shared mtime cache and every monkeypatch seam behave exactly as
before the carve.
"""
from __future__ import annotations

from typing import Any

# Terminal-lane prefixes that may NOT be disabled without --force — a model
# that can't write findings or memory can't comply with anything (tool_budget
# terminal-allowlist precedent).
_TERMINAL_PREFIXES = ("utils.memory_tools.", "utils.findings.")


def _matches_disabled(tool_id: str, prefixes: list[str]) -> str | None:
    """Return the prefix that disables ``tool_id``, or None.

    A trailing-dot prefix (``payloads.hash_crack.``) matches the whole family
    via startswith; a bare stem (no trailing dot) is an exact tool_id match
    only, so a typo can't silently become a family kill.
    """
    if not tool_id or not prefixes:
        return None
    for p in prefixes:
        if not p:
            continue
        if p.endswith("."):
            if tool_id.startswith(p):
                return p
        elif tool_id == p:
            return p
    return None


def is_disabled(tool_id: str) -> tuple[bool, str | None]:
    """Verdict: is ``tool_id`` disabled for the armed scope?

    Returns ``(True, prefix)`` when disabled (``prefix`` is the list entry
    that matched, for the remediation string), ``(False, None)`` when not
    disabled or no scope is armed. Mtime-cached like every other read here
    so a REPL-side ``scope disable`` is visible to a running Brain on the
    very next call.
    """
    from utils.scope_gate import _load_state
    state = _load_state()
    if state is None:
        return False, None
    prefixes = list(state.get("disabled_tools") or [])
    match = _matches_disabled(tool_id, prefixes)
    if match is not None:
        return True, match
    return False, None


def disable_tools(prefixes: list[str], *, force: bool = False) -> dict[str, Any]:
    """Add tool_id prefixes to the disabled list (REPL authority).

    Requires the gate to be armed — the disable list is an engagement-posture
    control, not a lab-mode control. Refuses to disable terminal-lane
    families (findings/memory) without ``force`` — a model that can't report
    findings or write memory is trapped with no way to comply.
    """
    from utils.scope_gate import _load_state, _write_state
    state = _load_state()
    if state is None:
        return {"ok": False, "error": "no scope armed; run 'scope on <handle>' first"}
    clean = [p.strip() for p in (prefixes or []) if p.strip()]
    if not clean:
        return {"ok": False, "error": "at least one prefix is required: scope disable <prefix> [...]"}
    # Terminal-lane guard: refuse without --force.
    blocked: list[str] = []
    if not force:
        for p in clean:
            if any(p.startswith(tp) or tp.startswith(p) for tp in _TERMINAL_PREFIXES):
                blocked.append(p)
        if blocked:
            return {
                "ok": False,
                "error": (
                    f"refusing to disable terminal-lane family {blocked} — a "
                    "model that can't write findings or memory can't comply "
                    "with anything. Re-run with --force to override."
                ),
            }
    current = list(state.get("disabled_tools") or [])
    added: list[str] = []
    for p in clean:
        if p not in current:
            current.append(p)
            added.append(p)
    state["disabled_tools"] = current
    _write_state(state)
    return {
        "ok": True,
        "disabled_tools": current,
        "added": added,
        "count": len(current),
        "message": f"disabled {len(added)} prefix(es)" + (
            "; list now: " + ", ".join(current) if current else ""
        ),
    }


def enable_tools(prefixes: list[str]) -> dict[str, Any]:
    """Remove tool_id prefixes from the disabled list (REPL authority)."""
    from utils.scope_gate import _load_state, _write_state
    state = _load_state()
    if state is None:
        return {"ok": False, "error": "no scope armed"}
    clean = [p.strip() for p in (prefixes or []) if p.strip()]
    if not clean:
        return {"ok": False, "error": "at least one prefix is required: scope enable <prefix> [...]"}
    current = list(state.get("disabled_tools") or [])
    removed: list[str] = []
    for p in clean:
        if p in current:
            current.remove(p)
            removed.append(p)
    state["disabled_tools"] = current
    _write_state(state)
    return {
        "ok": True,
        "disabled_tools": current,
        "removed": removed,
        "count": len(current),
        "message": f"enabled {len(removed)} prefix(es)" + (
            "; list now: " + ", ".join(current) if current else " (list empty)"
        ),
    }


def list_disabled() -> dict[str, Any]:
    """List the disabled prefixes + a per-tool verdict probe (REPL +
    agent-callable ``scope_status`` surface — read-only)."""
    from utils.scope_gate import _load_state
    state = _load_state()
    if state is None:
        return {"ok": True, "armed": False, "disabled_tools": [], "message": "disarmed (lab mode — no disable list)"}
    prefixes = list(state.get("disabled_tools") or [])
    return {
        "ok": True,
        "armed": True,
        "disabled_tools": prefixes,
        "count": len(prefixes),
        "message": f"{len(prefixes)} disabled prefix(es)" if prefixes else "no tools disabled",
    }


def disabled_reject_envelope(tool_id: str, prefix: str) -> dict[str, Any]:
    """Structured reject envelope for a disabled-tool dispatch refusal.

    Used by both enforcement points (executor preflight + Brain CALL_TOOL
    guard) so the model reads a consistent Failed status + remediation.
    """
    return {
        "status": "Failed",
        "error": (
            f"tool {tool_id!r} is disabled for the armed scope "
            f"(matched disable prefix {prefix!r}). The operator turned it "
            "off for this engagement."
        ),
        "remediation": (
            "Ask the operator to re-enable it ('scope enable <prefix>' in "
            "the Tool REPL), or use an alternative tool. This is an "
            "authorization brake, not hash-provenance enforcement — the "
            "list can't tell whether a hash came from an in-scope dump."
        ),
        "disabled": True,
        "matched_prefix": prefix,
    }

