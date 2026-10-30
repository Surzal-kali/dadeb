"""Connection contract + preflight plumbing for ``burp_mcp.py``.

Carved guts of ``auxiliaries/burp_mcp.py`` (2026-10-30): the BURP_MCP_*
connection constants, ``BurpMCPError``, the error-hint machinery
(``_BURP_ERROR_HINTS`` / ``_burp_error_guard``), and the two preflight
helpers every traffic-bearing tool shares (``_scope_check``,
``_host_from_raw_request``).  Docstring-only sibling — no argparse, no
``@framework_tool`` members — so static discovery never mints it; the
facade imports these names back and remains the tool surface.
"""

from __future__ import annotations

import functools
import os

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BURP_MCP_HOST = os.getenv("BURP_MCP_HOST", "127.0.0.1")
BURP_MCP_PORT = int(os.getenv("BURP_MCP_PORT", "9876"))
# The SSE endpoint path.  The BApp's Ktor server serves SSE at the root
# path — verified live: GET http://127.0.0.1:9876/ returns
# ``Content-Type: text/event-stream`` + an ``endpoint`` event immediately.
# The ``/sse`` convention some MCP servers use does NOT apply here; the
# BApp mounts the SSE handler at ``/``.  If a future BApp version changes
# the mount path, override via this env.
BURP_MCP_SSE_PATH = os.getenv("BURP_MCP_SSE_PATH", "/")
BURP_MCP_URL = f"http://{BURP_MCP_HOST}:{BURP_MCP_PORT}{BURP_MCP_SSE_PATH}"

# Connection / read timeouts for the SSE transport (seconds).
BURP_MCP_CONNECT_TIMEOUT = float(os.getenv("BURP_MCP_CONNECT_TIMEOUT", "10"))
BURP_MCP_READ_TIMEOUT = float(os.getenv("BURP_MCP_READ_TIMEOUT", "300"))

# Per-call timeout for MCP tool calls (seconds).  Burp's sendRequest blocks
# while its internal HTTP client hits the target; an unreachable host can
# hang for Burp's connection-timeout budget.  This caps the secretary's wait.
BURP_MCP_CALL_TIMEOUT = float(os.getenv("BURP_MCP_CALL_TIMEOUT", "60"))


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------
class BurpMCPError(Exception):
    """Raised when the Burp MCP server returns an error or is unreachable.

    Carries enough structured detail for ``_burp_error_guard`` to return a
    actionable dict instead of a bare exception string.
    """

    def __init__(self, code: str = "", message: str = "") -> None:
        self.code = code
        self.message = message
        super().__init__(f"Burp MCP {code}: {message}" if code
                         else f"Burp MCP: {message}")


# ---------------------------------------------------------------------------
# Error guard — mirrors _zap_error_guard
# ---------------------------------------------------------------------------
_BURP_ERROR_HINTS = {
    "connect_failed": (
        "Burp Suite is not running or the MCP Server BApp is not loaded/"
        "enabled. Open Burp, install the 'MCP Server' extension from the "
        "BApp Store, go to the MCP tab, and tick 'Enabled'. Verify "
        "BURP_MCP_HOST/BURP_MCP_PORT match the extension's advanced options "
        "(default 127.0.0.1:9876)."
    ),
    "call_failed": (
        "The MCP call failed — the SSE session may have dropped (Burp "
        "restarted?) or the tool name is not recognized. The client will "
        "reconnect on the next call. If this persists, check Burp's MCP "
        "tab for errors and verify the extension is still enabled."
    ),
    "call_timeout": (
        "The Burp MCP tool call timed out — Burp did not send a response "
        "on the SSE stream within BURP_MCP_CALL_TIMEOUT (default 60s). "
        "The SSE session is still alive (this is a per-call timeout, not "
        "a connection failure), so subsequent burp_* calls will reuse "
        "the existing session without reconnecting. The target was likely "
        "unreachable or slow to respond. Retry with a longer timeout "
        "(BURP_MCP_CALL_TIMEOUT env) or a different target."
    ),
    "tool_error": (
        "Burp's MCP tool returned an error. The request may have been "
        "rejected by Burp's own security controls (target not approved, "
        "data access denied) or the arguments were invalid. Check that "
        "the operator disabled approval dialogs or pre-approved the "
        "target in the BApp config."
    ),
    "pro_only": (
        "This tool is Professional-edition only (scanner issues, "
        "Collaborator). It is not registered on Burp Community. Use the "
        "framework's own equivalents (listeners.collaborator for OOB, "
        "zap_active_scan + zap_alerts for scanner findings)."
    ),
}


def _burp_error_guard(func):
    """Catch ``BurpMCPError`` and return a structured dict instead of raising.

    Applied as the inner decorator (below ``@framework_tool``) on every
    ``burp_*`` wrapper.  Uses ``functools.wraps`` so ``inspect.signature``
    (used by the registry for parameter extraction) sees the original
    signature.
    """

    @functools.wraps(func)
    def _wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except BurpMCPError as e:
            hint = _BURP_ERROR_HINTS.get(e.code, "")
            return {
                "error": str(e),
                "burp_code": e.code,
                "burp_message": e.message,
                "status": "Failed",
                **({"hint": hint} if hint else {}),
            }

    return _wrapper


# ---------------------------------------------------------------------------
# Scope-gate helper (shared by every traffic-bearing tool)
# ---------------------------------------------------------------------------
def _scope_check(target: str) -> None:
    """Validate ``target`` (host or URL) against the armed scope gate.

    Raises ``ScopeGateError`` on a blocked target — same pattern as
    ``zap_send_raw`` and ``probe_web``.  The BApp has its own approval
    dialogs, but those are a human-in-the-loop for the GUI operator; this
    lane needs the programmatic gate *before* the call.
    """
    from utils.scope_gate import ScopeGateError, check_scan

    _ok, _reason = check_scan(target)
    if not _ok:
        raise ScopeGateError(f"scope gate: {_reason}")


def _host_from_raw_request(raw_request: str) -> str | None:
    """Extract the target host from a raw HTTP request for scope gating.

    Mirrors the same-named helper in ``auxiliaries/zap.py``.  Checks the
    ``Host:`` header first, falling back to an absolute-form request target
    (``GET http://host/path HTTP/1.1``).
    """
    from urllib.parse import urlparse

    lines = (raw_request or "").lstrip().splitlines()
    host = None
    for ln in lines:
        if ln.lower().startswith("host:"):
            host = ln.split(":", 1)[1].strip()
            break
    if not host and lines:
        first = lines[0].split()
        if len(first) >= 2 and "://" in first[1]:
            host = urlparse(first[1]).hostname
    if not host:
        return None
    if host.startswith("[") and "]" in host:
        return host[1:host.index("]")]
    if host.count(":") == 1:  # IPv4/domain :port
        return host.rsplit(":", 1)[0]
    return host