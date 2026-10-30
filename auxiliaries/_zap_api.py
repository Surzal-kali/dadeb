"""ZAP API connection constants, pure helpers, and the tool-level error guard.

Carved guts of ``auxiliaries/zap.py`` (2026-10-30): the daemon connection
constants, the URL canonicalisation / status-line helpers, and
``ZAPAPIError`` + ``_zap_error_guard`` (the structured-error wrapper every
``zap_*`` tool is decorated with).  Plain guts only — no
``@framework_tool`` members, no argparse, so discovery never mints it;
``auxiliaries/zap.py`` keeps the ``ZAPClient`` class and the 19 decorated
tools, binding these names through its facade."""
from __future__ import annotations

import functools as _functools
import os
from typing import Any

ZAP_HOST = os.getenv("ZAP_HOST", "127.0.0.1")
ZAP_PORT = int(os.getenv("ZAP_PORT", "8090"))
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")
ZAP_BASE = f"http://{ZAP_HOST}:{ZAP_PORT}"


class ZAPAPIError(Exception):
    """Raised when ZAP returns an HTTP 4xx/5xx with a structured error body.

    Carries the ZAP ``code`` and ``message`` fields so callers (and the model)
    see *why* the call failed — e.g. ``url_not_found: URL Not Found in the
    Scan Tree`` — instead of a bare ``400 Client Error`` from
    ``raise_for_status``.
    """

    def __init__(self, status_code: int, code: str = "", message: str = "") -> None:
        self.status_code = status_code
        self.code = code
        self.message = message
        super().__init__(f"ZAP {status_code} {code}: {message}" if code
                         else f"ZAP {status_code}: {message}")


def _canonical(url: str) -> str:
    """Normalise a URL for comparison: strip trailing slashes, lowercase
    host, **preserve the query string**. Used to verify
    ``core/view/messages?url=...`` returned the URL we actually asked for
    (it does fuzzy substring matching otherwise).

    The query string MUST be preserved: without it, ``http://h/page?a=1``
    and ``http://h/page`` both canonicalise to ``hpage`` and the first
    match (the bare entry) is returned instead of the query-string entry
    — proven by the ``?zzprobe9=x`` probe returning the bare body (67808)
    instead of the real response (67952).
    """
    from urllib.parse import urlsplit
    parts = urlsplit(url.strip())
    host = (parts.hostname or "").lower()
    path = parts.path.rstrip("/") or "/"
    query = f"?{parts.query}" if parts.query else ""
    return f"{host}{path}{query}"


def _canonical_from_envelope(envelope: dict[str, Any]) -> str:
    """Recover the URL an envelope corresponds to from its requestHeader."""
    req = envelope.get("requestHeader", "")
    # requestHeader starts with "GET <url> HTTP/1.1" -- take the second token.
    parts = req.split()
    if len(parts) >= 2:
        return _canonical(parts[1])
    return ""


def _status_from_headers(response_header: str) -> str:
    """Pull the status line from a raw HTTP response header block.

    The header block starts with ``HTTP/1.1 200 OK\\r\\n`` -- return the
    second token (``200``) so the model can show status at a glance. Empty
    string on malformed input rather than raising -- callers display it.
    """
    if not response_header:
        return ""
    first_line = response_header.splitlines()[0] if response_header else ""
    parts = first_line.split()
    return parts[1] if len(parts) >= 2 else ""


# --- ZAP error guard --------------------------------------------------------
#
# Every zap_* wrapper is decorated with @_zap_error_guard (below the
# @framework_tool decorator) so a ZAPAPIError — whether a 400 structured
# error (url_not_found, MODE_VIOLATION, DOES_NOT_EXIST) or a 500 internal
# daemon error — is returned as a structured dict the model can reason about,
# instead of propagating as a bare exception that _launch_in_process wraps in
# a generic "In-process launch failed: ZAP 500: ..." message with no
# actionable detail.
#
# ScopeGateError is deliberately NOT caught here: it's a pre-flight scope
# violation (the operator armed the wrong scope), not a ZAP daemon problem.

# Hints surfaced for specific ZAP error codes / status patterns so the model
# gets an actionable next step, not just the raw error text.
_ZAP_ERROR_HINTS = {
    "MODE_VIOLATION": (
        "ZAP is in protect mode and refused this target as out-of-scope. "
        "Run zap_sync_scope to re-mirror the armed scope, or check that "
        "the target is in the armed scope manifest."
    ),
    "url_not_found": (
        "The URL is not in ZAP's sites tree. Run zap_open_url or zap_spider "
        "on it first so ZAP discovers it before querying."
    ),
    "DOES_NOT_EXIST": (
        "The named ZAP resource does not exist (e.g. a replacer rule that "
        "was already removed). This is usually benign — the operation is "
        "idempotent."
    ),
    "BAD_VIEW": (
        "This ZAP API endpoint was removed or renamed in this ZAP version "
        "(2.17). The client code may need updating for the installed build."
    ),
    "no_implementor": (
        "The required ZAP add-on is not installed. Install it from the ZAP "
        "marketplace and restart the daemon."
    ),
    "timeout": (
        "The ZAP API call timed out waiting for the target to respond. "
        "The target is likely unreachable or very slow. Verify the target "
        "is up and reachable from this host before retrying. "
        "Action endpoints are NOT retried (no double side-effects)."
    ),
    "no_response": (
        "ZAP sent the request but the target never spoke HTTP (closed "
        "port, unreachable host, or a non-HTTP service on that port). "
        "Scheme-forced https attempts are auto-retried over the request "
        "as written before this error is surfaced — the origin is silent "
        "on both the https and the as-written scheme."
    ),
}


def _zap_error_guard(func):
    """Catch ZAPAPIError and return a structured dict instead of propagating.

    Applied as the inner decorator (below @framework_tool) on every zap_*
    wrapper on ``auxiliaries/zap.py``.  Uses functools.wraps so
    inspect.signature (used by the registry for parameter extraction) sees
    the original function's signature.
    """

    @_functools.wraps(func)
    def _wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ZAPAPIError as e:
            hint = _ZAP_ERROR_HINTS.get(e.code, "")
            if not hint and e.status_code >= 500:
                _xmx = os.getenv("ZAP_XMX", "512m")
                hint = (
                    f"ZAP daemon returned HTTP {e.status_code} (internal "
                    f"server error). View endpoints are retried 5x with "
                    f"backoff; action endpoints (sendRequest, scan, etc.) "
                    f"are NOT retried to avoid double side-effects. If this "
                    f"persists: check /tmp/zap.log for Java stack traces, "
                    f"verify the daemon is healthy (curl "
                    f"http://127.0.0.1:{ZAP_PORT}/JSON/core/view/version), "
                    f"and consider restarting ZAP or raising ZAP_XMX "
                    f"(currently {_xmx}) if OOM-adjacent. If "
                    f"/tmp/zap.log shows an SSLException/ConnectException "
                    f"on sendRequest, the origin port does not speak the "
                    f"scheme in the request line — write the line in "
                    f"absolute form (GET http://host/path HTTP/1.1)."
                )
            return {
                "error": str(e),
                "zap_code": e.code,
                "zap_status": e.status_code,
                "zap_message": e.message,
                "status": "Failed",
                **({"hint": hint} if hint else {}),
            }

    return _wrapper