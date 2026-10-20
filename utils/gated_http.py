"""HTTP GET with per-hop scope-gate validation (redirect-bypass blocker).

The bypass this module closes (flagged by the operator 2026-09-19): a
tool validates its entry URL through the scope gate, fires the request,
the target answers 302 — and ``requests`` happily follows to a host the
gate never saw.  Redirects are attacker-controlled routing: a lab host
can 302 the client to an out-of-scope machine and the traffic fires
ungated.

:func:`gated_get` re-runs ``utils.scope_gate.check_scan`` on EVERY hop —
initial URL included — and raises :class:`ScopeGateError` the moment any
hop fails.  Callers that batch many URLs catch the error per-item (a
blocked probe is reported, never fired); single-URL tools let it
propagate as a hard failure.  Fail-closed in both shapes: no hop is ever
taken before its verdict.

All framework HTTP tools route through this helper (cors_probe, web_probe,
js_recon); archived_urls locks its endpoint by NOT following redirects at
all.  Since 2026-10-02 both helpers accept an optional caller-managed
``requests.Session`` — the hook the stateful web lane
(auxiliaries/web_session.py + utils/cookie_jar.py) uses to carry cookie-jar
state through the SAME per-hop gating without a second redirect loop.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests

from utils.scope_gate import ScopeGateError, check_scan

_REDIRECT_CODES = {301, 302, 303, 307, 308}


def gated_get(
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    verify: bool = True,
    timeout: Tuple[float, float] = (5.0, 10.0),
    max_hops: int = 5,
    session: Optional[requests.Session] = None,
) -> Tuple[requests.Response, List[Dict[str, Any]]]:
    """GET ``url`` manually following redirects, gate-checking every hop.

    Returns ``(response, hops)`` — ``hops`` is the ordered list of
    ``{"url", "status"}`` visited (first entry is the original URL).  The
    returned Response is the FINAL one.

    ``session`` (optional): a caller-managed ``requests.Session`` — used
    as-is and NOT closed on return (the caller owns its lifecycle).  This
    is how the stateful web lane (auxiliaries/web_session.py) carries
    jar-seeded cookies through the gated hop loop: redirect handling and
    per-hop gating stay in exactly one place while Set-Cookie accumulation
    lands on the caller's session.  ``None`` (every pre-existing caller)
    keeps the create-per-call + close behaviour unchanged.

    Raises:
        ScopeGateError: if the starting URL or ANY redirect target fails
            the armed scope gate, or if the chain exceeds ``max_hops``
            (stopped while still in scope — never fired past the cap).
    """
    hops: List[Dict[str, Any]] = []
    current = (url or "").strip()
    if not current:
        raise ScopeGateError("scope gate: empty URL")
    own_session = session is None
    if own_session:
        session = requests.Session()
    try:
        for _ in range(max_hops + 1):
            ok, reason = check_scan(current)
            if not ok:
                where = "initial URL" if not hops else f"redirect hop {len(hops)}"
                raise ScopeGateError(f"scope gate: {reason} ({where})")
            resp = session.get(
                current,
                headers=headers,
                verify=verify,
                timeout=timeout,
                allow_redirects=False,
            )
            hops.append({"url": current, "status": resp.status_code})
            if resp.status_code not in _REDIRECT_CODES:
                return resp, hops
            location = resp.headers.get("Location")
            if not location:
                return resp, hops
            nxt = urljoin(current, location)
            if nxt == current:  # self-redirect guard
                return resp, hops
            current = nxt
        # Hops exhausted while still in scope — stop, never fire past the cap.
        raise ScopeGateError(
            f"scope gate: redirect chain exceeded {max_hops} hops; "
            "stopped (all hops so far were in-scope)"
        )
    finally:
        if own_session:
            session.close()


def gated_request(
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
    data: Any = None,
    json: Any = None,
    files: Any = None,
    verify: bool = True,
    timeout: Tuple[float, float] = (5.0, 15.0),
    max_hops: int = 5,
    allow_redirects: bool = True,
    session: Optional[requests.Session] = None,
) -> Tuple[requests.Response, List[Dict[str, Any]]]:
    """Arbitrary-method HTTP request with per-hop scope-gate validation.

    Generalises :func:`gated_get` to POST/PUT/PATCH/DELETE with a body.
    Same redirect-bypass guarantee: every hop (initial URL + each 3xx
    target) is ``check_scan``-validated before the request fires; a
    cross-scope redirect raises :class:`ScopeGateError` (fail-closed).

    Redirect method handling follows common practice: 303 See Other always
    becomes GET with the body dropped; 307/308 preserve the original method
    and body; 301/302 preserve the method (servers vary; preserving avoids
    silently re-POSTing a payload to a redirect target the operator didn't
    bless — when in doubt, the gate catches an out-of-scope hop anyway).

    Set ``allow_redirects=False`` to send exactly one request and return the
    3xx response (no hop-following) — useful for SSRF probes that want to
    inspect a redirect body without following.

    ``files`` (optional): a requests-shaped multipart files mapping — with it,
    ``requests`` sends a ``multipart/form-data`` body (file-upload endpoints);
    paired with a dict ``data``, both travel as multipart form fields.  Dropped
    on a 303 redirect exactly like the body.

    ``session`` (optional): a caller-managed ``requests.Session`` — used
    as-is and NOT closed on return (caller owns the lifecycle; Set-Cookie
    from every hop accumulates on it).  This is the stateful hook the
    web-session lane uses to keep per-hop gating in one place while
    carrying cookie-jar state.  ``None`` (default) preserves the original
    create-per-call + close behaviour exactly.

    Returns ``(response, hops)``; ``hops`` is the ordered list of
    ``{"url", "status", "method"}`` visited.
    """
    hops: List[Dict[str, Any]] = []
    current = (url or "").strip()
    if not current:
        raise ScopeGateError("scope gate: empty URL")
    cur_method = (method or "GET").upper()
    cur_data, cur_json, cur_params, cur_files = data, json, params, files
    own_session = session is None
    if own_session:
        session = requests.Session()
    try:
        for _ in range(max_hops + 1):
            ok, reason = check_scan(current)
            if not ok:
                where = "initial URL" if not hops else f"redirect hop {len(hops)}"
                raise ScopeGateError(f"scope gate: {reason} ({where})")
            resp = session.request(
                cur_method,
                current,
                headers=headers,
                params=cur_params,
                data=cur_data,
                json=cur_json,
                files=cur_files,
                verify=verify,
                timeout=timeout,
                allow_redirects=False,
            )
            hops.append({"url": current, "status": resp.status_code, "method": cur_method})
            if not allow_redirects or resp.status_code not in _REDIRECT_CODES:
                return resp, hops
            location = resp.headers.get("Location")
            if not location:
                return resp, hops
            nxt = urljoin(current, location)
            if nxt == current:
                return resp, hops
            current = nxt
            # 303 -> GET + drop body (and files); 307/308 -> preserve; 301/302 -> preserve.
            if resp.status_code == 303:
                cur_method = "GET"
                cur_data, cur_json, cur_params, cur_files = None, None, None, None
        raise ScopeGateError(
            f"scope gate: redirect chain exceeded {max_hops} hops; "
            "stopped (all hops so far were in-scope)"
        )
    finally:
        if own_session:
            session.close()


__all__ = ["gated_get", "gated_request"]