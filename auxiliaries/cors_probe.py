"""CORS posture + security-header audit for web targets.

Two targeted active checks that ZAP's passive scan only half-covers:

- :func:`check_cors` — fires GETs with attacker-controlled Origin values
  (``https://evil.example.com`` and ``null``) and reads the response CORS
  headers.  The dangerous case is ACAO REFLECTING the arbitrary origin
  WITH ``Access-Control-Allow-Credentials: true`` — that is a
  cross-origin data-read against logged-in users, the bounty-relevant
  form.  Wildcard ACAO and no-ACAO verdicts are reported honestly with
  their real (lower) severity ceilings.
- :func:`check_security_headers` — one GET, audit of the standard
  hardening headers (CSP, HSTS, X-Frame-Options, XCTO, Referrer-Policy,
  Permissions-Policy, COOP/COEP/CORP).  Missing headers are hardening
  hints, NOT findings by themselves — the envelope says so.

Honest limits: this is a single-request-per-case probe from an
unauthenticated vantage — it proves the header CONFIGURATION, not an
exploitable credential flow end-to-end.  A reflected+credentialed verdict
still needs an authed browser test (playwright lane when it exists)
before report_finding severity is final.

Scope: both tools validate the URL through the operator-armed scope gate
(utils/scope_gate.check_scan) BEFORE anything fires.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple

import requests

from constants import framework_tool

_EVIL_ORIGIN = "https://evil.example.com"

_SECURITY_HEADERS: Tuple[Tuple[str, str], ...] = (
    ("Content-Security-Policy", "CSP — script/style origin control"),
    ("Strict-Transport-Security", "HSTS — enforces https on repeat visits"),
    ("X-Frame-Options", "clickjacking control (or CSP frame-ancestors)"),
    ("X-Content-Type-Options", "nosniff — MIME confusion control"),
    ("Referrer-Policy", "referrer leakage control"),
    ("Permissions-Policy", "browser feature gating"),
    ("Cross-Origin-Opener-Policy", "COOP — cross-window isolation"),
    ("Cross-Origin-Embedder-Policy", "COEP — cross-resource isolation"),
    ("Cross-Origin-Resource-Policy", "CORP — resource embedding control"),
)


def _cors_verdict(acao: Optional[str], acac: Optional[str], origin_sent: str) -> Tuple[str, str]:
    """Pure verdict fn: (verdict, severity_hint) from response headers."""
    if not acao:
        return "no_access_control_allow_origin", "clean"
    reflected = origin_sent in acao
    wildcard = "*" in acao
    credentialed = (acac or "").strip().lower() == "true"
    if reflected and credentialed:
        return (
            "reflects_arbitrary_origin_with_credentials",
            "HIGH candidate — arbitrary origin can read credentialed "
            "responses (needs an authed-context confirmation test)",
        )
    if reflected:
        return (
            "reflects_arbitrary_origin",
            "medium candidate — arbitrary origin read WITHOUT credentials",
        )
    if wildcard:
        return (
            "wildcard_origin",
            "info — '*' blocks credentialed reads in browsers; check "
            "whether auth tokens ride URLs instead of cookies",
        )
    return (
        "static_allow_origin",
        "info — ACAO is pinned to a fixed origin (not attacker-controlled)",
    )


def _fetch(url: str, headers: Dict[str, str], insecure: bool, timeout: float = 10.0):
    """GET via utils.gated_http — in-scope redirects are followed hop-by-hop
    with per-hop gate validation; a hop to an out-of-scope host raises
    ScopeGateError (hard fail for these single-URL tools)."""
    from utils.gated_http import gated_get

    r, _hops = gated_get(
        url,
        headers={"User-Agent": "framework-corsprobe/1.0", **(headers or {})},
        verify=not insecure,
        timeout=(5.0, max(1.0, float(timeout))),
    )
    return r


@framework_tool(
    "Probe a URL's CORS posture: sends requests with attacker-controlled "
    "Origins (https://evil.example.com and 'null') and reports whether "
    "Access-Control-Allow-Origin reflects them, whether credentials are "
    "allowed, and the honest severity ceiling of each verdict. A "
    "reflected+credentialed result is the bounty-relevant one (cross-"
    "origin data read against logged-in users). Scope-gated before firing.",
    next_hints=["check_security_headers", "report_finding", "probe_web"],
)
def check_cors(
    url: str,
    insecure: bool = False,
    timeout: float = 10.0,
) -> Dict[str, Any]:
    """Probe ``url`` with attacker origins and grade the CORS response.

    Args:
        url: In-scope URL (gate-checked first).
        insecure: Skip TLS verification (self-signed lab certs).
        timeout: Per-request timeout in seconds.
    """
    from utils.scope_gate import check_scan, ScopeGateError

    url = (url or "").strip()
    if not url or "://" not in url:
        raise ScopeGateError("scope gate: pass an explicit in-scope URL (scheme included)")
    _sc_ok, _sc_reason = check_scan(url)
    if not _sc_ok:
        raise ScopeGateError(f"scope gate: {_sc_reason}")

    started = time.time()
    probes: List[Dict[str, Any]] = []
    for label, origin in (("evil-origin", _EVIL_ORIGIN), ("null-origin", "null")):
        try:
            r = _fetch(url, {"Origin": origin}, insecure, timeout)
        except requests.exceptions.SSLError:
            return {
                "status": "Failed",
                "error": "TLS verification failed — retry with insecure=True",
                "url": url,
            }
        except requests.exceptions.RequestException as e:
            return {
                "status": "Failed",
                "error": f"request failed: {type(e).__name__}",
                "url": url,
            }
        acao = r.headers.get("Access-Control-Allow-Origin")
        acac = r.headers.get("Access-Control-Allow-Credentials")
        verdict, severity_hint = _cors_verdict(acao, acac, origin)
        probes.append(
            {
                "case": label,
                "origin_sent": origin,
                "status_code": r.status_code,
                "acao": acao,
                "acac": acac,
                "vary": r.headers.get("Vary"),
                "verdict": verdict,
                "severity_hint": severity_hint,
                "evidence": (
                    f"Origin: {origin} -> ACAO: {acao!r}, ACAC: {acac!r}"
                ),
            }
        )

    worst_case = worst_case_of(probes)
    return {
        "status": "Success",
        "url": url,
        "probes": probes,
        "worst_case": worst_case,
        "summary": worst_case["verdict"],
        "summary_severity_hint": worst_case["severity_hint"],
        "elapsed_s": round(time.time() - started, 2),
        "note": (
            "Single-request configuration probe: reflects+credentials is "
            "the real candidate — CONFIRM in an authed context before "
            "report_finding; clean/wildcard verdicts are honest negatives."
        ),
    }


def worst_case_of(probes: List[Dict[str, Any]]) -> Dict[str, Any]:
    return max(
        probes,
        key=lambda p: {"reflects_arbitrary_origin_with_credentials": 3,
                       "reflects_arbitrary_origin": 2,
                       "wildcard_origin": 1,
                       "static_allow_origin": 0,
                       "no_access_control_allow_origin": 0}[p["verdict"]],
    )


@framework_tool(
    "Audit a URL's security hardening headers with one GET: presence/"
    "absence of CSP, HSTS, X-Frame-Options, X-Content-Type-Options, "
    "Referrer-Policy, Permissions-Policy, and the COOP/COEP/CORP "
    "isolation headers, each with a one-line 'why it matters'. Missing "
    "headers are hardening hints for report_finding, not standalone "
    "vulns. Scope-gated before firing.",
    next_hints=["check_cors", "report_finding", "probe_web"],
)
def check_security_headers(
    url: str,
    insecure: bool = False,
    timeout: float = 10.0,
) -> Dict[str, Any]:
    """One GET to ``url``; audit standard hardening headers.

    Args:
        url: In-scope URL (gate-checked first).
        insecure: Skip TLS verification (self-signed lab certs).
        timeout: Request timeout in seconds.
    """
    from utils.scope_gate import check_scan, ScopeGateError

    url = (url or "").strip()
    if not url or "://" not in url:
        raise ScopeGateError("scope gate: pass an explicit in-scope URL (scheme included)")
    _sc_ok, _sc_reason = check_scan(url)
    if not _sc_ok:
        raise ScopeGateError(f"scope gate: {_sc_reason}")

    started = time.time()
    try:
        r = _fetch(url, {}, insecure, timeout)
    except requests.exceptions.SSLError:
        return {"status": "Failed", "error": "TLS verification failed — retry with insecure=True", "url": url}
    except requests.exceptions.RequestException as e:
        return {"status": "Failed", "error": f"request failed: {type(e).__name__}", "url": url}

    present: Dict[str, str] = {}
    missing: List[Dict[str, str]] = []
    for header, why in _SECURITY_HEADERS:
        value = r.headers.get(header)
        if value is not None:
            present[header] = value[:200]
        else:
            missing.append({"header": header, "why": why})
    # frame-ancestors in CSP counts toward clickjacking control
    csp = present.get("Content-Security-Policy", "")
    if missing and "frame-ancestors" in csp:
        missing = [m for m in missing if m["header"] != "X-Frame-Options"]

    return {
        "status": "Success",
        "url": url,
        "status_code": r.status_code,
        "final_url": str(r.url),
        "present": present,
        "missing": missing,
        "missing_count": len(missing),
        "elapsed_s": round(time.time() - started, 2),
        "note": (
            "Hardening hints, not standalone findings — pair with actual "
            "impact (e.g. XFO missing + a sensitive page + known "
            "clickjacking flow) before report_finding."
        ),
    }
