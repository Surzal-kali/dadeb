"""Concurrent web-surface prober: turn open ports into live HTTP intel.

Companion to the port scanners.  nmap/masscan answer "which TCP ports are
open"; this tool answers "which of those ports actually serve HTTP(S), and
what is it" — status code, title, Server/X-Powered-By fingerprints,
cookie-based stack hints, redirect chains — in ONE structured envelope, so
the secretary can decide where ffuf/ZAP/JS-recon go next without hand-curling
each host.

Origin note (honest): this box has NO projectdiscovery httpx binary.  The
``httpx`` executable in the framework venv is the Python ``httpx`` library's
curl-clone CLI (single-URL client, click-style options) — the wrong tool for
host probing.  Rather than depend on an install, the probe is implemented
directly with ``requests`` + a bounded thread pool.  If a PD httpx binary
lands on the box later, this module remains the gate-consistent frontend and
can grow a ``--engine pd-httpx`` passthrough.

Blocking by design and HARD-BOUNDED: targets x ports are capped (default
256 targets, 8 ports, 1024 requests), every request carries a per-request
timeout, and the whole run is wall-clock capped.  The dispatcher runs sync
tools in a worker thread, so a bounded blocking call is the intended shape
(AGENTS.md "Blocking Calls").

Scope: every entry in ``targets`` is validated by the operator-armed scope
gate (utils/scope_gate.check_scan) BEFORE any request fires — URLs and bare
hosts both parse; the whole run is refused if ANY entry is out of scope.
"""

from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
import urllib3

from constants import framework_tool


def _silence_insecure_warn(insecure: bool) -> None:
    """Suppress urllib3's InsecureRequestWarning — at the CALL SITE, gated.

    Was a process-global ``urllib3.disable_warnings()`` at module import,
    which muted TLS-verification warnings for the ENTIRE process (any module
    that imported web_probe, and everything else running in it). Now the
    suppression is only flipped when an actual ``insecure=True`` probe runs
    (idempotent, additive filter). Accepted residual trade: once flipped it
    stays for the process — but only a deliberate insecure probe can flip
    it, and the noise it silences is exactly its own.
    """
    if insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_MAX_TARGETS = 256
_MAX_PORTS = 8
_MAX_REQUESTS = 1024
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_BODY_STACK_MARKERS = (
    ("wp-content", "WordPress"),
    ("wp-json", "WordPress"),
    ("Joomla!", "Joomla"),
    ("drupal", "Drupal"),
    ("__NEXT_DATA__", "Next.js"),
    ("__NUXT__", "Nuxt"),
    ("csrfmiddlewaretoken", "Django"),
    ("meteor", "Meteor"),
    ("/_nuxt/", "Nuxt"),
)


def _split_targets(targets: str) -> List[str]:
    raw = (targets or "").strip()
    return [t for t in re.split(r"[\s,]+", raw) if t]


def _looks_like_url(entry: str) -> bool:
    return "://" in entry


def _ports(ports: str) -> List[int]:
    out: List[int] = []
    for part in re.split(r"[\s,]+", (ports or "").strip()):
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            out.extend(range(int(a), int(b) + 1))
        else:
            out.append(int(part))
    return out[:_MAX_PORTS]


def _fetch_one(
    url: str, timeout: float, insecure: bool
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """One probe. Returns (result_dict, None) or (None, error_string).

    Redirects are followed hop-by-hop with per-hop scope-gate validation
    (utils/gated_http): a 302 to an out-of-scope host BLOCKS that probe
    (reported in ``dead`` with the gate reason) instead of firing there.
    """
    from utils.gated_http import gated_get
    from utils.scope_gate import ScopeGateError

    _silence_insecure_warn(insecure)
    try:
        r, hops = gated_get(
            url,
            headers={"User-Agent": "framework-webprobe/1.0"},
            verify=not insecure,
            timeout=(3.0, timeout),
        )
        head = r.text[:65536] if r.encoding is not None or r.content else ""
        title_m = _TITLE_RE.search(head)
        title = _ws.sub(" ", title_m.group(1)).strip()[:200] if title_m else None
        stack: List[str] = []
        server = r.headers.get("Server")
        powered = r.headers.get("X-Powered-By") or r.headers.get("X-Generator")
        if server:
            stack.append(f"server:{server}")
        if powered:
            stack.append(f"powered:{powered}")
        low = head.lower()
        for c in r.cookies:
            n = (c.name or "").lower()
            if "phpsessid" in n and "PHP" not in stack:
                stack.append("PHP")
            elif "jsessionid" in n and "Java" not in stack:
                stack.append("Java")
            elif "asp.net_sessionid" in n and "ASP.NET" not in stack:
                stack.append("ASP.NET")
            elif "laravel_session" in n and "Laravel" not in stack:
                stack.append("Laravel")
            elif "csrftoken" in n and "Django" not in stack:
                stack.append("Django")
        for marker, label in _BODY_STACK_MARKERS:
            if marker.lower() in low and label not in stack:
                stack.append(label)
        return {
            "url": str(r.url),
            "status": r.status_code,
            "title": title,
            "length": len(r.content),
            "server": server,
            "x_powered_by": powered,
            "cookies": [c.name for c in r.cookies],
            "stack_hints": stack,
            "redirects": [h["url"] for h in hops[1:]],
        }, None
    except ScopeGateError as e:
        return None, f"scope-gate-blocked: {e}"
    except requests.exceptions.SSLError:
        return None, "ssl-error (try insecure=True)"
    except requests.exceptions.ConnectTimeout:
        return None, "connect-timeout"
    except requests.exceptions.ReadTimeout:
        return None, "read-timeout"
    except requests.exceptions.ConnectionError as e:
        return None, f"conn-refused/{type(e).__name__}"
    except Exception as e:  # noqa: BLE001 - probe must never crash the run
        return None, f"error:{type(e).__name__}:{e}"


_ws = re.compile(r"\s+")


@framework_tool(
    "Probe a list of web targets and report what is live: HTTP status, page "
    "title, Server/X-Powered-By fingerprints, cookie-based stack hints, "
    "redirect chains, and response sizes. This is the fast 'what serves "
    "HTTP here' triage between port scanning and deep scanning — run it "
    "after run_nmap/run_masscan on hosts with web ports, before ffuf/ZAP. "
    "Accepts bare hosts (default ports 80,443,8080,8443 probed) and full "
    "URLs (probed as-is). Bounded and non-blocking-friendly: caps at 256 "
    "targets / 8 ports / 1024 requests, wall-clock capped.",
    next_hints=["run_ffuf", "zap_open", "extract_js_routes", "report_finding"],
    untrusted_target=True,
)
def probe_web(
    targets: str,
    ports: str = "80,443,8080,8443",
    insecure: bool = False,
    timeout: float = 5.0,
    threads: int = 48,
    wall_cap: float = 90.0,
) -> Dict[str, Any]:
    """Probe ``targets`` (hosts and/or URLs) concurrently and return intel.

    Bare hosts get every port in ``ports`` probed with ONE scheme each
    (443/8443 -> https, everything else -> http — no alternate-scheme retry;
    port-scan results should tell you which is right).  Entries containing
    ``://`` are probed verbatim.  Every target is scope-gate validated first;
    a single out-of-scope entry refuses the whole run (never partially fire).

    Args:
        targets: Space/comma-separated hosts or URLs, e.g.
            ``"10.10.10.114,10.10.10.115"`` or
            ``"https://10.10.10.115/ 10.10.10.114"``.
        ports: Ports to probe for bare hosts (max 8).
        insecure: Skip TLS verification (self-signed lab certs).
        timeout: Per-request timeout in seconds.
        threads: Concurrent probe workers (default 48).
        wall_cap: Wall-clock cap in seconds; probes past the deadline are
            reported as ``skipped_deadline``.
    """
    from utils.scope_gate import check_scan, ScopeGateError

    entries = _split_targets(targets)
    if not entries:
        raise ScopeGateError(
            "scope gate: empty target list; pass explicit in-scope hosts/URLs."
        )
    if len(entries) > _MAX_TARGETS:
        return {
            "status": "Failed",
            "error": f"too many targets ({len(entries)} > {_MAX_TARGETS}); "
            "batch the run.",
        }

    _sc_ok, _sc_reason = check_scan(targets)
    if not _sc_ok:
        raise ScopeGateError(f"scope gate: {_sc_reason}")

    jobs: List[str] = []
    for entry in entries:
        if _looks_like_url(entry):
            jobs.append(entry if "://" in entry else f"https://{entry}")
        else:
            for port in _ports(ports):
                scheme = "https" if port in (443, 8443) else "http"
                jobs.append(f"{scheme}://{entry}:{port}")
    jobs = jobs[:_MAX_REQUESTS]

    started = time.time()
    results: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []
    skipped_deadline = 0
    with ThreadPoolExecutor(max_workers=max(1, min(threads, 96))) as pool:
        futs = {pool.submit(_fetch_one, u, timeout, insecure): u for u in jobs}
        try:
            for fut in as_completed(futs, timeout=max(1.0, float(wall_cap))):
                url = futs[fut]
                res, err = fut.result()
                if res is not None:
                    results.append(res)
                else:
                    errors.append({"url": url, "error": err or "unknown"})
        except TimeoutError:
            # Wall cap hit: keep what completed; the remainder is counted below.
            pass
        for fut in futs:
            if not fut.done():
                skipped_deadline += 1
        skipped_deadline += len(jobs) - len(results) - len(errors) - skipped_deadline

    alive = [r for r in results if 0 < (r.get("status") or 0) < 600]
    return {
        "status": "Success",
        "requested": len(jobs),
        "alive": sorted(alive, key=lambda r: (-(r.get("status") or 0), r["url"])),
        "dead": errors,
        "skipped_deadline": max(0, skipped_deadline),
        "elapsed_s": round(time.time() - started, 1),
        "note": (
            "alive = received an HTTP response (any code). Feed live URLs to "
            "run_ffuf / zap_open / extract_js_routes."
        ),
    }
