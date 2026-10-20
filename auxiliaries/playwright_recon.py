"""Playwright recon client: scope-gated rendered-DOM tools (sidecar API).

Client for :mod:`auxiliaries.playwright_sidecar` — the scope-enforcing
Chromium sidecar.  Mirrors the ZAP client pattern: thin ``@framework_tool``
wrappers that POST to the sidecar's loopback HTTP API and return structured
envelopes the secretary can act on.

Two tools:
  - :func:`playwright_fetch` — one-shot rendered-DOM envelope: final URL,
    status, title, visible text, links, forms, JS-discovered routes,
    ``blocked_requests`` (out-of-scope navigations/fetch/XHR/websockets the
    sidecar aborted), and ``challenge_detected`` (Cloudflare-class walls —
    honest flag, never faked).  Use for SPA recon where ``extract_js_routes``
    (static, no browser) can't see JS-rendered content.
  - :func:`playwright_crawl` / :func:`playwright_crawl_status` — launch/poll
    bounded crawl (nmap.py pattern): BFS over same-origin in-scope links up
    to ``max_pages``/``max_depth``/``wall_cap``, each page yielding the same
    envelope as ``playwright_fetch``.  Auth'd crawling via a persisted
    ``storageState`` (env-injected at sidecar launch, never a tool arg).

Scope: the entry URL is ``check_scan``-validated at the client BEFORE the
sidecar is asked to navigate (defense-in-depth — every other tool does this
too), AND the sidecar re-gates every navigation + fetch/XHR/websocket at the
browser request-routing layer (per operator policy, passive subresources are
allowed so pages render).  When the scope gate is DISARMED (lab mode) the
sidecar gates nothing — vanilla browser behaviour.

Honest limits (docstring is the contract):
  - ``challenge_detected`` flags interstitials but cannot solve them —
    vanilla only, no stealth patches (arms race; honest negatives).
  - The sidecar must be running (launched by ``bootstrap`` when
    ``PLAYWRIGHT_SIDECAR=1``).  If it is down, the tools return a clear
    error guiding the operator to start it — they never fake a result.
  - Passive subresource allowance means tracker CDNs can load; the
    programmatic request lane is where the scope boundary is enforced.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, Optional

import requests

from constants import framework_tool

_HOST = "127.0.0.1"
_PORT = 8484
_BASE = f"http://{_HOST}:{_PORT}"
_TIMEOUT = (3.0, 60.0)


class SidecarError(Exception):
    """Raised when the sidecar is unreachable / returns an error envelope."""


def _post(path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    try:
        r = requests.post(f"{_BASE}{path}", json=payload, timeout=_TIMEOUT)
    except requests.exceptions.ConnectionError as e:
        raise SidecarError(
            "playwright sidecar not reachable — start it (bootstrap with "
            "PLAYWRIGHT_SIDECAR=1, or `python -m auxiliaries.playwright_sidecar`). "
            f"Detail: {e}"
        )
    except requests.exceptions.Timeout:
        raise SidecarError("playwright sidecar timed out")
    if not r.ok:
        try:
            err = r.json().get("error", r.text[:300])
        except Exception:
            err = r.text[:300]
        raise SidecarError(f"sidecar error: {err}")
    return r.json()


def _get(path: str) -> Dict[str, Any]:
    try:
        r = requests.get(f"{_BASE}{path}", timeout=_TIMEOUT)
    except requests.exceptions.ConnectionError as e:
        raise SidecarError(
            "playwright sidecar not reachable — start it (bootstrap with "
            "PLAYWRIGHT_SIDECAR=1). " f"Detail: {e}"
        )
    except requests.exceptions.Timeout:
        raise SidecarError("playwright sidecar timed out")
    if not r.ok:
        try:
            err = r.json().get("error", r.text[:300])
        except Exception:
            err = r.text[:300]
        raise SidecarError(f"sidecar error: {err}")
    return r.json()


def _health() -> bool:
    try:
        return bool(_get("/health").get("ok"))
    except SidecarError:
        return False


def _gate(url: str) -> None:
    """Client-side pre-flight scope gate on the entry URL (defense-in-depth)."""
    from utils.scope_gate import check_scan, ScopeGateError
    ok, reason = check_scan(url)
    if not ok:
        raise ScopeGateError(f"scope gate: {reason}")


@framework_tool(
    "Rendered-DOM recon with a real headless Chromium (via the scope-enforcing "
    "playwright sidecar): navigate to a URL, wait for the page to render, and "
    "return the final URL, status, title, visible text, links, forms, "
    "JS-discovered routes, out-of-scope requests the sidecar blocked "
    "(navigations/fetch/XHR/websocket), and a challenge_detected flag for "
    "Cloudflare-class interstitials (honest — cannot solve them). Use this "
    "for SPA/JS-heavy surfaces where extract_js_routes (static, no browser) "
    "can't see rendered content. Scope-gated at the client AND at the "
    "browser request layer; passive subresources allowed so pages load. "
    "Auth'd crawling uses a storageState set at sidecar launch (env).",
    next_hints=["extract_js_routes", "playwright_crawl", "zap_open_url",
                "report_finding"],
)
def playwright_fetch(
    url: str,
    wait_until: str = "networkidle",
    timeout_ms: int = 25000,
) -> Dict[str, Any]:
    """One-shot rendered-DOM fetch of ``url`` via the sidecar.

    Args:
        url: In-scope URL (client-gate-checked, then sidecar re-gates every
            navigation + fetch/XHR/websocket).
        wait_until: Playwright load state to wait for: ``networkidle``
            (default), ``domcontentloaded``, or ``load``.
        timeout_ms: Navigation timeout in ms.
    """
    url = (url or "").strip()
    if not url or "://" not in url:
        from utils.scope_gate import ScopeGateError
        raise ScopeGateError("scope gate: pass an explicit in-scope URL (scheme included).")
    _gate(url)
    started = time.time()
    env = _post("/fetch", {"url": url, "wait_until": wait_until,
                           "timeout_ms": int(timeout_ms)})
    env["elapsed_s"] = round(time.time() - started, 2)
    env["sidecar"] = True
    env.setdefault("status", "Success")
    return env


@framework_tool(
    "Launch a bounded rendered-DOM crawl (BFS over same-origin in-scope links) "
    "via the scope-enforcing playwright sidecar. Returns a job_id; perform one "
    "status poll to confirm launch, then hand off to the user. Poll again only "
    "when the user requests an update. Each visited page yields the same envelope as "
    "playwright_fetch. Out-of-scope links are skipped and reported in "
    "blocked. Same-origin by default (set same_origin=False to follow "
    "cross-origin in-scope links). Scope-gated per navigation at the browser "
    "request layer; passive subresources allowed. Use for mapping a JS-heavy "
    "in-scope surface before ffuf/ZAP.",
    next_hints=["playwright_crawl_status", "extract_js_routes", "report_finding"],
)
def playwright_crawl(
    url: str,
    max_pages: int = 25,
    max_depth: int = 3,
    wall_cap: float = 120.0,
    same_origin: bool = True,
) -> Dict[str, Any]:
    """Start a bounded crawl; returns ``{job_id}`` — poll with crawl_status.

    Args:
        url: In-scope seed URL (gate-checked first).
        max_pages: Cap on pages visited (default 25).
        max_depth: BFS depth cap (default 3).
        wall_cap: Wall-clock cap in seconds (default 120).
        same_origin: Only follow links on the seed host (default True).
    """
    url = (url or "").strip()
    if not url or "://" not in url:
        from utils.scope_gate import ScopeGateError
        raise ScopeGateError("scope gate: pass an explicit in-scope URL (scheme included).")
    _gate(url)
    return _post("/crawl/start", {
        "url": url, "max_pages": int(max_pages), "max_depth": int(max_depth),
        "wall_cap": float(wall_cap), "same_origin": bool(same_origin),
    })


@framework_tool(
    "Poll a playwright_crawl job once for progress + results when the user "
    "requests an update; never poll repeatedly. Status is running / "
    "done / deadline / error. Results (per-page envelopes) are returned once "
    "the crawl finishes; blocked lists out-of-scope links skipped. Pass the "
    "job_id from playwright_crawl.",
    next_hints=["report_finding", "extract_js_routes"],
)
def playwright_crawl_status(job_id: str) -> Dict[str, Any]:
    """Poll crawl progress by ``job_id``."""
    job_id = (job_id or "").strip()
    if not job_id:
        return {"status": "Failed", "error": "job_id required"}
    return _get(f"/crawl/status?id={job_id}")


@framework_tool(
    "Stop a running playwright_crawl job by job_id. The crawl finishes "
    "in-progress pages and reports partial results via crawl_status.",
)
def playwright_crawl_stop(job_id: str) -> Dict[str, Any]:
    job_id = (job_id or "").strip()
    if not job_id:
        return {"status": "Failed", "error": "job_id required"}
    return _post(f"/crawl/stop?id={job_id}", {})
