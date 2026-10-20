"""Static JavaScript recon: routes + secrets from pages and JS bundles.

The todo.md "BUILD FIRST" tool (Sept 18 entry): a linkfinder-style static
extractor with NO browser and NO heavy deps.  Fetch a page, pull every
``<script src>`` bundle, and regex the bundles (plus inline script bodies)
for:

- **API routes / endpoints** — fetch/axios calls, ``xhr.open`` pairs, and
  quoted absolute paths (filtered against a static-asset denylist).  The
  output feeds ``run_ffuf`` (each route is a fuzzable path) and ZAP.
- **Full URLs** — third-party/absolute endpoints referenced in the code.
- **Secrets** — a regex battery: AWS access keys, Google API keys, GitHub /
  Slack tokens, JWTs, private-key blocks, Firebase URLs, credentialed URLs,
  and generic ``api_key``/``secret``/``password`` assignments.  Matches carry
  a short context snippet so the secretary can triage without re-fetching.
- **Sourcemaps** — ``sourceMappingURL`` / ``.js.map`` references; fetching
  them is left explicit (they can be enormous).

Honest limits (docstring is the contract): regex extraction is noisy by
design — a ~80% recall net, not a parser.  Bundles are fetched with GET only,
no rendering, no JS execution, no de-obfuscation: minified/webpacked bundles
still yield string literals, which is where the routes and secrets live.

Scope: the entry URL is validated by the operator-armed scope gate
(utils/scope_gate.check_scan) before anything fires; each fetched bundle on
a DIFFERENT host than the entry URL is gate-checked individually and
out-of-scope hosts are skipped (never fetched) and reported.
"""

from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests

from constants import framework_tool

_MAX_BODY_BYTES = 3_000_000
_MAX_SECRETS = 50
_MAX_ROUTES = 500
_MAX_URLS = 200
_MAX_SCRIPTS = 25

_STATIC_EXT = (
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
    ".woff2", ".ttf", ".eot", ".map", ".mp4", ".webm", ".mp3", ".pdf",
)
_NOISE_PREFIXES = ("/usr/", "/var/", "/etc/", "/proc/", "/sys/")

_SCRIPT_SRC_RE = re.compile(
    r"<script[^>]*?\bsrc\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE
)
_CLIENT_CALL_RE = re.compile(
    r"(?:fetch|axios(?:\.(?:get|post|put|patch|delete|request))?)\(\s*"
    r"[\"'`](?P<url>/[^\"'`\s]{1,200}|https?://[^\"'`\s]{1,200})", re.IGNORECASE
)
_XHR_OPEN_RE = re.compile(
    r"\.open\(\s*[\"'](?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)[\"']\s*,\s*"
    r"[\"'](?P<url>[^\"'\s]+)[\"']", re.IGNORECASE
)
_ABS_PATH_RE = re.compile(r"[\"'`](?P<url>/[A-Za-z0-9_\-][A-Za-z0-9_\-./]{1,120})[\"'`]")
_FULL_URL_RE = re.compile(r"https?://[^\s\"'`<>\\)]{4,300}")
_SOURCEMAP_RE = re.compile(r"sourceMappingURL\s*=\s*(\S+?\.map)")
_ANY_MAP_RE = re.compile(r"[A-Za-z0-9_\-./]+\.js\.map\b")

_SECRET_BATTERY: Tuple[Tuple[str, str], ...] = (
    ("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b"),
    ("google_api_key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("github_token", r"\bgh[pousr]_[0-9A-Za-z]{36}\b"),
    ("slack_token", r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"),
    (
        "jwt",
        r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.?[A-Za-z0-9_.\-]{0,64}",
    ),
    ("private_key_block", r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY"),
    ("firebase_url", r"https://[a-z0-9\-]{3,}\.firebaseio\.com"),
    (
        "credentialed_url",
        r"https?://[A-Za-z0-9._~%\-]{1,64}:[A-Za-z0-9._~%\-]{1,64}@"
        r"[A-Za-z0-9.\-]{1,255}",
    ),
    (
        "secret_assignment",
        r"(?i)\b(?:api[_-]?key|apikey|secret|secret[_-]?key|access[_-]?token"
        r"|auth[_-]?token|password|passwd|pwd)\b[\"']?\s*[:=]\s*"
        r"[\"']([^\"'\s]{8,64})[\"']",
    ),
)


def _fetch(url: str, timeout: float, insecure: bool) -> Tuple[Optional[str], int, str]:
    """GET ``url``; returns (text_or_None, status, error_string).

    Uses utils.gated_http: redirects are followed hop-by-hop with per-hop
    scope-gate validation — a bundle that 302s out of scope is BLOCKED,
    never fetched.
    """
    from utils.gated_http import gated_get
    from utils.scope_gate import ScopeGateError

    try:
        r, _hops = gated_get(
            url,
            headers={"User-Agent": "framework-jsrecon/1.0"},
            verify=not insecure,
            timeout=(5.0, timeout),
        )
    except ScopeGateError as e:
        return None, 0, f"scope-gate-blocked: {e}"
    except requests.exceptions.SSLError:
        return None, 0, "ssl-error (try insecure=True)"
    except requests.exceptions.Timeout:
        return None, 0, "timeout"
    except requests.exceptions.RequestException as e:
        return None, 0, f"{type(e).__name__}"
    except Exception as e:  # noqa: BLE001 - recon must never crash the run
        return None, 0, f"{type(e).__name__}:{e}"
    if len(r.content) > _MAX_BODY_BYTES:
        return None, r.status_code, "body-too-large"
    return r.text, r.status_code, ""


def _static_asset(path: str) -> bool:
    low = path.lower()
    return any(low.endswith(ext) for ext in _STATIC_EXT)


def _extract_script_srcs(page_text: str, base_url: str) -> List[str]:
    """Absolute <script src> URLs, resolved against the page URL."""
    out: List[str] = []
    seen: Set[str] = set()
    for raw in _SCRIPT_SRC_RE.findall(page_text):
        raw = raw.strip()
        if not raw or raw.startswith(("data:", "blob:", "javascript:")):
            continue
        absu = urljoin(base_url, raw)
        if absu not in seen:
            seen.add(absu)
            out.append(absu)
    return out


def _extract_routes(text: str) -> List[str]:
    """Endpoints from client calls, xhr.open, and quoted absolute paths."""
    found: Set[str] = set()
    for pattern in (_CLIENT_CALL_RE, _XHR_OPEN_RE, _ABS_PATH_RE):
        for m in pattern.finditer(text):
            candidate = m.group("url")
            if not candidate:
                continue
            if candidate.startswith("//"):
                continue
            if _static_asset(candidate) or any(
                candidate.startswith(p) for p in _NOISE_PREFIXES
            ):
                continue
            if len(candidate) < 2:
                continue
            found.add(candidate)
    return sorted(found)[:_MAX_ROUTES]


def _extract_full_urls(text: str) -> List[str]:
    out: Set[str] = set()
    for m in _FULL_URL_RE.finditer(text):
        u = m.group(0).rstrip(".,;:!?)]}'\"")
        if len(u) > 8 and not u.lower().endswith(_STATIC_EXT):
            out.add(u)
    return sorted(out)[:_MAX_URLS]


def _extract_sourcemaps(text: str) -> List[str]:
    out: Set[str] = set()
    out.update(_SOURCEMAP_RE.findall(text))
    out.update(_ANY_MAP_RE.findall(text))
    return sorted(out)[:25]


def _extract_secrets(text: str) -> List[Dict[str, str]]:
    """Regex battery. Returns {kind, match, context}; deduped, capped."""
    out: List[Dict[str, str]] = []
    seen: Set[Tuple[str, str]] = set()
    for kind, pattern in _SECRET_BATTERY:
        for m in re.finditer(pattern, text):
            match = (m.group(1) if m.groups() and m.group(1) else m.group(0)).strip()
            key = (kind, match)
            if key in seen:
                continue
            seen.add(key)
            start = max(0, m.start() - 40)
            end = min(len(text), m.end() + 40)
            ctx = re.sub(r"\s+", " ", text[start:end]).strip()
            out.append(
                {"kind": kind, "match": match[:120], "context": ctx[:160]}
            )
            if len(out) >= _MAX_SECRETS:
                return out
    return out


@framework_tool(
    "Static JavaScript recon: fetch a page (or a .js file directly), pull "
    "every <script src> bundle, and extract API routes/endpoints, full "
    "URLs, hardcoded secrets (AWS/Google/GitHub/Slack keys, JWTs, private "
    "key blocks, firebase URLs, credentialed URLs, api_key/secret/password "
    "assignments) and sourcemap references. Linkfinder-style regex net — "
    "no browser, GET-only, bounded. Feed discovered routes to run_ffuf; "
    "report confirmed secrets via report_finding. Cross-host bundles are "
    "scope-gate checked individually and skipped when out of scope.",
    next_hints=["run_ffuf", "report_finding", "zap_open", "probe_web"],
    untrusted_target=True,
)
def extract_js_routes(
    url: str,
    max_scripts: int = 25,
    timeout: float = 15.0,
    insecure: bool = False,
) -> Dict[str, Any]:
    """Fetch ``url`` and extract routes, URLs, secrets, sourcemaps from JS.

    If ``url`` ends in ``.js`` the file itself is the single blob; otherwise
    the page is treated as HTML: inline content is scanned AND every
    ``<script src>`` bundle is fetched (up to ``max_scripts``) and scanned.
    Bundles on a different host than the entry URL are individually
    scope-gate checked; refused hosts are never fetched and reported in
    ``skipped``.

    Args:
        url: In-scope page or JS file URL, e.g. ``http://10.10.10.114/``.
        max_scripts: Max bundles to fetch from one page (default 25).
        timeout: Per-fetch timeout in seconds.
        insecure: Skip TLS verification (self-signed lab certs).
    """
    from utils.scope_gate import check_scan, ScopeGateError

    url = (url or "").strip()
    if not url:
        raise ScopeGateError(
            "scope gate: empty url; pass an explicit in-scope page or JS URL."
        )
    _sc_ok, _sc_reason = check_scan(url)
    if not _sc_ok:
        raise ScopeGateError(f"scope gate: {_sc_reason}")

    started = time.time()
    page_text, page_status, err = _fetch(url, timeout, insecure)
    if page_text is None:
        return {"status": "Failed", "error": f"fetch failed: {err}", "url": url}

    all_routes: Set[str] = set()
    all_urls: Set[str] = set()
    maps: Set[str] = set()
    secrets: List[Dict[str, str]] = []
    js_files: List[Dict[str, Any]] = []
    skipped: List[Dict[str, str]] = []
    errors: List[Dict[str, str]] = []

    entry_host = urlparse(url).netloc
    if url.lower().endswith(".js"):
        script_urls: List[str] = []
        blobs = [(url, page_text)]
    else:
        script_urls = _extract_script_srcs(page_text, url)[: max(1, max_scripts)]
        blobs = [(url, page_text)]  # the page itself (inline <script> bodies)

    for src in script_urls:
        if urlparse(src).netloc != entry_host:
            ok, reason = check_scan(src)
            if not ok:
                skipped.append({"url": src, "reason": reason})
                continue
        text, status, ferr = _fetch(src, timeout, insecure)
        if text is None:
            errors.append({"url": src, "error": ferr})
            continue
        blobs.append((src, text))
        js_files.append({"url": src, "status": status, "size": len(text)})

    for blob_url, text in blobs:
        blob_routes = _extract_routes(text)
        blob_secrets = _extract_secrets(text)
        all_routes.update(blob_routes)
        all_urls.update(_extract_full_urls(text))
        maps.update(_extract_sourcemaps(text))
        secrets.extend(blob_secrets)
        if blob_url != url or not js_files:
            js_files.insert(
                0,
                {
                    "url": blob_url,
                    "status": page_status,
                    "size": len(text),
                    "routes": len(blob_routes),
                    "secrets": len(blob_secrets),
                },
            )

    return {
        "status": "Success",
        "page": {"url": url, "status": page_status, "scripts_found": len(script_urls)},
        "js_files": js_files,
        "routes": sorted(all_routes)[:_MAX_ROUTES],
        "full_urls": sorted(all_urls)[:_MAX_URLS],
        "secrets": secrets[:_MAX_SECRETS],
        "sourcemaps": sorted(maps)[:25],
        "skipped": skipped,
        "errors": errors,
        "elapsed_s": round(time.time() - started, 1),
        "note": (
            "Regex net: ~80% recall, noisy by design. Routes are fuzzable "
            "paths — feed them to run_ffuf. Secrets are CANDIDATES: verify "
            "in-context before report_finding."
        ),
    }
