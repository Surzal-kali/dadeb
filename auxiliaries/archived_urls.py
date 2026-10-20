"""Archived-URL discovery via the Wayback Machine CDX API (passive recon).

Queries web.archive.org's CDX index for every URL the archive has crawled
for a domain, then triages the result into bounty-relevant buckets:

- ``interesting_files`` — backup/config/dump-ish paths (``.bak`` ``.sql``
  ``.env`` ``.zip`` ``.git/`` ...) that may still be live,
- ``param_urls`` — archived URLs carrying query parameters (injection-
  surface archaeology: ``redirect=``, ``file=``, ``id=`` ...),
- ``admin_ish`` — admin/panel/staging/dev/internal path hits,
- ``paths`` + ``oldest``/``newest`` crawl timestamps for context.

Egress contract (hard, by construction): the CDX endpoint is a module
constant pointing at ``https://web.archive.org/cdx/search/cdx`` and the
tool accepts ONLY a domain name — never a URL, never an endpoint override.
There is no parameter that can make this module talk to any other host.
Output URLs are intel for triage; nothing here fetches target hosts.

Passive class, amass-style: the query is sent to a third-party archive
ABOUT an in-scope target (the same lane amass's passive data sources use).
The operator-armed scope gate (utils.scope_gate.check_scan) validates the
domain before anything fires — only in-scope domains are ever queried.
"""

from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

import requests

from constants import framework_tool

# HARDCODED egress host. Nothing in this module can be pointed elsewhere;
# there is deliberately no endpoint/env override.
_CDX_ENDPOINT = "https://web.archive.org/cdx/search/cdx"
_UA = "framework-archived-urls/1.0 (passive recon)"
_FL = "original,timestamp,statuscode,mimetype"

_INTERESTING_EXT = (
    ".bak", ".old", ".zip", ".sql", ".env", ".conf", ".config", ".ini",
    ".yml", ".yaml", ".xml", ".log", ".tar", ".tgz", ".swp", ".csv",
    ".dump", ".save", ".orig",
)
_INTERESTING_PATHS = ("/.git", "/.svn", "/.env", "/backup", "/dump")
_ADMINISH_RE = re.compile(
    r"/(?:admin|panel|dashboard|manager|staging|stage|test|dev|internal|"
    r"private|backup|cpanel|wp-admin|console|debug)",
    re.IGNORECASE,
)
_DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$"
)
_MAX_LIMIT = 5000
_DISPLAY_CAP = 500


def _validate_domain(domain: str) -> str:
    """Accept ONLY a bare hostname. Reject URLs, paths, wildcards, junk."""
    d = (domain or "").strip().lower().rstrip(".")
    if not d or any(c in d for c in " :/?#*@\\" ) or "://" in d:
        raise ValueError(
            "domain must be a bare hostname (no scheme, path, wildcard or "
            "spaces) — this tool queries web.archive.org only."
        )
    if not _DOMAIN_RE.match(d):
        raise ValueError(f"'{domain}' does not parse as a bare domain name.")
    return d


def _build_params(
    domain: str, limit: int, collapse: bool, statuscode: str
) -> Dict[str, str]:
    params = {
        "url": domain,
        "matchType": "domain",
        "output": "json",
        "fl": _FL,
        "limit": str(int(limit)),
    }
    if collapse:
        params["collapse"] = "urlkey"
    if statuscode:
        params["filter"] = f"statuscode:{statuscode}"
    return params


def _parse_rows(rows: List[List[str]]) -> Dict[str, Any]:
    """CDX JSON = [header, row, row, ...]. Triage into buckets."""
    buckets: Dict[str, List[str]] = {
        "interesting_files": [],
        "param_urls": [],
        "admin_ish": [],
        "all": [],
    }
    seen: set = set()
    timestamps: List[str] = []
    if not rows:
        return {k: [] for k in buckets} | {"oldest": None, "newest": None}
    header = [h.lower() for h in rows[0]]
    idx = {name: i for i, name in enumerate(header)}
    for row in rows[1:]:
        try:
            original = row[idx["original"]]
        except (IndexError, KeyError, TypeError):
            continue
        if original in seen:
            continue
        seen.add(original)
        buckets["all"].append(original)
        low = original.lower()
        path = original.split("?", 1)[0]
        if path.endswith(_INTERESTING_EXT) or any(
            p in low for p in _INTERESTING_PATHS
        ):
            buckets["interesting_files"].append(original)
        if "?" in original:
            buckets["param_urls"].append(original)
        if _ADMINISH_RE.search(original):
            buckets["admin_ish"].append(original)
        ts = row[idx["timestamp"]] if "timestamp" in idx else ""
        if ts and len(ts) >= 4:
            timestamps.append(ts)
    ordered = sorted(timestamps)
    return {
        "interesting_files": buckets["interesting_files"][:250],
        "param_urls": buckets["param_urls"][:250],
        "admin_ish": buckets["admin_ish"][:250],
        "all": buckets["all"][:_DISPLAY_CAP],
        "oldest": ordered[0] if ordered else None,
        "newest": ordered[-1] if ordered else None,
    }


@framework_tool(
    "Passive recon: query the Wayback Machine's CDX index for every URL it "
    "has archived under a domain (subdomains included), and triage results "
    "into bounty-relevant buckets — backup/config/dump files, parameter-"
    "bearing URLs, and admin/staging/dev paths. Dead endpoints that may "
    "still be live are the classic use. Egress is HARD-LOCKED to "
    "web.archive.org: the endpoint is hardcoded, the tool takes a bare "
    "domain (never a URL) and cannot be redirected to any other host. "
    "Domain is scope-gate checked before the query fires.",
    next_hints=["run_ffuf", "probe_web", "extract_js_routes", "report_finding"],
)
def archived_urls(
    domain: str,
    limit: int = 500,
    statuscode: str = "",
    collapse: bool = True,
) -> Dict[str, Any]:
    """Query the Wayback CDX index for ``domain`` (passive, archived only).

    Makes ONE GET to ``web.archive.org/cdx/search/cdx`` with
    ``matchType=domain`` (retries 429/5xx twice with backoff, then stops).
    Nothing is ever fetched from the target itself — this is public
    archive data only.

    Args:
        domain: Bare in-scope hostname, e.g. ``example.com``. Subdomains
            are included via ``matchType=domain``.
        limit: Max rows from the CDX API (cap 5000).
        statuscode: Optional CDX statuscode filter, e.g. ``"200"``.
        collapse: Collapse duplicate urlkeys (default True).
    """
    from utils.scope_gate import check_scan, ScopeGateError

    try:
        d = _validate_domain(domain)
    except ValueError as e:
        return {"status": "Failed", "error": str(e)}

    _sc_ok, _sc_reason = check_scan(d)
    if not _sc_ok:
        raise ScopeGateError(f"scope gate: {_sc_reason}")

    limit = max(1, min(int(limit), _MAX_LIMIT))
    url = f"{_CDX}?{urlencode(_build_params(d, limit, collapse, statuscode))}"

    last_err = ""
    for _attempt, wait in enumerate((0, 2.0, 5.0)):
        if wait:
            time.sleep(wait)
        try:
            r = requests.get(
                url,
                timeout=(10.0, 60.0),
                headers={"User-Agent": _UA},
                allow_redirects=False,
            )
            if r.status_code in (301, 302, 303, 307, 308):
                # Egress is hard-locked to web.archive.org: a redirect from
                # the CDX endpoint means something is wrong — refuse, never
                # follow.
                last_err = (
                    f"cdx endpoint redirected (HTTP {r.status_code}) — "
                    "refusing; egress is locked to web.archive.org"
                )
                break
            if r.status_code == 200:
                rows = r.json()
                parsed = _parse_rows(rows if isinstance(rows, list) else [])
                total = len(parsed.get("all", []))
                return {
                    "status": "Success",
                    "domain": d,
                    "archived": total,
                    "truncated_display": total > _DISPLAY_CAP,
                    "oldest": parsed.get("oldest"),
                    "newest": parsed.get("newest"),
                    "interesting_files": parsed["interesting_files"],
                    "param_urls": parsed["param_urls"],
                    "admin_ish": parsed["admin_ish"],
                    "all": parsed["all"],
                    "note": (
                        "Passive data from web.archive.org only — the target "
                        "was never contacted. Feed paths to run_ffuf; "
                        "'archived but interesting' files may still be live: "
                        "probe_web them. Old param names hint injection "
                        "surface; dead subdomains are takeover candidates."
                    ),
                }
            last_err = f"cdx HTTP {r.status_code}"
            if r.status_code not in (429, 503):
                break
        except requests.exceptions.Timeout:
            last_err = "cdx timeout"
        except requests.exceptions.RequestException as e:
            last_err = f"cdx request error: {type(e).__name__}"
        except ValueError:
            last_err = "cdx returned non-JSON (rate limited?)"

    return {
        "status": "Failed",
        "error": last_err or "cdx query failed",
        "domain": d,
        "endpoint_note": "queries go to web.archive.org only, by design",
    }