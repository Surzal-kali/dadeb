"""HackerOne program scope as a checkable manifest.

Pulls a program's structured scope, scope exclusions, weakness list, and
policy text from the HackerOne Hacker API v1 and turns them into a
machine-readable manifest the secretary model (and the scan tools) can
consult.  This closes two recurring gaps for bug-bounty runs:

* **Scope-compliance enforcement** — ``check_scope(target)`` answers
  "is this host/URL/CIDR/app-id inside the program's authorised assets?"
  *before* a scan tool fires, so a mis-targeted nmap/ffuf/masscan can't
  drift onto a different-org in-scope asset (``og.com``, ``nadex.com``)
  or a genuinely out-of-scope one.  The ``asset_type`` field means
  wildcards, URL hosts, mobile app IDs and blockchain tokens are matched
  correctly rather than treated as bare hostnames.

* **Reportability gate** — ``check_reportable(category_or_cwe)`` tests a
  candidate finding against the program's ``scope_exclusions`` (excluded
  report *categories*, e.g. "missing security headers", "brute force on
  rate-limited logins") and the reportable ``weaknesses`` allowlist, so
  the secretary doesn't burn HackerOne reputation filing N/A/spam-grade
  reports.  ``program_hacktivity`` adds a dedup check against already-
  disclosed reports for the program.

On load, the in-scope DOMAIN/WILDCARD/URL assets are also written to the
workspace ``.scope`` file in the format ``auxiliaries.amass._load_scope``
already consumes, so ``subdomain_enum`` auto-filters against the *real*
HackerOne scope with zero extra wiring.

Authentication
--------------
The structured_scopes / scope_exclusions / program / weaknesses endpoints
require a HackerOne API token (Basic auth, ``<username>:<token>``).  Generate
one at hackerone.com → Settings → API Tokens.  Set ``H1_API_USERNAME`` and
``H1_API_TOKEN`` in the environment (or ``.env``).  ``program_hacktivity``
works without credentials (the hacktivity feed is public); the other tools
return a clear ``auth_required`` error if no token is configured.

The manifest is cached to ``scope/<handle>.json`` under
``WORKSPACE_ROOT``; pass ``refresh=True`` to force a fresh fetch, or rely on
the ``updated_at`` filter for incremental refreshes.
"""

from __future__ import annotations

import html as _html
import ipaddress
import json as _json
import logging
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from constants import framework_tool, resolve_workspace_root

# --- .env loading (sudo-safe) ------------------------------------------------
# When the framework is launched under sudo, the shell environment is stripped
# and .env is never sourced.  Load it here as a module-level safety net so
# H1_API_USERNAME / H1_API_TOKEN (and every other .env var) are available
# regardless of entry point.  override=True is deliberate (operator decision
# 2026-09-25): the framework boots under sudo/root where shell exports don't
# survive env_reset, so .env is the AUTHORITATIVE config channel and
# intentionally stomps any inherited env.  Do NOT "fix" this to override=False.
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=True)
except Exception:
    pass  # dotenv not installed or .env missing — silently degrade


_H1_API = "https://api.hackerone.com/v1"
_TIMEOUT = 30.0


# --- credentials ------------------------------------------------------------

def _h1_auth() -> Tuple[Optional[Tuple[str, str]], bool]:
    """Return ((username, token), has_full_auth) for requests auth.

    ``has_full_auth`` is True only when both env vars are set — the
    structured-scope endpoints need it; hacktivity does not.
    """
    user = os.getenv("H1_API_USERNAME")
    token = os.getenv("H1_API_TOKEN")
    if user and token:
        return ((user, token), True)
    return (None, False)


def _get(path: str, *, params: Optional[Dict[str, Any]] = None,
         auth: Optional[Any] = ...) -> Tuple[int, Any]:
    """GET against the H1 Hacker API.  Returns (status, json).

    By default (``auth=...`` sentinel) the H1 Basic auth tuple is resolved
    via :func:`_h1_auth` and attached.  Pass ``auth=None`` explicitly to
    make an unauthenticated request (used for the public hacktivity feed,
    so stale/bad credentials don't poison a public endpoint with a 401).
    """
    import requests

    if auth is ...:
        auth, _ = _h1_auth()
    url = f"{_H1_API}{path}"
    r = requests.get(url, params=params, auth=auth, headers={"Accept": "application/json"},
                     timeout=_TIMEOUT)
    try:
        body = r.json()
    except ValueError:
        body = r.text
    return (r.status_code, body)


# --- paginated fetch --------------------------------------------------------

def _fetch_all_pages(path: str, *, params: Optional[Dict[str, Any]] = None,
                     max_pages: int = 100) -> Tuple[int, List[Dict[str, Any]], Optional[str]]:
    """Follow pagination links for a list endpoint.

    Returns (status, items, error).  H1 list endpoints wrap items in
    ``data`` and expose ``links.next``.  We also fall back to incrementing
    ``page[number]`` when ``links.next`` is absent.
    """
    params = dict(params or {})
    if "page[size]" not in params:
        params["page[size]"] = 100
    page = int(params.get("page[number]", 1))
    items: List[Dict[str, Any]] = []
    for _ in range(max_pages):
        params["page[number]"] = page
        status, body = _get(path, params=params)
        if status != 200 or not isinstance(body, dict):
            err = None
            if isinstance(body, dict) and body.get("errors"):
                err = str(body["errors"])
            return (status, items, err or f"HTTP {status}")
        data = body.get("data")
        if isinstance(data, list):
            items.extend(data)
        links = body.get("links") or {}
        nxt = links.get("next")
        if not nxt:
            # No link header: stop if this page was short, else keep paging.
            if len(data if isinstance(data, list) else []) < int(params["page[size]"]):
                break
            page += 1
            continue
        # Extract page[number] from the next URL if present, else increment.
        m = re.search(r"page%5Bnumber%5D=(\d+)", nxt) or re.search(r"page\[number\]=(\d+)", nxt)
        if m:
            page = int(m.group(1))
        else:
            page += 1
    return (200, items, None)


# --- manifest construction --------------------------------------------------

def _scope_cache_path(handle: str, platform: str = "h1") -> Path:
    d = resolve_workspace_root() / "scope"
    try:
        d.mkdir(parents=True, exist_ok=True)
    except OSError:
        # Unwritable WORKSPACE_ROOT (sandboxed seat, rebuilt container, or a
        # stale/stomped .env pointing at another user's home): degrade to a
        # stable per-user tmp dir so cache reads/writes stay best-effort and
        # never crash arm()/load_program_scope.  2026-09-25 regression: this
        # mkdir was unconditional and killed arm() with a raw PermissionError
        # (test_arm_requires_manifest) whenever WORKSPACE_ROOT pointed
        # somewhere the runner cannot create.
        d = Path(tempfile.gettempdir()) / "framework-scope-cache"
        try:
            d.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass  # even the fallback failed; callers' guards handle the miss
    name = handle if platform == "h1" else f"{platform}_{handle}"
    return d / f"{name}.json"


def _build_manifest(handle: str) -> Tuple[Dict[str, Any], Optional[str]]:
    """Fetch all H1 scope data for ``handle`` and assemble the manifest dict."""
    auth, has_auth = _h1_auth()
    if not has_auth:
        return ({}, ("auth_required: set H1_API_USERNAME and H1_API_TOKEN "
                     "(generate at hackerone.com → Settings → API Tokens)"))

    # structured scopes (in- AND out-of-scope assets, split by eligible flags)
    st, scopes, err = _fetch_all_pages(f"/hackers/programs/{handle}/structured_scopes")
    if err:
        return ({}, f"structured_scopes: {err}")

    in_scope: List[Dict[str, Any]] = []
    out_of_scope_assets: List[Dict[str, Any]] = []
    for it in scopes:
        a = it.get("attributes", {})
        entry = {
            "id": it.get("id"),
            "asset_type": a.get("asset_type"),
            "asset_identifier": a.get("asset_identifier"),
            "eligible_for_bounty": a.get("eligible_for_bounty"),
            "eligible_for_submission": a.get("eligible_for_submission"),
            "max_severity": a.get("max_severity"),
            "instruction": a.get("instruction"),
            "confidentiality_requirement": a.get("confidentiality_requirement"),
            "integrity_requirement": a.get("integrity_requirement"),
            "availability_requirement": a.get("availability_requirement"),
            "reference": a.get("reference"),
            "updated_at": a.get("updated_at"),
        }
        if a.get("eligible_for_submission"):
            in_scope.append(entry)
        else:
            out_of_scope_assets.append(entry)

    # scope exclusions (excluded report *categories*)
    _, exclusions, _ = _fetch_all_pages(f"/hackers/programs/{handle}/scope_exclusions")
    excluded_categories = [
        {
            "category": e.get("attributes", {}).get("category"),
            "details": e.get("attributes", {}).get("details"),
        }
        for e in exclusions
    ]

    # weaknesses (reportable CWE allowlist)
    _, weaknesses, _ = _fetch_all_pages(f"/hackers/programs/{handle}/weaknesses")
    weakness_list = [
        {
            "id": w.get("id"),
            "name": w.get("attributes", {}).get("name"),
            "external_id": w.get("attributes", {}).get("external_id"),
            "description": w.get("attributes", {}).get("description"),
        }
        for w in weaknesses
    ]

    # program policy text
    pol_status, pol_body = _get(f"/hackers/programs/{handle}")
    policy = ""
    if pol_status == 200 and isinstance(pol_body, dict):
        policy = (pol_body.get("data", {}).get("attributes", {}) or {}).get("policy", "")

    manifest = {
        "handle": handle,
        "fetched_at": time.time(),
        "in_scope": in_scope,
        "out_of_scope_assets": out_of_scope_assets,
        "excluded_categories": excluded_categories,
        "weaknesses": weakness_list,
        "policy": policy,
        "counts": {
            "in_scope": len(in_scope),
            "out_of_scope_assets": len(out_of_scope_assets),
            "excluded_categories": len(excluded_categories),
            "weaknesses": len(weakness_list),
        },
    }
    return (manifest, None)


# --- Bugcrowd lane (public engagement brief, anonymous) ---------------------

_BC_BASE = "https://bugcrowd.com"
_BC_UA = "Mozilla/5.0"  # UA verified against live endpoints Sept 2026
_UUID_RE = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


def _bc_get(url: str, *, accept: str = "application/json") -> Tuple[int, Any]:
    """Anonymous GET against bugcrowd.com. Returns (status, parsed-json-or-text)."""
    import requests

    r = requests.get(url, headers={"Accept": accept, "User-Agent": _BC_UA},
                     timeout=_TIMEOUT)
    if "json" in r.headers.get("content-type", ""):
        try:
            return (r.status_code, r.json())
        except ValueError:
            pass
    return (r.status_code, r.text)


def _bc_fetch_engagement_page(handle: str) -> Tuple[int, str]:
    """Fetch the public engagement page (follows /<handle> -> /engagements/<handle>)."""
    import requests

    r = requests.get(f"{_BC_BASE}/{handle}",
                     headers={"Accept": "text/html", "User-Agent": _BC_UA},
                     timeout=_TIMEOUT)
    return (r.status_code, r.text)


def _bc_brief_url(handle: str, page_html: str) -> Optional[str]:
    """Derive the brief-version-document JSON URL from an engagement page.

    Primary: the page's self-documenting ``data-api-endpoints`` attribute
    (``engagementBriefApi.getBriefVersionDocument``).  Fallback: regex the
    raw HTML for a ``changelog/<uuid>`` path.  The brief app bundle appends
    ``.json`` to endpoint paths — mirrored here.
    """
    m = re.search(r'data-api-endpoints="([^"]+)"', page_html)
    if m:
        try:
            eps = _json.loads(_html.unescape(m.group(1)))
            path = (eps.get("engagementBriefApi") or {}).get("getBriefVersionDocument")
            if path:
                return f"{_BC_BASE}{path}.json"
        except (ValueError, AttributeError):
            pass
    m = re.search(rf"/engagements/{re.escape(handle)}/changelog/({_UUID_RE})", page_html)
    if m:
        return f"{_BC_BASE}/engagements/{handle}/changelog/{m.group(1)}.json"
    return None


def _bc_target_entry(t: Dict[str, Any], group: Dict[str, Any]) -> Dict[str, Any]:
    """Map one Bugcrowd target onto the H1-shaped asset-entry schema."""
    name = (t.get("name") or "").strip()
    ident, note = name, None
    m = re.match(r"^(.*?)\s*\(([^()]*)\)\s*$", name, re.S)
    if m and m.group(1).strip():
        ident, note = m.group(1).strip(), m.group(2).strip()
    category = (t.get("category") or "other").lower()
    uri = t.get("uri")
    ipaddr = t.get("ipAddress")
    if ipaddr:
        atype, ident = "IP", ipaddr
    elif category in ("ios", "android"):
        # app targets carry an app-store uri — type by category, keep store
        # link out of asset_identifier (it would break host matching)
        atype = category.upper()
    elif name.startswith("*."):
        atype = "WILDCARD"
    elif uri:
        atype = "URL"
    elif category == "website":
        atype = "DOMAIN"
        if "://" in ident:  # reduce bare URLs to hosts for DOMAIN semantics
            ident = urlparse(ident).hostname or ident
    elif category in ("ios", "android"):
        atype = category.upper()
    else:
        atype = "OTHER"
    return {
        "id": t.get("id"),
        "asset_type": atype,
        "asset_identifier": ident,
        "raw_identifier": name,
        "eligible_for_bounty": bool(group.get("rewardRange")),
        "max_severity": None,
        "instruction": note,
        "confidentiality_requirement": None,
        "integrity_requirement": None,
        "availability_requirement": None,
        "reference": group.get("name"),
        "updated_at": None,
        "bc_category": category,
        "bc_tags": [tg.get("name") for tg in (t.get("tags") or []) if tg.get("name")],
    }


def _bc_build_manifest(handle: str) -> Tuple[Dict[str, Any], Optional[str]]:
    """Fetch a public Bugcrowd engagement brief anonymously; H1-shaped manifest."""
    st, page = _bc_fetch_engagement_page(handle)
    if st != 200:
        return ({}, f"engagement page: HTTP {st} (handle may not exist or program is private)")
    brief_url = _bc_brief_url(handle, page)
    if not brief_url:
        return ({}, "no brief endpoint on engagement page (no data-api-endpoints, "
                    "no changelog/<uuid>) — program may be private or non-standard")
    bst, brief = _bc_get(brief_url)
    if bst != 200 or not isinstance(brief, dict):
        return ({}, f"brief fetch: HTTP {bst} at {brief_url}")
    data = brief.get("data") or {}
    scope = data.get("scope")
    if not isinstance(scope, list) or not scope:
        return ({}, "brief JSON has no data.scope target groups — unsupported layout")
    b = data.get("brief") or {}
    in_scope: List[Dict[str, Any]] = []
    out_of_scope_assets: List[Dict[str, Any]] = []
    for g in scope:
        is_in = bool(g.get("inScope"))
        for t in (g.get("targets") or []):
            entry = _bc_target_entry(t, g)
            entry["eligible_for_submission"] = is_in
            (in_scope if is_in else out_of_scope_assets).append(entry)
    manifest = {
        "handle": handle,
        "platform": "bugcrowd",
        "fetched_at": time.time(),
        "in_scope": in_scope,
        "out_of_scope_assets": out_of_scope_assets,
        "excluded_categories": [],   # Bugcrowd briefs carry no structured exclusions
        "weaknesses": [],            # ...and no structured weakness allowlist
        "policy": b.get("description") or "",
        "program_name": b.get("name"),
        "safe_harbor": b.get("safeHarborStatus"),
        "counts": {
            "in_scope": len(in_scope),
            "out_of_scope_assets": len(out_of_scope_assets),
            "excluded_categories": 0,
            "weaknesses": 0,
        },
        "_warning": ("bugcrowd lane: check_reportable unsupported (no structured "
                     "exclusions/weaknesses in brief); reward info is per-group "
                     "(rewardRange), max_severity is None"),
    }
    return (manifest, None)


# --- Intigriti lane (Researcher API v1, PAT-gated) --------------------------
#
# The Intigriti researcher API (https://api.intigriti.com/external/researcher)
# uses Bearer-token auth with a Personal Access Token (PAT), generated from
# the Intigriti web UI → Settings → Personal access tokens.  Unlike H1, the
# detail endpoint takes a GUID ``programId``, not a handle — so we first list
# all accessible programs and resolve the handle to its GUID.
#
# Intigriti domains carry a **tier** (Tier 1/2/3, No bounty, Out of scope)
# instead of H1's ``eligible_for_bounty`` / ``eligible_for_submission`` flags.
# Tier "Out of scope" → out_of_scope_assets; everything else → in_scope.
# There are no structured scope_exclusions or weaknesses allowlists (the
# rules of engagement are prose), so check_reportable returns an explicit
# ``unsupported`` envelope (same as Bugcrowd).  The API does expose structured
# testing requirements (max requests/sec, custom User-Agent, request header)
# which we capture in the manifest so scan tools can self-configure.

_INTI_API = "https://api.intigriti.com/external/researcher"

# Intigriti domain type (value string) → H1-shaped asset_type.
_INTI_DOMAIN_TYPE_MAP: Dict[str, str] = {
    "URL": "URL",
    "Android": "ANDROID",
    "IOS": "IOS",
    "IP range": "CIDR",
    "Device": "OTHER",
    "Other": "OTHER",
    "Wildcard": "WILDCARD",
}
_inti_unmapped_type_logged: bool = False


def _inti_auth() -> Optional[str]:
    """Return the Intigriti PAT bearer token, or None if not configured."""
    return os.getenv("INTIGRITI_API_TOKEN")


def _inti_get(path: str, *, params: Optional[Dict[str, Any]] = None) -> Tuple[int, Any]:
    """GET against the Intigriti Researcher API with Bearer auth."""
    import requests

    token = _inti_auth()
    headers: Dict[str, str] = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = requests.get(f"{_INTI_API}{path}", params=params, headers=headers,
                     timeout=_TIMEOUT)
    try:
        body = r.json()
    except ValueError:
        body = r.text
    return (r.status_code, body)


def _inti_resolve_handle(handle: str) -> Tuple[Optional[str], Optional[str]]:
    """Resolve a program ``handle`` to its GUID ``programId``.

    Intigriti's detail endpoint requires a GUID, not a handle, so we page
    through ``GET /v1/programs`` (max 500/page) and match by ``handle``.
    Returns ``(program_id, error)``.
    """
    offset = 0
    for _ in range(20):  # max 20 pages × 500 = 10 000 programs
        status, body = _inti_get("/v1/programs", params={"limit": 500, "offset": offset})
        if status != 200 or not isinstance(body, dict):
            return (None, f"program listing: HTTP {status}")
        records = body.get("records") or []
        for rec in records:
            if (rec.get("handle") or "").lower() == handle.lower():
                return (rec.get("id"), None)
        max_count = body.get("maxCount", 0)
        offset += len(records)
        if not records or offset >= max_count:
            break
    # Self-diagnosing not-found: if Intigriti renames/omits the ``handle``
    # field, the error surfaces the first record's available keys so a
    # schema drift is obvious without a debugger session.
    available_keys = sorted(records[0].keys()) if records else "no records returned"
    return (None, f"handle {handle!r} not found in program listing "
                  f"(you may not have access, or the handle is wrong; "
                  f"first record keys: {available_keys})")


def _inti_map_domain(d: Dict[str, Any]) -> Dict[str, Any]:
    """Map one Intigriti ``DomainViewModel`` onto the H1-shaped asset schema."""
    global _inti_unmapped_type_logged
    dtype = (d.get("type") or {}).get("value") or "Other"
    atype = _INTI_DOMAIN_TYPE_MAP.get(dtype, "OTHER")
    if atype == "OTHER" and dtype not in _INTI_DOMAIN_TYPE_MAP:
        # One-time log so a new Intigriti domain type value surfaces instead
        # of silently degrading to OTHER.  Benign today (matching is
        # identifier-driven), but worth knowing about for forward compat.
        if not _inti_unmapped_type_logged:
            logging.getLogger(__name__).warning(
                "intigriti: unmapped domain type %r fell back to OTHER "
                "(add it to _INTI_DOMAIN_TYPE_MAP for correct typing)", dtype)
            _inti_unmapped_type_logged = True
    endpoint = (d.get("endpoint") or "").strip()
    tier = (d.get("tier") or {}).get("value") or ""
    desc = d.get("description") or ""

    # IP range without a CIDR mask → treat as /32 (single host)
    if atype == "CIDR" and "/" not in endpoint:
        endpoint = f"{endpoint}/32"

    tier_lc = tier.lower()
    return {
        "id": d.get("id"),
        "asset_type": atype,
        "asset_identifier": endpoint,
        "eligible_for_bounty": tier_lc not in ("no bounty", "out of scope", ""),
        "eligible_for_submission": tier_lc != "out of scope",
        "max_severity": None,
        "instruction": desc or None,
        "confidentiality_requirement": None,
        "integrity_requirement": None,
        "availability_requirement": None,
        "reference": None,
        "updated_at": None,
        "inti_tier": tier,
    }


def _inti_build_manifest(handle: str) -> Tuple[Dict[str, Any], Optional[str]]:
    """Fetch a program's scope + rules of engagement from the Intigriti
    Researcher API and assemble an H1-shaped manifest.

    Requires ``INTIGRITI_API_TOKEN`` (PAT) in the environment.
    """
    token = _inti_auth()
    if not token:
        return ({}, ("auth_required: set INTIGRITI_API_TOKEN "
                     "(generate at app.intigriti.com → Settings → "
                     "Personal access tokens)"))

    # Step 1: resolve handle → GUID programId
    program_id, err = _inti_resolve_handle(handle)
    if err:
        return ({}, err)

    # Step 2: fetch program detail (includes domains + rules of engagement)
    status, body = _inti_get(f"/v1/programs/{program_id}")
    if status != 200 or not isinstance(body, dict):
        if status == 403:
            return ({}, "HTTP 403: you must accept the program's terms and "
                        "conditions via the Intigriti web interface before "
                        "the API grants detail access")
        return ({}, f"program detail: HTTP {status}")

    # Step 3: extract domains (versioned blob → content list)
    domains_version = body.get("domains") or {}
    domains = domains_version.get("content") or []
    in_scope: List[Dict[str, Any]] = []
    out_of_scope_assets: List[Dict[str, Any]] = []
    for d in domains:
        entry = _inti_map_domain(d)
        (in_scope if entry.get("eligible_for_submission")
         else out_of_scope_assets).append(entry)

    # Step 4: extract rules of engagement (versioned blob → content)
    roe_version = body.get("rulesOfEngagement") or {}
    roe_content = roe_version.get("content") or {}
    policy = roe_content.get("description") or ""
    testing_req = roe_content.get("testingRequirements") or {}
    safe_harbour = roe_content.get("safeHarbour")
    attachments = roe_version.get("attachments") or []

    # Program metadata
    conf_level = (body.get("confidentialityLevel") or {}).get("value")
    prog_status = (body.get("status") or {}).get("value")
    prog_type = (body.get("type") or {}).get("value")
    prog_name = body.get("name")

    manifest = {
        "handle": handle,
        "platform": "intigriti",
        "program_id": program_id,
        "program_name": prog_name,
        "fetched_at": time.time(),
        "in_scope": in_scope,
        "out_of_scope_assets": out_of_scope_assets,
        "excluded_categories": [],   # Intigriti RoE is prose, not structured
        "weaknesses": [],            # ...no structured CWE allowlist
        "policy": policy,
        "safe_harbor": safe_harbour,
        "testing_requirements": {
            "intigriti_me": testing_req.get("intigritiMe"),
            "max_requests_per_second": testing_req.get("automatedTooling"),
            "user_agent": testing_req.get("userAgent"),
            "request_header": testing_req.get("requestHeader"),
        },
        "roe_attachments": [{"url": a.get("url")} for a in attachments],
        "confidentiality_level": conf_level,
        "program_status": prog_status,
        "program_type": prog_type,
        "counts": {
            "in_scope": len(in_scope),
            "out_of_scope_assets": len(out_of_scope_assets),
            "excluded_categories": 0,
            "weaknesses": 0,
        },
        "_warning": ("intigriti lane: check_reportable unsupported (no structured "
                     "exclusions/weaknesses in API; judge from RoE prose "
                     "[manifest['policy']]); no hacktivity/disclosed-reports "
                     "endpoint available for researchers; testing_requirements "
                     "may mandate a custom User-Agent or request header — "
                     "consult manifest['testing_requirements']"),
    }
    return (manifest, None)


def _write_scope_file(manifest: Dict[str, Any]) -> Optional[str]:
    """Write amass-compatible ``.scope`` from DOMAIN/WILDCARD/URL assets.

    Returns the path written, or None if nothing applicable.  Format matches
    ``auxiliaries.amass._load_scope``: ``*.example.com`` (wildcard),
    ``example.com`` (domain + subdomains), ``api.example.com`` (exact),
    ``#`` comments.  URL assets are reduced to their host.
    """
    patterns: List[str] = []

    def _hostlike(s: str) -> bool:
        # Skip policy prose ("Any host verified to be owned by Tesla...") —
        # only wildcard/host-shaped identifiers belong in the amass filter.
        return bool(re.match(r"^(\*\.)?[a-z0-9]([a-z0-9*._-]*[a-z0-9])?$", s.strip(), re.I))

    def _scope_pattern(atype: str, ident: str) -> Optional[str]:
        """Return the amass-filter pattern for one asset, or None to skip.

        For DOMAIN/WILDCARD the identifier is already host-shaped, so the
        _hostlike guard is applied directly.  For URL assets the raw
        identifier often carries a scheme (``https://host/path``) that would
        fail _hostlike, so the host is extracted FIRST and the guard is
        applied to the extracted host — otherwise a URL-only asset with no
        wildcard parent is silently dropped from the amass filter.
        """
        ident = (ident or "").strip()
        if not ident:
            return None
        if atype in ("WILDCARD", "DOMAIN"):
            return ident if _hostlike(ident) else None
        if atype == "URL":
            host = urlparse(ident if "://" in ident else f"http://{ident}").hostname
            return host if (host and _hostlike(host)) else None
        return None

    for a in manifest.get("in_scope", []):
        p = _scope_pattern((a.get("asset_type") or "").upper(),
                           a.get("asset_identifier") or "")
        if p:
            patterns.append(p)
    if not patterns:
        return None
    # Out-of-scope DOMAIN/WILDCARD/URL assets become `!`-prefixed deny lines
    # so amass's filter can exclude explicit OOS hosts even when they also
    # match an in-scope wildcard.  amass._load_scope returns these separately.
    for a in manifest.get("out_of_scope_assets", []):
        p = _scope_pattern((a.get("asset_type") or "").upper(),
                           a.get("asset_identifier") or "")
        if p:
            patterns.append("!" + p)
    platform = manifest.get("platform", "h1")
    scope_path = (resolve_workspace_root()
                  / f"{platform}_{manifest.get('handle', 'unknown')}.scope")
    seen = set()
    lines = [f"# Auto-generated from {platform.upper()} program scope — do not edit by hand.",
             f"# Source: {manifest.get('handle')} @ {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(manifest.get('fetched_at', time.time())))}"]
    for p in patterns:
        if p not in seen:
            seen.add(p)
            lines.append(p)
    try:
        scope_path.write_text("\n".join(lines) + "\n")
    except OSError as exc:
        # Derived .scope file is best-effort: the manifest stays valid even
        # when the workspace dir is unwritable (amass just gets no filter).
        logging.getLogger(__name__).warning(
            "scope file write failed (best-effort, ignored): %s", exc
        )
        return ""
    return str(scope_path)


def _save_cache(handle: str, manifest: Dict[str, Any], platform: str = "h1") -> str:
    # Cache write is best-effort: a successful live fetch must not die just
    # because the cache dir is unwritable (callers ignore this return).
    try:
        p = _scope_cache_path(handle, platform)
        p.write_text(_json.dumps(manifest, indent=2))
        return str(p)
    except OSError as exc:
        logging.getLogger(__name__).warning(
            "scope cache write failed (best-effort, ignored): %s", exc
        )
        return ""


def _load_cache(handle: str, platform: str = "h1") -> Optional[Dict[str, Any]]:
    p = _scope_cache_path(handle, platform)
    if not p.is_file():
        return None
    try:
        return _json.loads(p.read_text())
    except (OSError, ValueError):
        return None


# --- scan-config resolver (shared by ffuf / ZAP / amass) --------------------
#
# ``check_scope`` surfaces ``scan_config_required`` inline on positive
# verdicts, but that only helps if the *caller* reads it and acts on it.
# In a busy session the secretary model can forget to pass the custom UA /
# header / rate cap to ffuf or ZAP, and day-one traffic on a reopened
# program burns good standing.
#
# ``get_scan_config`` is the enforcement-by-code backstop: any scan tool
# that accepts ``scope_handle`` / ``scope_platform`` calls this to resolve
# the program's testing requirements into concrete, ready-to-inject
# values so headers and rate caps are auto-applied even when the secretary
# omits them.
#
# Platform coverage:
#   intigriti — structured testingRequirements in the API (custom UA with
#       intigriti:{Username}, X-Intigriti-Username header, req/sec cap).
#   h1 — no structured field; H1's own Traffic Identification docs
#       (docs.hackerone.com/en/articles/8369822) recommend
#       X-HackerOne-Research: [username].  We inject that as a default
#       and best-effort scan the policy text + per-asset instruction
#       fields for explicit per-program requirements (rate limits, custom
#       headers, custom UA).
#   bugcrowd — no structured field, no platform-wide identification
#       header; we inject a researcher-identifying UA suffix as a default
#       and best-effort scan the brief description for explicit
#       requirements.

_STANDARD_BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) "
    "Gecko/20100101 Firefox/128.0"
)

_RI_PREFIX = "intigriti-roar-"  # replacer/rate-limit rule descriptions

# Regex patterns for best-effort prose parsing of testing requirements.
_RATE_RE = re.compile(
    r"(?:max(?:imum)?\s+)?(\d+)\s+req(?:uest)?s?(?:ests)?\s*(?:per|/)\s*s(?:ec|econd)?s?",
    re.I,
)
_RATE_RE_ALT = re.compile(
    r"(?:rate\s*limit(?:ed)?\s*(?:to|of)?\s*)(\d+)\s*(?:rps|req/s|req/sec)",
    re.I,
)
# "X-Some-Header: value" in policy text — must look like a real HTTP header.
_CUSTOM_HEADER_RE = re.compile(
    r"(X-[A-Za-z][\w-]*):\s*(\S[^\n]{0,200})",
)
# "User-Agent: ..." in policy text.
_CUSTOM_UA_RE = re.compile(
    r"User-Agent\s*:\s*(\S[^\n]{0,200})",
    re.I,
)


def _parse_prose_testing_reqs(text: str) -> Dict[str, Any]:
    """Best-effort extraction of testing requirements from prose text.

    Scans policy / instruction / brief-description text for rate-limit,
    custom-header, and custom-User-Agent signals.  Returns a dict with
    optional keys ``user_agent``, ``request_header``, ``max_requests_per_second``
    — only keys that matched are included.  This is intentionally
    conservative: false negatives (missing a requirement) are acceptable
    because the platform-default identification is always applied; false
    positives (injecting a non-required header) could annoy the program.
    """
    if not text:
        return {}
    result: Dict[str, Any] = {}

    # --- Rate limit ---
    for rx in (_RATE_RE, _RATE_RE_ALT):
        m = rx.search(text)
        if m:
            try:
                rate = int(m.group(1))
                if 0 < rate <= 10000:  # sanity bounds
                    result["max_requests_per_second"] = rate
                    break
            except (ValueError, IndexError):
                pass

    # --- Custom User-Agent ---
    m = _CUSTOM_UA_RE.search(text)
    if m:
        result["user_agent"] = m.group(1).strip().rstrip(".")

    # --- Custom headers ---
    for m in _CUSTOM_HEADER_RE.finditer(text):
        hname = m.group(1)
        hval = m.group(2).strip().rstrip(".")
        # Stash as "Name: Value" — the caller splits on colon.
        result.setdefault("request_header", hname + ": " + hval)
        break  # first custom header only; additional ones are rare

    return result


def _resolve_username(platform: str) -> str:
    """Return the researcher username for the given platform from env vars."""
    if platform == "intigriti":
        return os.getenv("INTIGRITI_USERNAME", "")
    if platform == "h1":
        return os.getenv("H1_API_USERNAME", "")
    if platform == "bugcrowd":
        return os.getenv("BUGCROWD_USERNAME", "") or os.getenv("H1_API_USERNAME", "")
    return os.getenv("RESEARCHER_USERNAME", "")


def get_scan_config(handle: str, platform: str = "h1") -> Optional[Dict[str, Any]]:
    """Resolve a program's testing requirements into concrete, injectable
    scan configuration for ffuf / ZAP / amass.

    Loads the cached manifest for ``(handle, platform)`` and returns a
    normalized dict:

    .. code-block:: python

        {
            "platform": "intigriti",
            "handle": "adobepublic",
            "headers": {"User-Agent": "...", "X-Intigriti-Username": "..."},
            "max_requests_per_second": 20,
            "source": "structured",   # or "platform-default", "prose"
        }

    **Platform behaviour:**

    - **intigriti**: structured ``testing_requirements`` from the API.
      ``{Username}`` is substituted from ``INTIGRITI_USERNAME``.
    - **h1**: no structured field in the API.  H1's Traffic Identification
      docs recommend ``X-HackerOne-Research: [username]`` — that header is
      always injected (from ``H1_API_USERNAME``).  Policy text and per-asset
      ``instruction`` fields are best-effort scanned for explicit
      per-program rate limits or custom headers.
    - **bugcrowd**: no platform-wide identification header.  A
      researcher-identifying suffix is appended to the User-Agent (from
      ``BUGCROWD_USERNAME`` or ``H1_API_USERNAME``).  Brief description is
      best-effort scanned for explicit requirements.

    Returns ``None`` when no manifest is cached.  Otherwise always returns
    a config dict — even for H1/Bugcrowd programs with no explicit
    requirements, the platform-default identification is applied so the
    secretary never fires completely anonymous traffic.
    """
    platform = (platform or "h1").strip().lower()
    manifest = _load_cache(handle, platform)
    if manifest is None:
        return None

    if platform == "intigriti":
        return _get_scan_config_intigriti(manifest, handle)
    if platform == "h1":
        return _get_scan_config_h1(manifest, handle)
    if platform == "bugcrowd":
        return _get_scan_config_bugcrowd(manifest, handle)
    return None


def get_armed_scan_config() -> Optional[Dict[str, Any]]:
    """Resolve scan config from the OPERATOR-ARMED scope state (no args).

    Reads ``scope/.armed_packet_scope.json`` — the same file-backed state the
    packet gate enforces from (READ-ONLY here) — for the armed
    ``(handle, platform)`` and resolves that program's testing requirements
    via :func:`get_scan_config`.

    This is the zero-argument backstop for traffic tools that never receive a
    ``scope_handle`` (ssrf_probe, the playwright sidecar): identification
    headers and rate caps get applied by construction instead of by secretary
    discipline. Returns ``None`` when nothing is armed or no manifest is
    cached — callers then fall back to their own identification defaults.
    """
    state_path = (resolve_workspace_root()
                  / "scope" / ".armed_packet_scope.json")
    try:
        state = _json.loads(state_path.read_text())
    except (OSError, ValueError):
        return None
    handle = (state.get("handle") or "").strip()
    if not handle:
        return None
    platform = (state.get("platform") or "h1").strip().lower()
    return get_scan_config(handle, platform)


def _normalise_rate(raw: Any) -> Optional[int]:
    """Coerce a rate value to int or None (0 / None / negative → None)."""
    if raw is None:
        return None
    try:
        r = int(raw)
    except (TypeError, ValueError):
        return None
    return r if r > 0 else None


def _get_scan_config_intigriti(manifest: Dict[str, Any],
                               handle: str) -> Optional[Dict[str, Any]]:
    """Intigriti: structured testing_requirements from the API."""
    tr = manifest.get("testing_requirements") or {}
    ua_raw = tr.get("user_agent")
    hdr_raw = tr.get("request_header")
    rate = _normalise_rate(tr.get("max_requests_per_second"))
    if not ua_raw and not hdr_raw and not rate:
        return None  # program mandates no custom UA / header / rate

    username = os.getenv("INTIGRITI_USERNAME", "")
    headers: Dict[str, str] = {}

    def _resolve_placeholders(raw: str) -> str:
        s = raw or ""
        if username:
            s = s.replace("{Username}", username)
        s = s.replace("<standard browser/tool user agent>", _STANDARD_BROWSER_UA)
        return s.strip()

    if ua_raw:
        ua_val = _resolve_placeholders(ua_raw)
        if ua_val.lower().startswith("user-agent:"):
            ua_val = ua_val[len("user-agent:"):].strip()
        headers["User-Agent"] = ua_val

    if hdr_raw:
        hdr_val = _resolve_placeholders(hdr_raw)
        if ":" in hdr_val:
            hname, _, hval = hdr_val.partition(":")
            headers[hname.strip()] = hval.strip()

    return {
        "platform": "intigriti",
        "handle": handle,
        "headers": headers,
        "max_requests_per_second": rate,
        "source": "structured",
    }


def _get_scan_config_h1(manifest: Dict[str, Any],
                        handle: str) -> Dict[str, Any]:
    """HackerOne: default identification header + best-effort prose parsing.

    H1's Traffic Identification docs recommend ``X-HackerOne-Research:
    [username]``.  We always inject that as a baseline so traffic is
    attributable, then best-effort scan the policy text and per-asset
    instruction fields for explicit per-program requirements (rate limits,
    custom headers, custom UA).
    """
    username = os.getenv("H1_API_USERNAME", "")
    headers: Dict[str, str] = {}
    rate: Optional[int] = None
    sources: List[str] = ["platform-default"]

    # --- Default: H1-recommended identification header -------------------
    if username:
        headers["X-HackerOne-Research"] = username

    # --- Best-effort: scan policy + instructions for explicit reqs -------
    prose_parts: List[str] = [manifest.get("policy") or ""]
    for a in manifest.get("in_scope", []):
        inst = a.get("instruction")
        if inst:
            prose_parts.append(inst)
    prose = "\n".join(prose_parts)
    parsed = _parse_prose_testing_reqs(prose)

    if parsed:
        sources = ["platform-default", "prose"]
        if parsed.get("user_agent"):
            headers["User-Agent"] = parsed["user_agent"]
        if parsed.get("request_header"):
            hdr_val = parsed["request_header"]
            if ":" in hdr_val:
                hname, _, hval = hdr_val.partition(":")
                hname = hname.strip()
                # Don't let a prose template (e.g. "X-HackerOne-Research:
                # your_username") overwrite the resolved default — only
                # add headers the default didn't already set.
                if hname not in headers:
                    headers[hname] = hval.strip()
        rate = parsed.get("max_requests_per_second")

    return {
        "platform": "h1",
        "handle": handle,
        "headers": headers,
        "max_requests_per_second": _normalise_rate(rate),
        "source": "+".join(sources),
    }


def _get_scan_config_bugcrowd(manifest: Dict[str, Any],
                              handle: str) -> Dict[str, Any]:
    """Bugcrowd: default UA suffix + best-effort prose parsing.

    Bugcrowd has no platform-wide identification header.  Community
    practice is to append a researcher-identifying suffix to the
    User-Agent.  We do that as a baseline, then best-effort scan the
    brief description for explicit per-program requirements.
    """
    username = (os.getenv("BUGCROWD_USERNAME", "")
                or os.getenv("H1_API_USERNAME", ""))
    headers: Dict[str, str] = {}
    rate: Optional[int] = None
    sources: List[str] = ["platform-default"]

    # --- Default: researcher-identifying UA suffix ------------------------
    if username:
        headers["User-Agent"] = f"{_STANDARD_BROWSER_UA} (Bugcrowd:{username})"

    # --- Best-effort: scan brief description for explicit reqs ------------
    parsed = _parse_prose_testing_reqs(manifest.get("policy") or "")
    if parsed:
        sources = ["platform-default", "prose"]
        if parsed.get("user_agent"):
            headers["User-Agent"] = parsed["user_agent"]
        if parsed.get("request_header"):
            hdr_val = parsed["request_header"]
            if ":" in hdr_val:
                hname, _, hval = hdr_val.partition(":")
                hname = hname.strip()
                if hname not in headers:
                    headers[hname] = hval.strip()
        rate = parsed.get("max_requests_per_second")

    return {
        "platform": "bugcrowd",
        "handle": handle,
        "headers": headers,
        "max_requests_per_second": _normalise_rate(rate),
        "source": "+".join(sources),
    }


# --- scope matching ---------------------------------------------------------

def _host_of(target: str) -> str:
    """Extract a bare hostname from a URL/host-ish string."""
    t = target.strip()
    if "://" in t:
        h = urlparse(t).hostname
        return (h or "").lower()
    # strip any :port
    return t.split(":")[0].split("/")[0].lower()


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip())
        return True
    except ValueError:
        return False


def _match_asset(target: str, asset: Dict[str, Any]) -> bool:
    """Test whether ``target`` falls under one in-scope asset."""
    atype = (asset.get("asset_type") or "").upper()
    ident = (asset.get("asset_identifier") or "").strip()
    if not ident:
        return False
    t = target.strip()

    if atype == "WILDCARD":
        # *.crypto.com  ->  matches crypto.com and any subdomain
        root = ident.lstrip("*.").lower()
        host = _host_of(t)
        return host == root or host.endswith("." + root)
    if atype == "DOMAIN":
        root = ident.lower()
        host = _host_of(t)
        return host == root or host.endswith("." + root)
    if atype == "URL":
        host = _host_of(t)
        ahost = _host_of(ident)
        if host != ahost:
            return False
        # if the asset has a path, a URL target under that path is in scope
        apath = urlparse(ident if "://" in ident else f"http://{ident}").path or "/"
        tpath = urlparse(t if "://" in t else f"http://{t}").path or "/"
        if apath in ("/", ""):
            return True
        return tpath == apath or tpath.startswith(apath.rstrip("/") + "/")
    if atype == "CIDR":
        try:
            net = ipaddress.ip_network(ident, strict=False)
            ip = ipaddress.ip_address(_host_of(t) if _is_ip(_host_of(t)) else t)
            return ip in net
        except ValueError:
            return False
    if atype in ("IP", "IP_ADDRESS"):
        try:
            return ipaddress.ip_address(t.strip()) == ipaddress.ip_address(ident)
        except ValueError:
            return False
    if atype in ("ANDROID", "IOS"):
        return t.strip().lower() == ident.lower()
    if atype == "BLOCKCHAIN":
        return ident.lower() in t.lower() or t.lower() in ident.lower()
    # OTHER / unknown: substring match as a last resort
    return ident.lower() in t.lower()


def _find_match(target: str, assets: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Find the best-matching asset for ``target``.

    Two passes so a specific asset (URL with a path, IP, CIDR, app id,
    blockchain token) wins over a broad WILDCARD/DOMAIN that would also
    match the same host — e.g. ``https://crypto.com/exchange/BTC`` should
    bind to the ``https://crypto.com/exchange`` URL asset (with its own
    max_severity / CIA requirements) rather than to ``*.crypto.com``.
    """
    specific = {"URL", "IP", "IP_ADDRESS", "CIDR", "ANDROID", "IOS", "BLOCKCHAIN", "OTHER"}
    for a in assets:
        if (a.get("asset_type") or "").upper() in specific and _match_asset(target, a):
            return a
    for a in assets:
        if _match_asset(target, a):
            return a
    return None


# --- tools ------------------------------------------------------------------

@framework_tool(
    "Load a bug-bounty program's scope as a structured, checkable "
    "manifest (platform='h1' HackerOne API [default, member-gated], "
    "platform='bugcrowd' public engagement brief [anonymous, public "
    "programs], or platform='intigriti' Researcher API v1 [PAT-gated]): "
    "in-scope assets (typed: URL/WILDCARD/DOMAIN/CIDR/"
    "IP/ANDROID/IOS/BLOCKCHAIN with max_severity and CIA requirements), "
    "out-of-scope assets, excluded report categories, the reportable "
    "weakness/CWE allowlist, and the program policy text. Also writes the "
    "workspace .scope file so subdomain_enum auto-filters against the real "
    "program scope. Cached to disk; pass refresh=True to force a fresh "
    "fetch. H1 requires H1_API_USERNAME and H1_API_TOKEN; Intigriti "
    "requires INTIGRITI_API_TOKEN; Bugcrowd is anonymous.",
    next_hints=["check_scope", "check_reportable", "subdomain_enum"],
)
def load_program_scope(handle: str = "crypto", refresh: bool = False,
                       platform: str = "h1") -> Dict[str, Any]:
    """Fetch (or load cached) program scope for ``handle``.

    Args:
        handle: The program handle, e.g. ``"crypto"`` (H1), ``"tesla"``
            (Bugcrowd), or ``"sap"`` (Intigriti).  Defaults to ``"crypto"``.
        refresh: If True, ignore the on-disk cache and fetch fresh.
        platform: ``"h1"`` (HackerOne API, member-gated; default),
            ``"bugcrowd"`` (public engagement brief, anonymous), or
            ``"intigriti"`` (Researcher API v1, PAT-gated).
    """
    platform = (platform or "h1").strip().lower()
    if platform not in ("h1", "bugcrowd", "intigriti"):
        return {"handle": handle, "platform": platform,
                "status": "error", "error": f"unknown platform {platform!r}"}
    if not refresh:
        cached = _load_cache(handle, platform)
        if cached:
            cached["_cache"] = "hit"
            return cached

    if platform == "bugcrowd":
        manifest, err = _bc_build_manifest(handle)
    elif platform == "intigriti":
        manifest, err = _inti_build_manifest(handle)
    else:
        manifest, err = _build_manifest(handle)
    if err:
        # Fall back to cache if the live fetch failed but we have one.
        cached = _load_cache(handle)
        if cached:
            cached["_cache"] = "stale-fallback"
            cached["_warning"] = f"live fetch failed ({err}); serving cached copy"
            return cached
        return {"handle": handle, "status": "error", "error": err}

    _save_cache(handle, manifest, platform)
    scope_path = _write_scope_file(manifest)
    manifest["_cache"] = "miss"
    manifest["scope_file"] = scope_path
    manifest["status"] = "ok"
    return manifest


# --- board-wide program search ----------------------------------------------
#
# Keyword discovery ACROSS a board's program listing — recon of the boards
# themselves, not verdicts about a target.  What the researcher APIs actually
# expose, honestly:
#   * H1:        GET /hackers/programs — paged index of programs available to
#                the credentialed researcher (attributes include handle, name,
#                submission_state, offers_bounties).  No structured DOLLAR
#                bounty table: per-asset bounty eligibility + max_severity
#                come from structured_scopes; dollar figures live in policy
#                prose.
#   * Intigriti: GET /v1/programs — paged list of accessible programs
#                (handle + GUID + name + status/type enums).  Bounty shape is
#                tiers, not dollars (see _inti_map_domain).
#   * Bugcrowd:  no public program-list API in this lane — anonymous access is
#                per-engagement-page only, so the lane accepts an exact handle
#                probe.  Reward info is per-group rewardRange inside the brief
#                (see _bc_target_entry / _bc_build_manifest).
# Fetch lane only: queries the board APIs, never touches a target, and has
# nothing to do with the traffic-sending scope gate.

def _enumval(v: Any) -> Any:
    """Intigriti-style enum (``{'value': x}``) → ``x``; passthrough otherwise."""
    return v.get("value") if isinstance(v, dict) else v


def _h1_search_programs(query: str, limit: int) -> Tuple[List[Dict[str, Any]], Optional[str], bool]:
    """Client-side keyword match over the H1 program index (10 pages × 100).

    Returns ``(rows, error, truncated)``.  Matching is substring on name+handle
    — the researchers' index exposes no server-side search param, so we page
    and filter ourselves.
    """
    auth, has_auth = _h1_auth()
    if not has_auth:
        return [], ("auth_required: set H1_API_USERNAME and H1_API_TOKEN "
                    "(generate at hackerone.com → Settings → API Tokens)"), False
    kw = query.lower()
    rows: List[Dict[str, Any]] = []
    truncated = False
    for page in range(1, 11):
        params: Dict[str, Any] = {"page[size]": 100, "page[number]": page}
        status, body = _get("/hackers/programs", params=params)
        if status != 200 or not isinstance(body, dict):
            err = None
            if isinstance(body, dict) and body.get("errors"):
                err = str(body["errors"])
            return [], err or f"program index: HTTP {status}", truncated
        for it in (body.get("data") or []):
            a = (it.get("attributes") or {}) if isinstance(it, dict) else {}
            hay = f"{a.get('name', '')} {a.get('handle', '')}".lower()
            if kw in hay:
                rows.append({
                    "platform": "h1",
                    "handle": a.get("handle"),
                    "name": a.get("name"),
                    "bounty": bool(a.get("offers_bounties")),
                    "state": _enumval(a.get("submission_state")),
                })
                if len(rows) >= limit:
                    return rows, None, truncated
        if not (body.get("links") or {}).get("next"):
            break
        if page == 10:
            truncated = True
    return rows, None, truncated


def _inti_search_programs(query: str, limit: int) -> Tuple[List[Dict[str, Any]], Optional[str], bool]:
    """Client-side keyword match over the Intigriti program list (10 × 500).

    Returns ``(rows, error, truncated)``.  Requires ``INTIGRITI_API_TOKEN``.
    """
    if not _inti_auth():
        return [], ("auth_required: set INTIGRITI_API_TOKEN "
                    "(generate at app.intigriti.com → Settings → "
                    "Personal access tokens)"), False
    kw = query.lower()
    rows: List[Dict[str, Any]] = []
    truncated = False
    offset = 0
    for _ in range(10):
        status, body = _inti_get("/v1/programs", params={"limit": 500, "offset": offset})
        if status != 200 or not isinstance(body, dict):
            return [], f"program listing: HTTP {status}", truncated
        records = body.get("records") or []
        for rec in records:
            hay = f"{rec.get('name') or ''} {rec.get('handle') or ''}".lower()
            if kw in hay:
                rows.append({
                    "platform": "intigriti",
                    "handle": rec.get("handle"),
                    "id": rec.get("id"),
                    "name": rec.get("name"),
                    "state": _enumval(rec.get("status")),
                    "type": _enumval(rec.get("type")),
                })
                if len(rows) >= limit:
                    return rows, None, truncated
        offset += len(records)
        if not records or offset >= int(body.get("maxCount") or 0):
            break
        if offset >= 10 * 500:
            truncated = True
    return rows, None, truncated


def _bc_probe_program(handle: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Anonymous exact-handle probe of a Bugcrowd engagement page.

    This lane has no public program-list API, so 'search' degenerates to an
    exact-handle existence check (same page fetch _bc_build_manifest uses).
    """
    st, page = _bc_fetch_engagement_page(handle)
    if st != 200:
        return None, f"engagement page: HTTP {st} (handle may not exist or program is private)"
    m = re.search(r"<title>([^<]+)</title>", page or "", re.S)
    name = _html.unescape(m.group(1)).strip() if m else handle
    return {
        "platform": "bugcrowd", "handle": handle, "name": name,
        "bounty": "per-group rewardRange — fetch the brief (load_program_scope platform=bugcrowd)",
        "state": None, "type": None,
    }, None


def _summarize_manifest_assets(manifest: Dict[str, Any], cap: int = 100) -> Dict[str, Any]:
    """Compact bounty-relevant summary of a manifest (search_programs --assets)."""
    in_assets = manifest.get("in_scope") or []
    bounty_elig = sum(1 for a in in_assets if a.get("eligible_for_bounty"))
    detail_hist: Dict[str, int] = {}
    rows = []
    for a in in_assets[:cap]:
        detail = a.get("max_severity") or a.get("inti_tier") or a.get("reference") or ""
        if detail:
            detail_hist[str(detail)] = detail_hist.get(str(detail), 0) + 1
        rows.append({
            "asset_identifier": a.get("asset_identifier"),
            "asset_type": a.get("asset_type"),
            "eligible_for_bounty": bool(a.get("eligible_for_bounty")),
            "detail": detail or None,
        })
    return {
        "program_name": manifest.get("program_name") or manifest.get("handle"),
        "counts": {
            "in_scope": len(in_assets),
            "out_of_scope_assets": len(manifest.get("out_of_scope_assets") or []),
        },
        "bounty_stats": {
            "bounty_eligible_in_scope": bounty_elig,
            "no_bounty_in_scope": len(in_assets) - bounty_elig,
            "detail_histogram": detail_hist,
        },
        "assets": rows,
        "assets_truncated": len(in_assets) > cap,
        "_warning": manifest.get("_warning"),
    }


@framework_tool(
    "Search bug-bounty boards for programs matching a keyword: HackerOne "
    "(authed program index) and Intigriti (PAT program list) support keyword "
    "discovery; Bugcrowd has no public listing API — pass --handle for an "
    "exact anonymous probe. Rows carry platform/handle/name and "
    "bounty-relevant flags. with_assets=True additionally loads each match's "
    "manifest (cache-first; may write the scope cache) and summarises "
    "in-scope assets with bounty-relevant fields. Platform fetch lane only — "
    "never touches a target. Structured DOLLAR bounty tables are not exposed "
    "by the researcher APIs (H1: offers_bounties + per-asset eligibility + "
    "max_severity; Bugcrowd: per-group rewardRange; Intigriti: tiers) — "
    "dollar figures live in each program's policy prose.",
    next_hints=["load_program_scope", "check_scope"],
)
def search_programs(query: str = "", platform: str = "all", limit: int = 10,
                    with_assets: bool = False, handle: str = "",
                    refresh: bool = False) -> Dict[str, Any]:
    """Search board program listings by keyword (discovery, not verdicts).

    Args:
        query: Keyword, case-insensitive substring match on program name/handle.
        platform: ``all`` (default), ``h1``, ``intigriti``, or ``bugcrowd``.
            Bugcrowd supports an exact-handle probe only (no public listing API).
        limit: Max matches per lane.
        with_assets: Also load each match's manifest (cache-first) and attach a
            compact asset/bounty summary (first 3 matches, capped asset rows).
        handle: Exact handle for the bugcrowd probe lane.
        refresh: With with_assets, force a fresh manifest fetch (rewrites cache).
    """
    platform = (platform or "all").strip().lower()
    if platform not in ("all", "h1", "intigriti", "bugcrowd"):
        return {"ok": False, "error": f"unknown platform {platform!r} (all|h1|intigriti|bugcrowd)"}
    if platform == "bugcrowd" and not (handle or "").strip():
        return {"ok": False, "error": ("bugcrowd lane has no public program-list API; "
                                        "pass an exact --handle for the anonymous probe")}
    if platform in ("h1", "intigriti") and not (query or "").strip():
        return {"ok": False, "error": f"query is required for the {platform} lane"}

    rows: List[Dict[str, Any]] = []
    lane_errors: Dict[str, str] = {}
    lane_truncated: Dict[str, bool] = {}
    if platform == "bugcrowd":
        probe, err = _bc_probe_program(handle.strip())
        if err:
            lane_errors["bugcrowd"] = err
        else:
            rows.append(probe)
    else:
        lanes = ["h1", "intigriti"] if platform == "all" else [platform]
        for lane in lanes:
            if lane == "h1":
                lane_rows, err, tr = _h1_search_programs(query, limit)
            else:
                lane_rows, err, tr = _inti_search_programs(query, limit)
            if err:
                lane_errors[lane] = err
            else:
                rows.extend(lane_rows)
                lane_truncated[lane] = tr

    res: Dict[str, Any] = {
        "ok": bool(rows) or not lane_errors,
        "query": query,
        "platform": platform,
        "rows": rows,
        "lane_errors": lane_errors,
        "lane_truncated": {k: v for k, v in lane_truncated.items() if v},
        "note": ("negative result from a live index pull is real data; dollar "
                 "bounty tables are not structured on any lane — see the "
                 "program's policy prose"),
    }
    if not rows and lane_errors:
        res["ok"] = False
    if with_assets and rows:
        assets: Dict[str, Any] = {}
        for row in rows[:3]:
            key = f"{row['platform']}/{row.get('handle')}"
            if not row.get("handle"):
                assets[key] = {"error": "row has no handle to load"}
                continue
            m = load_program_scope(row["handle"], refresh=refresh, platform=row["platform"])
            if not isinstance(m, dict) or m.get("status") == "error":
                assets[key] = {"error": (m or {}).get("error", "manifest unavailable")
                               if isinstance(m, dict) else str(m)}
                continue
            assets[key] = _summarize_manifest_assets(m)
        res["assets"] = assets
    return res


@framework_tool(
    "Check whether a target (host, URL, IP/CIDR, or mobile app package id) "
    "is inside a program's authorised scope (platform: 'h1' default, "
    "'bugcrowd', or 'intigriti'). Returns in_scope "
    "True/False, the matched asset (with asset_type, max_severity, CIA "
    "requirements, and any instruction), and a reason. Call this BEFORE "
    "running nmap/masscan/ffuf/ZAP against any target to avoid scanning "
    "out-of-scope or wrong-org assets. Loads the scope manifest first "
    "(from cache or live) if not already loaded.",
    next_hints=["run_nmap", "run_ffuf", "run_masscan", "zap_open_url"],
)
def check_scope(target: str, handle: str, platform: str = "h1") -> Dict[str, Any]:
    """Test ``target`` against the loaded scope manifest for ``handle``.

    Args:
        target: A hostname, URL, IP, CIDR, or mobile app package id.
        handle: Program handle (REQUIRED — no default; a silent default
            silently checks against the wrong program's manifest).
        platform: ``"h1"`` (default), ``"bugcrowd"``, or ``"intigriti"``.
    """
    if not handle or not str(handle).strip():
        raise ValueError(
            "handle is required: scope checks against a silent default "
            "program produced wrong-verdict bugs (see bugcheck ledger 2026-09-12)"
        )
    handle = str(handle).strip()
    manifest = _load_cache(handle, platform)
    if manifest is None:
        manifest = load_program_scope(handle, refresh=False, platform=platform)
    if manifest.get("status") == "error" and not manifest.get("in_scope"):
        return {"target": target, "in_scope": False, "reason": manifest.get("error", "no scope loaded")}

    in_assets = manifest.get("in_scope", [])
    out_assets = manifest.get("out_of_scope_assets", [])
    # Precedence rule: an explicit OUT-OF-SCOPE asset match ALWAYS wins over
    # an in-scope wildcard.  Otherwise a host listed OOS under *.example.com
    # (e.g. selfservice.grindr.com under *.grindr.com) silently comes back
    # in_scope=True because the wildcard is consulted first.
    out_match = _find_match(target, out_assets)
    if out_match:
        return {
            "target": target,
            "in_scope": False,
            "matched_asset": out_match,
            "reason": (f"matches an explicitly out-of-scope asset "
                       f"{out_match.get('asset_identifier')!r}"),
        }
    match = _find_match(target, in_assets)
    if match:
        result: Dict[str, Any] = {
            "target": target,
            "in_scope": True,
            "matched_asset": match,
            "max_severity": match.get("max_severity"),
            "reason": f"matches in-scope {match.get('asset_type')} asset {match.get('asset_identifier')!r}",
        }
        # --- Testing-requirements enforcement chokepoint -------------------
        # check_scope is the last gate before every scan fires, so it is the
        # natural place to surface mandatory testing requirements inline on
        # the *positive* verdict.  Firing ffuf/ZAP with raw defaults on day
        # one of a reopened program burns good standing.
        #
        # All three platforms are handled: Intigriti via structured
        # testing_requirements, H1 via the recommended X-HackerOne-Research
        # identification header, Bugcrowd via a UA suffix.  The scan tools
        # (ffuf, ZAP) also call get_scan_config independently for
        # auto-injection, but surfacing it here means the secretary model
        # sees it in the scope-check response too.
        scan_cfg = get_scan_config(handle, platform)
        if scan_cfg:
            result["scan_config_required"] = scan_cfg
        return result
    return {
        "target": target,
        "in_scope": False,
        "reason": "no matching asset in the program scope",
    }


@framework_tool(
    "Check whether a candidate finding is reportable under a program's "
    "rules (H1 only — Bugcrowd briefs lack structured exclusions/weaknesses "
    "and return an explicit unsupported envelope): tests a category name or "
    "CWE id against the program's "
    "excluded report categories (scope_exclusions) and the reportable "
    "weakness allowlist. Returns reportable True/False, which exclusion it "
    "hit (if any), and whether the CWE is in the program's weakness list. "
    "Use this as a gate before report_finding to avoid filing N/A or "
    "spam-grade reports that hurt your HackerOne reputation. Bugcrowd and "
    "Intigriti return an explicit ``unsupported`` envelope (no structured "
    "exclusions/weaknesses; judge from prose).",
    next_hints=["report_finding", "program_hacktivity"],
)
def check_reportable(category_or_cwe: str, handle: str,
                     platform: str = "h1") -> Dict[str, Any]:
    """Test a finding category/CWE against the program's exclusion + weakness rules.

    Args:
        category_or_cwe: A vulnerability category name (e.g. "Missing security
            headers", "Brute force", "Open redirect") or a CWE id
            (e.g. "CWE-89", "cwe-352").  Matched case-insensitively.
        handle: Program handle (REQUIRED — no default).
        platform: ``"h1"`` (default), ``"bugcrowd"`` (returns an explicit
            ``unsupported`` envelope — Bugcrowd briefs carry no structured
            exclusions/weaknesses; judge from brief prose), or
            ``"intigriti"`` (same ``unsupported`` envelope — Intigriti RoE
            is prose, not structured exclusions/weaknesses).
    """
    if not handle or not str(handle).strip():
        raise ValueError("handle is required: silent program default produced wrong-verdict bugs")
    handle = str(handle).strip()
    if platform in ("bugcrowd", "intigriti"):
        return {"platform": platform, "handle": handle,
                "status": "unsupported", "reportable": None,
                "reason": (f"{platform.capitalize()} carries no structured "
                           "exclusion/weakness allowlists — judge reportability "
                           "from RoE/brief prose (manifest['policy'])")}
    manifest = _load_cache(handle, platform)
    if manifest is None:
        manifest = load_program_scope(handle, refresh=False, platform=platform)

    needle = category_or_cwe.strip().lower()
    cwe_norm = re.sub(r"[^0-9]", "", needle) if "cwe" in needle else None

    # 1. Excluded categories (scope_exclusions) — a hit means NOT reportable.
    excluded = manifest.get("excluded_categories", [])
    hit_excl = None
    for e in excluded:
        cat = (e.get("category") or "").lower()
        det = (e.get("details") or "").lower()
        if needle in cat or needle in det or cat and cat in needle:
            hit_excl = e
            break

    # 2. Weakness allowlist — is this CWE recognised by the program?
    weaknesses = manifest.get("weaknesses", [])
    weakness_hit = None
    if cwe_norm:
        for w in weaknesses:
            ext = (w.get("external_id") or "")
            if ext and re.sub(r"[^0-9]", "", ext) == cwe_norm:
                weakness_hit = w
                break
    # also try matching by name substring
    if not weakness_hit:
        for w in weaknesses:
            name = (w.get("name") or "").lower()
            if name and needle in name:
                weakness_hit = w
                break

    reportable = not hit_excl
    reason = "no exclusion matched"
    if hit_excl:
        reason = (f"matches excluded category {hit_excl.get('category')!r}: "
                  f"{hit_excl.get('details')}")
    return {
        "category_or_cwe": category_or_cwe,
        "reportable": reportable,
        "exclusion_hit": hit_excl,
        "weakness_match": weakness_hit,
        "reason": reason,
    }


@framework_tool(
    "Fetch a HackerOne program's hacktivity feed (LIVE, sorted newest-first "
    "by latest_disclosable_activity_at — report IDs are NOT the sort key) "
    "for duplicate-checking before you write up a finding. Works WITHOUT "
    "API credentials (the hacktivity feed is public). Optionally filter "
    "with a Lucene query string (e.g. 'severity_rating:high AND "
    "cwe:SSRF'), but note: query filtering on the public endpoint is "
    "BEST-EFFORT and may silently return 0 results if the filter is not "
    "honored (a warning is emitted in the response envelope when this is "
    "detected — do NOT read a filtered count:0 as 'no dupes'). Most items "
    "in an active program's feed are UNDISCLOSED: title, substate, url, "
    "severity, cwe, and disclosed_at will be null for those. The always-"
    "present useful fields are: disclosed, latest_disclosable_action, "
    "latest_disclosable_activity_at, submitted_at, votes, total_awarded, "
    "and reporter username.",
    next_hints=["check_reportable", "report_finding"],
)
def program_hacktivity(handle: str = "crypto", query: str = "", limit: int = 25) -> Dict[str, Any]:
    """Fetch a program's hacktivity feed (dedup aid).

    The public hacktivity endpoint is a live feed sorted newest-first by
    ``latest_disclosable_activity_at``.  Most items in an active program's
    feed are undisclosed — H1 redacts ``title``, ``substate``, ``url``,
    ``severity_rating``, ``cwe``, and ``disclosed_at`` for those.  The
    always-present fields (``disclosed``, ``latest_disclosable_action``,
    ``latest_disclosable_activity_at``, ``submitted_at``, ``votes``,
    ``total_awarded_amount``, reporter username) are extracted regardless.

    Query filtering is best-effort: the public endpoint silently ignores
    unknown/unhonored Lucene filters and returns 0 results with no error.
    When a non-empty query yields 0 results, a bare re-probe
    (``team_handle:<handle>`` only, ``page[size]=5``, no auth) is fired to
    detect this.  If the bare probe returns results, a warning is added to
    the response envelope so the caller does not mistake a silent zero for
    "no duplicates."

    Args:
        handle: HackerOne program handle. Defaults to ``"crypto"``.
        query: Optional Lucene filter appended to ``team_handle:<handle>``
            (e.g. ``"severity_rating:high"``).  Empty = all items.
        limit: Max items (1-100). Defaults to 25.
    """
    limit = max(1, min(100, int(limit)))
    has_filter = bool(query.strip())
    qs = f"team_handle:{handle}"
    if has_filter:
        qs += f" AND {query.strip()}"

    status, body = _get("/hackers/hacktivity",
                        params={"queryString": qs, "page[size]": limit},
                        auth=None)
    if status != 200 or not isinstance(body, dict):
        return {"handle": handle, "status": "error", "error": f"HTTP {status}", "reports": []}

    reports = _extract_hacktivity_items(body.get("data", []))

    # --- T-005: behavioral guard against silent filter ignoring ------------
    # When a non-empty query returns 0 results, the public endpoint may have
    # silently ignored the filter.  Re-probe with bare team_handle only
    # (page[size]=5, no auth) to distinguish "filter ignored" from "genuinely
    # no data."  This extra probe fires ONLY on the ambiguous zero path.
    warning = None
    if has_filter and len(reports) == 0:
        bare_qs = f"team_handle:{handle}"
        bare_status, bare_body = _get(
            "/hackers/hacktivity",
            params={"queryString": bare_qs, "page[size]": 5},
            auth=None,
        )
        bare_count = 0
        if bare_status == 200 and isinstance(bare_body, dict):
            bare_count = len(bare_body.get("data", []))
        if bare_count > 0:
            warning = (
                f"filter returned 0 but bare team_handle:{handle} returned "
                f"{bare_count} — public endpoint likely ignores this filter; "
                f"do NOT read 0 as 'no dupes'"
            )

    result: Dict[str, Any] = {
        "handle": handle,
        "status": "ok",
        "count": len(reports),
        "reports": reports,
    }
    if warning:
        result["warning"] = warning
    return result


def _extract_hacktivity_items(items: list) -> list:
    """Extract a compact dict from each hacktivity item.

    Undisclosed items have null for title/substate/url/severity/cwe/
    disclosed_at.  The always-present fields are extracted regardless so
    the feed is useful even when most items are undisclosed.
    """
    reports = []
    for it in items:
        a = it.get("attributes", {}) or {}
        # Reporter username is nested at relationships.reporter.data.attributes.username
        reporter_username = None
        rels = it.get("relationships", {}) or {}
        reporter = rels.get("reporter", {}) or {}
        reporter_data = reporter.get("data", {}) or {}
        reporter_attrs = reporter_data.get("attributes", {}) or {}
        reporter_username = reporter_attrs.get("username")
        reports.append({
            "id": it.get("id"),
            "title": a.get("title"),
            "substate": a.get("substate"),
            "severity": a.get("severity_rating"),
            "cwe": a.get("cwe"),
            "url": a.get("url"),
            "disclosed": a.get("disclosed"),
            "disclosed_at": a.get("disclosed_at"),
            "submitted_at": a.get("submitted_at"),
            "latest_disclosable_action": a.get("latest_disclosable_action"),
            "latest_disclosable_activity_at": a.get("latest_disclosable_activity_at"),
            "votes": a.get("votes"),
            "total_awarded": a.get("total_awarded_amount"),
            "reporter": reporter_username,
        })
    return reports
