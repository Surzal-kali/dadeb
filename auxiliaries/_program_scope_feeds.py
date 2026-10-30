"""Provider-adapter lane for the bug-bounty boards (H1 / Bugcrowd / Intigriti).

Carved guts of ``auxiliaries/program_scope.py`` (2026-10-30): the three
API adapters, their H1-shaped manifest builders, and the board search
probes. Anonymous lane — fetches the boards' OWN APIs, never touches a
target, and has nothing to do with the traffic-sending scope gate.

The tool surface (``@framework_tool`` defs, tool_ids, transports) never
moves: ``auxiliaries/program_scope.py`` keeps all five decorated tools
and consumes this lane through plain-helper shims."""
from __future__ import annotations

import html as _html
import json as _json
import logging
import os
import re
import time
from typing import Any
from urllib.parse import urlparse

_H1_API = "https://api.hackerone.com/v1"
_TIMEOUT = 30.0


# --- credentials ------------------------------------------------------------

def _h1_auth() -> tuple[tuple[str, str] | None, bool]:
    """Return ((username, token), has_full_auth) for requests auth.

    ``has_full_auth`` is True only when both env vars are set — the
    structured-scope endpoints need it; hacktivity does not.
    """
    user = os.getenv("H1_API_USERNAME")
    token = os.getenv("H1_API_TOKEN")
    if user and token:
        return ((user, token), True)
    return (None, False)


def _get(path: str, *, params: dict[str, Any] | None = None,
         auth: Any | None = ...) -> tuple[int, Any]:
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

def _fetch_all_pages(path: str, *, params: dict[str, Any] | None = None,
                     max_pages: int = 100) -> tuple[int, list[dict[str, Any]], str | None]:
    """Follow pagination links for a list endpoint.

    Returns (status, items, error).  H1 list endpoints wrap items in
    ``data`` and expose ``links.next``.  We also fall back to incrementing
    ``page[number]`` when ``links.next`` is absent.
    """
    params = dict(params or {})
    if "page[size]" not in params:
        params["page[size]"] = 100
    page = int(params.get("page[number]", 1))
    items: list[dict[str, Any]] = []
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


def _build_manifest(handle: str) -> tuple[dict[str, Any], str | None]:
    """Fetch all H1 scope data for ``handle`` and assemble the manifest dict."""
    auth, has_auth = _h1_auth()
    if not has_auth:
        return ({}, ("auth_required: set H1_API_USERNAME and H1_API_TOKEN "
                     "(generate at hackerone.com → Settings → API Tokens)"))

    # structured scopes (in- AND out-of-scope assets, split by eligible flags)
    st, scopes, err = _fetch_all_pages(f"/hackers/programs/{handle}/structured_scopes")
    if err:
        return ({}, f"structured_scopes: {err}")

    in_scope: list[dict[str, Any]] = []
    out_of_scope_assets: list[dict[str, Any]] = []
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


def _bc_get(url: str, *, accept: str = "application/json") -> tuple[int, Any]:
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


def _bc_fetch_engagement_page(handle: str) -> tuple[int, str]:
    """Fetch the public engagement page (follows /<handle> -> /engagements/<handle>)."""
    import requests

    r = requests.get(f"{_BC_BASE}/{handle}",
                     headers={"Accept": "text/html", "User-Agent": _BC_UA},
                     timeout=_TIMEOUT)
    return (r.status_code, r.text)


def _bc_brief_url(handle: str, page_html: str) -> str | None:
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


def _bc_target_entry(t: dict[str, Any], group: dict[str, Any]) -> dict[str, Any]:
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


def _bc_build_manifest(handle: str) -> tuple[dict[str, Any], str | None]:
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
    in_scope: list[dict[str, Any]] = []
    out_of_scope_assets: list[dict[str, Any]] = []
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
_INTI_DOMAIN_TYPE_MAP: dict[str, str] = {
    "URL": "URL",
    "Android": "ANDROID",
    "IOS": "IOS",
    "IP range": "CIDR",
    "Device": "OTHER",
    "Other": "OTHER",
    "Wildcard": "WILDCARD",
}
_inti_unmapped_type_logged: bool = False


def _inti_auth() -> str | None:
    """Return the Intigriti PAT bearer token, or None if not configured."""
    return os.getenv("INTIGRITI_API_TOKEN")


def _inti_get(path: str, *, params: dict[str, Any] | None = None) -> tuple[int, Any]:
    """GET against the Intigriti Researcher API with Bearer auth."""
    import requests

    token = _inti_auth()
    headers: dict[str, str] = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = requests.get(f"{_INTI_API}{path}", params=params, headers=headers,
                     timeout=_TIMEOUT)
    try:
        body = r.json()
    except ValueError:
        body = r.text
    return (r.status_code, body)


def _inti_resolve_handle(handle: str) -> tuple[str | None, str | None]:
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


def _inti_map_domain(d: dict[str, Any]) -> dict[str, Any]:
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


def _inti_build_manifest(handle: str) -> tuple[dict[str, Any], str | None]:
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
    in_scope: list[dict[str, Any]] = []
    out_of_scope_assets: list[dict[str, Any]] = []
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


def _h1_search_programs(query: str, limit: int) -> tuple[list[dict[str, Any]], str | None, bool]:
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
    rows: list[dict[str, Any]] = []
    truncated = False
    for page in range(1, 11):
        params: dict[str, Any] = {"page[size]": 100, "page[number]": page}
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


def _inti_search_programs(query: str, limit: int) -> tuple[list[dict[str, Any]], str | None, bool]:
    """Client-side keyword match over the Intigriti program list (10 × 500).

    Returns ``(rows, error, truncated)``.  Requires ``INTIGRITI_API_TOKEN``.
    """
    if not _inti_auth():
        return [], ("auth_required: set INTIGRITI_API_TOKEN "
                    "(generate at app.intigriti.com → Settings → "
                    "Personal access tokens)"), False
    kw = query.lower()
    rows: list[dict[str, Any]] = []
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


def _bc_probe_program(handle: str) -> tuple[dict[str, Any] | None, str | None]:
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


def _summarize_manifest_assets(manifest: dict[str, Any], cap: int = 100) -> dict[str, Any]:
    """Compact bounty-relevant summary of a manifest (search_programs --assets)."""
    in_assets = manifest.get("in_scope") or []
    bounty_elig = sum(1 for a in in_assets if a.get("eligible_for_bounty"))
    detail_hist: dict[str, int] = {}
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
