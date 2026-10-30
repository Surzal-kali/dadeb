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
import logging

import re
from pathlib import Path
from typing import Any

from constants import framework_tool

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
    # dotenv not installed or .env missing — silently degrade
    logging.getLogger(__name__).debug(
        "swallowed exception at module scope", exc_info=True)

# --- carved guts (tool surface never moves; plain-helper shims are lane-legal)
from auxiliaries._program_scope_feeds import (
    _bc_build_manifest,
    _bc_probe_program,
    _build_manifest,
    _get,
    _h1_search_programs,
    _inti_build_manifest,
    _inti_search_programs,
    _summarize_manifest_assets,
)
from auxiliaries._program_scope_match import _find_match
from auxiliaries._program_scope_store import (
    _load_cache,
    _save_cache,
    _scope_cache_path,  # noqa: F401 - scope_gate binds it through this facade
    _write_scope_file,
    get_armed_scan_config,  # noqa: F401 - ffuf/ZAP/ssrf/playwright bind it here
    get_scan_config,
)

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
                       platform: str = "h1") -> dict[str, Any]:
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
        cached = _load_cache(handle, platform)
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
                    refresh: bool = False) -> dict[str, Any]:
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

    rows: list[dict[str, Any]] = []
    lane_errors: dict[str, str] = {}
    lane_truncated: dict[str, bool] = {}
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

    res: dict[str, Any] = {
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
        assets: dict[str, Any] = {}
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
def check_scope(target: str, handle: str, platform: str = "h1") -> dict[str, Any]:
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
        result: dict[str, Any] = {
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
                     platform: str = "h1") -> dict[str, Any]:
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
def program_hacktivity(handle: str = "crypto", query: str = "", limit: int = 25) -> dict[str, Any]:
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

    result: dict[str, Any] = {
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
