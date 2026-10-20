"""Wordlist discovery/lookup tool shared by ffuf and hydra.

``list_wordlists`` walks every declared wordlist source (see
``utils.wordlists.WORDLIST_SOURCES``) and matches entries against an optional
``query`` substring, so the secretary model can look a list up by name
(``query="rockyou"``), by bin (``query="dirb"``), or browse the compact
summaries before calling ``run_ffuf`` / ``run_hydra``.  Both launchers
consume wordlists verbatim as file paths, so a wrong or non-existent path is
the dominant silent-failure mode; this tool turns "guess a path" into
"search the catalog".  The full catalog is never dumped: the no-query call
returns the summaries plus a small sample, and query-filtered calls return
only matches.

The ``next_hints`` point at both brute-force launchers so the manifest guides
the model from discovery straight to a run.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from constants import framework_tool
from utils.wordlists import (
    discover_wordlists,
    preflight_wordlists,
    resolve_default_wordlist,
)


def _category_matches(filter_str: str, category: str) -> bool:
    """True if *filter_str* matches the full category or any of its segments.

    Splits the multi-level category (e.g. ``Discovery/Web-Content``) on
    ``/`` so a filter like ``"web-content"`` matches even though it is only
    one segment of a deeper label.
    """
    cat_lower = category.lower()
    if filter_str in cat_lower:
        return True
    return any(filter_str in seg for seg in cat_lower.split("/"))


def _summarize(entries: List[Dict[str, Any]]) -> Dict[str, int]:
    """Per-category counts so the model sees the shape of the catalog."""
    counts: Dict[str, int] = {}
    for e in entries:
        counts[e.get("category", "wordlists")] = counts.get(
            e.get("category", "wordlists"), 0
        ) + 1
    return dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True))


def _summarize_sources(entries: List[Dict[str, Any]]) -> Dict[str, int]:
    """Per-source counts so the model sees which bins contributed."""
    counts: Dict[str, int] = {}
    for e in entries:
        counts[e.get("source", "wordlists")] = counts.get(
            e.get("source", "wordlists"), 0
        ) + 1
    return dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True))


def _query_matches(query_lower: str, entry: Dict[str, Any]) -> bool:
    """True when *query_lower* appears in any identifying field of *entry*.

    Fields searched, in practice ordered by usefulness: basename
    (``rockyou.txt``), full absolute path
    (``/usr/share/dirb/wordlists/common.txt``), category
    (``Discovery/Web-Content``), and source bin (``dirb``).  Plain
    case-insensitive substring — no glob semantics to explain to the model.
    Note the substring rule means ``"dirb"`` also matches ``dirbuster``
    paths; the ``source`` filter is the exact-bin escape hatch.
    """
    path = str(entry.get("path", ""))
    haystacks = (
        os.path.basename(path),
        path,
        str(entry.get("category", "")),
        str(entry.get("source", "")),
    )
    return any(query_lower in h.lower() for h in haystacks)


@framework_tool(
    "Search the framework's wordlist catalog for .txt list files across all "
    "declared wordlist sources — the primary root (/usr/share/wordlists, "
    "which on Kali holds rockyou.txt plus per-package symlinks) AND the "
    "per-package folders walked directly (dirb, dirbuster, wfuzz, "
    "metasploit, legion, seclists, ...). Pass 'query' to find lists by name "
    "(query='rockyou'), by path fragment (query='dirb/'), by category "
    "segment (query='Passwords'), or by source bin (query='legion') — "
    "matches carry each entry's absolute path, size, category, and source "
    "bin. WITHOUT a query it returns only a compact orientation view: "
    "per-category/per-source counts, headline common-list presence, the "
    "framework fallback defaults, and a small sample of paths — never the "
    "full 200+-entry catalog. Use a returned path verbatim as the -w "
    "argument to run_ffuf or the -P/-L argument to run_hydra. Call this "
    "BEFORE run_ffuf/run_hydra — never guess a wordlist path.",
    next_hints=["run_ffuf", "run_hydra"],
)
def list_wordlists(
    query: Optional[str] = None,
    category: Optional[str] = None,
    source: Optional[str] = None,
    limit: int = 25,
) -> Dict[str, Any]:
    """Search the wordlist catalog by ``query`` substring, or browse.

    Walks every entry of :data:`~utils.wordlists.WORDLIST_SOURCES` once (no
    caching).  With a ``query``, only matching entries are returned (matched
    against basename, absolute path, category, and source bin); without one,
    the response is a compact orientation view — the ``by_category`` /
    ``by_source`` summaries, headline common-list presence, the fallback
    defaults and a small sample — never the full 200+-entry catalog.

    Args:
        query: Case-insensitive substring (e.g. ``"rockyou"``,
            ``"dirbuster"``, ``"Passwords/Leaked"``).  ``None`` or empty
            returns the orientation view.
        category: Optional case-insensitive filter matched against the
            category label and any of its ``/``-separated segments (e.g.
            ``"Passwords"``, ``"web-content"``, or ``"Discovery"`` all match
            ``Discovery/Web-Content``).  Narrows query results too.
        source: Optional case-insensitive filter on the source bin label
            (``"dirb"``, ``"metasploit"``, ``"wordlists"``, ...).  Narrows
            query results too.
        limit: Maximum number of entries to return (default 25; hard cap
            200).  The summaries are unaffected by this cap.
    """
    limit = max(0, min(int(limit), 200))
    cat_filter = category.lower() if category else None
    src_filter = source.lower() if source else None

    # Run the preflight once: its sources_seen/warnings/defaults fields are
    # the orientation view's payload, and a missing/empty tree must be
    # reported as a structured warning rather than an empty list that looks
    # like "no match".
    pf = preflight_wordlists()

    entries: List[Dict[str, Any]] = []
    for e in discover_wordlists():
        if cat_filter and not _category_matches(cat_filter, e.get("category", "")):
            continue
        if src_filter and src_filter not in str(e.get("source", "")).lower():
            continue
        entries.append(e)

    mode = "query" if (query or "").strip() else "browse"
    query_used = (query or "").strip()
    if mode == "query":
        ql = query_used.lower()
        entries = [e for e in entries if _query_matches(ql, e)]

    by_category = _summarize(entries)
    by_source = _summarize_sources(entries)
    total = len(entries)

    if mode == "query":
        matched = entries[:limit] if limit else []
        return {
            "ok": pf["ok"],
            "root": pf["root"],
            "mode": mode,
            "query": query_used,
            "total": total,
            "returned": len(matched),
            "limit_applied": total > len(matched),
            "wordlists": matched,
            "by_category": by_category,
            "by_source": by_source,
            "warnings": pf["warnings"],
            "notes": (
                "query is a case-insensitive substring over basename, "
                "absolute path, category, and source bin — 'dirb' also "
                "matches dirbuster paths; pass source='<exact bin>' to "
                "narrow, or a longer query to disambiguate"
            ),
        }

    # --- browse mode: never dump the catalog — orientation view -------------
    # limit also sizes the browse sample (max 10) so callers tuning limit
    # get a consistent shape in both modes.
    sample = entries[: min(limit, 10)] if limit else []
    return {
        "ok": pf["ok"],
        "root": pf["root"],
        "mode": mode,
        "query": "",
        "total": total,
        "returned": len(sample),
        "by_category": by_category,
        "by_source": by_source,
        "sample": sample,
        "sources_seen": pf["sources_seen"],
        "sources_absent": pf["sources_absent"],
        "common_present": pf["common_present"],
        "common_absent": pf["common_absent"],
        "warnings": pf["warnings"],
        # The "just in case" fallback wordlists run_ffuf/run_hydra use when
        # no list is supplied.  A None value means the default file is absent
        # under the root — ffuf/hydra will error in that case.
        "defaults": {
            "ffuf": resolve_default_wordlist("ffuf"),
            "hydra_logins": resolve_default_wordlist("hydra_logins"),
            "hydra_passwords": resolve_default_wordlist("hydra_passwords"),
        },
    }
