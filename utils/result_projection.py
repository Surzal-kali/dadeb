"""Result projection: control what enters model context vs. what stays in scratch.

The projection layer sits between ``execute_tool()`` and the result entering
the model's conversation history.  It operates in three modes:

    large   — (default) the raw result with every string field capped to
              ``LARGE_FIELD_CHAR_CAP`` chars and the total serialized size
              capped to ``LARGE_MODE_BYTE_CAP`` bytes.  When the result is
              under the cap it passes through unchanged (zero behavior
              change for small/medium results).  When it exceeds the cap,
              the full result is stored in scratch and the capped copy + a
              scratch_ref is returned — the model gets the actual data it
              needs (status, handles, headers, body previews) without a
              single response blowing up its context window.
    digest  — store the full result in scratch, return a compact per-tool-family
              digest + the scratch reference + the retrieval instruction.
    page    — store the full result in scratch, return a bounded page of the
              result (offset/limit) + the scratch reference + continuation info.

``full`` is gone — it was an unbounded passthrough that could deliver a
100KB+ response wholesale into a cloud model's context.  ``large`` replaces
it as the "give me the actual data" mode: same data shape, field-capped.
For backward compatibility ``full`` is silently aliased to ``large``.

The ``result_mode`` is an execution-envelope parameter — it is NOT a tool
argument and never reaches the tool body.  The gateway and the secretary
agent pass it alongside ``tool_id`` / ``arguments``.

Digest adapter registration
---------------------------
Tools that want a family-specific digest register a ``to_digest(raw_result)``
callable via ``@framework_tool(..., result_digest=my_digest)``.  The adapter
returns ``{"summary": str, "row_hint_format": str}`` — the projection layer
wraps it in the standard envelope.  Tools without an adapter fall back to a
naive head+count digest (a bounded preview, not a "real" digest).

Why this is NOT the parked OWUI trim filter:
    - The projection runs BEFORE the result enters context, not after.
    - The retrieval instruction is part of the return — the model is taught
      the move every call, never left guessing how to get the full output.
    - Per-tool-family digest logic is honest because the tool knows its own
      output structure; a generic post-hoc summarizer does not.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Callable, Dict, Optional

from utils.scratch_store import ScratchStore, get_store

logger = logging.getLogger(__name__)

# --- Small-result passthrough threshold ------------------------------------
# Results whose serialized JSON is under this many bytes are returned in full
# regardless of result_mode.  Small results (ssh_connect returns a handle,
# check_scope returns a verdict, report_finding returns an ID) were never a
# context problem — storing them in scratch is wasted I/O and an extra
# retrieval round-trip for the model.  Only large outputs (nmap logs, ffuf
# hit lists, grep match dumps) trigger the digest/page projection.
_SMALL_RESULT_THRESHOLD = int(os.getenv("SCRATCH_SMALL_RESULT_BYTES", "2048"))

# --- Large-mode caps -------------------------------------------------------
# ``large`` mode is the default for every lane (REST, MCP, secretary, OWUI).
# It behaves like the old ``full`` passthrough for results under the byte
# cap, but field-truncates + stores-in-scratch when a single response would
# otherwise blow up the model's context window.  Two knobs:
#
#   LARGE_MODE_BYTE_CAP  — total serialized JSON size (bytes) at which the
#                          result is stored in scratch and a capped copy is
#                          returned instead.  Under the cap = zero change.
#                          Default 16384 (16 KiB) — large enough for a full
#                          nmap port list + headers + a Burp body_text, but
#                          small enough that a 100KB HTML dump or a 50KB
#                          scan log can't enter context wholesale.
#
#   LARGE_FIELD_CHAR_CAP — per-string-field truncation length (chars) when
#                          the byte cap is exceeded.  Each string field in
#                          the result dict is truncated to this many chars
#                          with a ``...[truncated N chars]`` marker.  Lists
#                          are capped to the first N items where N is derived
#                          from the byte cap.  Default 4096.
#
# These caps are deliberately generous — ``large`` is "give me the data",
# not "summarize it for me".  ``digest`` is the summarize mode.  The caps
# exist so a pathological single response (raw HTML, huge grep dump) can't
# 6x the context window before anyone notices.
_LARGE_MODE_BYTE_CAP = int(os.getenv("LARGE_MODE_BYTE_CAP", "16384"))
_LARGE_FIELD_CHAR_CAP = int(os.getenv("LARGE_FIELD_CHAR_CAP", "4096"))


# --- Digest adapter registry -----------------------------------------------
#
# Maps tool_id -> to_digest callable.  Populated at decoration time via
# @framework_tool(..., result_digest=fn) and at registry build time from the
# manifest's result_digest field.  The registry's dynamic-discovery pass sets
# func._result_digest which the manifest carries; this module looks it up
# by tool_id at projection time.
#
# Adapters are also registered directly here for tools that set
# result_digest in the decorator (the common path).

_DIGEST_ADAPTERS: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {}


def register_digest_adapter(
    tool_id: str, adapter: Callable[[Dict[str, Any]], Dict[str, Any]]
) -> None:
    """Register a per-tool digest adapter.

    The adapter takes the raw tool result dict and returns a dict with:
        - ``summary``: a compact, structurally-honest digest string.
        - ``row_hint_format`` (optional): a format hint for filtered retrieval,
          e.g. ``"scratch_search scratch:<id> --filter 'port:8080'"``.
    """
    _DIGEST_ADAPTERS[tool_id] = adapter


def get_digest_adapter(tool_id: str) -> Optional[Callable]:
    """Look up a registered digest adapter for a tool_id."""
    return _DIGEST_ADAPTERS.get(tool_id)


# --- Projection envelope shapes --------------------------------------------

_DIGEST_TEMPLATE = {
    "mode": "digest",
    "summary": "",         # filled by adapter or naive fallback
    "full_ref": "",        # scratch:<id>
    "retrieval": "",       # how to pull the full output
    "row_hint": "",        # how to pull specific rows (optional)
}

_PAGE_TEMPLATE = {
    "mode": "page",
    "summary": "",         # e.g. "Showing 50 of 312 rows"
    "rows": [],            # the bounded page
    "full_ref": "",
    "next": "",            # how to get the next page
}


# --- Public projection API --------------------------------------------------

def project_result(
    result: Dict[str, Any],
    *,
    result_mode: str = "full",
    tool_id: str = "",
    agent_id: str = "0",
    chat_id: Optional[str] = None,
    page_offset: int = 0,
    page_limit: int = 50,
) -> Dict[str, Any]:
    """Apply a result projection based on ``result_mode``.

    This is the single entry point called by the gateway, MCP handler, and
    the secretary agent after ``execute_tool()`` returns.

    Args:
        result: The raw tool result dict from execute_tool().
        result_mode: ``"full"``, ``"digest"``, or ``"page"``.
        tool_id: The tool that produced this result (for adapter lookup).
        agent_id: The agent/session owning this result (for scratch ownership).
        chat_id: Optional chat id for scratch ownership.
        page_offset: Page offset (``page`` mode only).
        page_limit: Page size cap (``page`` mode only).

    Returns:
        - ``full`` mode: the raw result, unchanged.
        - ``digest`` mode: a digest envelope with a scratch reference.
        - ``page`` mode: a bounded page envelope with a scratch reference.
    """
    mode = (result_mode or "large").strip().lower()

    # ``full`` is gone — aliased to ``large`` for backward compat so stale
    # callers, old tests, and hardcoded ``result_mode='full'`` strings don't
    # break.  ``full`` was an unbounded passthrough that could deliver a
    # 100KB+ response wholesale into a cloud model's context; ``large``
    # replaces it with field-capped data that still carries the actual
    # values the model needs.
    if mode == "full":
        mode = "large"

    if mode == "large":
        return _project_large(result, mode=mode, tool_id=tool_id,
                              agent_id=agent_id, chat_id=chat_id,
                              page_offset=page_offset, page_limit=page_limit)

    if not isinstance(result, dict):
        return result

    # Unwrap the executor transport envelope before projecting.
    #
    # The in-process/BRAIN_DISPATCH executor wraps every tool result as
    # ``{"status": "Success"|"Failed", "result": <raw>}`` — and optionally
    # ``stdout`` when the tool returned a bare string (no structured data to
    # duplicate).  Without unwrapping, the digest/page adapters run on the
    # *envelope*, not the tool result: e.g. nmap_status's adapter read
    # ``status="Success"`` (the envelope's transport status) and
    # ``open_ports=[]`` (nested under ``result``, not at top level), so the
    # digest reported 0 open ports while the scratch copy held the real 2.
    # The stored scratch payload and the envelope the model sees must both
    # carry the tool's own fields.
    envelope_status = ""
    provenance: Optional[Dict[str, Any]] = None
    if "result" in result and "status" in result:
        envelope_status = str(result.get("status", "")).lower()
        # Capture the untrusted-target provenance stamp the executor placed
        # on the envelope and/or the inner result before unwrapping — digest
        # and page envelopes are fresh dicts and would otherwise drop it.
        provenance = result.get("_provenance") or provenance
        result = result["result"]
        if not isinstance(result, dict):
            return result
        if result.get("_provenance"):
            provenance = result["_provenance"]

    # Failed results are always returned in full — a digest of an error
    # loses the error text the model needs to self-correct.  This covers
    # both the unwrapped tool result's own status (e.g. poll_job returning
    # status="done" — never failed/error, so never short-circuited here)
    # and the executor envelope's transport status (Failed).
    status = envelope_status or str(result.get("status", "")).lower()
    if status in ("failed", "error"):
        return result

    # Small-result passthrough: if the serialized result is under the
    # threshold, return it in full regardless of result_mode.  Small results
    # (handles, verdicts, IDs, config probes) were never a context problem —
    # storing them in scratch is wasted I/O and a retrieval round-trip.
    try:
        result_size = len(json.dumps(result, default=str).encode("utf-8"))
    except (TypeError, ValueError):
        result_size = 0
    if result_size <= _SMALL_RESULT_THRESHOLD:
        return result

    store = get_store()

    # Store the full result in scratch.
    try:
        scratch_info = store.store(
            result,
            agent_id=agent_id,
            tool_id=tool_id,
            chat_id=chat_id,
        )
    except Exception as exc:
        logger.warning(f"[projection] scratch store failed for {tool_id}: {exc}")
        # Storage failed — return the capped result so the model isn't left
        # with nothing and a single failure can't blow up context.
        result["_projection_note"] = (
            f"scratch store unavailable ({exc}); returning capped result"
        )
        return _cap_result_fields(result)

    scratch_ref = scratch_info["scratch_ref"]

    if mode == "digest":
        return _build_digest(result, tool_id, scratch_ref, scratch_info,
                             provenance=provenance)
    elif mode == "page":
        return _build_page(
            result, tool_id, scratch_ref, scratch_info,
            offset=page_offset, limit=page_limit,
            provenance=provenance,
        )
    else:
        # Unknown mode — degrade to large (capped, never unbounded).
        logger.warning(f"[projection] unknown result_mode {result_mode!r}; degrading to large")
        return _cap_result_fields(result)


# --- Large mode (default: capped passthrough) ------------------------------

def _cap_result_fields(
    result: Dict[str, Any],
    *,
    char_cap: int = _LARGE_FIELD_CHAR_CAP,
    byte_cap: int = _LARGE_MODE_BYTE_CAP,
) -> Dict[str, Any]:
    """Truncate every string field and list in ``result`` to stay under byte_cap.

    Returns a shallow-copied dict with:
    - Every string value truncated to ``char_cap`` chars (with a marker).
    - Every list truncated to a derived item count (enough to fill the byte
      cap, min 10, max 200).
    - Nested dicts recursed into.
    - A ``_projection`` sub-dict noting what was capped + the scratch_ref.

    This is the ``large`` mode's core: the model gets the actual data shape
    with real values, just field-capped so no single response can dominate
    the context window.
    """
    # Derive a list-item cap from the byte cap: assume ~256 bytes per item
    # on average, but never fewer than 10 or more than 200.
    list_item_cap = max(10, min(200, byte_cap // 256))

    def _cap_value(val: Any, depth: int = 0) -> Any:
        if depth > 6:  # prevent infinite recursion on cyclic structures
            return "<depth_capped>"
        if isinstance(val, str):
            if len(val) <= char_cap:
                return val
            return val[:char_cap] + f"...[truncated {len(val) - char_cap} chars]"
        if isinstance(val, list):
            if len(val) <= list_item_cap:
                return [_cap_value(v, depth + 1) for v in val]
            capped = [_cap_value(v, depth + 1) for v in val[:list_item_cap]]
            capped.append(f"...[{len(val) - list_item_cap} more items truncated]")
            return capped
        if isinstance(val, dict):
            return {k: _cap_value(v, depth + 1) for k, v in val.items()}
        # Numbers, bools, None — pass through.
        return val

    return {k: _cap_value(v) for k, v in result.items()}


def _project_large(
    result: Dict[str, Any],
    *,
    mode: str,
    tool_id: str,
    agent_id: str,
    chat_id: Optional[str],
    page_offset: int,
    page_limit: int,
) -> Dict[str, Any]:
    """Large mode: capped passthrough — the default for every lane.

    - Under ``LARGE_MODE_BYTE_CAP``: zero behavior change, raw result
      returned as-is (same as the old ``full`` mode for normal results).
    - Over the cap: full result stored in scratch, a field-capped copy +
      ``scratch_ref`` returned.  The model gets the actual data shape with
      real values (status, handles, headers, body previews), just truncated
      so a single pathological response can't blow up context.
    """
    # Unwrap executor envelope first (same logic as digest/page path).
    # The envelope is ``{"status": ..., "result": <raw>}`` — stdout is
    # optional and only present for bare-string tool results.
    envelope_status = ""
    if "result" in result and "status" in result:
        envelope_status = str(result.get("status", "")).lower()
        result = result["result"]
        if not isinstance(result, dict):
            return result

    # Failed results: cap fields but don't store in scratch — the model
    # needs the error text, and errors are usually small.
    status = envelope_status or str(result.get("status", "")).lower()
    if status in ("failed", "error"):
        return _cap_result_fields(result)

    # Size check: under the cap = passthrough.
    try:
        result_size = len(json.dumps(result, default=str).encode("utf-8"))
    except (TypeError, ValueError):
        result_size = 0
    if result_size <= _LARGE_MODE_BYTE_CAP:
        return result

    # Over the cap: store full result in scratch, return capped copy.
    store = get_store()
    try:
        scratch_info = store.store(
            result, agent_id=agent_id, tool_id=tool_id, chat_id=chat_id,
        )
    except Exception as exc:
        logger.warning(f"[projection] scratch store failed for {tool_id}: {exc}")
        result["_projection_note"] = (
            f"scratch store unavailable ({exc}); returning capped result"
        )
        return _cap_result_fields(result)

    scratch_ref = scratch_info["scratch_ref"]
    capped = _cap_result_fields(result)
    capped["_projection"] = {
        "mode": "large",
        "full_ref": scratch_ref,
        "retrieval": (
            f"Call framework_scratch_search with scratch_ref='{scratch_ref}' "
            f"to retrieve the full uncapped output."
        ),
        "continuation": {
            "call": {
                "tool": "framework_scratch_search",
                "arguments": {"scratch_ref": scratch_ref},
            },
            "note": (
                "Ready-to-call retrieval for the full uncapped payload. "
                "Retrieved payloads are field-capped like this one; use "
                "filter/regex/fields/limit arguments to narrow."
            ),
        },
        "stored_bytes": scratch_info.get("stored_bytes", 0),
        "original_size_bytes": result_size,
        "byte_cap": _LARGE_MODE_BYTE_CAP,
        "note": (
            "Result exceeded the large-mode byte cap and was field-capped. "
            "The full output is in scratch."
        ),
    }
    return capped


# --- Digest builder --------------------------------------------------------

def _build_digest(
    result: Dict[str, Any],
    tool_id: str,
    scratch_ref: str,
    scratch_info: Dict[str, Any],
    provenance: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a digest envelope using a registered adapter or the naive fallback."""
    adapter = get_digest_adapter(tool_id)

    if adapter is not None:
        try:
            digest = adapter(result)
            summary = digest.get("summary", "")
            row_hint = digest.get("row_hint_format", "")
        except Exception as exc:
            logger.warning(f"[projection] digest adapter for {tool_id} failed: {exc}")
            summary, row_hint = _naive_digest(result, scratch_ref)
    else:
        summary, row_hint = _naive_digest(result, scratch_ref)

    retrieval = (
        f"Call framework_scratch_search with scratch_ref='{scratch_ref}' "
        f"to retrieve the full output."
    )

    envelope = dict(_DIGEST_TEMPLATE)
    envelope["summary"] = summary
    envelope["full_ref"] = scratch_ref
    envelope["retrieval"] = retrieval
    if row_hint:
        envelope["row_hint"] = row_hint
    envelope["tool_id"] = tool_id
    envelope["stored_bytes"] = scratch_info.get("stored_bytes", 0)
    envelope["continuation"] = {
        "call": {
            "tool": "framework_scratch_search",
            "arguments": {"scratch_ref": scratch_ref},
        },
        "note": (
            "Ready-to-call retrieval for the full uncapped output. Narrow "
            "with filter/regex/fields/limit arguments instead of pulling "
            "everything — retrieved payloads are field-capped too."
        ),
    }
    if provenance:
        envelope["_provenance"] = provenance
    return envelope


# --- Page builder ----------------------------------------------------------

def _build_page(
    result: Dict[str, Any],
    tool_id: str,
    scratch_ref: str,
    scratch_info: Dict[str, Any],
    *,
    offset: int,
    limit: int,
    provenance: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a bounded page envelope from the result's list-bearing fields."""
    # Find the primary list field to page.  Priority: rows, open_ports,
    # recent_lines, results, candidates, all, items, findings.  Fallback:
    # the first list value found.
    list_fields_priority = (
        "rows", "open_ports", "recent_lines", "results",
        "candidates", "all", "items", "findings", "matches",
    )

    paged_field = None
    paged_value: list = []

    for field in list_fields_priority:
        val = result.get(field)
        if isinstance(val, list) and val:
            paged_field = field
            paged_value = val
            break

    if paged_field is None:
        # No list field found — page the whole result as a single item.
        total = 1
        page_items = [result] if offset == 0 else []
        summary = f"Showing {'1' if offset == 0 else '0'} of 1 (non-list result)"
    else:
        total = len(paged_value)
        page_slice = paged_value[offset:offset + limit] if limit > 0 else paged_value[offset:]
        page_items = page_slice
        shown = len(page_slice)
        summary = f"Showing {shown} of {total} {paged_field}"

    envelope = dict(_PAGE_TEMPLATE)
    envelope["summary"] = summary
    envelope["rows"] = page_items
    envelope["paged_field"] = paged_field or "(full result)"
    envelope["full_ref"] = scratch_ref
    envelope["total"] = total
    envelope["offset"] = offset
    envelope["limit"] = limit
    envelope["tool_id"] = tool_id

    # Continuation: how to get the next page.  Two forms:
    # - ``next``: human-readable instruction (kept for backward compat).
    # - ``continuation``: a READY-TO-CALL dict — exact tool name + exact
    #   arguments (with next_offset).  The model copies it verbatim instead
    #   of reconstructing the follow-up call, which is where small models
    #   drop the offset and loop on page 1.  Mirrors REA's
    #   details.reported_limits.continuation.
    next_offset = offset + limit if limit > 0 and offset + limit < total else None
    if next_offset is not None:
        envelope["next"] = (
            f"Call framework_scratch_search with scratch_ref='{scratch_ref}' "
            f"offset={next_offset} limit={limit} to get the next page."
        )
        envelope["continuation"] = {
            "call": {
                "tool": "framework_scratch_search",
                "arguments": {
                    "scratch_ref": scratch_ref,
                    "offset": next_offset,
                    "limit": limit,
                },
            },
            "next_offset": next_offset,
            "note": "Ready-to-call: copy arguments verbatim for the next page.",
        }
    else:
        envelope["next"] = (
            f"End of results. Full output available at {scratch_ref}."
        )

    if provenance:
        envelope["_provenance"] = provenance

    return envelope


# --- Naive fallback digest --------------------------------------------------

def _naive_digest(result: Dict[str, Any], scratch_ref: str) -> tuple:
    """Build a conservative fallback digest when no adapter is registered.

    This is a bounded preview, not a real digest.  It reports:
    - status
    - key names present
    - counts of any list fields
    - first ~500 chars of any string fields that look like output (stdout, note, summary)
    - the retrieval instruction

    Returns (summary_str, row_hint_str).
    """
    parts: list = []

    status = result.get("status", "unknown")
    parts.append(f"status={status}")

    # Count list fields.
    for key, val in result.items():
        if isinstance(val, list) and val:
            parts.append(f"{key}={len(val)} items")
        elif isinstance(val, dict):
            parts.append(f"{key}={len(val)} keys")

    # Pull short text fields that help the model decide if it needs the full output.
    for key in ("summary", "note", "error", "job_id", "handle", "target"):
        val = result.get(key)
        if val is not None:
            text = str(val)
            if len(text) <= 200:
                parts.append(f"{key}={text}")
            else:
                parts.append(f"{key}={text[:200]}...")

    # Any stdout-like field gets a head preview.
    for key in ("stdout", "output", "raw", "recent_lines"):
        val = result.get(key)
        if isinstance(val, str) and val:
            preview = val[:500]
            parts.append(f"{key}_head={preview!r}")
        elif isinstance(val, list) and val:
            first = str(val[0])[:200] if val else ""
            parts.append(f"{key}[0]={first!r}")

    summary = " | ".join(parts)

    row_hint = (
        f"scratch_search {scratch_ref} --filter '<keyword>' "
        f"# pull specific rows from the full output"
    )

    return summary, row_hint


# --- Web-result HTML extraction adapter ------------------------------------
#
# Web tool results (session_get, session_post, session_request, session_upload,
# probe_web) carry the page HTML as a big string in ``body_head`` / ``body``.
# The generic _cap_result_fields truncates it to the first N chars, which is
# almost never what the model needs — it wants the *structured* content:
# forms (with their inputs + actions), links, script/src URLs, meta tags,
# and extracted CSRF tokens.  This adapter parses the HTML and returns those
# as list fields so the digest/page projection can page+filter them like any
# other list-bearing result, instead of treating the page as an opaque blob.
#
# The adapter is registered for the session_* tool IDs below.  It's used in
# digest mode (the model gets a structured summary, not a 40KB HTML dump)
# and as a scratch_search filter target (the model can grep for "form" or
# "csrf" and get the relevant structured rows, not a raw HTML line).
#
# BeautifulSoup is imported lazily — it's in requirements.txt but the module
# loads even if it's absent (degrading to a regex-based fallback).

_WEB_TOOL_IDS = (
    "auxiliaries.web_session.session_get",
    "auxiliaries.web_session.session_post",
    "auxiliaries.web_session.session_request",
    "auxiliaries.web_session.session_upload",
)


def _web_html_digest(result: Dict[str, Any]) -> Dict[str, Any]:
    """Per-tool digest adapter for web session results.

    Extracts structured content from the HTML body: forms (with inputs,
    action, method), links, script srcs, meta tags, and CSRF tokens.
    Returns ``{"summary": str, "row_hint_format": str}`` for the digest
    envelope, plus the extracted structures are embedded so scratch_search
    can page/filter them.
    """
    body = result.get("body_head") or result.get("body") or ""
    if not body or not isinstance(body, str):
        return {"summary": "no HTML body to parse", "row_hint_format": ""}

    extracted = _extract_html_structure(body)

    parts: list = []
    status = result.get("http_status", "?")
    url = result.get("final_url") or result.get("url", "?")
    title = result.get("title") or extracted.get("title", "")
    parts.append(f"{status} {url}")
    if title:
        parts.append(f"title: {title}")
    if extracted["forms"]:
        form_summs = []
        for f in extracted["forms"]:
            inputs = ", ".join(
                f'{inp["name"]}({inp["type"]})' for inp in f.get("inputs", [])
            )
            form_summs.append(f'{f.get("method","GET")} {f.get("action","?")} [{inputs}]')
        parts.append(f"forms: {' | '.join(form_summs)}")
    if extracted["links"]:
        parts.append(f"links: {len(extracted['links'])}")
    if extracted["scripts"]:
        parts.append(f"scripts: {len(extracted['scripts'])}")
    if extracted["csrf_tokens"]:
        names = ", ".join(t["name"] for t in extracted["csrf_tokens"])
        parts.append(f"csrf: {names}")

    summary = " | ".join(parts)
    hint = (
        f"structured HTML in scratch; scratch_search {result.get('_scratch_ref','<ref>')} "
        f"with filter='form' or filter='csrf' to pull specific elements, "
        f"or fields=forms,links to select structured lists"
    )
    return {"summary": summary, "row_hint_format": hint, "_extracted": extracted}


def _extract_html_structure(html: str) -> Dict[str, Any]:
    """Parse HTML and return structured content (forms, links, scripts, metas, CSRF).

    Uses BeautifulSoup when available; falls back to regex extraction.
    """
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
        return _extract_with_bs4(soup)
    except ImportError:
        return _extract_with_regex(html)


def _extract_with_bs4(soup) -> Dict[str, Any]:
    """Structured extraction via BeautifulSoup."""
    forms: list = []
    for form in soup.find_all("form"):
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            inputs.append({
                "name": inp.get("name", ""),
                "type": inp.get("type", inp.name),
                "value": (inp.get("value", "") or "")[:200],
            })
        forms.append({
            "action": form.get("action", ""),
            "method": (form.get("method", "GET") or "GET").upper(),
            "inputs": inputs,
        })

    links = []
    for a in soup.find_all("a", href=True):
        links.append(a["href"])

    scripts = []
    for s in soup.find_all("script", src=True):
        scripts.append(s["src"])

    metas = []
    for m in soup.find_all("meta"):
        metas.append({
            "name": m.get("name", m.get("property", "")),
            "content": (m.get("content", "") or "")[:200],
        })

    # CSRF tokens: hidden inputs with token-like names.
    csrf_names = {
        "csrfmiddlewaretoken", "authenticity_token", "_token",
        "__requestverificationtoken", "csrf_token", "csrf-token",
        "xsrf_token", "x-csrf-token",
    }
    csrf_tokens = []
    for inp in soup.find_all("input"):
        name = (inp.get("name", "") or "").lower()
        if name in csrf_names or "csrf" in name or "token" in name:
            csrf_tokens.append({
                "name": inp.get("name", ""),
                "value": (inp.get("value", "") or "")[:200],
                "type": inp.get("type", ""),
            })

    title_tag = soup.find("title")
    title = title_tag.get_text(strip=True) if title_tag else ""

    return {
        "forms": forms,
        "links": links[:200],  # cap to avoid context blowup
        "scripts": scripts[:100],
        "metas": metas[:50],
        "csrf_tokens": csrf_tokens,
        "title": title,
    }


def _extract_with_regex(html: str) -> Dict[str, Any]:
    """Fallback HTML extraction via regex (no BeautifulSoup).

    Less accurate but covers the common cases (forms, inputs, links, scripts).
    """
    import re as _re

    forms: list = []
    for m in _re.finditer(r'<form[^>]*>', html, _re.IGNORECASE):
        tag = m.group(0)
        action = ""
        am = _re.search(r'action=["\']([^"\']*)["\']', tag, _re.IGNORECASE)
        if am:
            action = am.group(1)
        method = "GET"
        mm = _re.search(r'method=["\']([^"\']*)["\']', tag, _re.IGNORECASE)
        if mm:
            method = mm.group(1).upper()
        # Find inputs until the closing </form>.
        end = html.find("</form>", m.end(), _re.IGNORECASE)
        if end == -1:
            end = len(html)
        form_html = html[m.end():end]
        inputs = []
        for im in _re.finditer(
            r'<input[^>]*>', form_html, _re.IGNORECASE
        ):
            itag = im.group(0)
            name = ""
            nm = _re.search(r'name=["\']([^"\']*)["\']', itag, _re.IGNORECASE)
            if nm:
                name = nm.group(1)
            itype = "text"
            tm = _re.search(r'type=["\']([^"\']*)["\']', itag, _re.IGNORECASE)
            if tm:
                itype = tm.group(1)
            val = ""
            vm = _re.search(r'value=["\']([^"\']*)["\']', itag, _re.IGNORECASE)
            if vm:
                val = vm.group(1)[:200]
            inputs.append({"name": name, "type": itype, "value": val})
        forms.append({"action": action, "method": method, "inputs": inputs})

    links = [
        m.group(1)
        for m in _re.finditer(r'<a[^>]+href=["\']([^"\']+)["\']', html, _re.IGNORECASE)
    ]
    scripts = [
        m.group(1)
        for m in _re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, _re.IGNORECASE)
    ]
    metas = []
    for m in _re.finditer(r'<meta[^>]+>', html, _re.IGNORECASE):
        tag = m.group(0)
        name = ""
        nm = _re.search(r'(?:name|property)=["\']([^"\']*)["\']', tag, _re.IGNORECASE)
        if nm:
            name = nm.group(1)
        content = ""
        cm = _re.search(r'content=["\']([^"\']*)["\']', tag, _re.IGNORECASE)
        if cm:
            content = cm.group(1)[:200]
        metas.append({"name": name, "content": content})

    csrf_tokens = []
    for m in _re.finditer(r'<input[^>]*>', html, _re.IGNORECASE):
        tag = m.group(0)
        name = ""
        nm = _re.search(r'name=["\']([^"\']*)["\']', tag, _re.IGNORECASE)
        if nm:
            name = nm.group(1)
        if "csrf" in name.lower() or "token" in name.lower():
            val = ""
            vm = _re.search(r'value=["\']([^"\']*)["\']', tag, _re.IGNORECASE)
            if vm:
                val = vm.group(1)[:200]
            itype = ""
            tm = _re.search(r'type=["\']([^"\']*)["\']', tag, _re.IGNORECASE)
            if tm:
                itype = tm.group(1)
            csrf_tokens.append({"name": name, "value": val, "type": itype})

    title = ""
    tm = _re.search(r'<title[^>]*>(.*?)</title>', html, _re.IGNORECASE | _re.DOTALL)
    if tm:
        title = tm.group(1).strip()

    return {
        "forms": forms,
        "links": links[:200],
        "scripts": scripts[:100],
        "metas": metas[:50],
        "csrf_tokens": csrf_tokens,
        "title": title,
    }


# Register the web adapter for all session_* tool IDs.
for _tid in _WEB_TOOL_IDS:
    register_digest_adapter(_tid, _web_html_digest)