"""Envelope helpers: find / pluck / grep on large tool results.

Tool results in the REPL are plain dicts sitting in variables (``r``, ``out``,
whatever you assigned).  The structured payload is under ``result["result"]``
(a dict/list tree).  ``result["stdout"]`` is present only when the tool
returned a bare string — it is never a stringified copy of ``result``.
These helpers walk that tree so you don't have to remember the shape or
write a 5-line comprehension every time.

Ground-truth semantics mirror dabooks/primitives/kernelgate.py: the shim's
local walkers mirror the injected helpers EXACTLY, so behavior is
identical with or without delegation.

  find(r, "open_ports")        → list of all values at any key "open_ports"
  find(r, "port", value=80)    → list of {key:"port", value:80, path:"..."} dicts
  pluck(r, "ip")               → flat list of every "ip" value, no matter how deep
  grep(r, "admin")             → list of (path, matching_line) for any string containing "admin"
  keys(r)                      → sorted set of all keys anywhere in the tree
  scratch(ref, filter="8080")  → retrieve a stored scratch result with optional grep/paging
"""

import json
import re as _re
from typing import Any, Dict, List


class _Sentinel:
    """Marker for 'no value supplied' that's distinct from ``None``."""
    __slots__ = ()

    def __repr__(self):
        return "<MISSING>"


_MISSING = _Sentinel()


def _value_matches(actual: Any, expected: Any) -> bool:
    """Loose equality for ``find(..., value=)`` — handles int/str coercion."""
    if actual == expected:
        return True
    # Allow ``find(r, "port", value="80")`` to match int 80
    try:
        return str(actual) == str(expected)
    except Exception:
        return False


def _envelope_payload(envelope: Any) -> Any:
    """Unwrap a tool result envelope to its structured payload.

    The executor envelope is ``{"status": ..., "result": <raw>}`` — and
    optionally ``stdout`` when the tool returned a bare string (no structured
    data to duplicate).  If ``result`` is present, return it.  Otherwise fall
    back to ``stdout`` (parsing it as JSON if possible).  If neither is
    present, return the input unchanged — the operator may have passed the
    payload directly.
    """
    if not isinstance(envelope, dict):
        return envelope
    # Envelope detection: needs a transport status + at least one payload key.
    if "status" not in envelope:
        return envelope
    inner = envelope.get("result")
    if inner is not None:
        return inner
    # stdout is only present when there's no structured result (bare string
    # tool output, or legacy envelopes).  Try to parse it as JSON.
    raw = envelope.get("stdout", "")
    if isinstance(raw, str) and raw:
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return raw
    return raw


def find(envelope: Any, key: str, value: Any = _MISSING) -> List[Any]:
    """Deep-search a tool result for entries matching ``key`` (and optionally ``value``).

    Walks dicts, lists, and nested combinations.  Returns a list of matches:

      • ``find(r, "open_ports")`` → list of every value found at key ``"open_ports"``
        (regardless of depth).  One entry per occurrence.

      • ``find(r, "port", value=80)`` → list of ``{"key": "port", "value": 80,
        "path": "result.hosts[0].ports[1].port"}`` dicts — full context for
        each match, so you can see *where* the match was.

    Paths use dot notation with ``[N]`` for list indices, rooted at ``result``
    when the input is an envelope (or ``$`` when it's a bare value).
    """
    payload = _envelope_payload(envelope)
    root_label = "result" if payload is not envelope else "$"
    results: List[Any] = []

    def _walk(obj: Any, path: str) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                child_path = f"{path}.{k}"
                if k == key:
                    if value is _MISSING:
                        results.append(v)
                    else:
                        if _value_matches(v, value):
                            results.append({"key": k, "value": v, "path": child_path})
                _walk(v, child_path)
        elif isinstance(obj, (list, tuple)):
            for i, item in enumerate(obj):
                _walk(item, f"{path}[{i}]")

    _walk(payload, root_label)
    return results


def pluck(envelope: Any, key: str) -> List[Any]:
    """Extract all values for ``key`` from a tool result, no matter how deeply nested.

    Shortcut for ``find(envelope, key)`` when you just want the values (not
    paths).  Returns a flat list — list values kept WHOLE (one entry per
    occurrence, no flattening), dicts DROPPED.

      • ``pluck(r, "ip")`` → ``["10.0.0.1", "10.0.0.2", ...]``
      • ``pluck(r, "port")`` → ``[22, 80, 443, ...]``
    """
    return [v for v in find(envelope, key) if not isinstance(v, dict)]


def grep(envelope: Any, pattern: str, ignore_case: bool = True) -> List[tuple]:
    """Grep through all string values in a tool result, returning ``(path, line)`` tuples.

    Searches every string found anywhere in the structured payload (dict keys,
    dict values, list items).  When a value is a multi-line string, each line
    is searched independently and matching lines are returned with context.

      • ``grep(r, "admin")``           → all lines containing "admin"
      • ``grep(r, r"port.*80")``       → regex match
      • ``grep(r, "login", ignore_case=False)``  → case-sensitive

    Returns a list of ``(path, matching_line)`` tuples sorted by path.
    """
    payload = _envelope_payload(envelope)
    root_label = "result" if payload is not envelope else "$"
    flags = _re.IGNORECASE if ignore_case else 0
    rx = _re.compile(pattern, flags)
    matches: List[tuple] = []

    def _walk(obj: Any, path: str) -> None:
        if isinstance(obj, str):
            for line in obj.splitlines():
                if rx.search(line):
                    matches.append((path, line.strip()))
        elif isinstance(obj, dict):
            for k, v in obj.items():
                # Search keys too — useful for finding field names
                if rx.search(str(k)):
                    matches.append((f"{path}.{k}", f"<key> {k}"))
                _walk(v, f"{path}.{k}")
        elif isinstance(obj, (list, tuple)):
            for i, item in enumerate(obj):
                _walk(item, f"{path}[{i}]")

    _walk(payload, root_label)
    return matches


def keys(envelope: Any) -> List[str]:
    """Return a sorted list of every distinct key found anywhere in a tool result.

    Useful for discovering what fields a large envelope actually contains
    before you ``find`` or ``pluck`` them.

      • ``keys(r)`` → ``['host_state', 'hosts', 'ip', 'open_count', 'open_port_count', 'ports', ...]``
    """
    payload = _envelope_payload(envelope)
    seen: set = set()

    def _walk(obj: Any) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                seen.add(k)
                _walk(v)
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                _walk(item)

    _walk(payload)
    return sorted(seen)


def scratch(scratch_ref: str, *, filter: str = "", regex: str = "",
            fields: str = "", offset: int = 0, limit: int = 0,
            context: int = 0) -> Dict[str, Any]:
    """Retrieve a stored scratch result by reference, with optional grep/paging.

    Wraps ``ScratchStore.retrieve()`` — the same engine the API gateway's
    ``scratch_search`` endpoint uses, but callable directly from the REPL
    without going through HTTP.

      • ``scratch("scratch:abc123")``                     → full stored result
      • ``scratch("scratch:abc123", filter="8080")``      → lines containing "8080"
      • ``scratch("scratch:abc123", regex=r"port.*\\d+")``  → regex-filtered
      • ``scratch("scratch:abc123", fields="body_head,http_status")``  → select fields
      • ``scratch("scratch:abc123", offset=10, limit=5)`` → page through list results
      • ``scratch("scratch:abc123", filter="admin", context=3)``  → grep -C 3

    The REPL agent_id is ``"repl"``.
    """
    from utils.scratch_store import get_store
    store = get_store()
    return store.retrieve(
        scratch_ref,
        agent_id="repl",
        offset=offset,
        limit=limit,
        filter_pattern=filter or None,
        regex_pattern=regex or None,
        fields=fields or None,
        context_lines=context,
    )