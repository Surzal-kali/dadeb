"""Parameter introspection helpers for @framework_tool discovery.

Extracts per-parameter descriptions and type annotations from function
docstrings and signatures so the tool manifest's parameter schema is useful
to the secretary model instead of being generic placeholders like
``"description": "Parameter module_path"``.
"""

import inspect
import re
from typing import Any, Callable, Dict


def parse_param_docs(func: Callable) -> Dict[str, str]:
    """Parse per-parameter descriptions from a function's docstring.

    Supports Google-style (``Args:``) and NumPy-style (``Parameters``
    section) docstrings.  Returns a dict mapping parameter name to its
    description string.  Falls back to an empty dict when the docstring
    has no structured parameter docs.
    """
    doc = inspect.getdoc(func)
    if not doc:
        return {}

    result: Dict[str, str] = {}

    # Google-style: "Args:\n    name: description\n    name2: desc2"
    google_match = re.search(
        r"(?:Args|Arguments|Parameters)\s*:\s*\n((?:[ \t]+.+\n?)+)", doc
    )
    if google_match:
        block = google_match.group(1)
        # A parameter entry is a "name: desc" header line; any subsequent
        # indented line that is NOT a new "name: desc" header is a continuation
        # of the previous parameter's description (e.g. the multi-line
        # '(e.g. "--batch --forms --risk=3")' example under `options`).
        # Without this, continuation lines were silently dropped and the
        # manifest lost critical usage hints -- which is why the secretary
        # never learned to pass `--batch` to sqlmap and the scan blocked on
        # an interactive prompt until the turn timeout fired.
        current_name = None
        for line in block.splitlines():
            m = re.match(r"\s*(\w+)\s*(?:\([^)]*\))?\s*:\s*(.+)", line)
            if m:
                # New parameter header.
                current_name = m.group(1)
                result[current_name] = m.group(2).strip()
            elif current_name and line.strip():
                # Continuation of the previous parameter's description.
                result[current_name] = (result[current_name] + " " + line.strip()).strip()
        if result:
            return result

    # NumPy-style: "Parameters\n----------\nname : type\n    description"
    numpy_match = re.search(
        r"Parameters\s*\n\s*-+\s*\n((?:.+\n?)+?)(?=\n\s*[A-Z][a-z]+\s*\n|\n\s*-+|\Z)",
        doc,
    )
    if numpy_match:
        block = numpy_match.group(1)
        current_name = None
        current_desc = ""
        for line in block.splitlines():
            # Parameter header: "name : type" or just "name"
            header = re.match(r"\s*(\w+)\s*(?::\s*\S+)?\s*$", line)
            if header:
                if current_name and current_desc:
                    result[current_name] = current_desc.strip()
                current_name = header.group(1)
                current_desc = ""
            elif line.startswith("    ") and current_name:
                current_desc += " " + line.strip()
        if current_name and current_desc:
            result[current_name] = current_desc.strip()
        if result:
            return result

    return result


def annotation_to_schema_type(annotation: Any) -> str:
    """Map a Python type annotation to a JSON Schema type string.

    Falls back to "string" for untyped parameters (no annotation or
    ``inspect.Parameter.empty``), which is the safe default since most
    tool arguments are strings.

    Handles:
      - Bare types (int, str, bool, dict, list, ...)
      - typing module generics (Dict[str, Any], List[int], Tuple[...])
      - Optional[X] / Union[X, None] -> recurse on the non-None arm
      - str | None PEP-604 unions -> same recursion
      - Literal["a","b"] -> "string" (enum constraints come from
        :func:`annotation_to_schema_extras`, which the registry merges
        into the property dict alongside the type).
      - String annotations (PEP 563 ``from __future__ import annotations``):
        resolved by eval'ing in a small namespace of builtins + typing.
        Without this, every tool in a ``from __future__ import annotations``
        module would render as ``"string"`` in the manifest.
    """
    if annotation is inspect.Parameter.empty:
        return "string"

    # PEP 563: annotations stored as strings. ``inspect.signature`` returns
    # them as strings when ``eval_str=False`` (default) -- resolve them in
    # a controlled namespace so we can match against real types. Failures
    # fall through to the normal "string" fallback.
    if isinstance(annotation, str):
        try:
            import typing as _typing
            import builtins as _builtins
            # Expose the typing module *and* its public re-exports
            # (Optional, List, Dict, ...) at the top level, so annotations
            # like ``Optional[int]`` resolve the same way they would at
            # function definition time.
            _ns = {**_builtins.__dict__, "_typing": _typing}
            for _name in dir(_typing):
                if not _name.startswith("_"):
                    _ns[_name] = getattr(_typing, _name)
            annotation = eval(annotation, _ns)
        except Exception:
            return "string"

    origin = getattr(annotation, "__origin__", None)
    args = getattr(annotation, "__args__", ())

    # typing.Literal — return "string" and let annotation_to_schema_extras
    # add the enum constraint. We can't tell Literal apart from other
    # generics by __origin__ alone in older Pythons, so we also check by name.
    import typing as _typing
    if origin is _typing.Literal:
        return "string"

    # typing.Optional[X] and PEP-604 X | None both surface as Union[X, NoneType].
    if origin is not None and args:
        non_none = [a for a in args if a is not type(None)]
        if non_none and len(non_none) < len(args):
            # Strip the None and recurse on the remaining arm.
            return annotation_to_schema_type(non_none[0])
        # typing.Dict[str, int], typing.List[int], etc. — the origin is
        # the bare builtin (dict/list/tuple); look that up in the type_map.
        if origin in _TYPE_MAP:
            return _TYPE_MAP[origin]
        return "string"

    return _TYPE_MAP.get(annotation, "string")


def annotation_to_schema_extras(annotation: Any) -> Dict[str, Any]:
    """Return extra JSON Schema constraints an annotation implies, beyond
    its top-level ``type``.

    Currently produces ``{"enum": [...]}`` for ``Literal[...]`` annotations,
    which is the only annotation-derived constraint we need beyond the
    primitive type. Returns an empty dict for everything else.
    """
    import typing as _typing
    if annotation is inspect.Parameter.empty:
        return {}
    origin = getattr(annotation, "__origin__", None)
    args = getattr(annotation, "__args__", ())
    if origin is _typing.Literal and args:
        # Literal values can be strings, ints, bools, None; JSON-encode them
        # as their literal Python repr so the manifest round-trips cleanly.
        enum = []
        for v in args:
            if v is None:
                continue
            enum.append(v)
        if enum:
            return {"enum": enum}
    return {}


_TYPE_MAP = {
    int: "integer",
    float: "number",
    bool: "boolean",
    str: "string",
    list: "array",
    dict: "object",
    tuple: "array",
}
