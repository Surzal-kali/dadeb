"""Per-tool ``async def`` wrappers (signature + docstring) for the IPython lane.

The plain ``ipython`` command used to inject a flat ``List[ToolManifest]``
and a single ``quick_run("dotted.tool.id", **kw)`` helper.  Jedi completions
never fired because tool ids are *quoted strings*, not Python symbols — the
completer has nothing to index.  This module builds, per discovered tool, an
``async def`` wrapper that:

  • lives in the IPython namespace under a short, ergonomic alias
    (alias derivation lives in :mod:`replkit.aliases` — single source;
    ``curated_alias_name`` is the shared resolver)
  • carries an ``inspect.Signature`` built from the manifest's JSON-schema
    parameters so IPython shows ``target*``, ``options``, ``port`` with
    type + description tooltips on ``(``<Tab>``
  • has a ``__doc__`` assembled from the manifest's semantic capability +
    per-parameter descriptions so ``tool?`` / ``tool??`` work
  • dispatches through ``run_tool`` (→ executor → transport dispatch →
    scope gate + preflight) — never through raw ``resolve_callable`` — so
    the safety invariants that the REPL's ``run`` command enforces are
    identical inside IPython.

The wrappers are plain ``async def`` closures; IPython's ``%autoawait
asyncio`` (the default) lets the operator write ``await nmap(target=...)``
at the top level, same as the old ``quick_run``.

``scripts/gen_repl_stubs.py`` consumes ``_build_signature`` /
``_build_docstring`` / ``build_tool_aliases`` from here (via the top-level
shim) verbatim — "reimplementing signature logic there would guarantee
drift".
"""

import inspect
from typing import Any, Dict, List

from daharness.models import ToolManifest

from replkit.aliases import (
    build_tool_aliases,  # noqa: F401 — re-exported for gen_repl_stubs
    curated_alias_name,
)

# Backwards-compat re-exports for the shim: the stub generator and any doc
# references reach ``tool_repl._TOOL_ALIASES`` / ``_derive_alias`` / ...
from replkit.aliases import (  # noqa: F401
    _ALIAS_STRIP_PREFIXES,
    _ALIAS_STRIP_SUFFIXES,
    _derive_alias,
    _TOOL_ALIASES,
)


def _schema_type_to_py(schema_type: str) -> type:
    """Map a JSON-schema type string to a Python type for ``Signature``."""
    if schema_type in ("integer", "int"):
        return int
    if schema_type in ("number", "float"):
        return float
    if schema_type in ("boolean", "bool"):
        return bool
    if schema_type in ("array", "list"):
        return list
    if schema_type in ("object", "dict"):
        return dict
    return str


def _build_signature(manifest: ToolManifest) -> inspect.Signature:
    """Build an ``inspect.Signature`` from the manifest's parameter schema.

    Required parameters become positional-or-keyword with no default;
    optional parameters get ``None`` as a sentinel default.  Each parameter
    carries an ``annotation`` from the schema type, so IPython's tooltip
    shows ``target: str``, ``port: int``, etc.
    """
    if not manifest.parameters:
        return inspect.Signature()
    props = manifest.parameters.get("properties", {})
    required = set(manifest.parameters.get("required", []))
    params: List[inspect.Parameter] = []
    # Required first (so positional order matches declaration), then optional
    ordered = sorted(props.items(), key=lambda kv: (kv[0] not in required, kv[0]))
    for pname, pdef in ordered:
        stype = pdef.get("type", "string") if isinstance(pdef, dict) else "string"
        py_type = _schema_type_to_py(stype)
        default = inspect.Parameter.empty if pname in required else None
        params.append(
            inspect.Parameter(
                pname,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                default=default,
                annotation=py_type,
            )
        )
    return inspect.Signature(params)


def _build_docstring(manifest: ToolManifest) -> str:
    """Assemble a readable ``__doc__`` from the manifest's semantic capability
    and per-parameter descriptions.

    This is what ``tool?`` prints in IPython — the operator's quick reference.
    """
    lines = [manifest.internal_semantic_capability.strip(), ""]
    lines.append(f"    tool_id:    {manifest.module_id}")
    lines.append(f"    transport:  {manifest.transport.value}")
    lines.append(f"    path:        {manifest.implementation_path}")
    if manifest.tags:
        lines.append(f"    tags:        {', '.join(manifest.tags)}")
    if manifest.parameters:
        props = manifest.parameters.get("properties", {})
        required = set(manifest.parameters.get("required", []))
        if props:
            lines.append("")
            lines.append("    Parameters")
            lines.append("    ----------")
            for pname, pdef in props.items():
                stype = pdef.get("type", "string") if isinstance(pdef, dict) else "string"
                req = "*" if pname in required else " "
                desc = (pdef.get("description", "") if isinstance(pdef, dict) else "")[:80]
                lines.append(f"    {req} {pname} : {stype}  {desc}".rstrip())
    if manifest.next:
        lines.append("")
        lines.append("    Next steps")
        lines.append("    ----------")
        for hint in manifest.next:
            lines.append(f"    → {hint}")
    return "\n".join(lines)


def _make_tool_wrapper(manifest: ToolManifest, manifests_list: List[ToolManifest]):
    """Create an ``async def`` closure that dispatches a single tool through
    ``run_tool`` with a real ``Signature`` and ``__doc__``.

    The wrapper accepts ``**kwargs`` at the Python level but advertises its
    signature via ``__signature__`` so IPython/Jedi complete the named
    parameters.  Unknown kwargs are passed straight to ``run_tool``, which
    sends them through preflight validation — bad keys are rejected there,
    not silently dropped.
    """
    from replkit.core import run_tool

    tool_id = manifest.module_id
    sig = _build_signature(manifest)
    doc = _build_docstring(manifest)
    alias = curated_alias_name(tool_id)

    async def _wrapper(**kwargs):
        return await run_tool(tool_id, kwargs, manifests_list)

    # Attach the metadata that makes IPython completions + introspection work
    _wrapper.__name__ = alias
    _wrapper.__qualname__ = _wrapper.__name__
    _wrapper.__doc__ = doc
    _wrapper.__signature__ = sig
    # Stash the manifest for tools that want to introspect the wrapper
    _wrapper.__manifest__ = manifest  # type: ignore[attr-defined]
    return _wrapper