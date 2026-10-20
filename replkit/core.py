"""Core REPL machinery: discovery, execution, arg parsing, printers, selftest.

All of this ran inside the old monolithic tool_repl.py; nothing here changed
semantically except ``run_selftest`` — the pytest-lane macro that replaces
the legacy ``sweep`` command (see the selftest docstring for why the sweep
lane was shelved).

No ChromaDB, no secretary, no model: these helpers build a bare
``ToolRegistry`` instance via ``__new__`` and execute tools directly through
the executor's dispatch chain (same preflight + scope-gate + Brain transport
as the Brain and the agent lanes).
"""

import json
import shlex
import subprocess
import sys
import time
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional

from daharness.models import ToolManifest
from daharness.registry import ToolRegistry

from replkit.safe_args import SAFE_ARGS

# pytest's console entry point (the bare binary is NOT on PATH in every
# container lane — always invoke through the interpreter).
_PYTEST_ARGS = [sys.executable, "-m", "pytest"]

# The selftest macro's anchor: pytest is always spawned with this as cwd and
# passthrough args are resolved against it, so ``tool_repl.py selftest`` works
# from any working directory (REPL, operator shell alias, CI) — the macro used
# to pass a rootdir-relative ``tests/`` and silently require the repo root cwd.
_REPO_ROOT = Path(__file__).resolve().parent.parent


# ── Lightweight executor (no ChromaDB, no secretary) ─────────────────────────

def _make_executor() -> ToolRegistry:
    """Create a bare ToolRegistry instance for tool execution without ChromaDB."""
    reg = ToolRegistry.__new__(ToolRegistry)
    reg._tool_instances = {}
    return reg


# ── Discover tools ──────────────────────────────────────────────────────────

def discover_tools() -> List[ToolManifest]:
    """Discover all tools using the registry's static+dynamic scan (no ChromaDB)."""
    reg = ToolRegistry.__new__(ToolRegistry)
    return reg.discover_local_tools()


# ── Run a tool ───────────────────────────────────────────────────────────────

async def run_tool(tool_id: str, arguments: Dict[str, Any], manifests: List[ToolManifest]) -> Dict[str, Any]:
    """Run a single tool by ID and return the result dict."""
    manifest = next((m for m in manifests if m.module_id == tool_id), None)
    if manifest is None:
        return {"error": f"Unknown tool_id: {tool_id}", "status": "Failed"}

    executor = _make_executor()

    print(f"  [repl] Running {tool_id}")
    print(f"  [repl] Transport: {manifest.transport.value}")
    print(f"  [repl] Args: {json.dumps(arguments, default=str)[:500]}")
    print(f"  [repl] Implementation: {manifest.implementation_path}")

    start = time.monotonic()
    try:
        result = await executor.execute_tool(manifest, arguments)
    except Exception as exc:
        result = {"error": f"Exception during execution: {exc}", "status": "Failed"}
        traceback.print_exc()
    elapsed = time.monotonic() - start

    result["_elapsed_s"] = round(elapsed, 2)
    return result


# ── Resolve and inspect a tool function ──────────────────────────────────────

def resolve_callable(tool_id: str):
    """Resolve a tool_id to its Python callable (without running it)."""
    executor = _make_executor()
    return executor._resolve_callable(tool_id)


# ── Printers ────────────────────────────────────────────────────────────────

def print_manifest(m: ToolManifest, verbose: bool = False):
    """Print a tool manifest summary."""
    handle_info = ""
    if m.accepted_handle_kinds:
        handle_info = f"  handles={list(m.accepted_handle_kinds)}"
    print(f"  {m.module_id}")
    print(f"    transport:  {m.transport.value}")
    print(f"    capability: {m.internal_semantic_capability[:120]}")
    print(f"    path:        {m.implementation_path}")
    if handle_info:
        print(f"    {handle_info}")
    if verbose and m.parameters:
        props = m.parameters.get("properties", {})
        req = m.parameters.get("required", [])
        for pname, pdef in props.items():
            req_mark = "*" if pname in req else " "
            ptype = pdef.get("type", "?")
            pdesc = pdef.get("description", "")
            print(f"      {req_mark} {pname}: {ptype}  {pdesc}")


def print_result(result: Dict[str, Any]):
    """Pretty-print a tool execution result."""
    status = result.get("status", "unknown")
    elapsed = result.get("_elapsed_s", "?")
    marker = "✓" if status == "Success" else "✗"
    print(f"  [{marker}] Status: {status}  ({elapsed}s)")
    if result.get("degraded"):
        print("  ⚠ degraded: Brain socket down — executed IN-PROCESS in this REPL.")
        print("    Any session opened by this call is REPL-local (the agent cannot see it).")

    # Result and stdout are mutually exclusive in the new envelope: when
    # structured data is present under "result", there is no stringified
    # "stdout" copy of it.  Print whichever exists — never both.
    res = result.get("result")
    if res is not None:
        display = json.dumps(res, default=str, indent=2)[:2000]
        if len(json.dumps(res, default=str)) > 2000:
            display += "\n  ... (more data elided)"
        print(f"  result:\n{display}")
    else:
        stdout = result.get("stdout", "")
        if stdout:
            display = stdout[:2000] if len(stdout) > 2000 else stdout
            if len(stdout) > 2000:
                display += f"\n  ... ({len(stdout) - 2000} more chars)"
            print(f"  stdout:\n{display}")

    error = result.get("error")
    if error:
        print(f"  error: {error}")

    stderr = result.get("stderr", "")
    if stderr:
        display = stderr[:1000] if len(stderr) > 1000 else stderr
        print(f"  stderr:\n{display}")


# ── Argument parsing: --flag value, using manifest schema for coercion ──────

def parse_flag_args(tokens: List[str], manifest: Optional[ToolManifest] = None) -> Dict[str, Any]:
    """Parse --flag value style arguments into a dict.

    Uses the tool manifest's parameter schema for type coercion:
      - schema type "integer" / "number"  → int / float
      - schema type "boolean"            → True/False from true/false/yes/no/1/0
      - everything else                   → string

    Bare flags (--flag with no value) are set to True.
    --no-flag sets flag to False.
    Positional args fill required params in declaration order.

    Fallback: if the first token looks like JSON (starts with '{'), the whole
    string is parsed as JSON.  Also supports an explicit --json marker.
    """
    if not tokens:
        return {}

    # Fallback: entire arg string is JSON
    if tokens[0].startswith("{"):
        try:
            return json.loads(" ".join(tokens))
        except json.JSONDecodeError:
            pass

    # --json marker: everything after it is JSON
    if tokens[0] == "--json":
        remainder = tokens[1:]
        if not remainder:
            return {}
        try:
            return json.loads(" ".join(remainder))
        except json.JSONDecodeError as e:
            print(f"  Invalid JSON after --json: {e}")
            return {}

    # Build type map from the manifest schema (the authoritative source)
    type_map: Dict[str, str] = {}
    required_order: List[str] = []
    if manifest and manifest.parameters:
        props = manifest.parameters.get("properties", {})
        for pname, pdef in props.items():
            type_map[pname] = pdef.get("type", "string")
        required_order = list(manifest.parameters.get("required", []))

    args: Dict[str, Any] = {}
    i = 0
    positional_idx = 0

    while i < len(tokens):
        tok = tokens[i]

        # --no-flag → False
        if tok.startswith("--no-"):
            flag_name = tok[5:]
            args[flag_name] = False
            i += 1
            continue

        # --flag value or --flag (bare → True)
        if tok.startswith("--"):
            flag_name = tok[2:]
            if i + 1 < len(tokens) and not tokens[i + 1].startswith("--"):
                raw_value = tokens[i + 1]
                args[flag_name] = _coerce_value(raw_value, type_map.get(flag_name, "string"))
                i += 2
            else:
                args[flag_name] = True
                i += 1
            continue

        # Positional: assign to the next unfilled required param
        if positional_idx < len(required_order):
            pname = required_order[positional_idx]
            # Only fill if not already set by a --flag
            if pname not in args:
                args[pname] = _coerce_value(tok, type_map.get(pname, "string"))
                positional_idx += 1
                i += 1
                continue

        print(f"  Warning: skipping unrecognized arg: {tok}")
        i += 1

    return args


def _coerce_value(raw: str, schema_type: str) -> Any:
    """Coerce a raw string value using the schema-declared type."""
    if schema_type in ("integer", "int"):
        try:
            return int(raw)
        except ValueError:
            return raw
    elif schema_type in ("number", "float"):
        try:
            return float(raw)
        except ValueError:
            return raw
    elif schema_type in ("boolean", "bool"):
        return raw.lower() in ("true", "yes", "1", "on")
    return raw


# ── Selftest macro (the sweep lane's replacement) ────────────────────────────
#
# The legacy ``sweep`` ran every discoverable tool with per-tool test args —
# but the real test suite already covers that ground deterministically, and
# sweep's safe-args table duplicated it while tools that hit the armed scope
# gate just errored in bulk. Shelling out to pytest from the REPL reuses the
# exact same function slots a CI run uses. The spawn is anchored to the repo
# root (cwd + arg anchoring) so the macro fires from any directory:
#
#     repl> selftest                  → python -m pytest <root>/tests -q
#     repl> selftest test_scope_gate  → tests/test_scope_gate.py
#     repl> selftest -k budget        → passthrough of pytest args


def _anchor_pytest_arg(arg: str) -> str:
    """Map a passthrough pytest arg onto the repo root (cwd-independent).

    Bare test names get the ``tests/`` anchoring the help text documents
    (``test_scope_gate`` → ``tests/test_scope_gate.py``); repo-relative paths
    pass through and resolve because pytest is spawned with the repo root as
    cwd. Absolute paths and flags (``-k``, ``-x``, ``--tb=short``, …) are
    untouched. A file found under the *caller's* cwd is anchored absolute —
    the only case whose cwd cannot be assumed. Unknown tokens pass through
    so pytest surfaces its own honest "file not found" error.
    """
    if not arg or arg.startswith("-") or Path(arg).is_absolute():
        return arg
    file_part, sep, node_rest = arg.partition("::")
    for cand in (file_part, f"tests/{file_part}", f"tests/{file_part}.py"):
        if (_REPO_ROOT / cand).exists():
            return cand + (f"::{node_rest}" if sep else "")
    caller_file = Path.cwd() / file_part
    if caller_file.exists():
        return str(caller_file) + (f"::{node_rest}" if sep else "")
    return arg


def _selftest_argv(extra_args: Optional[List[str]] = None) -> List[str]:
    """Build the selftest macro's pytest argv (see :func:`run_selftest`).

    No extras runs the full ``tests/`` tree quiet; passthrough args are
    anchored to the repo root by :func:`_anchor_pytest_arg`.
    """
    extra = [a for a in (extra_args or []) if a not in ("--force", "-f")]
    if not extra:
        return list(_PYTEST_ARGS) + [str(_REPO_ROOT / "tests"), "-q"]
    return list(_PYTEST_ARGS) + [_anchor_pytest_arg(a) for a in extra]


def run_selftest(extra_args: Optional[List[str]] = None) -> int:
    """Run the pytest suite as a REPL macro. Returns pytest's exit code.

    Cwd-independent — fires the same from the REPL, an operator shell alias,
    or CI: pytest is spawned with the repo root as cwd and passthrough args
    are anchored there (``test_scope_gate`` → ``tests/test_scope_gate.py``;
    ``-k``-style flags untouched). ``--force``/``-f`` are accepted-and-ignored
    so old ``sweep --force`` muscle memory doesn't error — they carry no
    meaning in the pytest lane.
    """
    argv = _selftest_argv(extra_args)
    print(f"  [selftest] {' '.join(argv)}")
    try:
        return subprocess.run(argv, cwd=str(_REPO_ROOT)).returncode
    except KeyboardInterrupt:
        print("  [selftest] interrupted")
        return 130
    except Exception as exc:
        print(f"  [selftest] failed to launch pytest: {exc}")
        return 1


# ── Manifest lookup shared by loop + one-shots ──────────────────────────────

def find_manifest(tool_id: str, manifests: List[ToolManifest]) -> Optional[ToolManifest]:
    """Find a manifest by exact ID, or by substring match (unique only).

    Argument order follows the monolith's ``_find_manifest(tool_id,
    manifests)`` convention — tool first, list second.
    """
    m = next((m for m in manifests if m.module_id == tool_id), None)
    if m is not None:
        return m
    matches = [m for m in manifests if tool_id in m.module_id]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        print(f"  Multiple matches for '{tool_id}':")
        for mm in matches:
            print(f"    {mm.module_id}")
    return None


def safe_default_arguments(tool_id: str, m: Optional[ToolManifest]) -> Optional[Dict[str, Any]]:
    """Resolve the bare-`run` argument set for a tool from SAFE_ARGS.

    Returns the args dict when defaults exist, or ``None`` after printing
    guidance when they don't (required params surfaced for the operator).
    """
    arguments = dict(SAFE_ARGS.get(tool_id, {}))
    if arguments:
        return arguments
    req = (m.parameters or {}).get("required", []) if m else []
    if req:
        print(f"  No safe defaults for {tool_id}. Required params: {req}")
        print(f"  Usage: run {tool_id} --{' --'.join(req)} <value> ...")
    else:
        print(f"  No safe defaults for {tool_id}. Running with no args.")
    return {} if not req else None


# shlex re-export: command modules parse operator input the same way.
__all__ = [
    "SAFE_ARGS",
    "discover_tools",
    "find_manifest",
    "parse_flag_args",
    "print_manifest",
    "print_result",
    "resolve_callable",
    "run_selftest",
    "run_tool",
    "shlex",
    "safe_default_arguments",
]