"""Interactive REPL loop + one-shot helpers + help text.

``repl_loop`` is the ``repl>`` command loop (prompt_toolkit input with the
completer from :mod:`replkit.completer`, plain ``input()`` fallback).  The
``ipython`` branch hands off to :mod:`replkit.ipython_embed`; operator
commands delegate to :mod:`replkit.operator_cli`; session listing to
:mod:`replkit.brain_lane`.

One-shot helpers (``oneshot_run`` / ``oneshot_info``) back the CLI's
``run`` / ``info`` modes (:mod:`replkit.cli`) — each discovers fresh, runs
via :mod:`replkit.core`, and returns the process exit code.
"""

import asyncio
import inspect
import json
import shlex
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from daharness.models import ToolManifest

from replkit.brain_lane import _sessions_command
from replkit.completer import ToolReplCompleter
from replkit.core import (
    SAFE_ARGS,
    discover_tools,
    find_manifest,
    parse_flag_args,
    print_manifest,
    print_result,
    resolve_callable,
    run_tool,
)
from replkit.ipython_embed import run_embedded_ipython
from replkit.operator_cli import _engagement_command, _scope_command

# ── Rich input (prompt_toolkit) ──────────────────────────────────────────────
# Falls back to plain input() when prompt_toolkit isn't installed.  The
# context-aware Tier-4 completer lives in replkit.completer.
_PROMPT_TOOLKIT = False
try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.history import FileHistory
    _PROMPT_TOOLKIT = True
except ImportError:
    pass


def _normalise_tool_id(tool_id: str) -> str:
    """Accept jedi-style call form — ``run utils.journal.what_touched()``.

    IPython/jedi suggest tools as call sites, so operators type the ``()``
    call form into ``run`` / ``info`` / ``resolve``. It is not part of the
    tool_id.
    """
    return tool_id.removesuffix("()")


def _find_tool_live(
    tool_id: str,
    manifests: List[ToolManifest],
    completer: Optional[ToolReplCompleter] = None,
) -> tuple[Optional[ToolManifest], List[ToolManifest]]:
    """Manifest lookup with a one-shot live re-discovery on a miss.

    The ``repl>`` loop holds the manifest snapshot taken at startup
    (``reindex`` refreshes it), while jedi/IPython introspect live modules —
    so a newly added tool autocompletes minutes before the loop can run it.
    On a lookup miss, re-discover once and adopt the fresh list (refreshing
    the completer) when it gains the tool.
    """
    m = find_manifest(tool_id, manifests)
    if m is not None:
        return m, manifests
    fresh = discover_tools()
    m = find_manifest(tool_id, fresh)
    if m is not None:
        if completer is not None:
            completer.refresh(fresh)
        return m, fresh
    return None, manifests


def repl_help():
    print("""
Tool REPL commands:
  list [filter]          List all tools (optional substring filter)
  search <query>         Semantic search via ChromaDB (needs Ollama + ChromaDB);
                         results render worst-first so rank #1 sits right above the prompt
  info <tool_id>         Show full manifest for a tool
  resolve <tool_id>      Resolve a tool_id to its Python callable (dry run)
  sessions               Show Brain-held (SHARED with agent) vs REPL-local sessions
  run <tool_id> [--flag value ...]   Run a tool with flag args (schema-aware)
  run <tool_id> --json '{...}'       Run a tool with JSON args
  run <tool_id>          Run with safe-default args (if defined)
  selftest [pytest args] Run the pytest suite (replaces the legacy sweep);
                         fires from any directory (anchored to the repo root):
                         selftest                      → python -m pytest tests/ -q
                         selftest test_scope_gate      → one file (tests/-anchored)
                         selftest -k budget            → passthrough of pytest args
  reindex                Re-discover tools
  ipython                Drop into IPython with tools as named async callables
                         (Tab-completion on tool names + params, tool? introspection,
                         cell-based chaining).  await nmap(target=...), await ffuf(...), etc.
                         Stdlib modules pre-imported: json, os, socket, hashlib, base64,
                         re, subprocess, datetime, ipaddress, etc.  sleep(30), b64decode(),
                         sha256(), pp() available as bare names.
                         Envelope helpers: find(r,'key'), pluck(r,'ip'), grep(r,'admin'),
                         keys(r), scratch('scratch:ref', filter='8080').
  scope on <handle> [--platform h1|bugcrowd|intigriti] [--no-strict] [--ip-boundary]
                         Arm the packet-scope gate (send_packet refuses
                         out-of-scope destinations; operator-only, not exposed
                         to the agent). 'scope off' disarms (lab mode).
  scope status|off|add-ip <ip> [<hostname>]|rm-ip <ip>|list-ips|search <kw> [--assets]
  engagement on <slug> [<roe_note>]   Arm the engagement cobweb key (operator-only,
                         not exposed to the agent): journal + evidence rows across
                         every lane carry the slug so 'engagement purge <slug>'
                         erases one engagement in one transaction. 'engagement off'
                         disarms (rows keep their slug). Credential material is
                         bounded by the 24h floor, not mid-engage scrubbing.
  engagement status|purge <slug>
  help                   This message
  quit / exit            Leave the REPL

Flag args are type-coerced from the tool's own manifest schema:
  --target 10.10.10.50    string (default)
  --port 22               integer (per schema)
  --verbose               bare flag → True
  --no-verbose             → False
  --limit 5                integer (per schema)

Positional args fill required params in order:
  run auxiliaries.nmap.run_nmap 10.10.10.50 "-Pn -p 22"
  (equivalent to --target 10.10.10.50 --options "-Pn -p 22")
""")


async def repl_loop(manifests: List[ToolManifest]):
    """Interactive REPL loop."""
    repl_help()

    # Rich input: context-aware autocomplete via prompt_toolkit.  Falls back
    # to plain input() when the library isn't available.
    session = None
    completer = None
    if _PROMPT_TOOLKIT:
        completer = ToolReplCompleter(manifests)
        session = PromptSession(
            completer=completer,
            complete_while_typing=True,
            history=FileHistory(str(Path.home() / ".tool_repl_history")),
        )

    async def _read_line() -> str:
        # Scope-armed indicator: a checkmark when a scope is armed (sends
        # gated), no sign when disarmed (lab mode). Recomputed each prompt
        # so 'scope on/off' is reflected immediately. Cheap: one stat/json.
        try:
            from utils.scope_gate import is_armed
            _mark = "✓ " if is_armed() else ""
        except Exception:
            _mark = ""
        _prompt = f"\n{_mark}repl> "
        if session is not None:
            return await session.prompt_async(_prompt)
        return input(_prompt)

    while True:
        try:
            line = (await _read_line()).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not line:
            continue
        parts = line.split(None, 1)
        cmd = parts[0].lower()
        rest = parts[1] if len(parts) > 1 else ""

        if cmd in ("quit", "exit", "q"):
            break

        elif cmd == "help" or cmd == "h":
            repl_help()

        elif cmd == "list":
            filter_str = rest.lower()
            shown = 0
            for m in manifests:
                if filter_str and filter_str not in m.module_id.lower():
                    continue
                print_manifest(m)
                shown += 1
            print(f"\n  {shown} tool(s) shown ({len(manifests)} total)")

        elif cmd == "info":
            if not rest:
                print("  Usage: info <tool_id>")
                continue
            m, manifests = _find_tool_live(_normalise_tool_id(rest), manifests, completer)
            if m is None:
                if not any(rest in mm.module_id for mm in manifests):
                    print(f"  No tool found matching '{rest}'")
                continue
            print_manifest(m, verbose=True)

        elif cmd == "resolve":
            if not rest:
                print("  Usage: resolve <tool_id>")
                continue
            func, err = resolve_callable(_normalise_tool_id(rest))
            if func is None:
                print(f"  ✗ Resolve failed: {err}")
            else:
                print(f"  ✓ Resolved to: {func}")
                sig = inspect.signature(func)
                print(f"    Signature: {func.__qualname__}{sig}")
                doc = getattr(func, "_tool_doc", None) or inspect.getdoc(func) or ""
                if doc:
                    print(f"    Doc: {doc[:200]}")

        elif cmd == "run":
            if not rest:
                print("  Usage: run <tool_id> [--flag value ...] or run <tool_id> --json '{...}'")
                continue
            # Use shlex.split so shell-style quoting is honoured: without it,
            # --target 'https://example.com' passes the literal quotes as
            # part of the value → ZAP gets url='https://example.com' → 400.
            try:
                tokens = shlex.split(rest)
            except ValueError as e:
                print(f"  Argument parse error (unbalanced quotes?): {e}")
                continue
            tool_id = _normalise_tool_id(tokens[0])
            arg_tokens = tokens[1:]

            m, manifests = _find_tool_live(tool_id, manifests, completer)
            if m is None:
                if not any(tool_id in mm.module_id for mm in manifests):
                    print(f"  Unknown tool: {tool_id}")
                continue

            if not arg_tokens:
                from replkit.core import safe_default_arguments
                arguments = safe_default_arguments(tool_id, m)
                if arguments is None:
                    continue
            else:
                arguments = parse_flag_args(arg_tokens, manifest=m)

            result = await run_tool(tool_id, arguments, manifests)
            print_result(result)

        elif cmd == "selftest":
            from replkit.core import run_selftest
            extra = shlex.split(rest) if rest else []
            rc = await asyncio.to_thread(run_selftest, extra)
            print(f"  [selftest] exit code: {rc}")

        elif cmd == "search":
            if not rest:
                print("  Usage: search <semantic query>")
                continue
            try:
                from daharness.registry import OllamaEmbeddingFunction, ToolRegistry as RealRegistry
                real_reg = RealRegistry(embedding_model=OllamaEmbeddingFunction())
                results = await real_reg.find_tools(rest)
                if not results:
                    print("  No results.")
                # find_tools returns best-first (T-002: array position == rank,
                # and the secretary/agents read array position — do NOT change
                # that ordering).  The terminal renders top-down, so the REPL
                # prints the list in reverse: worst match lands highest on
                # screen, rank #1 prints LAST, right above the prompt instead
                # of scrolling off into scrollback.
                for rank, m in reversed(list(enumerate(results, 1))):
                    dist = f"  dist={m.distance}" if m.distance is not None else ""
                    print_manifest(m, verbose=True)
                    print(f"    #{rank}{dist}")
            except Exception as e:
                print(f"  Search failed (needs ChromaDB + Ollama): {e}")

        elif cmd == "reindex":
            manifests = discover_tools()
            if completer is not None:
                completer.refresh(manifests)
            print(f"  Re-discovered {len(manifests)} tools.")

        elif cmd == "ipython":
            try:
                await asyncio.to_thread(run_embedded_ipython, manifests)
            except ImportError:
                print("  IPython not installed. Install with: pip install ipython")

        elif cmd == "sessions":
            await _sessions_command()

        elif cmd == "scope":
            _scope_command(rest)

        elif cmd == "engagement":
            _engagement_command(rest)

        else:
            print(f"  Unknown command: {cmd}. Type 'help' for commands.")


# ── One-shot run ─────────────────────────────────────────────────────────────

async def oneshot_run(tool_id: str, arg_tokens: List[str]):
    """Run a single tool and print the result, then exit."""
    from replkit.core import safe_default_arguments

    manifests = discover_tools()
    tool_id = _normalise_tool_id(tool_id)
    m = find_manifest(tool_id, manifests)
    if m is None:
        print(f"Unknown tool: {tool_id}")
        return 1

    if not arg_tokens:
        arguments = safe_default_arguments(tool_id, m)
        if arguments is None:
            return 1
    else:
        arguments = parse_flag_args(arg_tokens, manifest=m)

    result = await run_tool(tool_id, arguments, manifests)
    print_result(result)
    return 0 if result.get("status") == "Success" else 1


async def oneshot_info(tool_id: str):
    """Show info for a single tool, then exit."""
    manifests = discover_tools()
    tool_id = _normalise_tool_id(tool_id)
    m = find_manifest(tool_id, manifests)
    if m is None:
        print(f"No tool found matching '{tool_id}'")
        return 1
    print_manifest(m, verbose=True)

    func, err = resolve_callable(tool_id)
    if func:
        print(f"  Resolved: {func}")
    else:
        print(f"  Resolve: FAILED — {err}")
    return 0