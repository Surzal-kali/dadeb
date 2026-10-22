#!/usr/bin/env python3
"""Tool REPL: standalone harness for testing framework tools independently.

Bypasses the LLM entirely — you pick a tool, supply arguments, and
see the raw result.  This isolates tool execution problems from model reasoning
problems so you can tell whether a tool actually works or if the model is just
calling it wrong.

Everything used to live in this file; it has been split into the
:mod:`replkit` package (focused modules — see ``replkit/__init__.py`` for the
map).  This file remains as a thin backwards-compat shim, and it stays a
**leaf**: every public and load-bearing private name is re-exported from the
modules there.  Keep it a leaf — importing it must never pull the optional
heavyweight lanes (ipykernel, IPython, prompt_toolkit; all are imported
lazily inside functions in the package).

**The filename is load-bearing.** This exact filename is matched/launched by:

  • the ``daharness`` kernelspec (kernel.json ``argv``) —
    ``replkit.kernel_lane._install_kernelspec`` and the deb's
    ``daharness-kernel`` wrapper
  • ``utils/engagement.py`` (journal lane inference via argv[0])
  • ``scripts/gen_repl_stubs.py`` (stub generator import + private helpers)

Modes (unchanged — see ``replkit.cli:main``):
  interactive       (default) — REPL prompt: list, run, info, selftest, quit
  run <id> [--flag val ...]   — one-shot: run a tool with --flag value args
  run <id> --json '{...}'     — one-shot: run a tool with JSON args (fallback)
  selftest [args]             — run the pytest suite (replaces legacy sweep;
                                works from any working directory)
  info <id>                   — show a tool's manifest without running it
  search <query>              — semantic search (needs ChromaDB + Ollama);
                                best match prints LAST, nearest the prompt
  scope / engagement          — operator-only gate/cobweb commands
  --kernel [-f <file>]        — start a Jupyter ZMQ kernel with every tool
                                pre-bound in user_ns; attach any Jupyter
                                frontend (jupyter console --existing,
                                JupyterLab, VS Code, PyCharm)
  --install-kernelspec        — register the 'daharness' kernel so every
                                Jupyter frontend's kernel picker lists it;
                                notebooks then run on framework tools
                                (package: `daharness-kernel --install-kernelspec`)

Argument parsing uses the tool's own parameter schema (from the manifest
discovered at startup) for type coercion — no hardcoded type maps.
"""

import sys
from pathlib import Path

# Vendored-wheel arm (deb lane) — TWIN of tree-root sitecustomize.py. This
# shim is the kernelspec entry point: frontends launch
# `python3 <tree>/tool_repl.py --kernel` BARE (no PYTHONPATH), and script-dir
# sitecustomize does NOT auto-import on py3.13/3.14 (verified — the tree arm
# only runs when PYTHONPATH carries the tree). Without this, daharness/
# __init__ -> registry.py's top-level `import chromadb` kills every
# frontend-launched kernel (jupyter console, nbconvert --execute,
# KernelManager) the moment a fresh deb exists whose chromadb lives only in
# <tree>/vendor. Same semantics as sitecustomize: prepend so the exact-pinned
# closure wins overlaps; inert when vendor/ is absent (dev-tree lanes keep
# pristine behavior) and idempotent, so wrapper-armed lanes (sitecustomize
# already inserted vendor via PYTHONPATH) insert nothing.
_vendor = str(Path(__file__).resolve().parent / "vendor")
# Interpreter-compat gate — see tree-root sitecustomize.py. The closure's
# C-extensions carry the packaging interpreter's cp-tag (pydantic_core's
# cp314-only binary killed this exact kernelspec lane on the dockered
# jupyter's py3.13). Arm only when this interpreter can actually load the
# closure; otherwise fall through to the environment's own site-packages.
_armable = True
if Path(_vendor).is_dir():
    _tag = f"cpython-{sys.version_info[0]}{sys.version_info[1]}"
    for _so in Path(_vendor).rglob("*.so"):
        if _so.name.endswith(".abi3.so"):
            continue
        _cp = next((p for p in _so.name.split(".") if p.startswith("cpython-")), "")
        if _cp and not _cp.startswith(_tag + "-"):
            _armable = False
            break
if _armable and Path(_vendor).is_dir() and _vendor not in sys.path:
    sys.path.insert(0, _vendor)

# Make project root importable (same as before the split — this file stays the
# one kernelspec entry points launch).
sys.path.insert(0, str(Path(__file__).resolve().parent))

# Load .env (same as bootstrap.py) so env-tunable knobs are visible.
# tool_repl.py is a standalone entry point — without this, os.getenv() only
# sees the system environment, not .env.
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent / ".env", override=True)
except ImportError:
    pass

# ── Re-exports: public API + load-bearing privates ──────────────────────────
#
# scripts/gen_repl_stubs.py reaches deep into the privates
# (_build_signature / _build_docstring / _STDLIB_BARES /
# _load_display_classes) — "reimplementing that logic in the generator
# would guarantee drift".  The shim keeps those attribute paths working.

from replkit.core import (  # noqa: F401
    SAFE_ARGS,
    discover_tools,
    find_manifest,
    parse_flag_args,
    print_manifest,
    print_result,
    resolve_callable,
    run_selftest,
    run_tool,
    safe_default_arguments,
)
from replkit.aliases import (  # noqa: F401
    build_tool_aliases,
    curated_alias_name,
    _derive_alias,
    _TOOL_ALIASES,
)
from replkit.brain_lane import (  # noqa: F401
    BRAIN_SOCKET,
    _brain_call,
    _brain_pack,
    _brain_read_message,
    _sessions_command,
)
from replkit.completer import ToolReplCompleter  # noqa: F401
from replkit.envelope import find, grep, keys, pluck, scratch  # noqa: F401
from replkit.operator_cli import (  # noqa: F401
    SCOPE_ON_FLAGS,
    SCOPE_SEARCH_FLAGS,
    SCOPE_SUBCOMMANDS,
    _engagement_command,
    _scope_command,
)
from replkit.namespace import (  # noqa: F401
    _STDLIB_BARES,
    _STDLIB_MODULES,
    _load_display_classes,
    build_ipython_namespace,
)
from replkit.wrappers import (  # noqa: F401
    _build_docstring,
    _build_signature,
    _make_tool_wrapper,
    _schema_type_to_py,
)
from replkit.ipython_ui import (  # noqa: F401
    _bottom_toolbar,
    _install_toolbar_and_keybindings,
    _ipython_toolbar_styles,
    _rprompt,
)
from replkit.ipython_embed import run_embedded_ipython  # noqa: F401
from replkit.kernel_lane import _install_kernelspec, _launch_kernel  # noqa: F401
from replkit.commands import oneshot_info, oneshot_run, repl_loop, repl_help  # noqa: F401
from replkit.cli import main  # noqa: F401


if __name__ == "__main__":
    main()