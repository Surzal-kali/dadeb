#!/usr/bin/env python3
"""Generate pyright type stubs for the framework REPL's runtime tool aliases.

The tool REPL (``tool_repl.py``) builds its IPython namespace at *runtime*:
``build_ipython_namespace(manifests)`` mints one ``async def`` wrapper per
discovered tool, keyed by short alias.  Static analysis can't see those names —
they don't exist until discovery scans the repo.  This script closes that gap
for the editor lane:

  1. Run the same no-ChromaDB discovery the REPL itself uses
     (``tool_repl.discover_tools`` — static AST + dynamic import, zero ChromaDB).
  2. Feed the manifests through ``tool_repl.build_tool_aliases`` VERBATIM — the
     alias map this emits is the same one that executes inside the REPL.
     Reimplementing alias logic here would guarantee drift.
  3. Emit two files into a fixed dir outside the repo:

       ~/.local/share/framework-stubs/framework_tools.py
           PEP 562 shim: ``__getattr__`` resolves each alias from the live
           IPython user_ns at access time.  ``__all__`` lists every alias so
           ``from framework_tools import *`` getattr's each entry, triggering
           ``__getattr__`` — which inside the REPL returns the live async wrapper.

       ~/.local/share/framework-stubs/framework_tools.pyi
           One ``async def <alias>(...params...) -> Any: ...`` per alias, built
           from ``_build_signature`` (the exact signature objects the wrappers
           advertise) with ``_build_docstring`` output.  This is what pyright
           consumes for completion + hover + signature help.

  3. Maintain the generated ``builtins`` block in ``dabooks/ruff.toml``
     (between BEGIN/END marks).  The notebook-lane ruff config needs every
     kernel-injected name declared as a lint ``builtins`` entry, and ruff has
     no external-fragment include — the values must live in the config file
     itself.  Only the marked block is ever touched; hand-written config
     around it is never modified.

  4. Emit a BUILTINS FORK into the stub dir:

       ~/.local/share/framework-stubs/builtins.pyi
           A complete fork of pyright's own typeshed builtins.pyi + appended
           declarations for every kernel-injected name.  Pylance/pyright
           treat a stubPath-resolved builtins.pyi as a REPLACEMENT for the
           builtins module (verified live), so the fork must be complete —
           a partial stub would make ``print`` unresolved.  With the full
           fork in place, bare injected names resolve without diagnostics
           while typos (undeclared names) stay flagged — the editor lane
           no longer needs the global reportUndefinedVariable kill.

Everything here reads framework code — nothing outside the marked builtins
block in dabooks/ruff.toml is written back into the repo.

Usage:
    python scripts/gen_repl_stubs.py            # regenerate stubs + builtins
    python scripts/gen_repl_stubs.py --check    # exit 1 if either is stale

Env knobs:
    FRAMEWORK_STUBS_DIR   override the output dir (default
                          ~/.local/share/framework-stubs)
"""

from __future__ import annotations

import argparse
import inspect
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

# ── Import the framework exactly the way tool_repl.py does ──────────────────
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import tool_repl  # noqa: E402  (after sys.path setup)

OUT_DIR = Path(
    os.environ.get(
        "FRAMEWORK_STUBS_DIR",
        str(Path.home() / ".local/share/framework-stubs"),
    )
)
PY_FILE = OUT_DIR / "framework_tools.py"
PYI_FILE = OUT_DIR / "framework_tools.pyi"
BUILTINS_FILE = OUT_DIR / "builtins.pyi"
REPO_TOML = _REPO_ROOT / "dabooks" / "ruff.toml"

# Fork source: pyright's own typeshed builtins.pyi.  Preferred order: the
# Pylance extension bundle (editor lane parity — Pylance serves it to the
# IDE), then the wheel-bundled pyright (CLI lane).  Both carry dist/typeshed-
# fallback/stdlib/builtins.pyi.  If neither exists, generation aborts loudly
# rather than shipping a partial builtins fork (which nukes real builtins).
_FORK_SOURCES = (
    Path.home() / ".vscode-server/extensions",  # scanned below for matching dirs
)


def _builtins_fork_source() -> Path:
    """Locate the newest Pylance (or wheel pyright) bundled typeshed builtins.pyi."""
    ext_root = Path.home() / ".vscode-server/extensions"
    candidates: list[Path] = []
    if ext_root.is_dir():
        for d in ext_root.iterdir():
            if d.name.startswith("ms-python.vscode-pylance-"):
                p = d / "dist/typeshed-fallback/stdlib/builtins.pyi"
                if p.is_file():
                    candidates.append(p)
    p = (
        Path(sys.prefix)
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages/pyright/dist/dist/typeshed-fallback/stdlib/builtins.pyi"
    )
    candidates.append(p)
    newest = max(candidates, key=lambda c: c.stat().st_mtime, default=None)
    if newest is None:
        raise SystemExit(
            "builtins.pyi fork source not found: no ms-python.vscode-pylance-* "
            "extension in ~/.vscode-server/extensions and no wheel-bundled "
            "pyright typeshed in the current environment. The fork must be "
            "COMPLETE (a partial builtins.pyi replaces real builtins and "
            "breaks print/len/etc.) — refusing to generate from nothing."
        )
    return newest

_BUILTINS_BEGIN = (
    "# ── BEGIN generated: framework builtins (scripts/gen_repl_stubs.py) — DO NOT EDIT ──"
)
_BUILTINS_END = "# ── END generated: framework builtins ──"

# Names the ZMQ kernel gets from IPython itself, not from
# build_ipython_namespace: ``display()`` is a shell builtin (InteractiveShell
# init_displayhook) and so is ``get_ipython()``.  Both are guaranteed in every
# notebook kernel, so they belong in the ruff builtins list too.
_KERNEL_EXTRA_BUILTINS = ("display", "get_ipython")

# Permissive catch-all: runtime wrappers accept **kwargs (unknown kwargs go
# through preflight validation and get rejected there), and discovery
# occasionally surfaces params the static schema pass misses.  **kwargs keeps
# the stubs honest against every dispatch path.  Dropping it later is a free
# tightening — static arg-name checking without call-site churn.
_PERMISSIVE = "**kwargs: Any"

_HEADER_STAMP = (
    "Generated by scripts/gen_repl_stubs.py — DO NOT EDIT by hand; "
    "re-run the generator after framework changes."
)


# ── Signature rendering ──────────────────────────────────────────────────────

def _param_str(p: inspect.Parameter) -> str:
    """Render one Parameter as pyright-friendly stub text (ann as string)."""
    ann = "Any"
    if p.annotation is not inspect.Parameter.empty:
        ann = getattr(p.annotation, "__name__", None) or str(p.annotation)
        # Annotation objects render like <class 'str'>; __name__ gives 'str'.
        if ann.startswith("<class"):
            ann = "Any"
    default = ""
    if p.default is not inspect.Parameter.empty:
        default = " = None"
    return f"{p.name}: {ann}{default}"


def _render_signature(manifest) -> str:
    """Render ``(params, **kwargs: Any)`` from the manifest — never re-derived."""
    sig = tool_repl._build_signature(manifest)
    parts = [_param_str(p) for p in sig.parameters.values()]
    has_star = any(
        p.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
        for p in sig.parameters.values()
    )
    if not has_star:
        parts.append(_PERMISSIVE)
    return ", ".join(parts)


# ── Stub generation ──────────────────────────────────────────────────────────

def generate_pyi(alias_map: Dict[str, Any]) -> str:
    """Render the full .pyi text for one alias map."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    n = len(alias_map)
    header = [
        '"""Type declarations for the framework tool REPL (runtime-injected aliases).',
        "",
        f"{_HEADER_STAMP}",
        "",
        f"Generated: {now}",
        f"Tool count: {n}",
        "",
        "These are the same names the REPL injects into its IPython user_ns.",
        "Signatures + docstrings come verbatim from tool_repl._build_signature /",
        "_build_docstring on the live discovery manifests — not re-derived,",
        "so editor-side stubs cannot drift from what actually executes.",
        "",
        "Stdlib convenience modules + bare functions are also injected —",
        "see the stdlib overlay section at the bottom of this file.",
        "",
        "Hover (K in nvim) shows each wrapper's manifest-backed docstring.",
        '"""',
        "",
        "from typing import Any",
        "import asyncio",
        "import json",
        "import os",
        "import sys",
        "import time",
        "import pathlib",
        "import base64",
        "import hashlib",
        "import datetime",
        "import ipaddress",
        "import re",
        "import socket",
        "import subprocess",
        "import random",
        "import string",
        "import textwrap",
        "import pprint",
        "import traceback",
        "import struct",
        "import urllib.parse",
        "from IPython.display import HTML, Image, Javascript, JSON, Markdown",
        "",
    ]

    body: list[str] = []
    for alias in sorted(alias_map):
        m = alias_map[alias]
        sig = _render_signature(m)
        body.append(f"async def {alias}({sig}) -> Any:")
        body.append("    \"\"\"")
        for ln in tool_repl._build_docstring(m).splitlines():
            body.append(f"    {ln}" if ln.strip() else "")
        body.append("    \"\"\"")
        body.append("    ...")
        # One-line tag / handle-kinds comment for quick visual grep.
        tags = getattr(m, "tags", ()) or ()
        handles = getattr(m, "accepted_handle_kinds", ()) or ()
        meta = []
        if handles:
            meta.append("handles: " + ", ".join(handles))
        if tags:
            meta.append("tags: " + ", ".join(tags))
        if meta:
            body.append("    # " + " | ".join(meta))

    # ── Stdlib bare functions (hoisted to top-level in the REPL) ────────
    body.append("")
    body.append("# ── Stdlib convenience bares (pre-imported in the REPL) ─────────────")
    body.append("sleep = time.sleep  # type: ignore[assignment]")
    body.append("b64decode = base64.b64decode  # type: ignore[assignment]")
    body.append("b64encode = base64.b64encode  # type: ignore[assignment]")
    body.append("pp = pprint.pprint  # type: ignore[assignment]")
    body.append("pformat = pprint.pformat  # type: ignore[assignment]")
    body.append("pprint = pprint.pprint  # type: ignore[assignment]")
    body.append("urlsplit = urllib.parse.urlsplit  # type: ignore[assignment]")
    body.append("urljoin = urllib.parse.urljoin  # type: ignore[assignment]")
    body.append("quote = urllib.parse.quote  # type: ignore[assignment]")
    body.append("unquote = urllib.parse.unquote  # type: ignore[assignment]")
    body.append("sha256 = hashlib.sha256  # type: ignore[assignment]")
    body.append("md5 = hashlib.md5  # type: ignore[assignment]")

    # ── IPython.display wrapper classes (injected as bare names) ────────
    body.append("")
    body.append("# ── IPython.display wrapper classes (bare names in the REPL/kernel) ───")
    body.append("Markdown = Markdown  # type: ignore[assignment]")
    body.append("HTML = HTML  # type: ignore[assignment]")
    body.append("JSON = JSON  # type: ignore[assignment]")
    body.append("Image = Image  # type: ignore[assignment]")
    body.append("Javascript = Javascript  # type: ignore[assignment]")

    # ── Envelope helpers (deep-search tool results in the REPL) ─────────
    body.append("")
    body.append("# ── Envelope helpers (find/pluck/grep/keys on tool results) ────────")
    body.append("from typing import List, Tuple, Any as _Any")
    body.append("def find(envelope: _Any, key: str, value: _Any = ...) -> List[_Any]: ...")
    body.append("def pluck(envelope: _Any, key: str) -> List[_Any]: ...")
    body.append("def grep(envelope: _Any, pattern: str, ignore_case: bool = True) -> List[Tuple[str, str]]: ...")
    body.append("def keys(envelope: _Any) -> List[str]: ...")
    body.append("def scratch(scratch_ref: str, *, filter: str = \"\", regex: str = \"\",")
    body.append("            fields: str = \"\", offset: int = 0, limit: int = 0,")
    body.append("            context: int = 0) -> dict: ...")

    return "\n".join(header) + "\n" + "\n".join(body) + "\n"


def build_shim(aliases) -> str:
    """Return the framework_tools.py shim text (PEP 562)."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    n = len(aliases)
    # Stdlib bare-function names + IPython.display wrapper classes injected
    # by build_ipython_namespace.  Display classes are merged in so the shim's
    # __all__ matches the live namespace exactly.
    bares = {**tool_repl._STDLIB_BARES, **tool_repl._load_display_classes()}
    stdlib_bares = sorted(bares)
    # Envelope helper names injected by build_ipython_namespace.
    envelope_helpers = ["find", "grep", "keys", "pluck", "scratch"]
    tool_body = "\n".join("    " + repr(a) + "," for a in sorted(aliases))
    stdlib_body = "\n".join("    " + repr(a) + "," for a in stdlib_bares)
    envelope_body = "\n".join("    " + repr(a) + "," for a in envelope_helpers)
    total = len(aliases) + len(stdlib_bares) + len(envelope_helpers)
    return f'''"""PEP 562 shim — runtime-resolved framework tool aliases + stdlib bares + envelope helpers.

{_HEADER_STAMP}
Generated: {now} | Tools: {n} | Stdlib bares: {len(stdlib_bares)} | Envelope helpers: {len(envelope_helpers)} | Total: {total}

Inside the framework REPL (tool_repl.py → the ``ipython`` command), the shell
injects one async wrapper per discovered tool directly into ``user_ns``, plus
a set of pre-imported stdlib modules and bare functions (``sleep``, ``b64decode``,
``sha256``, etc.), plus envelope helpers (``find``, ``pluck``, ``grep``, ``keys``,
``scratch``) for deep-searching tool results.  This shim surfaces those live
objects to plain imports:

    from framework_tools import *   # inside the REPL: binds the live wrappers

``__all__`` covers every tool alias, stdlib bare, and envelope helper the REPL
registers.  Star-import getattr's each ``__all__`` entry, which triggers
``__getattr__``, which pulls the name from the live shell (``get_ipython`` is a
builtin inside IPython).  The aliases ALREADY exist in user_ns — this shim
costs nothing at REPL time and exists for the header import in scratch cells.
Outside a live shell attribute access raises a descriptive AttributeError
(never a silent None).
"""

import builtins
from typing import Any

__all__ = [
    # ── Tool aliases ───────────────────────────────────────────────────
{tool_body}
    # ── Stdlib bare functions ──────────────────────────────────────────
{stdlib_body}
    # ── Envelope helpers ──────────────────────────────────────────────
{envelope_body}
]


def __getattr__(name: str) -> Any:
    """PEP 562: resolve ``name`` from the live IPython user_ns at access time."""
    _get_ip = getattr(builtins, "get_ipython", None)
    _ip = _get_ip() if _get_ip else None
    if _ip is not None and name in _ip.user_ns:
        return _ip.user_ns[name]
    raise AttributeError(
        "module 'framework_tools' has no attribute "
        f"{{name!r}}; inside the framework REPL this name should exist in "
        "get_ipython().user_ns — re-run scripts/gen_repl_stubs.py if the "
        "alias list changed."
    )
'''


# ── Ruff builtins block (dabooks notebook lane) ──────────────────────────────

def build_builtins(manifests) -> list[str]:
    """Every name the kernel namespace injects at runtime.

    Sourced from ``build_ipython_namespace`` VERBATIM — the same dict that
    lands in IPython ``user_ns`` — so the lint allowlist cannot drift from
    what actually executes, plus the two IPython-injected kernel builtins.
    """
    ns = tool_repl.build_ipython_namespace(manifests)
    names = set(ns) | set(_KERNEL_EXTRA_BUILTINS)
    return sorted(names)


def render_builtins_block(names: list[str]) -> str:
    """Render the generated TOML block: BEGIN mark .. END mark, inclusive."""
    lines = [_BUILTINS_BEGIN, "builtins = ["]
    lines.extend(f'    "{n}",' for n in names)
    lines.extend(["]", _BUILTINS_END])
    return "\n".join(lines)


def apply_builtins(text: str, names: list[str]) -> str:
    """Replace the marked block in ``text``; refuse if the marks are missing."""
    if _BUILTINS_BEGIN not in text or _BUILTINS_END not in text:
        raise SystemExit(
            f"{REPO_TOML}: generated-block marks missing — the file needs both\n"
            f"  {_BUILTINS_BEGIN}\n"
            f"  {_BUILTINS_END}\n"
            "with the builtins = [...] array between them."
        )
    b = text.index(_BUILTINS_BEGIN)
    e = text.index(_BUILTINS_END) + len(_BUILTINS_END)
    return text[:b] + render_builtins_block(names) + text[e:]


def build_builtins_fork(names: list[str]) -> str:
    """Complete typeshed builtins.pyi fork + appended injected-name decls.

    Empirically verified (pyright CLI 1.1.409): a stubPath-resolved
    ``builtins.pyi`` REPLACES the engine's builtins module wholesale — a
    partial fork makes ``print``/``len``/etc. "undefined".  So the fork
    ships the engine's complete file (newline-stamped with its source
    version, which is also what makes ``--check`` detect engine upgrades)
    with the framework decls appended.
    """
    src = _builtins_fork_source()
    base = src.read_text()
    header = (
        "# Fork of pyright's typeshed builtins.pyi + framework kernel-injected names.\n"
        f"# {_HEADER_STAMP}\n"
        f"# Source: {src} ({len(base.splitlines())} lines)\n"
        "# Replacement semantics: pyright resolves builtins from this file"
        " wholesale\n# when stubPath points here — completeness is load-bearing."
    )
    lines = [
        "",  # blank line before the block for readability
        "# ── BEGIN generated: kernel-injected names — DO NOT EDIT ──",
    ]
    lines.extend(f"def {n}(*args: Any, **kwargs: Any) -> Any: ..." for n in names)
    lines.append("# ── END generated: kernel-injected names ──")
    return f"{header}\n\n{base}\n" + "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Generate pyright stubs + ruff builtins for the REPL's runtime tool aliases."
    )
    ap.add_argument(
        "--check",
        action="store_true",
        help="exit 1 if the stubs or the ruff builtins block are stale",
    )
    args = ap.parse_args()

    manifests = tool_repl.discover_tools()
    alias_map = tool_repl.build_tool_aliases(manifests)
    aliases = sorted(alias_map)
    stdlib_bare_count = len(tool_repl._STDLIB_BARES) + len(tool_repl._load_display_classes())
    envelope_count = 5  # find, pluck, grep, keys, scratch

    # Ruff builtins: the full kernel namespace (tool aliases + stdlib overlay
    # + envelope helpers + operator wrappers) + IPython's own kernel builtins.
    # Built from the live namespace dict, not re-derived — same anti-drift
    # rule as the .pyi signatures.
    builtin_names = build_builtins(manifests)

    pyi_text = generate_pyi(alias_map)
    shim_text = build_shim(aliases)

    if args.check:
        stubs_ok = (
            PYI_FILE.exists()
            and PY_FILE.exists()
            and PYI_FILE.read_text() == pyi_text
            and PY_FILE.read_text() == shim_text
        )
        toml_ok = REPO_TOML.exists() and apply_builtins(
            REPO_TOML.read_text(), builtin_names
        ) == REPO_TOML.read_text()
        fork_ok = BUILTINS_FILE.exists() and (
            BUILTINS_FILE.read_text() == build_builtins_fork(builtin_names)
        )
        stubs_state = "OK" if stubs_ok else "STALE"
        toml_state = "OK" if toml_ok else "STALE"
        fork_state = "OK" if fork_ok else "STALE"
        print(f"  {stubs_state}  {len(aliases)} tools + {stdlib_bare_count} stdlib bares + {envelope_count} envelope helpers, {PYI_FILE}")
        print(f"  {toml_state}  ruff builtins block ({len(builtin_names)} names), {REPO_TOML}")
        print(f"  {fork_state}  builtins.pyi fork ({len(builtin_names)} injected names), {BUILTINS_FILE}")
        return 0 if (stubs_ok and toml_ok and fork_ok) else 1

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    PY_FILE.write_text(shim_text)
    PYI_FILE.write_text(pyi_text)
    BUILTINS_FILE.write_text(build_builtins_fork(builtin_names))
    total = len(aliases) + stdlib_bare_count + envelope_count
    print(f"  Wrote {PYI_FILE} ({len(aliases)} tools + {stdlib_bare_count} stdlib bares + {envelope_count} envelope helpers)")
    print(f"  Wrote {PY_FILE} (PEP 562 shim, __all__ = {total} entries)")
    print(f"  Wrote {BUILTINS_FILE} (complete typeshed fork + {len(builtin_names)} injected names)")
    if REPO_TOML.exists():
        REPO_TOML.write_text(apply_builtins(REPO_TOML.read_text(), builtin_names))
        print(f"  Updated ruff builtins block in {REPO_TOML} ({len(builtin_names)} names)")
    else:
        print(f"  WARNING: {REPO_TOML} not found — ruff builtins block not updated")
    print(f"  nvim pyright extraPaths → {OUT_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
