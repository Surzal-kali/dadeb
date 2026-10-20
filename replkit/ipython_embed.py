"""The ``ipython`` command: terminal IPython embed with the framework namespace.

Terminal-lane sugar layered on IPython's ``InteractiveShellEmbed``:
  • Pygments syntax highlighting flipped ON (``colors="linux"`` default —
    InteractiveShellEmbed ships ``nocolor``, which leaves the already-wired
    IPythonPTLexer without a style).
  • nvim as the F2 / Ctrl+X Ctrl+E editor escape hatch (F3 launches a full
    standalone nvim session — the TUI IDE escape hatch).
  • Bottom toolbar + right-prompt + F1 globals dump (see
    :mod:`replkit.ipython_ui` for the whole decoration layer).

All env knobs here are the IPYTHON_* family from the monolith, unchanged.
"""

from pathlib import Path
import os
import shlex
from typing import Dict, List

from replkit.ipython_ui import (
    _IPYTHON_COLORS,
    _IPYTHON_EDITOR,
    _IPYTHON_MOUSE_SUPPORT,
    _IPYTHON_NVIM_ESCAPE,
    _IPYTHON_RPROMPT_ENABLED,
    _IPYTHON_TOOLBAR_ENABLED,
    _IPYTHON_TOOLBAR_NEWLINES,
    _install_toolbar_and_keybindings,
    _ipython_toolbar_styles,
)


def ipython_banner() -> List[str]:
    """The startup help printed before the embedded shell takes over.

    Split out of the embed body so it stays testable without spawning
    IPython (rendered by replkit.commands when the operator types ``ipython``).
    """
    from replkit.namespace import _STDLIB_BARES

    lines = [
        "  ── Stdlib convenience (pre-imported) ──",
        "    Modules: json, os, sys, time, asyncio, socket, subprocess, re,",
        "             hashlib, base64, datetime, ipaddress, pathlib, struct,",
        "             random, string, textwrap, pprint, traceback, urllib",
        "    Bares:   " + ", ".join(f"{n}(...)" for n in sorted(_STDLIB_BARES)),
        "",
        "  ── Display (bare names, no import needed) ──",
        "    Markdown('## heading')  HTML(table_str)  JSON(obj)  Image(path)",
        "    DisplayHandle: h = display(obj, display_id=True)",
        "                   h.update(new_obj)  → in-place in JupyterLab,",
        "                                      re-print in terminal",
        "",
        "  ── Envelope helpers (deep-search tool results) ──",
        "    find(r, 'open_ports')        → all values at that key, any depth",
        "    find(r, 'port', value=80)     → matches with path context",
        "    pluck(r, 'ip')                → flat list of every 'ip' value",
        "    grep(r, 'admin')              → (path, line) for all strings matching",
        "    keys(r)                       → every distinct key in the result tree",
        "    scratch('scratch:abc', filter='8080')  → retrieve stored scratch result",
        "",
        "  ── UI upgrades ──",
        f"    Syntax highlighting: ON (colors={_IPYTHON_COLORS})",
    ]
    if _IPYTHON_TOOLBAR_ENABLED:
        lines += [
            "    Bottom toolbar: cursor L:C, cell overview + in-cell vars, globals, scope/brain",
            "      F1 → dump all variables (in-cell uncommitted + committed globals)",
            f"      Newlines: {_IPYTHON_TOOLBAR_NEWLINES}  (IPYTHON_TOOLBAR_NEWLINES=expand|collapse|off)",
        ]
    if _IPYTHON_RPROMPT_ENABLED:
        lines.append("    Right prompt: missing required params shown inside tool()")
    if _IPYTHON_MOUSE_SUPPORT:
        lines.append("    Mouse: click to position cursor (Shift+drag to select text)")
    lines += [
        "  ── Editor escape hatches ──",
        f"    F2            → open current cell in {_IPYTHON_EDITOR} (save+quit pipes back)",
        "    Ctrl+X Ctrl+E → same as F2 (emacs-style)",
    ]
    if _IPYTHON_NVIM_ESCAPE:
        lines.append(f"    F3            → full {_IPYTHON_EDITOR} session in workspace root (:qa to return)")
    lines.append("  Ctrl+D / exit() to return.")
    return lines


def run_embedded_ipython(manifests: List) -> None:
    """Drop into interactive IPython with the framework namespace preloaded.

    Called from the REPL's ``ipython`` command (replkit.commands).  Runs in
    a worker thread (``asyncio.to_thread`` at the call site) because
    ``IPython.embed()`` → prompt_toolkit → ``asyncio.run()`` crashes with
    "cannot be called from a running event loop" when we're inside
    ``asyncio.run(repl_loop(...))`` — the thread gets a clean loop context.

    ``build_ipython_namespace`` provides the tools; the toolbar/UI decoration
    happens after the shell is constructed via
    ``_install_toolbar_and_keybindings``.
    """
    from IPython import embed  # noqa: F401  (import proves availability)
    from IPython.terminal.embed import InteractiveShellEmbed

    from replkit.namespace import build_ipython_namespace

    user_ns = build_ipython_namespace(manifests)

    tool_count = sum(1 for v in user_ns.values()
                     if callable(v) and hasattr(v, "__manifest__"))
    print(f"  Dropping into IPython — {tool_count} tools as top-level callables.")
    print("  Tab-completes tool names + parameter keywords.")
    print("  tool?  → manifest + params    tool??  → source")
    print()
    print("  await nmap(target='10.0.0.1', options='-Pn -p 22,80')")
    print("  await ffuf(url='http://10.0.0.1', wordlist='...')")
    print("  await smb_recon(host='10.0.0.1')")
    print()
    print("  Operator functions:")
    print("    scope_status()   scope_search('kw', assets=True)   sessions()")
    print("    (scope_on/scope_off are NOT available here — use the CLI:")
    print("     python tool_repl.py scope on <handle> / scope off)")
    print()
    print("  Also: tools  (dict of all wrappers),  manifests  (list),")
    print("        manifest_by_id('full.tool.id'),  run_tool,  resolve_callable")
    print()
    for line in ipython_banner():
        print(line)

    # IPython.embed() → prompt_toolkit → asyncio.run() crashes with "cannot
    # be called from a running event loop" when we're inside
    # asyncio.run(repl_loop(...)).  The caller runs THIS body in
    # asyncio.to_thread so the thread has no running loop — exactly what
    # IPython needs (the shell creates its own asyncio loop there).

    # colors="linux" flips Pygments syntax highlighting ON.
    # InteractiveShellEmbed defaults to "nocolor" which disables the
    # IPythonPTLexer's Pygments styling — the lexer is already wired into
    # pt_app, it just has no colour style to apply.  "linux" =
    # dark-terminal theme.  Override via IPYTHON_COLORS env (linux|neutral|
    # lightbg|nocolor|pride|gruvbox-dark).
    shell = InteractiveShellEmbed(
        user_ns=user_ns, header="", colors=_IPYTHON_COLORS,
    )
    # Merge toolbar/rprompt style overrides into the shell's Pygments style
    # so the bottom bar and right prompt get their own colours.
    try:
        existing = dict(shell.highlighting_style_overrides)
        existing.update(_ipython_toolbar_styles())
        shell.highlighting_style_overrides = existing
        shell.refresh_style()
    except Exception:
        pass

    # ── Editor: nvim as the escape hatch ────────────────────────────────
    # F2 (always on in IPython) opens the current cell in $VISUAL/$EDITOR
    # via prompt_toolkit's Buffer.open_in_editor().  Without this,
    # prompt_toolkit falls back to /usr/bin/editor (nano/vi) — a blank,
    # boring text editor.  Setting VISUAL+EDITOR to nvim means F2 drops you
    # into LazyVim with syntax highlighting, treesitter, copilot, the works
    # — for the current cell.  Save+quit pipes the text back into the
    # IPython prompt.
    os.environ["VISUAL"] = _IPYTHON_EDITOR
    os.environ["EDITOR"] = _IPYTHON_EDITOR
    # Also wire IPython's %edit magic to nvim.
    shell.editor = _IPYTHON_EDITOR

    # Force asyncio autoawait so ``await tool(...)`` works at the top level.
    # IPython rewrites the cell into an async function and runs it on its own
    # event loop (created in this thread, which has no running loop — exactly
    # what we need since the main loop is in the other thread).
    shell.loop_manager = "asyncio"
    shell.enable_gui("asyncio")

    # ── Bottom toolbar + rprompt + F1 globals overlay ───────────────────
    # Wired after the shell is fully constructed (pt_app exists).  The
    # toolbar re-renders every keystroke; the rprompt shows remaining
    # required tool params when the cursor is inside a tool call; F1 dumps
    # all user globals above the active prompt.
    try:
        _install_toolbar_and_keybindings(shell)
    except Exception as _e:
        print(f"[toolbar] install skipped: {_e!r}")

    shell()