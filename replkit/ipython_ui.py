"""IPython bottom toolbar + globals overlay + rprompt (prompt_toolkit layer).

These are pure prompt_toolkit decorations layered on top of IPython's
existing ``pt_app`` (a ``PromptSession``).  No Jupyter, no kernel — just
``FormattedText`` callables and a ``KeyBindings`` entry.

  • ``_bottom_toolbar(shell)`` — re-renders every keystroke; shows cursor
    line:col, count of user-assigned globals, scope-armed marker, and the
    word under cursor if it matches a tool alias (so you see the tool's
    manifest snippet while typing its name).
  • ``_rprompt(shell)`` — right-aligned next to the input line; when the
    cursor is inside ``alias(``, shows the remaining **required** params
    with their types — the same info as ``tool?`` but live and contextual.
  • F1 keybinding — prints a formatted dump of all user globals (the
    variables set above the current cell) above the active prompt.
  • Syntax highlighting — IPython's ``IPythonPTLexer`` (Pygments
    ``PythonLexer``) is already wired into ``pt_app``; the only reason
    colours are off is ``InteractiveShellEmbed`` defaults to
    ``colors="nocolor"``.  Passing ``colors="linux"`` flips the Pygments
    style on.  (That last flip happens in :mod:`replkit.ipython_embed`.)

Env knobs (all optional):
  IPYTHON_COLORS            linux|neutral|lightbg|nocolor|pride|gruvbox-dark (default linux)
  IPYTHON_TOOLBAR           1/0 — bottom toolbar on/off
  IPYTHON_RPROMPT           1/0 — right prompt on/off
  IPYTHON_TOOLBAR_MAX_VARS  names shown per tier (default 6)
  IPYTHON_TOOLBAR_REPR_LEN  max repr length per variable (default 20)
  IPYTHON_TOOLBAR_NEWLINES  expand|collapse|off (default expand)
  IPYTHON_MOUSE             1/0 — click-to-position cursor.  When ON the
                            terminal's native drag-to-select is captured by
                            the app — hold Shift while dragging to force
                            terminal-native selection.
  IPYTHON_EDITOR            $EDITOR fallback for F2 (default nvim).
                            F2 is ALWAYS bound in IPython; the env only
                            changes which editor opens.
  IPYTHON_NVIM_ESCAPE       1/0 — F3 full-nvim-session escape hatch.
"""

from pathlib import Path
import os
import shlex
from typing import Any, Dict, List

from constants import brain_socket_path

# Env knobs for the toolbar / globals display.
_IPYTHON_COLORS = os.getenv("IPYTHON_COLORS", "linux")  # linux|neutral|lightbg|nocolor|pride|gruvbox-dark
_IPYTHON_TOOLBAR_ENABLED = os.getenv("IPYTHON_TOOLBAR", "1").lower() not in ("0", "false", "no", "off")
_IPYTHON_RPROMPT_ENABLED = os.getenv("IPYTHON_RPROMPT", "1").lower() not in ("0", "false", "no", "off")
# Max globals shown in the toolbar's compact line (F1 shows all).
_IPYTHON_TOOLBAR_MAX_VARS = int(os.getenv("IPYTHON_TOOLBAR_MAX_VARS", "6"))
# Max repr length per variable in the toolbar.
_IPYTHON_TOOLBAR_REPR_LEN = int(os.getenv("IPYTHON_TOOLBAR_REPR_LEN", "20"))
# Sanitize newlines/tabs in toolbar previews so the single-line bar doesn't
# break.  "expand" (default) shows ↵/→· glyphs; "collapse" replaces with
# spaces; "off" leaves raw (multi-line toolbar, may garble the display).
_IPYTHON_TOOLBAR_NEWLINES = os.getenv("IPYTHON_TOOLBAR_NEWLINES", "expand").lower()
# Mouse support: click to position cursor inside the input buffer.
# Tradeoff: when ON, the terminal's native drag-to-select is captured by
# the app — hold Shift while dragging to force terminal-native selection
# (works in GNOME Terminal, iTerm2, Windows Terminal, Konsole, etc.).
_IPYTHON_MOUSE_SUPPORT = os.getenv("IPYTHON_MOUSE", "1").lower() not in ("0", "false", "no", "off")
# External editor for the IPython shell.  F2 (always on in IPython) opens
# the current cell in $VISUAL/$EDITOR; we default to nvim so the escape
# hatch lands in a full TUI IDE (LazyVim, copilot, neo-tree, telescope, …)
# instead of the nano/vi fallback.  Override with IPYTHON_EDITOR="code --wait"
# or similar if you prefer a different editor.
_IPYTHON_EDITOR = os.getenv("IPYTHON_EDITOR", "nvim")
# F3 launches a full standalone nvim session (not cell-edit) — the TUI IDE
# escape hatch.  :qa returns to IPython with all live state intact.
# Set IPYTHON_NVIM_ESCAPE=0 to disable the F3 binding.
_IPYTHON_NVIM_ESCAPE = os.getenv("IPYTHON_NVIM_ESCAPE", "1").lower() not in ("0", "false", "no", "off")

def _sanitize_preview(text: str) -> str:
    """Replace newlines/tabs in a preview string so the toolbar stays one line.

    - ``expand`` (default): ``\n`` → ``↵``, ``\t`` → ``→·`` — visible but compact.
    - ``collapse``: replace with single spaces — clean but lossy.
    - ``off`` / anything else: return unchanged (may break the single-line bar).
    """
    if _IPYTHON_TOOLBAR_NEWLINES == "expand":
        return text.replace("\n", "↵").replace("\t", "→·")
    if _IPYTHON_TOOLBAR_NEWLINES == "collapse":
        return text.replace("\n", " ").replace("\t", " ")
    return text
# Mouse support: click to position cursor inside the input buffer.
# Tradeoff: when ON, the terminal's native drag-to-select is captured by
# the app — hold Shift while dragging to force terminal-native selection
# (works in GNOME Terminal, iTerm2, Windows Terminal, Konsole, etc.).
_IPYTHON_MOUSE_SUPPORT = os.getenv("IPYTHON_MOUSE", "1").lower() not in ("0", "false", "no", "off")
# External editor for the IPython shell.  F2 (always on in IPython) opens
# the current cell in $VISUAL/$EDITOR; we default to nvim so the escape
# hatch lands in a full TUI IDE (LazyVim, copilot, neo-tree, telescope, …)
# instead of the nano/vi fallback.  Override with IPYTHON_EDITOR="code --wait"
# or similar if you prefer a different editor.
_IPYTHON_EDITOR = os.getenv("IPYTHON_EDITOR", "nvim")
# F3 launches a full standalone nvim session (not cell-edit) — the TUI IDE
# escape hatch.  :qa returns to IPython with all live state intact.
# Set IPYTHON_NVIM_ESCAPE=0 to disable the F3 binding.
_IPYTHON_NVIM_ESCAPE = os.getenv("IPYTHON_NVIM_ESCAPE", "1").lower() not in ("0", "false", "no", "off")


def _user_globals(shell) -> List[tuple]:
    """Return ``[(name, value), ...]`` for user-assigned globals in the shell.

    Filters out dunder names, callables (tool wrappers, functions), classes,
    modules, and IPython internals (``__name__``, ``In``, ``Out``, etc.).
    Sorted by insertion order approximation (Python 3.7+ dicts preserve it;
    ``user_ns`` is a regular dict).
    """
    ns = shell.user_ns
    _skip = {"__builtin__", "__builtins__", "_", "__", "___", "_dh",
             "_ih", "_oh", "_sh", "In", "Out", "exit", "quit",
              "get_ipython", "user_ns", "tools", "manifests", "registry"}
    result = []
    for k, v in ns.items():
        if k.startswith("_") or k in _skip:
            continue
        if callable(v) and not hasattr(v, "__manifest__"):
            continue
        import types as _types_mod
        if isinstance(v, type) or isinstance(v, _types_mod.ModuleType):
            continue
        # Skip the tool-wrapper callables (they carry __manifest__)
        if hasattr(v, "__manifest__"):
            continue
        result.append((k, v))
    return result


def _cell_local_vars(cell_text: str, cursor_row: int = -1) -> List[tuple]:
    """Extract variable names assigned in the current (unexecuted) cell text.

    Uses ``ast`` to walk assignment targets — ``ast.parse`` is safe on
    incomplete code because we append a dummy line so the parser sees a
    complete module.  Returns ``[(name, preview_str), ...]`` sorted by
    line number, where ``preview_str`` is a best-effort literal preview
    (the RHS source text truncated, since we can't eval unexecuted code).

    Only names assigned **before** ``cursor_row`` (if given) are returned —
    you don't want completions for variables defined below your cursor.
    """
    import ast as _ast

    # Pad with a newline so an incomplete last line doesn't break the parser
    text = cell_text
    if not text.endswith("\n"):
        text += "\n"

    try:
        tree = _ast.parse(text)
    except SyntaxError:
        # Try wrapping in a try block — handles bare ``await`` at top level
        # which is only valid inside async def.  IPython rewrites it, but ast
        # doesn't.  Fallback: regex for ``name =`` patterns.
        return _cell_local_vars_regex(cell_text, cursor_row)

    results = []
    for node in _ast.iter_child_nodes(tree):
        if isinstance(node, _ast.Assign):
            # ``x = 42`` → targets are Names
            for target in node.targets:
                if isinstance(target, _ast.Name):
                    if cursor_row >= 0 and node.lineno > cursor_row + 1:
                        continue
                    rhs = _ast.get_source_segment(text, node) or ""
                    # Strip the ``name = `` prefix for the preview
                    eq_idx = rhs.find("=")
                    preview = rhs[eq_idx + 1:].strip() if eq_idx >= 0 else "?"
                    if len(preview) > _IPYTHON_TOOLBAR_REPR_LEN:
                        preview = preview[:_IPYTHON_TOOLBAR_REPR_LEN] + "~"
                    preview = _sanitize_preview(preview)
                    results.append((target.id, preview))
        elif isinstance(node, _ast.AnnAssign):
            # ``x: int = 42``
            if isinstance(node.target, _ast.Name):
                if cursor_row >= 0 and node.lineno > cursor_row + 1:
                    continue
                if node.value is not None:
                    rhs = _ast.get_source_segment(text, node) or ""
                    eq_idx = rhs.find("=")
                    preview = rhs[eq_idx + 1:].strip() if eq_idx >= 0 else "?"
                    if len(preview) > _IPYTHON_TOOLBAR_REPR_LEN:
                        preview = preview[:_IPYTHON_TOOLBAR_REPR_LEN] + "~"
                    preview = _sanitize_preview(preview)
                    results.append((node.target.id, preview))
        elif isinstance(node, (_ast.AugAssign,)):
            # ``x += 1`` — x must already exist, but we still track it
            if isinstance(node.target, _ast.Name):
                if cursor_row >= 0 and node.lineno > cursor_row + 1:
                    continue
                results.append((node.target.id, "<aug>"))
        # ``with ... as x:`` and ``for x in ...:`` targets
        elif isinstance(node, _ast.With):
            for item in node.items:
                if item.optional_vars and isinstance(item.optional_vars, _ast.Name):
                    if cursor_row >= 0 and node.lineno > cursor_row + 1:
                        continue
                    results.append((item.optional_vars.id, "<with>"))
        elif isinstance(node, _ast.For):
            if isinstance(node.target, _ast.Name):
                if cursor_row >= 0 and node.lineno > cursor_row + 1:
                    continue
                results.append((node.target.id, "<loop>"))

    return results


def _cell_local_vars_regex(cell_text: str, cursor_row: int = -1) -> List[tuple]:
    """Fallback regex-based extraction when ``ast.parse`` fails.

    Catches ``name = ...`` and ``name: type = ...`` patterns.  Less accurate
    than AST (misses unpacking, ignores indentation context) but handles
    incomplete code with bare ``await`` that ast.parse rejects.
    """
    import re as _re

    results = []
    lines = cell_text.split("\n")
    for i, line in enumerate(lines):
        if cursor_row >= 0 and i > cursor_row:
            break
        # ``name = value`` or ``name: type = value`` — top-level (no leading
        # whitespace) or indented inside a block we don't track.
        m = _re.match(r"^(\w+)\s*(?::\s*\S+)?\s*=\s*(.+)", line)
        if m:
            name = m.group(1)
            preview = m.group(2).strip()
            if len(preview) > _IPYTHON_TOOLBAR_REPR_LEN:
                preview = preview[:_IPYTHON_TOOLBAR_REPR_LEN] + "~"
            preview = _sanitize_preview(preview)
            results.append((name, preview))
    return results


def _cell_overview(cell_text: str, max_lines: int = 3) -> str:
    """Compact one-line overview of the current cell.

    Shows the first non-empty line (truncated) and the total line count.
    If the cell is multi-line, includes a ``… (+N lines)`` suffix.
    """
    lines = cell_text.split("\n")
    # Find the first non-empty, non-comment line
    first = ""
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            first = stripped
            break
    if not first:
        first = lines[0].strip() if lines else ""
    if len(first) > 40:
        first = first[:37] + "…"
    total = len(lines)
    if total > 1:
        return f"{first} … (+{total - 1}L)"
    return first


def _bottom_toolbar(shell):
    """Bottom status bar: cursor position + cell-local vars + globals + status.

    Returns ``FormattedText`` (list of ``(style, text)`` tuples) that
    prompt_toolkit re-renders on every keystroke via ``bottom_toolbar``.

    The toolbar shows **two tiers** of variables:
      1. **Cell-local** (uncommitted) — names assigned in the current cell
         text above the cursor, parsed via ``ast``.  These aren't in
         ``user_ns`` yet (the cell hasn't executed) but they're what you're
         actively working with.  Rendered in a distinct colour.
      2. **Globals** (committed) — variables in ``user_ns`` from previously
         executed cells.  The existing behaviour.
    """
    from prompt_toolkit.formatted_text import FormattedText

    parts = []
    cell_text = ""
    cursor_row = -1

    # ── Cursor position + cell overview ────────────────────────────────
    try:
        buf = shell.pt_app.app.current_buffer
        doc = buf.document
        row = doc.cursor_position_row + 1
        col = doc.cursor_position_col + 1
        cell_text = buf.text
        cursor_row = doc.cursor_position_row
        parts.append(("class:toolbar.cursor", f" L{row}:C{col} "))
        if cell_text.strip():
            overview = _cell_overview(cell_text)
            parts.append(("class:toolbar.cell", f" [{overview}] "))
    except Exception:
        parts.append(("", " L-:C- "))

    # ── Cell-local (uncommitted) variables ─────────────────────────────
    if cell_text.strip():
        try:
            cell_vars = _cell_local_vars(cell_text, cursor_row)
            if cell_vars:
                parts.append(("class:toolbar.cellvars", f" {len(cell_vars)} in-cell "))
                previews = []
                for name, preview in cell_vars[:_IPYTHON_TOOLBAR_MAX_VARS]:
                    previews.append(f"{name}={_sanitize_preview(preview)}")
                preview_str = "  ".join(previews)
                if len(cell_vars) > _IPYTHON_TOOLBAR_MAX_VARS:
                    preview_str += " …"
                parts.append(("class:toolbar.cellpreview", f" {preview_str} "))
        except Exception:
            pass

    # ── Committed globals count + compact preview ──────────────────────
    try:
        globs = _user_globals(shell)
        parts.append(("class:toolbar.vars", f" {len(globs)} globals "))
        if globs:
            recent = globs[-_IPYTHON_TOOLBAR_MAX_VARS:]
            previews = []
            for name, val in recent:
                try:
                    rv = repr(val)
                except Exception:
                    rv = "<?>"
                if len(rv) > _IPYTHON_TOOLBAR_REPR_LEN:
                    rv = rv[:_IPYTHON_TOOLBAR_REPR_LEN] + "~"
                rv = _sanitize_preview(rv)
                previews.append(f"{name}={rv}")
            preview_str = "  ".join(previews)
            if len(globs) > _IPYTHON_TOOLBAR_MAX_VARS:
                preview_str += " …"
            parts.append(("class:toolbar.preview", f" {preview_str} "))
    except Exception:
        pass

    # ── Scope-armed marker ─────────────────────────────────────────────
    try:
        from utils.scope_gate import is_armed as _is_armed
        if _is_armed():
            parts.append(("class:toolbar.scope", " [SCOPE ARMED] "))
    except Exception:
        pass

    # ── Brain socket status ────────────────────────────────────────────
    try:
        sock = Path(brain_socket_path())
        if sock.exists():
            parts.append(("class:toolbar.brain", " brain:✓ "))
        else:
            parts.append(("class:toolbar.brain.down", " brain:✗ "))
    except Exception:
        pass

    return FormattedText(parts)


def _rprompt(shell):
    """Right-prompt: show remaining required params when inside a tool call.

    Detects ``alias(`` in the text before the cursor and, if the alias is a
    known tool wrapper, renders the **required** params that haven't been
    supplied yet — live, right-aligned on the input line.
    """
    from prompt_toolkit.formatted_text import FormattedText

    try:
        buf = shell.pt_app.app.current_buffer
        text = buf.document.text_before_cursor
    except Exception:
        return FormattedText([])

    # Find the last unclosed ``(`` — are we inside a call?
    paren_depth = 0
    open_paren_idx = -1
    for i, ch in enumerate(text):
        if ch == "(":
            paren_depth += 1
            open_paren_idx = i
        elif ch == ")":
            paren_depth -= 1
    if paren_depth <= 0 or open_paren_idx < 0:
        return FormattedText([])

    # Extract the word immediately before the ``(`` (the function/alias name)
    before_paren = text[:open_paren_idx]
    # Strip trailing whitespace
    stripped = before_paren.rstrip()
    if not stripped:
        return FormattedText([])
    # Walk backwards to the first non-identifier char
    end = len(stripped)
    start = end
    while start > 0 and (stripped[start - 1].isalnum() or stripped[start - 1] == "_"):
        start -= 1
    alias = stripped[start:end]
    if not alias:
        return FormattedText([])

    # Strip a leading ``await`` — the alias is the word after it
    if alias == "await":
        remainder = stripped[:start].rstrip()
        end2 = len(remainder)
        start2 = end2
        while start2 > 0 and (remainder[start2 - 1].isalnum() or remainder[start2 - 1] == "_"):
            start2 -= 1
        alias = remainder[start2:end2]

    if not alias:
        return FormattedText([])

    # Look up the tool wrapper in user_ns
    wrapper = shell.user_ns.get(alias)
    if wrapper is None or not hasattr(wrapper, "__manifest__"):
        return FormattedText([])

    manifest = wrapper.__manifest__
    if not manifest.parameters:
        return FormattedText([])

    props = manifest.parameters.get("properties", {})
    required = set(manifest.parameters.get("required", []))
    if not required:
        return FormattedText([])

    # Which required params have already been supplied?
    args_section = text[open_paren_idx + 1:]
    supplied = set()
    for pname in props:
        if f"{pname}=" in args_section or f"{pname} =" in args_section:
            supplied.add(pname)

    missing = [p for p in required if p not in supplied]
    if not missing:
        return FormattedText([("class:rprompt.done", " ✓ all required ")])

    # Build the hint: ``target: str, options: str``
    pieces = []
    for pname in missing:
        pdef = props.get(pname, {})
        ptype = pdef.get("type", "str") if isinstance(pdef, dict) else "str"
        pieces.append(f"{pname}: {ptype}")
    hint = "  ".join(pieces)
    if len(hint) > 60:
        hint = hint[:57] + "…"

    return FormattedText([
        ("class:rprompt.missing", "missing: "),
        ("class:rprompt.params", hint),
    ])


def _install_toolbar_and_keybindings(shell) -> None:
    """Wire the bottom toolbar, rprompt, and F1 globals overlay into ``shell.pt_app``.

    Called after ``init_prompt_toolkit_cli()`` has created ``pt_app`` (i.e.
    inside ``_embed()``, after the shell is constructed but before the
    interactive loop starts).
    """
    from prompt_toolkit.key_binding import KeyBindings

    pt_app = shell.pt_app
    if pt_app is None:
        return

    # ── Bottom toolbar ─────────────────────────────────────────────────
    if _IPYTHON_TOOLBAR_ENABLED:
        pt_app.bottom_toolbar = lambda: _bottom_toolbar(shell)

    # ── Right prompt (param hints) ─────────────────────────────────────
    if _IPYTHON_RPROMPT_ENABLED:
        pt_app.rprompt = lambda: _rprompt(shell)

    # ── Mouse support: click to position cursor ───────────────────────
    # IPython defaults to mouse_support=False (terminal handles mouse
    # natively → drag-to-select works but click doesn't move the cursor).
    # Setting True enables click-to-position, but captures mouse events so
    # native drag-to-select needs Shift+drag (standard in most terminals).
    if _IPYTHON_MOUSE_SUPPORT:
        pt_app.mouse_support = True

    # ── F1: dump all user globals above the prompt ─────────────────────
    kb = KeyBindings()

    @kb.add("f1")
    def _dump_globals(event):
        """Print all user variables — both cell-local (uncommitted) and globals."""
        # ── Cell-local (uncommitted) variables ─────────────────────────
        try:
            buf = shell.pt_app.app.current_buffer
            cell_text = buf.text
            cursor_row = buf.document.cursor_position_row
            cell_vars = _cell_local_vars(cell_text, cursor_row)
        except Exception:
            cell_vars = []

        if cell_vars:
            print(f"  ── {len(cell_vars)} in-cell variable(s) (uncommitted) ──")
            for name, preview in cell_vars:
                print(f"  {name:25s} := {preview}")
            print()

        # ── Committed globals ──────────────────────────────────────────
        globs = _user_globals(shell)
        if not globs and not cell_vars:
            print("  (no user variables yet)")
            return
        if globs:
            print(f"  ── {len(globs)} global variable(s) (committed) ──")
            for name, val in globs:
                try:
                    rv = repr(val)
                except Exception:
                    rv = "<?>"
                # Truncate long reprs but show enough to be useful
                if len(rv) > 80:
                    rv = rv[:77] + "…"
                # Show the type name for non-trivial values
                tn = type(val).__name__
                print(f"  {name:25s} {tn:6s} = {rv}")
        print()

    # ── Ctrl+X Ctrl+E: open current cell in editor (emacs-style) ──────
    # IPython's F2 binding (open_input_in_editor) is always on, but the
    # emacs-style Ctrl+X Ctrl-E shortcut is gated behind
    # extra_open_editor_shortcuts which must be set at shell-creation time.
    # We add our own binding that does the same thing — calls
    # Buffer.open_in_editor() which writes the cell to a temp .py file,
    # launches $VISUAL/$EDITOR, and pipes the result back.
    @kb.add("c-x", "c-e")
    def _open_in_editor(event):
        """Open current cell in external editor (emacs-style, same as F2)."""
        event.app.current_buffer.open_in_editor()

    # ── F3: full nvim escape hatch ─────────────────────────────────────
    # Unlike F2/Ctrl+X Ctrl+E (which edit the current cell and pipe the
    # result back), F3 launches a standalone nvim session in the workspace
    # root.  The user gets their full TUI IDE — LazyVim, neo-tree,
    # telescope, copilot, the lot.  :qa returns to IPython with all live
    # state (sessions, globals, tool wrappers) intact.  Uses
    # run_in_terminal(in_executor=True) so nvim gets full terminal control
    # while prompt_toolkit's UI is suspended.
    if _IPYTHON_NVIM_ESCAPE:
        @kb.add("f3")
        async def _open_nvim_escape(event):
            """Launch a full nvim session in the workspace root."""
            import subprocess
            from prompt_toolkit.application.run_in_terminal import run_in_terminal
            await run_in_terminal(
                lambda: subprocess.call(
                    shlex.split(_IPYTHON_EDITOR) + [str(Path(__file__).resolve().parent)]
                ),
                in_executor=True,
            )

    # Merge our keybindings with IPython's existing set.
    # ``merge_key_bindings`` produces a ``_MergedKeyBindings`` that checks
    # both registries — the original bindings (Ctrl+L, Ctrl+R, Tab, etc.)
    # stay live, and F1/F3/Ctrl+X Ctrl+E are added alongside them.
    from prompt_toolkit.key_binding import merge_key_bindings as _merge_kb
    existing_kb = pt_app.key_bindings
    if existing_kb is not None:
        pt_app.key_bindings = _merge_kb([existing_kb, kb])
    else:
        pt_app.key_bindings = kb


def _ipython_toolbar_styles() -> Dict[str, str]:
    """Return Pygments style overrides for the toolbar/rprompt classes.

    Merged into ``shell.highlighting_style_overrides`` so the toolbar's
    ``class:toolbar.*`` and ``class:rprompt.*`` tokens get colours.
    """
    return {
        # Toolbar — dark background, muted text
        "toolbar.cursor": "bg:#333333 fg:#66aaff",
        "toolbar.cell": "bg:#333333 fg:#aa88cc",
        "toolbar.cellvars": "bg:#333333 fg:#ddaa44",
        "toolbar.cellpreview": "bg:#333333 fg:#aa7733",
        "toolbar.vars": "bg:#333333 fg:#66cc66",
        "toolbar.preview": "bg:#333333 fg:#888888",
        "toolbar.scope": "bg:#553333 fg:#ff6666 bold",
        "toolbar.brain": "bg:#333333 fg:#66cc66",
        "toolbar.brain.down": "bg:#333333 fg:#cc6666",
        # Right prompt — dim, right-aligned
        "rprompt.missing": "fg:#cc9933",
        "rprompt.params": "fg:#66aaff",
        "rprompt.done": "fg:#66cc66",
    }


