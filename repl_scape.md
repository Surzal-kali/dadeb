# REPL surface — the replkit package IDE layer reference

The REPL lives in the `replkit/` package (`tool_repl.py` is now a thin shim —
the *filename* stays load-bearing: kernelspecs, docker init scripts, the
systemd unit, and `utils/engagement.py`'s lane inference all match it by
name). Module map: `replkit/__init__.py`. Companion to ipythontips.md and the
playbook.

When to reach for this: any model/user suggestion about REPL keybinds, ghost-text
completion, toolbar/prompt contents, editor escapes, or completion tuning knobs.

## Keybinds

Keybinding registry is merged over IPython's defaults (Ctrl+L, Ctrl+R, Tab, etc. all stay live).

- **Tab** — framework completions. Tier 1: tool aliases after `run_tool(`-style calls; Tier 2:
  tool_id strings after a tool-accepting command. Ghost text (gray inline suggestion) appears
  for single prefix-matches. `tool?` → manifest + params, `tool??` → source.
- **F1** — dump variables. Prints in-cell (uncommitted, parsed from the cell text at cursor)
  and committed globals with name/type/truncated repr. For a model suggesting a next step,
  this is its memory probe: what's live, what's named.
- **F2** — open current cell in $EDITOR (nvim). Save+quit pipes the cell back into IPython.
- **Ctrl+X Ctrl+E** — same as F2, emacs-style chord.
- **F3** — full nvim escape hatch: launches nvim in workspace root (LazyVim, neo-tree, the
  lot). `:qa` returns; all IPython state (sessions, globals, tool wrappers) intact. Distinct
  from F2: F2 = edit one cell, F3 = standalone IDE session.

  (History ghost text — gray inline suggestion from past commands, IPython's own
  `NavigableAutoSuggestFromHistory` — stays live. The on-demand Ollama FIM completion
  lane was removed 2026-10-19: unused by the operator and its suggester machinery was
  scaffolding debt. No `OLLAMA_COMPLETION_*` knob means anything anymore.)

## Bottom toolbar

Left→right: cursor L:C; cell-local vars parsed from the current cell text (max 6 shown,
20-char reprs — `IPYTHON_TOOLBAR_MAX_VARS`/`_REPR_LEN`); globals count; `[SCOPE ARMED]`
when scope gate is armed; `brain:✓` / `brain:✗` when a brain check applies. Newlines:
`IPYTHON_TOOLBAR_NEWLINES=expand|collapse|off` (default expand).

## Right prompt

Inside a known tool call `alias(`, renders the still-missing **required** params (from the
tool manifest), color-coded: missing = amber, partially-supplied = blue, all-supplied = green.
This is the model's freebie guard against sending incomplete calls.

## Mouse

`IPYTHON_MOUSE` (default 1): click-to-position enabled; drag-to-select requires Shift+drag
(prompt_toolkit captures mouse events). Set 0 to restore native select-only behavior.

## Editor config

`IPYTHON_EDITOR` (default nvim) drives both F2/Ctrl+X Ctrl+E and F3. `IPYTHON_NVIM_ESCAPE`
(default 1) enables/disables the F3 standalone session.

## Onboarding command

Type `ipython` inside the REPL to print the full tour: tool-count, example calls, operator
functions (scope_on/off/status, scope_search, sessions), UI upgrades currently enabled, and
editor escapes. Good first move in a fresh session; also prints which features the .env has
disabled.
