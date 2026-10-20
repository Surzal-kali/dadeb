# nvim REPL lane — scratch-cell, stub, and completion config

Source: nvim config repo (LazyVim, blink.cmp) @ 807db1b, Oct 10 2026. Companion to
nvim-scratch-buffer.md (framework repo). When to reach for this: F2/nvim-side questions —
why completions, hover, or signature help work or fail in scratch cells; header stamping;
completion-provider wiring; editor-key collisions.

## Scratch-cell header lane (scratch-cells.lua)

The F2 cell header is load-bearing: `# vim: ft=python` + `from framework_tools import *`.
Tool aliases exist only in the REPL's user_ns — pyright sees them solely via the star-import
from generated stubs (~/.local/share/framework-stubs). Missing header = every alias reads
undefined in the editor while the REPL would execute it fine: the failure that actually bites.

- Empty F2 temp files (/tmp/tmp*, /tmp/prompt-toolkit-*) autostamp on open
  (BufReadPost/BufNewFile; mkstemp creates the file before nvim opens it).
- Non-empty cell-shaped files missing the header: notify hint only ("cell has no framework
  header — <leader>fc to stamp it") — typed cells are never mutated silently.
- `<leader>fc` / `:FrameworkCell` stamps the header unconditionally, idempotent (skips if
  "framework_tools" appears in the first 5 lines; modeline-only files without the import line
  will be re-stamped — keep both header lines).
- Opt-outs: `vim.g.fwcell_no_autostamp` (empty-file stamp only), `vim.g.fwcell_disable` (all).

## Pyright stub lane (python.lua)

- extraPaths → framework-stubs dir gives F2 cells real completion, hover (K), and
  signature-on-"(" for the ~190 runtime-generated tool aliases. Stubs land via the framework
  repo's scripts/gen_repl_stubs.py (see its docstring; nvim-scratch-buffer.md documents the lane).
- Dual-HOME trap: this config runs as kali AND as root (via the /root/.config/nvim symlink);
  expand("~") follows the caller's HOME. The spec resolves candidates by fs_stat existence —
  kali's dir is source of truth; root without a /root-side symlink would otherwise carry a
  void extraPaths → every alias undefined with no error pointing at HOME.
- ruff is killed two layers on purpose — belt: servers.ruff/ruff_lsp enabled=false;
  suspenders: setup.ruff/ruff_lsp return true so lspconfig setup skips entirely (LazyVim's
  python extra function-opts can't resurrect it). Reason: duplicate diagnostics + a flood of
  top-level-await noise in IPython-style scratch cells.
- diagnosticMode = openFilesOnly — diagnostics scoped to the open buffer, not whole-repo
  background analysis.

## Signature help (blink.lua)

blink.cmp `signature = { enabled = true }` — LazyVim ships this commented out. Without it,
typing `ssh_connect(` shows NO parameter window even though pyright serves signatureHelp.
With it: window pops after `(`/`,` and re-shows on insert-mode entry.

## Completion provider (minuet.lua + copilot.lua)

- Sole inline completion provider = minuet-ai via openai_fim_compatible → Ollama at
  http://192.168.56.1:11434/v1/completions (VBox host-only gateway → native Windows Ollama).
- Model: OLLAMA_MODEL env override, fallback codestral:22b. Codestral is the preferred
  native-FIM candidate for hand-rolled exploit work; keep qwen2.5-coder:32b as the fallback
  comparison model until the local manifest and prompt tests confirm the switch.
- blink sources: lsp/path/snippets/buffer + minuet (async, timeout_ms 3000, score_offset 50);
  copilot removed from blink sources AND blink-copilot plugin disabled; copilot.lua keeps
  copilot solely as the CopilotChat.nvim chat backend (suggestion/panel disabled).
- Request knobs: context_window 512, max_tokens 96, top_p 0.9, debounce 600, request_timeout 3.
- `<A-y>` = minuet make_blink_map — manually trigger/accept an AI completion.
- Co-residency: the 22b FIM model and the operator model time-share VRAM; while the operator
  model is resident, minuet requests queue behind it (see repl_surface.md FIM section).
  blink's LOCAL sources (lsp/stubs/path/snippets/buffer) never touch VRAM — always instant.

## Navigation (autocmds.lua)

`SecurityDashboard` command (also F2 and <leader>ss inside nvim): opens a botright 15-line
terminal split, or jumps into an existing terminal window if one is open.
COLLISION NOTE: F2 in the REPL = open current cell in $EDITOR; F2 in nvim = security
dashboard. Same key, different applications — know which app has focus before pressing.
