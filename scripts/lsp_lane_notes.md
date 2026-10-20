# Framework editor-lane notes (VS Code + JupyterLab LSP)

## How the three lanes see the tool stubs

The REPL (`tool_repl.py`) injects tool aliases at runtime into `IPython.user_ns`.
No static analysis can see them, so `scripts/gen_repl_stubs.py` regenerates
`framework_tools.pyi` (one async def per alias, manifest-backed) + a PEP 562
shim `framework_tools.py` into `FRAMEWORK_STUBS_DIR` (default
`~/.local/share/framework-stubs`). Lanes that consume it:

| Lane | Engine | Stub wiring |
|---|---|---|
| VS Code | Pylance | `.vscode/settings.json` → `python.analysis.stubPath` + `extraPaths` |
| nvim (F2 cells) | pyright | `~/.config/nvim/lua/plugins/python.lua` → `extraPaths` (see nvim-scratch-buffer.md) |
| JupyterLab (container) | pyright bundled in pip wheel | baked stubs + `pyrightconfig.json` at `/home/jovyan/work` |

## JupyterLab lane (dockered/)

- `jupyter.Dockerfile` generates stubs at build into
  `/opt/conda/share/framework-stubs` (same generator as host lanes; zero drift).
- `dockered/jupyter-lsp-pyright.json` → config.d registering a custom
  jupyter-lsp spec: `sh -c exec node <pip wheel>/pyright/dist/langserver.index.js --stdio`
  (the pip pyright wheel bundles the full npm pyright; node runs it directly).
  Same file drops pylsp via an `argv: []` entry — jupyter-lsp filters
  empty-argv specs in `_collect_language_servers` (bare `[]` as the server
  value crashes this build instead; see postmortem below).
- pyrightconfig for the lane lives in `jupyter.Dockerfile`'s
  `/opt/conda/share/jupyter/pyrightconfig.d/` heredoc; the before-notebook.d
  hook (`10-refresh-stubs.sh`) copies it into `/home/jovyan/work/` at boot
  (the notebooks dir is a host bind-mount, image-baked content there is
  shadowed). This is the authoritative settings channel: pyright restarts its
  analysis service on `didChangeConfiguration` and only honors a subset there,
  but a config file at the workspace root is honored on every service restart.
  The file suppresses the same rules `.vscode/settings.json` does
  (reportUndefinedVariable / reportMissingImports / reportMissingModuleSource /
  reportAttributeAccessIssue `none`) — the kernel injects names statically
  invisible to any engine.
- Same-name `.py`/`.pyi`: pyright resolves types from the `.pyi`; the `.py`
  shim exists for runtime star-imports.

## Config: why pyrightconfig.json, not didChangeConfiguration

pyright reads settings from `pyrightconfig.json` at the workspace root and
honors them on every analysis-service restart — verified live that `stubPath`
there resolves every tool alias cleanly. The jupyterlab-lsp settings-delivery
path (`workspace/didChangeConfiguration`) is unreliable: pyright restarts its
analysis service mid-session and honors only a subset of settings there, so
the config file is the authoritative channel.

Verification method (probes were removed after use; recreate if needed):
drive `LanguageServerManager` from `jupyter-lsp` with the config.d spec list,
attach an async listener via `all_listeners=[...]`, `session.initialize()`,
`session.write()` an initialize/initialized/didOpen chain, collect
`publishDiagnostics` off the listener. Or CLI-check a scratch doc with
`node /opt/conda/lib/python3.13/site-packages/pyright/dist/index.js
--outputjson <doc>` — the wheel's bundled CLI resolves identical config.

## Ruff notebook lane (dabooks)

`dabooks/ruff.toml` (repo) lints `**/*.ipynb` cell-aware: per-file ignores
(`E402 E501 F401 F841 F821` — F821 because cells lint in isolation, so
later-cell variables are false positives) + a generated `builtins` block
listing every kernel-injected name (tool aliases, stdlib overlay, envelope
helpers, operator wrappers, `display`/`get_ipython`). The block is maintained
by `scripts/gen_repl_stubs.py` between BEGIN/END marks and sourced from
`build_ipython_namespace()` verbatim — `--check` flags drift. Run via the
repo venv (`venv/bin/ruff`; not on system PATH). Editor side: the
**builtins.pyi fork** (generated into the stub dir by `gen_repl_stubs.py`) —
pyright/Pylance resolves a stubPath-found `builtins.pyi` as a REPLACEMENT for
its builtins module, so the fork = Pylance's complete typeshed
`builtins.pyi` + appended permissive decls for every kernel-injected name.
Bare injected names (`nmap`, `pluck`, …) resolve without diagnostics;
typos stay flagged. Generator picks the fork source: newest
`~/.vscode-server/extensions/ms-python.vscode-pylance-*/dist/typeshed-
fallback/stdlib/builtins.pyi`, falling back to the venv wheel's bundled
copy; `--check` detects drift including Pylance-extension upgrades. The
editor blanket kill was REMOVED from `.vscode/settings.json` (2026-10-15).

## Sourced-hook lesson (restart-loop postmortem)

docker-stacks `run-hooks.sh` SOURCES hooks (`source "${hook_file}"`) — a hook
ending in `exit` doesn't exit the hook, it exits `start.sh` itself. The first
draft of `dockered/10-refresh-stubs.sh` ended with `exit 0`, producing a
clean-shutdown restart wheel: container died `exitCode=0` ~hook-duration after
every boot, `RestartCount` climbed to 38, the notebook server never exec'd.
Hooks here must `return` (tail line tolerates direct execution), and any `cd`
must be inside a subshell — start.sh execs the server with the inherited cwd.
Diagnosis tell: `docker events` showed `container die … execDuration=12,
exitCode=0` on a loop. Hook logs live in `/tmp/refresh-stubs.log`.