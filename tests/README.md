# Selftest suite (the `selftest` REPL macro's engine)

The REPL's `selftest` command runs `python -m pytest tests/ -q` from the
tree root (see `replkit/commands.py` → `replkit.core.run_selftest`), so
whatever lands here is what operators and tool authors can macro — on a dev
checkout AND on a deb install, since `tests/` ships with the tree.

## Adding tests for your tool

The framework invites new tool scripts into the allowed roots
(`auxiliaries/`, `payloads/`, `listeners/`, `utils/`, `encoders/`,
`evasion/`). Your tests belong here, named `test_<your_tool>.py`. Two
working patterns to copy:

1. **Argparse CLI module** (`LOCAL_FILE`, static mint) — see
   `test_tool_addition_lane.py::test_argparse_module_mints_local_file_tool_and_runs`:
   assert the manifest gets minted from your docstring + `add_argument`
   flags, then run it for real through `daharness.executor.execute_tool`.

2. **`@framework_tool` function/method** (`BRAIN_DISPATCH`, dynamic mint) —
   see the same file's author-demo tests. Modules whose module-level
   argparse is internal plumbing set `_NO_LOCAL_TOOL = True`; the decorated
   members still mint. Execution runs through the executor with no Brain
   socket needed (in-process fallback).

Existing regression areas (write more; keep them hermetic — no network,
no live targets, no long sleeps):

- `test_brain_socket_lane.py` — socket-dir → bind-permission lane decision
  (`listeners.thebrain.socket_lane_perms`) plus a real bind/cleanup cycle
  with the startup scan stubbed.
- `test_framework_health.py` — findings-db probe truth-telling (exception
  text surfacing, lane-block reporting) against a throwaway `$WORKSPACE_ROOT`.
- `test_tool_addition_lane.py` — the author contract above.

House rules, inherited from `pyproject.toml`:

- `pythonpath = ["."]` — framework imports resolve from the repo root
  regardless of where pytest is invoked from.
- `testpaths`/`python_files` are pinned: `tests/`, `test_*.py`.
- cache_dir lives under gitignored `run/`.
- No unregistered marks (`--strict-markers`).

Run it the way the macro does:

    python -m pytest tests/ -q

…or single-file via the macro from the REPL: `selftest test_brain_socket_lane.py`.