# Selftest suite (the `selftest` REPL macro's engine)

The REPL's `selftest` command runs `python -m pytest tests/ -q` from the
tree root (see `replkit/commands.py` → `replkit.core.run_selftest`). The
macro carries an honest preamble (what selftest IS) and a postamble (what
the exit code means) so a green run doesn't misread as a live-capability
verdict.

**What selftest validates:** the framework's code paths work against
hermetic stubs — network calls, subprocess launches, and socket probes are
all monkeypatched in the test fixtures. A green run means the registry,
executor, scope gate, doctor, brain socket logic, etc. are correct in
isolation. It does NOT mean nmap/ssh/msf would work on a live target.

**For live tool capability:** run `framework_doctor` (or `daharness
doctor` on the deb) — that's the capability probe that checks real binaries,
sockets, and privileges on the current lane.

## Adding tests for your tool

The framework invites new tool scripts into the allowed roots
(`auxiliaries/`, `payloads/`, `listeners/`, `utils/`, `evasion/`). Your
tests belong here, named `test_<your_tool>.py`. Two working patterns to copy:

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
- cache_dir lives under gitignored `run/`; on a read-only install tree the
  selftest macro redirects it to a per-euid tmpdir instead of disabling
  cacheprovider (disabling it orphans the ini key and `--strict-config`
  errors the whole run — pytest 9 collects nothing).
- No unregistered marks (`--strict-markers`).
- Lanes with inputs a hermetic test cannot ship skip honestly, with a
  lane-specific reason: packaging-source asserts that read `debian/` +
  `packaging/systemd/` (the deb ships the built artifact, not the
  packaging sources — `test_daharness_pg.py` instead falls back to the
  instead fall back to the rules-installed twins so those contracts stay
  REAL on the deb), and `test_tool_addition_lane.py` when `payloads/` is
  unwritable (the deb's root-owned tool tree — its author contract
  mutates the real tree).

Run it the way the macro does:

    python -m pytest tests/ -q

…or single-file via the macro from the REPL: `selftest test_brain_socket_lane.py`.