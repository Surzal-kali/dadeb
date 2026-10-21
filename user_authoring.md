# User Authoring Lanes — `.dacustoms` + notebook macro dropbox (design note)

**Status: DESIGN ONLY — nothing here is wired.** Both lanes are parked behind
the open code review (discovery-roots / engagement cobweb / postinst).
Implementation begins when review unfreezes, verdict be damned; this doc is
the spec it follows. Written 2026-10-21.

---

## Lane A — `.dacustoms`: user Python modules, out of the tree

### Why (the real selling point)

The pitch was "version-controlled add-ons in `$HOME`"; the stronger property
is **update-day safety**. What happens today when Joe adds a module to the
workspace and upstream ships an overlapping integration later:

| Update-day collision | What actually happens today |
|---|---|
| Same filename upstream later (`auxiliaries/nmap_extra.py`) | `git pull` refuses (untracked file in the way), or conflict hell in a fork; on the deb lane `.py` files under `/usr/share/daharness` are **not conffiles** — dpkg replaces them silently, Joe's edits evaporate with no prompt |
| Same tool_id after an upstream rename/reorg | tool_ids are dotted file paths (`auxiliaries.nmap.run_nmap`), so a reorg relocates the id; Joe's stale Chroma entry lingers as a ghost that `find_tools` still serves, then fails at import on dispatch (`bootstrap_registry` only upserts — eviction happens only with `--clear`) |
| Joe leans on internals (`from daharness.registry import ...`) | Shipped helper changes shape → his module stops importing. The dynamic pass is crash-isolated per module (`except Exception` → log → skip, both in `daharness/registry.py` PASS 2 and the Brain's `scan_tools`), so this is a log line, not an outage. **But `SystemExit` is not `Exception`:** a naive module calling `argparse.parse_args()` at module level punches through both guards → Brain `_startup_scan()` dies mid-list → socket never binds → every lane silently falls back in-process |
| Joe monkeypatches at module level (`sys.path.insert`, patching `framework_tool`) | The Brain's startup scan **runs module-level code** for everything it scans. Shipped modules follow the no-side-effects rule by review; Joe, by definition, won't know it |

An out-of-tree package namespace kills every column: dpkg and git never see
`~/.dacustoms`, `dacustoms.*` ids can never collide with relocated upstream
ids, and nothing in `$HOME` can block a pull. Lead with that sentence, not
the purge one (note: apt purge *already keeps* `/var/lib/daharness` — our own
postinst says so — so `$HOME` never had a purge-survival edge; its edge is
ergonomics + collision-proofing).

### Facts already on the ground

- `ALLOWED_TOOL_ROOTS` (`daharness/registry.py`, built off
  `resolve_framework_root()`) is the single discovery list for BOTH passes
  (static argparse mint + dynamic `@framework_tool` import). One append wires
  both.
- `BRAIN_SCAN_DIRS` (`listeners/thebrain.py`) already accepts **absolute
  paths** — non-absolute entries resolve against `_FRAMEWORK_ROOT`, absolute
  ones pass through. The dynamic-import side needs ~no new code today.
- `utils/`-style modules excluded from the Brain's default scan still register
  through in-process fallback — state on disk (`cookie_jar` pattern) makes
  that harmless.
- `manifests['implementation_path']` resolution assumes paths under
  `FRAMEWORK_ROOT` (`FRAMEWORK_ROOT / candidate` in the path resolver,
  ~`daharness/registry.py:171`); LOCAL_FILE dispatch of an out-of-tree
  relative path breaks without a guard.
- `discover_local_tools` calls `path.relative_to(FRAMEWORK_ROOT)`
  (~line 447) **unguarded** — any out-of-tree file raises `ValueError` and
  takes the ENTIRE discovery pass with it, not just the folder. This single
  call is the difference between "Joe's folder doesn't index" and
  "nothing indexes".
- Kernel/REPL lanes import via the framework root; `sitecustomize.py` /
  kernelspec bootstraps are the right hook for making `$HOME/.dacustoms`
  importable there too.

### Decisions

- **D1 — it's a package, not a bare dir.** Require (and scaffold, via a
  `dacustoms init` stub or shipped example) `~/.dacustoms/__init__.py`. Never
  put `.dacustoms` itself on `sys.path` for stem-name imports: a bare-stem
  dir means one file named `requests.py` shadows stdlib for the whole Brain
  process, invisibly, with user-controlled filenames. Synthetic module names
  via `importlib.util.spec_from_file_location("dacustoms.<rel>", path)`
  keep the existing `__module__ == module_name` guard effective.
- **D2 — knob, not constant:** `DACUSTOMS_DIR` (default `~/.dacustoms`),
  read per call per the constants convention. Empty value disables the lane.
- **D3 — Brain gets nothing from `$HOME`.** The deb Brain runs as the
  `daharness` system user; scanning a home/group dir means the service user
  imports operator code at boot. dacustoms tools route Brain→miss→in-process
  fallback in the caller's process (documented, jar-style). Session sharing
  loss is real and known — document it, don't fix it here.
- **D4 — quarantine is visible:** a `dacustoms` provider folded into
  `framework_doctor` (REA-shaped `{available, reason, remediation}`,
  same as r2/jadx/masscan/msf) listing failed/skipped user modules with the
  import error. Joe gets told; we get a bug report that isn't "nothing
  indexes anymore".
- **D5 — `_NO_LOCAL_TOOL` opt-out applies** to user scripts whose argparse is
  internal plumbing; say so in the scaffold template.
- **D6 — scope gate is not weakened:** module-level code runs at import; the
  gate still fires per traffic-sending call. Document that this lane is
  operator-authored code (same trust level as the operator's own shell).

---

## Lane B — `notebooks/`: a papermillable macro dropbox

### Concept

A drop lane like all the others (`dropbox/` payloads, `apk/`, `binaries/`),
but for **operator-authored `.ipynb` macros**. The model gets a papermill
tool; the operator gets an expansive macro surface: a multi-step tool chain
as a parameterized notebook with narrative cells, re-runnable with fresh
parameters instead of re-typed execute_code blocks.

### Facts already on the ground

- `papermill==2.7.0` is **pinned** in `requirements.txt` and **imported
  nowhere** — greenfield wire-up, not a dependency fight.
- It is **not** in `debian/control` Depends — the lane must degrade honestly
  on the deb lane (doctor probe + remediation), exactly like the Postgres
  lane (`pip install -e ".[db]"` precedent). nbformat rides the papermill
  closure, so it may be used for introspection.
- `pyproject.toml` already ships a `[jupyter]` extra (ipython/ipykernel/
  jupyter_client) — papermill belongs there (notebook lane), not a new extra.
- Dropbox conventions: content gitignored, README tracked, env override knob
  (`MSFVENOM_DROPBOX` precedent → `NOTEBOOK_DROPBOX`).
- Drop-lane postinst pattern exists: the `for _LANE in binaries apk` loop in
  `debian/daharness.postinst` mkdirs state-root lanes 2770 and echoes a
  readiness line. One list entry wires this lane.
- The daharness kernelspec (same one OpenWebUI's execute_code lane uses) is
  what gives a kernel the framework namespace: bare tool names, async
  wrappers, envelope helpers, autoawait. **A papermill-spawned kernel with
  that same kernelspec gets the whole tool namespace** — `await nmap(...)` in
  a macro cell works exactly like execute_code. This is the key wiring
  insight: macros reuse the notebook kernel lane; no new bridge needed.
- Kernel lane is unbounded by the per-turn tool budget (execute_code
  precedent) — deliberate here too: a macro's point is an unbounded chain.
- The scope gate fires per traffic-sending call inside any kernel lane.
  Raw `subprocess`/`socket` calls inside a macro bypass it — same as
  execute_code; a notebook is the operator's hands.

### Decisions

- **D7 — location:** default `<state-root>/notebooks/` (resolved via the
  WORKSPACE_ROOT convention, NOT the read-only package tree — operator
  content lives beside `scope/`, `binaries/`, `apk/`); override
  `NOTEBOOK_DROPBOX`; keep README tracked, everything else gitignored;
  postinst loop gains `notebooks` (mkdir-if-missing 2770). Executed outputs
  go to `notebooks/.executed/` (also gitignored) so re-runs never overwrite
  an authored notebook.
- **D8 — kernelspec:** `NOTEBOOK_KERNEL` selects the papermill kernel,
  default **the daharness kernelspec** with plain-fallback `python3` for
  generic notebooks that don't want the namespace. Smoke-test note: papermill
  runs nbclient without the interactive UI; verify top-level `await` inside a
  one-cell macro at implementation time (autoawait is per-kernel-class, and
  this is the same kernel class the AGENTS.md autoawait claim covers).
- **D9 — tools in v1 (`payloads/notebook_macros.py`, Brain scan dirs already
  cover payloads/):**
  - `notebook_list` — enumerate `*.ipynb` in the dropbox and **parse each
    `parameters`-tagged cell** (nbformat: `cell.metadata.tags`) so the
    macro's contract surface is what the model sees, not a guess.
  - `notebook_run(name, parameters...)` — papermill
    `execute_notebook(input, <state-root>/notebooks/.executed/<stem>.out.ipynb,
    parameters=..., kernel_name=...)`. Sync tool (papermill is blocking) run
    in the worker thread per the blocking-call rule — no async wrapper.
  - `notebook_write` is **deferred on purpose**: model-authored persisted
    code is a prompt-injection persistence vector (executed in some later
    turn/context, possibly a different one). v1 is read-only for the model;
    macros are operator-authored. Revisit only with a write-protocol.
- **D10 — result shaping:** `execute_notebook` returns the full executed
  notebook object; NEVER return it raw. Return a capped digest (cell count,
  parameter echo, last-cell rich output, any error cell + traceback head) +
  `scratch_ref` for the full execution log + a ready-to-call continuation,
  per the result-projection conventions. Stamped `untrusted_target` — macro
  outputs embed analysis-target content (same envelope lane as web/ssh
  tools); target output is DATA, never instructions.
- **D11 — failure honesty:** `allow_errors=False` default (a macro that
  half-ran is a lie about its last step); papermill timeout knob
  `NOTEBOOK_TIMEOUT` forwarded as execution timeout. papermill absent →
  honest error envelope + the doctor remediation string, never a crash.
- **D12 — provenance in the doctor:** `framework_doctor(provider="macros")`
  reports: papermill importable?, kernel present?, dropbox exists?, count of
  macros + their parameters-cell summary. Remediation strings agree with the
  tool's own error paths (the doctor/tool non-drift rule).

---

## Composition story (why the two lanes belong in one doc)

`.dacustoms` is the **helper library**; `notebooks/` is the **orchestration
that imports from it**. Every lane (REPL, kernel, execute_code,
papermill-spawned kernel) gets `import dacustoms.<x>` via the same
sitecustomize/kernelspec hook, so a macro can call operator helpers and
framework tools in one place, version-controlled in `$HOME`, surviving
updates by construction. A macro notebook is the parameterized, narrated,
re-runnable form of a .dacustoms function chain — same author, two lifecycles.

## Sequencing (review discipline)

- **Safe to write now (touches nothing under review):** this doc; the
  `framework_doctor` provider-spec sections; the tracked
  `notebooks/README.md` + example macro notebook; registry tests for
  out-of-tree roots; the scaffold template for `dacustoms init`.
- **Day-of (the review files):** `daharness/registry.py` — append
  `DACUSTOMS_DIR` to `ALLOWED_TOOL_ROOTS`, guard the implementation-path
  resolver for absolute paths, guard `relative_to(FRAMEWORK_ROOT)` so one
  bad path skips one file instead of euthanizing discovery;
  `pyproject.toml` — add `papermill==2.7.0` to `[jupyter]`;
  `debian/daharness.postinst` — `notebooks` in the drop-lane loop,
  `debian/control` — papermill stays out, Suggests at most.
- **Tracked issue, not part of this feature:** ghost manifest eviction —
  reindex without `--clear` leaves stale tool_ids after upstream renames.
  Already bites today's users.

---

## Portability lanes (WSL / Pi test notes + NetHunter future) — 2026-10-21

Double-check of the install script against non-standard hosts (WSL, Pi /
aarch64, NetHunter chroot), plus the NetHunter display answer from the app's
own source. Facts verified in `debian/rules` + `debian/daharness.postinst`
and the `kali-nethunter-app` repo; the NetHunter integration itself stays a
future lane.

### Install-portability facts (verified)

- **Systemd is optional at install time**: every systemd touch in postinst
  (chroma retirement, daemon-reload) is guarded by
  ``if [ -d /run/systemd/system ] && command -v systemctl`` — no-ops on a
  systemd-less box; `deb-systemd-helper` (dh_installsystemd) manipulates
  enablement state without requiring PID 1; units are enabled-**not**-started
  so nothing can hang the install.
- **The state root is systemd-independent**: postinst creates
  `/var/lib/daharness` bare (mkdir + chown 2770 + scope seeding) —
  RuntimeDirectory/StateDirectory only re-assert what postinst already made.
- **`.pyc` are arch-neutral**: the `compileall` steps produce version-magic
  bytecode, safe to build on x86 and run on aarch64.
- **Trap 1 — everything compiled is a BUILD-arch artifact:**
  `rules` runs ``pip install --target vendor chromadb==1.5.9`` on the BUILD
  host; chromadb 1.x is a pyo3/Rust closure, so the `.so` files carried in
  the deb are the build machine's arch (plus pydantic-core, numpy, et al).
  Same for `frameit.so`: `override_dh_auto_build` gcc-compiles it at BUILD
  time and ships the binary — nothing compiles at install time. (Only the
  two C objects are repo-built — `frameit` shipped, `raw_scan` NOT in the
  packaging at all: manually compiled per listeners/README, so on the deb
  lane raw_scan degrades honestly via its failing CDLL.) A deb built on x86
  installs on a Pi and the Brain dies on the top-level chromadb import.
  ⇒ **Pi test = run `dpkg-buildpackage` ON the Pi** (or a per-arch vendor
  lane later) — one build resolves frameit's gcc target, the wheel closure's
  arch, and the (arch-neutral) compileall bytecode together. WSL2
  (``systemd=true``) should give the full service lane; WSL1 /
  systemd-off gets the bare-tree manual-lane posture.
- **Trap 2 — `/run/daharness` on non-systemd lanes**: on the package tree
  `brain_socket_path()` resolves `/run/daharness/brain.sock` unconditionally;
  a normal install relies on systemd's RuntimeDirectory to make it. On an
  init.d / systemd-less lane nobody creates it — the service entry point must
  `mkdir /run/daharness` before bind, or the Brain silently has no socket.

### NetHunter future lane (display mechanics verified from source)

The NetHunter app has **no package-discovery protocol** — its tabs are
hardcoded fragments (`AppNavHomeActivity`). The three real surfaces:

- **Custom Commands tab** = app-private **SQLite** (`CustomCommandsSQL` /
  `CustomCommandsData`: label, command, send-to, exec mode, run-on-boot),
  user-authored via the app UI, backup/restore as a DB file on the sdcard.
  A chroot package **cannot inject entries** — only the app's own restore
  flow writes that DB.
- **Kali Services tab** = the init.d route: the app ships
  `assets/etc.init.d` startup scripts into the chroot (and carries a
  chroot-side systemd workaround as of 2026-10). **This is the blessed
  display surface** — a system package's services appear as start/stop
  toggles.
- **NetHunter Store** = Android APKs; unrelated to chroot packaging.

Future daharness-on-NetHunter shape (an install-env check helper forks the
unpacked unit lane):

- Check: ``[ -d /run/systemd/system ] && command -v systemctl`` → existing
  deb lane untouched; else → same tree + state root, **init.d scripts
  instead of units** for `daharness` / `daharness-kernel`, and
  `mkdir /run/daharness` at boot (no RuntimeDirectory on this lane),
  `PYTHONDONTWRITEBYTECODE` irrelevant here (tree is root-owned; .pyc stay
  tracked).
- Expect: the two services surface in **Kali Services**; the REPL/gateway
  entry points get a documented "add these custom commands by hand" (the
  Custom-Commands DB is user-owned); no Store APK lane.

---

---

## Walkthrough refinements (2026-10-21, decisions stress-tested)

Amendments from the per-decision review — implementation follows THESE,
where they supersede the first-draft wording above.

- **D1 mechanism (supersedes "spec_from_file_location"):** implementation is
  a **meta-path finder** registered by `sitecustomize`, mapping the
  `dacustoms.*` prefix — and ONLY that prefix — to files under
  `DACUSTOMS_DIR`. Never put `$HOME` (or the customs dir itself) on
  `sys.path`: that makes every bare `.py` in `$HOME` importable, which
  imports D1's shadowing failure back through the back door. Discovery
  imports through the same finder (one canonical path per file), NOT
  spec-from-file-location alongside normal imports — two lanes to the same
  file means two module objects (duplicated module state, diverging class
  instances) and the `__module__ == module_name` guard only stays correct
  when `__module__` genuinely is `dacustoms.<rel>`.
- **PASS 2 hardening (joins the day-of registry touches):** the dynamic-pass
  guard becomes `except (Exception, SystemExit)` (log → skip → continue) in
  `daharness/registry.py` PASS 2 and the Brain's `scan_tools`. argparse
  exits 2 on bad args; naive scripts call `parse_args()` at module level.
  Catch deliberately, log loudly.
- **D4 probe is tiered:** (1) `compile()` the source — syntax errors caught
  with ZERO execution; (2) static shape checks (`__init__.py` present,
  parameters cell present, file mode); (3) full import only where it already
  happens (discovery) or as an explicit remediation step. A health probe
  must never execute a module that opens sockets.
- **D5 scaffold rules are load-bearing:** the example module embodies
  (a) `if __name__ == "__main__":` wrapping for any argparse, (b) a
  `_NO_LOCAL_TOOL` example for internal-plumbing scripts, (c) stateless
  module level (no side effects at import). LOCAL_FILE minting of user CLI
  scripts is a feature — subprocess execution quarantines their crashes
  already.
- **Pass-ladder facts (verified in tree, 2026-10-21):** the execution-free
  tier ALREADY EXISTS — `extract_module_profile` parses with `ast` only,
  never imports, and a failed parse yields an empty profile + a DEBUG log
  instead of killing the scan (its docstring says exactly this). Parse
  catches the same error class as compile-to-bytecode, so the effective
  ladder is TWO tiers: parse/compile (no execution) and import (execution,
  guarded by the PASS 2 / SystemExit change above). "Step further" is
  therefore LOUDNESS, not mechanism: log syntax failures at INFO with file +
  `lineno/offset` from the SyntaxError, and surface them as doctor tier-1
  remediation strings (`dacustoms/x.py:14 — invalid syntax`).
  Probes stay in-memory (`ast.parse`/`compile()`) — never `py_compile` to
  disk, no pyc artifacts, no snapshot-cache memoization (ms-cheap).
- **D3 escape hatch + bytecode hygiene:** an operator-opt-in
  `BRAIN_DACUSTOMS=1` may add the absolute DACUSTOMS_DIR to the Brain scan
  (documented as "you are feeding operator code to a service identity at
  boot"). When set, the sidecar runs with `PYTHONDONTWRITEBYTECODE=1` so
  the service user never drops `__pycache__` into the operator's
  version-controlled home dir (wrong-UID artifacts in $HOME).
- **D6 boundary stated plainly:** module-level import code is operator
  consent (same trust as the operator's shell); the scope gate applies to
  `@framework_tool` calls that code makes later. Static analysis of
  imports for network calls is rejected as security theater.
- **D7 dev-tree note:** when `WORKSPACE_ROOT` is unset in dev, notebooks
  resolve into the git checkout — the gitignore rule is the only separation
  there, not decoration. Never write execution results into the authored
  path (`.executed/` always) — on the deb lane 2770 group-write means
  re-runs would clobber a colleague's macro.
- **D8 constraints pinned:** kernelspec must exist in the calling lane's
  kernel search path; the `python3` fallback must LOG loudly ("namespace
  not loaded") — a silent namespace-less run fails with unresolved-name
  errors mid-cell. Verify list: synthesized `parameters` cell injection,
  top-level `await` through nbclient, language detection from the
  kernelspec.
- **D9 reframed as principle, not v1 scope cut:** when model-authored
  macros are demanded, the protocol is `notebooks/pending/` — the model
  drafts there, only the operator's move-to-root promotes. Promotion is
  human, always (same quarantine philosophy as D4 applied to provenance).
- **D10/D11 hooks:** `notebook_run` registers a real `result_digest=`
  adapter at decoration (projection digests + scratch-refs + continuations
  off the existing machinery — no bespoke path), stamps
  `untrusted_target=True`. `allow_errors` and timeout are per-call
  parameters with env-derived defaults (`False` / `NOTEBOOK_TIMEOUT`) —
  env knobs are defaults, not ceilings.