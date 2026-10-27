# Contributing to daharness

Thanks for helping make daharness better. This document covers the ground
rules and the practical "how" — including the framework's unusually short
path from "I wrote a function" to "the LLM can call it."

## Ground rules

- **Authorized testing only.** Contributions are code and docs for the
  authorized-use tool described in [`SECURITY.md`](SECURITY.md). PRs that
  remove or weaken the operator-only scope-gate arming, the untrusted-target
  provenance stamping, or the local-model safety stance will not be accepted.
  Fixing a bug *in* those mechanisms is welcome — discuss it in an issue
  first if the design itself is in question.
- **GPL-3.0 applies.** All contributions are licensed under the project's
  [GPL-3.0](../LICENSE) license. By opening a PR you confirm the code is
  yours to contribute under that license.
- **No target data in code, tests, or issues.** Redact credentials, internal
  hostnames, tokens, and response bodies from anything you share. If a
  reproduction needs a live service, use a local lab (e.g. Metasploitable,
  DVWA on loopback).

## Ways to contribute

| Contribution | Difficulty | Where to start |
| --- | --- | --- |
| Docs: fix, clarify, expand | Easy | `README.md`, `AGENTS.md`, `knowledge/` |
| New framework tool | Moderate | See "Adding a tool" below |
| Bug fix in the harness | Moderate | `daharness/`, `utils/`, `listeners/` |
| New scanner/auxiliary wrapper | Moderate | `auxiliaries/`, `payloads/` |
| Test coverage | Ongoing | `tests/` (pytest) |
| C/C++ plugin | Advanced | `listeners/plugins/`, `payloads/plugins/` |

## Issue first, PR second

For bug fixes and behavior changes, open an issue before writing code —
there may be a reason something is shaped the way it is (several design
decisions here exist specifically for scope compliance). Docs and tests
don't need an issue.

**Not for issues:** reports that the framework can attack things — that is
by design and covered in [`SECURITY.md`](SECURITY.md). Vulnerabilities in
the harness itself go through private reporting, not public issues.

## Adding a tool (the fun part)

Pick one of three lanes — full detail lives in `AGENTS.md` ("Adding a
Tool"):

### Option A — argparse module (subprocess tool)

Create a `.py` file under `auxiliaries/`, `payloads/`, `listeners/`,
`utils/`, or `evasion/` — the discovery roots
(`daharness/registry.py:ALLOWED_TOOL_ROOTS`). The module docstring becomes
the LLM's
*understanding* of the tool (it is the embedding text — write it like a
capability description, not a code comment). `argparse` flags become the
parameter schema, extracted statically — the module is **never imported**
during discovery.

### Option B — `@framework_tool` (the main lane)

```python
from constants import framework_tool

@framework_tool(
    "Check whether a target domain is inside the loaded program scope.",
    tags=["recon.scope"],
)
def check_scope(target):
    ...
```

- The decorator's first argument is the semantic description used for
  vector matching — make it descriptive, not brief.
- Place the module under a Brain scan dir (`auxiliaries/`, `listeners/`,
  `payloads/`) or `utils/` (in-process fallback lane).
- **No module-level side effects** — the Brain imports scanned modules at
  startup, so your module-level code would run inside the sidecar.
- Sync tools that block (subprocess, network I/O) are fine — dispatch runs
  them in a worker thread. Do **not** make a blocking tool `async` — that
  pins the event loop.
- Tools that start long-running services must not block: bind, hand serving
  to a background task, return immediately (see `listeners/listening.py`).
- Long-running CLI tools follow the `run_*` / `*_status` / `*_cancel` triplet
  pattern (`utils/background_job.py:launch_job` returns a `job_id`
  immediately).
- Stateful clients (SSH, MSF, DB) implement a `get_instance()` classmethod
  singleton so the Brain and in-process dispatchers share live handles.
- Traffic-sending tools must pass through the scope gate
  (`utils/scope_gate.py`); offline tools (crypto work, cracking) do not
  touch it.
- Give the tool category tags (`daharness/tool_tags.py:CANONICAL_TAGS`) so
  semantic search finds it even when the phrasing differs.

### Option C — C/C++ plugin

Write `.c`/`.cpp` under a `plugins/` directory, compile with
`gcc -shared -o plugin.so -fPIC plugin.c`, load it via `ctypes.CDLL` in a
Python wrapper, and wrap that in a `@framework_tool`. Always set
`argtypes` and `restype` explicitly — missing ctypes signatures cause
silent coercion or segfaults. Build absolute paths from
`Path(__file__).resolve()`.

### Registering what you built

```bash
python -m daharness.core      # re-index (re-embeds; restart the Brain after)
python tool_repl.py selftest  # hermetic pytest run through the REPL macro
pytest tests/                 # run the suite directly
```

Two refresh layers (easy to confuse): REPL `reindex` refreshes manifests
only; `python -m daharness.core` rebuilds embeddings — semantic `search`
keeps seeing old embeddings until it runs.

## Tool quality checklist

Before proposing a tool, check that it:

- [ ] Has a semantic description worth embedding (a stranger's LLM could
      pick the right tool from the description alone)
- [ ] Passes targets through the scope gate if it sends traffic anywhere
- [ ] Fails loudly and honestly — a tool that can't reach its backend
      returns an error, never a fabricated result
- [ ] Caps its own output (output caps / background-job pattern) so a
      chatty target cannot flood model context
- [ ] Raises `ValueError` for caller mistakes (bad local inputs) and keeps
      `ScopeGateError` reserved for "the armed gate blocked traffic"
- [ ] Is tagged and appears in the REPL `list` output

## Tests

```bash
pytest tests/          # full suite
```

Add tests for harness changes under `tests/test_*.py`. Tool wrappers get
mocked-backend tests where practical (see existing `tests/` for the
patterns); anything requiring a live target goes in the e2e lane and skips
cleanly when the target is absent.

## PR checklist

- [ ] `pytest tests/` passes locally
- [ ] New tools smoke-tested via `python tool_repl.py run <tool_id>`
- [ ] `README.md`/`AGENTS.md` updated if behavior is user-visible
- [ ] Sensitive values (tokens, IPs, passwords) nowhere in the diff
- [ ] Existing behavior preserved when `result_mode`/`full` defaults are in
      play — the registry's contract is "default = zero behavior change"

## Questions?

Open a discussion or issue with your question — design questions (scope
gate semantics, projection lanes, budget directives) are worth a
conversation before code.