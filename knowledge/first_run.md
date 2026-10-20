# First run — and when it doesn't work

You cloned, installed, ran `python bootstrap.py`, and something is unhappy.
This page is the decision tree for "is my setup broken, or is the framework
broken?" Run the probes below before filing anything.

All commands assume the repo root and your venv active.

## 1. The two diagnostic tools

```bash
# Smoke-test EVERY discovered tool with safe args — a summary table where
# each row is a tool verdict. Tools needing a live service are skipped
# unless you pass --force.
python tool_repl.py sweep

# Subsystem health: Brain socket, Ollama, ChromaDB, ZAP, findings DB,
# plus the registry tool count. Also works after bootstrap:
python tool_repl.py run framework_status
```

Read them together:

| Signal | Meaning |
| --- | --- |
| `sweep` fails for tool X, but `framework_status` is all-up | The tool (or its external CLI) — check that tool's backend binary is on `PATH` |
| `framework_status` shows Ollama down | Your model endpoint. Check `.env` → `OLLAMA_BASE_URL`, and that Ollama is actually running (`ollama list`) |
| `framework_status` shows ChromaDB down but the REPL `list` works | Discovery works; only *semantic search* needs ChromaDB. Start the server (`docker run -p 9000:8000 chromadb/chroma`) |
| Brain socket down | `bootstrap.py` starts it; check `/tmp/brain.log`. In-process fallback still executes `BRAIN_DISPATCH` tools, but sessions held by the Brain are invisible to it (see AGENTS.md pitfalls) |

## 2. The three setup mistakes everyone makes first

1. **`.env` not created / `OLLAMA_BASE_URL` not set** — the default is
   `http://localhost:11434/v1`; if your Ollama runs elsewhere, every
   embedding call fails. Copy `.env.example` → `.env` and set it.
2. **Registry not indexed** — a fresh clone has an empty vector registry:
   `python -m daharness.core` first (add `--clear` for a full rebuild).
3. **Code edited but embeddings stale** — the REPL `reindex` command
   refreshes manifests so `run` sees your edits immediately, but semantic
   `search` and the secretary keep seeing **old embeddings** until
   `python -m daharness.core` runs (then restart the Brain).

## 3. Scope-gate messages are not errors

If a tool raises `ScopeGateError`, the operator-armed gate chose to block
that traffic — that is the framework working. Armed state is controlled
only from the REPL (`scope on <handle>` / `scope off` / `scope status`);
the secretary cannot toggle it. Disarmed (lab) mode is the default. Full
semantics: [`knowledge/scope_gate.md`](scope_gate.md).

## 4. Still stuck

- [`AGENTS.md`](../AGENTS.md) → **Pitfalls** section — most known sharp
  edges are documented there
- Run `pytest tests/` — if failures appear, check whether they reproduce on
  a clean checkout before assuming your environment
- File a [bug report](https://github.com/Surzal-kali/daharness/issues/new?template=bug_report.yml)
  with the commit, the repro, and redacted output

## 5. A minimal end-to-end sanity run

Lab target assumed (disarm the scope gate for lab work — `scope off`):

```bash
python tool_repl.py run nmap_status --target 127.0.0.1 --options "-p 11434"
# expect: your Ollama port as an open service → discovery + dispatch +
# the full tool path works end to end
```

If that round-trips, the harness core is healthy and whatever failed next
is downstream (a tool's backend, a missing CLI, or a model endpoint).