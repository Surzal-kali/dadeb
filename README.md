# daharness

A platform for agentic, iterative security testing — a local LLM that plans,
picks, and runs 150+ security tools under your approval, with target data
never leaving your hardware.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Security Policy](https://img.shields.io/badge/Security-Policy-yellow.svg)](.github/SECURITY.md)

## What it is

One engine — a vector-indexed registry of `@framework_tool` callables and
gate-checked execution — surfaced through four lanes. Pick whichever fits
the moment:

- **Secretary chat** — talk to a local Ollama model that semantically
  searches the registry, chooses the right tool for "fuzz that login form",
  and executes it after you approve the exact call
- **API gateway + MCP** — `POST /tools/execute` and a streamable-HTTP MCP
  endpoint for wiring the registry into any external agent harness
- **Tool REPL** — bypass the LLM entirely: pick a tool, pass args, see raw
  output (`python tool_repl.py run <tool_id> --flag value`)
- **Jupyter kernel** — the same namespace preloaded into notebook cells for
  engagement journals (`python tool_repl.py --install-kernelspec`)

The intended workflow is a **hunt lifecycle**: load a program scope →
enumerate the surface → scan in-scope targets → collect evidence → file
structured findings — the scope-compliance and reportability gates hold at
every step.

Every execution is grounded (the model can only call tools its search
actually surfaced), approval-gated in the secretary lane, and
scope-compliance-checked against the loaded HackerOne/Intigriti program.
Large tool outputs are projected out of model context into a durable scratch
store (`full | digest | page` — `digest` by default) with a retrieval
reference — evidence stays queryable without flooding context.

## Why local-only models

The secretary reads target responses: credentials, tokens, internal IPs,
response bodies. A cloud LLM API transmits every one of those bytes to a
third party — unauthorized egress under most programs' ROE and data-protection
law. The framework defaults to a locally hosted Ollama endpoint and the docs
refuse to pretend otherwise. See the
[Legal Addendum](#legal-addendum--local-models-only-for-pentesting) under
Safety Notes and the responsible-use policy in
[`SECURITY.md`](.github/SECURITY.md).

## Quick start

Prereqs: Python 3.12+, [Ollama](https://ollama.ai) with an embedding model
(`nomic-embed-text`) and a chat model, and a ChromaDB server
(`docker run -p 9000:8000 chromadb/chroma`).

```bash
git clone https://github.com/Surzal-kali/daharness.git
cd daharness

# Minimal lab demo: core runtime + 3-line config
python -m venv venv && source venv/bin/activate
pip install -e .
cp .env.example .env          # set: OLLAMA_BASE_URL, SECRETARY_MODEL
cd dockered
docker compose up -d
cd ..
python -m daharness.core      # index the tool registry
python bootstrap.py           # chat with the secretary

# Full bounty workbench: optional lanes + dev tooling
pip install -e ".[web,jupyter,dev]"
pip install -r requirements-dev.txt   # exact dev-venv repro, all 361 pins
python tool_repl.py sweep      # smoke-test every tool with safe args
pytest tests/
```

Details: all env knobs (`.env.example` — 240 lines of them, most optional),
external CLI tools
([Nmap, ZAP, Metasploit, ffuf, …](#external-dependencies)), Docker bench
([`dockered/`](dockered/)), the operator scope gate
([`knowledge/scope_gate.md`](knowledge/scope_gate.md)), and the
first-run/when-it-doesn't-work playbook
([`knowledge/first_run.md`](knowledge/first_run.md)).

If something doesn't work: `python tool_repl.py sweep` and the
`framework_status` tool tell you whether it's your setup or the tool — then
check [`AGENTS.md`](AGENTS.md) pitfalls or open an issue.

## The rest of this README

This document is the project overview and harness-wide reference — identity,
quick start, core architecture, configuration, safety. Each lane's deep dive
lives beside its code:

- [`auxiliaries/README.md`](auxiliaries/README.md) — recon & access lanes:
  ZAP, the Playwright sidecar, program scope, the stateful HTTP lane
- [`payloads/README.md`](payloads/README.md) — offensive lanes: Metasploit
  client deep-dive, the msfvenom/upload chain, fuzzers, cracking
- [`utils/README.md`](utils/README.md) — harness plumbing: scope gate,
  result projection, scratch store, findings, tool budget, cookie jar
- [`listeners/README.md`](listeners/README.md) — the Brain sidecar, OOB
  collaborator, in-process fallback, zombie kill switch
- [`evasion/README.md`](evasion/README.md) — readiness lane: nmap wire-shaping
  presets, the browser-coherent web-session identity (per-host sticky UA ↔
  curl-impersonate TLS/header stack), + their honest limits
- [`dockered/README.md`](dockered/README.md) — the containerized workbench
  (ChromaDB + Open WebUI + JupyterLab)
- [`dabooks/README.md`](dabooks/README.md) — the JupyterLab notebook lane
- Drop folders & operator docs: [`dropbox/README.md`](dropbox/README.md),
  [`apk/README.md`](apk/README.md), [`pcaps/README.md`](pcaps/README.md),
  [`binaries/README.md`](binaries/README.md),
  [`knowledge/README.md`](knowledge/README.md)

Agent-facing development guide: [`AGENTS.md`](AGENTS.md). Contributor
walkthrough: [`CONTRIBUTING.md`](.github/CONTRIBUTING.md).

## Architecture

### Tool Secretary (`daharness/`)

The core of the framework. A local LLM (Ollama; `SECRETARY_MODEL`, default
`ornith-1.5:35b`) acts as a conversational agent with two tools:

1. **`search_tools`** — semantic search over the tool registry (ChromaDB,
   `nomic-embed-text` embeddings, HNSW cosine similarity). Returns full tool
   manifests.
2. **`execute_tool`** — runs a surfaced tool. It is declared
   `requires_approval=True`, so the run **always pauses** with pydantic-ai's
   `DeferredToolRequests`: the confirmer shows the operator the full
   manifest + arguments and execution proceeds only on approval
   (`run_secretary()` resumes the loop with the same `deps` + message
   history), capped at `SECRETARY_MAX_APPROVAL_ROUNDS` rounds per turn.
   After an approved execution a framework-log tail (Brain/MSF) can be
   appended to the result for visibility
   (`POST_EXECUTION_LOGS`: `off` | `failures` | `always`, default
   `failures`), and the result passes through the projection middleman
   before it enters context (see
   [Result Projection](utils/README.md#result-projection-result_projectionpy)).

   This gate is internal to the secretary lane — tool calls that arrive
   through the API gateway or the MCP endpoint skip it entirely.

**Grounding rule:** the secretary can only execute tools it has seen returned
by `search_tools` in the current conversation. A tool_id that was never
surfaced is rejected — the model cannot hallucinate a tool into existence.

The `daharness/` package exposes focused import paths:

- `daharness.core` — backwards-compat shim re-exporting legacy public names
- `daharness.agent` — secretary agent factory
- `daharness.executor` — standalone execution helpers (no ChromaDB needed)
- `daharness.registry` — discovery and semantic search API
- `daharness.findings` — SQLite-backed findings store (`FindingStore`)
- `daharness.models` — `ToolManifest` and `Finding` pydantic models

### Tool Discovery

Two passes scan the workspace at bootstrap:

1. **Static AST analysis** (`LOCAL_FILE` transport): parses Python modules
   with `ast` — never imports them — extracting docstrings and `argparse`
   options to mint `ToolManifest`s. These run as subprocesses.
2. **Dynamic import** (`BRAIN_DISPATCH` transport): imports modules and
   discovers functions/methods decorated with `@framework_tool`. These
   dispatch through the Brain sidecar or fall back to in-process execution.

A third transport, `MCP_RPC`, is reserved for external RPC integrations
(Metasploit).

### Brain Sidecar (`listeners/thebrain.py`)

A Unix domain socket server (the checkout's gitignored `run/brain.sock`,
resolved via `constants.brain_socket_path()` — the socket lives inside the
tree so bind-mounted container lanes such as the jupyter kernel reach the
SAME socket as the host; a `/tmp` path would be per-namespace and unreachable
across a container boundary) with length-prefixed message
framing. At startup it scans the six indexed roots (`auxiliaries/`, `payloads/`,
`listeners/`, `utils/`, `encoders/`, `evasion/`)
for `@framework_tool` callables and primes its function registry before
binding the socket. It dispatches `CALL_TOOL` events to registered Python
functions, and forwards unknown events to a C library (`frameit.so`) via
`ctypes`.

When the Brain is unavailable, `BRAIN_DISPATCH` tools fall back to in-process
execution with cached class instances (so stateful clients like
`MetasploitClient` keep their handles). Full startup sequence, event
protocol, timeout/shutdown semantics, and the zombie kill switch:
[`listeners/README.md`](listeners/README.md#brain-sidecar-thebrainpy).

### `@framework_tool` Decorator (`constants.py`)

```python
from constants import framework_tool, TransportType

@framework_tool("Run an Nmap scan on a target with specified options.")
def run_nmap(target, options="-Pn -sV"):
    ...
```

Marks a function or method as a callable framework tool. The doc string
becomes the semantic capability description that the registry embeds.

## Tool Modules

150+ tools live in six indexed roots: [`auxiliaries/`](auxiliaries/README.md)
(scanners, recon, the scope integration), [`payloads/`](payloads/README.md)
(offensive lanes: MSF, msfvenom, fuzzing, cracking), [`utils/`](utils/README.md)
(harness plumbing: scope gate, projection, scratch, findings),
[`listeners/`](listeners/README.md) (Brain sidecar services, OOB collaborator),
plus the readiness lanes [`evasion/`](evasion/README.md) (wire-shaping + the
browser-coherent web-session identity; `encoders/` loaders are staged but not
yet built).
Each folder README carries the per-module inventory and that lane's deep dive.

### Tool Categories (`daharness/tool_tags.py`)

With 150+ tools, not every tool surfaces for every reasonable phrasing. Each
tool carries category tags from a canonical 13-bucket vocabulary that are
appended to its embedded capability text (`...\n\nCategories: web.fuzz`), so a
search that uses category language ("recon", "fuzz", "brute", "packet")
surfaces the tagged tools even when the tool's own prose never used that word.

- Vocabulary (`CANONICAL_TAGS`): `recon.subdomain`, `recon.web`,
  `recon.dns-certs`, `recon.scope`, `web.fuzz`, `web.probe`, `web.auth`,
  `exploit.web`, `exploit.msf`, `brute.crack`, `net.raw`, `net.services`,
  `infra` (infra = main framework tooling and internals; net.services =
  non-HTTP network-service tooling — SSH/SMB/FTP access, remote exec, secrets
  dump, callback listeners — and the landing bucket for tool-nursery
  candidates from model suggestions during lab runs).
- Bulk assignment for existing tools: the `TOOL_TAGS` map in
  `daharness/tool_tags.py`, keyed by exact tool_id — one reviewable table.
- New tools: tag inline via the decorator — `@framework_tool(doc, ...,
  tags=["web.fuzz"])` (decorator tags win over the map for the same id).
- Tags persist in ChromaDB metadata (`tags_json`), surface in
  `describe_manifest` (the secretary sees the category beside every search
  hit), and a tag change re-embeds the tool automatically on the next
  `python -m daharness.core` (the doc changes, which is the change signal).
- Non-canonical tags are warned about (bootstrap/reindex log) but kept.
- All registry tools are tagged (`net.services` closed
  the non-HTTP-service gap; port scanners stay `net.raw` — the scan lane —
  while `net.services` is for interacting with a discovered service).

### Background Job Pattern

Long-running CLI tools follow the shared `utils/background_job.py` pattern:
`launch_job` returns a `job_id` immediately (a detached subprocess + JSON
sidecar so polls survive a restart) and tools come in
`run_*` / `*_status` / `*_cancel` triplets. Full mechanics:
[`utils/README.md`](utils/README.md#background-job-pattern-background_jobpy).

### C/C++ Plugins

- `listeners/plugins/raw_scan.cpp` → `raw_scan.so` — raw SYN scan (`SOCK_RAW`);
  requires root or `CAP_NET_RAW`
- `listeners/plugins/frameit.c` → `frameit.so` — C-side event bridge for the Brain
- `payloads/plugins/listen.cpp` — payload listener stub

Compiled with `-fPIC -shared`; loaded via `ctypes.CDLL` (always set
`argtypes` and `restype` explicitly).

## External Dependencies

The framework wraps several external security tools. Each is invoked as a
subprocess by the corresponding module; install the CLI binary and ensure it
is in your `PATH`.

| Tool | Module | Notes |
| --- | --- | --- |
| **Nmap** | `auxiliaries/nmap.py` | Port/service scanning; NSE script library accessible via `--script` in options (`nmap_scripts` lists the 600+ installed scripts) |
| **Masscan** | `auxiliaries/masscan.py` | Fast async port scanning; requires root or `CAP_NET_RAW` |
| **OWASP Amass** | `auxiliaries/amass.py` | Subdomain enumeration (v5+; passive mode by default) |
| **OWASP ZAP** | `auxiliaries/zap.py` | Web app scanning; launched in `-daemon` mode by `bootstrap.py` |
| **Radare2** | `auxiliaries/radare2.py` | Static binary analysis; `r2pm -ci r2ghidra` for decompilation |
| **jadx** | `auxiliaries/jadx.py` | APK/dex/jar decompilation (`apk/` drop folder, cached workspaces, grep/read over decompiled sources) |
| **Metasploit Framework** | `payloads/metasploiting.py` | MSF RPC integration (MCP sidecar started by `bootstrap.py`) |
| **msfvenom** | `payloads/msfvenom_tools.py` | Payload artifact generation for upload testing (`dropbox/` output; handler start built in) |
| **ffuf** | `payloads/ffuf.py` | Web content fuzzing |
| **Hydra** | `payloads/hydra.py` | Credential brute-force |
| **sqlmap** | `payloads/sqlmap.py` | SQL injection detection |
| **searchsploit** | `payloads/searchsploiting.py` | ExploitDB local lookup |
| **Impacket** | `auxiliaries/impacket_suite.py` | Windows post-exploitation (SMB, psexec, wmiexec, atexec, secretsdump) |
| **Scapy** | `utils/packetcraft.py` | Packet crafting, send, send-and-receive probes (sr1/srp1), sniffing (Python library) |
| **Paramiko** | `utils/paramiko_client.py`, `auxiliaries/ssh_exec.py` | SSH client (Python library) |
| **john the Ripper** | `payloads/hash_crack.py` | Password cracking (`run_john` / `john_status` / `john_show`, background-job pattern) |
| **hashcat** | `payloads/hash_crack.py` | Password cracking (`run_hashcat` / `hashcat_status` / `hashcat_show`, background-job pattern) |

The full install/launcher-resolution story, the daemon configuration, and
the proxy/bind posture live in
[`auxiliaries/README.md`](auxiliaries/README.md#owasp-zap). Short version:
install `zaproxy` (set `ZAP_BIN` if it lands elsewhere), the framework
launches ZAP in `-daemon` mode with a loopback-only API, `.zap_home/` pins
the home directory, and `ZAP_API_KEY` goes in `.env`.

### Playwright Rendered-DOM Recon Sidecar

A scope-enforcing headless-Chromium sidecar for JS-heavy / SPA recon —
gates navigations + fetch/XHR/websockets through the operator-armed scope
gate at the browser request-routing layer. Opt-in with `PLAYWRIGHT_SIDECAR=1`.
The full install instructions (browser-into-repo, root/no-sandbox handling,
`playwright_fetch` / crawl tools, auth'd crawling via
`PLAYWRIGHT_STORAGE_STATE`) live in
[`auxiliaries/README.md`](auxiliaries/README.md#playwright-rendered-dom-recon-sidecar).

### Metasploit Framework

Install Metasploit Framework, set `MSGRPC_PASSWORD` and `MSF_RPC_PORT` in
`.env`, and `bootstrap.py` starts the `msfrpcd` sidecar automatically and
vectorizes discovered modules into the tool registry. The client deep-dive
(payload-family rules, meterpreter RPC notes, `start_handler`
semantics, LHOST reachability) lives in
[`payloads/README.md`](payloads/README.md#metasploit-framework).

### Docker deployment (`dockered/`)

A containerized workbench (ChromaDB + Open WebUI + JupyterLab on a shared
bridge network) lives in `dockered/` and bind-mounts the live source tree —
code edits on the host need no rebuild. Start with:

```bash
cd dockered
docker rm -f chroma          # remove a legacy standalone chroma container if present
docker compose up -d --build
```

Service map, the JupyterLab nursery setup (nbi config, lab DNS, the
`daharness` kernel lane), and the Open WebUI wiring are documented in
[`dockered/README.md`](dockered/README.md).

## Supporting Services

### Findings Store (`daharness/findings.py`)

SQLite-backed findings store — the single source of truth for reported
findings, living in the `findings` table of `ids.db`. The `Finding` pydantic
model (`daharness.models.Finding`) carries title, severity (P1–P4), CWE,
asset, evidence (request/response/excerpt), reproduction steps, tool chain,
and a full lifecycle: `open` → `closed` / `false_positive` / `duplicate` /
`superseded`, with `closed_by`, `closed_reason`, and `superseded_by` for
audit trails.

The full finding objects **never** enter the secretary model's context. Only
a one-line pointer is stored in vector memory (ChromaDB, `findings`
namespace) so the secretary can recall that a finding *exists* without
bloating its context with the full evidence payload.

Framework tools in `utils/findings.py`:

- **`report_finding`** — the terminal action for any tool chain. Mints a
  structured finding and stores a one-line memory pointer.
- **`render_findings`** — renders all findings as a markdown report (filters
  by severity/asset/status). Also writes a timestamped `.md` file to
  `findings_md/` so reports persist outside the database.
- **`close_finding`** — close a finding as resolved, false positive, or
  duplicate.
- **`supersede_finding`** — mark an older finding as replaced by a newer,
  more accurate one.

### HackerOne Scope Integration (`auxiliaries/program_scope.py`)

Pulls a program's structured scope, scope exclusions, weakness list, and
policy text from the HackerOne Hacker API v1 and turns them into a
machine-readable manifest the secretary and scan tools consult. Caches
manifests to `scope/<handle>.json`.

Framework tools:

- **`load_program_scope`** — fetch (or load cached) program scope: in-scope
  assets (typed: URL/WILDCARD/DOMAIN/CIDR/IP/ANDROID/IOS/BLOCKCHAIN with
  `max_severity` and CIA requirements), out-of-scope assets, excluded
  report categories, reportable weakness/CWE allowlist, and policy text.
  Also writes the workspace `.scope` file so `subdomain_enum` auto-filters
  against the real HackerOne scope.
- **`check_scope`** — test whether a target is inside the program's
  authorised scope *before* running any scanner. Out-of-scope asset matches
  always win over in-scope wildcards.
- **`check_reportable`** — test a candidate finding's category/CWE against
  the program's excluded categories and weakness allowlist before filing, to
  avoid burning HackerOne reputation on N/A reports.
- **`program_hacktivity`** — fetch the program's hacktivity feed for
  duplicate-checking. Works without credentials (public feed); includes a
  behavioral guard against silent filter-ignoring.
- **`search_programs`** — keyword search ACROSS the boards' program listings
  (HackerOne authed index, Intigriti PAT list; Bugcrowd exact-handle probe —
  that lane has no public listing API). Rows carry platform/handle/name and
  bounty-relevant flags (`offers_bounties`, per-asset eligibility, tiers);
  `with_assets=True` pulls each match's manifest for a compact asset + bounty
  summary. Also exposed operator-side as `scope search <kw>` in the Tool
  REPL. Dollar bounty tables are not structured on any lane — they live in
  each program's policy prose.

**Authentication:** The structured-scope endpoints require a platform API
token. HackerOne uses Basic auth — set `H1_API_USERNAME` and `H1_API_TOKEN`
in `.env`. `program_hacktivity` works without credentials.

**Intigriti support:** `program_scope.py` also pulls Intigriti program scope
and hacktivity via `INTIGRITI_USERNAME` + `INTIGRITI_API_TOKEN`; manifests
cache to `scope/intigriti_<handle>.scope`.

### Tool REPL (`tool_repl.py`)

The operator's console for exercising framework tools directly — it
bypasses the secretary LLM entirely: pick a tool, supply arguments, see
the raw result. Use it to isolate tool-execution problems from
model-reasoning problems, to arm/control the scope gate, and to
smoke-test tools after adding or editing modules. `run` dispatches
through the same executor as the Brain, so the armed scope gate applies
here too — the REPL is also where refusals can be tested safely.

Launch: `python tool_repl.py` (interactive). One-shot modes:
`python tool_repl.py run <tool_id> [--flag value ...]` (or
`run <tool_id> --json '{...}'`, or bare `run <tool_id>` = safe defaults),
`info <tool_id>`, `sweep`, `search <query>`.

Jupyter kernel lane — the notebook/engagement-journal twin of the
interactive REPL: `python tool_repl.py --install-kernelspec` installs the
`daharness` kernel; notebook cells run on the same preloaded namespace
(`await session_post(...)`, envelope helpers) against the live Brain
session. Kernel conventions and caveats:
[`dockered/README.md`](dockered/README.md#jupyterlab--the-tool-nursery) and
[`AGENTS.md`](AGENTS.md#jupyter-kernel-dabooksipynb); the notebook work dir
is [`dabooks/README.md`](dabooks/README.md).

Interactive commands:

    list [filter]        print discovered tool manifests (substring filter)
    info <tool_id>       full manifest: params, defaults, embedding blurb
    resolve <tool_id>    import the callable; print signature + docstring
    run <tool_id> [--flag value ...] | --json '{...}'
                         execute a tool; shlex quoting honoured; args
                         type-coerced from the tool's own manifest schema;
                         bare `run` falls back to the tool's SAFE_ARGS
                         defaults (see safe-args)
    sweep [--force]      run EVERY discoverable tool with safe args and a
                         summary table; tools needing a live service are
                         skipped unless --force
    safe-args [<id>]     show the SAFE_ARGS table (or one tool's entry)
    search <query>       semantic search (needs ChromaDB + Ollama);
                         rendered worst-match-first so rank #1 prints
                         LAST, right above the prompt
    scope ...            scope-gate control — see the next section
    reindex              re-discover tools after adding/editing modules
                         (manifests only, no ChromaDB re-embed)
    ipython              IPython shell preloaded with the registry,
                         manifests, and quick_run(tool_id, **kwargs)
    help / quit

Input UX: prompt_toolkit ghost text plus a tiered completer — commands →
tool IDs → `--flag` names from the chosen tool's schema → scope
subcommands and their flags. History persists in `~/.tool_repl_history`.
The prompt carries a `✓` prefix while the scope gate is ARMED (sends
gated); it disappears when disarmed.

Two refresh layers, easy to confuse: REPL `reindex` re-runs tool
discovery in-process (manifests + direct `run` see code edits
immediately), while `python -m daharness.core` rebuilds the vector
registry — semantic `search` and the secretary keep seeing the OLD
embeddings until that re-embed runs (and the Brain is restarted).

### Scope Gate — Operator-Armed (`utils/scope_gate.py`)

A technical backstop the OPERATOR arms from the Tool REPL — separate from
`check_scope`, which only consults a loaded manifest. Arming is deliberately
not exposed as an `@framework_tool`, so the secretary can never toggle it.
Enforcement is file-backed (`scope/.armed_packet_scope.json`, mtime-checked
every call), gated calls fail closed with `ScopeGateError`, and an
out-of-scope match always beats an in-scope wildcard. Full verdict tiers,
the blessing commands, and known residual surfaces:
[`utils/README.md`](utils/README.md#scope-gate--operator-armed-scope_gatepy);
operator usage: [`knowledge/scope_gate.md`](knowledge/scope_gate.md).

### Memory Service (`memories.py`)

ChromaDB-backed persistent, namespaced vector memory for cross-harness
recall. Supports keyword search and vector similarity recall, with
session-scoped filtering. Exposed both as `@framework_tool` methods and via
the API gateway. The `findings` namespace stores lightweight pointers to
reported findings.

### Sessions, Cookies, Handles (`utils/`)

Three complementary state layers: the **Session Manager** holds live
connection objects (SSH, MSF) process-locally keyed by `session_id`; the
universal **cookie jar + token vault** persists web state in SQLite so the
Brain, in-process lane, REPL, and gateway all share it (it sidesteps the
Session Manager's process-local pitfall — see
[`utils/README.md`](utils/README.md#the-universal-cookie-jar--stateful-http-lane-cookie_jarpy));
typed **session handles** (`kind:session_id`) validate a handle's kind
against a tool's accepted set before execution. Deep dives:
[Session Manager](utils/README.md#session-manager-session_managerpy) ·
[Cookie jar](utils/README.md#the-universal-cookie-jar--stateful-http-lane-cookie_jarpy) ·
[Session handles](utils/README.md#session-handles-handlespy).

### OOB Collaborator (`listeners/collaborator.py`)

A Burp Collaborator analog for blind SSRF/XSS callbacks: HTTP/HTTPS/DNS on
one host, `collab_generate` / `collab_poll`, optional public mode via
`COLLAB_PUBLIC_URL` (e.g. a Tailscale Funnel) including a token-gated
redirect endpoint for internal-SSRF chains. Full story:
[`listeners/README.md`](listeners/README.md#oob-collaborator-collaboratorpy).

### SQLite Database (`utils/sessions.py`)

Tracks targets, sessions, payloads, and notes in `ids.db`. Schema defined
in `schema.md`. The findings table shares this database.

### API Gateway (`api_gateway.py`)

FastAPI server (port **5000** on the host lane; **6000** in the container
lane) exposing:

- `GET /health` — framework health check
- `POST /tools/execute` — exact `tool_id` dispatch or semantic lookup (accepts `result_mode`: full|digest|page, default `digest`). Enforces a per-turn tool budget: with `turn_key` (e.g. `chat_id:message_id`), each turn gets `TOOL_BUDGET_PER_TURN` executions (default 10) — the last call's result carries an end-turn directive, and past-the-limit calls are refused outright (memory/findings tools stay callable so the model can report).
- `POST /tools/search` — semantic tool search (no execution)
- `POST /scratch/search` — retrieve a stored tool result from the scratch store
- `GET /scratch/list` — list recent scratch entries for an agent
- `GET /scratch/stats` — scratch store statistics
- `POST /memory/search` — keyword memory search
- `POST /memory/recall` — vector similarity recall
- `POST /mcp` — streamable-HTTP MCP endpoint (`tools/list` + `tools/call`)

Also serves MCP (Model Context Protocol) handlers for tool listing and
execution. `POST /tools/execute` and MCP `tools/call` dispatch directly —
the internal approval gate does not exist in these lanes, so an integrating
harness that wants sign-off needs to add its own layer before calling. If
`GATEWAY_API_KEY` is set, every request is authenticated
(sent as `X-API-Key`); otherwise the gateway runs in unauthenticated dev
mode.

### Result Projection & Scratch Store (`utils/`)

Every result passes through the projection middleman *before* entering model
context: `result_mode` (`digest` | `page` | `full`) is an execution-envelope
parameter, never a tool argument. Oversized/digested/paged results are
stored intact in the durable, ownership-scoped **scratch store** and enter
context as a compact digest/page + a `scratch_ref` + a ready-to-call
continuation — evidence stays queryable without flooding context. Full
mechanics: [Projection](utils/README.md#result-projection-result_projectionpy)
· [Scratch store](utils/README.md#scratch-store-scratch_storepy).

## Full Setup

### Prerequisites

- Python 3.12+ (3.13 supported)
- [Ollama](https://ollama.ai) running with `nomic-embed-text` and a local
  chat model (code default: `ornith-1.5:35b`; a thinking/reasoning model is
  recommended — the secretary plans through defenses and
  edge-infrastructure fingerprinting, which rewards reasoning). Swap via
  `SECRETARY_MODEL` in `.env`. The Ollama endpoint defaults to a lab-LAN
  fallback baked into `daharness/registry.py`; set `OLLAMA_BASE_URL` in
  `.env` to your own listener and keep it loopback/LAN (see
  [Safety Notes](#safety-notes)).
- ChromaDB server (default: `localhost:9000`; used by the tool registry —
  the memory service `memories.py` uses its own embedded store at
  `.memory/chroma`)
- External CLI tools as needed (see [External Dependencies](#external-dependencies)):
  Nmap, Masscan, OWASP Amass, OWASP ZAP, Radare2, Metasploit Framework, ffuf,
  Hydra, sqlmap, searchsploit
- HackerOne API token (optional, for scope integration)
- Root or `CAP_NET_RAW` (optional, for raw SYN scanning and the OOB
  collaborator's privileged ports)

### Configuration

Environment variables — copy `.env.example` to `.env` and fill in real
values. `.env.example` carries the full annotated key list (most knobs are
optional); the day-one set:

| Variable | Default | Purpose |
| --- | --- | --- |
| `OLLAMA_BASE_URL` | Lab LAN fallback | Ollama API endpoint — set explicitly in `.env`, keep it loopback/LAN |
| `SECRETARY_MODEL` | `ornith-1.5:35b` | LLM model for the tool secretary (a thinking/reasoning local chat model is recommended) |
| `CHROMA_HOST` / `CHROMA_PORT` | `localhost` / `9000` | ChromaDB server used by the tool registry (the memory service uses its own embedded store) |
| `MSGRPC_PASSWORD` / `MSF_RPC_PORT` | — / `55553` | Metasploit RPC credentials |
| `GATEWAY_API_KEY` | — | API gateway auth key (unset = unauthenticated dev mode) |
| `BRAIN_DISPATCH_TIMEOUT` | `600` | Brain socket dispatch timeout (seconds) |
| `SECRETARY_MAX_APPROVAL_ROUNDS` | `5` | Max approval rounds per secretary turn |
| `ZAP_API_KEY` | — | ZAP daemon API key |
| `H1_API_USERNAME` / `H1_API_TOKEN` | — | HackerOne API credentials (scope integration) |
| `TOOL_BUDGET_PER_TURN` | `10` | Per-turn tool-execution cap in the gateway lanes (0 = off) |

### Running

```bash
# Install dependencies — pip install -e ".[web,dev]" installs the core runtime
# (see pyproject.toml) plus the optional lanes you need as editable extras.
# The full pinned dev-venv export is requirements-dev.txt.
pip install -r requirements.txt   # or: pip install -e .  for just the core

# Index tools into the vector registry
python -m daharness.core

# Clear and re-index
python -m daharness.core --clear

# Interactive chat with the secretary (starts all sidecars: Brain, ZAP, MSF MCP, API gateway)
python bootstrap.py            # interactive (indexes + chat)
python bootstrap.py --daemon   # background services only (no chat loop)

# Run tests
pytest tests/
```

For a systemd-managed service, copy the template from
[`scripts/daharness.service`](/home/kali/github/daharness/scripts/daharness.service)
to `/etc/systemd/system/` (adjust the checkout and virtualenv paths if needed),
then enable and start it:

```bash
sudo cp scripts/daharness.service /etc/systemd/system/daharness.service
sudo systemctl daemon-reload
sudo systemctl enable --now daharness.service
sudo journalctl -u daharness.service -f
```

Stop it with `sudo systemctl stop daharness.service`; `bootstrap.py --daemon`
handles SIGTERM and shuts down its child services before exiting.

In both modes, `bootstrap.py` starts the Brain sidecar, the ZAP daemon, the
Metasploit MCP sidecar, and the API gateway (with MCP handlers), after a
wordlist-tree preflight (`utils.wordlists.preflight_wordlists`) surfaces a
missing/empty wordlist source as a startup warning instead of a silent
ffuf/hydra failure. The Metasploit MCP sidecar is also vectorized, but the
full index is only searchable from the secretary chat loop, where executions
pause for operator approval.

## Adding a New Tool

> Contributor-oriented walkthrough (with the tool-quality checklist and PR
> checklist): see [`CONTRIBUTING.md`](.github/CONTRIBUTING.md).

### Python module (argparse, runs as subprocess)

1. Create a `.py` file under `auxiliaries/`, `payloads/`, `listeners/`,
   `utils/`, or `encoders/`.
2. Add a module docstring describing the capability.
3. Use `argparse` for CLI options — the static scanner extracts them as the
   parameter schema.
4. Re-run `python -m daharness.core` to index it.

### Decorated function/method (dispatched via Brain or in-process)

1. Import `framework_tool` from `constants`.
2. Decorate your function or class method:

   ```python
   from constants import framework_tool

   @framework_tool("Description of what this tool does.")
   def my_tool(target, port):
       ...
   ```

3. Place the module under `auxiliaries/`, `listeners/`, or `payloads/`
   (the Brain's default scan dirs).
4. Re-index or restart the Brain sidecar.

### C/C++ plugin

1. Write a `.c` or `.cpp` file in a `plugins/` subdirectory.
2. Compile: `gcc -shared -o plugin.so -fPIC plugin.c`
3. Load via `ctypes.CDLL` in a Python wrapper, explicitly defining
   `argtypes` and `restype`.

## Safety Notes

- **Authorized use only.** This software is for security research on systems
  you are explicitly authorized to test. See the full responsible-use policy
  in [`.github/SECURITY.md`](.github/SECURITY.md) — authorization first, the
  law applies to you regardless, target data never leaves your hardware.
- **Human-in-the-loop (secretary lane — always on there):** every
  secretary-driven tool execution pauses for explicit operator sign-off —
  `execute_tool` is declared `requires_approval=True`, the run halts with
  the full manifest + arguments for the operator to approve or deny, and
  only an approved execution actually runs. This gate is internal to the
  harness: the API gateway and MCP lanes dispatch directly, so an
  integrating harness must add its own approval if it wants sign-off.
- **Context hygiene:** tool results pass through the projection middleman
  (`digest` by default) before entering the model's context window — large
  outputs go to the durable scratch store intact and the model gets a
  compact envelope plus a retrieval reference (see
  [Result Projection](utils/README.md#result-projection-result_projectionpy)).
- **Scope compliance:** `check_scope` gates every scan against the loaded
  HackerOne program scope before execution — out-of-scope assets are
  rejected, and explicit out-of-scope entries override in-scope wildcards.
- **Reportability gate:** `check_reportable` tests candidate findings
  against the program's excluded categories and weakness allowlist before
  filing, preventing N/A or spam-grade reports.
- **Path confinement:** local script execution is restricted to
  `ALLOWED_TOOL_ROOTS` (`auxiliaries/`, `payloads/`, `listeners/`, `utils/`,
  `encoders/`).
- **No import at discovery time:** static analysis uses `ast` only — hostile
  or broken code cannot execute during indexing.
- **Timeouts:** Brain dispatch and subprocess execution are bounded to
  prevent hanging the conversation loop. Long-running CLI tools use the
  background job pattern so the secretary turn is never held open.

### Legal Addendum — Local Models Only for Pentesting

> **WARNING — DATA EGRESS RISK.** This framework orchestrates offensive
> security tools (port scanners, web spiders, active scanners, exploit
> frameworks) against live targets. The tool secretary is an LLM that
> reads target responses, HTTP bodies, command output, and findings to
> reason about next steps. **If the secretary model is hosted on a
> third-party cloud API (OpenAI, Anthropic, Google, or any provider
> outside your own infrastructure), every tool output it processes is
> transmitted to that provider's servers.** This includes response bodies
> from scanned targets, extracted credentials, session tokens, internal
> IP addresses, error messages, and any other data the tools surface.
>
> Sending this data to a third party constitutes **unauthorized data
> egress** from the target's environment and may violate:
>
> - The target organisation's acceptable-use / data-handling policies.
> - Bug bounty program rules of engagement (many programs explicitly
>   prohibit sending target data to third-party services).
> - Data protection regulations (GDPR, CCPA, HIPAA, and equivalents)
>   when the target handles personal, financial, or health data.
> - Non-disclosure agreements, engagement letters, or ROE scope terms.
>
> **You MUST use a locally-hosted model** (e.g. via Ollama, llama.cpp, or
> a self-managed vLLM instance on infrastructure you control) as the
> secretary. Set `OLLAMA_BASE_URL` to a loopback or LAN address. Do not
> point the framework at a cloud-hosted LLM API for any engagement
> involving live third-party targets.
>
> The framework's default `SECRETARY_MODEL` points to a locally-served
> GGUF model. Do not override it with a cloud model for pentesting work.
> If you are testing against your own infrastructure in an isolated lab
> with no real user data, the egress risk is your own to assess — but
> the default configuration assumes local models precisely to keep
> target data on-box.
>
> **Using a cloud-hosted LLM with this framework against a target you do
> not own is a data-handling decision you are solely responsible for.
> The framework authors assume no liability for data egress caused by
> misconfigured model endpoints.**

## Project Layout

```
daharness/              Tool secretary agent + semantic registry (core package)
  agent.py              Secretary agent factory
  registry.py           Discovery and semantic search API
  executor.py           Standalone execution helpers
  findings.py           SQLite-backed findings store (FindingStore)
  models.py             ToolManifest + Finding pydantic models
  _param_docs.py        Parameter-docstring introspection for tool manifests
  preflight.py          Deterministic pre-dispatch validation (fail-fast args gate)
  tool_tags.py          Canonical tool category tags + TOOL_TAGS map
  core.py               Backwards-compat shim / CLI entry point
constants.py            @framework_tool decorator + TransportType enum
bootstrap.py            Daemon entry point; launches all sidecars (Brain, ZAP, MSF MCP, API)
api_gateway.py          FastAPI control panel + MCP server (port 5000 host lane / 6000 container lane)
memories.py             ChromaDB-backed namespaced vector memory
SYSTEM_PROMPT.md        "Brain of a local security lab" agent system prompt (reference)
Modelfile.md            Ollama Modelfiles for the local secretary GGUF models
listeners/
  thebrain.py           Unix socket sidecar + function registry
  listening.py          TCP listener with Brain integration
  collaborator.py       OOB callback listener (HTTP/HTTPS/DNS, Burp Collaborator analog)
  responder_analog.py   CAPTURE-ONLY LLMNR/NBT-NS poisoner + self-contained SMB2 sink
                        (NTLMv2 -> hashcat 5600/john line; lab-gated; no relay path)
  raw_scan.py           SYN scanner wrapper (C++ plugin)
  brain_control.py      list/kill Brain-side tool executions (zombie control plane)
  execution_tracker.py  Brain execution tracker state (zombie kill switch)
  plugins/              C/C++ shared objects (frameit, raw_scan)
payloads/
  metasploiting.py      Metasploit RPC client (search/execute/sessions)
  msfvenom_tools.py     msfvenom payload generation + catch handler (upload lane)
  ffuf.py               ffuf web fuzzing (launch/poll/cancel)
  hydra.py              Hydra credential brute-force (launch/poll/cancel)
  sqlmap.py             sqlmap SQL injection (launch/poll)
  searchsploiting.py    searchsploit (ExploitDB) lookup
  fastcgi.py            FastCGI/PHP-FPM exploitation
  hash_crack.py         john/hashcat password cracking (launch/poll/show + mode suggestion)
  js_recon.py           Static JS recon: routes + secrets from bundles
  wordlists.py          Wordlist discovery
  plugins/              Payload listener (C++)
auxiliaries/
  nmap.py               Nmap scanner
  masscan.py            Masscan fast port scanner (launch/poll/cancel)
  amass.py              OWASP Amass v5 subdomain enumeration
  zap.py                OWASP ZAP HTTP API client
  radare2.py            Radare2 static binary analysis
  jadx.py               jadx APK/dex decompilation (run_jadx composite + list_apk_targets)
  program_scope.py      HackerOne scope integration
  impacket_suite.py     Impacket: SMB/psexec/wmiexec/atexec/secretsdump
  ssh_exec.py           SSH batch command execution
  smb_scanner.py        SMB null session scanner
  cert_tools.py         TLS cert generation for collaborator
  framework_status.py   Framework health check
  archived_urls.py      Wayback CDX archived-URL discovery (passive recon)
  cors_probe.py         CORS posture + security-header audit
  db_client.py          Direct-database client (MySQL/PostgreSQL) for known creds
  dns_lookup.py         Forward/reverse DNS resolution (scope-workflow feeder)
  ftp_recon.py          FTP/SFTP recon + transfer
  playwright_sidecar.py Scope-enforcing rendered-DOM recon sidecar (opt-in)
  playwright_recon.py   Playwright sidecar client tools
  ssrf_probe.py         Parametric SSRF fuzzer + OOB grading
  tls_info.py           TLS certificate + protocol posture inspector
  web_login_brute.py    Session-aware web-login brute (CSRF token reuse)
  web_probe.py          Concurrent web-surface prober (ports → HTTP intel)
  web_session.py        Stateful HTTP lane (session_get/post/upload over the shared jar)
utils/
  findings.py           Finding report/render/close/supersede tools
  paramiko_client.py    Persistent SSH tools
  session_manager.py    Singleton for live session objects
  sessions.py           SQLite database (targets/sessions/notes/findings)
  log_reader.py         Brain/MSF log reading and streaming
  packetcraft.py        Scapy packet crafting (craft_*/send/send_and_receive/sniff/dissect/modify + pcap forensic lane: save_pcap/sniff_to_pcap/load_pcap/list_pcaps)
  memory_tools.py       remember_text/recall_text vector memory tools
  background_job.py     Shared background-job launch/poll helper
  handles.py            Session handle formatting/parsing/validation
  result_projection.py  full|digest|page context-projection middleman
  scratch_store.py      Durable scratch store for projected-out results
  crypto_kit.py         Offline decode/identify/attack crypto-encoding workbench
  cookie_jar.py         Universal durable cookie jar + token vault (SQLite)
  gated_http.py         Per-hop scope-gated HTTP (redirect-bypass blocker; caller-managed session hook)
  wordlists.py          Wordlist utilities
  plugins/              C/C++ shared objects + TLS certs
encoders/               Encoder plugins (C/C++)
binaries/               Radare2 binary drop folder (gitignored)
apk/                    jadx apk drop folder (gitignored; decompiled workspaces under apk/decompiled/<name>/)
scope/                  Cached program scope manifests + .armed_packet_scope.json gate state (gitignored)
findings_md/            Rendered markdown finding reports (gitignored)
chroma-data/            ChromaDB persistence (gitignored)
tests/                  pytest suite for registry + secretary flows
schema.md               SQLite database schema
AGENTS.md               AI agent development guide
docs/                   Target dossiers (local-only, gitignored)
ledger_archive/         Rotated-out ledger snapshots (local-only, gitignored)
dockered/               Container workbench: ChromaDB + Open WebUI + JupyterLab (compose, jupyter.Dockerfile; see dockered/README.md)
owui-tools/             Open WebUI tool wrappers (framework bridge: search/run/memory/health)
.env.example            Configuration template (copy to .env; .env is not tracked)
```
