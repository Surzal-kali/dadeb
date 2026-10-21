# daharness

A headless orchestration harness for authorized security research: plug your
own LLM into a registry of 150+ security tools it can search, pick, and run
inside operator-armed scope gates — with target data never leaving your
hardware. The harness ships no conversation model of its own; whatever LLM
you wire into the gateway/MCP/REPL lanes does the driving.

This tree is the **Kali system package**: the framework code, the deb
packaging (`debian/`, `packaging/`), and the man pages. Operator docs live as
man pages — start with `daharness(1)`; per-lane deep dives sit beside the code
as `README.md` files.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

## What it is

One engine — a vector-indexed registry of `@framework_tool` callables and
gate-checked execution — surfaced through four lanes. Pick whichever fits the
moment:

- **API gateway + MCP** — `POST /tools/execute` and a streamable-HTTP MCP
  endpoint for wiring the registry into any external agent harness
- **Tool REPL** — bypass the LLM entirely: pick a tool, pass args, see raw
  output (`daharness-repl(1)` on the deb, `python tool_repl.py` in a checkout)
- **Jupyter kernel** — the same namespace preloaded into notebook cells for
  engagement journals (`daharness-kernel --install-kernelspec`)

The intended workflow is a **hunt lifecycle**: arm a scope → enumerate the
surface → scan in-scope targets → collect evidence → file structured
findings — the scope-compliance and reportability gates hold at every step.

Every dispatch is checked against the operator-armed scope, hard-capped on
the gateway lanes by a per-turn tool budget, and semantic dispatch abstains
when an intent doesn't resolve cleanly. Large tool outputs are projected out
of model context into a durable scratch store with a retrieval reference —
evidence stays queryable without flooding context.

## Why local-only models

The models driving the lanes read target responses: credentials, tokens,
internal IPs, response bodies. A cloud LLM API transmits every one of those
bytes to a third party — unauthorized egress under most programs' ROE and
data-protection law. The framework defaults to a locally hosted Ollama
endpoint; see the [Legal Addendum](#legal-addendum--local-models-only-for-pentesting)
and `daharness-safety(7)`. The same rule applies to the embeddings provider
(`EMBED_URL`) — it receives the text being embedded.

## Quick start (system package)

Prereqs: the deb pulls its own dependencies; Metasploit/ZAP/jadx/radare2 are
optional lanes in `Recommends`. On a fresh install the ChromaDB registry is
**empty** — index it once before anything can search:

```bash
sudo apt install ./daharness_*_<arch>.deb   # current pkg rev: see debian/files

# Re-index the tool registry (fresh install or after apt upgrades add tools)
sudo daharness-index

# Share the state root (/var/lib/daharness — run/, ids.db, scratch, cookie jar)
# with your operator shell; group + mode 2770, docker-socket footwork class
sudo usermod -aG daharness $USER && newgrp daharness

daharness doctor          # per-provider capability report (r2, msf, scanners, ...)
daharness                 # run the services stack (Brain, ZAP, MSF RPC,
                          # Chroma sidecar, gateway)
                          # ... or: sudo systemctl enable --now daharness.service
curl -s 127.0.0.1:5000/health
```

Configure via `/etc/daharness/daharness.env` (**daharness.env(5)** — day-one
set: `EMBED_URL` if not Ollama native, `GATEWAY_API_KEY`
when you want the gateway authenticated). The wrapper `daharness` is also the
CLI: `daharness doctor [provider]` grades lanes with remediation instead of
false "down" reports.

Then drive it — from Open WebUI, any MCP/REST client, or straight from a
shell:

```bash
daharness-repl scope on <program> --platform h1    # arm the scope gate
daharness-repl run <tool_id> --flag value          # one shot, raw output
daharness-repl search "enumerate subdomains"       # semantic tool lookup
```

Unprivileged user-profile lanes (`~/.local/state/daharness`,
`$XDG_RUNTIME_DIR/daharness/brain.sock`) are documented in
**daharness.env(5)**; the optional engagement-Postgres lane is
**daharness-pg(1)**; the JupyterLab/notebook lane is **daharness-kernel(1)**;
the tool-execution model itself is **daharness-tools(7)**; the scope gate,
budgets, and retention story is **daharness-safety(7)**.

## Quick start (from this checkout)

```bash
python -m venv venv && source venv/bin/activate
pip install -e ".[web,jupyter,dev]"   # core runtime + optional lanes + test deps
cp .env.example .env                  # annotated key list; set EMBED_URL etc.
python -m daharness.core              # index the tool registry (--clear to wipe)
python bootstrap.py --daemon          # Brain, ZAP, MSF MCP, Chroma, API gateway
pytest tests/                         # registry + dispatch suite
python tool_repl.py selftest          # same suite via the REPL macro
```

Deb packaging from this tree: `dpkg-buildpackage -us -uc` (see `debian/`).
`packaging/` carries the systemd units, profile script, wrapper entrypoints,
env conffile, Postgres init bundle, and the man-page sources
(`packaging/man/*.md`).

## How dispatch works

- **Discovery** — two passes over the indexed roots (`auxiliaries/`,
  `payloads/`, `listeners/`, `utils/`, `evasion/`): static AST
  analysis mints argparse modules as subprocess tools (never importing them),
  dynamic import mints `@framework_tool` functions/methods as Brain-dispatched
  tools. Every tool carries category tags (`daharness/tool_tags.py`) that ride
  its embedding.
- **Search + dispatch** — semantic search (`ToolRegistry.find_tools`) returns
  ranked manifests; direct dispatch (`find_best_tool`) abstains rather than
  guessing (`ROUTER_MAX_DISTANCE`). Execution passes argument preflight
  (manifest-schema validation), the scope gate, and result projection.
- **Brain sidecar** (`listeners/thebrain.py`) — Unix-socket dispatch core;
  when it's unavailable, tools fall back in-process with cached class
  instances so stateful clients keep their handles. If the Brain accepted a
  call but timed out, the result is a failure — never retried in-process
  (side effects may still be running).
- **Projection + scratch** — oversized/digested results are stored intact in
  the ownership-scoped scratch store; the model gets a compact digest plus a
  ready-to-call continuation ref. Target output is DATA, never instructions —
  untrusted-target tools get stamped provenance
  (`daharness/models.py:ExecutionEnvelope`).

Anatomy, transports, and the envelope contract: `daharness-tools(7)` and
[`AGENTS.md`](AGENTS.md) (agent-facing deep dive).

## External dependencies

The framework wraps external security CLIs as subprocess tools — install the
binary and keep it on `PATH` (the deb `Recommends` covers most):

| Tool | Module | Notes |
| --- | --- | --- |
| **Nmap** | `auxiliaries/nmap.py` | Port/service scanning, NSE scripts |
| **Masscan** | `auxiliaries/masscan.py` | Fast port scanning; root or `CAP_NET_RAW` |
| **OWASP Amass** | `auxiliaries/amass.py` | Subdomain enumeration (v5+, passive default) |
| **OWASP ZAP** | `auxiliaries/zap.py` | Web scanning; daemon launched by `bootstrap.py` |
| **Radare2** | `auxiliaries/radare2.py` | Static analysis; `r2pm -ci r2ghidra` for decompilation |
| **jadx** | `auxiliaries/jadx.py` | APK/dex decompilation (`apk/` drop folder) |
| **Metasploit Framework** | `payloads/metasploiting.py` | MSF RPC client + MCP sidecar |
| **msfvenom** | `payloads/msfvenom_tools.py` | Payload generation (`dropbox/` output) |
| **ffuf / Hydra / sqlmap / searchsploit** | `payloads/` | Fuzzing, brute-force, sqli, ExploitDB lookup |
| **Impacket** | `auxiliaries/impacket_suite.py` | Windows post-exploitation (secretsdump & co) |
| **john / hashcat** | `payloads/hash_crack.py` | Cracking (background-job pattern) |

Python-library lanes (Paramiko SSH, Scapy packetcraft, curl-impersonate
web-session identity) need no extra CLI installs.

## Safety notes

- **Authorized use only.** Scope gates (`utils/scope_gate.py` + the
  HackerOne/Intigriti manifest lane in `auxiliaries/program_scope.py`) reject
  out-of-scope targets, and arming the gate is operator-only — no model lane
  can toggle it. Full policy in `daharness-safety(7)`.
- **No approval gate inside the harness.** The gateway/MCP lanes dispatch
  directly; the conversational model lives in your own client, and an
  integrating harness that wants sign-off adds its own layer in front of the
  gateway.
- **Per-turn tool budget** (gateway lanes, `TOOL_BUDGET_PER_TURN`, default 10)
  with a terminal allowlist so memory/findings stay writable past the cap.
- **No import at discovery time** — static analysis uses `ast` only; hostile
  or broken code cannot execute during indexing.
- **Bounded execution** — Brain dispatch and subprocesses carry timeouts;
  long-running CLI tools use the background-job pattern so a turn is never
  held open.

### Legal Addendum — Local Models Only for Pentesting

> **WARNING — DATA EGRESS RISK.** The driving LLM reads target responses,
> HTTP bodies, command output, and findings. **If that model is hosted on a
> third-party cloud API, every tool output it processes is transmitted to
> that provider.** This includes response bodies from scanned targets,
> extracted credentials, session tokens, internal IPs, and error messages —
> sending them off-box may violate the target organisation's data-handling
> policies, bug-bounty program ROE, data-protection regulations (GDPR, CCPA,
> HIPAA), and NDAs.
>
> **You MUST use a locally-hosted model** (Ollama, llama.cpp, a self-managed
> vLLM) as the driving model for engagements involving live third-party
> targets. Keep the driving-LLM endpoint and `EMBED_URL` pointed at
> loopback/LAN
> infrastructure you control. A cloud embeddings API is target-data egress
> too — the embed endpoint receives the text being embedded, and memory
> contents carry finding material.
>
> Using a cloud-hosted LLM with this framework against a target you do not
> own is a data-handling decision you are solely responsible for. The
> framework authors assume no liability for egress caused by misconfigured
> model endpoints.

## Project layout

```
daharness/              Semantic tool registry + dispatch (core package)
  registry.py           Discovery and semantic search API
  executor.py           Standalone execution helpers
  embedding.py          Provider-agnostic embed lane (EMBED_URL model)
  findings.py           SQLite-backed findings store (FindingStore)
  models.py             ToolManifest + Finding + ExecutionEnvelope models
  preflight.py          Deterministic pre-dispatch validation
  tool_tags.py          Canonical tool category tags + TOOL_TAGS map
constants.py            @framework_tool decorator + TransportType enum
bootstrap.py            Daemon entry point; launches all sidecars (= deb's daharness)
api_gateway.py          FastAPI gateway + streamable-HTTP MCP server (port 5000)
memories.py             ChromaDB-backed namespaced vector memory
tool_repl.py            REPL shim over the replkit/ package (= deb's daharness-repl)
replkit/                REPL internals: completer, aliases, kernel lane, safe args
sitecustomize.py        Vendored-closure import path armer (deb lane)
AGENTS.md               Agent-facing architecture + development guidelines
auxiliaries/            Recon & access lanes (nmap, ZAP, r2, jadx, scope, web session)
payloads/               Offensive lanes (MSF, msfvenom, ffuf, hydra, sqlmap, cracking)
listeners/              Brain sidecar, OOB collaborator, C plugins
utils/                  Harness plumbing (scope gate, projection, scratch, findings)
evasion/                Nmap wire-shaping presets + browser-coherent session identity
knowledge/              Short operator/model reference docs (scope, lanes, findings)
tests/                  pytest suite for registry + dispatch flows
scripts/                Stub generator + dev systemd units
packaging/              Deb payload: wrappers, systemd units, env conffile,
                        Postgres init bundle, man-page sources (packaging/man/)
debian/                 debhelper packaging (rules, control, postinst, conffiles)
apk/ binaries/ dropbox/ pcaps/   Drop folders (READMEs document the lanes)
```

The code directories (`auxiliaries/`, `payloads/`, `listeners/`, `utils/`,
`evasion/`, `knowledge/`, `tests/` and the drop folders) each carry their own
`README.md` with the per-module inventory; `daharness/`, `replkit/` and the
packaging tree document through docstrings, module summaries and man pages
instead. Man-page sources live in `packaging/man/` as `.md` renditions of
the roff pages.
