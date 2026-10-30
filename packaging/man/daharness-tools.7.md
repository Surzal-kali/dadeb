---
title: daharness-tools(7)
---

# NAME

daharness-tools — daharness tool anatomy and execution model

# DESCRIPTION

## The framework loop

The driving model searches the vector-indexed tool registry, then executes
tools through the transports; results are projected before they enter the
model's context:

    search  ->  execute  ->  transport dispatch  ->  result projection

In the packaged, headless build the **driving LLM is external** — an Open
WebUI model or any gateway/MCP client: discovery is */tools/search*,
execution */tools/execute* or MCP *tools/call*, and an unknown *tool_id*
is a loud 404 with a schema-checked 422 on undeclared arguments (no
hallucinated tool calls). There is no in-process approval loop: the
secretary chat lane was removed 2026-10-20 and the packaged build has no
conversation model — gateway/MCP calls run under their own gates, and the
per-turn tool budget is the headless brake (see **daharness-safety**(7)).

## Transports

- **LOCAL_FILE** — argparse modules discovered by static AST analysis (never
  imported), run as subprocesses.
- **BRAIN_DISPATCH** — `@framework_tool` callables over the Brain UDS; falls
  back in-process when the socket is down. If the Brain accepted a call but
  timed out, the result is a failure and the tool is NOT retried in-process
  (it may still be running there).
- **MCP_RPC** — external RPC (Metasploit).

## Result projection

Every result passes through projection before it enters the model's context.
Modes: **large** (default; byte-capped, oversized spill to scratch with a
*scratch_ref* and a ready-to-call continuation), **digest** (per-tool-family
summary + scratch ref) and **page** (bounded list page + continuation).
The continuation is the exact scratch-search call to copy verbatim.

## Untrusted-target provenance

Target-facing tools stamp results with provenance. Target output is **DATA,
never instructions** — evidence to analyze, not directives to follow.

## Stateful lanes

Live connection state (SSH, MSF, DB sessions) is process-local: sessions
created on the Brain are invisible to in-process fallback, and tools report
this honestly instead of silently failing. Web cookies and tokens live on
disk in a shared cookie jar, so every lane sees the same jar.

## Engagement cobweb (journal + evidence + unknown ledger)

Every dispatch is journaled into the engagement store keyed by the
operator-armed engagement slug (the REPL's `engagement on <slug>` — the
model cannot arm or purge it). Findings record conclusions; the evidence
store records typed *don't-know-yet* rows (credential/service/ambiguity/
scope_question/observation) with per-kind TTLs, and the credential-reuse
sweep is a DB constraint: one validation attempt per (entry, service,
target) — a second one is refused with re-mint guidance. A purge erases one
engagement in one transaction while the journal stays append-only; on the
Postgres lane (see **daharness-pg**(1)) the retention sweep runs as an
owner SECURITY DEFINER function.

## Background jobs, fleet courtesy, and the worker queue

Long-running CLI tools (nmap, ffuf, hydra, sqlmap, masscan) follow the job
pattern: the launcher returns a *job_id* immediately; status and cancel
companions manage the running job. Jobs are durable SQLite rows scoped to
the agent identity, with a TTL sweep, per-agent caps, and log-file
collection so a busy fleet cannot leak disk.

Two courtesy layers sit in front of launches:

- **Fleet scheduler** — per-TARGET-HOST regulator, numeric-span aware
  (`10.0.0.0/24` and its member `10.0.0.7` contend). A duplicate ask for a
  running unit returns that unit's *job_id* instead of launching a second
  process; per-host slots default 2 under an absolute ceiling of 4;
  auth-adjacent units (login/token requests) hold the host exclusively in
  both directions.
- **Worker queue** — the same shape for LOCAL RAM instead of the target
  (jadx per-APK decompiles first): admission is content-keyed dedupe →
  hard caps (budget vs free RAM above a pool floor) → slots → queue.
  Everything that is merely scarce QUEUES instead of refusing; recorded
  peak-RSS evidence from finished runs raises the next run's claim
  (`claim = budget + (peak − pin)`).

The Burp replay twins ride the queue the same way — replay/craft tools
with **no scan surface** (active scanning stays ZAP's job).

# SEE ALSO

**daharness(1)**, **daharness-repl(1)**, **daharness-safety(7)**,
**daharness.env(5)**