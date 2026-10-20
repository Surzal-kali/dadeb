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
hallucinated tool calls). The approval-gated secretary lane remains an
in-tree interactive lane only (`daharness.core --chat`); gateway/MCP calls
bypass it — the per-turn tool budget is the headless brake (see
**daharness-safety**(7)).

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

## Background jobs

Long-running CLI tools (nmap, ffuf, hydra, sqlmap, masscan) follow the job
pattern: the launcher returns a *job_id* immediately; status and cancel
companions manage the running job.

# SEE ALSO

**daharness(1)**, **daharness-repl(1)**, **daharness-safety(7)**,
**daharness.env(5)**