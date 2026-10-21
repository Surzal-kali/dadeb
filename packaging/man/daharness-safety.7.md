---
title: daharness-safety(7)
---

# NAME

daharness-safety — daharness safety model: scope gate, approvals, budgets, retention

# DESCRIPTION

## Scope gate (operator-armed only)

Traffic-sending tools resolve every target through an operator-armed scope
state. Arming happens ONLY at the operator REPL (`scope on <handle>`) and is
deliberately NOT exposed as an LLM-callable tool, so no model lane can
toggle it. State persists across processes (the REPL can re-arm a running
Brain). Blocked targets raise a scope error instead of transmitting.

## Human-in-the-loop approval

There is no in-process approval loop: the secretary chat lane (pydantic-ai)
was removed 2026-10-20. Tool calls through the API gateway or MCP execute
under their own gates — the operator-armed scope gate, the per-turn budget
and the ROUTER_MAX_DISTANCE abstention. An integrating harness that wants
sign-off adds its own approval in front of the gateway.

## Per-turn tool budget

Gateway lanes (REST/MCP/Open WebUI) enforce a hard cap on tool executions per
turn; the final allowed call is wrapped with a directive to report findings
and end the turn; further calls are refused with structured guidance (not a
transient error). Terminal-lane tools (memory, findings, unknowns) stay
callable past the cap so the model can comply.

## Gateway bind + auth posture

The REST/MCP gateway binds GATEWAY_HOST:GATEWAY_PORT — loopback
(127.0.0.1:5000) in this profile. GATEWAY_API_KEY arms key auth
(X-API-Key or Bearer) over the whole REST + /mcp surface; the packaged
profile generates a random key at install (postinst), so a stock deb
never boots an off-host tool-execution gateway unauthenticated.

With or without a key, /docs, /redoc, /openapi.json and /health stay
unauthenticated by design (spec + liveness reachability) — remember this
when widening the bind: anything on 0.0.0.0 advertises the full API
surface shape via openapi.json. Unauthenticated AND non-loopback
together logs a boot-time error rather than serving silently.

## Local-only LLM policy

The models driving the lanes (Open WebUI conversation model, embedding
model) run on a locally hosted endpoint (Ollama, loopback/LAN) — never a
cloud LLM API. Tool outputs from live targets (credentials, tokens, internal
IPs) must not egress to third parties.

## Engagement cobweb

An engagement's rows (journal, evidence, findings, unknowns) unify under one
slug, so a purge erases one engagement in a single transaction while the
journal audit trail stays append-only until the operator closes it. Arming is
REPL-only.

## Engagement-Postgres lane (optional)

Off by default: no Postgres server ships; the journal runs on the SQLite
stores. `sudo daharness-pg init` provisions a **dedicated** Postgres
cluster (`daharness`, port 5433) whose fate msfdb can never touch (msf's
own `main` cluster keeps 5432), creates one no-superuser LOGIN role per
lane (harness_operator/brain_lane/gateway_lane/repl_lane), and mints
random per-role passwords into `/etc/daharness/pg.env` (0640
root:daharness). Lanes hold INSERT/SELECT (+ evidence UPDATE); **no lane
ever holds DELETE** — purge runs as a SECURITY DEFINER owner function the
operator alone calls. The server listens on loopback only with password
auth (scram-sha-256 on current Kali's PG 18); the operator REPL reaches it
via group membership. Postgres
absent or the cluster down = honest degrade back to SQLite stores, logged
once, never a crash.

## Credential-reuse sweep

Every recovered credential gets ONE validation attempt against each other
reachable service before deeper work resumes — logged as findings, auditable
in the evidence store.

# SEE ALSO

**daharness-repl(1)**, **daharness-tools(7)**, **daharness.env(5)**,
**daharness-pg(1)**