---
title: daharness-safety(7)
---

# NAME

daharness-safety — daharness safety model: scope gate, approvals, budgets, retention

# DESCRIPTION

## Scope gate (operator-armed only)

Traffic-sending tools resolve every target through an operator-armed scope
state. Arming happens ONLY at the operator REPL (`scope on <handle>`) and is
deliberately NOT exposed as an LLM-callable tool, so the secretary can never
toggle it. State persists across processes (the REPL can re-arm a running
Brain). Blocked targets raise a scope error instead of transmitting.

## Human-in-the-loop approval

Tool execution from the secretary is gated by an approval loop: the run
pauses until the confirmer approves the exact manifest + arguments, capped by
SECRETARY_MAX_APPROVAL_ROUNDS. Tool calls through the API gateway or MCP
bypass this lane by design — those lanes carry the per-turn budget instead.

## Per-turn tool budget

Gateway lanes (REST/MCP/Open WebUI) enforce a hard cap on tool executions per
turn; the final allowed call is wrapped with a directive to report findings
and end the turn; further calls are refused with structured guidance (not a
transient error). Terminal-lane tools (memory, findings, unknowns) stay
callable past the cap so the model can comply.

## Local-only LLM policy

The secretary runs on a locally hosted model (Ollama, loopback/LAN) — never a
cloud LLM API. Tool outputs from live targets (credentials, tokens, internal
IPs) must not egress to third parties.

## Engagement cobweb

An engagement's rows (journal, evidence, findings, unknowns) unify under one
slug, so a purge erases one engagement in a single transaction while the
journal audit trail stays append-only until the operator closes it. Arming is
REPL-only.

## Credential-reuse sweep

Every recovered credential gets ONE validation attempt against each other
reachable service before deeper work resumes — logged as findings, auditable
in the evidence store.

# SEE ALSO

**daharness-repl(1)**, **daharness-tools(7)**, **daharness.env(5)**