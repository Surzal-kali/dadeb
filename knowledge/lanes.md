# Framework Lanes — Five Execution Surfaces

## framework bridge lane

The ONLY path to targets; all security/target work. OWUI tools:
`framework_health`, `framework_search_tools`, `framework_run_tool`,
`framework_memory_search`, `framework_scratch_search`. Scope gate covered
(operator arms it). The model calls `framework_search_tools` first, picks a
`tool_id` from the menu, then calls `framework_run_tool` with that exact
id. Per-turn tool budget enforced (`TOOL_BUDGET_PER_TURN`, default 10).

## execute_code lane

The Jupyter kernel lane. OpenWebUI is configured with Jupyter as the code
interpreter and execution engine. `execute_code` runs in the same daharness
kernel the REPL uses — bare tool names, async wrappers, envelope helpers,
scope gate all wired in. Direct execution: run multi-step chains
programmatically, feeding outputs forward within a single call. No
per-turn budget (kernel talks to the framework directly). See
`knowledge/execute_code.md` for the full contract.

## web lane

Fact query + research only, never recon. No engagement data in any query.
Tools: `search_web`, `fetch_url`.

## file management + terminal lane

The codebase lane; powers the framework. Unscoped, fenced by rule — never a
path to targets. Agent-run, deliberate.

## REPL lane (operator)

`tool_repl.py` — the operator REPL that bypasses the LLM. Two forms: REPL
mode (`run nmap --target 10.10.10.50 -Pn -p 22,445`) and IPython mode
(`await nmap(target="10.10.10.50", options="-Pn -p 22,445")`). Same scope
gate, same tools, same namespace as the Jupyter kernel. Not a chat lane —
operator-driven.