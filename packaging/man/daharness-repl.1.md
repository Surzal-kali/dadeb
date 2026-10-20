---
title: daharness-repl(1)
---

# NAME

daharness-repl — operator REPL and one-shot lane for the daharness framework

# SYNOPSIS

**daharness-repl** [*run|search|scope|engagement* ...]
**daharness-repl** **run** *tool_id* [*--flag* *value* ...] — one-shot exit

# DESCRIPTION

The operator seat (also *tool_repl.py*, which keeps its filename — kernelspec
argv, systemd unit and refresh stubs depend on it). The operator chooses and
invokes tools directly — there is no LLM in this lane and no approval gate,
because the operator **is** the approval.

Interactive commands and modes:

**run** *tool_id* [*--flag* *value* ...]
: Execute a tool; flags follow its manifest parameter schema.

**search** *query*
: Semantic search over the tool registry (candidate manifests, no execution).

**reindex**
: Refresh tool *manifests* only. Semantic embeddings stay stale until the
  full index rebuild (`python -m daharness.core`); restart the Brain after.

**scope** **on**|**off** *handle*
: Arm the scope gate for a target handle — the ONLY arming surface; the state
  is never togglable by the LLM. See **daharness-safety(7)**.

**engagement** **on**|**off** *slug*
: Arm the engagement cobweb key that ties journal, evidence and findings rows
  together; arming is deliberately REPL-only. See **daharness-safety(7)**.

# DEPENDENCIES

The interactive embed (`ipython` command) hard-imports IPython; the deb
ships **python3-ipython** as Depends (shared with
**daharness-kernel(1)**'s python3-ipykernel requirement). In a checkout:
`pip install -e ".[jupyter]"`.

# SEE ALSO

**daharness(1)**, **daharness-kernel(1)**, **daharness-index(1)**,
**daharness-tools(7)**, **daharness-safety(7)**