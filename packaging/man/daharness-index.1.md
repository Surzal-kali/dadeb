% DAHARNESS-INDEX(1) daharness 0.1.0 | daharness manual

# NAME

daharness-index — build or refresh the semantic tool-registry index

# SYNOPSIS

**daharness-index** [--clear] [--chat]

# DESCRIPTION

The packaged deb ships an **empty** tool registry: the chroma collection
`tool_inventory` starts unpopulated and nothing fills it for you (the
services daemon never indexes — indexing was removed from its boot path
deliberately). **daharness-index** is the operator's one-typing pass that
builds it: discovery (static AST sweep + `@framework_tool` dynamic scan)
over the installed tree, embedding of every manifest through Ollama, and
upsert into the chroma collection that every discovery lane reads —
*tools/search*, *tools/execute* (exact-id and semantic), */mcp*
*tools/list*, the operator REPL, and memory recall.

Before doing any work it probes its two live dependencies and prints the
exact fix rather than a traceback: the chroma registry backend (the
*daharness* daemon's own sidecar — or a manual *daharness-chroma* lane
when running outside the service) and the Ollama host with the embed
model (default **nomic-embed-text**). Probe knobs are read from
/etc/daharness/daharness.env (CHROMA_PORT, EMBED_MODEL,
OLLAMA_BASE_URL), so a conffile retune is honored. The indexer writes
only through the chroma HTTP server, so it runs as **any user** — no
sudo needed (unless your conffile points at something privileged).

Re-runs are idempotent (upsert by tool id): newly added tools appear
without rebuilding. **--clear** wipes the collection first, for
from-scratch rebuilds. Embedding the ~97-tool universe takes on the
order of a minute against a local Ollama host.

An empty or stale registry is not an error for the gateway —
*tools/search* just finds nothing and *tools/execute* 404s an unknown
*tool_id*, which is exactly what a fresh install looks like before this
command has run once.

# OPTIONS

**--clear**
: Delete the collection contents before re-indexing.

**--chat**
: Drop into the in-tree interactive secretary chat lane instead of
  indexing (dev-tree convenience; the packaged headless build has no
  chat model consumer).

# FILES

/etc/daharness/daharness.env — read (tolerantly) for the probe knobs.

# SEE ALSO

**daharness(1)**, **daharness-repl(1)**, **daharness-tools(7)**,
**daharness.env(5)**