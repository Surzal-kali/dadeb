% DAHARNESS-INDEX(1) daharness 0.1.0 | daharness manual

# NAME

daharness-index — build or refresh the semantic tool-registry index

# SYNOPSIS

**daharness-index** [*--clear* | *--chat*]

**daharness-index** *--stubs* [*--check*]

# DESCRIPTION

The packaged deb ships an **empty** tool registry: the SQLite vector
store `tool_inventory` starts unpopulated and nothing fills it for you (the
services daemon never indexes — indexing was removed from its boot path
deliberately). **daharness-index** is the operator's one-typing pass that
builds it: discovery (static AST sweep + `@framework_tool` dynamic scan)
over the installed tree, embedding of every manifest through the embed
endpoint, and upsert into the registry that every discovery lane reads —
*tools/search*, *tools/execute* (exact-id and semantic), */mcp*
*tools/list*, the operator REPL, and memory recall.

Before doing any work it probes its live dependency and prints the
exact fix rather than a traceback: the embed endpoint (EMBED_URL, default
http://localhost:11434/api/embed) with the embed model (default
**nomic-embed-text**). Probe knobs are read from
/etc/daharness/daharness.env (EMBED_MODEL, EMBED_URL),
so a conffile retune is honored. The indexer writes to a local SQLite
file (tool_registry.db under the workspace root), so it needs filesystem
write access to the state root (run as root on the deb lane, or as a
member of the daharness group).

Re-runs are idempotent (upsert by tool id): newly added tools appear
without rebuilding. **--clear** wipes the collection first, for
from-scratch rebuilds. Embedding the ~97-tool universe takes on the
order of a minute against a local Ollama host.

An empty or stale registry is not an error for the gateway —
*tools/search* just finds nothing and *tools/execute* 404s an unknown
*tool_id*, which is exactly what a fresh install looks like before this
command has run once.

# THE STUB VIEW (--stubs)

`daharness-index --stubs` generates the static-analysis view of the same
registry: pyright stubs (a `.pyi`, a PEP 562 shim, and a builtins fork) for
the kernel- and REPL-injected tool aliases, plus the ruff `builtins` block
for the notebook lane. Injected names do not exist until discovery runs, so
without this pass an editor flags *every framework call* undefined — the
stubs close that gap from the alias/signature pipeline verbatim, so they
cannot drift from what actually executes.

This lane is **offline compute** (static AST + dynamic import — no embed
endpoint), so it routes *before* the index probes: a down embed host
never blocks it. The one prerequisite it enforces itself is a
complete typeshed `builtins.pyi` to fork (the Pylance-extension, wheel-pyright, or
the deb's own bundled `scripts/pyright_typeshed_builtins.pyi` copy) —
refused loudly rather than shipping a partial fork that un-defines `print`/`len`. Output lands in *FRAMEWORK_STUBS_DIR*
(default **~/.local/share/framework-stubs**) — point your editor's
`stubPath` there. `--check` reports OK/STALE — and SKIP for the
checkout-only *ruff.toml* builtins block, whose file the deb does not ship
and therefore cannot regenerate — without writing anything. Run it after
adding tools, or whenever hover/completion drifts from what the kernel
actually injects.

    daharness-index --stubs --check

# OPTIONS

**--clear**
: Delete the collection contents before re-indexing.

**--chat**
: Drop into the in-tree interactive secretary chat lane instead of
  indexing (dev-tree convenience; the packaged headless build has no
  chat model consumer).

**--stubs**
: Route to the stub generator (offline lane; see THE STUB VIEW above).
  Generator flags pass through, e.g. `--stubs --check`. Honors
  *FRAMEWORK_STUBS_DIR* for the output directory.

# FILES

/etc/daharness/daharness.env — read (tolerantly) for the probe knobs.

*~/.local/share/framework-stubs/* — the --stubs lane's default output
directory (FRAMEWORK_STUBS_DIR overrides).

# SEE ALSO

**daharness(1)**, **daharness-repl(1)**, **daharness-kernel(1)**,
**daharness-tools(7)**, **daharness.env(5)**