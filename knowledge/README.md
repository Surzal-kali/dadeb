# Framework Knowledge Directory

Version-controlled operational guides loaded into Open Web UI's knowledge
collection at container startup. The directory is bind-mounted into the
`open-webui` container (see `dockered/docker-compose.yaml`) and OWUI's RAG
pipeline handles chunking, embedding (`nomic-embed-text` via Ollama), and
context-top injection — the same way the `repl-bank` knowledge collection
works, minus the manual upload step.

## Why a directory, not an endpoint?

Embeddings need to land inside OWUI (the chat frontend), not behind a
gateway endpoint the model has to know to call. The schema-knowledge gap is
that OWUI's chat has no built-in schema/tool awareness at init — every
other surface (linters, VS Code, nvim, Jupyter) gets it from the runtime,
but the chat frontend only gets what the system prompt + knowledge
collections provide. This directory is the version-controlled source for
that knowledge; OWUI's own RAG is the delivery mechanism.

## File conventions

- One topic per file, sectioned by `##` headings (OWUI's RAG chunks by
  heading/paragraph — descriptive headings improve retrieval).
- Keep headings descriptive — they're what OWUI's semantic matcher scores
  against. `## ids.db schema` matches "database schema" better than `## DB`.
- Cross-reference source files (`schema.md`, `AGENTS.md`, `SYSTEM_PROMPT.md`)
  by name so the model can follow up with the full doc if needed.
- No engagement data, no target specifics — assistant-ops knowledge only
  (same scope rule as the `repl-bank` knowledge collection).

## Syncing

The bind mount keeps the container's view live with the repo — edit a file
and re-sync the OWUI knowledge collection (OWUI's UI has a re-embed action
per collection, or restart the container). The directory IS the index; no
embedding store in the framework, no sync script, no gateway endpoint.