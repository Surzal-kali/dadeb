---
description: Add a new tool to the daharness framework registry — argparse module, @framework_tool callable, or C/C++ plugin — and re-index it so the model can discover and execute it
applyTo: "**/*.py"
---

# Add a Framework Tool

Pick the tool type based on what the tool does. High-level logic, networking, config → Python. Raw memory, assembly, extreme performance → C/C++ plugin. Anything semantically discoverable and LLM-callable → wrap in `@framework_tool`.

## Option A — argparse module (LOCAL_FILE transport)

1. Create a `.py` file under an allowed root: `auxiliaries/`, `payloads/`, `listeners/`, `utils/`, `evasion/`.
2. Add a module-level docstring — this becomes the embedding text for vector search, so write it descriptively.
3. Use `argparse` with `add_argument` calls — the static AST scanner extracts flags, types, and required-ness into the parameter schema.
4. Re-index: `python -m daharness.core` (or `--clear` to wipe first).

**Important:** the static scanner uses `ast` — it never imports the module. No side effects at import time needed.

**Opt-out:** if the module's argparse is internal plumbing (e.g. a
background-job subprocess runner) rather than an operator-facing CLI,
set `_NO_LOCAL_TOOL = True` at module level — the static scanner skips
the mint, while decorated `@framework_tool` members still register
(`listeners/responder_analog.py` is the reference).

## Option B — @framework_tool function/method (BRAIN_DISPATCH transport)

1. Import `framework_tool` from `constants`.
2. Decorate the function or method. The decorator's first argument is the semantic description — write it for good vector matching, not brevity.
3. Place the module under a Brain scan dir (default: `auxiliaries/`, `listeners/`, `payloads/`).
4. Re-index or restart the Brain sidecar.

```python
from constants import framework_tool, TransportType

@framework_tool("Semantic description of what this tool does.")
def my_tool(target, port):
    ...

# For methods on stateful classes — implement get_instance() classmethod singleton
# so Brain and in-process dispatchers share live handles.
class MyClient:
    @classmethod
    def get_instance(cls):
        ...

    @framework_tool("Does something using this client's live connection.")
    def do_thing(self, target):
        ...
```

## Option C — C/C++ plugin (ctypes wrapper)

1. Write `.c`/`.cpp` in a `plugins/` subdirectory.
2. Compile: `gcc -shared -o plugin.so -fPIC plugin.c`
3. Load via `ctypes.CDLL` in a Python wrapper — **always** set `argtypes` and `restype` explicitly.
4. Use absolute paths built from `Path(__file__).resolve().parent / "plugins" / "name.so"`.
5. Wrap the ctypes call in a `@framework_tool` function for discovery.

## After adding — re-index

Two refresh layers to know about:
- REPL `reindex` refreshes manifests only (`run` sees code edits immediately).
- `python -m daharness.core` refreshes embeddings (semantic `search` finds the new tool). **A doc change is the re-embed signal.**
- Restart the Brain sidecar after re-indexing so the dynamic-discovery pass registers any new `@framework_tool` callables.

## Tags

Every tool carries category tags (canonical vocabulary in `daharness/tool_tags.py:CANONICAL_TAGS`, e.g. `recon.web`, `web.fuzz`, `net.services`). Tag inline via `@framework_tool(doc, tags=[...])` or add to the `TOOL_TAGS` map. Tags are appended to the embedded text and change re-embeds on next index.

## Conventions quick-check

- No module-level side effects in scanned dirs — the Brain's startup scan imports them.
- Sync blocking tools are fine — dispatchers run them in worker threads. Do **not** make a blocking tool async.
- Service/listener tools must **not** block: bind socket, hand serving to `asyncio.create_task()`, return immediately.
- Long-running CLI tools (nmap, masscan, ffuf, hydra, sqlmap) follow the background-job pattern in `utils/background_job.py`: `launch_job` returns a `job_id` immediately; tools come in `run_*` / `*_status` / `*_cancel` triples.
- Stateful clients (SSH, MSF, DB): implement `get_instance()` classmethod singleton.