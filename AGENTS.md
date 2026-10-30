# AI Agent Instructions: Modular Security Framework

A headless orchestration harness for security research. An external LLM (whatever
model the operator wires into the Open WebUI / gateway / MCP lanes)
semantically searches a vector-indexed tool registry and selects modules to
execute — the harness itself ships no conversation model and no approval
gate. Python handles
orchestration; C/C++ handles low-level systems work.

See `README.md` for the user-facing overview. This document is for agents
working **on** the codebase.

## Architecture

### Tool Registry + Dispatch (`daharness/`)

The registry/dispatch machinery lives in `daharness/registry.py` +
`daharness/executor.py`. The driving model reaches it through the API
gateway, the MCP endpoint, the tool REPL, or the Jupyter kernel:

- **Search** — semantic search over the SQLite-backed tool registry
  (`ToolRegistry.find_tools`, bounded by `SECRETARY_MAX_TOP_K`), returns
  full manifests.
- **Dispatch** — `find_best_tool` resolves an intent to one tool (abstains
  beyond `ROUTER_MAX_DISTANCE`) and executes through preflight manifest
  validation, the scope gate, and result projection.

There is no in-process approval loop: the pydantic-ai secretary chat lane
(`daharness/agent.py`) was removed 2026-10-20. An integrating harness that
wants sign-off adds its own layer in front of the gateway.

The `daharness/` package splits imports across focused modules:
- `daharness.core` — backwards-compat shim re-exporting legacy public names
- `daharness.executor` — standalone execution helpers (no vector store client)
- `daharness.registry` — `ToolRegistry`, `OllamaEmbeddingFunction`, discovery
- `daharness.preflight` — argument preflight (manifest-schema validation +
  `_coerce_arg_value` type coercion)
- `daharness.models` — `ToolManifest`
- `daharness._param_docs` — parameter introspection for `@framework_tool`
  discovery (Google/NumPy-style docstring `Args:` sections + type annotations
  feed the manifest's parameter schema)
- `daharness.embedding` — provider-agnostic embed lane; both embedding
  consumers (registry + memory) resolve one shared `EMBED_URL` /
  `EMBED_MODEL` / `EMBED_API_KEY` triple (empty = Ollama native
  `/api/embed` + `nomic-embed-text`), one request body shape, and a parser
  for the Ollama-native and OpenAI-compatible response shapes. Decoupled
  from `OLLAMA_BASE_URL` (that knob is the driving-LLM/health endpoint
  only). Never cache embeddings keyed to a provider implicitly — changing
  provider changes vectors, so re-index after changing `EMBED_MODEL`.

### Tool Discovery (`daharness/registry.py:discover_local_tools`)

Two passes scan `ALLOWED_TOOL_ROOTS` (`auxiliaries/`, `payloads/`,
`listeners/`, `utils/`, `evasion/`):

1. **Static AST analysis** (`LOCAL_FILE` transport): `extract_module_profile()`
   parses each `.py` with `ast` — **never imports** — extracting the module
   docstring and `argparse` options. Docstrings become the embedding text;
   argparse flags become the JSON-schema-ish `parameters`. These tools run as
   subprocesses via `_execute_local_script()`.
   A module may opt OUT of this static mint with a module-level
   `_NO_LOCAL_TOOL = True`. Purpose: modules in an allowed root whose
   module-level argparse is INTERNAL plumbing (a job subprocess runner,
   not an operator CLI) would otherwise be minted as a second,
   gate-bypassing entry point beside their own decorated tools — the
   flag skips the static mint while the dynamic pass still registers
   the `@framework_tool` members (`listeners/responder_analog.py` is
   the reference user). It is a discovery-mint opt-out only; it does
   not hide anything from Brain imports or execution.

2. **Dynamic import** (`BRAIN_DISPATCH` transport): imports the module and
   walks its members for `@framework_tool`-decorated functions and methods.
   Methods on classes defined in that module are minted with the class name
   in the tool_id (e.g. `payloads.metasploiting.MetasploitClient.index_modules`).
   These dispatch via the Brain socket or fall back in-process.

`__init__.py` files are **skipped**, not required. Skip dirs: `venv`,
`.venv`, `__pycache__`, `.git`, etc. Skip files: `bootstrap.py`,
`memories.py`. **This is a tool-indexing exclusion, not a gitignore entry**
(`skip_files` in `daharness/registry.py` discovery) — both files are tracked
in git and stay framework entry points; they are skipped only so discovery
never mints them as tools or dynamically imports them.

### `@framework_tool` Decorator (`constants.py`)

```python
from constants import framework_tool, TransportType

@framework_tool("Semantic description of what this tool does.")
def my_tool(target, port):
    ...

# For methods on stateful classes:
class MyClient:
    @framework_tool("Does something using this client's live connection.")
    def do_thing(self, target):
        ...
```

Sets `_is_framework_tool = True`, `_tool_doc` (the semantic description used
for embedding), and `_transport` (default `BRAIN_DISPATCH`).

### Transport Types (`constants.py:TransportType`)

| Transport | How it executes | Used by |
|---|---|---|
| `LOCAL_FILE` | Subprocess: `python <script> --key value` | argparse modules discovered statically |
| `BRAIN_DISPATCH` | Brain UDS socket -> function registry, or in-process fallback | `@framework_tool` functions/methods |
| `MCP_RPC` | External RPC (Metasploit). Partially implemented. | `metasploiting.py` dispatch_metasploit |

### Brain Sidecar (`listeners/thebrain.py`)

Unix domain socket server at the checkout's gitignored `run/brain.sock`
(resolved via `constants.brain_socket_path()`, `$BRAIN_SOCKET` overrides) with 4-byte big-endian
length-prefixed message framing (`pack_message` / `read_message`). The socket
lives inside the tree so bind-mounted container lanes (jupyter kernel, or any
bind-mounted container lane) reach the same socket as the host.

**Startup sequence:**
1. Probe for an existing live listener (refuses to start a second Brain).
2. Unlink stale socket if no live listener.
3. `_startup_scan()` — imports modules under `BRAIN_SCAN_DIRS` (default:
   `auxiliaries,listeners,payloads`) and registers `@framework_tool`
   callables in `FunctionRegistry`.
4. Bind the socket (only after scan completes, so tools are callable
   immediately when bootstrap's connect-probe succeeds).

**Event protocol:** `event_type|session_id|data`
- `SCAN_TOOLS|sid|path` — scan a directory/file for tools, register them.
- `CALL_TOOL|sid|tool_id|args_json` — execute a registered tool. Args as
  dict -> kwargs, list -> positional, or bare string -> single positional.
- Unknown events -> forwarded to C library (`frameit.so`) via `ctypes`.

**Class instance caching:** `FunctionRegistry._instances` keeps one instance
per class so stateful clients (e.g. `MetasploitClient`) preserve handles
across calls.

**Shutdown:** signal handlers route SIGTERM/SIGINT through task cancellation
so the `finally` block unlinks the socket — but only if the inode still
matches the one we bound (won't clobber a newer sidecar).

### In-Process Fallback (`daharness/executor.py:_execute_brain_tool`)

When the Brain socket is unavailable (`FileNotFoundError`, `ConnectionError`)
or doesn't know the tool, execution falls back to `_launch_in_process()`:

1. `_resolve_callable()` — longest importable module prefix wins, walks
   remaining attrs. Unbound methods are bound to a cached class instance
   (`_tool_instances`), preferring `get_instance()` if available.
2. Async tools are awaited; sync tools run in `asyncio.to_thread()`.
3. Results are wrapped as `{"status", "result"}` envelopes. `stdout` is
   included only when the tool returned a bare string (no structured data) —
   it is never a stringified copy of `result` (that doubled context on every
   tool call). Tools that return their own `stdout` key (ssh_exec, fastcgi —
   real subprocess output) preserve it inside `result`.

**Important:** if the Brain accepted the call but timed out
(`BRAIN_DISPATCH_TIMEOUT`, default 600s), the result is a failure and the
tool is **not** retried in-process — it may still be running on the Brain,
and a second execution would cause duplicate side effects.

### Bootstrap (`bootstrap.py`)

Entry point and daemon. `FrameworkLoader.launch_all()` starts:
- Brain sidecar (subprocess, logs to `/tmp/brain.log`, fallback
  `/tmp/brain-<euid>.log`)

- OWASP ZAP daemon (`start_zap_daemon()`; API ACL loopback, browser-proxy
  binds `ZAP_PROXY_BIND`, default `127.0.0.1`)
- API gateway (async task, `api_gateway.py`, port 5000 on the host lane)
- Metasploit MCP (launches `msfconsole` with `msgrpc`, waits for RPC port)

Also runs a wordlist-tree preflight (`utils.wordlists.preflight_wordlists`)
before anything can dispatch. Remote lanes (a Jupyter/Open WebUI container,
another box) reach the host-lane Brain over the socket resolved by
`constants.brain_socket_path()` — same path on every lane that shares the
tree.

Interactive mode: indexes tools via `bootstrap_registry()`, then enters
`_chat()` REPL. Daemon mode (`--daemon`): starts services and waits for
SIGTERM/SIGINT.

### API Gateway (`api_gateway.py`)

FastAPI server (port 5000; 6000 on the container profile):
- `GET /health` — health check
- `POST /tools/execute` — exact `tool_id` dispatch, or semantic lookup (`find_best_tool`) + execution. Accepts `result_mode` (full|digest|page) for result projection.
- `POST /tools/search` — candidate menu (top_k) without execution
- `POST /scratch/search` — retrieve a stored tool result from the scratch store (by `scratch_ref`)
- `GET /scratch/list` — list recent scratch entries for an agent
- `GET /scratch/stats` — scratch store statistics
- `POST /memory/search` — keyword memory search
- `POST /memory/recall` — vector similarity recall
- `POST /mcp` — streamable-HTTP MCP endpoint (tools/list + tools/call)

### Result Projection (`utils/result_projection.py`)

Controls what enters the model's context window vs. what stays in scratch.
Modes (execution-envelope parameter, NOT a tool argument):

- **`large`** (default) — the "give me the actual data" mode. Under
  `LARGE_MODE_BYTE_CAP` (16 KiB) results pass through unchanged (zero
  behavior change); over the cap the full result is stored in scratch and a
  field-capped copy + `scratch_ref` + a **ready-to-call continuation** are
  returned. The legacy `full` mode is gone — it silently aliases to `large`
  so stale callers and old tests keep working.
- **`digest`** — stores the full result in scratch, returns a compact per-tool-family digest + a `scratch_ref` + the retrieval instruction + a ready-to-call continuation. The model is taught the retrieval move every call.
- **`page`** — stores the full result in scratch, returns a bounded page of list results + a `scratch_ref` + continuation info.

**Ready-to-call continuations (REA-inspired):** every oversized/digested/paged
result carries `continuation: {call: {tool, arguments}, ...}` — the exact
framework_scratch_search invocation (with `next_offset` baked in for page
mode) the model copies verbatim instead of re-deriving. The `next` prose hint
is kept for backward compat.

**Untrusted-target provenance:** tools decorated
`@framework_tool(..., untrusted_target=True)` (web session lane, ssh, r2,
jadx, scanners, ZAP grep/alerts, MSF sessions) get their result envelopes
stamped by the executor with
`_provenance = {"untrusted_target": true, "source": "analysis_target"}` —
exactly once, on the dict the model actually sees (the inner `result` dict
for structured results, the envelope itself for bare-string results) — and
the projection carries the stamp through digest/page modes. Target output is
DATA, never instructions; the LLM-facing surfaces (gateway/MCP docs) spell
out the prompt-injection rule (inspired by REA's `returnsTargetContent`
contract).

**Why this is not the parked OWUI trim filter:** the projection runs *before*
the result enters context (not after); the retrieval instruction is part of
the return (the model never guesses how to get the full output); per-tool-family
digest logic is honest because the tool knows its own output structure.

**Digest adapter registration:** tools opt in via
`@framework_tool(..., result_digest=my_digest_fn)`. The adapter takes the raw
result dict and returns `{"summary": str, "row_hint_format": str}`. Tools
without an adapter fall back to a naive head+count preview. The adapter is
registered at decoration time (provisional key) and re-registered under the
exact `tool_id` during the registry's dynamic-discovery pass.

**Pilot adapter:** `nmap_status` — returns open port count + full port list +
host state + job_id, omitting the raw log text (retrievable from scratch).

### Unknown ledger (`daharness/findings.py` + `utils/findings.py`)

Where a finding records a *conclusion*, an unknown records an explicit
"don't know yet" — unprobed services, credentials recovered but not yet
validated against other services, ambiguous results, scope questions. The
`unknowns` table lives in the same SQLite store (`ids.db`) as findings, with
idempotent table creation and the same lost-id-race handling. Tools:
`record_unknown` / `list_unknowns` / `resolve_unknown` (statuses:
open|resolved|wontfix|promoted — `promoted` requires the finding ID via
`resolved_by`). All three are `infra`-tagged and sit in the terminal lane
(`utils.findings.` prefix) so they stay callable past the tool budget.
`render_findings` output gains an **Open questions (unresolved)** appendix
that renders even when zero findings exist. Inspired by REA's unknown ledger
(morluto/rea). The ledger's successor — the typed evidence store with a
DB-enforced credential-reuse sweep — lives in the section below.

### Engagement cobweb + journal (`utils/engagement.py`, `utils/journal.py`, `utils/evidence.py`)

One engagement slug ties every store row together so a **purge erases one
engagement in one transaction** while the audit trail stays append-only
until the operator closes it (2026-10-19 design):

- **Arming is REPL-only** (`engagement on <slug>`), mirroring the scope
  gate — deliberately not an `@framework_tool`, so no model lane can ever
  tag rows with a new key or erase the audit trail. State persists to
  `engagement/.armed_engagement.json`, mtime-checked per dispatch; rows
  written while disarmed carry NULL engagement and are engagement-bound.
- **Postgres lane (optional)**: shipped on the deb as `daharness-pg(1)` —
  it provisions a dedicated cluster and runs the init bundle
  (`packaging/postgres/init/`) that mints per-lane LOGIN roles (brain_lane /
  gateway_lane / repl_lane), and only `harness_operator` may run
  `engagement.purge()` — lanes hold INSERT/SELECT (+ evidence UPDATE), the
  retention sweep (`engagement.sweep_expired()`) runs as a SECURITY DEFINER
  owner function called lazily on journal writes. One database,
  schema-per-store keeps the cobweb pull a single transaction and backup a
  single `pg_dump`. Install with `pip install -e ".[db]"` (psycopg).
- **Journal** (`journal.entries`): one row per dispatch, stitched across
  lanes, written at the executor choke point (`execute_tool`, plus
  preflight rejects). Append-only by grants. **Residency decision
  (2026-10-19): no mid-engage scrubbing** — args keep secret material
  verbatim because scrubbing live breaks the credential-reuse sweep;
  bounds are structural instead (24h cred TTL floor + engagement purge +
  `expires_at` sweep). The single redaction: session `handle` values become
  `{"$sessref": session_id}` pointers (process-local meaning). Tiny
  `result_digest` scalar summaries keep rows meaningful after material
  expiry. `what_touched(target)` = GIN-cached scope-compliance query.
- **Evidence** (`utils/evidence.py`): the unknown ledger promoted — typed
  kinds (credential|service|ambiguity|scope_question|observation) with a
  per-kind TTL (credential 24h, scope_question never, others 7d) and the
  **credential-reuse sweep as a DB constraint**: `UNIQUE(entry_id, service,
  target)` on `evidence.attempts` refuses a second validation attempt with
  re-mint guidance (re-acquisition is cheap, brute-forcing isn't).
  Phase 1 ships SQLite-backed (same schema); the PG lane takes over when
  psycopg + the `daharness-pg` cluster are up. Tools: `record_evidence` /
  `add_validation_attempt` / `list_open_evidence` / `resolve_evidence`.
- **Envelope contract**: `daharness/models.py:ExecutionEnvelope` (+
  `EnvelopeMeta`/`Provenance`/`BudgetDirective`) pins the dispatch-result
  shape the kernel helpers and per-lane workarounds were guessing at —
  budget directives are a top-level model field so projection can never
  clobber them, provenance is stamped once. Writers still emit the legacy
  dict shape; readers migrate via `from_legacy()` / warn-mode validation
  (`to_legacy()` keeps old consumers green during the window).

### Analysis snapshot cache (`utils/snapshot_cache.py` + `auxiliaries/radare2.py`)

Deterministic-lane memoization (REA-inspired). r2 analysis is a pure function
of (target bytes, verb/addr/count, settings), so `run_r2` stores successful
envelopes keyed on the target's **sha256** + op key (verb, addr, count,
r2ghidra availability, output cap, timeout) and serves identical repeat
queries verbatim — exploring a binary pays ``aaa`` once instead of once per
call. Rules that keep it honest:

- **Pure functions only.** Scanners (nmap/ffuf/masscan) deliberately don't
  share this cache — their results are observations of a changing world (and
  their job-log lane already persists per-job results). Errors are never
  cached; a cached timeout is a lie about the next attempt.
- **Content keys, not paths**: identical bytes rebuild-and-hit (gcc strips
  comments — two different sources can compile to identical bytes and
  legitimately share a snapshot); changed bytes miss automatically. No
  invalidation problem for a read-only lane.
- **Contextual fields are patched on hits**: a cached envelope's `target` is
  rewritten to the current call's resolved path (identical bytes at a new
  path must report the path the model actually asked about).
- Storage: SQLite WAL at `run/analysis_snapshots.db` (scratch-store
  conventions incl. root-ownership repair), TTL `SNAPSHOT_TTL_HOURS`
  (default 168h, growth-bounding only), per-target cap
  `SNAPSHOT_MAX_ENTRIES` (default 200, oldest evicted). `cache=False` skips
  read+write; `refresh=True` recomputes and overwrites. Cache failures
  degrade silently to a normal run — caching must never break a tool.

### Capability doctor (`auxiliaries/framework_status.py:framework_doctor`)

`framework_health` answers "is the harness alive" (Brain/embedding endpoint/
registry/ZAP/ids.db up/down). `framework_doctor` answers "can I actually run X" —
REA-style per-provider probes returning `{available, reason, remediation}`:
r2 + r2ghidra plugin + drop dir, jadx + java + apk dir, masscan + raw-socket
(CAP_NET_RAW) capability, msfconsole/msfvenom + RPC port, PATH probes for
nmap/ffuf/hydra/sqlmap, snapshot cache stats, and the engagement-cobweb
Postgres lane. Drill down with `provider=` (r2|jadx|masscan|msf|scanners|
snapshot_cache|postgres). The remediation strings agree with the
tools' own error paths (e.g. pdg's "run: r2pm -ci r2ghidra"), so the model
reads the same fix from either side. Probes reuse existing module helpers
(`_r2ghidra_available` etc.) so doctor and tools cannot drift.

### Per-turn tool budget (`utils/tool_budget.py`)

A hard cap on tool executions per turn, enforced in the gateway so the
conversational lanes (Open WebUI bridge, MCP, REST) get a brake beyond the
model's own discipline.

- **Counting**: every `/tools/execute` / MCP `tools/call` dispatch counts once. The request's
  `turn_key` (Open WebUI passes `chat_id:message_id` from `__metadata__`; the
  model never fills it) starts a fresh budget per value; when omitted, a
  per-agent rolling counter resets after `TOOL_BUDGET_IDLE_RESET_MIN` idle.
- **Final call executes, wrapped**: call N (the last allowed) runs normally but
  its result gains a `tool_budget` directive — report findings and end the
  turn. Applied *after* result projection so it survives digest replacement.
- **Past the cap → refused**: the call does not execute; the response is a
  structured `budget_exhausted` envelope (HTTP 200 / plain MCP text, not an
  error — an instruction to reason over, not a transient failure to retry).
- **Terminal lane**: memory (`utils.memory_tools.`), findings, and the
  unknown ledger (`utils.findings.`) tools stay callable past the cap and
  don't consume budget, so the model can actually comply instead of being
  trapped.
- **Knobs**: `TOOL_BUDGET_PER_TURN` (default 10, 0 = disabled),
  `TOOL_BUDGET_IDLE_RESET_MIN`, `TOOL_BUDGET_TERMINAL_ALLOWLIST`. Counters
  are in gateway process memory and reset on restart.

### Scratch Store (`utils/scratch_store.py`)

Durable, ownership-scoped storage for raw tool results. NOT vector memory
(no embeddings, no semantic recall) and NOT the findings store (no lifecycle).
Deterministic, reference-keyed store the model retrieves from via
`scratch_search` when it needs the full or filtered output of a prior tool call.

- **Storage:** `scratch.db` (SQLite metadata) + `scratch-data/` (compressed JSON payloads, 0700/0600).
- **IDs:** opaque random values (`scratch:<16-hex>`), never sequential — a guess from another chat cannot leak data.
- **Ownership:** every entry is scoped to `agent_id`; a valid-looking ref from the wrong agent returns "not found".
- **Persistence:** entries survive a framework restart (on-disk).
- **TTL:** 24h (env `SCRATCH_TTL_HOURS`); cleanup runs on every `store()` call.
- **Caps:** per-entry 256 MiB (`SCRATCH_MAX_PAYLOAD_MB`), per-agent 1 GiB (`SCRATCH_MAX_AGENT_MB`).
- **Atomic writes:** payload written to temp → fsync → rename → metadata commit. A crash never leaves a torn entry.

### Agent identity + jobs substrate — Phase 0 (`utils/agent_identity.py`, `utils/job_store.py`, `utils/brain_sessions.py`, scale-doctrine Annex B)

Identity is **announce-or-mint** at one choke point
(`utils.agent_identity.resolve_agent_id`): a normalized announcement
(`[a-z0-9_.:-]{3,64}`) is used verbatim, exact `"0"` is the explicit
shared-session opt-in, and anything else mints ephemeral
`anon-<hex>` echoed as `result["identity"] = {agent_id, provenance}`
(declared|shared|minted) — adopt-on-echo for clients that want
continuity. The `anon-` prefix is gateway-reserved: an announced
`anon-x` is re-minted. The executor resolves identity around every
dispatch and sets the ambient ContextVar; tool bodies read
`utils.agent_identity.current_agent_id()` for row ownership (jobs,
evidence). **Never add a default agent_id to a store schema** — stores
take NOT NULL columns and resolved callers only (the old three
spellings — executor `"0"`, evidence `"secretary"`, PG `'unknown'` —
are collapsed; evidence keeps `"secretary"` only for direct
operator-store use). `replkit.core.run_tool` dispatches under the
explicit `repl` identity.

Background jobs (`launch_job`/`poll_job`/`get_job`/`terminate_job`,
`utils/background_job.py` — same signatures as ever) are rows in the
SQLite job store (`run/jobs/jobs.db`, scratch-store conventions, env
`BG_JOB_*`): agent-scoped ownership (cross-agent `terminate_job`
refused without `force=True`), per-agent finished-cap eviction that
never evicts running jobs, TTL sweep, one shared reaper thread (a cap
kill stamps `timed_out=True` — poll-side cap enforcement marks first,
kills second, so a racing poll can't downgrade a timeout to a clean
exit). Logs live under `run/jobs/<tool>/` — never /tmp.

**Log collection (2026-10-29):** rows were always collected (TTL +
finished-cap) but the log FILES they pointed at never were — a busy
fleet leaked disk forever. A mtime-based GC (window `BG_LOG_GC_HOURS`,
default 48h — comfortably above `BG_JOB_TTL_HOURS` so a known row's log
is never GC'd early; throttle `BG_LOG_GC_INTERVAL_S`, default 30 min;
window `0` disables) runs anchored at row-collection points
(`_enforce_caps`, the reaper pass); an idle lane can invoke
`utils.job_store.garbage_collect_logs()` directly. Deletion is decided
by the FILE's age, not the row table — young files keep existing even
when their row is already gone, so an unflushed writer is never
truncated. Logs written to an explicit per-call `log_dir` remain their
tool's own collection duty.

**Launch roll-down (2026-10-29):** the request→launch→INSERT window no
longer leaks orphans. A spawn failure (missing binary) closes the log
handle and unlinks its (empty) file before raising — no row, no
sidecar. An INSERT failure after a successful spawn rolls the launch
DOWN: the spawned tree is terminated, reaped and deregistered, and no
row is written — a pid-without-row envelope would hand the model a
job_id every poll answers "unknown". The launch is honest in both
directions: no phantom rows, no unrecorded running processes. Note
`register_verdict_parser` no longer constructs the store at import
time: with the default store dir unavailable it defers registrations
and applies them at the next `launch_job` (otherwise one unreadable
path aborted the import of every tool module that registers a parser —
seven of them at last count).

Brain session ints (`agent_id → stable int` for the C wire protocol)
resolve through `utils/brain_sessions.py` (SQLite, keyed by workspace+
agent) so the same agent re-resolves identically across restarts and
lanes; in-process fallback when the store is down. `"0"` short-circuits
to the shared session. The degraded-fallback int space is NAMESPACED
(2026-10-29): fallback ints come from a high per-instance-random band
(≈100M+) that durable ints (ascending from 1) can't realistically
reach, so a degraded lane's calls can never land in another agent's
Brain-side session instances (the wire field is a C int, so the fix is
a disjoint space, not a format). The fallback lock is an RLock —
`resolve()` holds it while minting a slot, and a plain Lock made the
first-ever degraded resolve self-deadlock (never caught by tests until
the band itself was tested, 2026-10-29).

Zombie discipline (cost a full test-suite debug 2026-10-29): a dead
child nobody `wait()`ed on still answers `os.kill(pid, 0)` — the
launching store reaps via live `Popen.poll()`; pid-probe is the
cross-lane fallback; terminate-grace uses `waitpid(WNOHANG)` so the
kill path can't stall on our own zombies.

### Fleet scheduler — Phase 1 (`utils/fleet_scheduler.py`, scale-doctrine Annex C)

Per-host concurrency regulator + dedupe ledger over the job store — the
coherence primitive for fleet adapters (sqlmap fleet first, Phase 2).
Accounting axis is the TARGET HOST, not the agent; NOT a process
supervisor (adapters launch via `utils.job_store`; the scheduler decides
may-this-start/dedupe/wait per unit).

Adapter contract (each adapter contributes only these; scheduling logic
is never copied between adapters):

1. `request_unit(tool, target, agent_id=..., body=...)` — decision
   envelope: `acquired` (launch now via job store, then `bind_job`),
   `duplicate` (a live unit with the same canonical key runs — POLL its
   `job_id`, never launch a second process), or `refused`
   (`slots_exhausted` | `host_serialized_auth`, with guidance).
2. Canonical key = `<tool>:<host>:<path>:<hash>` where the hash covers
   param/field NAMES only (shape keys — per-run CSRF/nonce values must
   not fork units). Never key on raw body bytes.
3. `release_unit` when the unit's job finishes (owner or `force=True`).

Policy (rules 6/7, env `FLEET_*`): per-host slots default 2 with an
ABSOLUTE hard ceiling 4 (override above it is refused; raising above
default needs explicit `override_slots` + a warning stamped on the
envelope). Auth-adjacent units (`FLEET_AUTH_ADJACENT_RE` —
login/auth/session/token/...) hold the host exclusively in both
directions. Crash-stale reclaim (`sweep_stale()`, runs inside every
request): finished-job (VERIFIED exit only — a missing job row is not
proof of completion), jobless past `FLEET_BIND_GRACE_S`, or past
`FLEET_UNIT_TTL_HOURS`. Storage `run/fleet/fleet.db`; rows are
agent-attributed and cross-actor visible (dedupe is the point);
`fleet_host_status` is the observability lens (`@framework_tool`,
infra tag — `utils/` runs in-process, cookie-jar lane).

### sqlmap fleet adapter — Phase 2 (`payloads/sqlmap.py`, scale-doctrine Annex D)

Annex A over the Phase 0/1 substrate. The scheduler rides the **launch
path**, not a parallel API: `launch_job(..., target=..., fleet_body=...,
override_slots=...)` (`utils/background_job.py`) runs `request_unit →
launch → bind_job` atomically — duplicate/refused decisions return
WITHOUT launching (structured envelopes the model reads). Single-target
`run_sqlmap` IS one fleet unit, so single launches and fleet fanouts
share the per-host courtesy contract; adapters opt in with one kwarg.
Models never touch `request_unit` themselves — acquire-and-use is one
step inside the tool body (a model that could hold slots without
launching would DoS the host table).

Adapter contributions (the only per-tool pieces): policy table
(`_build_sqlmap_command`: forced `--batch`, threads policy
`--threads=1`, per-unit `--output-dir=run/sqlmap_fleet/<key>/` +
`-t traffic.log`, caller options last, `--purge` REFUSED per rule 5),
aggregator (`_aggregate_log`: verdict + technique tags + params), and
the fleet twins: `run_sqlmap_fleet(targets) -> fleet_id` (per-unit
acquired/duplicate/refused/scope-blocked), `sqlmap_fleet_status`
(releases finished units), `sqlmap_fleet_results(dedupe=param|host)`
(rule 8: rows cite `traffic.log`), `sqlmap_fleet_stop` (ownership
fenced). `fleet_id` records live in the scheduler's generic batch
registry (PK `(batch_id, seq)` — same-shape targets in one batch are
two decisions, not one row).

**Verdict parsers are process-wide**: `utils/job_store._PARSERS` is
module-level, NOT per-instance — the env-override singleton dance
(launch on instance A, poll on instance B) silently parsed nothing when
the registry was instance state. A job's fleet unit is released at the
first `done` poll; `sweep_stale` stays the crash backstop.

### Worker queue — Phase 3 (`utils/worker_queue.py` + `payloads/jadx_fleet.py`, scale-doctrine §13)

Bounded-memory process pool for Arch-D units (jadx per-APK now, Burp-class
later) — the accounting axis is the LOCAL WORKER (RAM), not the target host.
The fleet scheduler answers "is this TARGETS's host busy?"; the worker queue
answers "CAN THIS BOX BACK ONE MORE JVM?". Evidence base (2026-10-30): real
APKs reach multi-GB RSS (upstream issues: 9 GB TikTok #2457, 11 GB/200 MB jar
#2170, 35 GB large-app runaway #2189; measured ~300 MB on trivial synthetic
corpora, flat across -j 1..16), and jadx's default launcher sets
`-XX:MaxRAMPercentage=70.0` — N concurrent JVMs EACH claim 70% of total RAM
with zero coordination. The queue exists because that arithmetic OOMs boxes.

- **Content-keyed dedupe** (`content_key`): `"<tool>:c<sha256[:12]>"` of the
  BYTES — identical APK bytes at a different filename are the same unit
  (snapshot-cache precedent). Unhashable input falls back to a path+size key.
- **Admission is one formula** (`request_unit`): dedupe → slots
  (`WORKER_QUEUE_SLOTS`, default 2) → claims+budget ≤ (free RAM − pool floor
  `WORKER_QUEUE_RAM_FLOOR`, default 25% of total RAM, min 2 GiB). Failing
  memory/slots ⇒ QUEUED, never refused — waiting is cheap, OOM-killing a
  started decompile loses its work. Queue depth is capped
  (`WORKER_QUEUE_MAX_Q`, 16) — deeper demand is an operator signal.
- **Heap pin rides the row**: `heap_pin_env(budget)` writes
  `JAVA_OPTS="… -Xms32m -Xmx<budget>m"` into the stored env (last-wins after
  the launcher's DEFAULT_JVM_OPTS) — the row's budget IS the worker's claim.
  Caller env merges UNDER the pin.
- **Launch is inline + atomic** (fleet roll-down precedent): admission claims
  the row (`launching`), launches through the job store OUTSIDE the DB tx,
  binds on success; launch failure deletes the claim (no phantom). Bind-fail
  kills the launched job (no slot leak).
- **Promotion is queue-side**: queued rows carry resolved argv + pinned env;
  `advance_queue()` (wired into `JobStore._reaper_pass`, also called from
  `jadx_fleet_status`) releases `launched` rows whose job VERIFIED finished
  (`poll()`, not `get()` — only poll observes/reaps; get-only sweeps leak
  slots) and launch-promotes FIFO heads while admission fits, one attempt
  per pass (a persistently failing binary cannot wedge the reaper).
- **Statuses**: `queued → launching → launched → finished|cancelled`.
  `finished` = ran, exited, slot freed (SUCCESS — keep it distinct from
  `cancelled` = operator stop/crash reclaim; conflating them made the pool
  ledger unobservable, first lesson of Phase 3). Terminal rows age out (TTL
  7d); queued rows TTL 24h (`WORKER_QUEUE_TTL_HOURS`); `launching` claims
  past `WORKER_QUEUE_BIND_GRACE_S` are swept as crashed launchers.
- **Popen(env=) is a REPLACEMENT, not a merge** — found live: queue-launched
  children got ONLY the pin env (no PATH → execvp fell back to the compiled-in
  default and silently ignored both test stubs and the operator's bin dir;
  the JVM's slower boot masqueraded as flaky test timing). `_launch_claim`
  merges into `os.environ`, pin merged last. RULE: any launch through the
  store with a custom env starts from `os.environ` and updates.
- **jadx twins** (`payloads/jadx_fleet.py`): `jadx_fleet(targets,
  memory_budget=640, threads, deobf, no_res)` → per-unit
  launched/queued/duplicate/refused + `fleet_id`; `jadx_fleet_status` (per-
  unit state, workspace-done check, pools the advance sweep); `jadx_fleet_
  stop` (terminate jobs + cancel queued, ownership-fenced);
  `worker_queue_status` observability lens. Default budget 640 MiB (2× the
  measured synthetic peak — operators raise for real APKs 1-4 GB+).
- Budget cap 16 GiB/unit (`_JADX_FLEET_BUDGET_CAP`); `-j` per unit defaults
  to half the cores clamped 1..8 (the pool bounds processes, -j tunes
  threads within one).

### Memory Service (`memories.py`)

SQLite + numpy vector store (`.memory/vectors.db`). Namespaced collections
(`memory_<namespace>`). Operations: `remember`, `search` (keyword),
`recall` (vector), `get`, `forget`. Session-scoped filtering via
`where` clauses. All five operations are `@framework_tool`-decorated.

### Session Manager (`utils/session_manager.py`)

Thread-safe singleton holding live connection objects keyed by `session_id`
(e.g. `sess-0001`). Tools call `register()` on open, `get()` for follow-up
commands. `cleanup_stale()` closes sessions idle beyond a threshold.

**Process-local:** sessions live in whichever process ran the tool (Brain or
in-process launcher). If the Brain dies and a call falls back in-process,
it cannot see sessions the Brain was holding.

### Universal Cookie Jar (`utils/cookie_jar.py`) + Stateful HTTP Lane (`auxiliaries/web_session.py`)

Durable web session state — the fix for middleware (Django CSRF, session
cookies) that blocks stateless tools at the front door. Cookies and tokens
are just strings, so they live in SQLite, not in process memory:

- `CookieJarStore` (`get_jar()` singleton) — SQLite (WAL) at `COOKIE_JAR_DB`
  (default `<workspace>/cookie_jar.db`). Two tables: `cookies` (domain,
  name, path PK) and `tokens` (domain, name PK). Because state is on disk,
  **every lane shares it**: Brain sidecar, in-process fallback, REPL, and
  API gateway all read/write the same jar — deliberately sidestepping the
  Session Manager's process-local pitfall. TTL purge
  (`COOKIE_JAR_TTL_HOURS`, default 72) plus server-expiry purge run on every
  mutation.
- Matching is RFC 6265: `domain_specified` dot-form cookies cover subdomains;
  **IP hosts never match dot-forms** (a `.56.106` suffix cookie must never
  leak onto `192.168.56.106`). `cookie_header()` also path-matches, to feed
  non-jar-aware tools (ffuf/sqlmap raw modes, ZAP reclient) a ready-made
  `Cookie:` header.
- `extract_csrf_tokens()` — pure function pulling tokens from hidden
  inputs, `<meta>` tags, and response headers (canonical field order:
  Django `csrfmiddlewaretoken` → Rails `authenticity_token` → Laravel
  `_token` → ASP.NET `__RequestVerificationToken`). Values HTML-unescaped.
- Management tools: `utils.cookie_jar.jar_state` / `jar_store_cookie`
  (parses pasted `a=1; b=2` strings) / `jar_store_token` / `jar_clear` /
  `jar_cookie_header`. Note: `BRAIN_SCAN_DIRS` excludes `utils/`, so these
  run through in-process fallback — harmless, since state is on disk.
- The lane (`auxiliaries.web_session`): `session_get` / `session_post` /
  `session_request` apply jar state to a per-call `requests.Session` via
  `gated_request(session=...)` — **every redirect hop still passes the
  operator-armed scope gate**; the jar never bypasses it. `session_post`
  auto-injects CSRF: form field into the body + `X-CSRFToken`-style header
  derived from the vault/cookie. A Django login is three plain calls:
  `session_get /login/` → `session_post` creds → `session_get /dashboard/`.
- `gated_http.gated_get/gated_request` take an optional caller-managed
  `session` — used as-is, never closed; `None` keeps the original
  create-and-close stateless behavior.

### Metasploit Client + msfvenom/upload lane (`payloads/`)

`MetasploitClient` (`payloads/metasploiting.py`) drives a standalone
`msfrpcd` via `pymetasploit3` RPC (singleton `get_instance()` shares one
`MsfRpcClient`/daemon with bootstrap's `start_mcp()`).
`dispatch_metasploit(module_path, category, options, start_handler=False)`
is the single entry point for MSF module execution; `category` must match
the `module_path` prefix ('exploit'/'auxiliary'/'post', with `post`
requiring `SESSION`). `payloads/msfvenom_tools.py` + the
`session_upload` delivery step (`auxiliaries/web_session.py`) form the
generate → upload → trigger file-upload lane (`dropbox/` output, shared
`_start_handler_job` listener primitive, meterpreter payloads work through
both lanes).

The operational rules live in the canonical deep-dive,
[`payloads/README.md`](payloads/README.md) — keyed facts: a binary
FTP/TFTP-stager payload cannot stage an ELF through a raw-shell backdoor
channel ("Unsupported Binary Selected") — use pure-command `cmd/unix/*`
payloads; meterpreter payloads now run through this client (the old
`AutoLoadExtensions` non-scalar bug no longer reproduces); `AutoCheck=False` +
`ForceExploit=True` are harness defaults for exploit modules;
`start_handler=True` starts a persistent handler job and sets
`DisablePayloadHandler=True`, `start_handler=False` for auxiliaries and
manual-handler exploits (vsftpd_234_backdoor); LHOST must be reachable FROM
the target — bind `cmd/unix/bind_*` payloads for unroutable targets;
launch failures (`job_id: null` / error envelope) surface immediately with
handler cleanup instead of the "No new sessions detected" mask; msfvenom
generation is offline compute (not gated) while `session_upload` and the
trigger `session_get` are per-hop scope-gated.

### Evasion lane (`evasion/`)

`evasion/` holds shaping policy + resolvers **consumed by** scanner and web
tools — it is tool-discoverable (in `ALLOWED_TOOL_ROOTS`) but its shipped
modules are plain resolvers, not `@framework_tool` entry points, and it never
contacts targets itself. `shaping.py:resolve(preset, options)` returns merged
nmap flag lists from wire-traffic presets: `quiet` / `polite` / `noisy` are
live-safe pacing; `decoy` / `fragment` are `lab_only` and refuse unless
`SHAPING_LAB_MODE=1` (`.env`). Consumed via
`run_nmap(target, options, shaping=)` (`auxiliaries/nmap.py`): preset flags go
in FRONT of operator `options`, and nmap honors the last repeated flag, so
explicit operator flags always win over preset values. `-T` templates tune the
scanner's own speed/accuracy trade, not the wire — real shaping is
`--max-rate` / `--scan-delay` / `--data-length`.

`webshape.py` supplies the stateful HTTP lane's fingerprint identity.
`sticky_ua(host)` is a deterministic per-host pick from a realistic browser
pool — pure hash, zero state, restarts-safe; the same host always sees the
same agent, and rotation-within-host is deliberately NOT provided
(authenticated servers bind sessions to fingerprints). `SESSION_UA` env
overrides the pick (`legacy` restores the old self-identifying
`framework-web-session/1.0` marker for RoE-mandated identification).
`HostFloor` paces per-host repeats via `SESSION_HOST_FLOOR` (seconds, clamped
≤15). Both are applied at web_session's single choke point
(`_merge_headers` / `_do_session_request`); caller-supplied
`headers={'User-Agent': ...}` always win over the pool pick.

Since 2026-10-17 the identity is a single resolved stack, not four knobs:
`sticky_profile(host)` maps the pick to a pinned curl-impersonate target
(`curl_cffi`, `web` extra) whose TLS ClientHello + template header set/order
match the UA claim; coherent platform overrides (UA, `sec-ch-ua-platform`)
replace template values in-place; the plain python-requests path degrades
honestly (same UA claim, canonicalised family header order + decodable-only
Accept fill) and every envelope reports which backend shipped via
`fingerprint.backend`. `SESSION_IMPERSONATION=off` disables the
impersonated lane; an operator-owned UA never impersonates. Contract and
honest limits: `evasion/README.md` (transport-identity stack section).

`payloads/msfvenom_tools.py:generate_payload` gained `encrypt` /
`encrypt_key` / `encrypt_iv` (aes256/aes256cbc/rc4/xor/base64; key+iv
hex-validated before any subprocess; exact cipher names come from
`msfvenom_menu(kind='encrypt')`). It emits **encrypted raw shellcode only** —
no decryptor stub, no wrapper. An encrypted blob alone is inert; a pairing
loader (decrypt + execute at runtime) is a future expansion lane.
Readiness framing, honest taxonomy, and expansion policy
live in [`evasion/README.md`](evasion/README.md).

## Development Guidelines

### Jupyter Kernel (notebook lane)

The Jupyter kernel used in this workspace resolves like the IPython REPL:
the framework root is on `sys.path`, so codebase modules and
`@framework_tool` functions resolve to their **bare tool names** with no
explicit import and no collision risk (same namespace setup as
`bootstrap.py`'s REPL and `tool_repl.py`). `extract_js_routes(...)` just
works — do not add `from payloads.js_recon import extract_js_routes` style
imports in notebook cells.

Framework tools are sync in the source, but the kernel namespace injects
**async wrappers**, not the raw functions — `_make_tool_wrapper`
(`tool_repl.py`) wraps each tool in `async def _wrapper(**kwargs)` that
dispatches through `run_tool`. The kernel's `ZMQInteractiveShell` enables
autoawait, so top-level `await` works in cells. **Always `await` every
framework tool call** in notebook cells — without `await` you get a
coroutine object, not the result, and the tool never actually executes.

Tool results come back wrapped in a **transport envelope**:
`{"status": ..., "result": <tool's actual dict>, "_elapsed_s": N}`. The
tool's own fields are under `result`, not at the top level. The kernel
namespace ships envelope helpers that auto-unwrap this layer
(`_envelope_payload`): `keys(r)` (every key at any depth), `pluck(r, K)`
(flat list of every value for key K), `find(r, K)` (values + paths),
`grep(r, RX)` (string search across all values). **Use these instead of
guessing the nesting** — `pluck(r, "routes")` works regardless of whether
the field is at the top level or nested under `result`.

### Adding a Tool

**Option A — argparse module (LOCAL_FILE):**
1. Create a `.py` file under an allowed root (`auxiliaries/`, `payloads/`,
   `listeners/`, `utils/`, `evasion/`).
2. Add a module-level docstring (this becomes the embedding text).
3. Use `argparse` with `add_argument` calls — the static scanner extracts
   flags, types, and required-ness into the parameter schema.
   A module whose argparse is internal plumbing (a background-job
   subprocess runner, not an operator CLI) sets `_NO_LOCAL_TOOL = True`
   at module level to skip the static mint — decorated
   `@framework_tool` members still register.
4. Re-index: `python -m daharness.core` (or `--clear` to wipe first).

**Option B — `@framework_tool` function/method (BRAIN_DISPATCH):**
1. Import `framework_tool` from `constants`.
2. Decorate the function or method. The doc string is the semantic
   description — make it descriptive for good vector matching.
3. Place the module under a Brain scan dir (default: `auxiliaries/`,
   `listeners/`, `payloads/`).
4. Re-index or restart the Brain sidecar.

**Option C — C/C++ plugin:**
1. Write `.c`/`.cpp` in a `plugins/` subdirectory.
2. Compile: `gcc -shared -o plugin.so -fPIC plugin.c`
3. Load via `ctypes.CDLL` in a Python wrapper.
4. **Always** set `argtypes` and `restype` explicitly.
5. Wrap the ctypes call in a `@framework_tool` function for discovery.

### Language Choice

- High-level logic, networking wrappers, configuration → **Python module**.
- Raw memory access, custom assembly, extreme performance → **C/C++ plugin**.
- Anything that should be semantically discoverable and LLM-callable → wrap
  it in a `@framework_tool` function.

### Stateful Clients

If a tool class holds live connections (SSH, MSF, database):
- Implement a `get_instance()` classmethod returning a shared singleton.
- The registry's `_tool_instances` cache and the Brain's
  `FunctionRegistry._instances` both prefer `get_instance()` when binding
  methods, so all callers share the same live handles.
- Register long-lived connections with `SessionManager` for cross-tool
  retrieval by `session_id`.

### Blocking Calls

Sync tools that block (subprocess, impacket, nmap) are fine — both
dispatchers run sync tools in a worker thread (`run_in_executor` /
`asyncio.to_thread`). Do **not** make them async just to "be async" — that
pins the blocking call to the event loop and freezes the harness.

### Listener/Service Tools

Tools that start a long-running service (TCP listener, etc.) must **not**
block — `serve_forever()` would hang the dispatcher. Bind the socket, hand
serving off to a background `asyncio.create_task()`, and return immediately.
See `listeners/listening.py:listen()` for the pattern.

### Credential-Reuse Sweep (standing runbook step)

Every recovered credential — dumped (secretsdump), cracked (hashcat/john),
decoded (GPP cpassword, Base64 config blobs) — gets **ONE validation attempt
against each other reachable service** before deeper work continues. This is a
standing step, not an afterthought:

1. After recovering a credential, enumerate the other services on the target
   (and pivots) that accept authentication: SSH, web login forms, HTTP Basic,
   MySQL, PostgreSQL, SMB, FTP, etc.
2. Try the credential exactly once per service. A single failure means "not
   reused here" — do not brute-force.
3. Log each validation (hit or miss) via `report_finding` so the chain is
   auditable. Reuse hits are findings in their own right (P2/P3).
4. Only after the sweep is complete, continue to deeper exploitation.

Reactive-only reuse checking misses pivots: a cred that works on SSH but was
recovered from a MySQL dump is the classic lab pivot. The `report_finding` tool
carries a `next_hints` entry that nudges the model to do this sweep
automatically after reporting any credential-bearing finding.

## Pitfalls

- **Stale Brain socket:** the kernel doesn't unlink a socket when its owner
  dies. Always probe with a real `connect()`, not `Path.exists()`. The Brain
  unlinks on clean shutdown but not on SIGKILL. Bootstrap's `_brain_ready()`
  handles this.
- **Brain timeout = no in-process retry:** if the Brain accepted a call but
  didn't reply within `BRAIN_DISPATCH_TIMEOUT`, the result is a failure and
  the tool is **not** retried in-process (it may still be running). Check
  sidecar logs before retrying.
- **Circular imports:** `listeners/thebrain.py` is launched directly, which
  puts `listeners/` on `sys.path` instead of the framework root. It inserts
  `_FRAMEWORK_ROOT` at the top of `sys.path` on import. If you add imports
  from thebrain, be aware of this.
- **Brain startup scan vs. discovery scan:** the Brain's `_startup_scan()`
  imports modules to register `@framework_tool` callables — this **runs
  module-level code**. The registry's static pass does not. Keep
  module-level side effects out of scanned modules, or exclude them from
  `BRAIN_SCAN_DIRS`.
- **sys.path collisions:** scanning a bare directory (not a package) derives
  module names like `nmap`, which can collide with installed packages
  (e.g. `python-nmap`). The Brain's `scan_tools()` handles this by checking
  for `__init__.py` and adjusting the import path.
- **ctypes signatures:** always define `argtypes` and `restype` explicitly.
  Missing signatures cause silent type coercion or segfaults.
- **C plugin paths:** use `Path(__file__).resolve().parent / "plugins" /
  "name.so"` for absolute paths. Relative paths break when the CWD changes.
- **Deb tree is read-only:** on the system-package lane the checkout at
  `/usr/share/daharness` is root-owned — never write state into it
  (`constants.resolve_workspace_root()` falls through to
  `/var/lib/daharness`, and `brain_socket_path()` resolves
  `/run/daharness/brain.sock`). Bare-tree invocations (kernelspec argv) rely
  on that fallback; don't add code paths that assume a writable checkout.
- **Process-local sessions:** `SessionManager` is per-process. If the Brain
  dies and a call falls back in-process, sessions created on the Brain are
  invisible. Design tools to detect and report this, not silently fail.
- **`_raw` argument passthrough:** the registry's arg parsing wraps
  unparseable JSON args
  as `{"_raw": ...}`. `_launch_in_process()` strips `_raw` before calling
  the tool. Don't rely on it being present in your tool function.
- **Debugging C plugins:** use `gdb` or `valgrind`. Test the Python
  integration separately to catch `ctypes` mapping errors.
