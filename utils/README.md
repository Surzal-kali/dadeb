# utils/ — harness plumbing

The framework's shared machinery: scope enforcement, result projection,
durable stores, stateful-client plumbing, and the background-job pattern.
Modules here are both `@framework_tool` callables (dispatched via the Brain
or in-process fallback — see
[`../listeners/README.md`](../listeners/README.md)) and helpers imported by
other lanes.

## Deep dives

### Scope Gate — Operator-Armed (`scope_gate.py`)

The armed gate is a technical backstop the OPERATOR arms from the Tool REPL
(see [`../README.md#tool-repl-tool_replpy`](../README.md#tool-repl-tool_replpy))
— separate from `check_scope` (program-scope manifest checks in
`auxiliaries/program_scope.py`), which only consults a loaded manifest.
Arming/disarming is deliberately NOT exposed as an `@framework_tool`, so the
secretary model has no way to toggle or bypass it. When disarmed (the
default — lab mode) tools behave exactly as before.

    scope on <handle> [--platform P] [--no-strict]   # arm (refuses blind: needs a cached manifest)
    scope status                                      # armed state, asset counts, manifest age
    scope add-ip <ip> [<hostname>]                    # bless a resolved in-scope IP (CDN-safe)
    scope add-host <hostname> <ip>                    # bless a vhost hostname (IP must already be blessed)
    scope rm-ip <ip> / scope rm-host <hostname>       # revoke blessings; scope list-ips shows the allowlist

Enforcement is file-backed, not in-process: the armed state lives in
`scope/.armed_packet_scope.json` (atomic writes, mtime-checked on every
call), so a blessing written from the REPL is authoritative in every process
— a REPL change takes effect immediately inside a running Brain.

Gated calls fail CLOSED — a block raises `ScopeGateError`, which surfaces as
`Failed` on both dispatch paths (Brain socket + in-process fallback):

- **`check_send`** — packetcraft `send_packet` / `send_and_receive_packet`:
  the destination IP extracted from the crafted packet (v4/v6 dst, ARP
  `pdst`); the check runs BEFORE the probe fires.
- **`check_scan`** — nmap, masscan, ffuf, hydra, ZAP, impacket/SMB,
  raw_scan, paramiko SSH, sqlmap, fastcgi, ssh_exec, MSF dispatch:
  URL / bare host / IP / CIDR / hyphen-range / list shapes; one
  out-of-scope spec refuses the whole call.

Verdict tiers (first match wins; an out-of-scope match always beats an
in-scope wildcard):

1. **Operator allowlist** — `scope add-ip` blessings (authoritative,
   CDN-safe: the operator confirmed the IP belongs to an in-scope host).
1b. **Operator-blessed hostnames** — `scope add-host <hostname> <ip>` maps a
   vhost hostname to an ALREADY-blessed IP (for lanes whose connect target
   is the Host header, e.g. ZAP raw send). The operator asserts the mapping;
   the gate never resolves DNS for it.
2. **Manifest match** — the program's typed in-scope assets (DOMAIN/
   WILDCARD/URL for hostnames, IP/CIDR for IPs).
3. **Reverse-DNS attribution** — PTR records are attacker-settable, so an
   in-scope PTR match only auto-allows after forward-confirmation (the PTR
   name must resolve back to the scanned IP; 2s cap, fail-closed).

Strict mode (default): any unconfirmed target is REFUSED with guidance;
`--no-strict` warns instead. Broad CIDR/hyphen ranges are allowed only as a
subnet of an explicit in-scope CIDR asset; otherwise refused — disarm
(`scope off`) for lab / internal-network work.

Never gated by design: non-routable destinations (broadcast, multicast,
loopback, link-local, reserved — DHCP/mDNS probes pass), pure-L2 frames with
no routable IP, receive-only traffic (sniffing, inbound replies), and offline
tools (crafting/dissecting never touch the wire). Known residual surfaces:
the gate sees the REQUESTED target only — DNS-resolver traffic is out of its
view, and redirect-following inside scan binaries is handled per-tool (ffuf
`-r` is denylist-stripped; ZAP crawls are mirrored by `zap_sync_scope`, which
puts ZAP itself in protect mode against OOS hops; and `gated_http.py`
re-validates every redirect hop that the HTTP probe tools follow).

### The Universal Cookie Jar + Stateful HTTP Lane (`cookie_jar.py`)

Almost every web tool in the framework is a stateless one-shot — it makes
one request and throws away everything the app handed back.
Middleware-managed state (Django's CSRF dance, session cookies, bearer
tokens) therefore blocks audits at the front door: you can't even see the
authenticated surface without carrying `csrftoken` + `csrfmiddlewaretoken` +
`sessionid` between calls. Cookies and tokens are just strings, so the jar
makes that state **durable and universal**:

- **SQLite-backed** (`cookie_jar.db`, WAL): state lives on disk, so every
  lane — Brain sidecar, in-process fallback, REPL, API gateway — sees the
  same jar without any cross-process broker. Deliberately sidesteps the
  process-local limitation of the Session Manager.
- **Cookie jar** (RFC 6265 matching): domain rules honor `Domain=`-style
  dot-forms, and IP hosts never match dot-forms (a `.56.106` suffix can't
  leak a cookie onto `192.168.56.106`). Path rules apply when building
  ready-made `Cookie:` headers for non-jar-aware tools (ffuf/sqlmap/ZAP).
- **Token vault**: named token strings per host (CSRF form fields, bearer
  tokens) with latest-wins upsert. `extract_csrf_tokens()` pulls values from
  hidden inputs, `<meta>` tags, and response headers (Django, Rails,
  Laravel, ASP.NET canonical order), HTML-unescaped.
- **Hygiene**: TTL purge (default 72h via `COOKIE_JAR_TTL_HOURS`) plus
  server-expiry purge on every mutation; `COOKIE_JAR_DB` overrides the path.
- **Tools**: `jar_state`, `jar_store_cookie` (paste `a=1; b=2` strings),
  `jar_store_token`, `jar_clear`, `jar_cookie_header`.

Note: `BRAIN_SCAN_DIRS` excludes `utils/`, so the management tools run
through in-process fallback — harmless, since state is on disk.

The consumer lane (`session_get`/`session_post`/`session_request`/
`session_upload` in `../auxiliaries/web_session.py`) applies this state
through `gated_request(session=...)` — every hop still passes the
operator-armed scope gate. The full login-flow walkthrough lives in the
[auxiliaries README](../auxiliaries/README.md#stateful-http-lane-web_sessionpy).

### Result Projection (`result_projection.py`)

A middleman between `execute_tool()` and the model's context window:
`result_mode` is an execution-envelope parameter (passed alongside
`tool_id`/`arguments`, NOT a tool argument — it never reaches the tool
body). Three modes:

- **`digest`** (default for both the secretary agent and
  `POST /tools/execute`) — stores the full result in scratch, returns a
  compact per-tool-family digest + a `scratch_ref` + the retrieval
  instruction. The model is taught the retrieval move every call. Results
  smaller than `SCRATCH_SMALL_RESULT_BYTES` (default 2 KiB — handles,
  verdicts, IDs) pass through in full automatically; only genuinely large
  outputs (scan logs, hit lists) are projected out.
- **`full`** — the raw tool result passes through unchanged (also the
  default on the MCP `tools/call` lane).
- **`page`** — stores the full result in scratch, returns a bounded page of
  list results (offset/limit) + a `scratch_ref` + continuation info.

**Why this is not a post-hoc trim filter:** the projection runs *before*
the result enters context (not after); the retrieval instruction is part of
the return (the model never guesses how to get the full output);
per-tool-family digest logic is honest because the tool knows its own output
structure.

**Digest adapter registration:** tools opt in via
`@framework_tool(..., result_digest=my_digest_fn)`. The adapter takes the
raw result dict and returns `{"summary": str, "row_hint_format": str}`.
Tools without an adapter fall back to a naive head+count preview.

**Pilot adapter:** `nmap_status` — returns open port count + full port list
+ host state + job_id, omitting the raw log text (retrievable from scratch).

### Scratch Store (`scratch_store.py`)

Durable, ownership-scoped storage for raw tool results. NOT vector memory
(no embeddings, no semantic recall) and NOT the findings store (no
lifecycle). Deterministic, reference-keyed store the model retrieves from
when it needs the full or filtered output of a prior projected call: via the
MCP `scratch_search` tool, the gateway's `POST /scratch/search`, or the Open
WebUI `framework_scratch_search` wrapper.

- **Storage:** `scratch.db` (SQLite metadata) + `scratch-data/` (compressed
  JSON payloads, 0700/0600).
- **IDs:** opaque random values (`scratch:<16-hex>`), never sequential — a
  guess from another chat cannot leak data.
- **Ownership:** every entry is scoped to `agent_id`; a valid-looking ref
  from the wrong agent returns "not found".
- **Persistence:** entries survive a framework restart (on-disk).
- **TTL:** 24h (env `SCRATCH_TTL_HOURS`); cleanup runs on every `store()`
  call.
- **Caps:** per-entry 256 MiB (`SCRATCH_MAX_PAYLOAD_MB`), per-agent 1 GiB
  (`SCRATCH_MAX_AGENT_MB`).
- **Atomic writes:** payload written to temp → fsync → rename → metadata
  commit. A crash never leaves a torn entry.

### Background Job Pattern (`background_job.py`)

Long-running CLI tools (nmap, masscan, amass, ffuf, hydra, sqlmap) use the
shared `launch_job` helper: it starts a detached `subprocess.Popen`, writes
a JSON sidecar to disk (so polls survive a harness restart), starts a reaper
thread for the wall-clock cap, and returns a `job_id` immediately — the
secretary turn is not held open. `poll_job` reads the log, checks liveness,
tails recent lines, and returns a structured `status: "running" | "done"`
dict. Each tool pair follows the `run_*` / `*_status` / `*_cancel` shape.

Poll verdicts are bounded: ffuf's parsed findings list is capped at
`FFUF_MAX_FINDINGS` (default 10000, most interesting status codes kept
first) because a catch-all target — an app that redirects every path, so
every wordlist word "hits" — can otherwise produce a verdict larger than the
Brain's 10 MiB wire-frame guard (`MAX_MESSAGE_SIZE`,
`listeners/thebrain.py`), and the reply dies on the socket read ("brain
dispatch failed: declared message length ... exceeds max"). The true count
is reported via `findings_total` / `findings_truncated`, and the full result
set always remains in the job's `-o` JSON output file (`meta.output_file`).

### Findings Tools + Unknown Ledger (`findings.py`)

The `finding` lifecycle tools over the SQLite store described in
[`../README.md#findings-store-daharnessfindingspy`](../README.md#findings-store-daharnessfindingspy) (deep content:
`daharness/findings.py`):

- **`report_finding`** — the terminal action for any tool chain. Mints a
  structured finding and stores a one-line memory pointer. Carries a
  `next_hints` entry that nudges the secretary into the standing
  credential-reuse sweep after any credential-bearing finding.
- **`render_findings`** — renders all findings as a markdown report (filters
  by severity/asset/status). Writes a timestamped `.md` file to
  `findings_md/` and gains an **Open questions (unresolved)** appendix that
  renders even when zero findings exist.
- **`close_finding`** — close a finding as resolved, false positive, or
  duplicate.
- **`supersede_finding`** — mark an older finding as replaced by a newer,
  more accurate one.

Beyond findings, the same store carries the **unknown ledger** — where a
finding records a *conclusion*, an unknown records an explicit "don't know
yet": unprobed services, credentials recovered but not yet validated against
other services, ambiguous results, scope questions. `record_unknown` /
`list_unknowns` / `resolve_unknown` (statuses: open|resolved|wontfix|
promoted — `promoted` requires the finding ID via `resolved_by`). All three
are `infra`-tagged and sit in the terminal lane
(`utils.findings.` prefix) so they stay callable past the tool budget.

### Analysis Snapshot Cache (`snapshot_cache.py`)

Deterministic-lane memoization for tools whose output is a pure function of
their inputs — currently `run_r2` (see the
[auxiliaries README](../auxiliaries/README.md#radare2--the-analysis-snapshot-cache)
for the consumer view). Successful r2 envelopes are stored at
`run/analysis_snapshots.db`, keyed on the target's **sha256** + op key
(verb, addr, count, r2ghidra availability, output cap, timeout); identical
repeat queries serve verbatim with a `_snapshot.hit` stamp. Rules that keep
it honest:

- **Pure functions only.** Scanners (nmap/ffuf/masscan) deliberately don't
  share this cache — their results are observations of a changing world (and
  their job-log lane already persists per-job results). Errors are never
  cached; a cached timeout is a lie about the next attempt.
- **Content keys, not paths**: identical bytes rebuild-and-hit; changed
  bytes miss automatically. No invalidation problem for a read-only lane.
- **Contextual fields are patched on hits**: a cached envelope's `target` is
  rewritten to the current call's resolved path.
- Storage: SQLite WAL, TTL `SNAPSHOT_TTL_HOURS` (default 168h),
  per-target cap `SNAPSHOT_MAX_ENTRIES` (default 200, oldest evicted).
  `cache=False` skips read+write; `refresh=True` recomputes + overwrites.
  Cache failures degrade silently to a normal run — caching must never
  break a tool.

### Session Manager (`session_manager.py`)

Process-local singleton holding live connection objects (SSH clients, MSF
sessions) keyed by `session_id`. Tools register connections on open and
retrieve them for follow-up commands without re-authenticating. Includes
stale-session cleanup. Process-local caveat: sessions live in whichever
process ran the tool (Brain or in-process launcher); if the Brain dies and a
call falls back in-process, it cannot see sessions the Brain was holding.
Tools should detect and report this, not silently fail.

### Session Handles (`handles.py`)

Typed session handles (`kind:session_id` strings) that tools declare via
`@framework_tool(..., accepted_handle_kinds=[...])`. The secretary validates
any `handle` argument's kind against the tool's accepted set before
execution, preventing cross-namespace misuse (e.g. passing an SSH handle to
an MSF tool).

### Per-Turn Tool Budget (`tool_budget.py`)

A hard cap on tool executions per turn, enforced in the gateway so the lanes
that bypass the secretary's approval gate (Open WebUI bridge, MCP, REST) get
the symmetric brake (`SECRETARY_MAX_APPROVAL_ROUNDS` covers the secretary).

- **Counting**: every `/tools/execute` / MCP `tools/call` dispatch counts
  once. The request's `turn_key` (Open WebUI passes `chat_id:message_id`
  from `__metadata__`; the model never fills it) starts a fresh budget per
  value; when omitted, a per-agent rolling counter resets after
  `TOOL_BUDGET_IDLE_RESET_MIN` idle.
- **Final call executes, wrapped**: call N (the last allowed) runs normally
  but its result gains a `tool_budget` directive — report findings and end
  the turn. Applied *after* result projection so it survives digest
  replacement.
- **Past the cap → refused**: the call does not execute; the response is a
  structured `budget_exhausted` envelope (HTTP 200 / plain MCP text, not an
  error — an instruction to reason over, not a transient failure to retry).
- **Terminal lane**: memory (`memory_tools.`), findings, and the unknown
  ledger (`findings.`) tools stay callable past the cap and don't consume
  budget, so the model can actually comply instead of being trapped.
- **Knobs**: `TOOL_BUDGET_PER_TURN` (default 10, 0 = disabled),
  `TOOL_BUDGET_IDLE_RESET_MIN`, `TOOL_BUDGET_TERMINAL_ALLOWLIST`. Counters
  are in gateway process memory and reset on restart.

## Small modules at a glance

| Module | Role |
| --- | --- |
| `gated_http.py` | Per-hop scope-gated HTTP — closes the 302-to-out-of-scope bypass; used by cors_probe, ssrf_probe, web_probe, js_recon; `gated_get`/`gated_request` accept an optional caller-managed `requests.Session` (the stateful web_session lane rides this hook) |
| `packetcraft.py` | Scapy crafting: `craft_*` (icmp/tcp/udp/arp/vlan/dhcp/dns/mdns/http), `send_packet`, `send_and_receive_packet` (sr1/srp1, gated before the probe fires), `sniff_packets`, dissect/modify, save/load pcap; pcap forensic lane (`save_pcap`, `sniff_to_pcap`, `load_pcap`, `list_pcaps` — `pcaps/` gitignored output dir, mirroring the msfvenom dropbox pattern) |
| `crypto_kit.py` | Offline decode/identify/attack workbench — Base64/JSON cookies, JWTs, unsalted hashes; zero network |
| `paramiko_client.py` | Persistent SSH (connect/exec/shell/close) + one-shot mode; `auxiliaries/ssh_exec.py` is the batch lane on the same session plumbing |
| `memory_tools.py` | `remember_text`/`recall_text` — namespaced vector memory |
| `log_reader.py` | Read/stream Brain and MSF logs |
| `wordlists.py` | Wordlist discovery + the startup preflight (`preflight_wordlists`) that surfaces a missing/empty wordlist tree as a bootstrap warning |
| `sessions.py` | SQLite tracking of targets/sessions/payloads/notes in `ids.db`; schema in `../schema.md`; the findings store shares this database |
| `plugins/` | C/C++ shared objects + TLS certs for the collaborator |