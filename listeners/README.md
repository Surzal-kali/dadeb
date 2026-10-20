# listeners/ — Brain sidecar, OOB callbacks, runtime services

The runtime services: the Brain sidecar (the tool dispatch hub), the OOB
collaborator, the TCP listener, and the Brain-side execution kill switch.

## Brain Sidecar (`thebrain.py`)

A Unix domain socket server at the checkout's gitignored `run/brain.sock`
(resolved via `constants.brain_socket_path()`; `$BRAIN_SOCKET` overrides)
with 4-byte big-endian length-prefixed message framing
(`pack_message` / `read_message`). The socket lives **inside the tree** so
bind-mounted container lanes (the jupyter kernel in the workbench, e.g.)
reach the SAME socket as the host — a `/tmp` path would be per-namespace and
unreachable across a container boundary.

**Startup sequence:**

1. Probe for an existing live listener (refuses to start a second Brain).
2. Unlink stale socket if no live listener.
3. `_startup_scan()` — imports modules under `BRAIN_SCAN_DIRS` (default:
   `auxiliaries,listeners,payloads`) and registers `@framework_tool`
   callables in the `FunctionRegistry`.
4. Bind the socket (only after the scan completes, so tools are callable
   immediately when bootstrap's connect-probe succeeds).

**Event protocol:** `event_type|session_id|data`

- `SCAN_TOOLS|sid|path` — scan a directory/file for tools, register them.
- `CALL_TOOL|sid|tool_id|args_json` — execute a registered tool. Args as
  dict → kwargs, list → positional, or bare string → single positional.
- Unknown events → forwarded to the C library (`frameit.so`) via `ctypes`.

**Class instance caching:** `FunctionRegistry._instances` keeps one instance
per class so stateful clients (e.g. `MetasploitClient`, via its
`get_instance()` singleton) preserve handles across calls.

**Timeout semantics:** dispatch waits up to `BRAIN_DISPATCH_TIMEOUT`
(default 600s). If the Brain **accepted** the call but timed out, the result
is a failure and the tool is **NOT retried in-process** — it may still be
running on the Brain, and a second execution would cause duplicate side
effects. `BRAIN_EXEC_CEILING` (default 3600s) hard-caps any single
execution on the Brain.

**Shutdown:** signal handlers route SIGTERM/SIGINT through task cancellation
so the `finally` block unlinks the socket — but only if the inode still
matches the one we bound (won't clobber a newer sidecar).

**Pitfall:** the kernel doesn't unlink the socket when its owner is killed
with SIGKILL. Always probe with a real `connect()`, never `Path.exists()` —
bootstrap's `_brain_ready()` does this.

### In-Process Fallback (`../daharness/executor.py`)

When the Brain socket is unavailable (`FileNotFoundError`,
`ConnectionError`) or doesn't know the tool, `BRAIN_DISPATCH` calls execute
in-process:

1. `_resolve_callable()` — longest importable module prefix wins, walks
   remaining attrs. Unbound methods are bound to a cached class instance,
   preferring `get_instance()` if available.
2. Async tools are awaited; sync tools run in `asyncio.to_thread()`.
3. Results are wrapped as `{"status", "result"}` envelopes; `stdout` is
   included only when the tool returned a bare string, never as a
   stringified copy of `result` (that doubled context on every call).

Process-local caveat: the fallback cannot see Brain-held sessions — see the
Session Manager notes in
[`../utils/README.md`](../utils/README.md#session-manager-session_managerpy).

## Zombie Kill Switch (`brain_control.py` + `execution_tracker.py`)

`execution_tracker` keeps the Brain-side live/tracked-execution state;
`brain_control` exposes it as framework tools — `list_tool_executions` /
`kill_tool_execution` — so wedged tool executions on the Brain can be
inspected and killed without killing the Brain itself.

## OOB Collaborator (`collaborator.py`)

A Burp Collaborator analog: multi-protocol listener catching blind SSRF,
blind XSS, and other OOB callbacks. HTTP on TCP 80, HTTPS on TCP 443
(self-signed cert), and DNS on UDP 53 — all on one host. The payload ID
rides in the subdomain; `collab_generate` produces a unique callback
URL/DNS name and `collab_poll` returns correlated events. Requires root for
ports 80, 443, and 53.

**Public mode** — set `COLLAB_PUBLIC_URL` (e.g. a Tailscale Funnel endpoint
like `https://<device>.<tailnet>.ts.net`) and `collab_generate` returns
path-based PUBLIC callback URLs (`<public>/c/<id>/`) instead of lab
subdomains, and a token-gated redirect endpoint goes live at
`/r/<id>?to=<url>` → 302 (redirect-to-internal blind SSRF; `scan_ssrf`
gains a `redirect_to` param for it). Funnel walkthrough: `tailscale funnel
<COLLAB_HTTP_PORT>` (use 8080 — no root needed), public HTTPS terminates at
Tailscale and forwards plain HTTP to `127.0.0.1:<COLLAB_HTTP_PORT>`. Honest
limits: Funnel serves HTTPS only and does not expose DNS-query events, so
public mode is HTTP-callback-only (subdomain mode keeps the DNS signal).
Every callback is appended to `scope/collab_hits.jsonl` as durable evidence
(gitignored); the in-memory store is capped at 5000 entries.

## TCP Listener (`listening.py`)

`listen()` starts a TCP listener **without blocking the dispatcher**: bind
the socket, hand serving off to a background `asyncio.create_task()`, and
return immediately. This is the required pattern for any service/listener
tool — a `serve_forever()` in a tool would hang its dispatcher.

## Raw SYN Scanner (`raw_scan.py` + `plugins/raw_scan.cpp`)

The scan lane's raw SYN port scanner: a C++ plugin (`SOCK_RAW`; requires
root or `CAP_NET_RAW`) wrapped via `ctypes.CDLL` and exposed as
`@framework_tool` callables — scope-gated like every other traffic-sending
tool.

## Responder Analog (`responder_analog.py`) — CAPTURE-ONLY LLMNR/NBT-NS + SMB2 sink

The Phase-4 credential-motion opener. Windows falls back to LLMNR
(UDP 5355, multicast 224.0.0.252) and NBT-NS (UDP 137, broadcast) when DNS
answers no-such-name, and both legacy protocols have no server
authentication — this module answers with OUR IP and catches the victim's
NTLMv2 challenge-response in a self-contained SMB2 sink.

- **Tool triplet + captures**: `responders_start` (background job,
  `job_id` immediate — the detached subprocess runs the engines + sink),
  `responders_status` (engine liveness + capture count + recent captures),
  `responders_stop` (SIGTERM cleanup), and
  `responders_captures` (full hash lines, hashcat -m 5600 / john
  netntlmv2 ready). Each capture also persists to
  `run/responder/captures.jsonl` (0600) and lands in vector memory
  (namespace `responder`, marked important) so the secretary recalls it.
- **Gates**: `SHAPING_LAB_MODE=1` required in .env — the SAME lab gate as
  `evasion/shaping.py`'s decoy/fragment (one switch for deceptive wire
  traffic). Port 445 is privileged: start probes the bind first and
  fails closed with the `setcap cap_net_bind_service+ep` remediation
  (UDP 137/5355 are unprivileged). The scope gate is deliberately NOT
  consulted — poisoning answers the segment, not a blessed target.
- **SMB2 sink** (self-contained — no MSF capture dependency): NBSS framing
  both directions (incl. type-0x81 session requests for 139-style
  clients), dialect 2.0.2, SPNEGO-wrapped NTLMSSP challenge
  (`a1 → 30 → a0/Accept-Incomplete → a2/OctetString`) with a realistic
  TargetInfo AV set (impacket's v2 compute subscribes to
  `MsvAvDnsHostname`-class pairs; empty TargetInfo kills client parses).
  Exactly one auth exchange per capture, then `STATUS_LOGON_FAILURE` —
  **no relay code path exists** in this module.
- **Own-name blacklist**: our hostname (short + FQDN) and `wpad` are never
  answered; LLMNR answers A queries only (AAAA ignored, IPv4 sink).

Acceptance chain (todo Phase 4): poison → capture → `run_hashcat` mode
5600 → credential-reuse sweep → `report_finding`, secretary-driven.
Parked-by-policy: relays (ntlmrelayx-class).

## C plugins in this folder

- `plugins/raw_scan.cpp` → `raw_scan.so` — raw SYN scan using `SOCK_RAW`
- `plugins/frameit.c` → `frameit.so` — C-side event bridge for the Brain

Compiled with `-fPIC -shared`; the Python wrappers always set `argtypes` and
`restype` explicitly (see the plugins convention in
[`AGENTS.md`](../AGENTS.md#language-choice)).