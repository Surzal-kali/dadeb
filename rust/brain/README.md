# rust/brain — Rust port of the Brain protocol (WIP)

Incremental, in-progress reimplementation of `listeners/thebrain.py`'s
orchestration plane in Rust. Tools stay in Python; this owns the socket,
framing, dispatch, and (later) execution tracking.

## Milestone 1 (this commit) — transport + framing + typed dispatch

- `codec.rs` — length-prefixed framing (4-byte big-endian length + payload,
  10 MiB ceiling). Byte-for-byte compatible with the Python
  `pack_message`/`read_message`, so existing clients interoperate.
- `event.rs` — parses the `event_type|session_id|payload` triplet into a typed
  `Event` enum. Unit-tested.
- `main.rs` — tokio `UnixListener`, one request per connection, dispatched via
  an exhaustive `match`. Each arm is a stub for now.

## Milestone 2 — Python tool-worker IPC seam

- `worker.rs` — the brain's client to the Python worker. Forwards tool events
  over the **same** `brain_codec()`; one framing layer, both links. The
  forward's coarse backstop is ceiling-aware: it defaults to
  `BRAIN_EXEC_CEILING + 30s` (the tracker's kill path always fires first),
  `BRAIN_WORKER_TIMEOUT` overrides (seconds; `0` disables).
- `worker.py` — a long-lived asyncio worker that holds the tool registry and
  executes tools. Ships a stdlib-only demo registry (`demo.echo`, `demo.add`,
  `demo.sysinfo`); the real registry wires in where marked in the file.
- `main.rs` `dispatch` now routes `CALL_TOOL`/`SCAN_TOOLS` to the worker and
  relays the reply (transparent proxy); `Other` events still stub locally.

## Milestone 3 — real registry + execution core in the worker

- `tool_exec.py` (repo root) — the shared CALL_TOOL execution core lifted from
  `thebrain.py`: JSON arg parsing, scope-gate brake, per-session instance
  rebind, execution tracking + `BRAIN_EXEC_CEILING`, status envelope. Import-
  light (stdlib only) so it carries no `scapy`/tool-chain weight.
- `worker.py` — now selects a backend: REAL (imports the harness registry +
  `EXECUTION_TRACKER`, primes it with a startup scan) or DEMO (stdlib-only
  registry + no-op tracker, for `BRAIN_WORKER_DEMO=1` or a bare env). Both run
  through `tool_exec`.

## Milestone 4 — OS singleton dance (`singleton.rs`)

Ported from `thebrain.py` `start_brain()`: an exclusive advisory `flock`
singleton guard, a connect-probe before unlinking a stale socket, per-lane
socket permissions via a `umask` swap around bind, and unlink-on-exit (only if
the socket is still the inode we bound). SIGTERM/SIGINT are routed to a graceful
shutdown so the cleanup runs. Uses `nix` for the Unix-only syscalls, `std::fs`
for the portable file ops.

Still in Python (by design): tool execution, registry + per-session isolation,
the scope gate, and the execution tracker / kill switch — all in the worker.

## Run it (three pieces: worker, brain, client)

```sh
# 1. the Python tool-worker  (drop BRAIN_WORKER_DEMO on a full harness checkout)
cd rust/brain
BRAIN_WORKER_DEMO=1 BRAIN_WORKER_SOCKET=run/brain-worker.sock python3 worker.py

# 2. the Rust brain (new shell) — forwards tool events to the worker
cd rust/brain
BRAIN_SOCKET=run/brain.sock BRAIN_WORKER_SOCKET=run/brain-worker.sock cargo run

# 3. the smoke client (new shell) — hit the path the brain printed
cd rust/brain
python3 smoke.py run/brain.sock
```

With all three up, `demo.*` calls return execution envelopes through the shared
`tool_exec` core, proving the full client -> brain -> worker -> client round-trip
over one wire format. `demo.sleep` exercises the ceiling/kill path end to end
(`demo.add`, long sleeps, etc. — the brain's forward backstop is
`BRAIN_EXEC_CEILING + 30s`, so the tracker's verdict reaches the client before
the brain gives up). Stop the worker and re-run the client to see the brain's
`worker unreachable` fallback. Start a second brain to see the singleton guard
refuse it; Ctrl-C the brain to see it unlink its own socket on the way out.

## Tests

```sh
cargo test                      # event-parser unit tests
```
