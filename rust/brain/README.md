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
  over the **same** `brain_codec()`; one framing layer, both links.
- `worker.py` — a long-lived asyncio worker that holds the tool registry and
  executes tools. Ships a stdlib-only demo registry (`demo.echo`, `demo.add`,
  `demo.sysinfo`); the real registry wires in where marked in the file.
- `main.rs` `dispatch` now routes `CALL_TOOL`/`SCAN_TOOLS` to the worker and
  relays the reply (transparent proxy); `Other` events still stub locally.

Not yet here: the flock/stale-inode/umask singleton dance, and the execution
tracker + kill switch (the brain-side control plane — where `Other` lands).

## Run it (three pieces: worker, brain, client)

```sh
# 1. the Python tool-worker
cd rust/brain
BRAIN_WORKER_SOCKET=run/brain-worker.sock python3 worker.py

# 2. the Rust brain (new shell) — forwards tool events to the worker
cd rust/brain
BRAIN_SOCKET=run/brain.sock BRAIN_WORKER_SOCKET=run/brain-worker.sock cargo run

# 3. the smoke client (new shell) — hit the path the brain printed
cd rust/brain
python3 smoke.py run/brain.sock
```

With all three up, `demo.*` calls return real execution envelopes from the
worker, proving the full client -> brain -> worker -> client round-trip over
one shared wire format. Stop the worker and re-run the client to see the
brain's `worker unreachable` fallback.

## Tests

```sh
cargo test                      # event-parser unit tests
```
