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

Not yet here: tool execution (goes to a Python worker over this same codec),
the flock/stale-inode/umask singleton dance, the execution tracker + kill
switch. Those are later milestones.

## Run it

```sh
cd rust/brain
cargo run                       # binds ./run/brain.sock (or $BRAIN_SOCKET)
```

## Smoke test (wire-compat with the Python framing)

In another shell, with the server running:

```sh
python3 rust/brain/smoke.py run/brain.sock
```

It sends a `CALL_TOOL` frame using the exact `!I`-prefixed format the Python
Brain uses and prints the framed reply.

## Tests

```sh
cargo test                      # event-parser unit tests
```
