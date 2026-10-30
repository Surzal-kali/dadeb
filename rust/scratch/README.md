# scratch — dadeb's scratch store, Rust port (milestone 5)

Rust port of [`utils/scratch_store.py`](../../utils/scratch_store.py): durable,
ownership-scoped storage for raw tool results. Same layering as `rust/brain` —
this is a library crate; a lane that wants scratch (a future Rust worker
handling result projection, a Rust gateway, the brain sidecar) imports it and
hands it a workspace location.

The python store stays the reference implementation; both sides are
cross-compatible over the **same** `scratch.db` + `scratch-data/` workspace
(see *Cross-compat verification*).

## What's ported (1:1 with `utils/scratch_store.py`)

| Python | Rust | Notes |
|---|---|---|
| env knobs (`SCRATCH_TTL_HOURS`, `SCRATCH_MAX_PAYLOAD_MB`, `SCRATCH_MAX_AGENT_MB`, `SCRATCH_GREP_MIN_CHARS`) | `ScratchConfig::from_env()` | captured once at `open()`; malformed values warn + default (python raises at import — a typo must not kill the store lane) |
| `__init__` (dir 0700, WAL dance, busy_timeout 10s, `_init_table`) | `ScratchStore::open()` | byte-identical DDL + indexes; whoever creates a db first, the other side uses it untouched |
| `_set_wal` (3-retry + readback acceptance) | `set_wal` | first WAL conversion can hit SQLITE_BUSY outside busy-handler coverage |
| `_repair_ownership_if_needed` (root guard) | `repair_ownership_if_needed` | native `chown(2)` via nix instead of shelling out; never raises; non-root + root-owned files → the same loud warning |
| `store()` | `ScratchStore::store()` → `StoreReceipt` (`to_envelope()`) | gzip level 6, sha256 of compressed bytes, `application/json+gzip`, `schema_version=1` |
| opaque ids (`secrets.token_hex(8)`) | `random_hex_id()` via `getrandom` | `scratch:<16-hex>`, lowercase, OS entropy |
| atomic payload write | temp (0600 at create) → fsync → rename | python chmods after fsync; final state identical |
| per-agent cap (`_enforce_agent_cap`) | `enforce_agent_cap` | evict oldest-first until within budget |
| `retrieve()` | `ScratchStore::retrieve()` → envelope `Value` | ownership-locked (`id + agent_id` query); unknown/expired/wrong-agent envelopes verbatim; lazy delete on expired/missing-file |
| `_apply_projection` / `_item_matches*` / `_grep_string` | `projection::apply_projection` / `grep_string` | list filter ⇒ substring beats regex; string grep ⇒ regex beats substring; `context_lines` ±-window with `...` separators; `_scratch_projection` meta block |
| `_parse_ref` | `parse_ref` | lowercase hex only |
| `list_entries` / `stats` / `cleanup_expired` | same | same envelope shapes |

## Documented divergences (structural, not behavioral)

- **Malformed env values warn + default** instead of raising at import.
- **Paging** takes `usize`: python's negative-offset slice wrap is dropped
  (nothing in the harness pages backwards; `tools/execute` callers pass
  forward offsets).
- **Truncation** floors to a UTF-8 boundary (python byte-slices, possibly
  mid-codepoint). Either way the JSON is broken, so retrieval reports
  `corrupted` exactly as before.
- **Root guard** uses `nix::unistd::chown` — no `subprocess`/timeout dance.
- **Logging** is `eprintln` (brain-crate style) instead of the logging module.
- **JSON serialization** is compact; python `json.dumps` leaves
  separator spaces — payload bytes differ slightly, `sha256` is per-store so
  nothing couples, and byte counts in envelopes reflect whichever store
  wrote the entry.
- **Non-object payloads**: python's `fields` selection would raise
  `AttributeError` on a list/array payload; the guard passes it through
  unprojected.

## Layout

```
src/lib.rs         crate docs + re-exports
src/config.rs      ScratchConfig (env-backed knobs)
src/projection.rs  filter/regex/paging/grep fallback (pure fns, unit-tested)
src/store.rs       ScratchStore: open/WAL/schema, store/retrieve/list/stats,
                   cleanup, cap eviction, root guard (unit-tested)
examples/pycompat.rs  cross-language round-trip probe (see below)
```

## Building + tests

```bash
cd rust/scratch
cargo test        # 20 unit tests: ownership, expiry, caps, projection, WAL...
```

## Cross-compat verification

`examples/pycompat.rs` drives one store; a python one-liner drives the other,
against the SAME db dir:

```bash
cd rust/scratch && mkdir -p /tmp/scratch-compat/scratch-data

# 1. Rust writes an entry
printf '{"nmap_status":{"ports":[22,80],"host":"10.0.0.5"}}' | \
  cargo run --quiet --example pycompat -- store \
  /tmp/scratch-compat/scratch.db /tmp/scratch-compat/scratch-data agent-a nmap_status
# → {"scratch_ref":"scratch:...","stored_bytes":N,...}

# 2. Python reads the Rust-written entry
python3 -c "
import sys; sys.path.insert(0, '../../utils')
from scratch_store import ScratchStore
import json
s = ScratchStore('/tmp/scratch-compat/scratch.db', '/tmp/scratch-compat/scratch-data')
env = s.retrieve(json.load(sys.stdin)['scratch_ref'], agent_id='agent-a')
assert env['status'] == 'ok' and env['result']['nmap_status']['ports'] == [22, 80]
print('python read rust-written entry:', env['tool_id'])
" <<< '{"scratch_ref":"scratch:<paste from step 1>"}'

# 3. Python writes, Rust reads
python3 -c "
import sys; sys.path.insert(0, '../../utils')
from scratch_store import ScratchStore
s = ScratchStore('/tmp/scratch-compat/scratch.db', '/tmp/scratch-compat/scratch-data')
print(json.dumps(s.store({'web': {'status': 200}}, agent_id='agent-b', tool_id='session_get')))
" > /tmp/pyref.json
cargo run --quiet --example pycompat -- retrieve \
  /tmp/scratch-compat/scratch.db /tmp/scratch-compat/scratch-data agent-b \
  "$(python3 -c "import json; print(json.load(open('/tmp/pyref.json'))['scratch_ref'])")"
```

Both directions must report `status: ok` with the original payload intact.

## Where this slots in

- Today the python projection layer (`utils/result_projection.py`) is the only
  `store()` caller; this crate gives the rust/brain worker lane the same
  scratch primitive for when projection moves closer to execution.
- Same store as the deb lane when `WORKSPACE_ROOT` is shared (the env-default
  constructor mirrors python's bare `ScratchStore()`).