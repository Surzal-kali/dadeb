# .dacustoms — Operator-Authored Tools

Out-of-tree Python tools that survive package updates by construction. Your
custom tools live in `~/.dacustoms/` (or `$DACUSTOMS_DIR`), completely outside
the framework's code tree. dpkg and git never see them; an `apt upgrade` can't
overwrite them; a `git pull` can't conflict with them.

## Quick start

```bash
# 1. Create the directory + package init
mkdir -p ~/.dacustoms
touch ~/.dacustoms/__init__.py

# 2. Copy the example or write your own
cp /usr/share/daharness/packaging/dacustoms/example_port_knock.py ~/.dacustoms/
# (dev tree: cp packaging/dacustoms/example_port_knock.py ~/.dacustoms/)

# 3. Verify it's discovered
daharness-repl  # then: list dacustoms

# 4. Syntax-check your modules
# From the framework:
#   framework_doctor(provider='customs')
```

## How tool_ids work

Your tools are prefixed `dacustoms.` — a clear rubber stamp of "user-authored":

| Your file | Your function | tool_id |
|---|---|---|
| `~/.dacustoms/myhelper.py` | `scan_stuff` | `dacustoms.myhelper.scan_stuff` |
| `~/.dacustoms/sub/mod.py` | `do_thing` | `dacustoms.sub.mod.do_thing` |

This prefix means your tools **can never collide** with upstream tool_ids, even
after a framework reorg or rename. The model sees the prefix and knows these
are your tools, not shipped ones.

## Two ways to add a tool

### Option A — `@framework_tool` function (recommended)

Semantically discoverable by the model. The doc string is embedded in the
vector registry, so the model can find your tool by intent.

```python
from constants import framework_tool

@framework_tool("Scan a custom protocol on the target.")
def my_scan(target, port=8080):
    # your logic here
    return {"status": "ok", "result": ...}
```

### Option B — argparse CLI script

Discovered statically (AST analysis, never imported at index time). Runs as
a subprocess. The module docstring becomes the embedding text; argparse flags
become the parameter schema.

```python
"""My custom CLI tool — does X on the target."""
import argparse

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--target", required=True)
    p.add_argument("--port", type=int, default=80)
    args = p.parse_args()
    # your logic here

if __name__ == "__main__":
    main()
```

## Rules

1. **No side effects at module level.** The Brain's startup scan imports your
   module to register `@framework_tool` callables. `argparse.parse_args()` at
   module level will kill the scan. Wrap argparse in
   `if __name__ == "__main__":`.

2. **The scope gate is not weakened.** Your tools that send traffic are
   subject to the same scope gate as shipped tools. A customs module is
   operator-authored code — same trust level as your own shell.

3. **`_NO_LOCAL_TOOL = True`** opts a module out of the static argparse mint.
   Use it for modules whose argparse is internal plumbing (a job subprocess
   runner, not an operator CLI). `@framework_tool` members still register.

## The doctor

Check your modules for syntax errors without executing them:

```
framework_doctor(provider='customs')
```

Returns per-file status with line numbers. The probe uses `ast.parse` (zero
execution) — it will never import a module that opens sockets.

## Lane resolution — one dir, every lane

The customs lane is lane-agnostic: the Brain sidecar, the in-process
fallback, the REPL, the gateway, and the kernel all resolve the **same**
`DACUSTOMS_DIR`. There is no "customs under brain vs in-process" split —
the design that gated the lane behind a service-identity guard was
rescinded 2026-10-23 because `framework_doctor` itself runs on the Brain,
so the guard made the doctor report customs clean from the in-process
fallback (Brain down) and broken from the Brain (Brain up) — a split-brain
that tracked the socket, not the customs dir.

On the **deb profile**, pin `DACUSTOMS_DIR` in `/etc/daharness/daharness.env`
so the service-user Brain and the operator shell resolve the same path
instead of each lane's own `$HOME`:

```
DACUSTOMS_DIR=/var/lib/daharness/dacustoms
```

The state root is group-readable (2770 setgid), so the `daharness` group
sees the customs modules from every lane. An operator who keeps customs in
`$HOME` sets `DACUSTOMS_DIR=~/.dacustoms` in their shell **and** in
`daharness.env` — both lanes must agree on the path.

## Configuration

| Env var | Default | Effect |
|---|---|---|
| `DACUSTOMS_DIR` | `~/.dacustoms` | Customs directory path. Empty = default (per-lane `$HOME`). `off`/`disabled` = lane disabled. Pin in `daharness.env` on the deb profile so every lane resolves the same dir. |