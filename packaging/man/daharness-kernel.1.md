---
title: daharness-kernel(1)
---

# NAME

daharness-kernel — Jupyter tool kernel for the daharness framework

# SYNOPSIS

**daharness-kernel** [*--kernel*]

# DESCRIPTION

Launches an ipython kernel (*tool_repl.py --kernel*) whose namespace is the
daharness tool surface, attachable from any local Jupyter frontend. It runs
under the *daharness-kernel.service* systemd unit in the system profile.

Framework tools resolve in the kernel as **bare tool names**: no imports, and
no collision risk. Every call must be **awaited** — the namespace injects async
wrappers that dispatch through `run_tool`; without *await* you receive a
coroutine object and the tool never executes.

Results arrive wrapped in a transport envelope:

    {status, result, _elapsed_s}

The tool's own fields sit under *result*. Envelope helpers ship in the
namespace (auto-unwrapping): **keys**(value), **pluck**(value, key),
**find**(value, key), **grep**(value, pattern). Prefer these over guessing the
nesting.

# ENVIRONMENT

**DAHARNESS_KERNEL_OWNER**
: Name or uid to chown the kernel connection file and runtime artifacts to,
  so the attaching operator's IDE can reach them. Empty falls back to the uid
  inferred by the launcher (SUDO_UID, else file owner).

# FILES

*/run/daharness/brain.sock* — shared with *daharness(1)*; the kernel
dispatches tools through the same Brain socket.

# SEE ALSO

**daharness(1)**, **daharness-repl(1)**, **daharness.env(5)**