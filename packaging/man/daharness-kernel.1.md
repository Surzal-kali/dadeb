---
title: daharness-kernel(1)
---

# NAME

daharness-kernel — Jupyter tool kernel for the daharness framework

# SYNOPSIS

**daharness-kernel** [*--kernel* | *--install-kernelspec*]

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

# INSTALLING THE KERNELSPEC

Frontends find the kernel through its kernelspec. Register it once:

    daharness-kernel --install-kernelspec

This writes *daharness/kernel.json* into the invoking user's kernel
directory (*~/.local/share/jupyter/kernels*); the spec points back at the
packaged *tool_repl.py --kernel*, so `jupyter kernelspec list` showing
*daharness* is the attach-ready signal and
`jupyter kernelspec uninstall daharness` removes it. Under sudo the
installer resolves the real owner via **DAHARNESS_KERNEL_OWNER** (fallback:
SUDO_UID, else file owner) and lands the spec in that user's directory, not
in */root*. *daharness-repl --install-kernelspec* is the same passthrough
under a different wrapper. The kernel dispatches through the same Brain
socket as the services lane (see FILES).

# DEPENDENCIES

The kernel lane hard-imports the Jupyter closure, so the deb ships it as
Depends: **python3-ipykernel** (pulls *python3-ipython*,
*python3-jupyter-client*, *python3-zmq*, *python3-tornado*); Kali builds
these against the system python. In a checkout, restore the lane with
`pip install -e ".[jupyter]"`. Without it the unit fails fast — kernel_lane
prints the remediation string above the traceback (journalctl -u
daharness-kernel).

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