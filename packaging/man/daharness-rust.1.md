% DAHARNESS-RUST(1) daharness 0.2.0 | daharness manual

# NAME

daharness-rust — the python/c to python/rust upgrade lane for the daharness deb

# SYNOPSIS

**daharness-rust** *status*

**daharness-rust** *toolchain*

**daharness-rust** *build* [*--no-pcap*]

**daharness-rust** *smoke*

**daharness-rust** *all*

**daharness-rust** *brain* [*--canonical*]

# DESCRIPTION

The daharness **0.2.0** deb ships the three rust crates under
`/usr/share/daharness/rust/` as **source** — *scratch* (port of the
scratch store), *pcap* (nano-pcap codec/dissector/search core with an
optional libpcap capture feature), and *brain* (the rust Brain sidecar:
transport, framing, typed dispatch, python tool-worker IPC, and the OS
singleton dance). The deb build lane itself stays python + C and
network-isolated by policy: no cargo Build-Depends, nothing compiles at
package time.

Building and verifying the rust lane is therefore the user's opt-in
upgrade step, and **daharness-rust** is its one command. The network
contract is explicit:

- **status** and **brain** never touch the network.
- **toolchain**, **build**, and **smoke** are deliberate fetches —
  crates.io on the first run only: `Cargo.lock` ships inside every
  crate and **--locked** pins the resolve.

Installing stays offline; the rust upgrade is explicit. That is the
shape the package policy wants, and why nothing here is automatic.

**Nothing built by this lane replaces the shipped python service
lanes.** `daharness.service` keeps running the python stack; tool
execution, the registry, the scope gate, and the execution tracker stay
in python by design — the rust brain is an opt-in *sidecar* whose
python tool-worker executes tools through the shared `tool_exec` core.

# COMMANDS

## status

Offline inventory: shipped sources and their versions, rust toolchain
presence (with the exact remediation hint when missing), libpcap dev
availability, per-crate build stamps, the built brain binary, and the
canonical brain socket. Prints the next step for every gap. Never
invokes cargo, never downloads.

## toolchain

Installs the build toolchain — `rustc`, `cargo`, `pkg-config`,
`libpcap-dev` (the pcap crate's capture feature links libpcap) — via a
noninteractive `apt-get install`. Needs root and network. Boxes without
apt: the error names the packages instead.

## build

`cargo build --release --locked` for each crate, with build output
redirected *out of the read-only package tree* into the state root
(`$WORKSPACE_ROOT/rust/target`, default `/var/lib/daharness/rust/target`,
daharness-group shared 2770). Per-crate `[ok]/[--]` lines; a successful
crate drops a *crate.build.ok* stamp (rustc version) that **status**
reads. On a real failure nothing is half-installed — the deb's python
stack never touches these crates. *--no-pcap* (or
`DAHARNESS_RUST_NO_PCAP=1`) builds the pcap crate's dependency-free
codec core when the libpcap capture lane is unwanted; a plain failure
on pcap points at the same remedy.

## smoke

`cargo test --release --locked` per crate — verifies the ports hold
their semantics on *your* box (the same suites upstream CI runs). A
failing suite prints the verbose rerun command and the lane refuses to
declare itself verified.

## all

The one-command upgrade: toolchain && build && smoke.

## brain

Runs the rust sidecar lane end-to-end: starts the python tool-worker
(`rust/brain/worker.py`, which imports the harness registry and
executes through the shared `tool_exec` core) and then the compiled
brain binary in the foreground. By default this is a **private lane**
— its own brain and worker sockets under
`$WORKSPACE_ROOT/run/`, so it coexists with the shipped python
sidecar. With *--canonical* it takes the real Brain socket path
(`$BRAIN_SOCKET` from the profile plumbing, e.g.
`/run/daharness/brain.sock`); a live python sidecar on that socket is
probed first and **refused** with `systemctl stop daharness` — the
brain binary's own flock/connect-probe singleton guard is the deeper
fence against races. Smoke it from another shell with
`python3 /usr/share/daharness/rust/brain/smoke.py <socket>`.

# FILES

- ``/usr/share/daharness/rust/{scratch,pcap,brain}/``— shipped crate
  sources (Cargo.locks included)
- `/var/lib/daharness/rust/target/` — build outputs + per-crate
  `*.build.ok` stamps (override: `DAHARNESS_RUST_TARGET`)
- ``$WORKSPACE_ROOT/run/brain-worker.sock``— the lane's python
  tool-worker socket
- `$WORKSPACE_ROOT/run/brain-rust.sock` — the lane's brain socket
  (private default; `--canonical` / `DAHARNESS_RUST_BRAIN_SOCKET`
  override)

# ENVIRONMENT

- `DAHARNESS_RUST_SRC` — crate sources root (default
  `/usr/share/daharness/rust`; dev checkouts override)
- `DAHARNESS_RUST_TARGET` — build output root
- `DAHARNESS_RUST_NO_PCAP` — `1` builds the pcap codec core without
  the capture feature
- `DAHARNESS_RUST_BRAIN_SOCKET`, `DAHARNESS_RUST_WORKER_SOCKET`,
  `DAHARNESS_RUST_RUN_DIR` — brain socket, worker socket, run dir
- `BRAIN_BIN` — brain binary path (default
  `$DAHARNESS_RUST_TARGET/release/brain`)
- `BRAIN_WORKER_DEMO` — `1` runs the worker's demo registry (stdlib
  only) instead of importing the harness registry
- `WORKSPACE_ROOT` — state root (profile plumbing / conffile fill it;
  defaults `/var/lib/daharness`)

# EXIT STATUS

Zero on success; nonzero with an honest message naming the fix. **all**
short-circuits at the first failing step.

# EXAMPLES

```
daharness-rust status
sudo daharness-rust all
daharness-rust brain --canonical
```

# SEE ALSO

daharness-index(1), daharness(1), daharness-tools(7), daharness-safety(7)

The rust-lane milestone status and the three-piece round-trip walkthrough
live in `/usr/share/daharness/rust/brain/README.md`.