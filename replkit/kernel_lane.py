"""Jupyter kernel lane: ZMQ kernel + kernelspec install.

A sibling to the interactive REPL's embedded ``ipython`` command: instead
of an in-terminal InteractiveShellEmbed (prompt_toolkit UI — bottom
toolbar, F2 editor), start a real ZMQ kernel speaking the Jupyter
protocol. Any frontend attaches and runs cells against the same
namespace: jupyter console --existing <file>, qtconsole, JupyterLab, VS
Code, PyCharm. The frontend renders the UI; the kernel owns the
namespace. The terminal-only sugar does not exist over ZMQ — that lane
stays in the REPL. Keep frontends LOCAL: cells execute against live
targets and tool output must not egress to third parties (same rule as
SECRETARY_MODEL).
"""

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# Root-spawned kernel artifacts: chown handling lives here too.
_KERNEL_NAMESPACE: Dict[str, Any] = {}


def _kernel_owner() -> Optional[tuple]:
    """Resolve the (uid, gid) to hand root-spawned kernel artifacts to.

    The REPL typically runs as root (raw sockets, MSF, ZAP); files it spawns
    come out root-owned and 0600 — and sudo points HOME at /root, so
    desktop-user IDEs can neither find nor read them. Resolution order:

    1. ``DAHARNESS_KERNEL_OWNER`` env — explicit name or numeric uid.
    2. ``SUDO_UID``/``SUDO_GID`` — the user who invoked sudo.
    3. Owner of this checkout — survives ``sudo su -`` (SUDO_* is gone).

    None when not root or nothing resolves: artifacts keep root ownership.
    """
    if os.geteuid() != 0:
        return None
    import pwd
    spec = os.getenv("DAHARNESS_KERNEL_OWNER", "").strip()
    if spec:
        try:
            pw = pwd.getpwuid(int(spec)) if spec.isdigit() else pwd.getpwnam(spec)
            return pw.pw_uid, pw.pw_gid
        except (KeyError, ValueError):
            print(f"  DAHARNESS_KERNEL_OWNER={spec!r} unresolvable; "
                  f"kernel artifacts stay root-owned.", flush=True)
            return None
    sudo_uid = os.getenv("SUDO_UID", "")
    sudo_gid = os.getenv("SUDO_GID", "")
    if sudo_uid.isdigit() and sudo_gid.isdigit():
        return int(sudo_uid), int(sudo_gid)
    try:
        st = Path(__file__).resolve().parent.parent.stat()
        if st.st_uid != 0:
            return st.st_uid, st.st_gid
    except OSError:
        pass
    return None


def _chown_kernel_artifact(path, recursive: bool = False, stream=None) -> None:
    """Chown a root-spawned kernel artifact to the resolved desktop user.

    No-op unless running as root with a resolvable owner (see
    ``_kernel_owner``). Only paths whose ownership differs are touched; one
    notice line is printed when something changed.
    """
    owner = _kernel_owner()
    if owner is None:
        return
    uid, gid = owner
    p = Path(path)
    targets = [p]
    if recursive:
        try:
            targets.extend(sorted(p.rglob("*")))
        except OSError:
            pass
    changed = False
    for t in targets:
        try:
            st = t.stat()
            if (st.st_uid, st.st_gid) != (uid, gid):
                os.chown(t, uid, gid)
                changed = True
        except OSError:
            pass
    if changed:
        import pwd
        try:
            name = pwd.getpwuid(uid).pw_name
        except KeyError:
            name = str(uid)
        print(f"  chown {p}{' (recursive)' if recursive else ''} -> {name}: "
              f"root-spawned artifact; IDEs running as {name} can attach.",
              file=stream if stream is not None else sys.stdout, flush=True)


def _launch_kernel(kernel_argv: Optional[List[str]] = None) -> None:
    """Start a Jupyter kernel with the framework namespace in ``user_ns``.

    ``python tool_repl.py --kernel`` (standalone) or spawned by a frontend
    through the kernelspec installed by ``--install-kernelspec``, which
    appends ``-f {connection_file}`` to the argv.

    Top-level ``await tool(...)`` works: ZMQInteractiveShell rewrites cells
    as coroutines on the kernel's own asyncio loop — the notebook-world twin
    of the REPL's ``shell.enable_gui("asyncio")`` wiring.
    """
    from ipykernel.ipkernel import IPythonKernel
    from ipykernel.kernelapp import IPKernelApp

    from replkit.core import discover_tools
    from replkit.namespace import build_ipython_namespace

    global _KERNEL_NAMESPACE

    # flush=True: stdout is block-buffered when redirected (daemon, log
    # capture); the kernel's SIGTERM shutdown path can skip interpreter
    # flushes, losing the banner — including the connection-file path the
    # operator needs to attach.
    print("Discovering tools...", flush=True)
    manifests = discover_tools()
    _KERNEL_NAMESPACE = build_ipython_namespace(manifests)
    tool_count = sum(1 for v in _KERNEL_NAMESPACE.values()
                     if callable(v) and hasattr(v, "__manifest__"))

    # Loud tripwire: a 0-tool kernel is a resolution failure (the scan
    # silently skips tool roots that don't exist), not an empty framework.
    # Without this the kernel boots fine and every cell dies with NameError.
    if tool_count == 0:
        from daharness.registry import ALLOWED_TOOL_ROOTS, WORKSPACE_ROOT as _root
        missing = [str(p) for p in ALLOWED_TOOL_ROOTS if not p.exists()]
        print(
            "  ERROR: 0 tools discovered — the tool scan found nothing.\n"
            f"    workspace root resolved to: {_root}\n"
            f"    tool roots missing: {missing or 'none (scan found files but minted no tools)'}\n"
            "    Hint: a WORKSPACE_ROOT pinned to a path that doesn't exist in\n"
            "    this lane (e.g. the HOST path from the shared .env inside a\n"
            "    bind-mounted container) empties discovery. The resolver falls\n"
            "    back to the code checkout, so this usually means the tree is\n"
            "    missing or the scan is broken — inspect the roots above.",
            flush=True,
        )

    # Root-spawned kernel: sudo points HOME at /root, so the connection
    # file would land where desktop-user IDEs can't even traverse. Redirect
    # it into the resolved owner's runtime dir (chowned after the app
    # writes it); must happen before IPKernelApp reads the env.
    owner = _kernel_owner()
    if owner is not None and not os.getenv("JUPYTER_RUNTIME_DIR"):
        import pwd
        os.environ["JUPYTER_RUNTIME_DIR"] = str(
            Path(pwd.getpwuid(owner[0]).pw_dir) / ".local/share/jupyter/runtime")

    class FrameworkKernel(IPythonKernel):
        """IPython kernel with the framework's kitted namespace stamped in."""

        implementation = "daharness"

        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            # user_ns is forwarded to the shell at construction; merge the
            # framework namespace in so tool aliases become committed globals.
            self.shell.user_ns.update(_KERNEL_NAMESPACE)

    # ipykernel swaps sys.stdout/sys.stderr for iopub OutStreams during
    # app.initialize(); prints after that land in the ZMQ channel, never on
    # the operator's terminal. Capture the real stderr first and banner
    # through it (stderr = where ipykernel's own kernel hints go).
    real_err = sys.stderr
    app = IPKernelApp.instance(kernel_class=FrameworkKernel)
    app.initialize(kernel_argv if kernel_argv is not None else [])
    conn_file = str(Path(getattr(app, "abs_connection_file", None)
                         or app.connection_file).resolve())
    tty = sys.stdin.isatty()
    banner = [
        f"  daharness kernel up — {tool_count} tools in user_ns.",
        f"  connection file: {conn_file}",
        "  Attach with any Jupyter-protocol frontend, e.g.:",
        f"      jupyter console --existing {conn_file}",
        "  New notebook? Run --install-kernelspec once, then pick the",
        "  'daharness' kernel in the frontend's kernel picker.",
        "  Exit: Ctrl-C twice within 3s in this terminal."
        if tty
        else "  Exit: shutdown_request from a client (or SIGTERM).",
        "  Keep frontends LOCAL — tool output must not egress to third parties.",
    ]
    for line in banner:
        print(line, file=real_err, flush=True)
    # Hand the connection file + runtime dir to the desktop user so IDEs
    # running as that user can read/attach without chown hops.
    if owner is not None:
        _chown_kernel_artifact(conn_file, stream=real_err)
        _chown_kernel_artifact(Path(conn_file).parent, stream=real_err)

    # ipykernel sets SIGINT to SIG_IGN while idle (kernelapp.init_signal)
    # because frontends use it for cell interrupts via pre/post_handler_hook
    # swaps — so a bare terminal has no easy exit. Frontend-spawned kernels
    # have no controlling tty, so arm a double-press Ctrl-C exit only for
    # tty launches. While a cell runs, ipykernel swaps SIGINT to
    # default_int_handler (single Ctrl-C interrupts sync cells; async cells
    # on Python 3.14 can't be aborted mid-await — upstream ipykernel
    # limitation, see README), and ours is restored afterward. SystemExit
    # unwinds app.start() and ipykernel's atexit hooks remove the
    # connection file.
    if tty:
        import signal

        def _tty_exit(signum, frame, _state={"t": 0.0}):
            now = time.monotonic()
            if now - _state["t"] > 3.0:
                _state["t"] = now
                print("\n  Ctrl-C again within 3s to shut the kernel down.",
                      file=real_err, flush=True)
                return
            print("\n  shutting down daharness kernel...", file=real_err, flush=True)
            raise SystemExit(0)

        signal.signal(signal.SIGINT, _tty_exit)
    app.start()


def _install_kernelspec() -> None:
    """Register the ``daharness`` kernel in the user kernelspec directory.

    ``python tool_repl.py --install-kernelspec``
    Afterwards every Jupyter-aware frontend (JupyterLab, VS Code, PyCharm)
    lists "daharness (framework tools)" in its kernel picker, and notebook
    cells run on framework tools + the live Brain session. The spec points
    back at the top-level ``tool_repl.py`` shim with ``--kernel``, so it
    always runs the checked-out tree's tool set.
    """
    import tool_repl  # the load-bearing shim filename (see replkit/__init__)

    from jupyter_client.kernelspec import KernelSpecManager

    spec = {
        "argv": [
            sys.executable,
            str(Path(tool_repl.__file__).resolve()),
            "--kernel",
            "-f",
            "{connection_file}",
        ],
        "display_name": "daharness (framework tools)",
        "language": "python",
        # Frontend interrupt buttons route through the control channel
        # instead of SIGINT straight to the kernel PID — the kernel then
        # signals its whole process group, so long-running tool subprocesses
        # spawned by a cell get interrupted too, and the signal never
        # collides with the terminal double-Ctrl-C exit on tty launches.
        "interrupt_mode": "message",
        # Advertise DAP debugger support so JupyterLab shows the debugger
        # panel + toggle. ipykernel backs this with debugpy (in
        # requirements.txt); without this key the frontend hides all
        # debugger UI even though the kernel is perfectly capable.
        # Must be nested under "metadata" — JupyterLab reads
        # metadata.debugger, not a top-level key (matches the stock
        # ipykernel kernelspec schema).
        "metadata": {
            "debugger": True,
        },
    }
    ksm = KernelSpecManager()
    kdir = Path(ksm.user_kernel_dir) / "daharness"
    owner = _kernel_owner()
    if owner is not None:
        # Root install: sudo points HOME (and thus ksm.user_kernel_dir) at
        # /root, where the desktop user's frontends never look. Install into
        # the resolved owner's jupyter dir instead.
        import pwd
        pw = pwd.getpwuid(owner[0])
        base = os.getenv("JUPYTER_DATA_DIR") or Path(pw.pw_dir) / ".local/share/jupyter"
        kdir = Path(base) / "kernels" / "daharness"
        print(f"  Running as root — installing into {pw.pw_name}'s kernel dir "
              f"(sudo points HOME at /root).")
    kdir.mkdir(parents=True, exist_ok=True)
    (kdir / "kernel.json").write_text(json.dumps(spec, indent=2) + "\n")
    _chown_kernel_artifact(kdir, recursive=True)
    print(f"Installed kernelspec 'daharness' -> {kdir / 'kernel.json'}")
    print("  It now appears in every frontend's kernel picker (JupyterLab,")
    print("  VS Code, PyCharm); `jupyter kernelspec list` shows it.")
    print("  Remove with: jupyter kernelspec uninstall daharness")