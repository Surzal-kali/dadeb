import logging
import asyncio
import os
import socket
import ctypes
import fcntl
import inspect
import importlib
import functools
import json
import signal
import struct
import sys
from pathlib import Path
from typing import Any
from collections.abc import Callable

# This file is often launched directly (python listeners/thebrain.py), which
# puts listeners/ -- not the framework root -- on sys.path, so top-level
# imports like 'constants' and 'listeners.*' would fail. Add the root first.
_FRAMEWORK_ROOT = Path(__file__).resolve().parent.parent
if str(_FRAMEWORK_ROOT) not in sys.path:
    sys.path.insert(0, str(_FRAMEWORK_ROOT))

from constants import framework_tool, brain_socket_path  # noqa: F401 — framework_tool re-exported for memories.py
from listeners.execution_tracker import EXECUTION_TRACKER

# Ambient identity plumbing (Phase 0) — imported lazily per call site, but
# the set/reset pair is bound here so the sync-tool wrapper below can close
# over them even when utils.agent_identity import happens inside the handler.
try:
    from utils.agent_identity import (
        set_current_agent_id as _set_agent,
        reset_current_agent_id as _reset_agent,
    )
except Exception:  # pragma: no cover — identity must never wedge startup
    from typing import Any as _Any

    def _set_agent(agent_id) -> _Any:
        """Type-compatible no-op fallback (matches set_current_agent_id)."""
        return None

    def _reset_agent(token) -> None:
        """Type-compatible no-op fallback (matches reset_current_agent_id)."""
        return None

# --- dedicated tool-executor pool (2026-09-25 executor-starvation fix) -------
#
# Sync tools previously ran on ``loop.run_in_executor(None, ...)`` — the
# DEFAULT pool, sized min(32, cpu+4) (≈6-8 threads inside the workbench
# container). A wedged tool (an ssh_exec blocked on a command chain that
# reads stdin or spawns a daemon child) pinned its thread forever; the OWUI
# wrapper timed out at 600s, the model retried, and after 3-4 wedged calls
# the pool was exhausted — every OTHER sync tool then queued forever and the
# whole stack appeared frozen until the container was reset.
#
# A dedicated, larger pool isolates tool execution: wedged tool threads can
# never starve the loop's default executor (DNS lookups, subprocess pipes,
# library internals that also use it), and BRAIN_TOOL_EXECUTORS gives the
# operator a concurrency dial.
_TOOL_EXECUTOR: "concurrent.futures.Executor | None" = None


def _tool_executor() -> "concurrent.futures.Executor":
    """Lazily build the dedicated executor for sync tool execution.

    Size: BRAIN_TOOL_EXECUTORS (default 16) — comfortably above the 6-8 the
    default pool offered, small enough that a runaway secretary can't fork-
    bomb the sidecar. Created once, on first sync-tool dispatch.
    """
    global _TOOL_EXECUTOR
    if _TOOL_EXECUTOR is None:
        import concurrent.futures
        workers = max(4, int(os.getenv("BRAIN_TOOL_EXECUTORS", "16")))
        _TOOL_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="brain-tool"
        )
    return _TOOL_EXECUTOR

EVENT_HANDLERS = {}

class FunctionRegistry:
    def __init__(self):
        self.tools: dict[str, Callable] = {}
        self.metadata: dict[str, dict] = {}
        # Per-session class instances, keyed by (session_id, class_key) so
        # concurrent agents (distinct session ids) get ISOLATED stateful tool
        # clients (e.g. separate MetasploitClient / RPC consoles) instead of
        # sharing one. Session "0" is the default/shared pool used by callers
        # that don't supply a session id (backward compatible with the old
        # single-instance behaviour).
        self._instances: dict[tuple, Any] = {}
        # tool_id -> (cls, method_name) for class-method tools, so dispatch can
        # rebind to the per-session instance. Module-level function tools have
        # no entry here and are called as-is (they're stateless).
        self._class_tools: dict[str, tuple] = {}

    def register(self, name: str, func: Callable, doc: str):
        self.tools[name] = func
        self.metadata[name] = {"doc": doc, "args": inspect.signature(func)}

    def get_tool(self, name: str) -> Callable | None:
        return self.tools.get(name)

    def get_metadata(self, name: str) -> dict | None:
        return self.metadata.get(name)

    @staticmethod
    def _class_key(cls) -> str:
        return f"{cls.__module__}.{cls.__qualname__}"

    def instance_for_session(self, session_id, cls):
        """Return the (lazily-created) class instance bound to a Brain session.

        Distinct session ids -> distinct instances, so concurrent agents don't
        share stateful clients. Session "0" is the shared default.
        """
        key = (str(session_id), self._class_key(cls))
        if key not in self._instances:
            # Prefer an explicit shared-instance classmethod (e.g.
            # MetasploitClient.get_instance) so brain-dispatched stateful
            # clients reuse the live handle bootstrap started, instead of a
            # bare cls() twin whose connection was never established. This
            # mirrors _resolve_callable in daharness/executor.py; without it
            # the brain path silently diverged from the in-process fallback
            # (which only became the active path once brain.sock was
            # unreachable, masking the bug until the umask fix made the
            # socket world-connectable). Per-session isolation still holds
            # for classes that don't define get_instance.
            factory = getattr(cls, "get_instance", None)
            if callable(factory):
                self._instances[key] = factory()
            else:
                self._instances[key] = cls()
        return self._instances[key]

    def _instance_for(self, cls):
        # Backward-compatible default-session binding used at scan time so the
        # registered bound method (and its signature metadata) match the legacy
        # single-instance behaviour for session "0" callers.
        return self.instance_for_session("0", cls)

    def scan_module(self, module):
        for name, obj in inspect.getmembers(module):
            if (
                inspect.isfunction(obj)
                and getattr(obj, "_is_framework_tool", False)
                # Register a function only in the module that DEFINES it, so a
                # tool re-exported in a package __init__ (auxiliaries/ and
                # payloads/ both do this) is not also registered under a phantom
                # <pkg>.__init__.<name> alias when scan_tools walks __init__.py.
                # Mirrors the obj.__module__ == module.__name__ guard the class
                # branch below already uses. (2026-10-30)
                and obj.__module__ == module.__name__
            ):
                tool_id = f"{module.__name__}.{name}"
                self.register(tool_id, obj, getattr(obj, "_tool_doc", ""))
                print(f"[+] Registered framework tool: {tool_id}")
            elif inspect.isclass(obj) and obj.__module__ == module.__name__:
                # @framework_tool methods on classes defined in THIS module
                for m_name, m_obj in inspect.getmembers(obj, inspect.isfunction):
                    if getattr(m_obj, "_is_framework_tool", False):
                        tool_id = f"{module.__name__}.{obj.__name__}.{m_name}"
                        try:
                            instance = self._instance_for(obj)
                            bound = getattr(instance, m_name)
                            self.register(tool_id, bound, getattr(m_obj, "_tool_doc", ""))
                            # Remember the class + method so dispatch can rebind
                            # to a per-session instance for caller isolation.
                            self._class_tools[tool_id] = (obj, m_name)
                            print(f"[+] Registered framework tool: {tool_id}")
                        except TypeError as e:
                            print(f"[!] Skipping {tool_id}: class needs constructor args ({e})")

registry = FunctionRegistry()

# Directories holding pythonic @framework_tool wrappers, scanned at sidecar
# startup. Deliberately narrow: metasploiting.py contributes 4 wrapper
# FUNCTIONS -- per-module MSF indexing stays out of the Brain entirely
# (bootstrap skips it separately). Excluded by default because they add
# startup weight or side effects, not tools: utils/ (heavy scapy import,
# zero tools), memories.py (instantiates MemoryService/chroma at import),
# bootstrap/api_gateway/daharness (harness machinery).
# Override with BRAIN_SCAN_DIRS="auxiliaries,memories.py"; empty disables.
# NOTE: utils/ as a directory stays out of the startup scan (packetcraft's
# scapy import is too heavy). The persistent-SSH session sidecar is
# registered separately in _startup_scan() via a direct module import — the
# Brain is the shared session broker for ssh:/listener: handles, and without
# it ssh: sessions strand in whichever process hit the in-process fallback
# (REPL / harness), invisible to the other lane.
DEFAULT_SCAN_DIRS = ("auxiliaries", "listeners", "payloads", "utils")


def scan_tools(scan_path: str) -> str:
    """Import modules under `scan_path` and register their @framework_tool
    callables. Accepts a directory (walked recursively) or a single .py file.

    Returns the same "SCAN_COMPLETE|..." / "ERROR: ..." string the SCAN_TOOLS
    event replies with.
    """
    try:
        path = Path(scan_path).resolve()
        found_tools = []

        if path.is_file():
            # Single module: its parent (normally the framework root) must be
            # importable from so 'from listeners.x import y' style imports work.
            if str(path.parent) not in sys.path:
                sys.path.insert(0, str(path.parent))
        elif (path / "__init__.py").exists():
            # If the scanned directory is itself a package, import its children
            # as pkg.child with the PARENT on sys.path. Otherwise a scan of e.g.
            # 'auxiliaries' derives the bare module name 'nmap', which collides
            # with the python-nmap library installed in the venv -- scanning the
            # WRONG module and registering nothing.
            if str(path.parent) not in sys.path:
                sys.path.insert(0, str(path.parent))
        elif str(path) not in sys.path:
            sys.path.insert(0, str(path))

        if path.is_file():
            candidates = [path]
        else:
            candidates = [Path(root) / f for root, _, files in os.walk(path) for f in files]

        for candidate in candidates:
            if not (candidate.name.endswith(".py") and candidate.name != "thebrain.py"):
                continue
            if candidate.parent == path or path.is_file():
                parts: List[str] = []
            else:
                parts = [p for p in candidate.parent.relative_to(path).parts
                         if p not in ("", ".")]
            prefix = path.name + "." if (path.is_dir() and (path / "__init__.py").exists()) else ""
            if parts or prefix:
                module_path = ".".join([prefix.rstrip(".")] + parts + [candidate.stem])
            else:
                module_path = candidate.stem

            try:
                mod = importlib.import_module(module_path)
                registry.scan_module(mod)

                # Collect metadata for the response
                for tool_id in registry.tools:
                    if tool_id.startswith(module_path):
                        found_tools.append(f"{tool_id}:{registry.metadata[tool_id]['doc']}")
            except (Exception, SystemExit) as e:
                # SystemExit: a naive script calling argparse.parse_args()
                # at module level exits 2 — catch it so one bad module
                # doesn't kill the whole scan pass.
                print(f"[!] Failed to scan module {module_path}: {e}")

        return "SCAN_COMPLETE|" + ",".join(found_tools)
    except Exception as e:
        return f"ERROR: Scan failed: {str(e)}"


def _startup_scan():
    """Prime the registry at sidecar startup so CALL_TOOL works immediately,
    without anyone having to send SCAN_TOOLS first."""
    raw = os.environ.get("BRAIN_SCAN_DIRS", ",".join(DEFAULT_SCAN_DIRS)).strip()
    if not raw:
        print("[*] BRAIN_SCAN_DIRS empty; skipping startup scan")
        return
    total = 0
    for entry in [e.strip() for e in raw.split(",") if e.strip()]:
        p = Path(entry)
        if not p.is_absolute():
            p = _FRAMEWORK_ROOT / entry
        before = len(registry.tools)
        status = scan_tools(str(p)).split("|", 1)[0]
        added = len(registry.tools) - before
        total += added
        print(f"[+] Startup scan {p.name}: {status} (+{added} tools)")

    # Shared-session broker: register the persistent SSH session tools
    # (utils.paramiko_client.*) DIRECTLY, not via DEFAULT_SCAN_DIRS. A direct
    # import keeps the canonical dotted tool_ids (scan_tools on a bare file
    # would import it as top-level "paramiko_client" and register ids the
    # harness/REPL can never match). The Brain's SessionManager then holds
    # every ssh:/listener: session, so a session the operator opens via the
    # REPL's Brain-routed `run` is visible to the agent through the Bridge
    # (and vice versa) — list_sessions is the shared view.
    try:
        import utils.paramiko_client as _paramiko_sidecar

        _before = len(registry.tools)
        registry.scan_module(_paramiko_sidecar)
        _added = len(registry.tools) - _before
        total += _added
        print(f"[+] Startup scan utils.paramiko_client: (+{_added} tools)")
    except Exception as e:
        print(f"[!] Startup scan utils.paramiko_client failed: {e}")
    print(f"[+] Brain registry primed: {total} tools available at startup")

class FrameworkEvent(ctypes.Structure):
    _fields_ = [
        ("event_type", ctypes.c_char * 32),
        ("session_id", ctypes.c_int),
        ("data", ctypes.c_char * 1024),
        ("data_len", ctypes.c_size_t),
    ]

# Get the directory where this script is located
SCRIPT_DIR = Path(__file__).resolve().parent
LIB_PATH = os.path.join(SCRIPT_DIR, "plugins", "frameit.so")
HEADER_FORMAT = "!I"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # guard against bogus/oversized length headers

lib = ctypes.CDLL(LIB_PATH)
# Bind path from the shared resolver: the socket lives in the checkout's
# run/ dir so every lane that mounts this tree (host REPL, jupyter kernel,
# open-terminal) reaches the SAME inode — a /tmp socket is per-namespace and
# can never cross a container boundary. $BRAIN_SOCKET overrides.
socket_path = str(brain_socket_path())

# Tell ctypes the C signature: void send_event(const FrameworkEvent *event);
lib.send_event.argtypes = [ctypes.POINTER(FrameworkEvent)]
lib.send_event.restype = None


def pack_message(payload: bytes) -> bytes:
    """Prefix payload with its 4-byte big-endian length."""
    return struct.pack(HEADER_FORMAT, len(payload)) + payload


async def read_message(reader: asyncio.StreamReader) -> bytes:
    """Read one length-prefixed message from a StreamReader.

    Raises asyncio.IncompleteReadError if the stream closes mid-message, and
    ValueError if the declared length is absurd (protects against a corrupt
    or malicious header driving an unbounded read).
    """
    header = await reader.readexactly(HEADER_SIZE)
    (length,) = struct.unpack(HEADER_FORMAT, header)
    if length > MAX_MESSAGE_SIZE:
        raise ValueError(f"declared message length {length} exceeds max {MAX_MESSAGE_SIZE}")
    return await reader.readexactly(length)

def _cleanup_brain_log():
    """Truncate /tmp/brain.log on Brain exit.

    Runs from start_brain()'s finally, which is reached on every controlled
    exit path: serve_forever() returning, and SIGINT/SIGTERM (both routed
    through task cancellation so the finally unwinds). SIGKILL still skips it.
    Truncates in place rather than unlinking so a concurrent reader never
    races on a vanished file; the inode stays, contents are emptied.
    """
    log_path = "/tmp/brain.log"
    try:
        if os.path.exists(log_path):
            with open(log_path, "w") as fh:
                fh.truncate(0)
            print(f"[+] Cleared {log_path} on exit")
    except OSError as e:
        # Best-effort: never let log cleanup mask or abort a real shutdown.
        print(f"[!] Could not clear {log_path}: {e}")


def socket_lane_perms(dir_mode: int) -> tuple[int, int, int]:
    """Map a socket-dir's permission bits to (umask, socket_perm, lock_perm).

    One decision point for every lane that shares run/: the socket dir's own
    mode says how lanes share it, and the bind follows that shape instead of
    forcing world access over it.

    - group-writable (system profile: RuntimeDirectoryMode 0770 /
      StateDirectoryMode 2770 setgid, operator joined via the daharness
      group) binds a 0770 socket and 0660 lock;
    - world-writable (legacy container lanes with no shared group) keeps the
      old 0777/0666 behavior;
    - owner-only (single-user dev checkout, umask 0022) gets 0700/0600.
    """
    if dir_mode & 0o020:
        return 0o007, 0o770, 0o660
    if dir_mode & 0o002:
        return 0o000, 0o777, 0o666
    return 0o077, 0o700, 0o600


async def start_brain():
    loop = asyncio.get_running_loop()
    # SIGTERM (what bootstrap.stop() sends) would otherwise kill the process
    # outright -- no Python unwinding, no cleanup -- leaving a stale socket
    # behind that passes every Path.exists() check while nothing listens on it.
    # Route both signals through task cancellation so the finally below runs.
    main_task = asyncio.current_task()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, main_task.cancel)
        except NotImplementedError:
            pass  # non-unix event loop; best effort only

    # Singleton guard via an exclusive flock on a separate lockfile. The
    # connect-probe below only catches a second Brain when the FIRST one's
    # socket file is still on disk -- but a reparented orphan (parent
    # bootstrap died; start_new_session=True keeps the brain alive, reparented
    # to init) goes on listening on an UNLINKED inode after /tmp is swept by
    # systemd-tmpfiles, invisible to Path.exists()/connect(). The flock catches
    # that: the orphan holds it, a new instance can't acquire it, and the
    # kernel releases it on death (even SIGKILL) so it can never go stale.
    # Acquired here in start_brain() ONLY -- never at import time -- so the
    # harness dispatch path and other modules importing listeners.thebrain
    # never contend on it. lock_fh is deliberately kept referenced for the
    # lifetime of serve_forever(); closing it (implicit on exit) releases the
    # lock.
    # Lock + socket live in the shared run/ dir (see brain_socket_path) so
    # the singleton guard crosses container boundaries too: a lane that
    # mounts this tree sees the same lockfile/socket inodes, and a second
    # Brain is refused here instead of racing across separate /tmp
    # namespaces (the duplicate-brain bug the old container entrypoint
    # worked around). Prepare the dir, then FOLLOW the lane's own sharing
    # shape instead of forcing world access over it: a group-writable dir
    # (system profile — RuntimeDirectoryMode 0770 / StateDirectoryMode 2770
    # setgid, operator joined via the daharness group) gets a 0770 socket
    # and 0660 lock; a world-writable dir (legacy container lanes with no
    # shared group) keeps the old 0777/0666 behavior; an owner-only dir
    # (single-user dev checkout, umask 0022) gets a 0700/0600 socket pair.
    # The old unconditional `chmod(sock_dir, 0o777)` widened /run/daharness
    # behind the unit's back — the exact world-writable socket dir this
    # permission pass was staged to close.
    sock_dir = os.path.dirname(socket_path) or "."
    try:
        os.makedirs(sock_dir, exist_ok=True)
    except OSError as e:
        print(f"[!] Could not prepare Brain socket dir {sock_dir}: {e}")
    try:
        _dir_mode = os.stat(sock_dir).st_mode
    except OSError:
        _dir_mode = 0
    _lane_umask, _sock_perm, _lock_perm = socket_lane_perms(_dir_mode)
    try:
        lock_fh = open(os.path.join(sock_dir, "brain.lock"), "w")
        lock_path = os.path.join(sock_dir, "brain.lock")
    except OSError:
        # Shared lockfile unwritable (poisoned ownership / immutable bit /
        # MAC). Fall back to a uid-scoped lockfile in /tmp so a bad shared
        # lock can't kill the sidecar; the singleton guard then applies
        # per-uid.
        lock_path = f"/tmp/brain.lock-{os.geteuid()}"
        lock_fh = open(lock_path, "w")
    # Ensure the lock file matches the lane's sharing shape (see the
    # socket-dir comment above) so a second instance can contest the
    # singleton only at the same trust level the socket itself allows.
    try:
        os.chmod(lock_path, _lock_perm)
    except OSError:
        pass  # best-effort; the file is still flockable by same-uid callers
    try:
        fcntl.flock(lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (BlockingIOError, OSError) as e:
        lock_fh.close()
        raise RuntimeError(
            f"another Brain holds {lock_path}; refusing to start a second "
            f"Brain (orphan listening on an unlinked socket?). {e}"
        ) from e

    # Unlink a STALE socket file before binding. This must NOT run at module
    # import time: any process importing listeners.thebrain (the harness
    # dispatch path, smb_scanner, listening.py, even this sidecar importing a
    # scanned module that imports it back) would delete the LIVE sidecar's
    # socket file, leaving the Brain serving on an unlinked inode while every
    # subsequent connect() failed with ENOENT. Guarded with a live-listener
    # probe so a second sidecar can never clobber a running one either.
    if os.path.exists(socket_path):
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            if probe.connect_ex(socket_path) == 0:
                raise RuntimeError(
                    f"{socket_path} already has a live listener; refusing to start a second Brain"
                )
        finally:
            probe.close()
        try:
            os.remove(socket_path)
        except PermissionError:
            # Stale socket owned by a different uid (e.g. root died and left
            # it; we're non-root and the socket dir lacks write permission).
            # We can't remove it, but we also can't bind over it.  Fail with
            # a clear message so the operator knows to delete it manually.
            raise RuntimeError(
                f"Stale socket {socket_path} is owned by a different user and "
                f"cannot be removed.  Run: "
                f"sudo rm {socket_path}"
            ) from None

    # Prime the registry BEFORE binding the socket, so the connect-probe in
    # bootstrap only reports "ready" once tools are actually callable.
    _startup_scan()

    async def handle_client(reader, writer):
        try:
            data = await read_message(reader)
        except (asyncio.IncompleteReadError, ValueError) as e:
            print(f"Dropped connection: {e}")
            writer.close()
            return

        try:
            message = data.decode()

            # Parse the event triplet: "event|session_id|data"
            try:
                event_type, session_id, payload = message.split('|', 2)
                session_id = int(session_id)
            except ValueError:
                print(f"Malformed event received: {message}")
                writer.write(pack_message(b"Error: Malformed event"))
                await writer.drain()
                return

            print(f"Received {event_type} for session {session_id}: {payload}")

            # Create the event struct. The FrameworkEvent.data field is a fixed
            # c_char*1024 buffer inherited from the legacy C plugin (frameit.so
            # / lib.send_event) and CANNOT carry payloads larger than 1023
            # bytes. The wire transport (pack_message/read_message) already
            # uses a 4-byte big-endian length prefix ("!I") and delivers the
            # FULL message intact -- so instead of truncating into the struct
            # and losing the tail of large CALL_TOOL arg dicts, pass the full
            # payload string through to dispatch for the Python-handled event
            # types. The struct is still populated (truncated) for the legacy
            # C send_event pathway at the bottom of dispatch, which only ever
            # dealt with small C events and never JSON tool args.
            event = FrameworkEvent()
            event.event_type = event_type.encode()[:31]
            event.session_id = session_id
            event.data = payload.encode()[:1023]
            event.data_len = len(payload)

            result = await dispatch(event, full_payload=payload)
            response = result.encode() if result else b"Event dispatched."
            writer.write(pack_message(response))
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError, ConnectionError) as e:
            # Client hung up before we finished sending the response. Harmless
            # to the server -- asyncio isolates per-connection callbacks -- but
            # unhandled it spams the log as "Unhandled exception in
            # client_connected_cb" with a full traceback. Log quietly instead.
            print(f"Client disconnected before response completed: {e}")
        finally:
            try:
                writer.close()
            except Exception:
                logging.getLogger(__name__).debug(
                    "swallowed exception in handle_client", exc_info=True)
    # Bind the socket at the lane's trust level: the umask swap lands the
    # permed mode atomically (no race window between bind and chmod).
    # 0777 is reserved for world-writable socket dirs (legacy container
    # lanes); group-shared lanes get 0770 and operator-group members
    # connect, while other local users cannot. When the framework was
    # launched via sudo (inherited umask 0022), a default-umask bind would
    # create the socket srwxr-xr-x — Unix domain sockets require WRITE
    # permission to connect, so only the owner (root) would reach it and
    # every operator-lane call silently fell back to in-process dispatch;
    # the explicit umask per lane replaces the old blanket 0.
    _old_umask = os.umask(_lane_umask)
    try:
        server = await asyncio.start_unix_server(handle_client, path=socket_path)
    finally:
        os.umask(_old_umask)
    # Remember which socket file inode WE bound, so the shutdown unlink below
    # can never delete a newer sidecar's live socket after we lingered past it.
    try:
        bound_ino = os.stat(socket_path).st_ino
    except OSError:
        bound_ino = None
    try:
        async with server:
            await server.serve_forever()
    finally:
        # The kernel does not unlink a socket when the owning process dies, so
        # a killed sidecar leaves a stale file that looks alive to every
        # Path.exists() check. Unlink on every exit path we can reach (SIGINT
        # via asyncio.run's cancellation, SIGTERM via the handler above) -- but
        # only if the file is still the one we bound. SIGKILL still leaks the
        # file; bootstrap's connect-probe sees through it.
        try:
            if bound_ino is not None and os.stat(socket_path).st_ino == bound_ino:
                os.unlink(socket_path)
        except (FileNotFoundError, OSError):
            pass
        _cleanup_brain_log()

async def dispatch(event, full_payload=None):
    event_type = event.event_type.decode().strip('\x00')

    # full_payload is the un-truncated message body the wire transport
    # delivered (pack_message/read_message already handle arbitrary sizes via
    # the "!I" big-endian length prefix). When absent (e.g. a legacy caller
    # that only has the FrameworkEvent struct), fall back to the struct's
    # 1024-byte buffer -- the old, truncating behaviour.
    payload_str = full_payload if full_payload is not None else event.data.decode().strip('\x00')

    # Handle tool discovery: "SCAN_TOOLS|session_id|path/to/scan"
    if event_type == "SCAN_TOOLS":
        scan_path = payload_str
        if not scan_path:
            # Default to framework root if no path provided
            scan_path = str(SCRIPT_DIR.parent)
        return scan_tools(scan_path)

    # Handle tool calls via the Brain
    if event_type == "CALL_TOOL":
        tool_id = "unknown"
        try:
            # Expecting data as "tool_id|args_json" (dict -> kwargs, list -> positional).
            # Use the full un-truncated payload -- large options dicts (many
            # RHOSTS, credential sets) routinely exceed the 1024-byte
            # FrameworkEvent.data buffer; reading event.data here would slice
            # mid-JSON, fail json.loads, and silently fall back to the legacy
            # comma-split producing garbage kwargs.
            payload = payload_str
            kwargs: dict[str, Any] = {}
            args: list = []
            if '|' in payload:
                tool_id, args_str = payload.split('|', 1)
                args_str = args_str.strip()
                if args_str:
                    try:
                        parsed = json.loads(args_str)
                        if isinstance(parsed, dict):
                            kwargs = parsed
                        elif isinstance(parsed, list):
                            args = parsed
                        else:
                            # Scalar payload (string/number/bool): reject instead
                            # of a positional call. Fuzz 2026-09-20: scalar args
                            # reached tool bodies as garbage and could hang them
                            # until BRAIN_DISPATCH_TIMEOUT. Legit positional
                            # callers send a JSON list.
                            return json.dumps({
                                "status": "error",
                                "tool_id": tool_id,
                                "error": (
                                    f"Malformed arguments for {tool_id}: expected a "
                                    f"JSON object (named args) or a JSON list "
                                    f"(positional), got {type(parsed).__name__}."
                                ),
                            })
                    except json.JSONDecodeError:
                        # Legacy fallback: bare comma-separated positional args —
                        # only for payloads that never looked like JSON. A
                        # malformed JSON OBJECT must NOT silently become garbage
                        # positional args (fuzz 2026-09-20 hang root cause).
                        if "{" in args_str or '"' in args_str:
                            return json.dumps({
                                "status": "error",
                                "tool_id": tool_id,
                                "error": (
                                    f"Malformed arguments for {tool_id}: payload is "
                                    "not valid JSON. Send arguments as a JSON object."
                                ),
                            })
                        args = [a for a in args_str.split(',') if a]
            else:
                tool_id = payload

            # Scope tool-disable list (defense-in-depth): a direct-socket
            # caller that skips the registry/executor path must still hit
            # the operator's disable brake. Same mtime-cached _load_state()
            # the executor uses, so both processes converge on the same list
            # within one call.
            try:
                from utils.scope_gate import is_disabled, disabled_reject_envelope
                _dis, _prefix = is_disabled(tool_id)
                if _dis:
                    return json.dumps(disabled_reject_envelope(tool_id, _prefix))
            except Exception:
                # scope_gate import must never wedge the Brain
                logging.getLogger(__name__).debug(
                    "swallowed exception in dispatch", exc_info=True)

            tool = registry.get_tool(tool_id)
            if tool:
                # Rebind class-method tools to a per-session instance so
                # concurrent agents don't share stateful clients (e.g. one
                # msfconsole handle between all agents). Module-level function
                # tools are stateless and called as-is. Session "0" (the
                # default, used by callers that don't supply a session id)
                # rebinds to the same shared instance as before — backward
                # compatible. ``event.session_id`` is the int the harness
                # resolved from the caller's agent/session id.
                if tool_id in registry._class_tools:
                    cls, m_name = registry._class_tools[tool_id]
                    instance = registry.instance_for_session(event.session_id, cls)
                    tool = getattr(instance, m_name)
                # Execute tool without blocking the event loop. Coroutine
                # functions MUST be awaited directly — run_in_executor on them
                # silently creates a coroutine that never runs.
                #
                # Fuzz 2026-09-20 residual fix: every execution is now tracked
                # (EXECUTION_TRACKER) so list_tool_executions /
                # kill_tool_execution can see and stop zombies, and
                # BRAIN_EXEC_CEILING (default 3600s, 0=off) hard-stops an
                # execution that outlives every caller's timeout.
                loop = asyncio.get_event_loop()
                EXECUTION_TRACKER.set_caller_session(event.session_id)
                # Ambient identity inside tool bodies (Phase 0): thread/async
                # workers inherit the resolved caller identity so identity-
                # bearing writes (jobs, evidence, memory) tag rows per agent.
                # The wire carries the executor's resolved session INT; the
                # authoritative string id is journaled by the dispatching
                # executor, so this prefix keeps Brain-side rows distinct
                # per agent without pretending to know the string spelling.
                _agent_ctx: Any = None
                _identity_wrapped: Any = None
                _inner_agent: Any = None
                try:
                    from utils.agent_identity import (
                        agent_id_context,
                        BRAIN_AGENT_PREFIX,
                    )
                except Exception:  # identity must never wedge the Brain
                    agent_id_context = None
                    BRAIN_AGENT_PREFIX = "s"
                try:
                    # The contextvar is a ContextVar: the async tool task
                    # inherits it via ensure_future; the sync pool thread does
                    # NOT (asyncio.to_thread copies context, run_in_executor
                    # does not) — so for sync tools the value is set inside
                    # the call itself via a context-wrapped partial.
                    if inspect.iscoroutinefunction(tool):
                        _agent_ctx = agent_id_context(
                            f"{BRAIN_AGENT_PREFIX}{event.session_id}"
                        )
                        _agent_ctx.__enter__()
                    else:
                        # Sync tools: run_in_executor does NOT copy the
                        # current context, so the value must be set INSIDE
                        # the worker thread — the call itself is wrapped.
                        _inner_agent = f"{BRAIN_AGENT_PREFIX}{event.session_id}"

                        def _identity_wrapped(fn, *a, **kw):
                            tok = _set_agent(_inner_agent)
                            try:
                                return fn(*a, **kw)
                            finally:
                                _reset_agent(tok)
                except Exception:  # identity must never wedge the Brain
                    _agent_ctx = None
                    _identity_wrapped = None
                    _inner_agent = None
                kind = "async" if inspect.iscoroutinefunction(tool) else "thread"
                exec_id = EXECUTION_TRACKER.begin(tool_id, event.session_id, kind)
                ceiling = float(os.getenv("BRAIN_EXEC_CEILING", "3600"))
                try:
                    if kind == "async":
                        task = asyncio.ensure_future(
                            tool(**kwargs) if kwargs else tool(*args)
                        )
                        EXECUTION_TRACKER.attach_task(exec_id, task)
                        result = (
                            await asyncio.wait_for(task, ceiling)
                            if ceiling > 0
                            else await task
                        )
                    else:
                        if kwargs:
                            if _identity_wrapped is not None:
                                call = functools.partial(
                                    _identity_wrapped, tool, **kwargs
                                )
                            else:
                                call = functools.partial(tool, **kwargs)
                        else:
                            if _identity_wrapped is not None:
                                call = functools.partial(
                                    _identity_wrapped, tool, *args
                                )
                            else:
                                call = functools.partial(tool, *args)
                        # Dedicated tool pool (2026-09-25): NOT the default
                        # executor. A wedged sync tool pins its thread for the
                        # ceiling duration (or forever for a thread the kill
                        # path cannot reap); on the default pool that starved
                        # every other sync tool after a few retries.
                        fut = loop.run_in_executor(_tool_executor(), call)
                        EXECUTION_TRACKER.attach_future(exec_id, fut)
                        result = (
                            await asyncio.wait_for(fut, ceiling)
                            if ceiling > 0
                            else await fut
                        )
                except TimeoutError:
                    verdict = await EXECUTION_TRACKER.kill(
                        exec_id,
                        force=True,
                        reason=f"BRAIN_EXEC_CEILING ({ceiling:.0f}s) exceeded",
                    )
                    print(f"[!] Ceiling-terminated {tool_id} ({exec_id}): {verdict}")
                    return json.dumps({
                        "status": "error",
                        "tool_id": tool_id,
                        "error": (
                            f"Execution of {tool_id} ({exec_id}) exceeded "
                            f"BRAIN_EXEC_CEILING ({ceiling:.0f}s) and was terminated "
                            f"on the Brain. Details: {verdict}"
                        ),
                    })
                except asyncio.CancelledError:
                    return json.dumps({
                        "status": "error",
                        "tool_id": tool_id,
                        "error": (
                            f"Execution of {tool_id} ({exec_id}) was cancelled "
                            "(kill_tool_execution or ceiling)."
                        ),
                    })
                finally:
                    EXECUTION_TRACKER.finish(exec_id)
                    if _agent_ctx is not None:
                        _agent_ctx.__exit__(None, None, None)

                print(f"[+] Tool {tool_id} executed successfully: {result}")
                # JSON status envelope — the harness parses this structurally
                # instead of string-matching on "SUCCESS"/"ERROR".  The result
                # is included as-is when JSON-serializable, stringified
                # otherwise so structured callers can read typed fields.
                try:
                    json.dumps(result)
                    serializable_result = result
                except (TypeError, ValueError):
                    serializable_result = str(result)
                return json.dumps({
                    "status": "success",
                    "tool_id": tool_id,
                    "result": serializable_result,
                })
            else:
                return json.dumps({
                    "status": "error",
                    "tool_id": tool_id,
                    "error": f"Tool {tool_id} not found in registry.",
                })
        except Exception as e:
            return json.dumps({
                "status": "error",
                "tool_id": tool_id,
                "error": f"Execution failed: {str(e)}",
            })

    handler = EVENT_HANDLERS.get(event_type)
    
    if handler:
        await handler(event)
    else:
        # Default: forward to the C library if no Python handler is found
        loop = asyncio.get_event_loop()
        loop.run_in_executor(None, lib.send_event, ctypes.byref(event))

if __name__ == "__main__":
    try:
        asyncio.run(start_brain())
    except (KeyboardInterrupt, asyncio.CancelledError):
        # Cancellation unwound start_brain, whose finally already unlinked the
        # socket. Swallow the noise so the sidecar exits cleanly on signal.
        pass



