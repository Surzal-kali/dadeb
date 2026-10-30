#!/usr/bin/env python3
"""dadeb Brain tool-worker.

The Rust brain owns the client-facing socket, framing, and dispatch ROUTING.
Tool EXECUTION stays here, in Python — this is the long-lived worker the brain
forwards CALL_TOOL / SCAN_TOOLS to, over the SAME length-prefixed framing
(4-byte big-endian length + payload) as listeners/thebrain.py. One wire format,
both links.

Backend selection (load_backend):
  * REAL: imports the harness registry + execution tracker and primes it with a
    startup scan. Requires the harness env (frameit.so built, scapy + tool deps
    installed) — i.e. a normal checkout on the box.
  * DEMO: a stdlib-only registry (demo.echo/add/sysinfo/sleep) + a no-op tracker,
    used when BRAIN_WORKER_DEMO=1 or when the real import fails (bare env). Lets
    the transport be smoke-tested without the full tool chain.

Both backends execute through the SAME core, tool_exec.execute_call_tool.

Run:
    BRAIN_WORKER_SOCKET=/run/daharness/brain-worker.sock python3 worker.py
    BRAIN_WORKER_DEMO=1 BRAIN_WORKER_SOCKET=run/brain-worker.sock python3 worker.py
"""
import asyncio
import json
import os
import struct
import sys
from pathlib import Path

# This worker lives at rust/brain/worker.py; put the framework ROOT on sys.path
# (rust/brain -> rust -> root) so `import tool_exec` and the `listeners` package
# resolve, same trick thebrain.py uses when launched directly.
_FRAMEWORK_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_FRAMEWORK_ROOT) not in sys.path:
    sys.path.insert(0, str(_FRAMEWORK_ROOT))

import tool_exec  # root-level, import-light shared execution core

# --- framing: identical wire shape to thebrain.py / the Rust codec ----------
HEADER = "!I"
HEADER_SIZE = struct.calcsize(HEADER)
MAX_MESSAGE_SIZE = 10 * 1024 * 1024


def worker_socket_path() -> str:
    return os.environ.get("BRAIN_WORKER_SOCKET", "run/brain-worker.sock")


def pack_message(payload: bytes) -> bytes:
    return struct.pack(HEADER, len(payload)) + payload


async def read_message(reader: asyncio.StreamReader) -> bytes:
    header = await reader.readexactly(HEADER_SIZE)
    (length,) = struct.unpack(HEADER, header)
    if length > MAX_MESSAGE_SIZE:
        raise ValueError(f"declared length {length} exceeds max {MAX_MESSAGE_SIZE}")
    return await reader.readexactly(length)


# --- DEMO backend (stdlib-only, scapy-free) ---------------------------------
def _echo(*args, **kwargs):
    return {"args": list(args), "kwargs": kwargs}


def _add(a, b):
    return a + b


def _sysinfo():
    return {"pid": os.getpid(), "python": sys.version.split()[0]}


async def _sleep(seconds):
    # Async tool, used to exercise the ceiling / kill path end to end.
    await asyncio.sleep(float(seconds))
    return f"slept {seconds}s"


class DemoRegistry:
    """Minimal FunctionRegistry-shaped stand-in so demo mode runs through the
    exact same tool_exec path as the real registry (get_tool / _class_tools /
    instance_for_session)."""

    def __init__(self):
        self._tools = {
            "demo.echo": _echo,
            "demo.add": _add,
            "demo.sysinfo": _sysinfo,
            "demo.sleep": _sleep,
        }
        self._class_tools = {}  # no class-method tools in the demo set

    def get_tool(self, name):
        return self._tools.get(name)

    def instance_for_session(self, session_id, cls):  # pragma: no cover - unused
        return cls()

    def names(self):
        return list(self._tools)


class NoopTracker:
    """A tracker that satisfies tool_exec's contract without real bookkeeping —
    enough for demo mode. The REAL EXECUTION_TRACKER (zombie reaping, ceilings,
    kill switch) is used in real mode."""

    def set_caller_session(self, session_id): pass
    def begin(self, tool_id, session_id, kind): return "demo-exec"
    def attach_task(self, exec_id, task): pass
    def attach_future(self, exec_id, future): pass
    def finish(self, exec_id): pass

    async def kill(self, exec_id, force=False, reason=""):
        return {"status": "noop", "reason": reason}


def load_backend():
    """Return (registry, scan_fn_or_None, tracker, mode)."""
    if os.getenv("BRAIN_WORKER_DEMO") == "1":
        print("[worker] BRAIN_WORKER_DEMO=1 — demo backend")
        return DemoRegistry(), None, NoopTracker(), "demo"
    try:
        from listeners.thebrain import registry, scan_tools, _startup_scan
        from listeners.execution_tracker import EXECUTION_TRACKER
        _startup_scan()  # prime the registry (scans the harness tool dirs)
        print(f"[worker] real backend — {len(registry.tools)} tools registered")
        return registry, scan_tools, EXECUTION_TRACKER, "real"
    except Exception as e:  # noqa: BLE001 — any import/scan failure -> demo
        print(f"[worker] real registry unavailable ({e!r}); falling back to demo backend")
        return DemoRegistry(), None, NoopTracker(), "demo"


REGISTRY, SCAN_FN, TRACKER, MODE = load_backend()


def handle_scan_tools(payload: str) -> str:
    if SCAN_FN is not None:
        # Real scan: path in payload, else the framework root (thebrain default).
        return SCAN_FN(payload or str(_FRAMEWORK_ROOT))
    tools = ",".join(f"{name}:(demo tool)" for name in REGISTRY.names())
    return "SCAN_COMPLETE|" + tools


async def handle_client(reader, writer):
    try:
        data = await read_message(reader)
    except (asyncio.IncompleteReadError, ValueError) as e:
        print(f"[worker] dropped connection: {e}")
        writer.close()
        return
    try:
        message = data.decode()
        try:
            event_type, session_id, payload = message.split("|", 2)
            session_id = int(session_id)
        except ValueError:
            writer.write(pack_message(b"Error: Malformed event"))
            await writer.drain()
            return

        print(f"[worker:{MODE}] {event_type} session={session_id} :: {payload}")
        if event_type == "SCAN_TOOLS":
            resp = handle_scan_tools(payload)
        elif event_type == "CALL_TOOL":
            resp = await tool_exec.execute_call_tool(REGISTRY, payload, session_id, TRACKER)
        else:
            resp = json.dumps(
                {"status": "error",
                 "error": f"worker received a non-tool event {event_type!r}"}
            )
        writer.write(pack_message(resp.encode()))
        await writer.drain()
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def main():
    path = worker_socket_path()
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    if os.path.exists(path):
        os.remove(path)
    server = await asyncio.start_unix_server(handle_client, path=path)
    print(f"[worker] listening on {path} (mode={MODE})")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
