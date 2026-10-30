#!/usr/bin/env python3
"""dadeb Brain tool-worker (milestone 2).

The Rust brain owns the client-facing socket, framing, and dispatch ROUTING.
Tool EXECUTION stays here, in Python — this is the long-lived worker the brain
forwards CALL_TOOL / SCAN_TOOLS to. It speaks the SAME length-prefixed framing
as listeners/thebrain.py (4-byte big-endian length + payload), so the
brain<->worker hop and the client<->brain hop share one wire format.

Scope: a minimal, stdlib-only demo registry (demo.echo, demo.add, demo.sysinfo)
so the IPC seam runs end-to-end TODAY without dragging in the full 218-tool
import chain (scapy et al.). The real registry wires in where marked below.

Run:
    BRAIN_WORKER_SOCKET=/run/daharness/brain-worker.sock python3 worker.py
"""
import asyncio
import json
import os
import struct
import sys

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


# --- demo registry ----------------------------------------------------------
# MILESTONE-2 PLACEHOLDER. To run the real tools, import the existing registry
# instead of this dict, e.g.:
#     from listeners.thebrain import registry, scan_tools
# and route CALL_TOOL/SCAN_TOOLS through registry.get_tool(...) / scan_tools(...).
# Kept minimal + stdlib-only here so the seam runs without the heavy tool-module
# import chain while we validate the transport.
def _echo(*args, **kwargs):
    return {"args": list(args), "kwargs": kwargs}


def _add(a, b):
    return a + b


def _sysinfo():
    return {"pid": os.getpid(), "python": sys.version.split()[0]}


REGISTRY = {
    "demo.echo": _echo,
    "demo.add": _add,
    "demo.sysinfo": _sysinfo,
}


def _parse_args(args_str: str):
    """dict -> kwargs, list -> positional. Same contract as thebrain CALL_TOOL."""
    args_str = args_str.strip()
    if not args_str:
        return [], {}
    parsed = json.loads(args_str)
    if isinstance(parsed, dict):
        return [], parsed
    if isinstance(parsed, list):
        return parsed, {}
    raise ValueError(f"expected a JSON object or list, got {type(parsed).__name__}")


def handle_scan_tools(_payload: str) -> str:
    # The Python Brain returns "SCAN_COMPLETE|id:doc,id:doc,...".
    tools = ",".join(f"{name}:(demo tool)" for name in REGISTRY)
    return "SCAN_COMPLETE|" + tools


def handle_call_tool(payload: str) -> str:
    tool_id, args_str = payload.split("|", 1) if "|" in payload else (payload, "")
    tool = REGISTRY.get(tool_id)
    if tool is None:
        return json.dumps(
            {"status": "error", "tool_id": tool_id,
             "error": f"Tool {tool_id} not found in demo registry."}
        )
    try:
        args, kwargs = _parse_args(args_str)
        result = tool(*args, **kwargs)
        try:
            json.dumps(result)  # keep the envelope JSON-serializable
        except (TypeError, ValueError):
            result = str(result)
        return json.dumps({"status": "success", "tool_id": tool_id, "result": result})
    except Exception as e:  # noqa: BLE001 — envelope every failure, never crash the worker
        return json.dumps(
            {"status": "error", "tool_id": tool_id, "error": f"Execution failed: {e}"}
        )


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
            event_type, _session_id, payload = message.split("|", 2)
        except ValueError:
            writer.write(pack_message(b"Error: Malformed event"))
            await writer.drain()
            return

        print(f"[worker] {event_type} :: {payload}")
        if event_type == "SCAN_TOOLS":
            resp = handle_scan_tools(payload)
        elif event_type == "CALL_TOOL":
            resp = handle_call_tool(payload)
        else:
            # The brain only forwards tool events here; anything else is a bug
            # on the brain side, so say so rather than guessing.
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
    print(f"[worker] listening on {path}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
