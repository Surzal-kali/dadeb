"""Brain-socket helpers: SHARED-session dispatch, no in-process fallback.

utils/session_manager.SessionManager is a PROCESS-LOCAL singleton: whichever
process actually executes ssh_connect / open_listener holds the live object.
The Brain sidecar (run/brain.sock — shared into container lanes by the
tree's bind mount) is the shared owner — the agent's Bridge dispatches
through that same socket — so a session opened ON the Brain is usable by
BOTH lanes. msf: handles are daemon-backed (msfrpcd) and were always
cross-process visible. The ``sessions`` command shows both worlds side by
side so you always know which process holds what.
"""

import asyncio
import json
import struct
import time
from typing import Any, Dict

from constants import brain_socket_path

BRAIN_SOCKET = str(brain_socket_path())
_BRAIN_TIMEOUT = 60.0


def _brain_pack(payload: bytes) -> bytes:
    """4-byte big-endian length framing, byte-identical to
    listeners.thebrain.pack_message — reimplemented locally so the REPL never
    imports the Brain module (its module-level ctypes CDLL load of frameit.so
    is a side effect a diagnostic tool must not carry)."""
    return struct.pack("!I", len(payload)) + payload


async def _brain_read_message(reader) -> bytes:
    """Read one length-prefixed reply (same framing as the Brain side)."""
    header = await reader.readexactly(4)
    (length,) = struct.unpack("!I", header)
    if length > 10 * 1024 * 1024:
        raise ValueError(f"declared message length {length} exceeds max {10 * 1024 * 1024}")
    return await reader.readexactly(length)


async def _brain_call(tool_id: str, arguments: Dict[str, Any], brain_session: int = 0) -> Dict[str, Any]:
    """Route one tool call to the Brain sidecar (CALL_TOOL wire format), with
    NO in-process fallback: a fallback would strand session state in this REPL
    process, invisible to the agent — the split-brain this helper exists to
    prevent."""
    message = f"CALL_TOOL|{brain_session}|{tool_id}|{json.dumps(arguments)}"
    start = time.monotonic()

    try:
        reader, writer = await asyncio.open_unix_connection(BRAIN_SOCKET)
    except (FileNotFoundError, ConnectionError, OSError) as e:
        return {
            "stdout": "",
            "status": "Failed",
            "error": (
                f"Brain sidecar is down ({BRAIN_SOCKET}: {e}). Refusing to run "
                f"{tool_id} in-process — the session would be REPL-local and "
                "invisible to the agent. Start the Brain, or use `run` for an "
                "explicitly REPL-local (unshared) session."
            ),
            "_elapsed_s": round(time.monotonic() - start, 2),
        }

    try:
        writer.write(_brain_pack(message.encode()))
        await writer.drain()
        data = await asyncio.wait_for(_brain_read_message(reader), timeout=_BRAIN_TIMEOUT)
        writer.close()
        await writer.wait_closed()
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, ValueError) as e:
        try:
            writer.close()
        except Exception:
            pass
        return {
            "stdout": "",
            "status": "Failed",
            "error": (
                f"Brain call {tool_id} did not complete within {_BRAIN_TIMEOUT:.0f}s "
                f"({type(e).__name__}); it may still be running on the Brain."
            ),
            "_elapsed_s": round(time.monotonic() - start, 2),
        }

    text = data.decode(errors="replace")
    try:
        envelope = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        # Legacy raw-text Brain — surface the raw text honestly.
        return {
            "stdout": text,
            "status": "Success",
            "_elapsed_s": round(time.monotonic() - start, 2),
        }

    status = str(envelope.get("status", "")).lower()
    error_msg = envelope.get("error")
    result_value = envelope.get("result")
    shaped: Dict[str, Any] = {
        "status": "Success" if status == "success" else "Failed",
        "_elapsed_s": round(time.monotonic() - start, 2),
    }
    # stdout is NOT a stringified copy of result — that doubled context.
    # Include stdout only when the Brain returned a bare string (no
    # structured result) or an error message.
    if result_value is not None and not isinstance(result_value, str):
        shaped["result"] = result_value
    elif result_value is not None and isinstance(result_value, str):
        shaped["stdout"] = result_value
    elif error_msg:
        shaped["stdout"] = error_msg
    if status != "success" and error_msg:
        shaped["error"] = error_msg
    return shaped


async def _sessions_command() -> None:
    """List sessions from BOTH lanes so the operator always knows what is shared."""
    from replkit.core import _make_executor, print_result

    print("  ── Brain-held sessions (SHARED with agent — these handles work on both sides) ──")
    result = await _brain_call("utils.paramiko_client.list_sessions", {})
    print_result(result)

    print("  ── REPL-local sessions (THIS process only — agent cannot see these) ──")
    executor = _make_executor()
    func, err = executor._resolve_callable("utils.paramiko_client.list_sessions")
    if func is None:
        print(f"  ✗ Resolve failed: {err}")
        return
    try:
        output = await asyncio.to_thread(func)
        print(output)
    except Exception as exc:
        print(f"  ✗ Local list failed: {exc}")

    print("  [i] msf: handles are backed by the shared msfrpcd daemon and are")
    print("      visible from both lanes regardless of which side opened them.")