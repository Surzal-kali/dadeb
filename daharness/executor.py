"""Execution API exposed by the harness package.

The ``ExecutorMixin`` carries the execution/dispatch methods that are mixed into
:class:`daharness.registry.ToolRegistry`; the module-level helpers below provide
the same capability to callers that do not want to construct a full registry
client (they build a bare instance via ``__new__``).
"""

import asyncio
import functools
import importlib
import inspect
import json
import logging
import os
import struct
import subprocess
import sys
import threading
import time
from typing import Any, Dict, Optional

from pydantic import ValidationError

from constants import TransportType, brain_socket_path
from .models import ToolManifest
from .preflight import normalize_arguments, validate_against_manifest

logger = logging.getLogger(__name__)


# Byte-identical local framing for Brain dispatch when listeners.thebrain
# cannot be imported — its module-level ctypes CDLL load of frameit.so is a
# host-compiled artifact that may not load in a container lane, and the
# socket is now legitimately reachable from inside one. 4-byte big-endian
# length prefix, same wire format as listeners.thebrain.pack_message (the
# same pattern tool_repl's _brain_pack/_brain_read_message use).
_HEADER_FORMAT = "!I"
_MAX_MESSAGE_SIZE = 10 * 1024 * 1024


def _brain_pack_message(payload: bytes) -> bytes:
    return struct.pack(_HEADER_FORMAT, len(payload)) + payload


async def _brain_read_message(reader) -> bytes:
    header = await reader.readexactly(struct.calcsize(_HEADER_FORMAT))
    (length,) = struct.unpack(_HEADER_FORMAT, header)
    if length > _MAX_MESSAGE_SIZE:
        raise ValueError(
            f"declared message length {length} exceeds max {_MAX_MESSAGE_SIZE}"
        )
    return await reader.readexactly(length)


class ExecutorMixin:
    """Execution and dispatch behaviour for :class:`ToolRegistry`.

    Kept as a mixin so the registry class in :mod:`daharness.registry` stays
    focused on discovery/embedding while all the "run a tool" paths live here.
    """

    async def execute_tool(self, manifest: ToolManifest, arguments: dict, *, session_id: str = "0"):
        manifest = self._ensure_valid_manifest(manifest)

        # --- Pre-flight (deterministic, <1ms): validate BEFORE anything that
        # can block. Fuzz 2026-09-20: malformed calls (JSON-string arguments,
        # bogus keys, scalar args) flowed past every entry gate and hung inside
        # tool bodies until BRAIN_DISPATCH_TIMEOUT. A rejected call must cost
        # milliseconds, never the dispatch budget. See daharness/preflight.py.
        _args, _rej = normalize_arguments(arguments)
        if _rej is not None:
            logger.warning(f"[PREFLIGHT_REJECT] {manifest.module_id}: {_rej.get('error')}")
            self._journal_reject(manifest.module_id, _rej, session_id)
            return _rej
        _rej = validate_against_manifest(_args, manifest)
        if _rej is not None:
            logger.info(f"[PREFLIGHT_REJECT] {manifest.module_id}: {_rej.get('error')}")
            self._journal_reject(manifest.module_id, _rej, session_id)
            return _rej
        arguments = _args

        # LOGGING: Record actual execution start
        logger.info(
            f"[TOOL_EXECUTE] Executing Tool ID: {manifest.module_id} | Path: {manifest.implementation_path} | Args: {arguments} | Session: {session_id}"
        )

        started = time.time()
        try:
            result = await self._dispatch_by_transport(manifest, arguments, session_id)
            status = "error" if (not isinstance(result, dict) or result.get("status") not in ("Success", "unknown_delivery")) else "ok"
        except Exception as exc:
            logger.error(f"[TOOL_EXECUTE] {manifest.module_id} raised: {exc}", exc_info=True)
            result = {"error": f"dispatch failed: {exc}", "status": "Failed"}
            status = "error"
        duration_s = time.time() - started

        self._journal_dispatch(manifest, arguments, result, status, duration_s, session_id)
        return result

    async def _dispatch_by_transport(self, manifest: ToolManifest, arguments: dict, session_id: str):
        """Transport dispatch — behavior identical to the original inline
        branches (kept async; execute_tool awaits it so the journal can time
        the whole path uniformly)."""
        if manifest.transport == TransportType.LOCAL_FILE:
            # Static-scan manifests (argparse modules) run as subprocesses of
            # the script itself; _execute_local_script also enforces the
            # ALLOWED_TOOL_ROOTS path check.  Local scripts have no Brain
            # session concept, so session_id is ignored here.
            return self._stamp_provenance(
                manifest,
                await self._execute_local_script(manifest.implementation_path, arguments),
            )

        if manifest.transport in (TransportType.BRAIN_DISPATCH, TransportType.MCP_RPC):
            # MCP_RPC tools (e.g. MetasploitClient.dispatch_metasploit) are async
            # methods on the same in-process class instances as the
            # BRAIN_DISPATCH tools — route them through the identical
            # Brain-first / in-process fallback path.
            return self._stamp_provenance(
                manifest,
                await self._execute_brain_tool(manifest.module_id, arguments, session_id=session_id),
            )

        raise ValueError(f"Unsupported transport type: {manifest.transport}")

    def _journal_dispatch(self, manifest, arguments, result, status, duration_s, session_id):
        """Append one row to the engagement journal (best-effort, never
        raises — the journal is additive and must not affect dispatch)."""
        try:
            from utils.journal import write_dispatch
            from utils.engagement import lane_name
            write_dispatch(
                tool_id=manifest.module_id,
                status=status,
                lane=lane_name(),
                args=arguments,
                session_id=str(session_id),
                duration_s=duration_s,
                result=result,
                approval_path=os.getenv("HARNESS_APPROVAL_PATH", "gateway"),
                envelope_meta={
                    "transport": manifest.transport.value,
                    "untrusted_target": bool(getattr(manifest, "untrusted_target", False)),
                },
            )
        except Exception:
            logger.debug("[JOURNAL] dispatch row skipped (non-fatal)", exc_info=True)

    def _journal_reject(self, tool_id: str, rejection: dict, session_id: str):
        """Journal a preflight reject — a refused call is an auditable event
        too (the 'we never ran that' side of the compliance query)."""
        try:
            from utils.journal import write_dispatch
            from utils.engagement import lane_name
            write_dispatch(
                tool_id=tool_id,
                status="error",
                lane=lane_name(),
                args=rejection.get("arguments") or {},
                session_id=str(session_id),
                approval_path=os.getenv("HARNESS_APPROVAL_PATH", "gateway"),
                envelope_meta={"preflight_reject": True},
            )
        except Exception:
            logger.debug("[JOURNAL] reject row skipped (non-fatal)", exc_info=True)

    @staticmethod
    def _stamp_provenance(manifest: ToolManifest, result: Any) -> Any:
        """Stamp result envelopes from untrusted-target tools with provenance.

        Tools decorated ``@framework_tool(..., untrusted_target=True)`` produce
        results that embed ANALYSIS-TARGET content: page HTML and headers,
        shell output, service banners, binary strings, scanner log lines. A
        target can write that text to look like instructions to the agent.
        Every envelope from such tools carries::

            {"_provenance": {"untrusted_target": true, "source": "analysis_target"}}

        The stamp is applied to BOTH the transport envelope and the tool's own
        result dict (when it's a dict) — the projection layer unwraps the
        envelope before digesting/paging, so the inner copy is the one that
        survives into the model context and the scratch store.  ``setdefault``
        keeps the operation idempotent for nested re-dispatches.

        Mirrors REA's ``returnsTargetContent`` contract
        (morluto/rea docs/mcp-contracts.md).
        """
        if not getattr(manifest, "untrusted_target", False):
            return result
        if not isinstance(result, dict):
            return result
        stamp = {"untrusted_target": True, "source": "analysis_target"}
        result.setdefault("_provenance", stamp)
        inner = result.get("result")
        if isinstance(inner, dict):
            inner.setdefault("_provenance", stamp)
        return result

    def _resolve_brain_session(self, session_id: str) -> int:
        """Map a caller session/agent id to the integer the Brain wire protocol
        requires (``FrameworkEvent.session_id`` is a C ``int``).

        ``"0"`` / empty -> ``0`` (the default *shared* session, backward
        compatible with the old hardcoded ``CALL_TOOL|0|...``). Any other id —
        numeric or not (e.g. an agent_id) — is mapped to a stable, unique int
        slot so the same caller always lands on the same Brain session and a
        concurrent agent gets its own. This is what lets multiple agents run
        concurrently without sharing one stateful tool instance (e.g. one
        msfconsole handle) on the Brain side.
        """
        sid = str(session_id if session_id is not None else "0").strip() or "0"
        if sid == "0":
            return 0
        with self._brain_session_lock:
            if sid not in self._brain_session_map:
                self._next_brain_session += 1
                self._brain_session_map[sid] = self._next_brain_session
            return self._brain_session_map[sid]

    async def _execute_brain_tool(self, tool_id: str, arguments: dict, *, session_id: str = "0"):
        """Dispatch a tool call, launching the decorated function directly.

        Order of preference:
        1. Brain UDS socket (the checkout's ``run/brain.sock``, resolved via
           ``brain_socket_path()`` — shared into container lanes by the tree's
           bind mount) when it is up and knows the tool.
        2. In-process launch of the pythonic function — this is the fallback that
           keeps tools runnable when the Brain sidecar is down (its startup code
           unlinks the socket, and if the sidecar dies the socket goes with it,
           surfacing as FileNotFoundError: [Errno 2] No such file or directory).

        When the fallback is triggered because the Brain **socket is down**
        (not merely because the Brain doesn't know the tool), the result is
        tagged ``degraded=True`` so callers know the data came from a
        fallback path, not the sidecar.  Negative-existence conclusions
        ("no modules found", "zero results") from a degraded session are
        void until re-verified on a healthy Brain (standing rule T-01).
        """
        brain_result, socket_down = await self._dispatch_via_brain(
            tool_id, arguments, session_id=session_id
        )
        if brain_result is not None:
            return brain_result

        logger.info(
            f"[BRAIN_DISPATCH] Socket unavailable or tool unknown; launching {tool_id} in-process"
        )
        result = await self._launch_in_process(tool_id, arguments)
        # Only tag as degraded when the Brain socket was actually down — a
        # tool-not-in-registry fallback is normal (the Brain didn't scan
        # that module) and doesn't indicate a degraded session.
        if socket_down and isinstance(result, dict):
            result["degraded"] = True
            result["degraded_reason"] = (
                "Brain socket unavailable; executed via in-process fallback. "
                "Negative-existence conclusions from this result are void until "
                "re-verified on a healthy Brain."
            )
        return result

    async def _dispatch_via_brain(
        self, tool_id: str, arguments: dict, *, session_id: str = "0"
    ) -> tuple:
        """Try the Brain socket. Returns ``(result, socket_down)``.

        - ``(dict, False)`` — the Brain ran (or genuinely failed) the tool.
          The result is NOT retried in-process to avoid double side effects.
        - ``(None, False)`` — the Brain is up but doesn't know the tool;
          caller falls back in-process (normal, not degraded).
        - ``(None, True)`` — the Brain socket is down (FileNotFoundError,
          ConnectionError, OSError); caller falls back in-process and
          should tag the result ``degraded``.
        """
        socket_path = str(brain_socket_path())
        # A tool that never returns (a listener, a wedged subprocess, a slow
        # nmap -p- -sV, a sqlmap crawl) used to hang this read forever and freeze
        # the whole conversation. Bound it. 600s matches the tool budget the
        # e2e doc assumes (e.g. sqlmap's documented "600s tool timeout"); env
        # overridable for faster lab targets.
        dispatch_timeout = float(os.getenv("BRAIN_DISPATCH_TIMEOUT", "600"))
        # The Brain wire protocol carries session_id as a C int, so map the
        # caller's (possibly non-numeric) session/agent id to a stable int.
        # Distinct agents -> distinct Brain sessions -> isolated stateful tool
        # instances on the sidecar (no more shared session 0 for everyone).
        brain_session = self._resolve_brain_session(session_id)
        try:
            # Prepare the payload: "CALL_TOOL|session_id|tool_id|args"
            # session_id is now the caller's resolved Brain session, not a
            # hardcoded 0 — so concurrent agents don't interleave on one
            # shared Brain session/state.
            args_json = json.dumps(arguments)
            message = f"CALL_TOOL|{brain_session}|{tool_id}|{args_json}"

            # Use asyncio for non-blocking socket I/O
            # Connect and read are different failure modes (fuzz 2026-09-20):
            # a dead/wedged socket should fail in seconds, not burn the whole
            # tool budget. BRAIN_CONNECT_TIMEOUT (default 10s) bounds the
            # connect; the read below keeps BRAIN_DISPATCH_TIMEOUT so
            # long-running legit tools keep their full budget.
            connect_timeout = float(os.getenv("BRAIN_CONNECT_TIMEOUT", "10"))
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_unix_connection(socket_path), connect_timeout
                )
            except asyncio.TimeoutError:
                logger.error(
                    f"[BRAIN_DISPATCH] {tool_id}: Brain socket connect did not complete "
                    f"within {connect_timeout:.0f}s (BRAIN_CONNECT_TIMEOUT); sidecar wedged "
                    "or overloaded. Tool was NOT started."
                )
                return {
                    "error": (
                        f"Brain socket connect timed out after {connect_timeout:.0f}s "
                        f"(BRAIN_CONNECT_TIMEOUT); tool '{tool_id}' was not started. "
                        "Check the sidecar before retrying."
                    ),
                    "status": "Failed",
                }, False

            # Use the framing logic to send/receive (consistent with the Brain).
            # Importing listeners.thebrain loads its ctypes frameit.so, which
            # may not load in a container lane — and the shared socket makes
            # dispatch from inside a container legitimate — so fall back to
            # the local byte-identical framing above on any import failure.
            try:
                from listeners.thebrain import pack_message, read_message
            except Exception:
                pack_message = _brain_pack_message
                read_message = _brain_read_message
            writer.write(pack_message(message.encode()))
            await writer.drain()

            data = await asyncio.wait_for(read_message(reader), dispatch_timeout)
            writer.close()
            await writer.wait_closed()

            text = data.decode(errors="replace")

            # Parse the JSON status envelope from the Brain. Older sidecars
            # that still return raw text ("SUCCESS: ...", "ERROR: ...") are
            # handled by the legacy fallback so a rolling upgrade doesn't break.
            try:
                envelope = json.loads(text)
            except (json.JSONDecodeError, TypeError):
                # Legacy raw-text Brain: fall back to string matching.
                if "not found in registry" in text:
                    logger.info(f"[BRAIN_DISPATCH] Brain does not know '{tool_id}'; falling back in-process")
                    return None, False
                return {
                    "stdout": text,
                    "status": "Success" if "ERROR" not in text else "Failed",
                }, False

            status = str(envelope.get("status", "")).lower()
            error_msg = envelope.get("error")

            # "not found in registry" means the Brain never scanned this tool;
            # fall back in-process instead of failing.
            if status == "error" and error_msg and "not found in registry" in error_msg:
                logger.info(f"[BRAIN_DISPATCH] Brain does not know '{tool_id}'; falling back in-process")
                return None, False

            result_value = envelope.get("result")

            shaped: Dict[str, Any] = {
                "status": "Success" if status == "success" else "Failed",
            }
            # Pass through structured result data for typed callers.
            # stdout is NOT a stringified copy of result — that doubled
            # context on every tool call.  stdout is included only when the
            # Brain returned a bare string (no structured result) or an error
            # message (so the model sees the text).
            if result_value is not None and not isinstance(result_value, str):
                shaped["result"] = result_value
            elif result_value is not None and isinstance(result_value, str):
                shaped["stdout"] = result_value
            elif error_msg:
                shaped["stdout"] = error_msg
            if status != "success" and error_msg:
                shaped["error"] = error_msg
            return shaped, False
        except FileNotFoundError:
            logger.info(f"[BRAIN_DISPATCH] {socket_path} does not exist; Brain sidecar is down")
            return None, True
        except asyncio.TimeoutError:
            # Abandon the connection cleanly: an unclosed writer leaks the fd
            # (and the socket pair) for as long as the tool keeps running.
            try:
                writer.close()
            except (NameError, UnboundLocalError):
                pass  # never connected
            # The Brain accepted the call and is still executing it. Report a
            # failure but do NOT fall back in-process: that would run the tool
            # a second time with real side effects (scans, listeners, payloads).
            logger.error(
                f"[BRAIN_DISPATCH] {tool_id}: no reply within {dispatch_timeout}s; "
                "the tool may still be running on the Brain"
            )
            return {
                "error": (
                    f"Tool '{tool_id}' did not return a result within {dispatch_timeout:.0f}s. "
                    "It may still be running on the Brain; see list_tool_executions / kill_tool_execution (and BRAIN_EXEC_CEILING) to stop it."
                ),
                "status": "Failed",
            }, False
        except (ConnectionError, OSError) as e:
            logger.info(f"[BRAIN_DISPATCH] Socket connect failed ({e}); falling back in-process")
            return None, True
        except Exception as e:
            logger.error(f"[BRAIN_ERROR] Failed to dispatch tool {tool_id}: {e}")
            return {"error": f"Brain dispatch failed: {str(e)}", "status": "Failed"}, False

    def _resolve_callable(self, tool_id: str) -> tuple:
        """Resolve a tool_id like 'pkg.mod.func' or 'pkg.mod.Class.func' to a
        runnable callable, instantiating the owning class if needed.

        Returns (callable, error_message); exactly one of the two is populated.
        """
        parts = tool_id.split(".")
        if len(parts) < 2:
            return None, f"Tool id '{tool_id}' is not a dotted module path"

        # Longest importable module prefix wins, so 'pkg.mod.Class.func'
        # resolves the module 'pkg.mod' and walks the remaining attrs.
        mod = None
        mod_len = 0
        for i in range(len(parts) - 1, 0, -1):
            try:
                mod = importlib.import_module(".".join(parts[:i]))
                mod_len = i
                break
            except ImportError:
                continue
        if mod is None:
            return None, f"No importable module found for '{tool_id}'"

        obj: Any = mod
        cls: Any = None
        cls_key = ""
        walked = []
        for attr in parts[mod_len:]:
            walked.append(attr)
            nxt = getattr(obj, attr, None)
            if nxt is None:
                return None, f"Attribute '{'.'.join(walked)}' not found in '{tool_id}'"
            if inspect.isclass(nxt):
                cls = nxt
                cls_key = f"{mod.__name__}.{'.'.join(walked)}"
            obj = nxt

        if cls is not None and inspect.isfunction(obj):
            # Unbound method: bind it to a cached class instance so stateful
            # clients (MetasploitClient, SMBScanner, ...) keep their handles.
            if cls_key not in self._tool_instances:
                try:
                    # Prefer an explicit shared-instance classmethod so stateful
                    # clients (MetasploitClient, SMBScanner, ...) reuse the same
                    # live handles bootstrap created instead of a dead twin.
                    factory = getattr(cls, "get_instance", None)
                    if callable(factory):
                        self._tool_instances[cls_key] = factory()
                    else:
                        self._tool_instances[cls_key] = cls()
                except TypeError as e:
                    return None, (
                        f"Class {cls.__name__} requires constructor arguments "
                        f"and cannot be auto-instantiated: {e}"
                    )
            obj = getattr(self._tool_instances[cls_key], parts[-1])

        if not callable(obj):
            return None, f"'{tool_id}' resolved to non-callable {type(obj).__name__}"
        return obj, ""

    async def _launch_in_process(self, tool_id: str, arguments: dict):
        """Launch the decorated pythonic function directly in this process.

        Async tools are awaited on the running loop; sync tools run in a worker
        thread so blocking calls (impacket, nmap) don't freeze the loop.
        """
        try:
            func, error = self._resolve_callable(tool_id)
            if func is None:
                logger.error(f"[INPROC_LAUNCH] {tool_id}: {error}")
                return {"error": error, "status": "Failed"}

            args = dict(arguments or {})
            # The secretary wraps unparseable argument payloads as {"_raw": ...}
            # and passes them through; leaving it in place makes every tool die
            # with "unexpected keyword argument '_raw'" instead of a clear
            # missing-argument error.
            args.pop("_raw", None)
            # Cap in-process tools with the same BRAIN_DISPATCH_TIMEOUT the
            # out-of-process Brain path already enforces. Without this a
            # blocking in-process tool (e.g. the amass alive-check sweep) can
            # hang the worker thread indefinitely while the MCP caller's
            # socket dies opaquely. Mirroring the Brain path turns a silent
            # socket-timeout into an honest "did not return within Ns".
            dispatch_timeout = float(os.getenv("BRAIN_DISPATCH_TIMEOUT", "600"))
            if inspect.iscoroutinefunction(func):
                coro = func(**args)
            else:
                coro = asyncio.to_thread(functools.partial(func, **args))
            try:
                result = await asyncio.wait_for(coro, timeout=dispatch_timeout)
            except asyncio.TimeoutError:
                logger.error(
                    "[INPROC_LAUNCH] %s did not return within %.0fs (BRAIN_DISPATCH_TIMEOUT)",
                    tool_id, dispatch_timeout,
                )
                return {
                    "error": (
                        f"In-process tool '{tool_id}' did not return a result "
                        f"within {dispatch_timeout:.0f}s (BRAIN_DISPATCH_TIMEOUT). "
                        "If this is expected for a long-running tool, raise "
                        "BRAIN_DISPATCH_TIMEOUT or split into a launch+poll job."
                    ),
                    "status": "Failed",
                }

            return self._wrap_launch_result(result)
        except TypeError as e:
            return {"error": f"Bad arguments for {tool_id}: {e}", "status": "Failed"}
        except Exception as e:
            logger.error(f"[INPROC_LAUNCH] {tool_id} failed: {e}", exc_info=True)
            return {"error": f"In-process launch failed: {e}", "status": "Failed"}

    @staticmethod
    def _wrap_launch_result(result: Any) -> Dict[str, Any]:
        """Shape an in-process result into the executor transport envelope.

        The envelope carries the *structured* result under ``result`` and the
        transport status under ``status``.  ``stdout`` is included ONLY when
        the tool returned a bare string (no structured data to duplicate) or
        when the tool's own dict already has a ``stdout`` key (e.g. ssh_exec,
        fastcgi — real subprocess output, not a stringified copy).  When
        ``result`` is present, ``stdout`` is never a second serialization of
        the same data — that doubled context on every tool call for no reason.
        """
        if result is None:
            return {
                "result": None,
                "status": "Failed",
                "error": "Tool returned no result (precondition likely not met)",
            }
        if isinstance(result, str):
            return {"stdout": result, "status": "Success"}
        if isinstance(result, dict):
            # If the wrapper already produced a status dict, respect it.
            # Pre-approval wrappers (dispatch_metasploit's category checks,
            # for example) return {status: "Failed", error: "..."} to
            # signal failure to the secretary, and we should not relabel
            # it as Success just because it's a dict.
            existing_status = result.get("status")
            if existing_status in ("Success", "Failed", "unknown_delivery"):
                # "unknown_delivery" (send_to_listener) is a third, honest
                # status: the write was interrupted and we don't know if bytes
                # went out — it must NOT be relabeled Success or the secretary
                # will narrate a maybe-failure as a success and skip the
                # read_listener check.
                wrapped: Dict[str, Any] = {
                    "status": existing_status,
                    "result": result,
                }
                # Preserve a real stdout from the tool's own output (ssh_exec,
                # fastcgi, etc. carry genuine subprocess stdout — not a
                # stringified copy of the result dict).
                tool_stdout = result.get("stdout")
                if isinstance(tool_stdout, str) and tool_stdout:
                    wrapped["stdout"] = tool_stdout
                if "error" in result:
                    wrapped["error"] = result["error"]
                return wrapped
            return {
                "result": result,
                "status": "Success",
            }
        if isinstance(result, (list, int, float, bool)):
            return {
                "result": result,
                "status": "Success",
            }
        return {"stdout": str(result), "status": "Success"}

    async def _execute_local_script(self, script_path: str, arguments: dict):
        """
        Execute a local Python script or module.
        """
        try:
            resolved_path = self._resolve_script_path(script_path)
            arg_list = []
            for key, value in (arguments or {}).items():
                if isinstance(value, (dict, list, tuple, bool)):
                    arg_list.extend([f"--{key}", json.dumps(value)])
                else:
                    arg_list.extend([f"--{key}", str(value)])

            result = await asyncio.to_thread(
                subprocess.run,
                [sys.executable, str(resolved_path), *arg_list],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode,
                "status": "Success" if result.returncode == 0 else "Failed",
            }
        except subprocess.TimeoutExpired:
            return {"error": "Script execution timed out", "return_code": -1}
        except Exception as e:
            return {"error": str(e), "return_code": -1}


# ---------------------------------------------------------------------------
# Standalone helpers for callers that do not want a full registry client.
# Registry-owned execution is preferred because it preserves cached class
# instances across calls; these exist for one-off jobs.
# ---------------------------------------------------------------------------


def _new_registry():
    # Lazy import avoids a circular import with daharness.registry, which mixes
    # ExecutorMixin into ToolRegistry at class-definition time.
    from .registry import ToolRegistry

    registry = ToolRegistry.__new__(ToolRegistry)
    registry._tool_instances = {}
    return registry


async def execute_tool(manifest: ToolManifest, arguments: dict, *, session_id: str = "0"):
    """Execute a manifest without creating a ChromaDB client."""
    return await _new_registry().execute_tool(manifest, arguments, session_id=session_id)


async def execute_local_script(script_path: str, arguments: dict):
    """Run a local manifest script using the shared execution rules."""
    return await _new_registry()._execute_local_script(script_path, arguments)


async def dispatch_via_brain(tool_id: str, arguments: dict):
    """Attempt Brain dispatch without constructing a registry client."""
    result, _socket_down = await _new_registry()._dispatch_via_brain(tool_id, arguments)
    return result


async def launch_in_process(tool_id: str, arguments: dict):
    """Launch a decorated Python tool without constructing a registry client."""
    return await _new_registry()._launch_in_process(tool_id, arguments)


__all__ = [
    "ExecutorMixin",
    "dispatch_via_brain",
    "execute_local_script",
    "execute_tool",
    "launch_in_process",
    "ToolManifest",
]
