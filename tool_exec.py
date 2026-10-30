"""Shared tool-execution core.

This is the CALL_TOOL execution body from listeners/thebrain.py's dispatch(),
lifted out so it lives in ONE place. The new Rust-brain's Python worker
(rust/brain/worker.py) runs tools through this; thebrain.py's own dispatch can
later delegate here too, instead of the two paths drifting apart.

Deliberately import-light: stdlib only at module scope, so it can be imported
without dragging in the heavy tool-module chain (scapy et al.) that the
`listeners` package pulls at import time. The registry and tracker are passed
IN, and scope_gate is imported lazily inside the call, so this module has no
hard dependency on the harness being fully installed.

Faithful to thebrain.py:
  * JSON arg parsing — dict -> kwargs, list -> positional, scalar rejected,
    with the legacy bare-comma fallback ONLY for payloads that never looked
    like JSON (the fuzz-2026-09-20 hang root cause: a malformed JSON object
    must not silently become garbage positional args);
  * the scope-gate brake (defense in depth), before execution;
  * per-session instance rebind so concurrent agents don't share a stateful
    client (e.g. one msfconsole handle between all agents);
  * execution tracking with a hard BRAIN_EXEC_CEILING;
  * the JSON status envelope the harness parses structurally.

The `registry` is duck-typed: anything exposing get_tool(name), a _class_tools
map, and instance_for_session(session, cls) works — the real FunctionRegistry
or a lightweight stand-in. The `tracker` likewise needs
begin/attach_task/attach_future/finish/set_caller_session/kill.
"""
import asyncio
import concurrent.futures
import functools
import inspect
import json
import os
from typing import Any

# Dedicated tool-executor pool — NOT asyncio's default executor. Mirrors the
# 2026-09-25 executor-starvation fix in thebrain.py: a wedged sync tool pins its
# own thread here, so it can never starve the event loop's default pool (DNS,
# subprocess pipes, library internals). Sized by BRAIN_TOOL_EXECUTORS.
_TOOL_EXECUTOR: "concurrent.futures.Executor | None" = None


def _tool_executor() -> "concurrent.futures.Executor":
    global _TOOL_EXECUTOR
    if _TOOL_EXECUTOR is None:
        workers = max(4, int(os.getenv("BRAIN_TOOL_EXECUTORS", "16")))
        _TOOL_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="worker-tool"
        )
    return _TOOL_EXECUTOR


def parse_call_args(args_str: str):
    """Return (args, kwargs, error). error is None on success.

    dict -> kwargs, list -> positional, scalar -> rejected. Bare comma-split is
    the legacy fallback, used ONLY when the payload never looked like JSON.
    """
    args_str = args_str.strip()
    if not args_str:
        return [], {}, None
    try:
        parsed = json.loads(args_str)
    except json.JSONDecodeError:
        # A malformed JSON object/string must NOT become garbage positional
        # args; only treat it as legacy comma-separated if it never looked JSON.
        if "{" in args_str or '"' in args_str:
            return None, None, "payload is not valid JSON; send arguments as a JSON object"
        return [a for a in args_str.split(",") if a], {}, None
    if isinstance(parsed, dict):
        return [], parsed, None
    if isinstance(parsed, list):
        return parsed, {}, None
    return None, None, (
        f"expected a JSON object (named args) or a JSON list (positional), "
        f"got {type(parsed).__name__}"
    )


async def execute_call_tool(registry, payload: str, session_id: Any, tracker, *, ceiling=None) -> str:
    """Execute one CALL_TOOL payload ("tool_id|args_json" or "tool_id") and
    return the JSON status envelope string."""
    if ceiling is None:
        ceiling = float(os.getenv("BRAIN_EXEC_CEILING", "3600"))

    tool_id, args_str = payload.split("|", 1) if "|" in payload else (payload, "")

    # Scope-gate brake (defense in depth), before anything runs. Guarded so a
    # missing/partially-installed scope_gate can never wedge the worker.
    try:
        from utils.scope_gate import is_disabled, disabled_reject_envelope
        disabled, prefix = is_disabled(tool_id)
        if disabled:
            return json.dumps(disabled_reject_envelope(tool_id, prefix))
    except Exception:
        pass

    args, kwargs, err = parse_call_args(args_str)
    if err is not None:
        return json.dumps(
            {"status": "error", "tool_id": tool_id,
             "error": f"Malformed arguments for {tool_id}: {err}."}
        )

    tool = registry.get_tool(tool_id)
    if tool is None:
        return json.dumps(
            {"status": "error", "tool_id": tool_id,
             "error": f"Tool {tool_id} not found in registry."}
        )

    # Per-session rebind: class-method tools get the instance bound to THIS
    # session so concurrent agents don't share stateful clients. Module-level
    # function tools are stateless and called as-is.
    class_tools = getattr(registry, "_class_tools", {})
    if tool_id in class_tools:
        cls, method_name = class_tools[tool_id]
        instance = registry.instance_for_session(session_id, cls)
        tool = getattr(instance, method_name)

    tracker.set_caller_session(session_id)
    kind = "async" if inspect.iscoroutinefunction(tool) else "thread"
    exec_id = tracker.begin(tool_id, session_id, kind)
    try:
        if kind == "async":
            # Coroutine tools MUST be awaited directly — run_in_executor on a
            # coroutine function silently creates a coroutine that never runs.
            task = asyncio.ensure_future(tool(**kwargs) if kwargs else tool(*args))
            tracker.attach_task(exec_id, task)
            result = await (asyncio.wait_for(task, ceiling) if ceiling > 0 else task)
        else:
            call = functools.partial(tool, **kwargs) if kwargs else functools.partial(tool, *args)
            loop = asyncio.get_event_loop()
            fut = loop.run_in_executor(_tool_executor(), call)
            tracker.attach_future(exec_id, fut)
            result = await (asyncio.wait_for(fut, ceiling) if ceiling > 0 else fut)
    except TimeoutError:
        verdict = await tracker.kill(
            exec_id, force=True, reason=f"BRAIN_EXEC_CEILING ({ceiling:.0f}s) exceeded"
        )
        return json.dumps(
            {"status": "error", "tool_id": tool_id,
             "error": (f"Execution of {tool_id} ({exec_id}) exceeded "
                       f"BRAIN_EXEC_CEILING ({ceiling:.0f}s) and was terminated: {verdict}")}
        )
    except asyncio.CancelledError:
        return json.dumps(
            {"status": "error", "tool_id": tool_id,
             "error": f"Execution of {tool_id} ({exec_id}) was cancelled."}
        )
    finally:
        tracker.finish(exec_id)

    # JSON status envelope: include the result as-is when serializable, else
    # stringify so structured callers always get valid JSON.
    try:
        json.dumps(result)
        serializable = result
    except (TypeError, ValueError):
        serializable = str(result)
    return json.dumps({"status": "success", "tool_id": tool_id, "result": serializable})
