"""Brain-side execution tracker + zombie kill switch.

Fuzz 2026-09-20 residual: the Brain ran tools to completion even after the
caller timed out (zombie executions) and neither models nor the operator had
a way to see or stop them. This module is the shared control-plane state:

- ``thebrain.py`` CALL_TOOL registers every execution here (async task or
  executor-thread future, plus a baseline snapshot of descendant PIDs).
- ``listeners.brain_control.list_tool_executions()`` reads it (model-facing).
- ``listeners.brain_control.kill_tool_execution(exec_id, force)`` cancels
  async tasks and kills the execution's spawned child-process tree
  (SIGTERM -> 3s grace -> SIGKILL).
- ``BRAIN_EXEC_CEILING`` (default 3600s, 0 = off) hard-stops an execution
  that outlives every caller's timeout, even when nobody kills it manually.

Honest limits: a sync tool running in the executor thread pool cannot be
force-killed in Python — its child PROCESSES are killed and the thread is
marked 'abandoned' (it ends when its blocking call returns). Kill defaults
to same-session only; ``force=True`` crosses sessions (operator-level).
Target-independent control plane: never scope-gated by design (like
read_logs). Every kill is logged with session attribution.
"""

import asyncio
import contextvars
import json
import logging
import os
import signal
import threading
import time
from typing import Any, Dict, Optional

try:
    import psutil
except Exception:  # pragma: no cover - degraded install only
    psutil = None

logger = logging.getLogger(__name__)

# Seconds between SIGTERM and SIGKILL escalation when sweeping child processes.
KILL_GRACE_S = 3.0

# The caller's Brain session for the CURRENT dispatch. thebrain.py sets this
# at the top of CALL_TOOL so kill_tool_execution can enforce same-session
# semantics without threading session ids through every tool signature.
CURRENT_SESSION: contextvars.ContextVar = contextvars.ContextVar(
    "brain_caller_session", default=None
)


def _descendants(pid: int) -> set:
    """All descendant PIDs of ``pid`` (psutil preferred, /proc fallback)."""
    if psutil is not None:
        try:
            return {p.pid for p in psutil.Process(pid).children(recursive=True)}
        except Exception:
            pass
    try:
        ppid: Dict[int, int] = {}
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                with open(f"/proc/{entry}/stat", "r") as fh:
                    after = fh.read().rsplit(") ", 1)[-1].split()
                ppid[int(entry)] = int(after[1])
            except (OSError, IndexError, ValueError):
                continue
        kids: set = set()
        stack = [pid]
        while stack:
            parent = stack.pop()
            for child, parent_pid in ppid.items():
                if parent_pid == parent and child not in kids:
                    kids.add(child)
                    stack.append(child)
        return kids
    except OSError:
        return set()


class ExecutionTracker:
    """Registry of the Brain's running tool executions."""

    def __init__(self) -> None:
        self._running: Dict[str, Dict[str, Any]] = {}
        self._counter = 0
        self._lock = threading.Lock()

    # --- registration ------------------------------------------------------

    def begin(self, tool_id: str, session_id: Any, kind: str) -> str:
        """Register an execution; returns its exec_id (E-N)."""
        with self._lock:
            self._counter += 1
            exec_id = f"E-{self._counter}"
        self._running[exec_id] = {
            "tool_id": tool_id,
            "session": str(session_id),
            "kind": kind,  # "async" (cancellable Task) | "thread" (executor)
            "started": time.time(),
            # Descendant PIDs at start: at kill time, children NOT in this
            # snapshot are attributed to this execution (baseline-diff).
            "baseline_pids": _descendants(os.getpid()),
            "task": None,
            "future": None,
            "status": "running",
        }
        return exec_id

    def attach_task(self, exec_id: str, task: "asyncio.Task") -> None:
        info = self._running.get(exec_id)
        if info is not None:
            info["task"] = task

    def attach_future(self, exec_id: str, future: Any) -> None:
        info = self._running.get(exec_id)
        if info is not None:
            info["future"] = future

    def finish(self, exec_id: str) -> None:
        self._running.pop(exec_id, None)

    def set_caller_session(self, session_id: Any) -> None:
        CURRENT_SESSION.set(str(session_id))

    # --- views --------------------------------------------------------------

    def list_executions(self) -> Dict[str, Any]:
        now = time.time()
        executions = []
        for exec_id, info in sorted(self._running.items()):
            executions.append(
                {
                    "exec_id": exec_id,
                    "tool_id": info["tool_id"],
                    "session": info["session"],
                    "kind": info["kind"],
                    "age_s": round(now - info["started"], 1),
                    "status": info["status"],
                }
            )
        return {"executions": executions, "count": len(executions)}

    # --- kill ----------------------------------------------------------------

    async def kill(
        self,
        exec_id: str,
        force: bool = False,
        reason: str = "",
    ) -> Dict[str, Any]:
        """Kill one tracked execution. Returns a verdict envelope.

        - async execution: Task.cancel() (precise).
        - thread execution: child processes SIGTERM -> grace -> SIGKILL;
          the executor thread is abandoned (Python cannot force-kill threads).
        - same-session only unless force=True (operator-level).
        """
        info = self._running.get(exec_id)
        if info is None:
            return {
                "status": "Failed",
                "error": (
                    f"no running execution '{exec_id}'; call "
                    "list_tool_executions for current ids."
                ),
            }
        caller = str(CURRENT_SESSION.get() or "0")
        if not force and str(info["session"]) != caller:
            return {
                "status": "Failed",
                "error": (
                    f"execution {exec_id} belongs to session '{info['session']}' "
                    f"(you are '{caller}'). Use force=True to cross sessions — "
                    "that is an operator-level action."
                ),
            }

        verdict: Dict[str, Any] = {
            "exec_id": exec_id,
            "tool_id": info["tool_id"],
            "cancelled": False,
            "cancel_observed": None,
            "children_sigterm": [],
            "children_sigkill": [],
            "abandoned_thread": False,
        }

        task = info.get("task")
        if task is not None and not task.done():
            task.cancel()
            verdict["cancelled"] = True
            done, _pending = await asyncio.wait([task], timeout=2.0)
            verdict["cancel_observed"] = bool(done)

        # Kill child processes this execution spawned (baseline diff).
        baseline = set(info.get("baseline_pids") or ())
        new_children = sorted(_descendants(os.getpid()) - baseline)
        for pid in new_children:
            try:
                os.kill(pid, signal.SIGTERM)
                verdict["children_sigterm"].append(pid)
            except OSError:
                pass
        if new_children:
            await asyncio.sleep(KILL_GRACE_S)
            for pid in new_children:
                alive = False
                if psutil is not None:
                    try:
                        alive = psutil.Process(pid).is_running()
                    except Exception:
                        alive = False
                else:
                    alive = os.path.exists(f"/proc/{pid}")
                if alive:
                    try:
                        os.kill(pid, signal.SIGKILL)
                        verdict["children_sigkill"].append(pid)
                    except OSError:
                        pass

        fut = info.get("future")
        if fut is not None and not fut.done():
            fut.cancel()
            verdict["abandoned_thread"] = True

        self._running.pop(exec_id, None)
        verdict["status"] = "Success"
        logger.warning(
            "[EXEC_KILL] %s %s session=%s reason=%s sigterm=%s sigkill=%s abandoned_thread=%s",
            exec_id, info["tool_id"], info["session"], reason or "manual kill",
            verdict["children_sigterm"], verdict["children_sigkill"],
            verdict["abandoned_thread"],
        )
        return verdict


EXECUTION_TRACKER = ExecutionTracker()

__all__ = ["CURRENT_SESSION", "EXECUTION_TRACKER", "ExecutionTracker", "KILL_GRACE_S"]