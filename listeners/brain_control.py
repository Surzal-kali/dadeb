"""Control-plane tools for the Brain's execution tracker (models + operator).

Fuzz 2026-09-20 residual fix: zombie executions — tools that kept running on
the Brain after their caller timed out — had no visibility and no kill
switch. These two tools are that switch, for BOTH lanes:

- models: framework_run_tool(listeners.brain_control.list_tool_executions)
  then kill_tool_execution(exec_id=...) via the Bridge;
- operator: same tools from tool_repl (`run listeners.brain_control...`),
  plus plain process tools as always.

Never scope-gated by design: this is target-independent control-plane state
(like read_logs). Killing IS a judgment call — you can terminate a legit
long-running job — so kill requires an explicit exec_id taken from a fresh
list_tool_executions (auditable two-step) and is same-session-only unless
force=True. Every kill is logged with session attribution.
"""

from constants import TransportType, framework_tool


@framework_tool(
    doc=(
        "List the Brain's RUNNING tool executions: exec_id, tool_id, session, "
        "kind (async/thread), age_s. Read-only control-plane view for spotting "
        "zombie executions (calls that outlived their caller or are wedged). "
        "Pair with kill_tool_execution."
    ),
    transport=TransportType.BRAIN_DISPATCH,
)
async def list_tool_executions() -> dict:
    from listeners.execution_tracker import EXECUTION_TRACKER

    return EXECUTION_TRACKER.list_executions()


@framework_tool(
    doc=(
        "Kill a RUNNING tool execution on the Brain by exec_id (from "
        "list_tool_executions). Cancels async tasks; kills the execution's "
        "spawned child processes (SIGTERM, 3s grace, then SIGKILL) and "
        "abandons the executor thread for thread-kind executions (Python "
        "cannot force-kill threads). Same-session-only unless force=True "
        "(operator-level). Every kill is logged with attribution."
    ),
    transport=TransportType.BRAIN_DISPATCH,
)
async def kill_tool_execution(exec_id: str, force: bool = False, reason: str = "") -> dict:
    from listeners.execution_tracker import EXECUTION_TRACKER

    return await EXECUTION_TRACKER.kill(
        str(exec_id), force=bool(force), reason=str(reason or "manual kill")
    )