"""Per-turn tool budget — a hard brake on runaway tool-call loops.

Enforced in the API gateway (REST ``/tools/execute`` and the MCP
``tools/call`` path) so every lane that bypasses the secretary's approval
gate by design (Open WebUI bridge, MCP clients, REST integrations) shares
one counter per ``agent_id`` + turn. The secretary lane has its own cap
(``SECRETARY_MAX_APPROVAL_ROUNDS``); this is the symmetric brake for the
other lanes.

Turn semantics:
- ``turn_key`` supplied (e.g. Open WebUI ``chat_id:message_id``): each
  distinct key starts a fresh budget.
- ``turn_key`` omitted: per-agent rolling counter that auto-resets after
  the same agent goes idle longer than ``TOOL_BUDGET_IDLE_RESET_MIN``
  (turn boundaries are then an approximation).
- ``TOOL_BUDGET_PER_TURN=0`` disables the budget entirely.

The final allowed call of a turn executes normally but its result is
wrapped with a terminal directive telling the model to report findings and
end the turn. Past-the-limit calls are refused outright with a structured
envelope (HTTP 200 / plain MCP text — an instruction to reason over, not a
transient error to retry) EXCEPT for the terminal lane: non-traffic
reporting tools (memory + findings) stay callable so the model can
actually comply instead of being trapped.

Counters live in gateway process memory and reset on gateway restart.
"""

import os
import threading
import time
from typing import Dict, Optional, Tuple

# Decision states returned by pre_dispatch.
BUDGET_OK = "ok"                      # within budget — execute normally
BUDGET_LAST = "last_call"             # final call of the turn — wrap the result
BUDGET_EXHAUSTED = "budget_exhausted" # refused — not a terminal-lane tool
BUDGET_TERMINAL_LANE = "terminal_lane"  # past limit, but allowed (report tools)

DEFAULT_LIMIT = 12
DEFAULT_IDLE_RESET_MIN = 5.0

# Non-traffic reporting families that stay callable after exhaustion, so the
# model can write itself up. Prefix match on the tool_id.
# scratch_search is NOT here — it counts against the budget like a regular
# tool call (it pulls context into the model, so it must be metered).
DEFAULT_TERMINAL_ALLOWLIST = "utils.memory_tools.,utils.findings."

_LAST_CALL_DIRECTIVE = (
    "TOOL BUDGET: this was the FINAL tool call of this turn "
    "({used}/{limit} used). Do not call any more tools this turn. "
    "Report your findings now (report_finding / summaries), then END YOUR TURN."
)

_EXHAUSTED_DIRECTIVE = (
    "TOOL BUDGET EXHAUSTED: {used}/{limit} tool calls used this turn and "
    "further executions are refused. Do NOT retry. Summarize what you have, "
    "record findings (report_finding) and memory (remember_text) if needed — "
    "only memory and findings tools remain available — then END YOUR TURN."
)


def terminal_directive(kind: str, used: int, limit: int) -> str:
    return (
        _LAST_CALL_DIRECTIVE if kind == BUDGET_LAST else _EXHAUSTED_DIRECTIVE
    ).format(used=used, limit=limit)


def wrap_result(result, directive: str, meta: dict):
    """Attach the budget directive to a result without destroying it."""
    if isinstance(result, dict):
        out = dict(result)
        out.setdefault("tool_budget", {**meta, "directive": directive})
        return out
    suffix = f"\n\n[budget:{meta['status']}] {directive}"
    if isinstance(result, str):
        return result + suffix
    return result


class ToolBudget:
    """Thread-safe per-turn tool-call budget for one gateway process."""

    def __init__(
        self,
        limit: Optional[int] = None,
        idle_reset_min: Optional[float] = None,
        allowlist: Optional[str] = None,
    ):
        env = os.environ
        if limit is None:
            try:
                limit = int(env.get("TOOL_BUDGET_PER_TURN") or DEFAULT_LIMIT)
            except ValueError:
                limit = DEFAULT_LIMIT
        if idle_reset_min is None:
            try:
                idle_reset_min = float(
                    env.get("TOOL_BUDGET_IDLE_RESET_MIN", DEFAULT_IDLE_RESET_MIN)
                )
            except ValueError:
                idle_reset_min = DEFAULT_IDLE_RESET_MIN
        if allowlist is None:
            allowlist = env.get(
                "TOOL_BUDGET_TERMINAL_ALLOWLIST", DEFAULT_TERMINAL_ALLOWLIST
            )
        self.limit = max(0, int(limit))          # 0 = disabled
        self.idle_reset_sec = max(0.0, float(idle_reset_min) * 60.0)
        self.terminal_prefixes = tuple(
            p.strip() for p in str(allowlist).split(",") if p.strip()
        )
        self._lock = threading.Lock()
        self._counts: Dict[str, int] = {}
        self._last_ts: Dict[str, float] = {}

    def _key(self, agent_id: str, turn_key: Optional[str]) -> str:
        base = agent_id or "0"
        return f"{base}|{turn_key}" if turn_key else base

    def is_terminal_lane(self, tool_id: str) -> bool:
        return bool(tool_id) and any(
            tool_id.startswith(p) for p in self.terminal_prefixes
        )

    def consumes_budget(self, tool_id: str) -> bool:
        """Whether a successful dispatch of this tool counts against the cap."""
        return not self.is_terminal_lane(tool_id)

    def pre_dispatch(
        self, agent_id: Optional[str], turn_key: Optional[str], tool_id: str
    ) -> Tuple[str, dict]:
        """Consume one call before dispatch.

        Returns ``(decision, meta)``. Decisions:
        - ``ok`` — execute normally.
        - ``last_call`` — execute, then wrap the result with the terminal
          directive (call ``terminal_directive(BUDGET_LAST, ...)``).
        - ``budget_exhausted`` — refuse; ``meta`` already carries the
          envelope (status + directive) to return instead of executing.
        - ``terminal_lane`` — past the limit but in the reporting lane;
          execute normally and do not count it.
        """
        if self.limit <= 0:
            return BUDGET_OK, {"enabled": False}

        key = self._key(agent_id or "0", turn_key)
        now = time.time()
        with self._lock:
            # Rolling-counter reset for turns without an explicit key.
            if not turn_key:
                ts = self._last_ts.get(key)
                if ts is not None and now - ts > self.idle_reset_sec:
                    self._counts.pop(key, None)

            used = self._counts.get(key, 0)

            if used >= self.limit:
                if self.is_terminal_lane(tool_id):
                    meta = {
                        "status": BUDGET_TERMINAL_LANE,
                        "used": used,
                        "limit": self.limit,
                        "remaining": 0,
                    }
                    return BUDGET_TERMINAL_LANE, meta
                meta = {
                    "status": BUDGET_EXHAUSTED,
                    "used": used,
                    "limit": self.limit,
                    "remaining": 0,
                    "directive": terminal_directive(BUDGET_EXHAUSTED, used, self.limit),
                }
                return BUDGET_EXHAUSTED, meta

            next_used = used + 1
            self._counts[key] = next_used
            if not turn_key:
                self._last_ts[key] = now
            decision = BUDGET_LAST if next_used >= self.limit else BUDGET_OK
            meta = {
                "status": decision,
                "enabled": True,
                "used": next_used,
                "limit": self.limit,
                "remaining": max(0, self.limit - next_used),
            }
            return decision, meta