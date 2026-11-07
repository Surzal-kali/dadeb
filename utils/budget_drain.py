"""The pacemaker: operator-lane drain loop + dispatch decision mapping for
the ration engine's deferral queue.

Two duties, one module:

1. ``drain_dispatcher`` — the envelope-mapping policy every operator drain
   pass uses to turn a re-admitted tool result into an engine decision
   (bind / requeued / finished / Failed / plan_minted). This used to live
   in replkit.operator_cli; it moved here 2026-11-07 so the REPL command
   and the always-running drain loop cannot drift apart.

2. ``drain_loop`` — the always-on drumbeat (debt doc §5.1): an interval
   loop that calls ``RationEngine.operator_tick`` every
   ``BUDGET_DRAIN_INTERVAL_S`` so anything the model queues (or the
   chokepoint defers) is actually paid out without a human sitting in the
   REPL issuing ``budget drain``. The loop is a pacemaker, not a supervisor:
   all pacing, jitter, per-host economics, and manual-phase HOLD respect
   live in the engine tick — the operator stops output with
   ``budget set-phase hold <node>`` exactly as if the loop did not exist.

The loop never dies: every tick is wrapped, exceptions are logged and
stamped into ``run/budget/drain_state.json`` (the doctor's lens), and a
cancelled loop re-raises cleanly. The state file is also how the doctor
distinguishes "draining" from "stalled": alive means ``now - last_tick_at``
is inside 3x the configured interval.

Identity: dispatches run under the ORIGINAL queued item's agent id (the
model lane that minted the queue row) via the ambient identity var, so
job-store rows, evidence and findings stay owned by the requesting agent
even when the drain launches from the daemon lane.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections.abc import Callable, Coroutine
from typing import Any

logger = logging.getLogger(__name__)

_DRAIN_STATE_SUBDIR = os.path.join("run", "budget")
_DRAIN_STATE_FILE = "drain_state.json"

_SESSION_ID = "ration-drain"


def _env_float(name: str, default: float, *, minimum: float = 0.0) -> float:
    try:
        v = float(os.getenv(name, "") or default)
    except (TypeError, ValueError):
        return default
    return max(minimum, v)


def drain_state_path() -> str:
    """<workspace>/run/budget/drain_state.json (multi-lane doctor lens)."""
    from constants import resolve_workspace_root
    root = resolve_workspace_root()
    return os.path.join(root, _DRAIN_STATE_SUBDIR, _DRAIN_STATE_FILE)


def write_drain_state(payload: dict[str, Any]) -> None:
    """Atomically stamp the drain state file (0600 — same hygiene as the
    budget store). Failure to write state must never break a tick."""
    try:
        path = drain_state_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
        with open(tmp, "rb") as fh:
            os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except OSError:
        logger.debug("drain state write failed", exc_info=True)


def read_drain_state() -> dict[str, Any] | None:
    try:
        with open(drain_state_path(), "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _budget_lane_enabled() -> bool:
    """Single source of truth for the kill switch (utils.ration's
    _env_bool/DEFAULT_ENABLED); fail-closed to enabled-with-None-checks is
    NOT acceptable here — an unreadable ration module reads as DISABLED so
    the loop cannot tick against a broken lane."""
    try:
        from utils.ration import DEFAULT_ENABLED, _env_bool
        return bool(_env_bool("BUDGET_ENABLED", DEFAULT_ENABLED))
    except Exception:
        logger.debug("swallowed budget-lane probe", exc_info=True)
        return False


def budget_drain_doctor() -> dict[str, Any]:
    """``framework_doctor(provider="budget_drain")`` record — alive iff the
    last tick is inside 3x the configured interval."""
    try:
        enabled = _budget_lane_enabled()
    except Exception:
        logger.debug("swallowed budget_enabled probe in doctor", exc_info=True)
        enabled = None  # unknown lane — let the state file speak
    state = read_drain_state()
    interval = _env_float("BUDGET_DRAIN_INTERVAL_S", 30.0)
    if not enabled:
        return {
            "available": True,
            "provider": "budget_drain",
            "state": "disabled",
            "reason": "budget lane disabled (BUDGET_ENABLED=0) — the loop "
                      "idles on its interval without opening the store",
            "interval_s": interval,
            "remediation": "set BUDGET_ENABLED=1 and restart the harness",
        }
    if state is None:
        return {
            "available": False,
            "provider": "budget_drain",
            "state": "never_ticked",
            "reason": "no drain state file — the drain loop has never ticked "
                      "on this lane",
            "remediation": "check BUDGET_DRAIN_AUTOSTART=1 (bootstrap "
                           "starting) and the harness logs for a loop "
                           "traceback; state lands in "
                           "run/budget/drain_state.json",
        }
    last = float(state.get("last_tick_ts") or 0.0)
    age = time.time() - last
    stale = age > (3.0 * interval)
    detail: dict[str, Any] = {
        "available": not stale,
        "provider": "budget_drain",
        "state": "stale" if stale else "running",
        "interval_s": interval,
        "last_tick_age_s": round(age, 1),
        "backlog": state.get("backlog"),
        "launched": state.get("launched"),
        "last_error": state.get("last_error"),
    }
    if stale:
        detail["remediation"] = (
            "no tick inside 3x the interval — check the harness log for a "
            "per-tick traceback, or the process was moved/frozen on this "
            "lane")
    return detail


def item_carries_chunk_keys(item: dict[str, Any]) -> bool:
    """True when the queued row's arguments are chunk-keyed (U2 vocabulary):
    their presence means the item re-decides CHUNK mode at the tool body —
    never plan mode. Used by the dispatcher (self-describing envelope) and
    re-derived by the engine branch (authoritative)."""
    raw = item.get("arguments_json")
    try:
        arguments = json.loads(raw) if isinstance(raw, str) else (raw or {})
    except ValueError:
        return False
    if not isinstance(arguments, dict):
        return False
    from utils.wordlist_chunking import CHUNK_KEYS
    return any(key in arguments for key in CHUNK_KEYS)


def drain_dispatcher(manifests: list | None):
    """Drain decision mapping: envelope carries a job_id → bind
    ({"job_id": ...}); anything else ran to completion inline — report
    {"finished": True} so operator_tick consumes the item as done (no
    double-execution). Raises propagate; a raise keeps the item queued.

    Ration-aware (§7 Phase D): a drain dispatch is re-admission-checked by
    the same chokepoint every lane uses — a ``budget_deferred`` envelope
    means still short (item stays queued, BudgetStillShort) and a
    ``budget_refused`` envelope means never-fit/fail-closed (item cancels,
    BudgetRefused). An envelope that re-deferred NEVER maps to finished.

    U2 wordlist lane: a chunk whose launch hit a fleet duplicate/transient
    refusal returns a ``requeued`` envelope — the wrapper re-enqueued the
    SAME chunk inside its plan; the tick records "requeued" (batch-pacing
    churn) and the item stays queued for its next due turn (it must NOT
    map to finished — the chunk would be silently consumed). A ``chunk_plan``
    envelope (§3.2, 2026-11-07) reports ``plan_minted`` and the ENGINE
    decides the fate: a chunk-keyed item that still minted a plan is a
    phantom mint (deterministic arg-loss — the plan's minter would
    re-decide plan mode whole-wordlist on every pass), while an un-keyed
    item minting a plan is legitimate work conversion.

    Preflight rejections (executor arg-schema rejects) map onto the same
    Failed seam: they are neither budget-deferred nor budget-refused, and
    consuming one as finished silently destroys a plan's chunk indices
    (the minter never re-mints a consumed index — 2026-11-06 ffuf drain).
    The same honesty now covers ``status: "error"`` tool envelopes (§3.2:
    e.g. a chunk plan that no longer exists) which previously fell through
    to finished.

    Strictness (§3.2): for a CHUNK-KEYED item, an envelope matching
    NOTHING (no job_id, no requeued, no Failed/Rejected/refused, no
    chunk_plan) must NEVER consume the item as finished — silent success
    of a never-launched chunk makes the plan settle while its work never
    ran. Un-keyed items keep the present catch-all (inline-dict success)
    because an honest finished that got swallowed would double-run the
    tool on the next drain.
    """
    from daharness.preflight import format_rejection as _fmt_rej
    from daharness.preflight import is_rejection as _is_rej
    from replkit.core import run_tool
    from utils.ration import BudgetRefused, BudgetStillShort

    manifests_box: dict[str, list] = {"manifests": list(manifests or [])}
    known: set[str] = set()
    for m in manifests_box["manifests"]:
        mid = getattr(m, "module_id", None) or (
            m.get("module_id") if isinstance(m, dict) else None)
        if mid:
            known.add(mid)

    def _refresh_manifests(tool_id: str) -> None:
        """In-process re-discovery on an unknown-tool miss — one retry per
        dispatch, cost paid only when manifests are actually stale."""
        try:
            from replkit.core import discover_tools
            fresh = discover_tools()
        except Exception:
            logger.debug("swallowed drain manifest refresh", exc_info=True)
            return
        manifests_box["manifests"] = fresh
        known.clear()
        for m in fresh:
            mid = getattr(m, "module_id", None)
            if mid:
                known.add(mid)
        logger.info("drain dispatcher refreshed manifests for %s", tool_id)

    async def _dispatch(item: dict[str, Any]) -> dict[str, Any]:
        from utils.agent_identity import agent_id_context
        args = item.get("arguments_json")
        arguments = json.loads(args) if isinstance(args, str) else (args or {})
        owner = item.get("agent_id") or "0"

        async def _run(manifest_list: list) -> dict[str, Any]:
            with agent_id_context(owner):
                return await run_tool(item["tool"], arguments, manifest_list,
                                      session_id=_SESSION_ID)

        res = await _run(manifests_box["manifests"])
        if isinstance(res, dict) \
                and "Unknown tool_id" in str(res.get("error") or ""):
            _refresh_manifests(item["tool"])
            res = await _run(manifests_box["manifests"])

        if isinstance(res, dict) and res.get("status") == "budget_deferred":
            raise BudgetStillShort(queue_id=res.get("queue_id"))
        if isinstance(res, dict) and res.get("status") == "budget_refused":
            raise BudgetRefused(reason=res.get("reason") or "never fit")
        inner = res.get("result") if isinstance(res, dict) else None
        if isinstance(inner, dict):
            if inner.get("status") == "budget_deferred":
                raise BudgetStillShort(queue_id=inner.get("queue_id"))
            if inner.get("status") == "budget_refused":
                raise BudgetRefused(reason=inner.get("reason") or "never fit")
            if inner.get("requeued"):
                return {"requeued": True,
                        "plan_id": inner.get("plan_id"),
                        "reason": inner.get("reason")}
            if inner.get("status") == "chunk_plan" or inner.get("plan_id"):
                # §3.2: a (re-)mint during a dispatch. The ENGINE decides
                # phantom-vs-converted by re-deriving keyed-ness from the
                # item's own args (the envelope field is observability).
                return {"plan_minted": True,
                        "plan_id": inner.get("plan_id"),
                        "phantom": item_carries_chunk_keys(item)}
            job = inner.get("job_id")
            if job:
                return {"job_id": job}
        if isinstance(res, dict) and res.get("job_id"):
            return {"job_id": res["job_id"]}
        if isinstance(res, dict) \
                and (res.get("status") == "chunk_plan" or res.get("plan_id")) \
                and not res.get("requeued"):
            return {"plan_minted": True,
                    "plan_id": res.get("plan_id"),
                    "phantom": item_carries_chunk_keys(item)}
        # Preflight-rejection seam (2026-11-06): an executor arg-schema
        # reject returns {"status": "Rejected", "phase": "preflight"} —
        # it matched NEITHER the budget checks NOR the Failed seam and fell
        # through to {"finished": True}, consuming every rejected chunk as
        # done-forever (plan indices never re-mint, the work just vanishes).
        # Map the reject onto the Failed pathway: the engine stamps the
        # attempt and the row exits visibly with the reject text past the
        # retry budget.
        for probe in (res, inner):
            if _is_rej(probe):
                return {"status": "Failed",
                        "error": ("preflight rejected the drain dispatch: "
                                  + _fmt_rej(probe))}
        # Failed-tool envelope propagates to the ENGINE (§2.6 bounded
        # failure ledger): run_tool wraps every raised tool-body error
        # (incl. ScopeGateError) as {"status": "Failed"}. Consuming it as
        # {"finished": True} here would mark the item done-forever despite
        # nothing launching — the engine stamps the attempt and exits the
        # item past BUDGET_RETRY_MAX with the error on the row. Do NOT
        # pre-map it to BudgetRefused: a Failed envelope is often a
        # transient tool-body mislaunch, and the retry budget (not the
        # never-fit verdict) is the honest fate. §3.2 adds the
        # {"status": "error"} shape (never failed-anything, never
        # requeued, previously fell through to finished — e.g. a chunk
        # plan that no longer exists).
        _status = res.get("status") if isinstance(res, dict) else None
        if _status == "Failed" \
                or (isinstance(inner, dict) and inner.get("status") == "Failed") \
                or _status == "error" \
                or (isinstance(inner, dict) and inner.get("status") == "error"):
            _ferr = (res.get("error") if isinstance(res, dict) else None) \
                or (inner.get("error") if isinstance(inner, dict) else None) \
                or f"tool returned status {_status!r}"
            return {"status": "Failed", "error": str(_ferr)}
        # §3.2 strictness: a chunk-keyed item whose envelope matched
        # NOTHING must not consume the item as done — the plan would settle
        # over work that never launched. Un-keyed rows (generic inline
        # dict) stay the historical catch-all: a deliberately-swallowed
        # finished would DOUBLE-run the tool next drain.
        if item_carries_chunk_keys(item):
            return {"status": "Failed",
                    "error": "unrecognized drain envelope for a chunk-keyed "
                             "item (§3.2 strictness — refusing to consume "
                             "as finished): " + json.dumps(res, default=str)[:500]}
        return {"finished": True}

    return _dispatch


def _summarize_tick(out: dict[str, Any]) -> dict[str, Any]:
    """Compact state-file summary of an operator_tick result."""
    results = out.get("results") or []
    counts: dict[str, int] = {}
    launched = 0
    for r in results:
        d = str(r.get("decision") or "?")
        counts[d] = counts.get(d, 0) + 1
        if r.get("job_id"):
            launched += 1
    advance = out.get("advance") if isinstance(out.get("advance"), dict) else {}
    return {
        "decisions": counts,
        "launched": launched,
        "backlog": out.get("backlog_remaining", out.get("backlog")),
        "settled": advance.get("settled") or [],
        "failed_plans": advance.get("failed_plans") or [],
    }


async def _dispatch_tick(engine: Any, manifests: list | None,
                         discover: Callable[[], list] | None = None) -> dict[str, Any]:
    """One loop heartbeat: advance plans (engine-side) + one operator tick
    through the shared drain dispatcher. Unknown-tool misses are logged and
    retried next tick after ``drain_dispatcher``'s own manifest refresh."""
    from replkit.core import run_tool  # noqa: F401  (import lints the lane)
    from utils.wordlist_chunking import advance_plans
    advance_plans()
    if manifests is None:
        try:
            from replkit.core import discover_tools
            manifests = discover_tools()
        except Exception:
            logger.debug("swallowed drain manifest discovery", exc_info=True)
            manifests = []
    return await engine.operator_tick(
        dispatch=drain_dispatcher(manifests),
        sleep_fn=asyncio.sleep)


async def drain_loop(*,
                     interval: float | None = None,
                     engine: Any | None = None,
                     _tick: Callable[[], Any] | None = None,
                     _sleep: Callable[[float], Coroutine[Any, Any, None]] | None = None,
                     ) -> None:
    """The standing drumbeat (debt §5.1). ``BUDGET_DRAIN_AUTOSTART=0`` stops
    bootstrap from STARTING the loop; inside the loop the honest switch is
    ``BUDGET_ENABLED`` (disabled → cheap env read + idle state stamp, no
    store open). All pacing/HOLD/econ decisions are the engine's.

    ``_tick`` injectable for tests: () -> outcome dict (awaitable).
    ``_sleep`` injectable so tests never wall-clock the interval.
    """
    try:
        interval = float(interval if interval is not None
                         else os.getenv("BUDGET_DRAIN_INTERVAL_S", "") or 30.0)
    except (TypeError, ValueError):
        interval = 30.0
    interval = max(1.0, interval)
    sleep = _sleep or asyncio.sleep
    while True:
        started = time.time()
        try:
            if not _budget_lane_enabled():
                write_drain_state({
                    "ts": started, "interval_s": interval,
                    "phase": "disabled",
                    "note": "BUDGET_ENABLED=0 — loop idling, no store open",
                })
            else:
                if _tick is not None:
                    out = await _tick()
                else:
                    eng = engine
                    if eng is None:
                        from utils.ration import get_engine
                        eng = get_engine()
                    out = await _dispatch_tick(eng, None)
                summary = _summarize_tick(out)
                write_drain_state({
                    "ts": started,
                    "last_tick_ts": started,
                    "interval_s": interval,
                    "next_tick_ts": started + interval,
                    "phase": "running",
                    "backlog": summary.get("backlog"),
                    "launched": summary.get("launched"),
                    "decisions": summary.get("decisions"),
                    "settled": summary.get("settled"),
                    "failed_plans": summary.get("failed_plans"),
                    "last_error": None,
                })
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("drain tick failed: %s", exc, exc_info=True)
            write_drain_state({
                "ts": started, "last_tick_ts": None,
                "interval_s": interval, "phase": "error",
                "last_error": f"{type(exc).__name__}: {exc}",
            })
        await sleep(interval)
