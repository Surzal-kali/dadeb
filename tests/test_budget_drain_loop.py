"""Debt §5.1 pacemaker tests (2026-11-07): the always-on drain loop —
state-file contract, disabled-lane fast path, per-tick error survival,
cancel, manifest refresh on unknown-tool, and the doctor lens."""

import asyncio
import time
import types

import pytest

import utils.ration as rt


@pytest.fixture
def lane(tmp_path, monkeypatch):
    """Budget store + workspace rooted in tmp so the drain state file
    (run/budget/drain_state.json) lands here too."""
    (tmp_path / "budget").mkdir()
    monkeypatch.setenv("BUDGET_STORE_DIR", str(tmp_path / "budget"))
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path))
    monkeypatch.setenv("BUDGET_ENABLED", "1")
    for k in ("BUDGET_CONSTITUTION", "BUDGET_CONSTITUTION_FILE",
              "BUDGET_EPOCH_SECONDS", "BUDGET_QUEUE_TTL_HOURS",
              "BUDGET_DRAIN_BATCH", "BUDGET_DRAIN_INTERVAL_S"):
        monkeypatch.delenv(k, raising=False)
    rt.reset_engine()
    rt.reset_ration_store()
    yield tmp_path
    rt.reset_engine()
    rt.reset_ration_store()


class _FakeSleep:
    """Awaitable fake sleep that never wall-clocks: counts hops, optional
    per-hop failure to end the loop for tests. Must yield to the event
    loop, or the loop spins without a cancel point."""

    def __init__(self, fail_after=None):
        self.hops = 0
        self.fail_after = fail_after

    async def __call__(self, seconds):
        await asyncio.sleep(0)
        self.hops += 1
        if self.fail_after is not None and self.hops > self.fail_after:
            raise _LoopStop()


class _LoopStop(Exception):
    pass


async def _drive_until(task, sleep, hops):
    """Pump the event loop until `hops` sleep hops happened (deadline-
    bounded), then cancel the loop task cleanly."""
    deadline = time.time() + 5
    while sleep.hops < hops and time.time() < deadline:
        await asyncio.sleep(0.001)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


def _state_path(tmp_path):
    import utils.budget_drain as bd
    return bd.drain_state_path()


# --- loop ticks + state file -------------------------------------------------


def test_loop_ticks_and_writes_state(lane):
    import utils.budget_drain as bd
    ticks = []

    async def fake_tick():
        ticks.append(1)
        return {"decision": "drained",
                "results": [{"qid": "q1", "decision": "dispatched",
                             "job_id": "17"},
                            {"qid": "q2", "decision": "still_short"}],
                "backlog_remaining": 3,
                "advance": {"settled": [], "failed_plans": []}}

    sleep = _FakeSleep()

    async def driver():
        await _drive_until(
            asyncio.create_task(bd.drain_loop(_tick=fake_tick,
                                              _sleep=sleep)),
            sleep, hops=2)
    asyncio.run(driver())
    assert len(ticks) >= 2, f"loop ticked only {len(ticks)} times"
    st = bd.read_drain_state()
    assert st["phase"] == "running"
    assert st["interval_s"] == 30.0
    assert st["decisions"] == {"dispatched": 1, "still_short": 1}
    assert st["launched"] == 1
    assert st["backlog"] == 3
    assert st["last_error"] is None


def test_loop_disabled_lane_never_ticks(lane, monkeypatch):
    import utils.budget_drain as bd
    monkeypatch.setenv("BUDGET_ENABLED", "0")
    ticked = []

    async def fake_tick():
        ticked.append(1)
        return {"decision": "drained", "results": []}

    async def driver():
        sleep = _FakeSleep()
        task = asyncio.create_task(bd.drain_loop(_tick=fake_tick,
                                                 _sleep=sleep))
        deadline = time.time() + 5
        while sleep.hops < 1 and time.time() < deadline:
            await asyncio.sleep(0.001)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    asyncio.run(driver())
    assert ticked == [], "disabled loop must not tick (no store open)"
    st = bd.read_drain_state()
    assert st["phase"] == "disabled"


def test_loop_survives_tick_error(lane):
    import utils.budget_drain as bd
    ticks = []

    async def fake_tick():
        ticks.append(1)
        if len(ticks) == 1:
            raise RuntimeError("tick exploded")
        return {"decision": "drained", "results": []}

    async def driver():
        sleep = _FakeSleep()
        task = asyncio.create_task(bd.drain_loop(_tick=fake_tick,
                                                 _sleep=sleep))
        deadline = time.time() + 5
        while sleep.hops < 2 and time.time() < deadline:
            await asyncio.sleep(0.001)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    asyncio.run(driver())
    st = bd.read_drain_state()
    # the loop recorded the error, kept running, and settled on the
    # successful second tick
    assert len(ticks) >= 2
    assert st["phase"] == "running"
    assert st["last_error"] is None


# --- dispatcher manifest refresh ---------------------------------------------


def test_dispatcher_refreshes_on_unknown_tool(lane, monkeypatch):
    import utils.budget_drain as bd
    calls = []

    async def fake_run_tool(tool_id, arguments, manifests, session_id=None):
        calls.append(len(manifests))
        if calls[-1] == 0:
            return {"status": "Failed", "error": "Unknown tool_id: mytool"}
        return {"status": "ok", "result": {"job_id": 55}}

    import replkit.core as core
    monkeypatch.setattr(core, "run_tool", fake_run_tool)
    refreshes = []

    def fake_discover():
        refreshes.append(1)
        return [types.SimpleNamespace(module_id="mytool")]

    import utils.budget_drain as bd_inner
    from replkit import core as core_mod
    # the dispatcher's refresh path imports replkit.core.discover_tools
    monkeypatch.setattr(core_mod, "discover_tools", fake_discover)
    d = bd.drain_dispatcher([])
    out = asyncio.run(d({"tool": "mytool", "arguments_json": "{}"}))
    assert out == {"job_id": 55}
    assert refreshes, "unknown-tool envelope must trigger a re-discovery"
    assert calls == [0, 1], "refresh must retry the dispatch with fresh manifests"


# --- doctor lens ---------------------------------------------------------------


def test_doctor_running_is_available(lane):
    import utils.budget_drain as bd
    bd.write_drain_state({"last_tick_ts": time.time(),
                          "interval_s": 60.0, "backlog": 0})
    rec = bd.budget_drain_doctor()
    assert rec["available"] is True
    assert rec["state"] == "running"


def test_doctor_stale_is_degrade(lane):
    import utils.budget_drain as bd
    bd.write_drain_state({"last_tick_ts": time.time() - 400.0,
                          "interval_s": 60.0})
    rec = bd.budget_drain_doctor()
    assert rec["available"] is False
    assert rec["state"] == "stale"
    assert rec["remediation"]


def test_doctor_never_ticked_and_disabled(lane, monkeypatch):
    import os
    import utils.budget_drain as bd
    rec = bd.budget_drain_doctor()
    assert rec["available"] is False
    assert rec["state"] == "never_ticked"
    os.environ["BUDGET_ENABLED"] = "0"
    try:
        rec = bd.budget_drain_doctor()
        assert rec["available"] is True
        assert rec["state"] == "disabled"
    finally:
        os.environ["BUDGET_ENABLED"] = "1"


def test_drain_state_file_is_0600(lane):
    import utils.budget_drain as bd
    bd.write_drain_state({"ts": 1.0})
    st = bd.drain_state_path()
    assert (bd.os.stat(st).st_mode & 0o777) == 0o600
