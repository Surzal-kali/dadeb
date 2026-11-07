"""Debt §5.1 pacemaker tests (2026-11-07): the always-on drain loop —
state-file contract, disabled-lane fast path, per-tick error survival,
cancel, manifest refresh on unknown-tool, and the doctor lens."""

import asyncio
import json
import os
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


# --- env parse: systemd EnvironmentFile inline comments (2026-11-06) ---
# The deb unit reads /etc/daharness/daharness.env with systemd, which does
# NOT strip trailing "# ..." comments — an operator who uncomments the
# packaged `#BUDGET_DRAIN_BATCH=2   # items per tick` row feeds
# "2   # items per tick" to the parser. Live crash (22:04:45): the drain
# loop died on _env_int("BUDGET_DRAIN_BATCH") before its first tick.


def test_env_numeric_strips_inline_comment(lane, monkeypatch):
    monkeypatch.setenv("BUDGET_TEST_NUM", "30   # tick cadence, s (code default 30)")
    assert rt._env_float("BUDGET_TEST_NUM", 7.0) == 30.0
    monkeypatch.setenv("BUDGET_TEST_NUM", "2\t# items per tick (code default 2)")
    assert rt._env_int("BUDGET_TEST_NUM", 9) == 2


def test_env_numeric_blank_goes_default(lane, monkeypatch):
    monkeypatch.setenv("BUDGET_TEST_NUM", "   # operator cleared the value")
    monkeypatch.setenv("BUDGET_TEST_NUM_EMPTY", "")
    assert rt._env_float("BUDGET_TEST_NUM", 30.0) == 30.0
    assert rt._env_float("BUDGET_TEST_NUM_EMPTY", 30.0) == 30.0


def test_env_numeric_garbage_still_raises(lane, monkeypatch):
    monkeypatch.setenv("BUDGET_TEST_NUM", "abc#def")
    with pytest.raises(ValueError):
        rt._env_float("BUDGET_TEST_NUM", 1.0)


def test_env_bool_strips_inline_comment(lane, monkeypatch):
    monkeypatch.setenv("BUDGET_TEST_FLAG", "1  # default on -- bootstrap task")
    assert rt._env_bool("BUDGET_TEST_FLAG", False) is True
    monkeypatch.setenv("BUDGET_TEST_FLAG", "false  # off")
    assert rt._env_bool("BUDGET_TEST_FLAG", True) is False


# --- §6.2 drum drip (2026-11-06 live incident) --------------------------------
#
# The .107 drum watch: a 600-request chunk queued for >1h12m of 30s ticks
# with zero launches and a STALL stamp. admit_vector is contractually
# read-only, so its ``enqueue`` verdict never reached debit_vector's
# short-grant persistence — every tick recomputed the accrued refill from
# the same stale stored balance and discarded it. The one operator writer
# now materializes the drip for due items' nodes before the batch runs.


def _drainlaw_engine():
    """Default-law engine (ceiling 600 requests, refill 150/epoch, epoch
    300s — the shipped law) on whatever store dir the fixture set."""
    rt.reset_engine()
    rt.reset_ration_store()
    return rt.get_engine()


def _starved_chunk_item(engine, *, decl_requests=600.0):
    """One queued ffuf CHUNK on a zero-balance node (the live box's
    post-lane-spend leftover). Chunk-keyed args so the estimator declares
    the slice vector deterministically (600 requests) with no wordlist."""
    from utils.ration_store import _node_key

    t_dims = rt.dims_for_target("10.0.0.5")
    dims = ({"engagement": None, **t_dims} if "engagement" not in t_dims
            else t_dims)
    args = {"url": "http://10.0.0.5/FUZZ",
            "wordlist": "/tmp/never-resolved.txt",
            "chunk_plan_id": "wp-test", "chunk_index": 0,
            "chunk_offset": 0, "chunk_slice": int(decl_requests),
            "chunk_total_chunks": 2}
    engine.store.enqueue_item(
        tool="payloads.ffuf.run_ffuf", arguments=args,
        decl={"requests": decl_requests, "packets": None,
              "auth_events": None, "bytes": decl_requests * 8192.0},
        dims=dims, reason="starve test", agent_id="tester",
        engagement=None)
    key = _node_key(None, dims.get("entry_partition"), None, None,
                    "10.0.0.5", None)
    row = engine.store.conn.execute(
        "SELECT 1 FROM nodes WHERE node_key=?", (key,)).fetchone()
    if row is None:
        engine.store.conn.execute(
            "INSERT INTO nodes (node_key, engagement, host_axis,"
            " ceiling_json, floor_json, refill_json, remaining_requests,"
            " remaining_packets, remaining_auth, remaining_bytes,"
            " last_refill, epoch_anchor) VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?,NULL)",
            (key, None, "10.0.0.5",
            json.dumps({"requests": 600.0, "packets": 2000000.0,
                          "auth_events": 60.0, "bytes": 268435456.0}),
            json.dumps({"requests": 2.0, "packets": 500.0,
                          "auth_events": 0.2, "bytes": 262144.0}),
            json.dumps({"requests": 150.0, "packets": 250000.0,
                          "auth_events": 5.0, "bytes": 33554432.0}),
            0.0, 0.0, 0.0, 0.0, 0.0))
    else:
        # zero it (and clear any anchor/phase) like the live box's leftover
        engine.store.conn.execute(
            "UPDATE nodes SET remaining_requests=0, last_refill=0,"
            " epoch_anchor=NULL, mode='normal' WHERE node_key=?", (key,))
    engine.store.conn.commit()
    return key, time.time()


def test_drain_drip_persists_refill_starved_chunk_launches(lane,
                                                           monkeypatch):
    """A 600-request chunk on a zeroed node must LAUNCH through operator
    ticks: the drip persists accrual each tick (150/epoch), and once the
    stored balance crosses the declaration the same lane admits and
    debits. Pre-2026-11-07 the grant was recomputed-and-discarded forever
    (admit is read-only; debit never ran) — the queue starved silently."""
    import asyncio

    rt.reset_engine()
    rt.reset_ration_store()
    monkeypatch.delenv("BUDGET_DRAIN_INTERVAL_S", raising=False)
    eng = _drainlaw_engine()
    node_key, t0 = _starved_chunk_item(eng)

    launches: list[str] = []

    async def drainlike(item):
        # the drain lane's dispatch semantics, minimally: gate → debit → job
        decision = eng.preflight(
            item["tool"], json.loads(item["arguments_json"]),
            agent_id="drain", operator_release=True)
        from utils.ration import BudgetStillShort
        if decision.get("decision") != "admit":
            raise BudgetStillShort(queue_id=decision.get("queue_id"))
        receipt = eng.dispatch_debit(
            item["tool"], json.loads(item["arguments_json"]),
            agent_id="drain")
        if receipt.get("committed"):
            launches.append(f"job-{len(launches)}")
            return {"job_id": launches[-1]}
        raise BudgetStillShort(queue_id=receipt.get("queue_id"))

    t0 = t0 + 1.0     # helper's enqueue instant; ticks walk the real clock
    for tick in range(6):
        out = asyncio.run(eng.operator_tick(
            dispatch=drainlike, sleep_fn=lambda *_a: None,
            now=t0 + tick * 300.0))
        rem = eng.store.conn.execute(
            "SELECT remaining_requests, last_refill FROM nodes "
            "WHERE node_key=?", (node_key,)).fetchone()
        if tick < 3:            # 150/epoch accrual: 150, 300, 450 — short
            assert launches == [], "launched before the balance could fund it"
            # THE FIX UNDER TEST: the grant PERSISTED across ticks (the
            # pre-fix read-only store recomputed from the stale balance and
            # never rose).
            assert rem["remaining_requests"] >= 150.0 * (tick + 1), (
                f"tick {tick}: grant not persisted "
                f"(stored {rem['remaining_requests']})")
        assert launches or rem["last_refill"] >= t0, "drip never ran"

    assert launches, "a 600-request chunk never launched through the drip"
    rem = eng.store.conn.execute(
        "SELECT remaining_requests FROM nodes WHERE node_key=?",
        (node_key,)).fetchone()
    assert rem["remaining_requests"] < 600.0    # the debit took the spend


def test_drip_commit_no_double_grant_within_touch(lane, monkeypatch):
    """last_refill stamps each drip write so a second touch at the same
    ``now`` (e.g. two due items on one node) grants nothing extra."""
    rt.reset_engine()
    rt.reset_ration_store()
    eng = _drainlaw_engine()
    node_key, t = _starved_chunk_item(eng)
    items = eng.store.due_items(now=t)
    first = eng.store.drip_due_nodes(items, 300.0, now=t)
    assert first["nodes"] == 1, first
    rem1 = eng.store.conn.execute(
        "SELECT remaining_requests FROM nodes WHERE node_key=?",
        (node_key,)).fetchone()["remaining_requests"]
    assert rem1 > 0.0
    eng.store.drip_due_nodes(items, 300.0, now=t)
    rem2 = eng.store.conn.execute(
        "SELECT remaining_requests FROM nodes WHERE node_key=?",
        (node_key,)).fetchone()["remaining_requests"]
    assert rem2 == rem1, "same-touch drip double-granted"
