"""Phase C ration-engine tests: controller posture machine (§8.1), authority
rails (§8.2), tripwire interval learning (§8.3), automatic refill modes +
jittered epoch re-anchor (§6.2), stall alarm, and release-side jitter/pacing
(§6.1, §7.3)."""

import asyncio
import json

import pytest

import utils.ration as rt
from utils.ration import CONTROLLER_PACING, Controller


def asyncio_run(coro):
    return asyncio.run(coro)


@pytest.fixture
def engine(tmp_path, monkeypatch):
    (tmp_path / "budget").mkdir()
    monkeypatch.setenv("BUDGET_STORE_DIR", str(tmp_path / "budget"))
    monkeypatch.setenv("BUDGET_ENABLED", "1")
    for k in ("BUDGET_CONSTITUTION", "BUDGET_CONSTITUTION_FILE",
              "BUDGET_EPOCH_SECONDS", "BUDGET_QUEUE_TTL_HOURS",
              "BUDGET_DRAIN_BATCH", "BUDGET_TRIPWIRE_WINDOW_S"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("BUDGET_TRIPWIRE_WINDOW_S", "300")
    rt.reset_engine()
    yield rt.get_engine()
    rt.reset_engine()


@pytest.fixture
def store(engine):
    return engine.store


def _debit(engine, target="10.0.0.7", engagement=None, now=1000.0, n=1.0):
    r = engine.dispatch_debit(
        "auxiliaries.web_session.session_get",
        {"target": target}, engagement=engagement, agent_id="test", now=now)
    assert r.get("committed") or r.get("decision") in ("enqueue",
                                                       "reject"), r
    return r


def _mint(engine, store, target="10.0.0.7", now=1000.0):
    _debit(engine, target=target, now=now)


def _host_node_key(store, host):
    """Host-level node key (the axis slot, not string containment)."""
    for r in store.conn.execute("SELECT node_key FROM nodes"):
        parts = r["node_key"].split("\x1f")
        if len(parts) > 4 and parts[4] == host:
            return r["node_key"]
    raise AssertionError(f"no host node for {host}")


class TestControllerMachine:
    def test_single_429_never_advances(self, store):
        c = Controller(store, now_fn=lambda: 1000.0)
        rec = c.observe(engagement=None, host_axis="10.0.0.7",
                        response_class="429")
        assert rec["state"] == "normal"
        assert rec["streak"] == 1

    def test_k_consecutive_advance_one_level(self, store):
        c = Controller(store, hysteresis_k=2, now_fn=lambda: 1000.0)
        c.observe(engagement=None, host_axis="h", response_class="429")
        rec = c.observe(engagement=None, host_axis="h", response_class="429")
        assert rec["state"] == "soft_signal"

    def test_hard_pressure_walks_ladder(self, store):
        c = Controller(store, hysteresis_k=1, now_fn=lambda: 1000.0)
        for i in range(3):
            rec = c.observe(engagement=None, host_axis="h",
                            response_class="reset")
        assert rec["state"] == "backoff"

    def test_soft_never_passes_throttled(self, store):
        c = Controller(store, hysteresis_k=1, now_fn=lambda: 1000.0)
        for i in range(10):
            rec = c.observe(engagement=None, host_axis="h",
                            response_class="challenge")
        assert rec["state"] == "throttled"

    def test_quiet_decay_one_level_per_window(self, store):
        now = {"t": 1000.0}
        c = Controller(store, hysteresis_k=1, quiet_window_s=120.0,
                       now_fn=lambda: now["t"])
        for _ in range(3):
            c.observe(engagement=None, host_axis="h", response_class="429")
        rec = c.observe(engagement=None, host_axis="h",
                        response_class="200", now=1001.0)
        assert rec["state"] == "backoff"  # no immediate decay
        rec = c.observe(engagement=None, host_axis="h", response_class="200",
                        now=1001.0 + 121)
        assert rec["state"] == "throttled"  # exactly one level back
        rec = c.observe(engagement=None, host_axis="h", response_class="200",
                        now=1001.0 + 242)
        assert rec["state"] == "soft_signal"

    def test_transitions_hour_authority_cap(self, store):
        c = Controller(store, hysteresis_k=1, max_transitions_h=1,
                       now_fn=lambda: 1000.0)
        rec = c.observe(engagement=None, host_axis="h", response_class="429")
        first = rec["state"]
        rec = c.observe(engagement=None, host_axis="h", response_class="429")
        assert rec["state"] == first  # refused — authority spent

    def test_pacing_values_and_floor(self, store):
        c = Controller(store, hysteresis_k=1, now_fn=lambda: 1000.0)
        assert c.pacing(engagement=None, host_axis="h") == 1.0
        rec = c.observe(engagement=None, host_axis="h", response_class="429")
        assert c.pacing(engagement=None, host_axis="h") == \
            CONTROLLER_PACING["soft_signal"]
        for i in range(3):
            rec = c.observe(engagement=None, host_axis="h",
                            response_class="429")
        assert rec["state"] == "cooldown"
        assert c.pacing(engagement=None, host_axis="h") == \
            CONTROLLER_PACING["cooldown"] > 0.0  # not 0: §8.2

    def test_state_survives_restart(self, store, tmp_path):
        c = Controller(store, hysteresis_k=1, now_fn=lambda: 1000.0)
        c.observe(engagement=None, host_axis="h", response_class="429")
        st2 = rt.RationStore(store_dir=store.dir)
        rec = st2.get_controller_states()
        vals = [v["state"] for d in rec.values() for v in d.values()]
        assert "soft_signal" in vals


class TestTripwireIntervals:
    def test_monotone_tightening(self, store):
        rec = store.tripwire_interval("e1", "10.0.0.7", "requests",
                                      upper=10.0, window_seconds=300.0)
        assert rec["upper"] == 10.0 and rec["lower"] is None
        rec = store.tripwire_interval("e1", "10.0.0.7", "requests",
                                      upper=12.0, window_seconds=300.0)
        assert rec["upper"] == 10.0  # never loosens
        rec = store.tripwire_interval("e1", "10.0.0.7", "requests",
                                      lower=5.0, window_seconds=300.0)
        assert rec["lower"] == 5.0
        rec = store.tripwire_interval("e1", "10.0.0.7", "requests",
                                      lower=2.0, window_seconds=300.0)
        assert rec["lower"] == 5.0

    def test_reconcile_feeds_onset_and_clean_run(self, engine, store):
        _debit(engine, now=1000.0)
        rec = engine.reconcile({"emission_id": 1, "tool": "run_nmap"},
                               {"requests": 1}, response_class="429")
        iv = store.tripwire_intervals(engagement=None,
                                      host_axis="10.0.0.7")
        assert iv and iv[0]["upper"] is not None
        assert iv[0]["provenance"] == "onset"
        rows = [v for d in store.get_controller_states().values()
                for v in d.values()]
        assert rows and rows[0]["state"] == "normal"  # one 429: no advance
        assert rows[0]["streak"] == 1

    def test_clean_run_raises_lower(self, engine, store):
        for i, rc in enumerate(("429", "200", "200", "200")):
            _debit(engine, now=2000.0 + i)
            engine.reconcile({"emission_id": i + 1, "tool": "run_nmap"},
                             {"requests": 1}, response_class=rc)
        iv = store.tripwire_intervals(engagement=None, host_axis="10.0.0.7")
        lows = [i["lower"] for i in iv if i["lower"] is not None]
        assert lows and lows[-1] >= 3.0

    def test_per_engagement_scoping_and_purge(self, store):
        store.tripwire_interval("e1", "h", "requests", upper=9.0,
                                window_seconds=300.0)
        assert store.tripwire_intervals(engagement="e2") == []
        assert store.tripwire_intervals(engagement="e1")
        store.purge_engagement("e1")
        assert store.tripwire_intervals(engagement="e1") == []

    def test_tripwire_bound_auto_throttles_pacing(self, engine, store):
        store.tripwire_interval(None, "10.0.0.7", "requests", lower=3.0,
                                window_seconds=300.0)
        for _ in range(4):
            _debit(engine, now=5000.0)
        # spend in window (4) >= lower (3) → pacing clamps to throttled
        assert engine.controller.pacing(
            engagement=None, host_axis="10.0.0.7",
            now=5001.0) == CONTROLLER_PACING["throttled"]


class TestBacklogModes:
    def test_backlog_holds_own_host_only(self, engine, store):
        _mint(engine, store, "10.0.0.7")
        _mint(engine, store, "10.0.0.8", now=1001.0)
        store.enqueue_item(tool="run_nmap", arguments={"target": "10.0.0.7",
                          "ports": "80"}, decl={}, dims=rt.dims_for_target(
                          "10.0.0.7"), reason="budget_short",
                          agent_id="test", engagement=None, now=1002.0)
        trans = store.apply_backlog_modes(
            1003.0, 3600.0, jitter_lo=3060.0, jitter_hi=4140.0)
        modes = {n["node_key"]: n["mode"] for n in
                 store.conn.execute("SELECT node_key, mode FROM nodes")}
        host7 = _host_node_key(store, "10.0.0.7")
        host8 = _host_node_key(store, "10.0.0.8")
        assert modes[host7] == "hold"
        assert modes[host8] == "normal"
        host_axes = set()
        for r in store.conn.execute("SELECT node_key FROM nodes"):
            p = r["node_key"].split("\x1f")
            if len(p) > 4 and p[4]:
                host_axes.add(p[4])
        assert host_axes == {"10.0.0.7", "10.0.0.8"}
        assert all(t["mode"] == "hold" for t in trans)

    def test_drained_host_reanchors_with_jitter(self, engine, store):
        _mint(engine, store, "10.0.0.7")
        qid = store.enqueue_item(
            tool="run_nmap", arguments={"target": "10.0.0.7", "ports": "80"},
            decl={}, dims=rt.dims_for_target("10.0.0.7"),
            reason="budget_short", agent_id="test", engagement=None,
            now=1002.0)
        store.apply_backlog_modes(1003.0, 3600.0, jitter_lo=0.0,
                                  jitter_hi=0.1)
        store.finish_item(qid)
        trans = store.apply_backlog_modes(
            1004.0, 3600.0, jitter_lo=3060.0, jitter_hi=4140.0)
        assert trans and trans[0]["mode"] == "normal"
        anchor = trans[0]["epoch_anchor"]
        assert anchor is not None
        assert 1004.0 + 3060.0 <= anchor <= 1004.0 + 4140.0

    def test_no_refill_before_anchor(self, engine, store):
        _mint(engine, store, "10.0.0.7", now=1000.0)
        key = next(iter(r["node_key"] for r in store.conn.execute(
            "SELECT node_key FROM nodes")))
        row = store._node_row(key)
        stored = float(row["remaining_requests"])
        store.conn.execute(
            "UPDATE nodes SET epoch_anchor=? WHERE node_key=?",
            (1000.0 + 500.0, key))
        bal = store._accrue(store._node_row(key), 1000.0 + 100.0, 3600.0)
        assert bal["requests"]["remaining"] == stored
        bal = store._accrue(store._node_row(key), 1000.0 + 600.0, 3600.0)
        assert bal["requests"]["remaining"] > stored

    def test_manual_pin_wins(self, engine, store):
        _mint(engine, store, "10.0.0.7")
        store.set_phase(mode="hold", engagement=None,
                        host_axis="10.0.0.7")
        trans = store.apply_backlog_modes(1005.0, 3600.0, jitter_lo=0.0,
                                          jitter_hi=1.0)
        assert trans == []  # pinned hold stays — only the operator lifts
        modes = {n["node_key"]: n["mode"] for n in
                 store.conn.execute("SELECT node_key, mode FROM nodes")}
        host7 = _host_node_key(store, "10.0.0.7")
        assert modes[host7] == "hold"
        store.set_phase(mode="normal", engagement=None,
                        host_axis="10.0.0.7")
        modes = {n["node_key"]: n["mode"] for n in
                 store.conn.execute("SELECT node_key, mode FROM nodes")}
        assert modes[host7] == "normal"


class TestStallAlarm:
    def test_stalled_hold_reported(self, engine, store):
        _mint(engine, store, "10.0.0.7", now=1000.0)
        store.set_phase(mode="hold", engagement=None, host_axis="10.0.0.7")
        store.enqueue_item(tool="run_nmap", arguments={"target": "10.0.0.7",
                           "ports": "80"}, decl={}, dims=rt.dims_for_target(
                           "10.0.0.7"), reason="budget_short",
                           agent_id="test", engagement=None,
                           now=1000.0 - 2 * 3600.0)
        stalls = store.stall_report(1000.0, 3600.0)
        assert stalls and stalls[0]["host_axis"] == "10.0.0.7"
        assert stalls[0]["oldest_queued_s"] > 3600.0

    def test_progressing_hold_not_stalled(self, engine, store):
        _mint(engine, store, "10.0.0.7", now=1000.0)
        store.set_phase(mode="hold", engagement=None, host_axis="10.0.0.7")
        qid = store.enqueue_item(tool="run_nmap", arguments={},
                                 decl={}, dims={"host_axis": "10.0.0.7"},
                                 reason="budget_short", agent_id="test",
                                 engagement=None, now=1000.0 - 2 * 3600.0)
        # drain progress since the oldest queued request → not stalled
        store.bind_item(qid, "777")
        assert store.stall_report(1000.0, 3600.0) == []

    def test_status_twin_renders_stall_line(self, engine, store):
        _mint(engine, store, "10.0.0.7", now=1000.0)
        store.set_phase(mode="hold", engagement=None, host_axis="10.0.0.7")
        store.enqueue_item(tool="run_nmap", arguments={},
                           decl={}, dims={"host_axis": "10.0.0.7"},
                           reason="budget_short", agent_id="test",
                           engagement=None, now=1000.0 - 2 * 3600.0)
        text = rt.budget_status()
        assert "STALL" in text


class TestDrainPacingJitter:
    def test_throttled_drain_scales_and_jitters(self, engine, store,
                                                monkeypatch):
        for target in ("10.0.0.7",):
            _debit(engine, target=target, now=1000.0)
        c = engine.controller = Controller(engine.store, hysteresis_k=1,
                                           now_fn=lambda: 1000.5)
        for _ in range(2):
            c.observe(engagement=None, host_axis="10.0.0.7",
                      response_class="429")
        assert c.pacing(engagement=None, host_axis="10.0.0.7") == \
            CONTROLLER_PACING["throttled"]
        for i in range(6):
            store.enqueue_item(tool="run_nmap", arguments={"target":
                               "10.0.0.7", "ports": "80"}, decl={},
                               dims=rt.dims_for_target("10.0.0.7"),
                               reason="budget_short", agent_id="test",
                               engagement=None, now=999.0)
        monkeypatch.setenv("BUDGET_DRAIN_BATCH", "8")
        monkeypatch.setenv("BUDGET_RELEASE_JITTER_S", "1.0")
        monkeypatch.setenv("BUDGET_RELEASE_JITTER_CAP_S", "10.0")
        sleeps: list[float] = []
        out = asyncio_run(engine.operator_tick(
            dispatch=lambda item: {"job_id": f"J{item['qid'][-2:]}"}, now=1001.0,
            sleep_fn=lambda s: sleeps.append(s)))
        n_dispatched = sum(
            1 for r in out["results"] if r["decision"] == "dispatched")
        assert n_dispatched >= 1
        # batch scales by pacing 0.4 → at most int(8 * .4) = 3 dispatches
        assert n_dispatched <= 3
        assert len(sleeps) == max(0, n_dispatched - 1)
        assert all(0.0 <= s <= 10.0 for s in sleeps)
        assert len(set(sleeps)) >= 2  # entropy, not a fixed cadence

    def test_cooldown_holds_items_dispatched_never(self, engine, store):
        _debit(engine, target="10.0.0.7", now=1000.0)
        c = engine.controller = Controller(engine.store, hysteresis_k=1,
                                           now_fn=lambda: 1000.5)
        for _ in range(11):
            c.observe(engagement=None, host_axis="10.0.0.7",
                      response_class="429")
        assert c.pacing(engagement=None, host_axis="10.0.0.7") == 0.1
        for i in range(3):
            store.enqueue_item(tool="run_nmap", arguments={},
                               decl={}, dims=rt.dims_for_target("10.0.0.7"),
                               reason="budget_short", agent_id="test",
                               engagement=None, now=999.0)
        sleeps: list[float] = []
        out = asyncio_run(engine.operator_tick(
            dispatch=lambda item: {"finished": True}, now=1001.0,
            sleep_fn=lambda s: sleeps.append(s)))
        assert all(r["decision"] == "held_cooldown" for r in out["results"])
        assert sleeps == []
