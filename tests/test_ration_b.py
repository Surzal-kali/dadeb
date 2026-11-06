"""Phase B ration-engine tests: status twins, terminal lane, the finished/
in-line drain decision, and restart-resume (§13: SQLite is the durable lane
— a new engine over the same BUDGET_STORE_DIR must pick the queue, node
balances, HOLD phase, and emissions back up with no velocity re-arm).

REPL surfaces (replkit _budget_command) are exercised at the store/engine
level they delegate to.
"""

import asyncio

import pytest

import utils.ration as rt
from utils.ration_store import DIMS, RationStore


@pytest.fixture
def engine(tmp_path, monkeypatch):
    (tmp_path / "budget").mkdir()
    monkeypatch.setenv("BUDGET_STORE_DIR", str(tmp_path / "budget"))
    monkeypatch.setenv("BUDGET_ENABLED", "1")
    for k in ("BUDGET_CONSTITUTION", "BUDGET_CONSTITUTION_FILE",
              "BUDGET_EPOCH_SECONDS", "BUDGET_QUEUE_TTL_HOURS",
              "BUDGET_DRAIN_BATCH"):
        monkeypatch.delenv(k, raising=False)
    rt.reset_engine()
    yield rt.get_engine()
    rt.reset_engine()


def _fresh_store() -> RationStore:
    """The restart: same dir (env), brand-new store/engine singletons."""
    rt.reset_ration_store()
    rt.reset_engine()
    return rt.get_ration_store()


def _decl(**kw):
    return {d: kw.get(d) for d in DIMS}


def _dims(**kw):
    dims = rt.dims_for_target(kw.pop("target", "10.0.0.7"))
    dims.update(kw)
    return dims


def _const_kw():
    c = rt.constitution()
    return dict(policy=c.policy(), epoch_s=c.epoch_s, max_single=c.max_single())


def _hold_all_nodes(store) -> int:
    """Flip every existing node to HOLD (one selector pass per row)."""
    n = 0
    for row in store.conn.execute("SELECT node_key FROM nodes"):
        parts = tuple(str(row["node_key"]).split("\x1f"))
        sel = dict(zip(("engagement", "entry_partition", "exit_id",
                        "range_axis", "host_axis", "principal"), parts))
        sel = {k: v for k, v in sel.items() if v}
        n += store.set_phase(mode="hold", **sel)
    return n


# ─── status twins (model-visible, read-only) ─────────────────────────────────

class TestBudgetStatusTwin:
    def test_arm_and_backlog_render(self, engine):
        engine.store.debit_vector(
            _decl(requests=1), _dims(), tool="tests.s", now=0.0, **_const_kw())
        out = rt.budget_status()
        assert isinstance(out, str)
        assert "ARMED" in out
        assert "nodes: 3" in out
        assert "backlog" in out

    def test_disabled_kill_switch_shows(self, engine, monkeypatch):
        monkeypatch.setenv("BUDGET_ENABLED", "0")
        assert "DISABLED (kill switch)" in rt.budget_status()

    def test_hold_nodes_surfaced(self, engine):
        engine.store.debit_vector(
            _decl(requests=1), _dims(), tool="tests.s", now=0.0, **_const_kw())
        assert _hold_all_nodes(engine.store) >= 1
        assert "HOLD" in rt.budget_status()

    def test_low_balance_surfaced(self, engine):
        # requests ceiling 600 → drain to <25% (150) and expect the LOW line
        engine.store.debit_vector(
            _decl(requests=470), _dims(), tool="tests.s", now=0.0, **_const_kw())
        out = rt.budget_status()
        assert "LOW" in out and "requests" in out

    def test_fail_closed_text_on_store_error(self, engine, monkeypatch):
        monkeypatch.setenv("BUDGET_STORE_DIR",
                           str(engine.store.workspace_unused
                               if hasattr(engine.store, "workspace_unused")
                               else "/proc/nonexistent-budget-dir"))
        rt.reset_ration_store()
        rt.reset_engine()
        try:
            out = rt.budget_status()
            assert "UNAVAILABLE" in out or "budget:" in out
        finally:
            rt.reset_ration_store()
            rt.reset_engine()


class TestQueueStatusTwin:
    def test_listing_default_queued_and_states(self, engine):
        q1 = engine.store.enqueue_item(
            tool="tests.a", arguments={}, decl=_decl(), dims=_dims(),
            reason="x", agent_id="a", engagement=None, now=1000.0)
        engine.store.enqueue_item(
            tool="tests.b", arguments={}, decl=_decl(), dims=_dims(),
            reason="x", agent_id="a", engagement=None, now=1001.0)
        engine.store.bind_item(q1, "777")
        out = rt.budget_queue_status()
        assert "tests.b" in out and "tests.a" not in out  # default = queued
        out_l = rt.budget_queue_status(state="launched")
        assert "tests.a" in out_l and "tests.b" not in out_l
        assert "job=777" in out_l

    def test_tool_filter(self, engine):
        engine.store.enqueue_item(
            tool="tests.always", arguments={}, decl=_decl(), dims=_dims(),
            reason="x", agent_id="a", engagement=None, now=1000.0)
        engine.store.enqueue_item(
            tool="tests.never", arguments={}, decl=_decl(), dims=_dims(),
            reason="x", agent_id="a", engagement=None, now=1001.0)
        out = rt.budget_queue_status(tool="always")
        assert "tests.always" in out and "tests.never" not in out

    def test_empty(self, engine):
        assert "(queue empty)" in rt.budget_queue_status()


def test_ration_twins_on_terminal_lane():
    """The read-only twins ride the budget allowlist so they stay callable
    when the per-turn tool budget is exhausted (terminal-lane contract)."""
    from utils.tool_budget import ToolBudget
    b = ToolBudget()
    assert b.is_terminal_lane("utils.ration.budget_status")
    assert b.is_terminal_lane("utils.ration.budget_queue_status")
    assert b.is_terminal_lane("utils.memory_tools.remember")


# ─── finished / in-line drain decision ───────────────────────────────────────

class TestInlineDrain:
    def test_finished_consumes_item(self, engine):
        engine.store.debit_vector(
            _decl(requests=600), _dims(), tool="tests.i", now=1000.0,
            **_const_kw())
        out = engine.preflight("auxiliaries.web_session.session_get",
                               {"target": "10.0.0.7"}, now=1001.0)
        assert out["decision"] == "enqueue"

        async def inline(item):
            assert item["tool"] == "auxiliaries.web_session.session_get"
            return {"finished": True}

        res = asyncio.run(engine.operator_tick(dispatch=inline, now=1005.0))
        assert res["results"][0]["decision"] == "dispatched_inline"
        assert engine.store.get_item(out["queue_id"])["status"] == "finished"

    def test_sync_callable_still_binds_job_id(self, engine):
        engine.store.enqueue_item(
            tool="tests.bg", arguments={}, decl=_decl(), dims=_dims(),
            reason="x", agent_id="a", engagement=None, now=1000.0)
        res = asyncio.run(engine.operator_tick(
            dispatch=lambda item: {"job_id": 42}, now=1005.0))
        assert res["results"][0]["decision"] == "dispatched"
        assert res["results"][0]["job_id"] == "42"


class TestDrainDispatcherMapping:
    def test_job_id_from_inner_result(self, monkeypatch):
        import replkit.core as core
        import replkit.operator_cli as cli

        async def fake_run_tool(tool_id, arguments, manifests,
                                 session_id=None):
            assert session_id == "ration-drain", \
                "drain lane must announce itself"
            return {"status": "ok", "result": {"job_id": 9001}}
        monkeypatch.setattr(core, "run_tool", fake_run_tool)
        d = cli._budget_drain_dispatcher(())
        out = asyncio.run(d({"tool": "t", "arguments_json": "{}"}))
        assert out == {"job_id": 9001}

    def test_bare_result_job_id(self, monkeypatch):
        import replkit.core as core
        import replkit.operator_cli as cli

        async def fake_run_tool(tool_id, arguments, manifests,
                                 session_id=None):
            assert session_id == "ration-drain", \
                "drain lane must announce itself"
            return {"job_id": 7}
        monkeypatch.setattr(core, "run_tool", fake_run_tool)
        d = cli._budget_drain_dispatcher(())
        out = asyncio.run(d({"tool": "t", "arguments_json": "{}"}))
        assert out == {"job_id": 7}

    def test_inline_fallback_marks_finished(self, monkeypatch):
        import replkit.core as core
        import replkit.operator_cli as cli

        async def fake_run_tool(tool_id, arguments, manifests,
                                 session_id=None):
            assert session_id == "ration-drain", \
                "drain lane must announce itself"
            return {"status": "ok", "result": {"stdout": "data"}}
        monkeypatch.setattr(core, "run_tool", fake_run_tool)
        d = cli._budget_drain_dispatcher(())
        out = asyncio.run(d({"tool": "t", "arguments_json": "{}"}))
        assert out == {"finished": True}


# ─── restart-resume (§13) ────────────────────────────────────────────────────

class TestRestartResume:
    def test_queue_balances_phase_and_emissions_survive(self, engine):
        engine.store.debit_vector(
            _decl(requests=600), _dims(), tool="tests.r", now=1000.0,
            **_const_kw())
        out = engine.preflight("auxiliaries.web_session.session_get",
                               {"target": "10.0.0.7"}, now=1001.0)
        assert out["decision"] == "enqueue"
        pre_nodes = {r["node_key"]: dict(r)
                     for r in engine.store.conn.execute("SELECT * FROM nodes")}
        _hold_all_nodes(engine.store)

        # ── restart ──
        store2 = _fresh_store()
        engine2 = rt.get_engine()

        # queue survives; the drained item binds post-restart
        due = store2.due_items(now=1005.0)
        assert len(due) == 1
        assert due[0]["qid"] == out["queue_id"]
        res = asyncio.run(engine2.operator_tick(
            dispatch=lambda item: {"job_id": 1234}, now=1006.0))
        assert res["results"][0]["decision"] == "dispatched"

        # spent balances persist (lazy accrual does not resurrect spent value)
        post_nodes = {r["node_key"]: dict(r)
                      for r in store2.conn.execute("SELECT * FROM nodes")}
        assert set(post_nodes) == set(pre_nodes)
        for key, row in post_nodes.items():
            assert row["remaining_requests"] \
                == pre_nodes[key]["remaining_requests"]

        # emissions survive identically
        n_e = list(store2.conn.execute("SELECT COUNT(*) c FROM emissions"))[0]["c"]
        assert n_e == 1

        # HOLD mode survives — no velocity re-arm on restart
        held = [dict(r) for r in store2.conn.execute(
            "SELECT node_key, mode FROM nodes WHERE mode='hold'")]
        assert held, "HOLD phase must persist across restart"

    def test_hold_refill_projection_after_restart(self, engine):
        engine.store.debit_vector(
            _decl(requests=600), _dims(), tool="tests.h", now=0.0,
            **_const_kw())
        _hold_all_nodes(engine.store)
        rt.reset_ration_store()
        rt.reset_engine()
        store2 = rt.get_ration_store()
        # HOLD floor-accrual projection at a later read time: stored balance
        # stays put, the projection fills toward the floor
        rows = [dict(r) for r in store2.conn.execute(
            "SELECT * FROM nodes WHERE remaining_requests < 10")]
        assert rows
        raw = rows[0]
        proj = store2._accrue(raw, now=float(raw["last_refill"]) + 3600.0,
                              epoch_s=rt.constitution().epoch_s)
        assert proj["requests"]["remaining"] > float(raw["remaining_requests"])


# ─── REPL-delegated store surfaces ───────────────────────────────────────────

class TestSetPhaseGuards:
    def test_blanket_flip_refused(self, engine):
        with pytest.raises(ValueError):
            engine.store.set_phase(mode="hold")

    def test_round_trip(self, engine):
        # CIDR target becomes its own host_axis (hyphen span), range None
        dims = _dims(target="10.9.9.0/24")
        engine.store.debit_vector(
            _decl(requests=1), dims, tool="tests.p", now=0.0, **_const_kw())
        host_axis = dims["host_axis"]
        assert host_axis and "10.9.9.0" in host_axis
        assert dims["range_axis"] is None
        assert engine.store.set_phase(mode="hold", host_axis=host_axis) >= 1
        assert engine.store.set_phase(mode="normal", host_axis=host_axis) >= 1
        modes = set(dict(r)["mode"] for r in
                    engine.store.conn.execute("SELECT mode FROM nodes"))
        assert modes == {"normal"}


class TestListItems:
    def test_history_order_and_filters(self, engine):
        for i in range(3):
            engine.store.enqueue_item(
                tool=f"tests.t{i}", arguments={}, decl=_decl(),
                dims=_dims(), reason="x", agent_id="a", engagement=None,
                now=1000.0 + i)
        rows = engine.store.list_items()
        assert [r["tool"] for r in rows] == ["tests.t2", "tests.t1", "tests.t0"]
        assert [r["tool"] for r in engine.store.list_items(tool="t1")] \
            == ["tests.t1"]
        engine.store.finish_item(rows[0]["qid"])
        assert [r["qid"] for r in engine.store.list_items(state="finished")] \
            == [rows[0]["qid"]]
