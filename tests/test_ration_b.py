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
    monkeypatch.setenv("BUDGET_CONSTITUTION",
                       '{"release_jitter": {"min": 0.0, "max": 0.0}}')
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

    def test_failed_envelope_propagates_not_finished(self, monkeypatch):
        """§2.6 seam close: a Failed-tool envelope (run_tool wraps raised
        tool bodies, incl. ScopeGateError) must reach the engine's bounded
        ledger — the dispatcher returns it verbatim instead of consuming
        the item as an inline success."""
        import replkit.core as core
        import replkit.operator_cli as cli

        async def fake_run_tool(tool_id, arguments, manifests,
                                 session_id=None):
            return {"status": "Failed",
                    "error": "Exception during execution: scope gate: "
                             "host not blessed"}
        monkeypatch.setattr(core, "run_tool", fake_run_tool)
        d = cli._budget_drain_dispatcher(())
        out = asyncio.run(d({"tool": "t", "arguments_json": "{}"}))
        assert out["status"] == "Failed"
        assert "scope gate" in out["error"]
        assert "finished" not in out      # NEVER consumed as done

    def test_failed_inner_envelope_propagates(self, monkeypatch):
        import replkit.core as core
        import replkit.operator_cli as cli

        async def fake_run_tool(tool_id, arguments, manifests,
                                 session_id=None):
            # inner-result shape (executor-wrapped transports)
            return {"status": "ok",
                    "result": {"status": "Failed", "error": "brain refused"}}
        monkeypatch.setattr(core, "run_tool", fake_run_tool)
        d = cli._budget_drain_dispatcher(())
        out = asyncio.run(d({"tool": "t", "arguments_json": "{}"}))
        assert out["status"] == "Failed" and "brain refused" in out["error"]

    def test_preflight_rejected_envelope_propagates_not_finished(self, monkeypatch):
        """2026-11-06 ffuf drain: a preflight arg-schema reject
        ({'status': 'Rejected', 'phase': 'preflight'}) matched neither the
        budget checks nor the Failed seam and fell through to
        {'finished': True} — every rejected chunk was consumed done-forever
        while plan indices never re-mint. The reject must map onto the
        Failed pathway with the reject text on the row."""
        import replkit.core as core
        import replkit.operator_cli as cli

        async def fake_run_tool(tool_id, arguments, manifests,
                                 session_id=None):
            return {"status": "Rejected", "phase": "preflight",
                    "tool_id": "payloads.ffuf.run_ffuf",
                    "error": "unknown argument(s): ['chunk_slice']",
                    "accepted_keys": ["url", "wordlist"], "required": []}
        monkeypatch.setattr(core, "run_tool", fake_run_tool)
        d = cli._budget_drain_dispatcher(())
        out = asyncio.run(d({"tool": "t", "arguments_json": "{}"}))
        assert out["status"] == "Failed"
        assert "chunk_slice" in out["error"]
        assert "finished" not in out      # NEVER consumed as done

    def test_preflight_rejected_inner_envelope_propagates(self, monkeypatch):
        import replkit.core as core
        import replkit.operator_cli as cli

        async def fake_run_tool(tool_id, arguments, manifests,
                                 session_id=None):
            # executor-transport wrappers nest the reject under "result"
            return {"status": "ok",
                    "result": {"status": "Rejected", "phase": "preflight",
                               "error": "bad arg", "accepted_keys": [],
                               "required": []}}
        monkeypatch.setattr(core, "run_tool", fake_run_tool)
        d = cli._budget_drain_dispatcher(())
        out = asyncio.run(d({"tool": "t", "arguments_json": "{}"}))
        assert out["status"] == "Failed" and "bad arg" in out["error"]


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


# ─── 2026-11-06: queue position + held_pending envelope honesty ──────────────

class TestQueuePosition:
    """Position must mirror the drain's EXACT launch order (priority DESC,
    requested ASC) — a position computed on any other order teaches the
    model to wait for a launch sequence that won't happen."""

    def _enq(self, engine, prio, now, tool="tests.p"):
        return engine.store.enqueue_item(
            tool=tool, arguments={}, decl=_decl(), dims=_dims(),
            reason="budget_short", agent_id="a", engagement=None,
            priority=prio, now=now)

    def test_position_matches_drain_order(self, engine):
        late_low = self._enq(engine, 0, 1030.0)
        high = self._enq(engine, 5, 1040.0)     # newer but higher prio → 1st
        early_low = self._enq(engine, 0, 1010.0)
        s = engine.store
        assert s.queued_position(high) == 1
        assert s.queued_position(early_low) == 2   # same prio, requested first
        assert s.queued_position(late_low) == 3
        out = rt.budget_queue_status()
        import re as _re
        assert f"pos=1" in out and f"pos=2" in out and f"pos=3" in out
        rows = {m.group(1): m.group(2)
                for m in _re.finditer(r"(q-[0-9a-f]+) \[queued\]( pos=\d+)?", out)}
        assert rows[high].endswith("pos=1") and rows[late_low].endswith("pos=3")

    def test_position_none_after_launch(self, engine):
        q1 = self._enq(engine, 0, 1000.0)
        q2 = self._enq(engine, 0, 1001.0)
        engine.store.bind_item(q1, "777")
        assert engine.store.queued_position(q1) is None  # launched → no queue slot
        assert engine.store.queued_position(q2) == 1     # next in line moved up
        out_all = rt.budget_queue_status(state="all")   # default shows queued only
        assert "job=777" in out_all and " pos=" not in out_all.split(q1)[1].split("\n")[0]

    def test_envelope_instruction_carries_position(self, engine, monkeypatch):
        monkeypatch.setenv("BUDGET_ENABLED", "1")
        self._enq(engine, 0, 1000.0)
        q2 = self._enq(engine, 0, 1001.0)
        env = rt._budget_envelope(
            "tests.p", status="budget_deferred", queue_id=q2,
            declared={}, arguments={})
        assert "(position 2 in queue)" in env["instruction"], env["instruction"]

    def test_envelope_no_position_when_qid_unknown(self):
        env = rt._budget_envelope(
            "tests.p", status="budget_deferred", queue_id="q-doesnotexist",
            declared={}, arguments={})
        assert "(position" not in env["instruction"]
        assert "do NOT retry" in env["instruction"]

    def test_held_pending_envelope_never_lies_about_queue(self, engine,
                                                          monkeypatch, tmp_path):
        """F-1 class regression pin: a held_pending deferral has NO queue row —
        its instruction must say NOT queued, never 'the item is queued'."""
        store = engine.store
        # session_get = estimator-backed (a gate-less tool returns None and
        # never reaches the envelope — the F-1 file's tool choice).
        r = engine.dispatch_debit(
            "auxiliaries.web_session.session_get", {"target": "10.9.9.9"},
            agent_id="seed", engagement=None, now=1000.0)
        assert r.get("committed"), r
        store.set_phase(mode="hold", host_axis="10.9.9.9")
        env = rt.ration_gate(  # sync fn (F-1 pattern); the envelope carries
            "auxiliaries.web_session.session_get", {"target": "10.9.9.9"},
            agent_id="fresh", session_id="fresh-sess", now=1001.0)
        assert env["status"] == "budget_deferred"
        assert env.get("queue_id") is None
        assert "is queued" not in env["instruction"]
        assert "NOT queued" in env["instruction"], env["instruction"]


# ─── §3.2 (2026-11-07): plan_minted mapping + chunk-keyed strictness ─────────

import json


class TestDrainPlanMintedMapping:
    def _disp(self, monkeypatch, run_tool_result):
        import replkit.core as core
        import utils.budget_drain as bd

        async def fake_run_tool(tool_id, arguments, manifests,
                                session_id=None):
            assert session_id == "ration-drain", \
                "drain lane must announce itself"
            return run_tool_result
        monkeypatch.setattr(core, "run_tool", fake_run_tool)
        return bd.drain_dispatcher(())

    def test_chunk_plan_top_level_is_plan_minted(self, monkeypatch):
        """A whole-wordlist dispatch that minted a plan must surface as
        plan_minted — NEVER as finished (the plan's queued chunks would be
        silently consumed-and-done before launching)."""
        d = self._disp(monkeypatch, {
            "status": "chunk_plan", "plan_id": "wp-1"})
        out = asyncio.run(d({"tool": "t", "arguments_json": "{}"}))
        assert out == {"plan_minted": True, "plan_id": "wp-1",
                       "phantom": False}

    def test_chunk_plan_inner_result_is_plan_minted(self, monkeypatch):
        d = self._disp(monkeypatch, {
            "status": "ok",
            "result": {"status": "chunk_plan", "plan_id": "wp-2"}})
        out = asyncio.run(d({"tool": "t", "arguments_json": "{}"}))
        assert out == {"plan_minted": True, "plan_id": "wp-2",
                       "phantom": False}

    def test_chunk_plan_keyed_item_is_phantom(self, monkeypatch):
        """§3.1 phantom mint observed from the dispatcher: the item carried
        chunk keys yet still re-minted — the envelope self-describes it."""
        d = self._disp(monkeypatch, {
            "status": "chunk_plan", "plan_id": "wp-ghost"})
        keyed = {"chunk_plan_id": "wp-real", "chunk_index": 0,
                 "chunk_offset": 0, "chunk_slice": 50,
                 "chunk_total_chunks": 2}
        out = asyncio.run(d({"tool": "t", "arguments_json":
                             json.dumps(keyed)}))
        assert out["plan_minted"] is True and out["plan_id"] == "wp-ghost"
        assert out["phantom"] is True

    def test_error_status_envelope_maps_failed(self, monkeypatch):
        """§3.2: an honest tool error (e.g. a chunk plan that no longer
        exists) used to fall through to finished; it must reach the
        engine's bounded-failure ledger instead."""
        d = self._disp(monkeypatch, {
            "job_id": None, "status": "error",
            "error": "chunk plan wp-gone no longer exists (expired)"},
            )
        out = asyncio.run(d({"tool": "t", "arguments_json": "{}"}))
        assert out["status"] == "Failed"
        assert "no longer exists" in out["error"]
        assert "finished" not in out

    def test_unrecognized_envelope_keyed_item_never_finished(self, monkeypatch):
        """§3.2 strictness: a chunk-keyed item whose envelope matches
        NOTHING must be Failed — consuming it as done settles a plan over
        work that never launched. Un-keyed rows keep the historical
        catch-all (a swallowed successful inline work would double-run)."""
        d = self._disp(monkeypatch, {"ok": True, "unparsed": True})
        keyed = {"chunk_plan_id": "wp-real", "chunk_index": 0,
                 "chunk_offset": 0, "chunk_slice": 50,
                 "chunk_total_chunks": 2}
        out = asyncio.run(d({"tool": "t", "arguments_json":
                             json.dumps(keyed)}))
        assert out["status"] == "Failed" and "§3.2" in out["error"]
        out2 = asyncio.run(d({"tool": "t", "arguments_json": "{}"}))
        assert out2 == {"finished": True}

    def test_requeued_still_wins_over_plan_id(self, monkeypatch):
        """A requeued envelope that ALSO carries a plan_id (wrapper
        re-enqueued a chunk) remains churn — never plan conversion."""
        d = self._disp(monkeypatch, {
            "status": "ok", "result": {"requeued": True,
                                       "plan_id": "wp-x"}})
        out = asyncio.run(d({"tool": "t", "arguments_json": "{}"}))
        assert out == {"requeued": True, "plan_id": "wp-x",
                       "reason": None}


class TestEnginePlanMintedBranch:
    @staticmethod
    def _plan_row(store, plan_id="wp-eng"):
        store.conn.execute(
            "INSERT INTO queue_plans (plan_id, tool, arguments_json,"
            " declared_json, dims_json, wordlist, lines, chunk_size,"
            " total_chunks, binding_dim, window, priority, agent_id,"
            " engagement, requested, expires_at, state)"
            " VALUES (?, 'payloads.ffuf.run_ffuf', '{}', '{}', '{}', '/w',"
            " 650, 600, 2, 'requests', 2, 0, 'tester', NULL, 1000.0,"
            " 99999.0, 'open')", (plan_id,))
        store.conn.commit()

    def test_keyed_item_phantom_mint_fails_item_and_plan(self, engine):
        """§3.2: a keyed dispatch that STILL minted a plan is a phantom —
        the item fails on first observation (deterministic arg-loss, no
        retry budget: retries only produce more ghosts) and the fresh plan
        is cancelled."""
        import utils.budget_drain as bd
        store = engine.store
        self._plan_row(store, "wp-ghost")
        store.enqueue_item(tool="payloads.ffuf.run_ffuf",
                           dims={"host_axis": "10.0.0.7"},
                           decl={"requests": 50, "packets": None,
                                 "auth_events": None, "bytes": 50 * 8192},
                           arguments={**_dims(), "chunk_plan_id": "wp-real",
                                      "chunk_index": 0, "chunk_offset": 0,
                                      "chunk_slice": 50,
                                      "chunk_total_chunks": 2},
                           reason="plan wp-real chunk 1/2",
                           agent_id="tester", engagement=None, now=1000.0)
        (qid,) = [i["qid"] for i in store.due_items(now=1000.0)]

        async def tick():
            return await engine.operator_tick(
                dispatch=lambda item: {"plan_minted": True,
                                       "plan_id": "wp-ghost",
                                       "phantom": True},
                now=1001.0, batch=1, sleep_fn=lambda s: None)

        out = asyncio.run(tick())
        assert [r["decision"] for r in out["results"]] == \
            ["failed_phantom_plan"]
        row = store.conn.execute(
            "SELECT * FROM queue_items WHERE qid=?", (qid,)).fetchone()
        assert row["status"] == "failed"
        assert "phantom plan" in (row["notes_json"] or "")
        plan = store.plan_get("wp-ghost")
        assert plan["state"] == "cancelled"

    def test_unkeyed_item_plan_mint_converts(self, engine):
        """§3.2: an un-keyed (whole-wordlist) item minting a plan is
        legitimate conversion — the item is consumed as done-converted and
        the plan's chunk queue carries the work."""
        store = engine.store
        self._plan_row(store, "wp-conv")
        store.enqueue_item(tool="payloads.ffuf.run_ffuf", dims=_dims(),
                           decl=_decl(requests=600, bytes=600 * 8192),
                           arguments={"url": "http://10.0.0.7/FUZZ",
                                      "wordlist": "/w"},
                           reason="whole wordlist",
                           agent_id="tester", engagement=None, now=1000.0)
        (qid,) = [i["qid"] for i in store.due_items(now=1000.0)]

        async def tick():
            return await engine.operator_tick(
                dispatch=lambda item: {"plan_minted": True,
                                       "plan_id": "wp-conv",
                                       "phantom": False},
                now=1001.0, batch=1, sleep_fn=lambda s: None)

        out = asyncio.run(tick())
        assert [r["decision"] for r in out["results"]] == \
            ["converted_to_plan"]
        row = store.conn.execute(
            "SELECT * FROM queue_items WHERE qid=?", (qid,)).fetchone()
        assert row["status"] == "cancelled"
        assert "converted to plan wp-conv" in (row["notes_json"] or "")
        assert store.plan_get("wp-conv")["state"] == "open"

    def test_tick_result_carries_advance_summary(self, engine):
        """Debt §4: the drain state/doctor need the plan-advance summary on
        the tick result, not just the lens."""
        async def tick():
            return await engine.operator_tick(
                dispatch=lambda item: {"finished": True},
                now=1001.0, batch=1, sleep_fn=lambda s: None)
        out = asyncio.run(tick())
        assert out["advance"] == {"settled": [], "failed_plans": []}
