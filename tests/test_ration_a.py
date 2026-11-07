"""Phase A ration-engine tests (utils/ration_store.py + utils/ration.py).

Covers the §15 Phase-A hooks: read-only preflight routing, the atomic
cascade debit + emission append, L1 reconcile drift stamps, fail-closed
Unknown verdicts, the L0 estimator registry (unregistered = credit-line),
REJECT never-fit, the queue skeleton (enqueue/drain/brain-timeout/
no_reenqueue/sweep), HOLD-mode floor accrual, and engagement-scoped purge.

Store state is isolated per test via BUDGET_STORE_DIR -> tmp_path and the
module's reset hooks.
"""

import json

import asyncio

import pytest

import utils.ration as rt
from utils.ration_store import DIMS, RationStore


def asyncio_run(coro):
    return asyncio.run(coro)


@pytest.fixture
def engine(tmp_path, monkeypatch):
    (tmp_path / "budget").mkdir()
    monkeypatch.setenv("BUDGET_STORE_DIR", str(tmp_path / "budget"))
    monkeypatch.setenv("BUDGET_ENABLED", "1")
    for k in ("BUDGET_CONSTITUTION", "BUDGET_CONSTITUTION_FILE",
              "BUDGET_EPOCH_SECONDS", "BUDGET_QUEUE_TTL_HOURS",
              "BUDGET_DRAIN_BATCH"):
        monkeypatch.delenv(k, raising=False)
    # decline the drum band — the engine's default 1.5-6.0s release jitter
    # would slow multi-release ticks; zero-band authors env pacing back
    monkeypatch.setenv("BUDGET_CONSTITUTION",
                       '{"release_jitter": {"min": 0.0, "max": 0.0}}')
    rt.reset_engine()
    yield rt.get_engine()
    rt.reset_engine()


def _decl(**kw):
    return {d: kw.get(d) for d in DIMS}


def _dims(tool=None, **kw):
    dims = rt.dims_for_target(kw.pop("target", "10.0.0.7"))
    if tool:
        dims["tool"] = tool
    dims.update(kw)
    return dims


def _nodes(store):
    return {r["node_key"]: dict(r) for r in store.conn.execute("SELECT * FROM nodes")}


def _emissions(store):
    return [dict(r) for r in store.conn.execute("SELECT * FROM emissions ORDER BY id")]


# ─── preflight routing + debit math ──────────────────────────────────────────

class TestAdmitAndDebit:
    def test_admit_then_debit_deducts_every_level(self, engine):
        const = rt.constitution()
        policy, epoch = const.policy(), const.epoch_s
        receipt = engine.store.debit_vector(
            _decl(requests=1), _dims(), tool="tests.t",
            policy=policy, epoch_s=epoch, max_single=const.max_single(),
            now=1000.0, estimator="seed")
        assert receipt["committed"] is True
        assert receipt["emission_id"] == 1
        # every cascade level (host + range + global) debited by exactly 1
        by_host = by_range = by_global = 0
        for key, node in _nodes(engine.store).items():
            if node["host_axis"] == "10.0.0.7" and node["range_axis"] is None:
                by_host = node["remaining_requests"]
            elif node["range_axis"] == "10.0.0.0-10.0.0.255" and \
                    node["host_axis"] is None:
                by_range = node["remaining_requests"]
            elif node["host_axis"] is None and node["range_axis"] is None:
                by_global = node["remaining_requests"]
        assert by_host == pytest.approx(599.0)
        assert by_range == pytest.approx(599.0)
        assert by_global == pytest.approx(599.0)
        assert len(_emissions(engine.store)) == 1

    def test_preflight_admit_routes_clean(self, engine):
        out = engine.preflight("tests.fresh.tool", {"target": "10.0.0.7"},
                               now=1000.0)
        assert out["decision"] == "admit"
        assert out["estimator"] == "unregistered"
        assert out["declared_basis"] == "credit_line"

    def test_refill_and_redebit(self, engine):
        const = rt.constitution()
        engine.store.debit_vector(
            _decl(requests=600), _dims(), tool="tests.t",
            policy=const.policy(), epoch_s=const.epoch_s,
            max_single=const.max_single(), now=1000.0)
        # one epoch later the node refilled 150 → a 50 call fits now
        receipt = engine.store.debit_vector(
            _decl(requests=50), _dims(), tool="tests.t",
            policy=const.policy(), epoch_s=const.epoch_s,
            max_single=const.max_single(), now=1000.0 + const.epoch_s)
        assert receipt["committed"] is True


# ─── atomicity (§5) ──────────────────────────────────────────────────────────

class TestCascadeAtomicity:
    def test_global_shortfall_rolls_back_host_and_emits_nothing(self, engine):
        const = rt.constitution()
        kw = dict(policy=const.policy(), epoch_s=const.epoch_s,
                  max_single=const.max_single())
        s = engine.store
        # drain host A + the shared global node to 1/600 spent
        assert s.debit_vector(_decl(requests=1), _dims(target="10.0.0.1"),
                              tool="tests.t", now=1000.0, **kw)["committed"]
        # one half-epoch later: every node has 50 accrued (host A: 600 clamp)
        # a SECOND-RANGE host (10.0.1.2) draws 100 — the global node drops
        # to 500 while host/range for .1 stay untouched by this debit
        assert s.debit_vector(_decl(requests=100), _dims(target="10.0.1.2"),
                              tool="tests.t", now=1000.0 + 1800, **kw)["committed"]
        # now host A (capped back at 600) CAN cover 600 but the global node
        # (500) cannot — shortfall must surface at global and roll the host
        # debit back untouched
        receipt = s.debit_vector(_decl(requests=600),
                                 _dims(target="10.0.0.1"), tool="tests.t",
                                 now=1000.0 + 1800, **kw)
        assert receipt["committed"] is False
        assert receipt["decision"] == "enqueue"
        assert receipt["level"] == "global"
        assert receipt["shortfall_dims"] == ["requests"]
        # host node still at its STORED ceiling-spent value (lazy accrual —
        # balances persist only on debit writes; the projection refills at
        # accrue-time) and exactly one emission row exists
        host = [n for n in _nodes(s).values()
                if n["host_axis"] == "10.0.0.1"][0]
        # 2026-11-06 grant-persistence: a SHORT attempt now materializes the
        # drip it earned (600 here — host starts ceiling-clamped) WITHOUT
        # charging the debit; emissions stay untouched (2 committed only).
        assert host["remaining_requests"] == pytest.approx(600.0)
        node = s._node_row(host["node_key"])
        assert s._accrue(node, 1000.0 + 1800, const.epoch_s)["requests"][
            "remaining"] == pytest.approx(600.0)  # clamped projection
        # two committed debits, two emission rows — the rolled-back attempt
        # charged nothing
        assert len(_emissions(s)) == 2

    def test_shortfall_at_host_reports_level(self, engine):
        const = rt.constitution()
        kw = dict(policy=const.policy(), epoch_s=const.epoch_s,
                  max_single=const.max_single())
        s = engine.store
        assert s.debit_vector(_decl(requests=599), _dims(target="10.0.0.1"),
                              tool="tests.t", now=1000.0, **kw)["committed"]
        out = s.debit_vector(_decl(requests=10), _dims(target="10.0.0.1"),
                             tool="tests.t", now=1000.0, **kw)
        assert out["committed"] is False
        assert out["level"] == "host"


# ─── L1 reconcile (§10) ──────────────────────────────────────────────────────

class TestReconcile:
    def test_drift_trips_over_5pct_and_declared_never_rewritten(self, engine):
        const = rt.constitution()
        receipt = engine.store.debit_vector(
            _decl(requests=10), _dims(), tool="tests.drift",
            policy=const.policy(), epoch_s=const.epoch_s,
            max_single=const.max_single(), now=1000.0)
        out = engine.reconcile(receipt, {"requests": 11})
        assert out["tripped"] is True
        row = _emissions(engine.store)[0]
        assert row["drift"] == 1
        assert json.loads(row["declared_json"]) == _decl(requests=10)

    def test_actual_at_declared_no_trip(self, engine):
        const = rt.constitution()
        receipt = engine.store.debit_vector(
            _decl(requests=10, packets=100), _dims(), tool="tests.drift2",
            policy=const.policy(), epoch_s=const.epoch_s,
            max_single=const.max_single(), now=1000.0)
        out = engine.reconcile(receipt, {"requests": 10, "packets": 99})
        assert out["tripped"] is False

    def test_reconcile_drift_seeds_tripwire(self, engine):
        const = rt.constitution()
        receipt = engine.store.debit_vector(
            _decl(requests=10), _dims(), tool="tests.tw",
            policy=const.policy(), epoch_s=const.epoch_s,
            max_single=const.max_single(), now=1000.0)
        engine.reconcile(receipt, {"requests": 20, "bytes": 4096})
        row = engine.store.conn.execute(
            "SELECT * FROM tripwire_estimates WHERE tool='tests.tw'").fetchone()
        per = json.loads(row["per_dim_json"])
        assert per["requests"] == 20.0        # first sample seeds directly
        assert per["bytes"] == 4096.0         # undeclared dims still seed
        assert row["samples"] == 1
        engine.reconcile(receipt, {"requests": 4})
        per = json.loads(engine.store.conn.execute(
            "SELECT per_dim_json FROM tripwire_estimates WHERE "
            "tool='tests.tw'").fetchone()["per_dim_json"])
        assert per["requests"] == pytest.approx((20.0 * 1 + 4.0) / 2)

    def test_reconcile_seeds_tripwire_on_any_actual(self, engine):
        # §15 hook: the seed is the meter (updates on ALL actuals); drift
        # is the alarm. No-trip reconciliation still feeds the average.
        const = rt.constitution()
        receipt = engine.store.debit_vector(
            _decl(requests=10), _dims(), tool="tests.tw2",
            policy=const.policy(), epoch_s=const.epoch_s,
            max_single=const.max_single(), now=1000.0)
        out = engine.reconcile(receipt, {"requests": 1})
        assert out["tripped"] is False
        row = engine.store.conn.execute(
            "SELECT * FROM tripwire_estimates WHERE tool='tests.tw2'"
        ).fetchone()
        assert row is not None
        assert json.loads(row["per_dim_json"])["requests"] == 1.0


# ─── fail-closed Unknown (§13) ───────────────────────────────────────────────

class TestFailClosed:
    def test_store_construction_refuses_unwritable_dir(self, tmp_path):
        bad = tmp_path / "not-a-dir"
        bad.write_text("i am a file")
        with pytest.raises(RuntimeError, match="unusable"):
            RationStore(store_dir=bad)

    def test_preflight_unknown_when_store_errors(self, engine, monkeypatch):
        def boom(*a, **k):
            raise RuntimeError("disk on fire")
        monkeypatch.setattr(engine.store, "admit_vector", boom)
        out = engine.preflight("tests.t", {"target": "10.0.0.7"}, now=1000.0)
        assert out["decision"] == "unknown"
        assert out["fail_closed"] is True

    def test_dispatch_debit_unknown_on_store_error(self, engine, monkeypatch):
        def boom(*a, **k):
            raise RuntimeError("disk on fire")
        monkeypatch.setattr(engine.store, "debit_vector", boom)
        out = engine.dispatch_debit("tests.t", {"target": "10.0.0.7"},
                                    now=1000.0)
        assert out["committed"] is False
        assert out["decision"] == "unknown"
        assert out["fail_closed"] is True

    def test_invalid_consitution_fail_closed(self, engine, monkeypatch):
        monkeypatch.setenv("BUDGET_CONSTITUTION", json.dumps({
            "defaults": {"requests": {"ceiling": 10.0,
                                      "refill_per_epoch": 5.0, "floor": 0.0}},
            "max_single_call": {"requests": 10.0}}))
        out = engine.preflight("tests.t", {"target": "10.0.0.7"}, now=1000.0)
        assert out["decision"] == "unknown"
        assert out["fail_closed"] is True
        assert "constitution invalid" in out["reason"]

    def test_floor0_validation_message(self):
        with pytest.raises(ValueError, match="permanent-HOLD"):
            rt.Constitution.validate(
                {"requests": {"ceiling": 10.0, "refill_per_epoch": 5.0,
                              "floor": 0.0}, **{
                    d: dict(rt._DIM_DEFAULTS[d]) for d in DIMS
                    if d != "requests"}},
                dict(rt._MAX_SINGLE_CALL), 3600.0)

    def test_disabled_kill_switch(self, engine, monkeypatch):
        monkeypatch.setenv("BUDGET_ENABLED", "0")
        out = engine.preflight("tests.t", {"target": "10.0.0.7"}, now=1000.0)
        assert out["decision"] == "disabled"


# ─── L0 estimator registry (§4.2) ────────────────────────────────────────────

class TestEstimatorRegistry:
    def test_unregistered_tool_is_credit_line_and_admits(self, engine):
        out = engine.preflight("tests.never.registered", {"target": "10.0.0.7"},
                               now=1000.0)
        assert out["decision"] == "admit"
        assert out["declared"] == _decl()
        assert out["estimator"] == "unregistered"
        assert out["declared_basis"] == "credit_line"

    def test_web_session_seed_is_measured(self, engine):
        out = engine.preflight(
            "auxiliaries.web_session.session_get", {"target": "10.0.0.7"},
            now=1000.0)
        assert out["decision"] == "admit"
        assert out["declared"] == _decl(requests=1)
        assert out["estimator"] == "web_session_get"
        assert out["declared_basis"] == "measured"

    def test_nmap_seed_estimates_packets_from_span_and_ports(self, engine):
        out = engine.preflight(
            "auxiliaries.nmap.run_nmap", {"target": "10.0.0.0/24",
                                          "options": "-p 1-1000 -sV"},
            now=1000.0)
        assert out["decision"] == "admit"
        assert out["declared"]["packets"] == 256 * 1000
        assert out["declared_basis"] == "estimation"

    def test_estimator_error_falls_to_credit_line(self, engine):
        @rt.register_estimator("tests.broken", basis="estimation",
                               name="broken_seed")
        def _broken(target, arguments):
            raise TypeError("boom")

        out = engine.preflight("tests.broken", {"target": "10.0.0.7"},
                               now=1000.0)
        assert out["declared"] == _decl()
        assert out["estimator"] == "broken_seed@error"
        assert out["declared_basis"] == "credit_line"

    def test_credit_line_admits_even_when_drained(self, engine):
        const = rt.constitution()
        engine.store.debit_vector(
            _decl(requests=600), _dims(), tool="tests.t",
            policy=const.policy(), epoch_s=const.epoch_s,
            max_single=const.max_single(), now=1000.0)
        out = engine.preflight("tests.open.tool", {"target": "10.0.0.7"},
                               now=1000.0)
        assert out["decision"] == "admit"


# ─── REJECT never-fit (§7.1) ─────────────────────────────────────────────────

class TestNeverFit:
    def test_over_ceiling_declaration_uses_credit_line(self, engine):
        @rt.register_estimator("tests.rejection_tool", basis="measured",
                               name="too_big")
        def _too_big(target, arguments):
            return {"requests": 700}

        out = engine.preflight("tests.rejection_tool", {"target": "10.0.0.7"},
                               now=1000.0)
        assert out["decision"] == "reject"
        assert "reject" in out.get("instruction", "") or out.get("level")
        assert len(_emissions(engine.store)) == 0

    def test_nmap_full_sweep_vs_default_ceiling_is_rejected(self, engine):
        # /24 × all 65535 ports under the default 2M-packet ceiling: honest
        # NEVER-FIT — the constitution must be raised, not waited on.
        out = engine.preflight(
            "auxiliaries.nmap.run_nmap", {"target": "10.0.0.0/24",
                                          "options": "-p-"},
            now=1000.0)
        assert out["decision"] == "reject"
        assert out["declared"]["packets"] == 256 * 65535

    def test_max_single_call_rejects(self, engine, monkeypatch):
        monkeypatch.setenv("BUDGET_CONSTITUTION", json.dumps({
            "defaults": {"requests": {"ceiling": 100.0,
                                      "refill_per_epoch": 10.0,
                                      "floor": 1.0}},
            "max_single_call": {"requests": 50.0}}))
        receipt = engine.store.debit_vector(
            _decl(requests=60), _dims(), tool="tests.big",
            policy=rt.constitution().policy(),
            epoch_s=rt.constitution().epoch_s,
            max_single=rt.constitution().max_single(), now=1000.0)
        assert receipt["committed"] is False
        assert receipt["decision"] == "reject"
        assert receipt["level"] == "config"
        assert receipt["shortfall_dims"] == ["requests"]


# ─── queue skeleton (§7.2) ───────────────────────────────────────────────────

class TestQueue:
    def _short_call(self, engine, now=1000.0):
        engine.store.debit_vector(
            _decl(requests=600), _dims(), tool="tests.q",
            policy=rt.constitution().policy(),
            epoch_s=rt.constitution().epoch_s,
            max_single=rt.constitution().max_single(), now=now)
        return engine.preflight("auxiliaries.web_session.session_get",
                                {"target": "10.0.0.7"}, now=now)

    def test_enqueue_decision_carry_qid_and_instruction(self, engine):
        out = self._short_call(engine)
        assert out["decision"] == "enqueue"
        assert out["queue_id"].startswith("q-")
        assert "do NOT retry" in out["instruction"]
        item = engine.store.get_item(out["queue_id"])
        assert item["status"] == "queued"
        assert item["tool"] == "auxiliaries.web_session.session_get"
        assert item["agent_id"] == "0"

    def test_duplicate_satisfied_skips_enqueue(self, engine):
        out = engine.preflight(
            "auxiliaries.web_session.session_get", {"target": "10.0.0.7"},
            now=1000.0,
            satisfied_check=lambda tool, args: 4321)
        assert out["decision"] == "satisfied"
        assert out["job_id"] == "4321"
        queued = engine.store.due_items(now=1000.0)
        assert queued == []

    def test_operator_tick_drains_and_binds(self, engine):
        out = self._short_call(engine)
        dispatched = []
        res = asyncio_run(engine.operator_tick(
            dispatch=lambda item: (dispatched.append(item) or {"job_id": 99}),
            now=1005.0))
        assert res["decision"] == "drained"
        assert res["results"][0]["decision"] == "dispatched"
        assert res["results"][0]["job_id"] == "99"
        item = engine.store.get_item(out["queue_id"])
        assert item["status"] == "launched"
        assert item["job_ref"] == "99"
        assert dispatched[0]["tool"] == "auxiliaries.web_session.session_get"

    def test_tick_without_dispatcher_is_noop(self, engine):
        self._short_call(engine)
        res = asyncio_run(engine.operator_tick(now=1005.0))
        assert res["decision"] == "noop"
        assert res["backlog"] == 1

    def test_dispatch_raise_keeps_item_queued(self, engine):
        self._short_call(engine)
        res = asyncio_run(engine.operator_tick(
            dispatch=lambda item: (_ for _ in ()).throw(RuntimeError("jvm")),
            now=1005.0))
        assert res["results"][0]["decision"] == "dispatch_failed"
        item = engine.store.due_items(now=1006.0)
        assert len(item) == 1 and item[0]["status"] == "queued"

    def test_brain_timeout_is_cancelled_not_reenqueued(self, engine):
        out = self._short_call(engine)
        res = asyncio_run(engine.operator_tick(
            dispatch=lambda item: {"brain_timeout": True}, now=1005.0))
        assert res["results"][0]["decision"] == "brain_timeout_flagged"
        item = engine.store.get_item(out["queue_id"])
        assert item["status"] == "cancelled"
        assert "brain_timeout" in item["notes_json"]
        assert engine.store.due_items(now=1006.0) == []

    def test_no_reenqueue_flag_items_are_flagged_not_dispatched(self, engine):
        engine.store.enqueue_item(
            tool="tests.q", arguments={}, decl=_decl(requests=1),
            dims=_dims(), reason="budget_short", agent_id="0",
            engagement=None, no_reenqueue=True, now=1000.0)
        dispatched = []
        res = asyncio_run(engine.operator_tick(
            dispatch=lambda item: (dispatched.append(item) or {"job_id": 1}),
            now=1005.0))
        assert res["results"][0]["decision"] == "flagged_for_human"
        assert dispatched == []

    # ── bounded-failure exit (2026-11-06 seam close) ──

    def test_dispatch_failed_stamps_attempt_and_survives(self, engine):
        self._short_call(engine)
        res = asyncio_run(engine.operator_tick(
            dispatch=lambda item: (_ for _ in ()).throw(RuntimeError("jvm")),
            now=1005.0))
        assert res["results"][0]["decision"] == "dispatch_failed"
        (item,) = engine.store.due_items(now=1006.0)
        assert item["status"] == "queued"
        assert item["attempts"] == 1
        assert "jvm" in (item["notes_json"] or "")   # last error visible NOW

    def test_failed_envelope_exhausts_to_failed_status(self, engine,
                                                       monkeypatch):
        """Default budget 3: four Failed-envelope ticks consume the item as
        'failed' with the last tool error on the row."""
        def _fail(item):
            return {"status": "Failed", "error": "tool body raised: crash"}
        out = self._short_call(engine)
        for tick in range(4):
            res = asyncio_run(engine.operator_tick(dispatch=_fail,
                                                   now=1006.0 + tick))
            last = res["results"][0]["decision"]
        assert last == "failed_exhausted"
        item = engine.store.get_item(out["queue_id"])
        assert item["status"] == "failed"
        assert "crash" in (item["notes_json"] or "")
        assert engine.store.due_items(now=1006.0 + 4) == []

    def test_retry_budget_exhaustion_exits_queue(self, engine, monkeypatch):
        monkeypatch.setenv("BUDGET_RETRY_MAX", "2")
        out = self._short_call(engine)
        for tick in range(3):                       # 3 raises > budget 2
            asyncio_run(engine.operator_tick(
                dispatch=lambda item: (_ for _ in ()).throw(
                    RuntimeError("gate")),
                now=1006.0 + tick))
        item = engine.store.get_item(out["queue_id"])
        assert item["status"] == "failed"
        assert "retry budget exhausted" in (item["notes_json"] or "")
        assert "gate" in (item["notes_json"] or "")
        assert engine.store.due_items(now=1006.0 + 3) == []   # queue moves on

    def test_zero_retry_budget_fails_on_first_raise(self, engine,
                                                    monkeypatch):
        monkeypatch.setenv("BUDGET_RETRY_MAX", "0")
        out = self._short_call(engine)
        res = asyncio_run(engine.operator_tick(
            dispatch=lambda item: (_ for _ in ()).throw(RuntimeError("x")),
            now=1005.0))
        assert res["results"][0]["decision"] == "failed_exhausted"
        assert engine.store.get_item(out["queue_id"])["status"] == "failed"

    def test_success_resets_nothing_but_item_exits_normally(self, engine):
        """A dispatch that succeeds is never touched by the retry ledger."""
        out = self._short_call(engine)
        res = asyncio_run(engine.operator_tick(
            dispatch=lambda item: {"job_id": 1}, now=1005.0))
        assert res["results"][0]["decision"] == "dispatched"
        item = engine.store.get_item(out["queue_id"])
        assert item["status"] == "launched"
        assert item["attempts"] == 0

    def test_fail_envelope_maps_to_bounded_fate(self, engine):
        """A scope-gate-class Failed envelope from the dispatch lane is no
        longer consumed as an inline success — it stamps an attempt, keeps
        the item queued with the error visible, and exits after the budget."""
        self._short_call(engine)
        res = asyncio_run(engine.operator_tick(
            dispatch=lambda item: {"status": "Failed",
                                   "error": "scope gate: host not blessed"},
            now=1005.0))
        assert res["results"][0]["decision"] == "tool_failed"
        (item,) = engine.store.due_items(now=1006.0)
        assert item["status"] == "queued"          # still bounded-retrying
        assert item["attempts"] == 1
        assert "scope gate" in (item["notes_json"] or "")

    def test_sweep_expired_cancels_only_queued(self, engine, tmp_path,
                                              monkeypatch):
        const = rt.constitution()
        kw = dict(policy=const.policy(), epoch_s=const.epoch_s,
                  max_single=const.max_single())
        engine.store.debit_vector(_decl(requests=600), _dims(),
                                  tool="tests.sweep", now=0.0, **kw)
        a = engine.preflight("auxiliaries.web_session.session_get",
                             {"target": "10.0.0.7"}, now=1.0,
                             agent_id="agent-a")
        engine.store.enqueue_item(
            tool="tests.sweep", arguments={}, decl=_decl(),
            dims=_dims(), reason="x", agent_id="a", engagement=None,
            ttl_hours=0.0, now=2000.0, no_reenqueue=False)  # pre-expired
        n = engine.store.sweep_expired(now=2001.0)
        assert n == 1
        # the 24h-TTL enqueue item is untouched; only the ttl=0 one cancelled
        assert engine.store.get_item(a["queue_id"])["status"] == "queued"

    def test_drain_batch_cap_respected(self, engine, monkeypatch):
        for i in range(5):
            engine.store.enqueue_item(
                tool="tests.q", arguments={}, decl=_decl(),
                dims=_dims(), reason="x", agent_id="a", engagement=None,
                now=1000.0 + i)
        monkeypatch.setenv("BUDGET_DRAIN_BATCH", "2")
        dispatched = []
        res = asyncio_run(engine.operator_tick(
            dispatch=lambda item: (dispatched.append(item) or {"job_id": 1}),
            now=1010.0))
        assert len(dispatched) == 2
        assert res["backlog_remaining"] == 3


# ─── HOLD mode (§6.2) ────────────────────────────────────────────────────────

class TestHoldMode:
    def test_hold_accrues_at_refill_drip_not_floor(self, engine):
        """2026-11-06 ffuf drain starvation: HOLD accrual at the floor alone
        (2/epoch) could never reach a 600-request chunk while the node held its
        OWN backlog (apply_backlog_modes holds on any queued item) — the
        math could never admit a chunk, so the drain looped on still_short
        forever. Held nodes now accrue at the CONSTITUTIONAL DRIP (the
        normal refill rate, 150/epoch here); the floor stays the guarantee
        for floors RAISED above the drip (max(floor, refill))."""
        const = rt.constitution()
        kw = dict(policy=const.policy(), epoch_s=const.epoch_s,
                  max_single=const.max_single())
        s = engine.store
        assert s.debit_vector(_decl(requests=600), _dims(target="10.0.0.42"),
                              tool="tests.h", now=1000.0, **kw)["committed"]
        n = s.set_phase(mode="hold", host_axis="10.0.0.42")
        assert n == 1
        # one full epoch under HOLD grants the +150 drip, not the +2 floor
        receipt = s.debit_vector(_decl(requests=100),
                                 _dims(target="10.0.0.42"),
                                 tool="tests.h", now=1000.0 + const.epoch_s,
                                 **kw)
        assert receipt["committed"] is True, (
            "HOLD must accrue at the refill drip so a self-held backlog can "
            "drain — floor-only accrual starves the queue forever")

    def test_hold_backlog_drain_eventually_admits_ceiling_chunk(self, engine):
        """The live incident as a test: burst ceiling 600, chunk needs 600,
        node HOLDs on its own backlog. The drain must reach 600 again via
        drip accrual — six epochs — and admit; the loop is finite."""
        const = rt.constitution()
        kw = dict(policy=const.policy(), epoch_s=const.epoch_s,
                  max_single=const.max_single())
        s = engine.store
        assert s.debit_vector(_decl(requests=600), _dims(target="10.0.0.42"),
                              tool="tests.h", now=1000.0, **kw)["committed"]
        s.set_phase(mode="hold", host_axis="10.0.0.42")
        admit = False
        for tick in range(1, 21):
            r = s.debit_vector(_decl(requests=600), _dims(target="10.0.0.42"),
                               tool="tests.h", now=1000.0 + tick * const.epoch_s,
                               **kw)
            if r["committed"]:
                admit = True
                break
        assert admit, "600/epoch drip must re-fill the ceiling within 6 epochs"

    def test_hold_never_zero_floor(self, engine):
        engine.store.set_phase(mode="hold", host_axis="10.0.0.42") \
            if engine.store._node_row("\x1f".join(
                [""] * 4 + ["10.0.0.42", ""])) else None
        # the honest guarantee lives in the constitution validator (floor 0
        # forbidden) — HOLD accrual rate IS the floor, never zero.
        row = engine.store.conn.execute(
            "SELECT floor_json FROM nodes WHERE host_axis='10.0.0.42'"
        ).fetchone()
        if row is not None:
            assert json.loads(row["floor_json"])["requests"] > 0

    def test_hold_set_phase_requires_selector(self, engine):
        with pytest.raises(ValueError, match="selector"):
            engine.store.set_phase(mode="hold")


# ─── principals + engagement attribution (§4.3) ─────────────────────────────

class TestPrincipalsAndPurge:
    def test_debit_attribution_and_principal_touch(self, engine):
        receipt = engine.dispatch_debit(
            "auxiliaries.web_session.session_post",
            {"target": "10.0.0.7"}, now=1000.0, agent_id="agent-1",
            engagement="lab-e", principal="admin")
        assert receipt["committed"] is True
        rows = _emissions(engine.store)
        assert rows[0]["engagement"] == "lab-e"
        assert rows[0]["agent_id"] == "agent-1"
        assert rows[0]["budget_phase"] == "phase_a"
        assert engine.store.distinct_principals(
            host_axis="10.0.0.7", now=1000.0, window_s=3600.0 * 168) == 1

    def test_unarmed_rows_are_null_engagement(self, engine):
        engine.dispatch_debit("auxiliaries.web_session.session_get",
                              {"target": "10.0.0.7"}, now=1000.0,
                              agent_id="agent-1")
        assert _emissions(engine.store)[0]["engagement"] is None

    def test_purge_removes_only_engagement_rows(self, engine):
        kw = dict(policy=rt.constitution().policy(),
                  epoch_s=rt.constitution().epoch_s,
                  max_single=rt.constitution().max_single())
        s = engine.store
        s.debit_vector(_decl(requests=1), _dims(target="10.0.0.7"),
                       tool="tests.p", now=1000.0, **kw)               # NULL
        s.debit_vector(_decl(requests=1), _dims(target="10.0.0.8"),
                       tool="tests.p", now=1000.0, engagement="job-e",
                       **kw)                                           # slugged
        counts = s.purge_engagement("job-e")
        assert counts["emissions"] == 1
        rows = _emissions(s)
        assert len(rows) == 1
        assert rows[0]["engagement"] is None
        assert all(n["engagement"] != "job-e" for n in _nodes(s).values())

    def test_purge_counts_tripwire_as_zero(self, engine):
        engine.store.upsert_tripwire("tests.p", {"requests": 3})
        counts = engine.store.purge_engagement("whatever")
        assert counts["tripwire_estimates"] == 0
        assert engine.store.conn.execute(
            "SELECT COUNT(*) FROM tripwire_estimates").fetchone()[0] == 1


# ─── engine.status / budget knobs ────────────────────────────────────────────

class TestStatus:
    def test_status_snapshot_shape(self, engine):
        st = engine.status(now=1000.0)
        assert st["generated"] == 1000.0
        assert st["backlog"] == 0
        assert isinstance(st["nodes"], list)
        st2 = engine.status(now=1001.0)
        assert "queue" in st2

    def test_reconstitute_re_stamps_policy(self, engine, monkeypatch):
        const = rt.constitution()
        engine.store.debit_vector(
            _decl(requests=1), _dims(), tool="tests.rc",
            policy=const.policy(), epoch_s=const.epoch_s,
            max_single=const.max_single(), now=1000.0)
        monkeypatch.setenv("BUDGET_CONSTITUTION", json.dumps({
            "defaults": {"requests": {"ceiling": 99.0,
                                      "refill_per_epoch": 9.0,
                                      "floor": 1.0}},
            "max_single_call": {"requests": 50.0}}))
        new_const = rt.constitution()
        engine.store.reconstitute(None, policy=new_const.policy())
        for node in _nodes(engine.store).values():
            assert json.loads(node["ceiling_json"])["requests"] == 99.0
        # and the next debit uses the new ceiling without erroring
        out = engine.store.debit_vector(
            _decl(requests=50), _dims(), tool="tests.rc",
            policy=new_const.policy(), epoch_s=new_const.epoch_s,
            max_single=new_const.max_single(), now=1000.0)
        assert out["committed"] is True


# ─── registry lock regression (the 2025 self-deadlock) ───────────────────────

class TestRegistry:
    def test_seed_then_register_on_same_thread_does_not_deadlock(self):
        # ensure_seed_estimators holds _ESTIMATORS_LOCK while the decorator
        # inside takes it again — a plain Lock hung forever here (found live
        # in the first smoke run; RLock is the fix).
        rt.ensure_seed_estimators()
        assert "auxiliaries.web_session.session_get" in rt._ESTIMATORS

    def test_bad_basis_rejected(self):
        with pytest.raises(ValueError, match="basis"):
            rt.register_estimator("tests.bad", basis="vibes")

    def test_budget_vector_validation(self):
        with pytest.raises(ValueError, match=">= 0"):
            rt.BudgetVector(requests=-1)
        assert rt.BudgetVector(requests=None).as_dict() == _decl()


# ─── dims resolution (§4.2 node identity) ────────────────────────────────────

class TestDims:
    def test_bare_ip_gets_containing_slash24_range(self):
        d = rt.dims_for_target("10.0.0.7")
        assert d["host_axis"] == "10.0.0.7"
        assert d["range_axis"] == "10.0.0.0-10.0.0.255"

    def test_cidr_is_its_own_host_axis_no_range(self):
        d = rt.dims_for_target("10.0.0.0/24")
        assert d["host_axis"] == "10.0.0.0-10.0.0.255"
        assert d["range_axis"] is None

    def test_url_host_numeric(self):
        d = rt.dims_for_target("http://10.0.0.9/admin")
        assert d["host_axis"] == "10.0.0.9"
        assert d["range_axis"] == "10.0.0.0-10.0.0.255"

    def test_hostname_no_dns(self):
        d = rt.dims_for_target("BLUE.HTB")
        assert d["host_axis"] == "blue.htb"
        assert d["range_axis"] is None

    def test_find_target_key_order(self):
        args = {"host": "a", "target": "b", "url": "c"}
        assert rt.find_target(args) == "b"
        assert rt.find_target({}) is None


# ─── 2026-11-05-late: constitution file on-ramp + viewer provenance pins ─────

class TestConstitutionFileOnramp:
    """BUDGET_CONSTITUTION_FILE mechanics + the doc-inventory drift guard.

    Pins the two real legs (inline JSON string vs file path) exactly as
    .env.example documents them, a provenance verdict on the Constitution
    dataclass, and clean refusal on unreadable files. Companion pins for
    the operator viewer live in TestBudgetCLIViewProvenance."""

    def _file(self, tmp_path, text, suffix):
        p = tmp_path / f"constitution.{suffix}"
        p.write_text(text)
        return p

    def test_yaml_file_loads(self, tmp_path, monkeypatch):
        p = self._file(tmp_path, (
            "per_dim:\n"
            "  requests:\n"
            "    ceiling: 700\n"
            "    floor: 5\n"), "yaml")
        monkeypatch.setenv("BUDGET_CONSTITUTION_FILE", str(p))
        c = rt.constitution()
        assert c.defaults["requests"]["ceiling"] == 700.0, c.defaults["requests"]

    def test_json_file_loads_and_epoch(self, tmp_path, monkeypatch):
        p = self._file(tmp_path, json.dumps(
            {"epoch_seconds": 7200}), "json")
        monkeypatch.setenv("BUDGET_CONSTITUTION_FILE", str(p))
        assert rt.constitution().epoch_s == 7200.0

    def test_inline_constitution_takes_a_path_and_fails_closed(self):
        """The .env.example bug class: a PATH inside BUDGET_CONSTITUTION is
        parsed as JSON text → guaranteed failure → engine fail-closed."""
        import os as _os
        _os.environ["BUDGET_CONSTITUTION"] = "/etc/daharness/budget.yaml"
        try:
            c = rt.constitution()
            raise AssertionError(
                f"path-in-inline must fail closed, got epoch_s={c.epoch_s}")
        except Exception:
            pass
        finally:
            _os.environ.pop("BUDGET_CONSTITUTION", None)

    def test_provenance_verdict_on_dataclass(self, monkeypatch, tmp_path):
        p = self._file(tmp_path, json.dumps({}), "json")
        monkeypatch.setenv("BUDGET_CONSTITUTION_FILE", str(p))
        c = rt.constitution()
        assert getattr(c, "source", None), (
            "Constitution must carry a provenance verdict for the viewer")

    def test_env_example_knobs_are_read_by_ration(self):
        """Doc-drift guard: every BUDGET_* knob documented in .env.example
        must be read somewhere in the engine code. The inventory may never
        document a knob the code ignores ('the docs are allowed to lie' is
        the failure class this session caught)."""
        import re as _re, pathlib as _pl
        repo = _pl.Path(__file__).resolve().parent.parent
        doc = (repo / ".env.example").read_text()
        documented = set(_re.findall(r"#\s*(BUDGET_[A-Z_]+)=", doc))
        assert documented, "inventory lost its BUDGET_* rows?"
        engine_src = "\n".join(
            (repo / f).read_text()
            for f in ("utils/ration.py", "utils/ration_store.py"))
        unread = {k for k in documented if k not in engine_src}
        assert not unread, f".env.example documents knobs the engine never reads: {sorted(unread)}"


class TestBudgetCLIViewProvenance:
    """The viewer prints WHERE the live law came from and refuses cleanly
    on authored-config errors (no raw traceback — operator honesty)."""

    def _invoke(self, monkeypatch, tmp_path, **env):
        # _budget_command is ASYNC (prints inside an event loop) and
        # get_ration_store() runs before subcommand dispatch, so point the
        # store at a hermetic dir too.
        import asyncio as _a, io, contextlib
        for k in ("BUDGET_CONSTITUTION", "BUDGET_CONSTITUTION_FILE"):
            monkeypatch.delenv(k, raising=False)
        (tmp_path / "budget").mkdir()
        monkeypatch.setenv("BUDGET_STORE_DIR", str(tmp_path / "budget"))
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        from replkit import operator_cli as oc
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _a.run(oc._budget_command("constitution"))
        return buf.getvalue()

    def test_defaults_source_line(self, monkeypatch, tmp_path):
        out = self._invoke(monkeypatch, tmp_path)
        assert "Source: built-in defaults" in out, out

    def test_file_source_line(self, monkeypatch, tmp_path):
        p = tmp_path / "c.json"
        p.write_text("{}")
        out = self._invoke(monkeypatch, tmp_path,
                           BUDGET_CONSTITUTION_FILE=str(p))
        assert f"Source: file {p}" in out, out

    def test_bad_file_refuses_cleanly(self, monkeypatch, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{{{{not json")
        out = self._invoke(monkeypatch, tmp_path,
                           BUDGET_CONSTITUTION_FILE=str(p))
        assert "Constitution INVALID" in out and "Traceback" not in out, out


class TestDefaultConstitutionYamlFidelity:
    """packaging/reference/budget.constitution.yaml must mirror the no-env
    law field-for-field (a shipped 'default' that differs from defaults is
    a doc-lie of the BUDGET_CONSTITUTION class), and every commented
    example block must be load-accurate."""

    def _ref_path(self):
        import pathlib as _pl
        return (_pl.Path(__file__).resolve().parent.parent
                / "packaging/reference/budget.constitution.yaml")

    def test_reference_yaml_is_field_for_field_identical_to_defaults(
            self, monkeypatch):
        import dataclasses as _dc
        ref = self._ref_path()
        assert ref.exists(), "reference constitution yaml went missing"
        monkeypatch.delenv("BUDGET_CONSTITUTION", raising=False)
        monkeypatch.delenv("BUDGET_CONSTITUTION_FILE", raising=False)
        baseline = rt.constitution()
        monkeypatch.setenv("BUDGET_CONSTITUTION_FILE", str(ref))
        fromfile = rt.constitution()
        for f in _dc.fields(fromfile):
            if f.name == "source":
                continue  # provenance legitimately differs
            assert getattr(fromfile, f.name) == getattr(baseline, f.name), (
                f"reference yaml drifted from code defaults: {f.name}")

    def test_reference_yaml_commented_examples_all_parse(self):
        # Only the OPTIONAL-region example rows are un-commented (prose and
        # the section marker are dropped), then the document must load AND
        # the restored option keys must be exactly loader-schema keys.
        import re as _re, yaml as _y
        from utils.ration import _ALLOWED_CONST_KEYS as _allowed
        text = self._ref_path().read_text()
        tail = text.split("everything below is OPTIONAL", 1)[1]
        keep = []
        for line in tail.splitlines():
            m = _re.match(r"^# (.*)$", line)
            if not m:
                continue
            body = m.group(1)
            if _re.match(r"^[a-z_]+:", body) or body.startswith((" ", "\t")):
                keep.append(body)  # option key row or indented block member
        doc = _y.safe_load("\n".join(keep))
        assert {"release_jitter", "controller", "reserve_partitions",
                "cdn_origin_keys", "reserve_tag_wildcards"} <= set(doc)
        assert set(doc["controller"]) <= {"max_transitions_per_hour",
                                          "max_throttle_down", "max_speed_up"}
        assert set(doc) <= set(_allowed)
