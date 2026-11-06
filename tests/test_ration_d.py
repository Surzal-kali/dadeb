"""Phase D ration-engine tests: dispatch-chokepoint gate + discharge (§3),
reserve tokens (§9), credit-line draw lifetime (§7.1: poll reconciliation +
sweep backstop), posture dwell (§11 seam), and drain-lane ration-awareness
(BudgetStillShort / BudgetRefused at operator_tick)."""

import asyncio
import json
import time

import pytest

import utils.ration as rt
from utils.ration_store import DIMS


def asyncio_run(coro):
    return asyncio.run(coro)


@pytest.fixture
def engine(tmp_path, monkeypatch):
    (tmp_path / "budget").mkdir()
    monkeypatch.setenv("BUDGET_STORE_DIR", str(tmp_path / "budget"))
    monkeypatch.setenv("BUDGET_ENABLED", "1")
    monkeypatch.setenv("BUDGET_DWELL_CAP_S", "0.2")
    for k in ("BUDGET_CONSTITUTION", "BUDGET_CONSTITUTION_FILE",
              "BUDGET_EPOCH_SECONDS", "BUDGET_QUEUE_TTL_HOURS",
              "BUDGET_DRAIN_BATCH", "BUDGET_TRIPWIRE_WINDOW_S",
              "BUDGET_DRAW_TTL_HOURS"):
        monkeypatch.delenv(k, raising=False)
    rt.reset_engine()
    yield rt.get_engine()
    rt.reset_engine()


@pytest.fixture
def store(engine):
    return engine.store


def _decl(**kw):
    return {d: kw.get(d) for d in DIMS}


def _dims(**kw):
    dims = rt.dims_for_target(kw.pop("target", "10.0.0.7"))
    dims.update(kw)
    return dims


def _kw(engine):
    const = rt.constitution()
    return dict(policy=const.policy(), epoch_s=const.epoch_s,
                max_single=const.max_single())


def _mint(store, **kw):
    """Released reserve token (released by default — frozen reserves opt in
    explicitly with released=False)."""
    dims = {"entry_partition": None, "exit_id": None, "range_axis": None,
            "host_axis": None, "principal": None}
    dims.update(kw.pop("dims", {}))
    released = kw.pop("released", True)
    kw.setdefault("now", 1000.0)
    kw.setdefault("partition", "web")
    kw.setdefault("max_vector", {"requests": 100.0})
    out = store.mint_reserve(dims=dims, **kw)
    if released:
        store.release_reserve(out["token_id"])
    return out


def _drain_host(store, target="10.0.0.7", amount=600.0, now=1000.0):
    """Exhaust the host AND its range AND the engagement (global) node —
    all three cascade levels sit at 0 remaining after this (default ceiling
    600/epoch, no refill accrued at a single timestamp)."""
    const = rt.constitution()
    receipt = store.debit_vector(
        _decl(requests=amount), _dims(target=target), tool="tests.drainer",
        policy=const.policy(), epoch_s=const.epoch_s,
        max_single=const.max_single(), now=now)
    assert receipt.get("committed") is True, receipt


def _reserve_rows(store, token_id=None):
    rows = {r["token_id"]: r for r in store.list_reserves()}
    return rows.get(token_id) if token_id else rows


class TestReserves:
    def test_mint_list_release_lifecycle(self, store):
        tok = store.mint_reserve(partition="web", dims=_dims(),
                                 max_vector={"requests": 50.0}, now=1000.0)
        assert tok["frozen"] is True
        assert tok["token_id"].startswith("resv:")
        rows = store.list_reserves()
        assert len(rows) == 1 and rows[0]["released"] is None
        rel = store.release_reserve(tok["token_id"])
        assert rel["released"] is not None
        assert store.release_reserve("resv:does-not-exist") is None
        # freeze again suspends consumption eligibility
        store.release_reserve(tok["token_id"], release=False)
        assert store.list_reserves()[0]["released"] is None

    def test_mint_zero_vector_refused(self, store):
        with pytest.raises(ValueError, match="covers nothing"):
            store.mint_reserve(partition="web", dims=_dims(),
                               max_vector={"requests": 0.0}, now=1000.0)
        with pytest.raises(ValueError, match="covers nothing"):
            store.mint_reserve(partition="web",
                               dims=_dims(), max_vector={}, now=1000.0)

    def test_frozen_reserve_never_covers(self, engine, store):
        _drain_host(store)
        tok = _mint(store, released=False, max_vector={"requests": 50.0})
        const = rt.constitution()
        receipt = store.debit_vector(
            _decl(requests=10), _dims(), tool="tests.t",
            policy=const.policy(), epoch_s=const.epoch_s,
            max_single=const.max_single(), now=1000.0)
        assert receipt["committed"] is False
        assert receipt["level"] == "host"
        assert receipt["shortfall_dims"] == ["requests"]
        assert _reserve_rows(store, tok["token_id"])["remaining"][
            "requests"] == pytest.approx(50.0)   # untouched

    def test_released_reserve_covers_and_is_consumed(self, engine, store):
        _drain_host(store)
        tok = _mint(store, max_vector={"requests": 100.0})
        const = rt.constitution()
        # deficit accumulates over EVERY cascade level: host+range+global
        # each paid 0 of the declared 10 → total deficit 30
        receipt = store.debit_vector(
            _decl(requests=10), _dims(), tool="tests.t",
            policy=const.policy(), epoch_s=const.epoch_s,
            max_single=const.max_single(), now=1000.0)
        assert receipt["committed"] is True
        assert receipt["decision"] == "debit"
        assert _reserve_rows(store, tok["token_id"])["remaining"][
            "requests"] == pytest.approx(70.0)

    def test_reserve_one_off_consumption_then_rollback(self, engine, store):
        _drain_host(store)
        tok = _mint(store, max_vector={"requests": 35.0})
        const = rt.constitution()
        kw = dict(policy=const.policy(), epoch_s=const.epoch_s,
                  max_single=const.max_single())
        assert store.debit_vector(_decl(requests=10), _dims(), tool="t",
                                  now=1000.0, **kw)["committed"]
        assert _reserve_rows(store, tok["token_id"])["remaining"][
            "requests"] == pytest.approx(5.0)
        # deficit 30 > 5 remaining — no cover, nothing written, token intact
        out = store.debit_vector(_decl(requests=10), _dims(), tool="t",
                                 now=1000.0, **kw)
        assert out["committed"] is False
        assert _reserve_rows(store, tok["token_id"])["remaining"][
            "requests"] == pytest.approx(5.0)

    def test_total_deficit_across_levels_covers_or_rolls_back(self, engine,
                                                              store):
        # the total deficit spans host + range + global (10 each) — cover
        # must absorb ALL of it; anything less rolls the whole debit back
        _drain_host(store)
        const = rt.constitution()
        kw = dict(policy=const.policy(), epoch_s=const.epoch_s,
                  max_single=const.max_single())
        # control: without a token the short debit rolls back at host level
        out = store.debit_vector(_decl(requests=10), _dims(), tool="t",
                                 now=1000.0, **kw)
        assert out["committed"] is False
        assert out["level"] == "host"
        # a token sized exactly to the TOTAL deficit admits it — consumed 1:1
        tok = _mint(store, max_vector={"requests": 30.0})
        out = store.debit_vector(_decl(requests=10), _dims(), tool="t",
                                 now=1000.0, **kw)
        assert out["committed"] is True
        assert _reserve_rows(store, tok["token_id"])["remaining"][
            "requests"] == pytest.approx(0.0)

    def test_insufficient_reserve_no_cover(self, engine, store):
        _drain_host(store)
        tok = _mint(store, max_vector={"requests": 8.0})   # deficit is 9
        const = rt.constitution()
        out = store.debit_vector(
            _decl(requests=10), _dims(), tool="t",
            policy=const.policy(), epoch_s=const.epoch_s,
            max_single=const.max_single(), now=1000.0)
        assert out["committed"] is False
        assert _reserve_rows(store, tok["token_id"])["remaining"][
            "requests"] == pytest.approx(8.0)

    def test_dims_mismatch_no_cover(self, engine, store):
        _drain_host(store)
        tok = _mint(store, max_vector={"requests": 100.0},
                    dims={"host_axis": "99.9.9.9"})
        const = rt.constitution()
        out = store.debit_vector(
            _decl(requests=10), _dims(), tool="t",
            policy=const.policy(), epoch_s=const.epoch_s,
            max_single=const.max_single(), now=1000.0)
        assert out["committed"] is False
        assert _reserve_rows(store, tok["token_id"])["remaining"][
            "requests"] == pytest.approx(100.0)

    def test_engagement_binding(self, engine, store):
        _drain_host(store)
        tok_pg = _mint(store, max_vector={"requests": 100.0},
                       engagement="pg")
        const = rt.constitution()
        kw = dict(policy=const.policy(), epoch_s=const.epoch_s,
                  max_single=const.max_single())
        # token pinned to engagement 'pg' does NOT cover a NULL-engagement
        # (lab) debit — matching is the enforceable contract
        out = store.debit_vector(_decl(requests=10), _dims(), tool="t",
                                 engagement=None, now=1000.0, **kw)
        assert out["committed"] is False
        assert _reserve_rows(store, tok_pg["token_id"])["remaining"][
            "requests"] == pytest.approx(100.0)
        tok_wild = _mint(store, max_vector={"requests": 100.0})
        # a NULL-engagement token is the wildcard — covers
        out = store.debit_vector(_decl(requests=10), _dims(), tool="t",
                                 engagement=None, now=1000.0, **kw)
        assert out["committed"] is True
        assert _reserve_rows(store, tok_wild["token_id"])["remaining"][
            "requests"] == pytest.approx(70.0)

    def test_admit_side_projection(self, engine, store):
        _drain_host(store)
        _mint(store, max_vector={"requests": 100.0})
        const = rt.constitution()
        out = store.admit_vector(
            _decl(requests=10), _dims(),
            policy=const.policy(), epoch_s=const.epoch_s,
            max_single=const.max_single(), now=1000.0)
        assert out["decision"] == "admit"

    def test_sweep_reserves_ttl(self, store):
        _mint(store, ttl_hours=0.5)
        _mint(store)                                   # no ttl — survives
        n = store.sweep_reserves(now=1000.0 + 1801)
        assert n == 1
        rows = store.list_reserves()
        assert len(rows) == 1 and rows[0]["ttl_expiry"] is None

    def test_purge_wipes_reserves(self, store):
        _mint(store, engagement="pg")
        _mint(store, engagement="keep")
        out = store.purge_engagement("pg")
        assert out["reserves"] == 1
        remaining = {r["engagement"] for r in store.list_reserves()}
        assert remaining == {"keep"}


# ─── dispatch chokepoint (§3) ────────────────────────────────────────────────

class TestGate:
    def test_gate_disabled_returns_none(self, engine, monkeypatch):
        monkeypatch.setenv("BUDGET_ENABLED", "0")
        assert rt.ration_gate("auxiliaries.web_session.session_get",
                              {"target": "10.0.0.7"}, now=1000.0) is None

    def test_gate_unregistered_returns_none(self, engine):
        assert rt.ration_gate("tests.probe.nope",
                              {"target": "10.0.0.7"}, now=1000.0) is None

    def test_gate_debits_registered_tool(self, engine, store):
        g = rt.ration_gate("auxiliaries.web_session.session_get",
                           {"target": "10.0.0.7"},
                           agent_id="t1", session_id="s1", now=1000.0)
        assert isinstance(g, dict) and g["gate"] == "debited"
        rcpt = g["receipt"]
        assert rcpt["committed"] is True
        assert isinstance(rcpt["emission_id"], int)
        assert g["tool_id"] == "auxiliaries.web_session.session_get"
        assert g["declared"]["requests"] == 1
        assert g["declared_basis"] == "measured"
        assert g["dims"]["host_axis"] == "10.0.0.7"
        em = store.conn.execute(
            "SELECT * FROM emissions WHERE id=?", (rcpt["emission_id"],)
        ).fetchone()
        assert em["agent_id"] == "t1"
        # the ROW stamps the honest declaration shape: any open (None) dim
        # grades credit_line; the receipt keeps the estimator family basis
        assert em["declared_basis"] == "credit_line"
        assert g["declared_basis"] == "measured"

    def test_gate_deferred_envelope_and_queue_row(self, engine, store):
        _drain_host(store)
        g = rt.ration_gate("auxiliaries.web_session.session_get",
                           {"target": "10.0.0.7"}, agent_id="t1",
                           now=1000.0)
        assert g["status"] == "budget_deferred"
        assert g["queue_id"].startswith("q-")
        assert "do NOT retry" in g["instruction"]
        item = store.get_item(g["queue_id"])
        assert item["status"] == "queued"
        assert item["tool"] == "auxiliaries.web_session.session_get"

    def test_gate_refused_on_neverfit(self, engine, monkeypatch):
        monkeypatch.setenv("BUDGET_CONSTITUTION", json.dumps({
            "defaults": {"requests": {"ceiling": 0.5,
                                      "refill_per_epoch": 0.0, "floor": 0.0}},
            "max_single_call": {"requests": 0.5}}))
        rt.reset_engine()
        try:
            g = rt.ration_gate("auxiliaries.web_session.session_get",
                               {"target": "10.0.0.7"}, now=1000.0)
        finally:
            rt.reset_engine()
        assert g["status"] == "budget_refused"
        assert g.get("fail_closed") is True

    def test_gate_state_matches_executor_contract(self, engine):
        g = rt.ration_gate("auxiliaries.masscan.run_masscan",
                           {"target": "10.0.9.5"}, now=1000.0)
        assert g["gate"] == "debited"
        for key in ("tool_id", "receipt", "declared", "dims", "agent_id",
                    "engagement", "declared_basis", "estimator"):
            assert key in g
        assert g["declared_basis"] == "credit_line"


# ─── discharge: compensation + job binding (§3 step 6) ──────────────────────

class TestDischarge:
    @staticmethod
    def _emission(store, emission_id):
        return dict(store.conn.execute(
            "SELECT * FROM emissions WHERE id=?", (emission_id,)
        ).fetchone())

    def test_duplicate_compensates(self, engine, store):
        g = rt.ration_gate("auxiliaries.web_session.session_get",
                           {"target": "10.0.0.7"}, now=1000.0)
        eid = g["receipt"]["emission_id"]
        out = rt.ration_discharge(g, {"status": "duplicate",
                                      "job_id": "bg-live"})
        assert out is not None
        em = self._emission(store, eid)
        assert em["drift"] == 2
        assert "duplicate" in em["drift_note"]
        assert em["job_ref"] is None    # never bind the LIVE unit's job
        # the declared request was paid back
        host = [r for r in store.conn.execute("SELECT * FROM nodes")
                if r["host_axis"] == "10.0.0.7" and r["range_axis"] is None][0]
        assert host["remaining_requests"] == pytest.approx(600.0)

    def test_refused_compensates(self, engine, store):
        g = rt.ration_gate("auxiliaries.web_session.session_get",
                           {"target": "10.0.0.7"}, now=1000.0)
        eid = g["receipt"]["emission_id"]
        rt.ration_discharge(g, {"status": "refused",
                                "reason": "slots_exhausted"})
        em = self._emission(store, eid)
        assert em["drift"] == 2
        assert "slots_exhausted" in em["drift_note"]

    def test_discharge_binds_job(self, engine, store):
        g = rt.ration_gate("auxiliaries.web_session.session_get",
                           {"target": "10.0.0.7"}, now=1000.0)
        eid = g["receipt"]["emission_id"]
        out = rt.ration_discharge(g, {"result": {"job_id": "bg-7"}})
        assert out == {"discharge": "job-bound", "job_ref": "bg-7",
                       "emission_id": eid}
        assert self._emission(store, eid)["job_ref"] == "bg-7"

    def test_discharge_open_for_bare_result(self, engine):
        g = rt.ration_gate("auxiliaries.web_session.session_get",
                           {"target": "10.0.0.7"}, now=1000.0)
        out = rt.ration_discharge(g, {"result": {"status": "ok"}})
        assert out["discharge"] == "open"

    def test_discharge_none_gate_is_none(self, engine):
        assert rt.ration_discharge(None, {"job_id": "bg-1"}) is None


# ─── credit-line draws (§7.1) ────────────────────────────────────────────────

class TestDraws:
    def _masscan_gate(self, engine):
        g = rt.ration_gate("auxiliaries.masscan.run_masscan",
                           {"target": "10.0.9.5"}, now=1000.0)
        assert g["gate"] == "debited"
        assert g["declared_basis"] == "credit_line"
        return g

    def test_poll_reconciles_draw_with_actuals(self, engine, store):
        g = self._masscan_gate(engine)
        eid = g["receipt"]["emission_id"]
        rt.ration_discharge(g, {"job_id": "bg-9"})
        assert len(store.open_draws()) == 1
        out = rt.reconcile_poll_job("bg-9", {"result": {"sent": 500}})
        assert out["job_ref"] == "bg-9"
        assert out["actual"] == {"requests": 500.0}
        assert out["draws"][0]["reconciled"] is True
        assert out["draws"][0]["emission_id"] == eid
        assert store.open_draws() == []
        em = dict(store.conn.execute(
            "SELECT * FROM emissions WHERE id=?", (eid,)).fetchone())
        assert json.loads(em["actual_json"]) == {"requests": 500.0}

    def test_poll_closes_draw_without_actuals(self, engine, store):
        g = self._masscan_gate(engine)
        eid = g["receipt"]["emission_id"]
        rt.ration_discharge(g, {"job_id": "bg-8"})
        out = rt.reconcile_poll_job(
            "bg-8", {"status": "done", "result": {"verdict": "no numbers"}})
        assert out["draws"][0]["closed"] is True
        assert out["actual"] is None
        assert store.open_draws() == []
        em = dict(store.conn.execute(
            "SELECT * FROM emissions WHERE id=?", (eid,)).fetchone())
        assert em["actual_json"] is None
        assert em["drift_note"].startswith("closed at job release")

    def test_poll_without_draws_is_empty(self, engine):
        assert rt.reconcile_poll_job("bg-none", {"status": "done"}) == \
            {"draws": []}

    def test_sweep_draws_closes_abandoned_and_staled(self, engine, store):
        g = self._masscan_gate(engine)
        rt.ration_discharge(g, {"job_id": "bg-gone"})      # bound, row gone
        # second, unbound draw: never picked up by a job
        g3 = rt.ration_gate("auxiliaries.masscan.run_masscan",
                            {"target": "10.0.9.6"}, now=1000.0)
        assert len(store.open_draws()) == 2
        n = rt.sweep_draws(jobs_getter=lambda jid: None,
                           now=time.time() + 3600 * 24 * 2)
        assert n == 2
        rows = {r["job_ref"]: r["drift_note"] for r in store.conn.execute(
            "SELECT job_ref, drift_note FROM emissions WHERE drift_note LIKE"
            " 'closed%'")}
        assert rows["bg-gone"].startswith(
            "closed: job row gone — declared stands")
        assert rows[None].startswith("closed: staled unbound draw past TTL")
        assert store.open_draws() == []

    def test_sweep_leaves_live_job_and_fresh_draw(self, engine, store):
        g = self._masscan_gate(engine)
        rt.ration_discharge(g, {"job_id": "bg-alive"})
        # a live job row keeps its draw open for the poll reconciler
        assert rt.sweep_draws(jobs_getter=lambda jid: {"id": jid}) == 0
        assert len(store.open_draws()) == 1
        # a fresh unbound draw is inside its TTL window — untouched
        g2 = rt.ration_gate("auxiliaries.masscan.run_masscan",
                            {"target": "10.0.9.6"}, now=1000.0)
        assert g2["gate"] == "debited"
        assert rt.sweep_draws(jobs_getter=lambda jid: {
            "id": jid} if jid == "bg-alive" else None, now=1000.0) == 0
        assert len(store.open_draws()) == 2


# ─── posture dwell (§11 seam) ────────────────────────────────────────────────

class TestDwell:
    def test_healthy_host_zero(self, engine):
        assert rt.ration_dwell("10.0.4.4") == 0.0

    def test_disabled_zero(self, engine, monkeypatch):
        monkeypatch.setenv("BUDGET_ENABLED", "0")
        assert rt.ration_dwell("10.0.4.4") == 0.0

    def test_no_host_zero(self, engine):
        assert rt.ration_dwell(None) == 0.0

    def test_backoff_host_dwell_bounded(self, engine):
        for _ in range(6):
            engine.controller.observe(engagement=None,
                                      host_axis="10.0.4.5",
                                      response_class="reset")
        assert engine.controller.pacing(
            engagement=None, host_axis="10.0.4.5") < 0.999
        dwell = rt.ration_dwell("10.0.4.5")
        assert 0.0 < dwell <= 0.2 + 1e-9


# ─── drain-lane ration-awareness (§7.2) ─────────────────────────────────────

class TestDrainRationAwareness:
    @staticmethod
    def _enqueue(store, now=1000.0, tool="tests.d"):
        return store.enqueue_item(
            tool=tool, arguments={"target": "10.0.0.7"},
            decl=_decl(requests=1), dims=_dims(), reason="budget_short",
            agent_id="op", engagement=None, now=now)

    def test_still_short_keeps_original_cancels_dup(self, engine, store):
        orig = self._enqueue(store, now=1000.0)
        dup = self._enqueue(store, now=1000.5)
        res = asyncio_run(engine.operator_tick(
            dispatch=lambda item: (_ for _ in ()).throw(
                rt.BudgetStillShort(queue_id=dup)),
            now=1006.0))
        first = [r for r in res["results"] if r["qid"] == orig][0]
        assert first["decision"] == "still_short"
        assert store.get_item(orig)["status"] == "queued"
        assert store.get_item(dup)["status"] == "cancelled"

    def test_budget_refused_cancels_item(self, engine, store):
        qid = self._enqueue(store)
        res = asyncio_run(engine.operator_tick(
            dispatch=lambda item: (_ for _ in ()).throw(
                rt.BudgetRefused(reason="never fits under ceiling")),
            now=1006.0))
        assert res["results"][0]["decision"] == "refused_cancelled"
        assert "never fits" in res["results"][0]["reason"]
        item = store.get_item(qid)
        assert item["status"] == "cancelled"
        assert "budget refused" in item["notes_json"]
