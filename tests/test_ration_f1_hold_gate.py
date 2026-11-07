"""F-1 pinning tests: §6.2 HOLD gates fresh lanes; operator drain passes.

Doc row (evasion_design.md §6.2): a HOLD node is release-eligible ONLY to
the operator (backlog drain). Fresh dispatches defer with budget_deferred /
held_pending, spend nothing, and mint no queue row — the drain re-admits
them every tick until the node re-normalizes. The drain carries
operator_release=True through ration_gate and admits against floor credit.
"""

import asyncio

import pytest

import utils.ration as rt


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
    monkeypatch.setenv("BUDGET_CONSTITUTION",
                       '{"release_jitter": {"min": 0.0, "max": 0.0}}')
    rt.reset_engine()
    yield rt.get_engine()
    rt.reset_engine()


def _seed_held(engine, host="10.0.0.7", engagement=None):
    """Committed mint (NORMAL) -> pin HOLD -> seed one backlog item."""
    store = engine.store
    r = engine.dispatch_debit(
        "auxiliaries.web_session.session_get", {"target": host},
        agent_id="seed", engagement=engagement, now=1000.0)
    assert r.get("committed"), r
    store.set_phase(mode="hold", host_axis=host)
    qid = store.enqueue_item(
        tool="auxiliaries.nmap.run_nmap", arguments={"target": host},
        decl={"requests": 2, "packets": None, "auth_events": None,
              "bytes": None},
        dims={"engagement": engagement, "host_axis": host},
        reason="budget_short", agent_id="op", engagement=engagement,
        now=1000.0)
    return qid


def _host_remaining(store, host):
    row = store.conn.execute(
        "SELECT remaining_requests FROM nodes WHERE host_axis=?",
        (host,)).fetchone()
    return row[0] if row is not None else None


class TestHoldGatesFreshLanes:
    def test_fresh_admit_at_hold_defers_without_debit(self, engine):
        """THE F-1 case: credit IS spendable (minted full ceiling) and the
        node is HOLD — the fresh lane must defer, never queue-jump."""
        _seed_held(engine)
        before = _host_remaining(engine.store, "10.0.0.7")
        g = rt.ration_gate(
            "auxiliaries.web_session.session_get", {"target": "10.0.0.7"},
            agent_id="fresh", session_id="fresh-sess", now=1000.0)
        assert g["status"] == "budget_deferred"
        assert g["decision"] == "enqueue"
        assert "HOLD" in (g.get("reason") or "")
        assert _host_remaining(engine.store, "10.0.0.7") == before

    def test_held_dispatch_mints_no_queue_row(self, engine):
        qid = _seed_held(engine)
        g = rt.ration_gate(
            "auxiliaries.web_session.session_get", {"target": "10.0.0.7"},
            agent_id="fresh", session_id="fresh-sess", now=1000.0)
        assert g["status"] == "budget_deferred"
        assert g.get("queue_id") is None
        queued = engine.store.due_items(now=1000.0)
        assert len(queued) == 1 and queued[0]["qid"] == qid

    def test_shortfall_at_hold_defers_like_admit(self, engine):
        """Shortfall (enqueue decision) under HOLD: same held semantics."""
        _seed_held(engine)
        engine.store.conn.execute(
            "UPDATE nodes SET remaining_requests=0 WHERE host_axis=?",
            ("10.0.0.7",))
        engine.store.conn.commit()
        g = rt.ration_gate(
            "auxiliaries.web_session.session_get", {"target": "10.0.0.7"},
            agent_id="fresh", session_id="fresh-sess", now=1000.0)
        assert g["status"] == "budget_deferred"
        assert g["decision"] == "enqueue"

    def test_operator_release_admits_at_hold(self, engine):
        """§6.2 exception: the drain is release-eligible at HOLD."""
        _seed_held(engine)
        before = _host_remaining(engine.store, "10.0.0.7")
        g = rt.ration_gate(
            "auxiliaries.web_session.session_get", {"target": "10.0.0.7"},
            agent_id="operator", session_id="ration-drain",
            operator_release=True, now=1000.0)
        assert g["gate"] == "debited"
        after = _host_remaining(engine.store, "10.0.0.7")
        assert after == before - 1.0
        # ...and the fresh lane stays gated alongside the operator's spend
        g2 = rt.ration_gate(
            "auxiliaries.web_session.session_get", {"target": "10.0.0.7"},
            agent_id="fresh2", session_id="fresh2-sess", now=1000.0)
        assert g2["status"] == "budget_deferred"

    def test_tick_drains_own_item_while_held(self, engine):
        qid = _seed_held(engine)
        # The operator tick drains its own backlog while the node HOLDS —
        # without the release exception this would deadlock (§6.2).
        async def tick():
            return await engine.operator_tick(
                dispatch=lambda item: {"job_id": 77}, now=1000.0)
        res = asyncio_run(tick())
        assert res["decision"] == "drained"
        assert res["results"][0]["decision"] == "dispatched"
        item = engine.store.get_item(qid)
        assert item["status"] == "launched" and item["job_ref"] == "77"

    def test_unpinned_node_re_admits_fresh(self, engine):
        qid = _seed_held(engine)
        engine.operator_tick(dispatch=lambda item: {"job_id": 1}, now=1000.0)
        engine.store.set_phase(mode="normal", host_axis="10.0.0.7",
                               epoch_anchor=1005.0)
        engine.store.finish_item(qid)
        g = rt.ration_gate(
            "auxiliaries.web_session.session_get", {"target": "10.0.0.7"},
            agent_id="fresh3", session_id="fresh3-sess", now=1010.0)
        assert g["gate"] == "debited"
