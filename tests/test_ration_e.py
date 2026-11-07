"""Phase E ration tests (§17 adoption-pack findings, hand-applied).

Covers: M4 clock discipline (anti-burst refill clamp + monotonic anchor),
M1 credit-line lifecycle (draw→HOLD→METER→SETTLE, exhaustion mid-flight),
M3 debit-direction rule (reconcile to max(L0, L1); under-declared never
refunds), H2 two-tier ledger (request spans, aggregate spans, the controller
verdict + aggregate-only deadband), M5 CDN origin-key pinning, M2
constitution sketch forms (loader validation, store=sqlite sole leg,
controller bounds), L2 wildcard reserve tags (engagement binding never
loosened), and L7 honesty (unusable store dir + bad constitution fail
closed, never green).
"""

import asyncio
import json
import sqlite3  # noqa: F401  (imported for store-level transaction reads)

import pytest

import utils.ration as rt
from utils.ration_store import DIMS


def asyncio_run(coro):  # pragma: no cover - parity with phase A helper
    return asyncio.run(coro)


@pytest.fixture
def engine(tmp_path, monkeypatch):
    (tmp_path / "budget").mkdir()
    monkeypatch.setenv("BUDGET_STORE_DIR", str(tmp_path / "budget"))
    monkeypatch.setenv("BUDGET_ENABLED", "1")
    for k in ("BUDGET_CONSTITUTION", "BUDGET_CONSTITUTION_FILE",
              "BUDGET_EPOCH_SECONDS", "BUDGET_CDN_ORIGIN_KEYS",
              "BUDGET_RESERVE_WILD_TAGS", "BUDGET_SPAN_AGG_DEADBAND",
              "BUDGET_ACCRUE_TICK_EPOCHS", "BUDGET_MONO_CLOCK",
              "BUDGET_DRAW_TTL_HOURS"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("BUDGET_CONSTITUTION",
                       '{"release_jitter": {"min": 0.0, "max": 0.0}}')
    rt.reset_engine()
    yield rt.get_engine()
    rt.reset_engine()


def _decl(**kw):
    return {d: kw.get(d) for d in DIMS}


def _dims(**kw):
    dims = rt.dims_for_target(kw.pop("target", "10.0.0.7"))
    dims.update(kw)
    return dims


def _kw(const):
    return dict(policy=const.policy(), epoch_s=const.epoch_s,
                max_single=const.max_single())


def _host_node(store, host="10.0.0.7", engagement=None):
    return [dict(r) for r in store.conn.execute(
        "SELECT * FROM nodes WHERE host_axis=? AND range_axis IS NULL AND"
        " engagement IS ?", (host, engagement))][0]


# ─── M4 — clock discipline ────────────────────────────────────────────────────

class TestM4Clock:
    def test_refill_clamped_to_one_tick_per_accrue(self, engine):
        s = engine.store
        const = rt.constitution()
        rc = s.debit_vector(_decl(requests=600), _dims(), tool="tests.t",
                            now=1000.0, estimator="seed", **_kw(const))
        assert rc["committed"] and rc["decision"] == "debit"
        # a suspended/NTP-jumped wall clock (21 epochs of phantom elapsed)
        # must NOT inflate: at most BUDGET_ACCRUE_TICK_EPOCHS (1) of refill
        node = _host_node(s)
        bal = s._accrue(node, 1000.0 + 21 * const.epoch_s,
                        const.epoch_s)
        assert bal["requests"]["remaining"] == pytest.approx(
            const.defaults["requests"]["refill_per_epoch"], abs=0.5), \
            "clock-jump must not grant 21 epochs of credit"

    def test_budget_now_ignores_wall_clock_jumps(self, engine, monkeypatch):
        fake = [1000.0]
        monkeypatch.setattr(rt.time, "time", lambda: fake[0])
        b1 = rt.budget_now()
        fake[0] += 10 ** 6          # NTP step / suspend-resume fantasy
        b2 = rt.budget_now()
        assert 0 <= b2 - b1 < 60    # monotonic anchor: no inflation
        monkeypatch.setenv("BUDGET_MONO_CLOCK", "0")
        assert rt.budget_now() == pytest.approx(fake[0])


# ─── M1 — credit-line lifecycle ──────────────────────────────────────────────

def _credit_receipt(engine, **extra):
    const = rt.constitution()
    dims = _dims(**extra)
    return engine.store.debit_vector(
        _decl(), dims, tool="tests.batch", now=1000.0,
        estimator="seed", declared_basis="credit_line", **_kw(const))


class TestM1Lifecycle:
    def test_hold_meters_settles(self, engine):
        s = engine.store
        const = rt.constitution()
        receipt = s.debit_vector(
            _decl(), _dims(), tool="tests.batch", now=1000.0,
            estimator="seed", declared_basis="credit_line", **_kw(const))
        assert receipt["committed"] and receipt["credit_line"]
        em = receipt["emission_id"]
        row = dict(s.conn.execute(
            "SELECT meter_state FROM emissions WHERE id=?", (em,)).fetchone())
        assert row["meter_state"] == "hold"          # drawn, not yet running
        m = s.meter_draw(em, {"requests": 5}, policy=const.policy(),
                         epoch_s=const.epoch_s, now=1100.0)
        assert m["charged"] and m["metered"]["requests"] == pytest.approx(5.0)
        row2 = dict(s.conn.execute(
            "SELECT meter_state FROM emissions WHERE id=?", (em,)).fetchone())
        assert row2["meter_state"] == "metering"     # METER started
        m2 = s.meter_draw(em, {"requests": 5}, policy=const.policy(),
                          epoch_s=const.epoch_s, now=1200.0)
        assert not m2["charged"]                     # idempotent cumulative
        out = rt.get_engine().reconcile(receipt, {"requests": 3}, settle=True)
        assert out is not None
        assert out["meter"]["meter_state"] == "settled"
        assert out["meter"]["metered"]["requests"] == pytest.approx(5.0)
        snap = s.status_snapshot()
        assert not snap["open_draws"]
        assert snap["exhausted_draws"] == 0

    def test_settle_even_when_terminal_actual_runs_under(self, engine):
        s = engine.store
        const = rt.constitution()
        receipt = s.debit_vector(
            _decl(), _dims(), tool="tests.batch", now=1000.0,
            estimator="seed", declared_basis="credit_line", **_kw(const))
        em = receipt["emission_id"]
        out = rt.get_engine().reconcile(receipt, {"requests": 2}, settle=True)
        # no charge (2 ≤ ...cum 0 + max) hmm: baseline 0 → tgt 2 → charge 2 —
        # then SETTLE; either path the lifecycle must close.
        assert out["meter"]["meter_state"] == "settled"
        row = dict(s.conn.execute(
            "SELECT metered_json FROM emissions WHERE id=?", (em,)).fetchone())
        assert json.loads(row["metered_json"])["requests"] == pytest.approx(2.0)

    def test_exhaustion_mid_flight_ends_the_tool(self, engine):
        s = engine.store
        const = rt.constitution()
        receipt = s.debit_vector(
            _decl(), _dims(), tool="tests.batch", now=1000.0,
            estimator="seed", declared_basis="credit_line", **_kw(const))
        em = receipt["emission_id"]
        before = _host_node(s)["remaining_requests"]
        m = s.meter_draw(em, {"requests": 10_000}, policy=const.policy(),
                         epoch_s=const.epoch_s, now=1100.0)
        assert m["exhausted"] and not m["charged"] and m["ledger_short"]
        row = dict(s.conn.execute(
            "SELECT meter_state, drift_note FROM emissions WHERE id=?",
            (em,)).fetchone())
        assert row["meter_state"] == "exhausted"
        assert "must END" in (row["drift_note"] or "")
        assert _host_node(s)["remaining_requests"] == pytest.approx(
            before), "exhausted cascade must roll back, never overdraw"
        # post-exhaustion retry at a LOWER target charges honestly
        m2 = s.meter_draw(em, {"requests": 400}, policy=const.policy(),
                          epoch_s=const.epoch_s, now=1200.0)
        assert m2["charged"] and m2["metered"]["requests"] == pytest.approx(
            400.0)

    def test_sweep_expires_stale_holds(self, engine, monkeypatch):
        s = engine.store
        const = rt.constitution()
        s.debit_vector(_decl(), _dims(), tool="tests.batch", now=1000.0,
                       estimator="seed", declared_basis="credit_line",
                       **_kw(const))
        # BUDGET_DRAW_HOLD_HOURS default — force expiry by sweeping far ahead
        closed = rt.sweep_draws(now=1000.0 + 30 * 3600.0)
        assert closed >= 1
        row = dict(s.conn.execute(
            "SELECT meter_state FROM emissions WHERE id=?",
            (1,)).fetchone())
        assert row["meter_state"] == "expired"
        assert not s.status_snapshot()["open_draws"]


# ─── M3 — debit direction rule ───────────────────────────────────────────────

class TestM3DebitDirection:
    def test_under_declared_actual_never_refunds(self, engine):
        s = engine.store
        const = rt.constitution()
        receipt = s.debit_vector(_decl(requests=10), _dims(), tool="tests.t",
                                 now=1000.0, estimator="seed", **_kw(const))
        assert receipt["committed"]
        before = _host_node(s)["remaining_requests"]
        m = s.meter_draw(receipt["emission_id"], {"requests": 4},
                         policy=const.policy(), epoch_s=const.epoch_s,
                         now=1100.0)
        assert not m["charged"]            # max(10, 4) = 10 already charged
        assert not m["exhausted"] and not m.get("ledger_short")
        assert _host_node(s)["remaining_requests"] == pytest.approx(before)
        assert m["metered"]["requests"] == pytest.approx(10.0)

    def test_over_declared_actual_charges_as_consumed(self, engine):
        s = engine.store
        const = rt.constitution()
        receipt = s.debit_vector(_decl(requests=10), _dims(), tool="tests.t",
                                 now=1000.0, estimator="seed", **_kw(const))
        before = _host_node(s)["remaining_requests"]
        m = s.meter_draw(receipt["emission_id"], {"requests": 30},
                         policy=const.policy(), epoch_s=const.epoch_s,
                         now=1000.0)          # elapsed 0 → zero accrual
        assert m["charged"]
        # the DELTA charged is exactly 20 (max(L0=10, L1=30) − 10)
        after = _host_node(s)["remaining_requests"]
        assert after == pytest.approx(before - 20)
        assert m["metered"]["requests"] == pytest.approx(30.0)


# ─── H2 — two-tier ledger ────────────────────────────────────────────────────

class TestH2Verdicts:
    def test_no_spans_is_unknown(self, engine):
        assert engine.controller.verdict(host_axis="10.0.0.7",
                                         now=5000.0) == "unknown"

    def test_aggregate_then_measured(self, engine):
        s = engine.store
        s.record_span(1, provenance="aggregate", host_axis="10.0.0.7",
                      ts=5000.0)
        assert engine.controller.verdict(host_axis="10.0.0.7",
                                         now=5100.0) == "aggregate"
        s.record_span(1, provenance="request", response_class="2xx",
                      host_axis="10.0.0.7", ts=5010.0)
        assert engine.controller.verdict(host_axis="10.0.0.7",
                                         now=5100.0) == "measured"

    def test_bad_provenance_is_authored_error(self, engine):
        with pytest.raises(ValueError):
            engine.store.record_span(1, provenance="vibes",
                                     host_axis="10.0.0.7")

    def test_aggregate_only_widens_tripwire_deadband(self, engine):
        s = engine.store
        # give the lane a tripwire lower bound and spend past it (3 in-window
        # emissions, lower=2) — tight bounds WOULD throttle
        s.conn.execute(
            "INSERT INTO tripwire_intervals (engagement, host_axis, kind,"
            " lower, upper, window_seconds, samples, provenance, updated)"
            " VALUES (NULL, '10.0.0.7', 'requests', 2, 6, 120, 1,"
            " 'seed', 1000.0)")
        for t in (990.0, 995.0, 1000.0):
            s.record_emission(ts=t, tool="tests.t", engagement=None,
                              agent_id="0", dims=_dims(),
                              declared=_decl(requests=1),
                              declared_basis="estimated", estimator="seed")
        s.conn.commit()
        ctl = engine.controller
        # aggregate-only: the deadband widens ×4 → spent 3 < 2*4 → NO throttle
        s.record_span(1, provenance="aggregate", host_axis="10.0.0.7",
                      ts=1001.0)
        assert ctl.verdict(host_axis="10.0.0.7", now=1100.0) == "aggregate"
        assert ctl.pacing(host_axis="10.0.0.7", now=1100.0) == pytest.approx(
            1.0)
        # request-level truth: tight bounds drive the throttle again
        s.record_span(2, provenance="request", response_class="429",
                      host_axis="10.0.0.7", ts=1002.0)
        assert ctl.verdict(host_axis="10.0.0.7", now=1100.0) == "measured"
        assert ctl.pacing(host_axis="10.0.0.7", now=1100.0) == pytest.approx(
            0.4)


class TestH2SpanRecording:
    def test_inline_session_result_records_request_spans_and_settles(
            self, engine):
        const = rt.constitution()
        dims = _dims()
        receipt = engine.store.debit_vector(
            _decl(), dims,
            tool="auxiliaries.web_session.session_get", now=1000.0,
            estimator="seed", declared_basis="credit_line", **_kw(const))
        gate_state = {"gate": "debited", "tool_id":
                      "auxiliaries.web_session.session_get",
                      "receipt": receipt, "declared": _decl(),
                      "dims": dims, "agent_id": "0", "engagement": None,
                      "declared_basis": "credit_line", "estimator": "seed"}
        result = {"status": "ok", "result": {"hops": [
            {"status": 200, "url": "http://10.0.0.7/login"},
            {"status": 429, "url": "http://10.0.0.7/dashboard"}]}}
        out = rt.ration_discharge(gate_state, result)
        assert out["discharge"] == "reconciled"
        assert out["spans"] == 2
        summary = engine.store.span_summary(host_axis="10.0.0.7")
        assert summary["request"] == 2 and summary["aggregate"] == 0
        spans = engine.store.spans_for_emission(receipt["emission_id"])
        assert [sp["response_class"] for sp in spans] == ["2xx", "429"]
        row = dict(engine.store.conn.execute(
            "SELECT meter_state, actual_json FROM emissions WHERE id=?",
            (receipt["emission_id"],)).fetchone())
        assert row["meter_state"] == "settled"
        assert json.loads(row["actual_json"])["requests"] == 2

    def test_batch_job_release_records_one_aggregate_span(self, engine):
        s = engine.store
        const = rt.constitution()
        receipt = s.debit_vector(
            _decl(), _dims(engagement="proj"), tool="auxiliaries.nmap.run_nmap",
            now=1000.0, estimator="seed", declared_basis="credit_line",
            engagement="proj", **_kw(const))
        em = receipt["emission_id"]
        s.bind_emission_job(em, "JOB-E2E-1")
        out = rt.reconcile_poll_job(
            "JOB-E2E-1", {"status": "done", "requests_made": 42})
        closed = out.get("draws") or []
        assert closed and closed[0]["reconciled"]
        summary = s.span_summary(host_axis="10.0.0.7", engagement="proj")
        assert summary["aggregate"] == 1 and summary["request"] == 0
        spans = s.spans_for_emission(em)
        assert spans[0]["provenance"] == "aggregate"
        assert spans[0]["response_class"] == "ok"
        assert spans[0]["window_count"] == pytest.approx(42.0)
        assert spans[0]["detail"]["job_id"] == "JOB-E2E-1"
        # the draw closed with max(L0=∞, L1=42) metered
        row = dict(s.conn.execute(
            "SELECT meter_state, metered_json FROM emissions WHERE id=?",
            (em,)).fetchone())
        assert row["meter_state"] == "settled"
        assert json.loads(row["metered_json"])["requests"] == pytest.approx(
            42.0)

    def test_meter_poll_job_bills_midflight_without_closing(self, engine):
        s = engine.store
        const = rt.constitution()
        receipt = s.debit_vector(
            _decl(), _dims(), tool="auxiliaries.nmap.run_nmap", now=1000.0,
            estimator="seed", declared_basis="credit_line", **_kw(const))
        em = receipt["emission_id"]
        s.bind_emission_job(em, "JOB-METER-1")
        mout = rt.meter_poll_job(
            "JOB-METER-1", {"status": "running", "requests_made": 17})
        assert mout["draws"][0]["meter"]["metered"]["requests"] == \
            pytest.approx(17.0)
        row = dict(s.conn.execute(
            "SELECT meter_state, actual_json FROM emissions WHERE id=?",
            (em,)).fetchone())
        assert row["meter_state"] == "metering"
        assert row["actual_json"] is None      # terminal only reconciles


# ─── M5 — CDN origin keys ────────────────────────────────────────────────────

class TestM5CdnKeys:
    def test_env_pins_origin_over_cidr(self, engine, monkeypatch):
        monkeypatch.setenv("BUDGET_CDN_ORIGIN_KEYS", json.dumps({
            "cdn.example.com": "origin-web-1",
            "*.example.net": "origin-2"}))
        d = rt.dims_for_target("cdn.example.com")
        assert d["host_axis"] == "origin-web-1"
        assert d["range_axis"] is None
        d2 = rt.dims_for_target("https://shop.example.net/page")
        assert d2["host_axis"] == "origin-2"
        d3 = rt.dims_for_target("example.org")
        assert d3["host_axis"] == "example.org"      # unpinned stays mechanical

    def test_unparseable_env_raises_honest(self, engine, monkeypatch):
        monkeypatch.setenv("BUDGET_CDN_ORIGIN_KEYS", "{bad json")
        with pytest.raises(ValueError):
            rt.dims_for_target("cdn.example.com")


# ─── M2 — constitution sketch ────────────────────────────────────────────────

class TestM2Constitution:
    def _write(self, tmp_path, body, name="constitution.yml"):
        cfg = tmp_path / name
        cfg.write_text(json.dumps(body))
        return cfg

    def test_sketch_form_loads(self, engine, tmp_path, monkeypatch):
        cfg = self._write(tmp_path, {
            "per_dim": {"requests": {"ceiling": 500, "floor": 4,
                                     "refill_per_epoch": 80}},
            "max_single_call": {"requests": 400},   # must fit the ceiling
            "epoch_seconds": 900,
            "release_jitter": {"min": 5, "max": 60},
            "controller": {"max_transitions_per_hour": 6,
                           "max_throttle_down": "throttled",
                           "max_speed_up": "normal"},
            "reserve_partitions": {"entry": {"size": 100},
                                   "exit": {"size": 50}},
            "cdn_origin_keys": {"a.com": "o1"},
            "reserve_tag_wildcards": ["shared"],
            "store": "sqlite"})
        monkeypatch.setenv("BUDGET_CONSTITUTION_FILE", str(cfg))
        c = rt.constitution()
        assert c.epoch_s == pytest.approx(900.0)
        assert c.defaults["requests"]["ceiling"] == 500
        assert c.defaults["requests"]["floor"] == 4
        assert c.max_single()["requests"] == 400
        assert c.controller["max_throttle_down"] == "throttled"
        assert c.reserve_partitions["exit"]["size"] == 50
        assert c.cdn_origin_keys == {"a.com": "o1"}
        assert c.reserve_tag_wildcards == ("shared",)
        assert c.store_backend == "sqlite"

    def test_store_must_be_sqlite(self, engine, monkeypatch):
        monkeypatch.setenv("BUDGET_CONSTITUTION", json.dumps(
            {"store": "postgres"}))
        with pytest.raises(ValueError, match="no postgres"):
            rt.constitution()

    def test_unknown_top_level_key_raises(self, engine, monkeypatch):
        monkeypatch.setenv("BUDGET_CONSTITUTION", json.dumps({"gandalf": 1}))
        with pytest.raises(ValueError, match="unknown key"):
            rt.constitution()

    def test_per_dim_requires_floor(self, engine, monkeypatch):
        monkeypatch.setenv("BUDGET_CONSTITUTION", json.dumps(
            {"per_dim": {"requests": {"ceiling": 500}}}))
        with pytest.raises(ValueError):
            rt.constitution()

    def test_controller_authority_bounds(self, engine, tmp_path, monkeypatch):
        cfg = self._write(tmp_path, {
            "controller": {"max_throttle_down": "throttled",
                           "max_speed_up": "soft_signal"}}, name="c2.yml")
        monkeypatch.setenv("BUDGET_CONSTITUTION_FILE", str(cfg))
        rt.reset_engine()
        ctl = rt.get_engine().controller
        assert ctl.max_throttle_down == "throttled"
        assert ctl.max_speed_up == "soft_signal"
        ha = "10.0.0.7"
        # hysteresis advances ONE level per k-streak; the cap sits at throttled
        ctl.observe(engagement=None, host_axis=ha, response_class="429",
                    now=1000.0)                       # streak 1 → still normal
        out = ctl.observe(engagement=None, host_axis=ha, response_class="429",
                          now=1001.0)                 # streak 2 → soft_signal
        assert out["state"] == "soft_signal"
        ctl.observe(engagement=None, host_axis=ha, response_class="429",
                    now=1003.0)
        ctl.observe(engagement=None, host_axis=ha, response_class="429",
                    now=1004.0)
        out2 = ctl.observe(engagement=None, host_axis=ha,
                           response_class="429", now=1005.0)
        assert out2["state"] == "throttled"           # hard evidence reached
        # NEVER backoff: further deepening refuses at the authority cap
        ctl.observe(engagement=None, host_axis=ha, response_class="reset",
                    now=1010.0)
        ctl.observe(engagement=None, host_axis=ha, response_class="reset",
                    now=1011.0)
        out3 = ctl.observe(engagement=None, host_axis=ha,
                           response_class="reset", now=1012.0)
        assert out3["state"] == "throttled"   # cap holds: no backoff, ever
        assert out3["streak"] >= 2            # evidence keeps counting, no burn
        # quiet decay: throttled → soft_signal, then PINNED there
        q = ctl.quiet_window_s
        o1 = ctl.observe(engagement=None, host_axis=ha, now=2000.0)
        o2 = ctl.observe(engagement=None, host_axis=ha, now=2000.0 + q)
        assert o2["state"] == "soft_signal"
        o3 = ctl.observe(engagement=None, host_axis=ha, now=2000.0 + 2 * q)
        assert o3["state"] == "soft_signal"   # max_speed_up rail holds
        rt.reset_engine()


# ─── L2 — wildcard reserve tags ──────────────────────────────────────────────

class TestL2Wildcards:
    def test_wildcard_covers_only_within_engagement(self, engine,
                                                    monkeypatch):
        monkeypatch.setenv("BUDGET_RESERVE_WILD_TAGS", "shared")
        s = engine.store
        const = rt.constitution()
        kw = _kw(const)
        tok1 = s.mint_reserve(partition="default", dims={},
                              max_vector={"requests": 400}, tag="shared",
                              engagement="alpha")
        s.release_reserve(tok1["token_id"])
        s.debit_vector(_decl(requests=600), _dims(engagement="alpha"),
                       tool="tests.t", now=1000.0, estimator="seed",
                       engagement="alpha", **kw)
        s.debit_vector(_decl(requests=600), _dims(engagement="beta"),
                       tool="tests.t", now=1000.0, estimator="seed",
                       engagement="beta", **kw)
        r1 = s.debit_vector(_decl(requests=50), _dims(engagement="beta"),
                            tool="tests.t", now=1000.0, estimator="seed",
                            engagement="beta", **kw)
        assert not r1["committed"]   # alpha-bound wildcard refuses beta
        # an UNBOUND wildcard token is a global fund — it covers any engagement
        tok2 = s.mint_reserve(partition="default", dims={},
                              max_vector={"requests": 400}, tag="wildcard-free",
                              engagement=None)
        s.release_reserve(tok2["token_id"])
        r2 = s.debit_vector(_decl(requests=50), _dims(engagement="alpha"),
                            tool="tests.t", now=1000.0, estimator="seed",
                            engagement="alpha", **kw)
        assert r2["committed"]
        assert r2["reserve_cover"]["wildcard_tag"] == "shared"
        r3 = s.debit_vector(_decl(requests=50), _dims(engagement="beta"),
                            tool="tests.t", now=1000.0, estimator="seed",
                            engagement="beta", **kw)
        assert r3["committed"]       # unbound token funds any engagement
        rc3 = r3.get("reserve_cover") or {}
        assert rc3.get("token_id") == tok2["token_id"]

    def test_no_wildcard_config_is_strict(self, engine, monkeypatch):
        monkeypatch.delenv("BUDGET_RESERVE_WILD_TAGS", raising=False)
        s = engine.store
        const = rt.constitution()
        kw = _kw(const)
        s.mint_reserve(partition="default",
                       dims={"host_axis": "10.0.0.7"},
                       max_vector={"requests": 400}, tag="shared",
                       engagement="alpha")
        toks = [r["token_id"] for r in s.list_reserves()]
        for t in toks:
            s.release_reserve(t)
        s.debit_vector(_decl(requests=600), _dims(engagement="alpha"),
                       tool="tests.t", now=1000.0, estimator="seed",
                       engagement="alpha", **kw)
        s.debit_vector(_decl(requests=600), _dims(engagement="beta"),
                       tool="tests.t", now=1000.0, estimator="seed",
                       engagement="beta", **kw)
        r2 = s.debit_vector(_decl(requests=50), _dims(engagement="alpha"),
                            tool="tests.t", now=1000.0, estimator="seed",
                            engagement="alpha", **kw)
        assert r2["committed"]       # exact-dims match covers
        rc = r2.get("reserve_cover") or {}
        assert rc.get("wildcard_tag") is None
        r1 = s.debit_vector(_decl(requests=50), _dims(engagement="beta"),
                            tool="tests.t", now=1000.0, estimator="seed",
                            engagement="beta", **kw)
        assert not r1["committed"]   # no env wildcards → strict dims only


# ─── L7 — honesty: fail closed, never green ──────────────────────────────────

class TestL7Honesty:
    def test_store_dir_unusable_fails_closed(self, tmp_path, monkeypatch):
        bad = tmp_path / "not_a_dir"
        bad.write_text("x")            # a FILE where the store dir goes
        monkeypatch.setenv("BUDGET_STORE_DIR", str(bad))
        monkeypatch.setenv("BUDGET_ENABLED", "1")
        for k in ("BUDGET_CONSTITUTION", "BUDGET_CONSTITUTION_FILE"):
            monkeypatch.delenv(k, raising=False)
        rt.reset_engine()
        try:
            with pytest.raises(RuntimeError, match="unusable"):
                rt.get_ration_store()
            env = rt.ration_gate("auxiliaries.web_session.session_get",
                                 {"target": "10.0.0.7"})
            assert env["status"] == "budget_refused"
            assert env.get("fail_closed") is True
        finally:
            rt.reset_engine()

    def test_bad_constitution_unknown_fail_closed(self, engine, monkeypatch):
        monkeypatch.setenv("BUDGET_CONSTITUTION", "{oops")
        out = engine.preflight("auxiliaries.web_session.session_get",
                               {"target": "10.0.0.7"}, now=1000.0)
        assert out["decision"] == "unknown"
        assert out["fail_closed"] is True

    def test_budget_status_reports_spans_and_partitions(
            self, engine, tmp_path, monkeypatch):
        cfg = tmp_path / "c3.yml"
        cfg.write_text(json.dumps({
            "reserve_partitions": {"entry": {"size": 100},
                                   "exit": {"size": 50}}}))
        monkeypatch.setenv("BUDGET_CONSTITUTION_FILE", str(cfg))
        engine.store.record_span(1, provenance="request",
                                 response_class="2xx",
                                 host_axis="10.0.0.7",
                                 ts=rt.budget_now())
        out = rt.budget_status()
        assert "spans:" in out and "10.0.0.7" in out
        assert "reserve partitions (advisory):" in out
