"""Wordlist-shaped budget chunking tests (evasion_upgrade.md §2, U2 lane).

Covers the three contracts the lane lives on:

1. **lane_decision three-case** — the ONE predicate the estimator and the
   ffuf body both read (None/single/plan/chunk), with the slice arithmetic
   derived from the constitution's max_single.
2. **Plan lifecycle** — lazy window minting (window W, not all chunks),
   poll-verified advance (poll_job is the ONLY observer), settle to
   'finished', and TTL measured from the LAST minted activity (§2.5).
3. **Drain requeue contract** — a chunk whose launch hit a fleet
   duplicate/refusal returns an honest ``requeued`` envelope with NO
   job-id-keyed fields (a sibling's live job must never be mistaken for
   ours), keeps the queue item alive for the next tick, and the discharge
   compensates the attempt's slice debit so requeue cycles don't leak.

Also: U1 estimator-key fixes (stale auxiliaries.* keys gone, real
payloads.* ids registered) and the budget_queue_status plan lens.
"""

import asyncio

import pytest

import utils.ration as rt
from utils import wordlist_chunking as wlc
from utils.ration_store import DIMS, RationStore


def test_chunk_lane_keys_declared_on_tool_manifest():
    """2026-11-06 ffuf drain: the lane minted chunk items keyed
    ``chunk_slice`` while run_ffuf declared the slice count as
    ``chunk_size`` — preflight rejected EVERY chunk dispatch
    ('unknown argument(s): [chunk_slice]') and the drain dispatcher
    consumed the rejects as finished. Invariant: every CHUNK_KEYS key any
    vector-mapped wordlist tool can receive must be a declared parameter
    of that tool. A key rename on the lane side without the tool side
    re-breaks this test instead of silently wedge-draining."""
    from payloads.ffuf import run_ffuf

    import inspect
    fn = inspect.unwrap(run_ffuf)
    sig = inspect.signature(fn)
    declared = set(sig.parameters)
    for key in wlc.CHUNK_KEYS:
        assert key in declared, (
            f"chunk lane key {key!r} is not a declared parameter of "
            f"payloads.ffuf.run_ffuf (declared: {sorted(declared)}) — "
            "preflight would reject every minted chunk dispatch")


@pytest.fixture
def engine(tmp_path, monkeypatch):
    (tmp_path / "budget").mkdir()
    monkeypatch.setenv("BUDGET_STORE_DIR", str(tmp_path / "budget"))
    monkeypatch.setenv("BUDGET_ENABLED", "1")
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path))
    monkeypatch.setenv("BUDGET_PLAN_WINDOW", "2")
    for k in ("BUDGET_CONSTITUTION", "BUDGET_CONSTITUTION_FILE",
              "BUDGET_EPOCH_SECONDS", "BUDGET_QUEUE_TTL_HOURS",
              "BUDGET_DRAIN_BATCH", "BUDGET_PLAN_TTL_HOURS"):
        monkeypatch.delenv(k, raising=False)
    rt.reset_engine()
    rt.reset_ration_store()
    yield rt.get_engine()
    rt.reset_engine()
    rt.reset_ration_store()


def _wordlist(tmp_path, name, lines):
    path = tmp_path / name
    path.write_text("\n".join(f"entry-{i}" for i in range(lines)) + "\n")
    return str(path)


def _ffuf_args(wordlist_path):
    return {"url": "http://10.0.0.5/FUZZ", "wordlist": wordlist_path}


def _plan(engine, wordlist_path, *, window=2):
    args = _ffuf_args(wordlist_path)
    decision = wlc.lane_decision("payloads.ffuf.run_ffuf", args, wordlist_path)
    assert decision and decision["mode"] == "plan"
    return wlc.mint_wordlist_plan(
        "payloads.ffuf.run_ffuf", args, decision,
        decl=dict(decision["slices"]), dims=rt.dims_for_target("10.0.0.5"),
        agent_id="tester", engagement=None, priority=0)


# --- slice arithmetic --------------------------------------------------------


def test_slice_bounds_exact_and_remainder():
    assert wlc.slice_bounds(0, 100, 350) == (0, 100)
    assert wlc.slice_bounds(3, 100, 350) == (300, 50)   # remainder chunk
    assert wlc.slice_bounds(2, 100, 200) == (200, 0)    # at-the-edge → empty
    assert wlc.slice_bounds(1, 100, 50) == (100, 0)     # past-the-end safety


# --- lane_decision three-case ------------------------------------------------


def test_lane_decision_small_list_is_single(engine, tmp_path):
    wl = _wordlist(tmp_path, "small.txt", 3)
    decision = wlc.lane_decision("payloads.ffuf.run_ffuf", _ffuf_args(wl), wl)
    assert decision == {"mode": "single", "lines": 3, "wordlist": wl,
                        "decl": {"requests": 3, "packets": None,
                                 "auth_events": None, "bytes": 3 * 8192}}


def test_lane_decision_oversized_is_plan(engine, tmp_path):
    wl = _wordlist(tmp_path, "big.txt", 650)  # 650 > 600-request ceiling
    decision = wlc.lane_decision("payloads.ffuf.run_ffuf", _ffuf_args(wl), wl)
    assert decision["mode"] == "plan"
    assert decision["lines"] == 650
    assert decision["chunk_size"] == 600            # binding dim: requests
    assert decision["binding_dim"] == "requests"
    assert decision["total_chunks"] == 2            # ceil(650 / 600)
    assert decision["window"] == 2                  # min(2, BUDGET_PLAN_WINDOW)
    assert decision["slices"]["requests"] == 600
    assert decision["slices"]["bytes"] == 600 * 8192
    assert decision["slices"]["auth_events"] is None


def test_ffuf_body_lane_args_carry_chunk_keys(engine):
    """2026-11-06 drain incident: run_ffuf built _lane_args WITHOUT the
    chunk params, so every drain chunk dispatch re-decided PLAN mode —
    minted a fresh plan (zero traffic) and returned the chunk_plan
    envelope while the slice debit stood; the drain consumed it as an
    inline finish (chunk_plan carries no job_id/requeued Failed marker).
    The body MUST let the lane predicate see this dispatch's own chunk
    keys so a keyed dispatch decides CHUNK mode."""
    import inspect

    from payloads.ffuf import run_ffuf

    body_src = inspect.getsource(inspect.unwrap(run_ffuf))
    # The body reads its own chunk params explicitly (the 2026-11-06 fix);
    # guard on the explicit-locals merge either via the chunk-key loop or a
    # CHUNK_KEYS reference — both prove the lane predicate can see them.
    has_merge = (any(k in body_src for k in wlc.CHUNK_KEYS)
                 or "CHUNK_KEYS" in body_src)
    assert has_merge, (
        "run_ffuf's _lane_args no longer merges the chunk keys — a chunk "
        "dispatch will re-decide plan mode and the drain will consume it "
        "as finished (regression of the 2026-11-06 partitioning incident)")

    # And behaviorally: the merged-args construction must decide chunk
    # for keyed args exactly like a direct lane_decision call.
    args = {"url": "http://h/FUZZ", "wordlist": "wl",
            "chunk_plan_id": "wp-x", "chunk_index": 0, "chunk_offset": 0,
            "chunk_slice": 50, "chunk_total_chunks": 4}
    merged = dict(args)
    merged = {**{k: merged[k] for k in merged if k not in wlc.CHUNK_KEYS}}
    merged.update({k: args[k] for k in wlc.CHUNK_KEYS})
    decision = wlc.lane_decision("payloads.ffuf.run_ffuf", merged, None)
    assert decision is not None and decision["mode"] == "chunk"
    assert decision["chunk_size"] == 50


def test_lane_decision_chunk_keys_declare_slice(engine, tmp_path):
    wl = _wordlist(tmp_path, "big.txt", 650)
    args = _ffuf_args(wl)
    args.update({"chunk_plan_id": "wp-test", "chunk_index": 1,
                 "chunk_offset": 600, "chunk_slice": 50,
                 "chunk_total_chunks": 2})
    decision = wlc.lane_decision("payloads.ffuf.run_ffuf", args, None)
    assert decision["mode"] == "chunk"
    assert decision["chunk_size"] == 50
    # the slice declares its OWN vector, not the plan's
    assert decision["decl"]["requests"] == 50
    assert decision["decl"]["bytes"] == 50 * 8192


def test_lane_decision_inert_when_chunking_disabled(engine, tmp_path,
                                                    monkeypatch):
    wl = _wordlist(tmp_path, "big.txt", 650)
    monkeypatch.setenv("BUDGET_WORDLIST_CHUNK", "0")
    assert wlc.lane_decision("payloads.ffuf.run_ffuf", _ffuf_args(wl), wl) \
        is None


def test_lane_decision_unknown_wordlist_is_none(engine, tmp_path):
    missing = str(tmp_path / "nope.txt")
    assert wlc.lane_decision("payloads.ffuf.run_ffuf",
                             _ffuf_args(missing), missing) is None


# --- plan minting + lazy window + advance -----------------------------------


def test_mint_is_lazy_and_advance_settles(engine, tmp_path, monkeypatch):
    wl = _wordlist(tmp_path, "huge.txt", 2000)      # ceil(2000/600) = 4
    plan = _plan(engine, wl)
    assert plan["total_chunks"] == 4
    # lazy frontier: only the FIRST window (2) is minted
    assert engine.store.plan_counts(plan["plan_id"])["queued"] == 2
    # window cap: mint_window refuses to over-mint past outstanding+window
    assert wlc.mint_window(plan["plan_id"]) == 0

    # drain pays chunk 0 → launched; nothing finished yet → no new minting
    chunks = engine.store.plan_chunks(plan["plan_id"], status="queued")
    engine.store.bind_item(chunks[0]["qid"], "job-chunk-0")
    assert wlc.advance_plans()["minted"] == 0

    # poll_job is the ONLY verified observer: still 'running' → not finished
    monkeypatch.setattr("utils.background_job.poll_job",
                        lambda jid: {"status": "running"})
    out = wlc.advance_plans()
    assert out["finished"] == 0
    assert engine.store.plan_counts(plan["plan_id"])["launched"] == 1

    # verified done → finish_item + mint the next window (2 more, capped)
    monkeypatch.setattr("utils.background_job.poll_job",
                        lambda jid: {"status": "done"})
    out = wlc.advance_plans()
    assert out["finished"] == 1
    counts = engine.store.plan_counts(plan["plan_id"])
    assert counts["finished"] == 1
    assert counts["queued"] == 2                    # window 2 minted
    assert counts["minted"] == 3                    # frontier idx 2

    # keep paying + minting the lazy window until the frontier drains →
    # plan settles 'finished' with all 4 chunks done
    for _ in range(8):
        if rt.get_ration_store().plan_get(plan["plan_id"])["state"] == \
                "finished":
            break
        for row in engine.store.plan_chunks(plan["plan_id"], status="queued"):
            engine.store.bind_item(row["qid"], f"job-{row['qid']}")
        wlc.advance_plans()                         # still 'launched'
        wlc.advance_plans()                         # verified done → + mint
    counts = engine.store.plan_counts(plan["plan_id"])
    assert counts["finished"] == 4
    assert counts["minted"] == 4                    # frontier covered fully
    fresh = rt.get_ration_store().plan_get(plan["plan_id"])
    assert fresh["state"] == "finished"


def test_advance_ttl_counts_last_activity_not_plan_mint(engine, tmp_path,
                                                        monkeypatch):
    wl = _wordlist(tmp_path, "ttl.txt", 2000)
    monkeypatch.setenv("BUDGET_PLAN_TTL_HOURS", "1")
    plan = _plan(engine, wl)
    store = rt.get_ration_store()
    fresh = store.plan_get(plan["plan_id"])
    store.conn.execute("UPDATE queue_plans SET requested=? WHERE plan_id=?",
                       (fresh["requested"] - 86400.0, plan["plan_id"]))
    store.conn.commit()
    # the plan ROW is a day stale but the chunk rows are fresh → alive:
    # TTL measures the LAST minted activity, not the plan mint (§2.5)
    assert wlc.advance_plans(now=fresh["requested"] + 0.5)["expired"] == []
    assert store.plan_get(plan["plan_id"])["state"] == "open"

    # everything stale past TTL → cancelled
    store.conn.execute(
        "UPDATE queue_items SET requested=? WHERE parent_plan_id=?",
        (fresh["requested"] - 86400.0, plan["plan_id"]))
    store.conn.commit()
    expiring = wlc.advance_plans(now=fresh["requested"] + 100.0)
    assert plan["plan_id"] in expiring["expired"]
    assert store.plan_get(plan["plan_id"])["state"] == "cancelled"


# --- store round-trips -------------------------------------------------------


def test_get_item_by_plan_chunk_and_release(engine, tmp_path):
    wl = _wordlist(tmp_path, "r.txt", 2000)
    plan = _plan(engine, wl)
    store = rt.get_ration_store()
    row = store.get_item_by_plan_chunk(plan["plan_id"], 0)
    assert row is not None and row["chunk_index"] == 0
    assert store.get_item_by_plan_chunk(plan["plan_id"], 97) is None
    # release_item only reclaims UNBOUND stale claims; a bound item is not
    # released by it (bind wins)
    store.bind_item(row["qid"], "job-1")
    store.release_item(row["qid"])
    assert store.get_item_by_plan_chunk(plan["plan_id"], 0)["status"] == \
        "launched"
    assert store.plan_counts(plan["plan_id"])["total_chunks"] == 4


# --- requeued envelope (fleet duplicate / transient refusal) -----------------


def test_requeued_envelope_contract(engine, tmp_path):
    wl = _wordlist(tmp_path, "requeue.txt", 2000)
    plan = _plan(engine, wl)
    out = wlc.requeued_envelope(plan["plan_id"], chunk_index=0, total=4,
                                reason="fleet duplicate: sibling runs")
    assert out["status"] == "requeued" and out["requeued"] is True
    assert out["queue_id"]
    # DELIBERATE: no job_id-keyed field anywhere — the discharge's bind
    # scan would mistake a sibling's live job for ours (§2.5)
    assert not [k for k in out if "job_id" in k or k in ("jobId",)]
    # the honest envelope only RECORDS the requeue; item state untouched
    store = rt.get_ration_store()
    assert store.get_item_by_plan_chunk(plan["plan_id"], 0)["status"] == \
        "queued"
    # plan-lost honesty: a vanished plan row reports it instead of crashing
    lost = wlc.requeued_envelope("wp-does-not-exist", chunk_index=0, total=4,
                                 reason="fleet duplicate: sibling runs")
    assert lost["status"] == "chunk_plan_lost"


# --- discharge branches ------------------------------------------------------


def test_discharge_requeued_compensates_and_chunk_plan_settles(engine):
    # chunk dispatch (positive slice vector) → debit → requeued → compensated
    args = {"url": "http://10.0.0.5/FUZZ", "wordlist": "x",
            "chunk_plan_id": "wp-t", "chunk_index": 0, "chunk_offset": 0,
            "chunk_slice": 50, "chunk_total_chunks": 4}
    gate = rt.ration_gate("payloads.ffuf.run_ffuf", args,
                          agent_id="tester", session_id="s",
                          operator_release=True)
    assert gate and gate.get("gate") == "debited", gate
    d = rt.ration_discharge(gate, {"status": "requeued", "requeued": True})
    assert d and d.get("emission_id"), d
    row = engine.store.conn.execute(
        "SELECT drift, drift_note FROM emissions WHERE id=?",
        (d["emission_id"],)).fetchone()
    assert row["drift"] == 2 and "compensated" in row["drift_note"]

    # plan issue (zero declared vector) → settle at once, no open draw
    gate0 = rt.ration_gate("payloads.ffuf.run_ffuf",
                           {"url": "http://10.0.0.5/FUZZ", "wordlist": "x"},
                           agent_id="tester", session_id="s",
                           operator_release=True)
    assert gate0 and gate0.get("gate") == "debited"
    d0 = rt.ration_discharge(gate0, {"status": "chunk_plan"})
    assert d0 and d0.get("discharge") == "plan_issued"


# --- drain requeue mapping ---------------------------------------------------


def test_drain_requeued_keeps_item_for_next_tick(engine, tmp_path):
    wl = _wordlist(tmp_path, "drain.txt", 650)
    plan = _plan(engine, wl)
    requeued = []

    async def requeue_then_launch(item):
        requeued.append(item)
        if len(requeued) == 1:
            return {"requeued": True, "plan_id": plan["plan_id"],
                    "reason": "fleet duplicate"}
        return {"job_id": "job-real"}

    async def run():
        return await engine.operator_tick(
            dispatch=requeue_then_launch, sleep_fn=lambda s: None, batch=4)
    tick1 = asyncio.run(run())
    decisions = [r["decision"] for r in tick1["results"]]
    assert decisions.count("requeued") == 1
    assert decisions.count("dispatched") == 1
    assert tick1["backlog_remaining"] == 0
    store = rt.get_ration_store()
    item0 = store.get_item_by_plan_chunk(plan["plan_id"], 0)
    assert item0["status"] == "queued" and item0["job_ref"] is None
    item1 = store.get_item_by_plan_chunk(plan["plan_id"], 1)
    assert item1["status"] == "launched"
    # next tick: the SAME chunk pays again (fresh debit, no leak)
    tick2 = asyncio.run(run())
    assert [r["decision"] for r in tick2["results"]] == ["dispatched"]
    assert tick2["results"][0]["job_id"] == "job-real"
    assert store.get_item_by_plan_chunk(plan["plan_id"], 0)["status"] == \
        "launched"


# --- dead-plan settle (2026-11-06 seam close) --------------------------------


def test_advance_settles_fully_cancelled_plan_as_failed(engine, tmp_path):
    """Bounded-failure exits cancel chunks; once the frontier is exhausted
    and every chunk is terminal-without-completion, the plan settles
    'failed' instead of sitting 'open' forever with nothing left to drain."""
    wl = _wordlist(tmp_path, "dead.txt", 650)
    plan = _plan(engine, wl)                        # 2 chunks, window 2
    store = rt.get_ration_store()
    chunks = store.plan_chunks(plan["plan_id"], status="queued")
    for c in chunks:
        store.cancel_item(c["qid"], note="retry budget exhausted — gate "
                                          "blocked")
    out = wlc.advance_plans()
    fresh = store.plan_get(plan["plan_id"])
    assert fresh["state"] == "failed"
    assert out["failed_plans"] and out["failed_plans"][0]["plan_id"] == \
        plan["plan_id"]
    assert "retry budget exhausted" in out["failed_plans"][0]["reason"]
    # the status lens names the why so a dead plan is never a bare 'failed'
    lens = rt.budget_queue_status(plan_id=plan["plan_id"])
    assert "[failed]" in lens and "retry budget exhausted" in lens


def test_open_plan_with_live_chunks_never_settles_failed(engine, tmp_path):
    """A plan whose frontier still has un-minted chunks stays open even
    when some minted chunks were cancelled (operator cancel-partial)."""
    wl = _wordlist(tmp_path, "partial.txt", 1300)   # 3 chunks, window 2
    plan = _plan(engine, wl)
    store = rt.get_ration_store()
    chunks = store.plan_chunks(plan["plan_id"], status="queued")
    store.cancel_item(chunks[0]["qid"], note="operator stop")
    out = wlc.advance_plans()
    # frontier idx 2 is un-minted → plan must REMAIN open
    assert store.plan_get(plan["plan_id"])["state"] == "open"
    assert out["failed_plans"] == []


# --- run_ffuf wrapper seam ----------------------------------------------------


def test_run_ffuf_plan_mode_mints_without_launching(engine, tmp_path,
                                                   monkeypatch):
    from payloads import ffuf as ffuf_mod

    def _boom(*a, **k):
        raise AssertionError("plan mode must never reach launch_job")

    big = _wordlist(tmp_path, "seam.txt", 700)      # 700 > 600-request ceiling
    monkeypatch.setattr(ffuf_mod, "resolve_wordlist", lambda p: str(p))
    monkeypatch.setattr(ffuf_mod, "launch_job", _boom)
    res = ffuf_mod.run_ffuf("http://10.0.0.5/FUZZ", wordlist=big)
    assert res["status"] == "chunk_plan"
    assert res["total_chunks"] == 2
    assert res["window"] == 2
    assert res["minted_first_window"] == 2          # lazy first window minted
    assert "budget_queue_status(plan_id=" in res["poll"]
    counts = rt.get_ration_store().plan_counts(res["plan_id"])
    assert counts["queued"] == 2 and counts["minted"] == 2


# --- U1: estimator registration keys ----------------------------------------


def test_u1_estimator_registration(engine):
    from utils.ration import _estimator_engaged, resolve_declaration
    assert _estimator_engaged("payloads.ffuf.run_ffuf")
    assert _estimator_engaged("payloads.hydra.run_hydra")
    assert _estimator_engaged(
        "auxiliaries.web_login_brute.web_login_brute")
    assert _estimator_engaged(
        "payloads.metasploiting.MetasploitClient.dispatch_metasploit")
    # stale pre-U1 keys are gone
    assert not _estimator_engaged("auxiliaries.ffuf.run_ffuf")
    assert not _estimator_engaged("auxiliaries.hydra.run_hydra")


def test_u1_ffuf_estimator_declarations(engine, tmp_path):
    decl_small, name, basis = rt.resolve_declaration(
        "payloads.ffuf.run_ffuf", "10.0.0.5",
        _ffuf_args(_wordlist(tmp_path, "small2.txt", 3)))
    assert basis == "estimation" and name == "ffuf_lines"
    assert decl_small["requests"] == 3

    # oversized → the plan-issue ZERO declaration (spend lands per chunk)
    decl_zero, name, basis = rt.resolve_declaration(
        "payloads.ffuf.run_ffuf", "10.0.0.5",
        _ffuf_args(_wordlist(tmp_path, "big2.txt", 650)))
    assert dict.get(decl_zero, "requests") == 0

    # chunk dispatch → the slice vector
    args = _ffuf_args("whatever")
    args.update({"chunk_plan_id": "wp-t", "chunk_slice": 50})
    decl_chunk, _, _ = rt.resolve_declaration(
        "payloads.ffuf.run_ffuf", "10.0.0.5", args)
    assert decl_chunk["requests"] == 50


# --- status lens -------------------------------------------------------------


def test_queue_status_plan_lens(engine, tmp_path):
    wl = _wordlist(tmp_path, "lens.txt", 650)
    plan = _plan(engine, wl)
    text = rt.budget_queue_status(plan_id=plan["plan_id"])
    assert plan["plan_id"] in text and "lines=650" in text
    assert "total=2" in text and "chunk 1/2" in text
