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
import json

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
    monkeypatch.setenv("BUDGET_CONSTITUTION",
                       '{"release_jitter": {"min": 0.0, "max": 0.0}}')
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
    # pkg7: the slice binds on what ONE epoch funds (requests refill 150
    # per code default), not the 600-request burst ceiling
    assert decision["chunk_size"] == 150            # binding dim: requests
    assert decision["binding_dim"] == "requests"
    assert decision["total_chunks"] == 5            # ceil(650 / 150)
    assert decision["window"] == 2                  # min(2, BUDGET_PLAN_WINDOW)
    assert decision["pace_epoch_s"] == 300.0
    assert decision["slices"]["requests"] == 150
    assert decision["slices"]["bytes"] == 150 * 8192
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
    wl = _wordlist(tmp_path, "huge.txt", 2000)      # ceil(2000/150) = 14
    plan = _plan(engine, wl)
    assert plan["total_chunks"] == 14
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
    # plan settles 'finished' with all 14 chunks done
    for _ in range(120):
        if rt.get_ration_store().plan_get(plan["plan_id"])["state"] == \
                "finished":
            break
        for row in engine.store.plan_chunks(plan["plan_id"], status="queued"):
            engine.store.bind_item(row["qid"], f"job-{row['qid']}")
        wlc.advance_plans()                         # still 'launched'
        wlc.advance_plans()                         # verified done → + mint
    counts = engine.store.plan_counts(plan["plan_id"])
    assert counts["finished"] == 14
    assert counts["minted"] == 14                   # frontier covered fully
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
    assert store.plan_counts(plan["plan_id"])["total_chunks"] == 14


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
    plan = _plan(engine, wl)
    store = rt.get_ration_store()
    # cancel every chunk as it is lazily minted until the frontier runs
    # out (window 2 of 5); the advance that settles the plan reports it
    out = {"failed_plans": []}
    for _ in range(64):
        leftovers = store.plan_chunks(plan["plan_id"], status="queued")
        if not leftovers:
            break
        for c in leftovers:
            store.cancel_item(c["qid"], note="retry budget exhausted — gate "
                                             "blocked")
        out = wlc.advance_plans()
        if out["failed_plans"]:
            break
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

    big = _wordlist(tmp_path, "seam.txt", 700)      # 700 > 150-epoch slice
    monkeypatch.setattr(ffuf_mod, "resolve_wordlist", lambda p: str(p))
    monkeypatch.setattr(ffuf_mod, "launch_job", _boom)
    res = ffuf_mod.run_ffuf("http://10.0.0.5/FUZZ", wordlist=big)
    assert res["status"] == "chunk_plan"
    assert res["total_chunks"] == 5
    assert res["paced"] is True
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
    assert "total=5" in text and "chunk 1/5" in text


# --- §3.1 verified behaviorally (2026-11-07) ---------------------------------

def test_run_ffuf_chunk_keyed_body_launches_slice(engine, tmp_path,
                                                  monkeypatch):
    """§3.1, behavioral (the 2026-11-06 UDS discriminant in-process): with
    a REAL plan minted, a body call carrying its chunk keys must launch the
    SLICE (the -w arg is the plan's materialized slice file for this
    index) and NEVER re-mint or mint extra plans. A keyed call that
    returns a chunk_plan envelope is the phantom-mint bug; error-status is
    the honest degenerate (missing plan)."""
    import inspect
    import os

    import utils.scope_gate as sg
    from payloads.ffuf import run_ffuf

    wl = _wordlist(tmp_path, "big.txt", 650)
    plan = _plan(engine, wl)
    pid = plan["plan_id"]
    store = rt.get_ration_store()
    items = store.due_items()
    assert items, "plan mint pre-mints its first lazy window"
    item = items[0]
    args = json.loads(item["arguments_json"])
    assert args.get("chunk_plan_id") == pid

    captured = {}

    def fake_launch(command, **kwargs):
        captured["command"] = list(command)
        captured["kwargs"] = kwargs
        return {"job_id": 4242}

    monkeypatch.setattr(sg, "check_scan", lambda target: (True, ""))
    monkeypatch.setattr("payloads.ffuf.launch_job", fake_launch)

    minted_before = store.plan_counts(pid)["minted"]
    out = inspect.unwrap(run_ffuf)(**args)
    assert out.get("job_id") == 4242, \
        f"keyed dispatch must LAUNCH, not re-mint: {out}"
    assert out.get("chunk_plan_id") == pid
    assert out.get("chunk_index") == item["chunk_index"] + 1
    wl_arg = captured["command"][captured["command"].index("-w") + 1]
    assert wl_arg.endswith(f"{pid}/{item['chunk_index']}.txt"), \
        f"slice file must be the launched wordlist, got {wl_arg}"
    assert out.get("wordlist") == wl_arg
    # results never live in /tmp (debt §4 P0): -o lands in the job dir
    o_arg = captured["command"][captured["command"].index("-o") + 1]
    assert f"{os.sep}run{os.sep}jobs{os.sep}ffuf" in o_arg and o_arg not in (
        "/tmp",), "ffuf -o must live under <workspace>/run/jobs/ffuf"
    # no plan growth: the keyed call never re-minted (+no window bump)
    assert store.plan_counts(pid)["minted"] == minted_before


def test_run_ffuf_keyed_bogus_plan_honest_error(engine, tmp_path,
                                                monkeypatch):
    """§3.1 negative: a keyed call whose plan is gone returns the honest
    error envelope — and mints NOTHING (the phantom-mint shape)."""
    import inspect

    import utils.scope_gate as sg
    from payloads.ffuf import run_ffuf

    wl = _wordlist(tmp_path, "small.txt", 3)
    monkeypatch.setattr(sg, "check_scan", lambda target: (True, ""))
    args = {"url": "http://10.0.0.5/FUZZ", "wordlist": wl,
            "chunk_plan_id": "wp-nope", "chunk_index": 0,
            "chunk_offset": 0, "chunk_slice": 3, "chunk_total_chunks": 1}
    out = inspect.unwrap(run_ffuf)(**args)
    assert out.get("job_id") is None
    assert out.get("status") == "error"
    assert "no longer exists" in out.get("error", "")
    store = rt.get_ration_store()
    n_plans = store.conn.execute(
        "SELECT COUNT(*) FROM queue_plans").fetchone()[0]
    assert n_plans == 0, "an honest-error keyed call must not mint a plan"


# --- pkg7: epoch-bound slices + wire pacing ----------------------------------


@pytest.fixture
def law_engine(tmp_path, monkeypatch):
    """The engine fixture, with an explicit law: requests refill 80 per
    epoch over a 200s epoch; sizes otherwise at code defaults."""
    (tmp_path / "budget").mkdir()
    monkeypatch.setenv("BUDGET_STORE_DIR", str(tmp_path / "budget"))
    monkeypatch.setenv("BUDGET_ENABLED", "1")
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path))
    monkeypatch.setenv("BUDGET_PLAN_WINDOW", "2")
    for k in ("BUDGET_CONSTITUTION", "BUDGET_CONSTITUTION_FILE",
              "BUDGET_EPOCH_SECONDS", "BUDGET_QUEUE_TTL_HOURS",
              "BUDGET_DRAIN_BATCH", "BUDGET_PLAN_TTL_HOURS"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("BUDGET_CONSTITUTION", (
        '{"per_dim": {'
        '"requests": {"ceiling": 600, "refill_per_epoch": 80, "floor": 2}, '
        '"packets": {"ceiling": 2000000, "refill_per_epoch": 250000, '
        '"floor": 500}, '
        '"auth_events": {"ceiling": 60, "refill_per_epoch": 5, '
        '"floor": 0.2}, '
        '"bytes": {"ceiling": 268435456, "refill_per_epoch": 33554432, '
        '"floor": 262144}}, '
        '"max_single_call": {"requests": 600}, "epoch_seconds": 200}'))
    rt.reset_engine()
    rt.reset_ration_store()
    yield rt.get_engine()
    rt.reset_engine()
    rt.reset_ration_store()


def test_lane_slices_to_epoch_refill_not_ceiling(law_engine, tmp_path):
    """pkg7 core shape change: a never-fit plan slices to what ONE epoch
    funds (the law's refill_per_epoch, 80 here), NOT the burst ceiling —
    the 600-request ceiling slice emptied a funded chunk at ffuf's own
    wire speed while the ledger refilled one epoch per chunk (bursts
    separated by minutes of dead air)."""
    wl = _wordlist(tmp_path, "law.txt", 650)
    decision = wlc.lane_decision("payloads.ffuf.run_ffuf", _ffuf_args(wl), wl)
    assert decision["mode"] == "plan"
    assert decision["chunk_size"] == 80
    assert decision["total_chunks"] == 9            # ceil(650 / 80)
    assert decision["pace_epoch_s"] == 200.0
    assert decision["slices"]["requests"] == 80


def test_lane_slice_clamps_to_one_request(engine, tmp_path):
    """A law whose refill is below one request's cost still yields a
    payable slice (floored at 1) — never a zero-n mint loop."""

    def _starved_law():
        from utils.ration import Constitution
        return Constitution(
            defaults={d: {"ceiling": 600.0, "refill_per_epoch": 0.5,
                          "floor": 2.0} for d in DIMS},
            max_single_call={"requests": 600},
            epoch_s=300.0, release_jitter={"min": 0.0, "max": 0.0})

    import utils.ration as rt_mod
    orig = rt_mod.constitution
    rt_mod.constitution = _starved_law
    try:
        wl = _wordlist(tmp_path, "clamped.txt", 700)
        decision = wlc.lane_decision("payloads.ffuf.run_ffuf",
                                     _ffuf_args(wl), wl)
    finally:
        rt_mod.constitution = orig
    assert decision is not None
    # 700 lines never fit max_single, but the refill band (0.5 per epoch)
    # floors the slice at 1 — a slice must never be unpayable
    assert decision["mode"] == "plan"
    assert decision["chunk_size"] == 1
    assert decision["total_chunks"] == 700


def test_epoch_pacing_math(engine):
    assert wlc.epoch_pacing(150) == {"rate_per_second": 1, "epoch_s": 300.0}
    assert wlc.epoch_pacing(1200)["rate_per_second"] == 4   # 1200/300s
    assert wlc.epoch_pacing(0) is None
    assert wlc.epoch_pacing(-5) is None


def test_wire_pacing_degrades_without_law(monkeypatch):
    """Constitution unreadable → pacing returns None and the launch stays
    unshaped (exactly the pkg6 behavior) — never a guessed rate."""

    def _boom():
        raise RuntimeError("law is gone")

    monkeypatch.setattr("utils.ration.constitution", _boom)
    assert wlc.epoch_funding() is None
    assert wlc.epoch_pacing(150) is None
    # and the ffuf helper propagates the degenerate case
    from payloads.ffuf import _inject_wire_pacing
    tokens: list = []
    assert _inject_wire_pacing(tokens, 150) is None
    assert tokens == []          # nothing injected on a failed law read


def test_wire_pacing_injection_respects_caller():
    from payloads.ffuf import _inject_wire_pacing
    tokens: list = []
    out = _inject_wire_pacing(tokens, 150)
    assert tokens == ["-rate", "1", "-t", "1"]
    assert out["applied"] == ["rate", "threads"]
    assert out["caller_wins"] == []

    tokens = ["-t", "80"]
    out = _inject_wire_pacing(tokens, 150)          # caller threads win
    assert tokens == ["-t", "80", "-rate", "1"]
    assert out["applied"] == ["rate"]
    assert out["caller_wins"] == ["threads"]

    tokens = ["-rate", "5"]
    out = _inject_wire_pacing(tokens, 150)          # caller rate win
    assert tokens == ["-rate", "5", "-t", "1"]
    assert out["caller_wins"] == ["rate"]


def test_chunk_dispatch_paces_the_wire(engine, tmp_path, monkeypatch):
    """The pkg7 point: a dispatched chunk's ffuf command carries the
    epoch pacing (-t 1 -rate slice/epoch) — the wire no longer bursts 150
    requests at default concurrency."""
    import inspect

    import utils.scope_gate as sg
    from payloads.ffuf import run_ffuf

    wl = _wordlist(tmp_path, "paced.txt", 2000)
    plan = _plan(engine, wl)
    store = rt.get_ration_store()
    item = store.get_item_by_plan_chunk(plan["plan_id"], 0)
    args = json.loads(item["arguments_json"])

    captured = {}

    def fake_launch(command, **kwargs):
        captured["command"] = list(command)
        return {"job_id": 4242}

    monkeypatch.setattr(sg, "check_scan", lambda target: (True, ""))
    monkeypatch.setattr("payloads.ffuf.launch_job", fake_launch)

    out = inspect.unwrap(run_ffuf)(**args)
    assert out.get("job_id") == 4242
    cmd = captured["command"]
    assert cmd[cmd.index("-rate") + 1] == "1"       # 150-slice, 300s epoch
    assert cmd[cmd.index("-t") + 1] == "1"
    pacing = out.get("wire_pacing")
    assert pacing["rate_per_second"] == 1 and pacing["epoch_s"] == 300.0
    assert pacing["applied"] == ["rate", "threads"]
    # -t/-rate stay inside options: the json output tail is still last
    assert cmd[-2] == "-o"


def test_chunk_dispatch_single_mode_leaves_wire_alone(engine, tmp_path,
                                                      monkeypatch):
    """Zero behavior change outside the chunk lane: a single-call (fits-in
    one) dispatch is NOT paced — pkg7 shapes chunks only."""
    import inspect

    import utils.scope_gate as sg
    from payloads.ffuf import run_ffuf

    wl = _wordlist(tmp_path, "small.txt", 3)
    captured = {}

    def fake_launch(command, **kwargs):
        captured["command"] = list(command)
        return {"job_id": 7}

    monkeypatch.setattr(sg, "check_scan", lambda target: (True, ""))
    monkeypatch.setattr("payloads.ffuf.launch_job", fake_launch)
    out = inspect.unwrap(run_ffuf)("http://10.0.0.5/FUZZ", wordlist=wl)
    assert out.get("job_id") == 7
    cmd = captured["command"]
    assert "-rate" not in cmd and "-t" not in cmd
    assert "wire_pacing" not in out
