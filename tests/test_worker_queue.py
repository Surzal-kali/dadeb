"""Worker-queue tests — bounded-memory pool for Arch-D units (Phase 3).

Covers utils/worker_queue.py + the jadx fleet twins (payloads/jadx_fleet.py):
content-keyed dedupe, memory-axis admission (budget vs measured free RAM),
heap pinning (JAVA_OPTS -Xmx), FIFO promotion on the reaper pass, the
launch roll-down, bind-grace reclaim, ownership fence, and pool
observability. Concurrency primitives are Annex E's (same store family).
"""

import os
import time

import pytest

from utils.worker_queue import (
    content_key,
    get_worker_queue,
    heap_pin_env,
    reset_worker_queue,
)
import utils.worker_queue as wq


STUB_JADX = """#!/bin/bash
# Stub jadx: parses -d OUT and writes a fake source tree; honors a
# STUB_SLEEP knob so tests can hold a slot.
OUT=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-d" ]; then OUT="$a"; fi
  prev="$a"
done
echo "[jadx-stub] args: $*" >&2
sleep "${STUB_SLEEP:-0.2}"
mkdir -p "$OUT/sources/com/example"
echo "public class Stub {}" > "$OUT/sources/com/example/Stub.java"
exit 0
"""


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Isolated queue + job store + PATH stub jadx + headroom knobs."""
    monkeypatch.setenv("WORKER_QUEUE_DIR", str(tmp_path / "wq"))
    monkeypatch.setenv("BG_JOB_STORE_DIR", str(tmp_path / "jobs"))
    monkeypatch.setenv("BG_JOB_REAPER_INTERVAL_S", "0.2")
    monkeypatch.setenv("WORKER_QUEUE_BIND_GRACE_S", "60")
    # Give the tests deterministic admission: floor low, so budgets rule.
    monkeypatch.setenv("WORKER_QUEUE_RAM_FLOOR", "64")
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    stub = bindir / "jadx"
    stub.write_text(STUB_JADX)
    stub.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
    jar = tmp_path / "probe.jar"
    _make_jar(jar, count=4, tag="probe")
    reset_worker_queue()
    from utils.job_store import reset_store

    reset_store()
    yield {"tmp": tmp_path, "jar": str(jar), "bin": bindir}
    reset_worker_queue()
    from utils.job_store import reset_store

    reset_store()


def _make_jar(path, count=4, tag="probe"):
    """Tiny valid-ish zip jadx-stub doesn't parse — the STUB is what runs,
    so the 'jar' only supports the content key."""
    import zipfile

    with zipfile.ZipFile(path, "w") as z:
        for i in range(count):
            z.writestr(f"{tag}{i}.txt", "stub")


def _drain(q, job_id, timeout=8):
    from utils.job_store import get_store

    deadline = time.time() + timeout
    while time.time() < deadline:
        s = get_store().poll(job_id)
        if s.get("status") == "done":
            return s
        time.sleep(0.1)
    return get_store().poll(job_id)


# --- content key ----------------------------------------------------------------


def test_content_key_is_byte_identity_not_path(tmp_path):
    a = tmp_path / "a.jar"
    b = tmp_path / "renamed.jar"
    _make_jar(a, tag="same")
    import shutil

    shutil.copy(a, b)  # identical bytes, different name
    assert content_key("jadx", str(a)) == content_key("jadx", str(b))


def test_content_key_differs_by_bytes_and_tool(tmp_path):
    a = tmp_path / "a.jar"
    c = tmp_path / "c.jar"
    _make_jar(a, tag="one")
    _make_jar(c, tag="two")
    assert content_key("jadx", str(a)) != content_key("jadx", str(c))
    assert content_key("jadx", str(a)) != content_key("burp", str(a))


def test_content_key_missing_file_still_resolves(tmp_path):
    k = content_key("jadx", str(tmp_path / "nope.jar"))
    assert k.startswith("jadx:p")  # path-fallback, never raises


def test_heap_pin_env_overrides_and_merges():
    env = heap_pin_env(640)
    assert env["JAVA_OPTS"] == "-Xms32m -Xmx640m"
    env2 = heap_pin_env(1024, {"JAVA_OPTS": "-XX:+UseG1GC", "OTHER": "x"})
    assert env2["JAVA_OPTS"] == "-XX:+UseG1GC -Xms32m -Xmx1024m"
    assert env2["OTHER"] == "x"


# --- admission + dedupe -----------------------------------------------------------


def test_admitted_launches_inline_and_binds(env):
    q = get_worker_queue()
    r = q.request_unit(
        "jadx", env["jar"], agent_id="a1", memory_budget=64,
        command=["jadx", "-d", "/tmp/ws", env["jar"]],
    )
    assert r["decision"] == "launched"
    assert r["job_id"]
    assert "-Xmx64m" in r["JAVA_OPTS"]
    # Row is 'launched' with the bound job.
    row = q.conn.execute(
        "SELECT * FROM worker_units WHERE unit_key = ?", (r["unit_key"],)
    ).fetchone()
    assert row["status"] == "launched" and row["job_id"] == r["job_id"]
    # Job actually runs under the stub.
    final = _drain(q, r["job_id"])
    assert final["status"] == "done"


def test_dedupe_running_returns_existing_job(env):
    q = get_worker_queue()
    r1 = q.request_unit(
        "jadx", env["jar"], agent_id="a1", memory_budget=64,
        command=["jadx", "-d", "/tmp/ws", env["jar"]],
    )
    r2 = q.request_unit(
        "jadx", env["jar"], agent_id="a2", memory_budget=64,
        command=["jadx", "-d", "/tmp/other", env["jar"]],
    )
    assert r1["decision"] == "launched"
    assert r2["decision"] == "duplicate"  # labelled at the source
    assert r2["state"] == "running"
    assert r2["job_id"] == r1["job_id"]  # the twin's ref, not a new launch
    assert "already running" in r2["message"]


def test_pool_full_queues_fifo(env, monkeypatch):
    monkeypatch.setenv("WORKER_QUEUE_SLOTS", "1")
    monkeypatch.setenv("BG_JOB_REAPER_INTERVAL_S", "600")  # no reaper help
    q = get_worker_queue()
    jar2 = env["tmp"] / "two.jar"
    _make_jar(jar2, tag="two")
    jar3 = env["tmp"] / "three.jar"
    _make_jar(jar3, tag="three")

    r1 = q.request_unit(
        "jadx", env["jar"], agent_id="a", memory_budget=64,
        command=["jadx", "-d", "/tmp/ws1", env["jar"]],
    )
    r2 = q.request_unit(
        "jadx", str(jar2), agent_id="a", memory_budget=64,
        command=["jadx", "-d", "/tmp/ws2", str(jar2)],
    )
    r3 = q.request_unit(
        "jadx", str(jar3), agent_id="a", memory_budget=64,
        command=["jadx", "-d", "/tmp/ws3", str(jar3)],
    )
    assert r1["decision"] == "launched"
    assert r2["decision"] == "queued" and r2["position"] == 1
    assert r3["decision"] == "queued" and r3["position"] == 2


def test_memory_overcommit_queues_instead_of_refusing(env, monkeypatch):
    """A unit whose budget cannot fit in free RAM NOW queues (waiting is
    cheap; OOM is the lossy failure the queue prevents) — but only while
    the box could EVENTUALLY back it (budget <= total - floor). Budgets
    above that capacity are a permanent impossibility; their refusal is
    tested separately."""
    monkeypatch.setattr(wq, "free_ram_mib", lambda: 2048)
    monkeypatch.setattr(wq, "_total_ram_mib", lambda: 8192)
    q = get_worker_queue()
    # 4096 MiB: above free-minus-floor (2048-64=1984), under capacity
    # (8192-64=8128) — transient shortfall, must queue.
    r = q.request_unit(
        "jadx", env["jar"], agent_id="a", memory_budget=4096,
        command=["jadx", "-d", "/tmp/ws", env["jar"]],
    )
    assert r["decision"] == "queued"
    # Heap pin still present in the stored env (applies when promoted).
    row = q.conn.execute(
        "SELECT env FROM worker_units WHERE unit_key = ?", (r["unit_key"],)
    ).fetchone()
    assert "-Xmx4096m" in row["env"]


def test_budget_impossible_refused_not_queued(env, monkeypatch):
    """budget > total - floor is a PERMANENT impossibility: free RAM can
    never grow past total, so queueing it would wedge the FIFO forever —
    refused with a clear reason, no row, no slot held."""
    monkeypatch.setattr(wq, "free_ram_mib", lambda: 2048)
    monkeypatch.setattr(wq, "_total_ram_mib", lambda: 8192)
    q = get_worker_queue()
    r = q.request_unit(
        "jadx", env["jar"], agent_id="a", memory_budget=9000,  # > 8192-64
        command=["jadx", "-d", "/tmp/ws", env["jar"]],
    )
    assert r["decision"] == "refused"
    assert r["reason"] == "budget_impossible"
    assert r["budget_capacity_mib"] == 8128
    rows = q.conn.execute(
        "SELECT * FROM worker_units WHERE unit_key = ?", (r["unit_key"],)
    ).fetchall()
    assert rows == []  # nothing queued — a permanent impossibility is policy


def test_unmeasurable_free_ram_fails_closed(env, monkeypatch):
    """Free RAM unreadable (probe returns 0): the admission gate cannot
    be verified, so it FAILS CLOSED with a clear reason instead of
    queueing a unit that may never launch."""
    monkeypatch.setattr(wq, "free_ram_mib", lambda: 0)
    monkeypatch.setattr(wq, "_total_ram_mib", lambda: 8192)
    q = get_worker_queue()
    r = q.request_unit(
        "jadx", env["jar"], agent_id="a", memory_budget=64,
        command=["jadx", "-d", "/tmp/ws", env["jar"]],
    )
    assert r["decision"] == "refused"
    assert r["reason"] == "memory_unmeasurable"
    rows = q.conn.execute(
        "SELECT * FROM worker_units WHERE unit_key = ?", (r["unit_key"],)
    ).fetchall()
    assert rows == []


def test_queue_full_refusal(env, monkeypatch):
    monkeypatch.setenv("WORKER_QUEUE_MAX_Q", "1")
    monkeypatch.setenv("WORKER_QUEUE_SLOTS", "1")
    monkeypatch.setenv("BG_JOB_REAPER_INTERVAL_S", "600")
    # Deterministic memory probes: free RAM below the budget, but the box
    # COULD back it eventually (total >> budget) — a transient shortfall
    # queues; only then does the queue cap refuse.
    monkeypatch.setattr(wq, "free_ram_mib", lambda: 100)
    monkeypatch.setattr(wq, "_total_ram_mib", lambda: 8192)
    q = get_worker_queue()
    jar2 = env["tmp"] / "two.jar"
    _make_jar(jar2, tag="two")

    # Fill the queue with a unit that cannot launch right now.
    r1 = q.request_unit(
        "jadx", env["jar"], agent_id="a", memory_budget=64,
        command=["jadx", "-d", "/tmp/ws1", env["jar"]],
    )
    assert r1["decision"] == "queued"
    r2 = q.request_unit(
        "jadx", str(jar2), agent_id="a", memory_budget=64,
        command=["jadx", "-d", "/tmp/ws2", str(jar2)],
    )
    assert r2["decision"] == "refused"
    assert r2["reason"] == "queue_full"


# --- promotion + release -----------------------------------------------------------


def test_advance_queue_releases_and_promotes_fifo(env, monkeypatch):
    monkeypatch.setenv("WORKER_QUEUE_SLOTS", "1")
    monkeypatch.setenv("STUB_SLEEP", "0.2")
    q = get_worker_queue()
    jar2 = env["tmp"] / "two.jar"
    _make_jar(jar2, tag="two")

    r1 = q.request_unit(
        "jadx", env["jar"], agent_id="a", memory_budget=64,
        command=["jadx", "-d", "/tmp/ws1", env["jar"]],
    )
    r2 = q.request_unit(
        "jadx", str(jar2), agent_id="a", memory_budget=64,
        command=["jadx", "-d", "/tmp/ws2", str(jar2)],
    )
    assert r2["decision"] == "queued"
    done = _drain(q, r1["job_id"])
    assert done["status"] == "done"

    # NOTE: the wired job-store reaper also runs advance_queue on its own
    # pass — it may claim the release/promotion FIRST. Assert the FINAL
    # state (slot freed + head launched), not which observer did it.
    deadline = time.time() + 8
    row2 = None
    while time.time() < deadline:
        q.advance_queue()  # contributes an observation if the reaper hasn't
        row2 = q.conn.execute(
            "SELECT status, job_id FROM worker_units WHERE unit_key = ?",
            (r2["unit_key"],),
        ).fetchone()
        if row2["status"] == "launched" and row2["job_id"]:
            break
        time.sleep(0.2)
    assert row2 is not None and row2["status"] == "launched" and row2["job_id"]
    final = _drain(q, row2["job_id"])
    assert final["status"] == "done"


def test_promotion_is_one_lane_wins(env, monkeypatch):
    """Two queue instances advancing the same queue must not double-launch
    the head (the guarded claim UPDATE yields one promoter)."""
    monkeypatch.setenv("WORKER_QUEUE_SLOTS", "1")
    q = get_worker_queue()
    jar2 = env["tmp"] / "two.jar"
    _make_jar(jar2, tag="two")
    q.request_unit(
        "jadx", env["jar"], agent_id="a", memory_budget=64,
        command=["jadx", "-d", "/tmp/ws1", env["jar"]],
    )
    r2 = q.request_unit(
        "jadx", str(jar2), agent_id="a", memory_budget=64,
        command=["jadx", "-d", "/tmp/ws2", str(jar2)],
    )
    assert r2["decision"] == "queued"
    # The first job must FINISH before the sweep can promote (FIFO: the
    # head blocks while its slot is held) — drain it, then race two lanes.
    from utils.job_store import get_store

    jobs = get_store().list_jobs(agent_id="a")
    first_job = [j for j in jobs if j["tool"] == "jadx_queue"][0]
    _drain(q, first_job["job_id"])
    other = wq.WorkerQueue(store_dir=os.environ["WORKER_QUEUE_DIR"])
    a = q.advance_queue()
    b = other.advance_queue()
    # Promotion may land in either sweep — but each row is claimed exactly
    # once (the guarded claim UPDATE): r2's key must hold ONE launched row
    # with a bound job, and no duplicate row for the same key.
    r2_row = q.conn.execute(
        "SELECT status, job_id FROM worker_units WHERE unit_key = ?",
        (r2["unit_key"],),
    ).fetchone()
    assert r2_row["status"] == "launched" and r2_row["job_id"]
    twin_rows = q.conn.execute(
        "SELECT COUNT(*) AS n FROM worker_units WHERE unit_key = ?",
        (r2["unit_key"],),
    ).fetchone()["n"]
    assert twin_rows == 1


def test_bind_grace_reclaims_crashed_launcher(env, monkeypatch):
    """A 'launching' claim that never bound is reclaimed after grace
    (legacy row without a launch stamp falls back to ``requested``)."""
    monkeypatch.setenv("WORKER_QUEUE_BIND_GRACE_S", "0.3")
    q = get_worker_queue()
    # Fake a crashed claim by inserting a 'launching' row directly.
    key = content_key("jadx", env["jar"])
    q.conn.execute(
        "INSERT INTO worker_units (unit_key, tool, target, agent_id, status, "
        " memory_budget, command, env, queued_at, requested) "
        "VALUES (?, 'jadx', ?, 'a', 'launching', 64, '[]', '{}', ?, ?)",
        (key, env["jar"], time.time() - 60, time.time() - 60),
    )
    out = q.sweep_stale()
    assert out["count"] == 1
    row = q.conn.execute(
        "SELECT status FROM worker_units WHERE unit_key = ?", (key,)
    ).fetchone()
    assert row["status"] == "cancelled"


def test_bind_grace_measured_from_claim_not_queue_entry(env, monkeypatch):
    """The bind-grace clock is the queued->launching claim stamp, not the
    queue-entry time: a long-queued unit's fresh claim must NOT be killed
    at the instant it finally launches."""
    monkeypatch.setenv("WORKER_QUEUE_BIND_GRACE_S", "0.3")
    q = get_worker_queue()
    key = content_key("jadx", env["jar"])
    now = time.time()
    long_ago = now - 3600
    q.conn.execute(
        "INSERT INTO worker_units (unit_key, tool, target, agent_id, status, "
        " memory_budget, command, env, queued_at, requested, launching_at) "
        "VALUES (?, 'jadx', ?, 'a', 'launching', 64, '[]', '{}', ?, ?, ?)",
        (key, env["jar"], long_ago, long_ago, now),
    )
    out = q.sweep_stale()
    assert out["count"] == 0  # fresh claim of a long-queued row — safe
    row = q.conn.execute(
        "SELECT status FROM worker_units WHERE unit_key = ?", (key,)
    ).fetchone()
    assert row["status"] == "launching"
    # The same claim aging PAST grace is reclaimed (the crashed-launcher case).
    q.conn.execute(
        "UPDATE worker_units SET launching_at = ? WHERE unit_key = ?",
        (now - 60, key),
    )
    out = q.sweep_stale()
    assert out["count"] == 1


def test_advance_queue_cancels_impossible_head(env, monkeypatch):
    """A legacy queued row whose budget is permanently impossible must
    not wedge strict FIFO: the advance cancels it and the REAL head
    promotes (the wedge the request-time cap now prevents, for rows
    queued before that cap existed)."""
    monkeypatch.setenv("WORKER_QUEUE_SLOTS", "1")
    monkeypatch.setenv("BG_JOB_REAPER_INTERVAL_S", "600")  # no periodic reaper
    monkeypatch.setattr(wq, "free_ram_mib", lambda: 2048)
    monkeypatch.setattr(wq, "_total_ram_mib", lambda: 8192)
    q = get_worker_queue()
    jar2 = env["tmp"] / "two.jar"
    _make_jar(jar2, tag="two")
    r1 = q.request_unit(
        "jadx", env["jar"], agent_id="a", memory_budget=64,
        command=["jadx", "-d", "/tmp/ws1", env["jar"]],
    )
    assert r1["decision"] == "launched"
    r_good = q.request_unit(
        "jadx", str(jar2), agent_id="a", memory_budget=64,
        command=["jadx", "-d", "/tmp/ws2", str(jar2)],
    )
    assert r_good["decision"] == "queued"  # slot held by r1
    # Legacy impossible head: older than the good row, budget > capacity.
    old = time.time() - 30
    q.conn.execute(
        "INSERT INTO worker_units (unit_key, tool, target, agent_id, status, "
        " memory_budget, command, env, queued_at, requested, note) "
        "VALUES ('jadx:pimpossible', 'jadx', ?, 'a', 'queued', 9000, "
        "'[]', '{}', ?, ?, '')",
        (env["jar"], old, old),
    )
    _drain(q, r1["job_id"])  # free the slot so promotion is possible
    adv = q.advance_queue()
    # The reaper also runs advance_queue in-process (a launch's pending
    # _REAPER_WAKE beats the interval), so cancel/promote may land on
    # either observer's counters — the contract is the final ledger
    # state, which is identical whichever pass wins the claim race.
    key_good = r_good["unit_key"]
    deadline = time.time() + 5
    row_good = None
    while time.time() < deadline:
        row_good = q.conn.execute(
            "SELECT status, job_id FROM worker_units WHERE unit_key = ?",
            (key_good,),
        ).fetchone()
        if row_good is not None and row_good["status"] in ("launched", "finished"):
            break
        time.sleep(0.05)
    row_imp = q.conn.execute(
        "SELECT status, job_id FROM worker_units "
        "WHERE unit_key = 'jadx:pimpossible'"
    ).fetchone()
    # The impossible head is gone from the FIFO (cancelled, never
    # launched) and the queue is un-wedged behind it.
    assert row_imp["status"] == "cancelled"
    assert row_imp["job_id"] is None
    assert row_good is not None
    assert row_good["status"] in ("launched", "finished")
    # No double launch: r1 is finished, the impossible head cancelled —
    # the only live claim left is the good row itself.
    rows = q.conn.execute(
        "SELECT unit_key FROM worker_units WHERE status IN "
        "('launching','launched')"
    ).fetchall()
    if row_good["status"] == "launched":
        assert len(rows) == 1 and rows[0]["unit_key"] == key_good
    else:
        assert rows == []


def test_launch_failure_deletes_claim_no_phantom(env, monkeypatch):
    """A command that cannot spawn: the claim is deleted, no row holds a
    slot, the decision is an honest refusal."""
    monkeypatch.setenv("WORKER_QUEUE_SLOTS", "1")
    q = get_worker_queue()
    r = q.request_unit(
        "jadx", env["jar"], agent_id="a", memory_budget=64,
        command=["/nonexistent-jadx-xyz", "-d", "/tmp/ws", env["jar"]],
    )
    assert r["decision"] == "refused"
    assert r["reason"] == "launch_failed"
    rows = q.conn.execute(
        "SELECT * FROM worker_units WHERE unit_key = ?", (r["unit_key"],)
    ).fetchall()
    assert rows == []  # claim deleted — no phantom slot holder


# --- ownership + cancellation -------------------------------------------------------


def test_cross_agent_release_needs_force(env):
    q = get_worker_queue()
    r = q.request_unit(
        "jadx", env["jar"], agent_id="owner", memory_budget=64,
        command=["jadx", "-d", "/tmp/ws", env["jar"]],
    )
    other = q.release_unit(r["unit_key"], agent_id="intruder")
    assert other["status"] == "refused"
    ok = q.release_unit(r["unit_key"], force=True)
    assert ok["status"] == "released"


def test_cancel_queued_refuses_launched(env, monkeypatch):
    monkeypatch.setenv("BG_JOB_REAPER_INTERVAL_S", "600")
    q = get_worker_queue()
    r = q.request_unit(
        "jadx", env["jar"], agent_id="a", memory_budget=64,
        command=["jadx", "-d", "/tmp/ws", env["jar"]],
    )
    cancel = q.cancel_unit(r["unit_key"], agent_id="a")
    assert cancel["status"] == "refused"  # launched — terminate the JOB instead


def test_reaper_pass_advances_queue(env, monkeypatch):
    """The job-store reaper pass advances the queue (wired integration).

    The stub finishes in ~0.1s and the reaper ticks every 0.2s, so by the
    time we look, the promoted unit may ALREADY be 'finished' (ran, slot
    freed) — the FULL successful lifecycle is the contract, not the
    transient 'launched' snapshot:
      queued → launched (job_id) AND its job reaches done.
    """
    monkeypatch.setenv("WORKER_QUEUE_SLOTS", "1")
    monkeypatch.setenv("BG_JOB_REAPER_INTERVAL_S", "0.2")
    monkeypatch.setenv("STUB_SLEEP", "0.1")
    q = get_worker_queue()
    jar2 = env["tmp"] / "two.jar"
    _make_jar(jar2, tag="two")
    r1 = q.request_unit(
        "jadx", env["jar"], agent_id="a", memory_budget=64,
        command=["jadx", "-d", "/tmp/ws1", env["jar"]],
    )
    r2 = q.request_unit(
        "jadx", str(jar2), agent_id="a", memory_budget=64,
        command=["jadx", "-d", "/tmp/ws2", str(jar2)],
    )
    assert r2["decision"] == "queued"
    deadline = time.time() + 10
    row2 = None
    stall_trace: list[str] = []
    while time.time() < deadline:
        adv = q.advance_queue()  # alongside the reaper's own advance
        row2 = q.conn.execute(
            "SELECT status, job_id FROM worker_units WHERE unit_key = ?",
            (r2["unit_key"],),
        ).fetchone()
        stall_trace.append(
            f"adv(freed={adv['freed']},prom={adv['promoted']},"
            f"blk={adv['blocked']},lf={adv['launch_failed']}) r2={row2['status']}"
        )
        # Contract: the head got a slot. 'launched' = running or waiting to
        # be observed; 'finished' = already ran AND freed (still success).
        if row2["status"] in ("launched", "finished"):
            break
        time.sleep(0.2)
    assert row2 is not None and row2["status"] in ("launched", "finished"), (
        f"queued head never promoted (last state {dict(row2) if row2 else None}) "
        f"— trace tail: {stall_trace[-8:]}"
    )
    if row2["status"] == "launched":
        assert row2["job_id"]
        final = _drain(q, row2["job_id"])
        assert final["status"] == "done"
    else:
        # finished rows carry the terminal transition; the job ran under
        # the same unit_key — its workspace was written by the stub.
        from utils.job_store import get_store

        assert get_store().stats()["total"] >= 2  # both units launched jobs


# --- jadx fleet twins (e2e through the stub) -----------------------------------------


def test_jadx_fleet_e2e_launch_and_status(env, monkeypatch):
    import payloads.jadx_fleet as jf
    from utils.agent_identity import agent_id_context

    monkeypatch.setenv("STUB_SLEEP", "0.1")
    with agent_id_context("fleet-user"):
        r = jf.jadx_fleet(env["jar"], memory_budget=64)
    assert r["status"] == "ok"
    assert r["decision_counts"].get("launched") == 1
    unit = r["units"][0]
    assert unit["job_id"]

    final = _drain(q := get_worker_queue(), unit["job_id"])
    assert final["status"] == "done"
    with agent_id_context("fleet-user"):
        st = jf.jadx_fleet_status(r["fleet_id"])
    assert st["status"] == "ok"
    # The advance sweep may have already released the unit — its terminal
    # state is 'finished' (ran + freed), not 'cancelled'. Either observed
    # state means the lifecycle ran; total unit rows is the real pin.
    assert sum(st["counts"].values()) >= 1
    assert st["counts"].get("cancelled", 0) == 0  # nothing stopped here


def test_jadx_fleet_dedupes_content(env, monkeypatch):
    import payloads.jadx_fleet as jf
    from utils.agent_identity import agent_id_context

    import shutil

    twin = env["tmp"] / "twin_of_probe.jar"
    shutil.copy(env["jar"], twin)  # identical bytes, different name
    with agent_id_context("fleet-user"):
        r1 = jf.jadx_fleet(env["jar"], memory_budget=64)
        r2 = jf.jadx_fleet(f"{env['tmp'] / 'twin_of_probe.jar'}", memory_budget=64)
    assert r1["decision_counts"].get("launched") == 1
    # Second request hits the running unit — one unit total across both.
    jobs1 = [u.get("job_id") for u in r1["units"] if u.get("job_id")]
    ref2 = r2["units"][0]
    assert ref2["decision"] == "duplicate"  # labelled by the queue itself
    assert ref2["state"] == "running"
    assert ref2["job_id"] in jobs1


def test_jadx_fleet_batch_queues_when_full(env, monkeypatch):
    import payloads.jadx_fleet as jf
    from utils.agent_identity import agent_id_context

    monkeypatch.setenv("WORKER_QUEUE_SLOTS", "1")
    monkeypatch.setenv("BG_JOB_REAPER_INTERVAL_S", "600")
    monkeypatch.setenv("STUB_SLEEP", "3")
    jar2 = env["tmp"] / "two.jar"
    _make_jar(jar2, tag="two")
    with agent_id_context("fleet-user"):
        r = jf.jadx_fleet(f"{env['jar']},{jar2}", memory_budget=64)
    assert r["status"] == "ok"
    assert r["decision_counts"].get("launched") == 1
    assert r["decision_counts"].get("queued") == 1
    # stop must handle both states
    with agent_id_context("fleet-user"):
        st = jf.jadx_fleet_stop(r["fleet_id"])
    assert st["status"] == "ok"
    assert st["stopped_jobs"] or st["cancelled_queued"]


def test_worker_queue_status_lens(env):
    import payloads.jadx_fleet as jf
    from utils.agent_identity import agent_id_context

    with agent_id_context("lens-user"):
        jf.jadx_fleet(env["jar"], memory_budget=64)
        out = jf.worker_queue_status()
    assert out["slots"] >= 1
    assert out["free_ram_mib"] >= 0
    assert len(out["units"]) == 1

# --- RSS feedback: record the measured peak, admit from the evidence ----


def _seed_evidence(q, unit_key, tool="jadx", peak=512.0, budget=64.0):
    """Pre-record a run's peak for a content key (as advance_queue would
    at finish) without having to launch anything."""
    now = time.time()
    q.conn.execute(
        "INSERT INTO worker_rss (unit_key, tool, peak_rss_mib, memory_budget, "
        "runs, finished_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?)",
        (unit_key, tool, peak, budget, now, now),
    )


def test_rss_evidence_recorded_on_finish(env, monkeypatch):
    """A finished unit's measured worst footprint (kernel VmHWM read while
    it ran) lands on the row and in the evidence table, next to the claim
    it ran under. Stub sleeps long enough that the reaper's advance pass
    always samples at least once."""
    monkeypatch.setenv("STUB_SLEEP", "1.0")
    q = get_worker_queue()
    r = q.request_unit(
        "jadx", env["jar"], agent_id="a1", memory_budget=64,
        command=["jadx", "-d", "/tmp/ws", env["jar"]],
    )
    assert r["decision"] == "launched"
    _drain(q, r["job_id"])
    deadline = time.time() + 5
    while time.time() < deadline:
        ev = q.rss_evidence()
        if ev:
            break
        q.advance_queue()
        time.sleep(0.1)
    ev = q.rss_evidence()
    assert len(ev) == 1
    assert ev[0]["unit_key"] == r["unit_key"]
    assert ev[0]["tool"] == "jadx"
    assert ev[0]["memory_budget"] == 64
    assert 0 < ev[0]["peak_rss_mib"] < 500  # bash VmHWM: single-digit MiB
    # The ledger row carries the same peak, and poll_unit surfaces it.
    units = q.host_pressure()["units"]
    assert units[0]["peak_rss_mib"] > 0
    st = q.poll_unit(r["unit_key"])
    assert st["status"] == "finished"
    assert st.get("peak_rss_mib") > 0
    # The pid exposure that makes sampling possible is in the poll return.
    from utils.job_store import get_store

    assert get_store().poll(r["job_id"]).get("pid")


def test_rss_evidence_informs_claim_envelope(env, monkeypatch):
    """A future request of the SAME bytes carries an additively-stamped,
    evidence-backed claim (max of budget and recorded peak); a fresh
    content key with no evidence keeps the plain-budget envelope shape."""
    q = get_worker_queue()
    jar2 = env["tmp"] / "two.jar"
    _make_jar(jar2, tag="two")
    _seed_evidence(q, content_key("jadx", jar2), peak=512.0, budget=64.0)
    r = q.request_unit(
        "jadx", str(jar2), agent_id="a1", memory_budget=64,
        command=["jadx", "-d", "/tmp/ws2", str(jar2)],
    )
    # Unconstrained RAM on any dev box: launched. (If the box is squeezed
    # the decision is queued — either way the claim stamp must be there.)
    assert r["decision"] in ("launched", "queued")
    assert r["claim_mib"] == 512
    assert r["evidence_peak_mib"] == 512.0
    assert "peaked at 512 MiB" in r["message"]
    fresh = env["tmp"] / "evidence_free.jar"
    _make_jar(fresh, tag="clean")
    r2 = q.request_unit(
        "jadx", str(fresh), agent_id="a2", memory_budget=64,
        command=["jadx", "-d", "/tmp/ws3", str(fresh)],
    )
    assert r2["decision"] in ("launched", "queued")
    assert "claim_mib" not in r2  # no evidence → no additive stamps
    assert "evidence_peak_mib" not in r2


def test_rss_evidence_changes_queue_decision(env, monkeypatch):
    """The claim is the admission currency: with free RAM staged so a
    plain 64 MiB budget fits but the measured 512 MiB peak does not, the
    evidence-backed request QUEUES where the guess-backed one would
    have launched straight into the same over-commitment."""
    monkeypatch.setattr(wq, "free_ram_mib", lambda: 448)
    # Floor is 64 (fixture) → usable 384: budget 64 fits, claim 512 doesn't.
    q = get_worker_queue()
    jar2 = env["tmp"] / "three.jar"
    _make_jar(jar2, tag="three")
    _seed_evidence(q, content_key("jadx", jar2), peak=512.0, budget=64.0)
    r = q.request_unit(
        "jadx", str(jar2), agent_id="a1", memory_budget=64,
        command=["jadx", "-d", "/tmp/ws4", str(jar2)],
    )
    assert r["decision"] == "queued"
    assert r["claim_mib"] == 512
    fresh = env["tmp"] / "four.jar"
    _make_jar(fresh, tag="four")
    r2 = q.request_unit(
        "jadx", str(fresh), agent_id="a2", memory_budget=64,
        command=["jadx", "-d", "/tmp/ws5", str(fresh)],
    )
    assert r2["decision"] == "launched"  # same arithmetic, no evidence


def test_evidence_bump_refuses_permanent_impossibility(env, monkeypatch):
    """An evidence-backed claim above total-minus-floor is refused
    (budget_impossible) with the measurement named — a box that cannot
    back the bytes' MEASURED appetite will not admit them with a token
    claim."""
    monkeypatch.setattr(wq, "free_ram_mib", lambda: 2048)
    monkeypatch.setattr(wq, "_total_ram_mib", lambda: 1024)
    q = get_worker_queue()
    _seed_evidence(q, content_key("jadx", env["jar"]), peak=8192.0)
    r = q.request_unit(
        "jadx", env["jar"], agent_id="a1", memory_budget=64,
        command=["jadx", "-d", "/tmp/ws6", env["jar"]],
    )
    assert r["decision"] == "refused"
    assert r["reason"] == "budget_impossible"
    assert r["claim_mib"] == 8192
    assert r["evidence_peak_mib"] == 8192.0
    assert "peaked at 8192 MiB" in r["message"]


def test_rss_evidence_ttl_sweep(env, monkeypatch):
    """Evidence ages out (WORKER_QUEUE_EVIDENCE_TTL_HOURS) — old
    measurements stop constraining new runs."""
    monkeypatch.setenv("WORKER_QUEUE_EVIDENCE_TTL_HOURS", "0.001")
    q = get_worker_queue()
    _seed_evidence(q, content_key("jadx", env["jar"]))
    q.conn.execute(
        "UPDATE worker_rss SET updated_at = ? WHERE unit_key = ?",
        (time.time() - 100, content_key("jadx", env["jar"])),
    )
    adv = q.advance_queue()
    assert adv.get("evidence_swept", 0) >= 1
    assert q.rss_evidence() == []


# --- terminal-row re-requests (2026-10-30 PK-conflict fix) --------------------------


def test_rerun_of_finished_unit_points_at_run(env):
    """Re-requesting a COMPLETED unit's identical bytes returns a
    duplicate pointing at the finished run (state=finished + job_id) —
    never a second launch, and never the IntegrityError the old fall-
    through-to-INSERT produced (PK conflict on worker_units.unit_key)."""
    q = get_worker_queue()
    r = q.request_unit(
        "jadx", env["jar"], agent_id="a1", memory_budget=64,
        command=["jadx", "-d", "/tmp/ws-fin", env["jar"]],
    )
    assert r["decision"] == "launched"
    _drain(q, r["job_id"])
    q.advance_queue()  # release the done job → status='finished'
    again = q.request_unit(
        "jadx", env["jar"], agent_id="a2", memory_budget=64,
        command=["jadx", "-d", "/tmp/ws-fin2", env["jar"]],
    )
    assert again["decision"] == "duplicate"
    assert again["state"] == "finished"
    assert again["job_id"] == r["job_id"]
    assert "retrievable by job_id" in again["message"]


def test_rerun_after_cancel_launches_fresh_row(env, monkeypatch):
    """A cancelled unit's re-request is a FRESH decision: the terminal row
    is dropped, the new request launches (release_unit's fresh-row
    promise — previously an IntegrityError)."""
    monkeypatch.setenv("STUB_SLEEP", "4.0")
    q = get_worker_queue()
    r = q.request_unit(
        "jadx", env["jar"], agent_id="a1", memory_budget=64,
        command=["jadx", "-d", "/tmp/ws-c", env["jar"]],
    )
    assert r["decision"] == "launched"
    q.release_unit(r["unit_key"], agent_id="a1")
    # Stop the cancelled run's own job so no 4s orphan outlives the test.
    from utils.job_store import get_store

    get_store().stop(r["job_id"], force=True)
    monkeypatch.setenv("STUB_SLEEP", "0.1")
    again = q.request_unit(
        "jadx", env["jar"], agent_id="a2", memory_budget=64,
        command=["jadx", "-d", "/tmp/ws-c2", env["jar"]],
    )
    assert again["decision"] == "launched", again
    _drain(q, again["job_id"])
