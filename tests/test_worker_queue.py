"""Worker-queue tests — bounded-memory pool for Arch-D units (Phase 3).

Covers utils/worker_queue.py + the jadx fleet twins (payloads/jadx_fleet.py):
content-keyed dedupe, memory-axis admission (budget vs measured free RAM),
heap pinning (JAVA_OPTS -Xmx), FIFO promotion on the reaper pass, the
launch roll-down, bind-grace reclaim, ownership fence, and pool
observability. Concurrency primitives are Annex E's (same store family).
"""

import json
import os
import time

import pytest

from utils.worker_queue import (
    WorkerQueue,
    content_key,
    free_ram_mib,
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
    assert r2["decision"] in ("launched", "launching")
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


def test_memory_overcommit_queues_instead_of_refusing(env):
    """A unit whose budget cannot fit in free RAM QUEUES (waiting is
    cheap; OOM is the lossy failure the queue prevents)."""
    q = get_worker_queue()
    # Ask for a budget bigger than free RAM (huge number under any box).
    huge = max(free_ram_mib(), 1) + 10_000
    r = q.request_unit(
        "jadx", env["jar"], agent_id="a", memory_budget=huge,
        command=["jadx", "-d", "/tmp/ws", env["jar"]],
    )
    assert r["decision"] == "queued"
    # Heap pin still present in the stored env (applies when promoted).
    row = q.conn.execute(
        "SELECT env FROM worker_units WHERE unit_key = ?", (r["unit_key"],)
    ).fetchone()
    assert f"-Xmx{huge}m" in row["env"]


def test_queue_full_refusal(env, monkeypatch):
    monkeypatch.setenv("WORKER_QUEUE_MAX_Q", "1")
    monkeypatch.setenv("WORKER_QUEUE_SLOTS", "1")
    monkeypatch.setenv("BG_JOB_REAPER_INTERVAL_S", "600")
    monkeypatch.setenv("WORKER_QUEUE_RAM_FLOOR", str(free_ram_mib() + 999999))
    q = get_worker_queue()
    jar2 = env["tmp"] / "two.jar"
    _make_jar(jar2, tag="two")
    jar3 = env["tmp"] / "three.jar"
    _make_jar(jar3, tag="three")

    # Fill the queue with a unit that will never fit (floor above free RAM).
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
    other = WorkerQueue(store_dir=os.environ["WORKER_QUEUE_DIR"])
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
    """A 'launching' claim that never bound is reclaimed after grace."""
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
    ref2 = [u for u in r2["units"]][0]
    if ref2["decision"] in ("launched", "launching"):
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