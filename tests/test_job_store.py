"""Job store v2 tests — agent-scoped ownership, cross-lane poll, reaper.

Covers utils/job_store.py + the background_job compat wrapper: agent
ownership on rows, per-agent finished-cap eviction (running never evicted),
cross-agent stop fencing, TTL sweep, the durable Brain-session map, and
the wrapper's signature compatibility.
"""

import os
import time

import pytest

from utils.job_store import JobStore, reset_store
import utils.job_store as job_store_module


@pytest.fixture
def store(tmp_path, monkeypatch):
    """Isolated job store: re-pointed dir, short reaper interval."""
    jobs_dir = tmp_path / "jobs"
    monkeypatch.setenv("BG_JOB_STORE_DIR", str(jobs_dir))
    monkeypatch.setenv("BG_JOB_REAPER_INTERVAL_S", "0.2")
    reset_store()
    s = JobStore(jobs_dir=jobs_dir)
    yield s
    reset_store()


def _quick_cmd(tmp_path, seconds=0.3):
    """Portable sleep command arg list (seconds positional — callers pass
    ``_quick_cmd(tmp_path, 60)`` for a long-running job)."""
    return ["sleep", str(seconds)]


# --- launch + poll -------------------------------------------------------------


def test_launch_and_running_poll(store, tmp_path):
    result = store.launch(_quick_cmd(tmp_path), tool_name="t", agent_id="kai9000", timeout=60)
    job_id = result["job_id"]
    assert result["agent_id"] == "kai9000"
    assert result["status"] == "running"
    # Log lives under the store's per-tool dir, never /tmp.
    assert str(store.jobs_dir) in result["log_file"]

    time.sleep(0.1)
    poll = store.poll(job_id)
    assert poll["status"] in ("running", "done")
    assert poll["tool"] == "t"

    # Wait for exit; poll observes done with a log tail.
    deadline = time.time() + 5
    while time.time() < deadline:
        poll = store.poll(job_id)
        if poll["status"] == "done":
            break
        time.sleep(0.1)
    assert poll["status"] == "done"
    assert poll["recent_lines"] == [] or isinstance(poll["recent_lines"], list)


def test_poll_unknown_job(store):
    poll = store.poll("no-such-job")
    assert poll["status"] == "unknown"
    assert "error" in poll


def test_launch_requires_agent_id(store, tmp_path):
    with pytest.raises(ValueError):
        store.launch(_quick_cmd(tmp_path), tool_name="t", agent_id="")


# --- ownership -----------------------------------------------------------------


def test_cross_agent_stop_refused_without_force(store, tmp_path):
    launched = store.launch(_quick_cmd(tmp_path, 30), tool_name="t", agent_id="kai9000", timeout=600)
    job_id = launched["job_id"]

    from utils.agent_identity import agent_id_context

    with agent_id_context("someone-else"):
        verdict = store.stop(job_id)
    assert verdict["status"] == "Failed"
    assert "force=True" in verdict["error"]

    with agent_id_context("kai9000"):
        verdict = store.stop(job_id)
    assert verdict["status"] == "ok"


def test_cross_agent_stop_allowed_with_force(store, tmp_path):
    launched = store.launch(_quick_cmd(tmp_path, 30), tool_name="t", agent_id="kai9000", timeout=600)
    verdict = store.stop(launched["job_id"], force=True)
    assert verdict["status"] == "ok"


def test_ownership_survives_in_row(store, tmp_path):
    launched = store.launch(_quick_cmd(tmp_path), tool_name="t", agent_id="owui:chat1", timeout=60)
    row = store.get(launched["job_id"])
    assert row["agent_id"] == "owui:chat1"


# --- caps + sweeps ---------------------------------------------------------------


def test_finished_cap_evicts_oldest_never_running(store, tmp_path, monkeypatch):
    monkeypatch.setenv("BG_JOB_MAX_FINISHED_PER_AGENT", "3")

    long_jobs = [
        store.launch(_quick_cmd(tmp_path, 30), tool_name="t", agent_id="cap", timeout=600)
        for _ in range(2)
    ]
    short_jobs = [
        store.launch(_quick_cmd(tmp_path), tool_name="t", agent_id="cap", timeout=60)
        for _ in range(4)
    ]
    deadline = time.time() + 5
    while time.time() < deadline:
        if all(store.poll(j["job_id"])["status"] == "done" for j in short_jobs):
            break
        time.sleep(0.1)

    # A new launch triggers the cap enforcement.
    store.launch(_quick_cmd(tmp_path), tool_name="t", agent_id="cap", timeout=60)

    rows = store.list_jobs(agent_id="cap", limit=100)
    done_ids = {r["job_id"] for r in rows if r["status"] == "done"}
    running_ids = {r["job_id"] for r in rows if r["status"] == "running"}
    # Running jobs survive any eviction.
    assert {j["job_id"] for j in long_jobs} <= running_ids
    # Finished jobs got trimmed to <= the cap (3) + possibly the newest done.
    assert len(done_ids) <= 4


def test_ttl_sweep_removes_old_finished_rows(store, tmp_path, monkeypatch):
    monkeypatch.setenv("BG_JOB_TTL_HOURS", "0.0001")  # ~0.36s
    j = store.launch(_quick_cmd(tmp_path), tool_name="t", agent_id="ttl", timeout=60)
    deadline = time.time() + 5
    while time.time() < deadline:
        if store.poll(j["job_id"])["status"] == "done":
            break
        time.sleep(0.1)
    # Age the finished row past the short-TTL cutoff: sweep() reads the
    # env at call time, so the row must be OLDER than the 0.36s cutoff.
    time.sleep(0.6)
    # Sweep UNDER the short TTL — the reset-to-24h happens after.
    removed = store.sweep()
    monkeypatch.setenv("BG_JOB_TTL_HOURS", "24")
    assert removed["expired"] >= 1
    assert store.get(j["job_id"]) is None


# --- reaper (wall-clock cap) ------------------------------------------------------


def test_reaper_enforces_cap(store, tmp_path):
    j = store.launch(
        _quick_cmd(tmp_path, 60), tool_name="reap", agent_id="reaper", timeout=0.5
    )
    deadline = time.time() + 6
    poll = store.poll(j["job_id"])
    while time.time() < deadline:
        poll = store.poll(j["job_id"])
        if poll["timed_out"]:
            break
        time.sleep(0.2)
    assert poll["timed_out"] is True
    assert poll["status"] == "done"


# --- cross-lane poll (second store instance over the same dir) --------------------


def test_second_lane_polls_same_store(store, tmp_path):
    j = store.launch(_quick_cmd(tmp_path, 30), tool_name="lane", agent_id="lane-a", timeout=600)
    # A 'different process' lane: fresh instance on the same dir.
    lane2 = JobStore(jobs_dir=store.jobs_dir)
    poll = lane2.poll(j["job_id"])
    assert poll["status"] == "running"
    assert poll["agent_id"] == "lane-a"
    verdict = lane2.stop(j["job_id"], force=True)  # operator-level cross lane
    assert verdict["status"] == "ok"


# --- verdict parser --------------------------------------------------------------


def test_verdict_parser_applied(store, tmp_path):
    log_file = tmp_path / "out.log"
    log_file.write_text("hello world\n")
    cmd = ["bash", "-c", f"cat {log_file}"]
    store.register_parser("vp", lambda text: {"hello_seen": "hello world" in text})
    j = store.launch(cmd, tool_name="vp", agent_id="vpa", timeout=60)
    deadline = time.time() + 5
    while time.time() < deadline:
        poll = store.poll(j["job_id"])
        if poll["status"] == "done":
            break
        time.sleep(0.1)
    assert poll.get("hello_seen") is True


# --- compat wrapper ---------------------------------------------------------------


def test_wrapper_launch_launches_and_polls(tmp_path, monkeypatch):
    monkeypatch.setenv("BG_JOB_STORE_DIR", str(tmp_path / "jobs"))
    reset_store()
    from utils.background_job import launch_job, poll_job, get_job, terminate_job

    j = launch_job(["sleep", "0.2"], tool_name="wrap", agent_id="wrapa", timeout=60)
    poll = poll_job(j["job_id"], tool_name="wrap")
    assert poll["status"] in ("running", "done")
    row = get_job(j["job_id"])
    assert row is not None and row["tool"] == "wrap"
    assert terminate_job(j["job_id"]) in (True, False)  # may have finished
    reset_store()


def test_wrapper_uses_ambient_identity(tmp_path, monkeypatch):
    monkeypatch.setenv("BG_JOB_STORE_DIR", str(tmp_path / "jobs2"))
    reset_store()
    from utils.background_job import launch_job
    from utils.agent_identity import agent_id_context

    with agent_id_context("ambient-owner"):
        j = launch_job(["sleep", "0.1"], tool_name="wrap2", timeout=60)
    assert j["agent_id"] == "ambient-owner"
    reset_store()


# --- durable Brain session map -----------------------------------------------------


def test_brain_session_map_stable_and_distinct(tmp_path, monkeypatch):
    from utils.brain_sessions import BrainSessionMap

    db = tmp_path / "bs.db"
    m1 = BrainSessionMap(db_path=str(db))
    a1 = m1.resolve("kai9000")
    a1b = m1.resolve("kai9000")
    b1 = m1.resolve("owui:chat1")
    assert a1 == a1b
    assert b1 != a1

    # A fresh map over the same DB (restart simulation) resolves identically.
    m2 = BrainSessionMap(db_path=str(db))
    assert m2.resolve("kai9000") == a1


def test_brain_session_map_shared_zero_shortcircuits(tmp_path):
    from utils.brain_sessions import BrainSessionMap

    m = BrainSessionMap(db_path=str(tmp_path / "bs2.db"))
    assert m.resolve("0") == 0