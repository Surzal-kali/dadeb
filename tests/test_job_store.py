"""Job store v2 tests — agent-scoped ownership, cross-lane poll, reaper.

Covers utils/job_store.py + the background_job compat wrapper: agent
ownership on rows, per-agent finished-cap eviction (running never evicted),
cross-agent stop fencing, TTL sweep, the durable Brain-session map, and
the wrapper's signature compatibility.
"""

import os
import time
from pathlib import Path

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


# --- log-file garbage collect (2026-10-29) ------------------------------------------


def test_log_gc_deletes_files_of_collected_rows_keeps_fresh(store, tmp_path, monkeypatch):
    """Files of rows ALREADY collected (TTL/cap) are deleted past the keep
    window; fresh files (young mtime) survive even with no row at all."""
    import os as _os

    monkeypatch.setenv("BG_LOG_GC_HOURS", "48")
    # The launch below anchors an UNTHROTTLED GC pass at _enforce_caps —
    # build all fixtures BEFORE launching so that pass sees the intended
    # state, and reset the throttle afterward for the explicit test pass.
    from utils import job_store as jsm

    jsm._LOG_GC_LAST = time.time()  # suppress anchored passes mid-setup

    tool_dir = store.jobs_dir / "gone"
    tool_dir.mkdir(parents=True, exist_ok=True)
    old_log = tool_dir / "gone_deadbeef.log"
    old_log.write_text("old runner log\n")
    past = time.time() - 49 * 3600
    os.utime(old_log, (past, past))

    fresh_orphan_dir = store.jobs_dir / "orphan"
    fresh_orphan_dir.mkdir(parents=True, exist_ok=True)
    fresh_orphan = fresh_orphan_dir / "orphan_fresh.log"
    fresh_orphan.write_text("just started\n")

    # A row still present (young file): its log must survive any pass.
    r = store.launch(["sleep", "0.1"], tool_name="kept", agent_id="gca", timeout=60)
    kept_log = Path(r["log_file"])
    assert kept_log.exists()

    jsm._LOG_GC_LAST = 0.0  # let the explicit test pass through
    out = store._log_garbage_collect(force=True)
    assert out["deleted"] >= 1
    assert not old_log.exists()          # collected row's old log: gone
    assert kept_log.exists()             # live row: kept
    assert fresh_orphan.exists()         # young, no row: kept


def test_log_gc_prunes_empty_tool_dirs_and_throttles(store, tmp_path, monkeypatch):
    """A per-tool dir left empty by the GC is pruned; a second immediate
    non-forced pass is skipped by the interval throttle."""
    import os as _os

    monkeypatch.setenv("BG_LOG_GC_HOURS", "1")
    from utils import job_store as jsm

    jsm._LOG_GC_LAST = 0.0
    tool_dir = store.jobs_dir / "swept"
    tool_dir.mkdir(parents=True, exist_ok=True)
    old_log = tool_dir / "swept_abc123.log"
    old_log.write_text("x\n")
    past = time.time() - 2 * 3600
    os.utime(old_log, (past, past))

    first = store._log_garbage_collect(force=True)
    assert first["deleted"] == 1
    assert not tool_dir.exists()         # empty dir pruned

    second = store._log_garbage_collect()  # not forced; interval was just stamped
    assert second.get("skipped") == "interval"


def test_log_gc_disabled_by_zero_window(tmp_path, monkeypatch):
    monkeypatch.setenv("BG_LOG_GC_HOURS", "0")
    s2 = JobStore(jobs_dir=tmp_path / "gc0")
    out = s2._log_garbage_collect(force=True)
    assert out.get("disabled") is True


def test_garbage_collect_logs_public_entry(store, monkeypatch):
    from utils.job_store import garbage_collect_logs

    monkeypatch.setenv("BG_LOG_GC_HOURS", "1")
    tool_dir = store.jobs_dir / "pub"
    tool_dir.mkdir(parents=True, exist_ok=True)
    old = tool_dir / "pub_1.log"
    old.write_text("x\n")
    past = time.time() - 2 * 3600
    import os as _os

    os.utime(old, (past, past))
    out = garbage_collect_logs(force=True)
    assert out["deleted"] == 1
    assert not old.exists()


# --- launch orphan window (2026-10-29) ----------------------------------------------


def test_launch_popen_failure_leaves_no_row_or_handle(store, tmp_path):
    """A command that cannot spawn (missing binary) must raise (no row is
    minted, so no zombie "running" phantom with pid NULL) and must not
    leak the log handle or its empty sidecar file."""
    with pytest.raises(FileNotFoundError):
        store.launch(
            ["/nonexistent-binary-xyz", "--flag"],
            tool_name="orph", agent_id="orph-a", timeout=60,
        )
    # No row for the agent; the (empty) log sidecar for the failed job is
    # unlinked, not left behind.
    assert store.list_jobs(agent_id="orph-a") == []
    tool_dir = store.jobs_dir / "orph"
    if tool_dir.exists():
        assert sorted(p.name for p in tool_dir.iterdir()) == []


def test_launch_insert_failure_rolls_down_spawned(store, tmp_path, monkeypatch):
    """The dangerous window: Popen SUCCEEDS, then the row INSERT fails.
    The launch must roll DOWN — the spawned tree is terminated, reaped and
    deregistered, and no row is written (a pid-without-row launch envelope
    would hand the model a job_id every poll answers "unknown")."""

    class FailingConn:
        """Wrapper over a real connection: the INSERT statement fails
        (sqlite3.Connection.execute is read-only, so the seam is a proxy)."""

        def __init__(self, real, sqlite3_mod):
            self._real = real
            self._s3 = sqlite3_mod

        def execute(self, sql, *a, **kw):
            if "INSERT INTO jobs" in sql:
                raise self._s3.OperationalError("database is locked (test)")
            return self._real.execute(sql, *a, **kw)

        def __getattr__(self, name):
            return getattr(self._real, name)

    s = JobStore(jobs_dir=tmp_path / "roll")
    real_conn_property = type(s).conn
    try:
        type(s).conn = property(
            lambda self: FailingConn(real_conn_property.fget(self), s._sqlite3)
        )
        with pytest.raises(s._sqlite3.OperationalError):
            s.launch(["sleep", "30"], tool_name="roll", agent_id="roll-a", timeout=600)
    finally:
        type(s).conn = real_conn_property
    # Rolled down: no row; the spawned child must be gone (killed + reaped).
    time.sleep(0.2)
    assert [j for j in s.list_jobs(agent_id="roll-a") if j["tool"] == "roll"] == []
    for proc in list(s._live_proc.values()):
        assert proc.poll() is not None  # reaped — no orphan kept running



# --- brain-session fallback band (2026-10-29) ----------------------------------------


def test_brain_session_fallback_band_disjoint_from_store_ints(tmp_path, monkeypatch):
    """Degraded fallback ints live in a high random band: they never equal
    a durable-store int, so a degraded lane's calls can never land on
    another agent's Brain session."""
    from utils.brain_sessions import BrainSessionMap, _FALLBACK_BAND_BASE

    db = tmp_path / "bs.band.db"
    healthy = BrainSessionMap(db_path=str(db))
    durable = {f"agent-{i}": healthy.resolve(f"agent-{i}") for i in range(5)}
    assert max(durable.values()) < _FALLBACK_BAND_BASE

    # Degraded instance: point at an un-openable path.
    bad = BrainSessionMap(db_path="/proc/no/such/dir/bs.db")
    assert bad.degraded
    fbx = bad.resolve("agent-3")           # same agent id as the healthy map
    fby = bad.resolve("agent-4")
    assert fbx >= _FALLBACK_BAND_BASE and fby >= _FALLBACK_BAND_BASE
    assert fbx != fby
    # Collision guarantee: the degraded lane's ints match NONE of the
    # durable ints — the Brain could never route X's calls into Y's session.
    assert fbx not in set(durable.values())
    assert fby not in set(durable.values())
    # Stable within the degraded instance (same agent keeps its slot),
    # and int-valued (the wire field is a C int).
    assert bad.resolve("agent-3") == fbx
    assert isinstance(fbx, int)


def test_brain_session_fallback_token_stable_per_instance(tmp_path, monkeypatch):
    """One degraded instance keeps ONE band offset across repeated store
    failures (a repeating store must not re-randomize the lane's slots)."""
    from utils.brain_sessions import BrainSessionMap

    bad = BrainSessionMap(db_path="/proc/definitely/not/a/db/2")
    tok = bad._fallback_token
    a = bad.resolve("x-agent")
    b = bad.resolve("y-agent")
    assert bad._fallback_token == tok
    assert b == a + 1  # same band, same instance → contiguous slots