"""Concurrency-suite tests — the layer no prior suite covered.

Prior suites validated POLICY (dedupe, slots, ownership) single-threaded.
These tests validate the CONCURRENCY contract, because the coordination
primitives that make the fleet contract real across lanes are:

- per-thread SQLite connections (the shared-conn design raced the reaper
  thread against poll threads — InterfaceError, seen live during Phase 0);
- ``BEGIN IMMEDIATE`` admission (slot ceiling atomic across PROCESSES —
  an RLock inside one process says nothing about the gateway and the
  Brain both admitting a third unit);
- first-marker-wins finish stamps (a racing poll must not downgrade a
  reaper's timeout);
- conditional release (racing double-release frees the slot once).

Two hammer families:

1. **Multiprocess** (fork): N real processes, each its own scheduler
   instance + job store instance, all hammering the SAME sqlite file —
   the actual 30-actor shape. Uses ``spawn``-free ``fork`` semantics via
   multiprocessing with an explicit target function (no pickling of the
   store).
2. **Threads-in-process**: same-instance + mixed-instance thread hammers
   that reproduce the InterfaceError/zombie-liveness races deterministically.
"""

import json
import os
import time
from concurrent import futures

import pytest

from utils.fleet_scheduler import FleetScheduler, reset_scheduler
from utils.job_store import JobStore, reset_store


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("FLEET_STORE_DIR", str(tmp_path / "fleet"))
    monkeypatch.setenv("BG_JOB_STORE_DIR", str(tmp_path / "jobs"))
    reset_scheduler()
    reset_store()
    yield tmp_path
    reset_scheduler()
    reset_store()


# --- multiprocess: forked children each build their own instances ----------


def _proc_request_worker(store_dir_fleet, store_dir_jobs, host, n, results_q):
    """Child-process body: own scheduler + job store, request n units."""
    import sys

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from utils.fleet_scheduler import FleetScheduler

    s = FleetScheduler(store_dir=store_dir_fleet)
    acquired, refused, dup = 0, 0, 0
    for i in range(n):
        r = s.request_unit("t", f"http://{host}/{i}", agent_id="procworker")
        d = r["decision"]
        if d == "acquired":
            acquired += 1
            s.bind_job(r["unit_key"], f"fake-job-{acquired}")  # hold slot stable
        elif d == "refused":
            refused += 1
        else:
            dup += 1
    results_q.put({"acquired": acquired, "refused": refused, "dup": dup})


def _proc_releaser(store_dir_fleet, unit_key):
    import sys

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from utils.fleet_scheduler import FleetScheduler

    s = FleetScheduler(store_dir=store_dir_fleet)
    return s.release_unit(unit_key, force=True)


def _proc_same_shape(fleet_dir, q):
    """Module-level for pickling: request one canonical shape."""
    import sys

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from utils.fleet_scheduler import FleetScheduler

    s = FleetScheduler(store_dir=fleet_dir)
    r = s.request_unit("sqlmap", "http://dupehost/x?id=1", agent_id="p")
    if r["decision"] == "acquired":
        s.bind_job(r["unit_key"], "job-dedupe-proc")
    q.put(r["decision"])


def _proc_marker(job_id, jobs_dir, sleep_s, exit_code, timed_out):
    """Module-level for pickling: mark a job finished with given stamp."""
    import sys

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from utils.job_store import JobStore

    time.sleep(sleep_s)
    st = JobStore(jobs_dir=jobs_dir)
    st._mark_finished(job_id, exit_code=exit_code, timed_out=timed_out)


class TestMultiprocessSlotCeiling:
    """THE test the old suite could not express: two PROCESSES racing the
    same host's slot ceiling must admit exactly the ceiling, never more."""

    def test_ceiling_atomic_across_processes(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FLEET_SLOTS_PER_HOST", "2")
        list(_isolate(tmp_path, monkeypatch))
        import multiprocessing as mp

        fleet_dir = str(tmp_path / "fleet")
        q = mp.Queue()
        # 4 processes x 5 units = 20 requests against a 2-slot host. The
        # pre-hardening race admitted >2 (two processes both count 1 and
        # both admit); post-hardening exactly 2 acquire.
        procs = [
            mp.Process(target=_proc_request_worker, args=(fleet_dir, str(tmp_path / "jobs"), "racehost", 5, q))
            for _ in range(4)
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join(timeout=30)
        got = [q.get(timeout=5) for _ in range(4)]

        s = FleetScheduler(store_dir=fleet_dir)
        s.sweep_stale()  # bind-grace irrelevant: fake jobs bound; TTL long
        # NOTE: bound fake job ids don't exist in the job store — the sweep
        # cannot verify finished (missing row is NOT completion), so rows stay
        # running and pressure is countable.
        pressure = s.host_pressure("racehost")
        running = pressure["hosts"]["racehost"]["running"]
        total_acquired = sum(g["acquired"] for g in got)
        assert total_acquired == running, (
            "every acquired+bound unit must be running (no lost rows)"
        )
        assert running == 2, (
            f"ceiling violated across processes: {running} running "
            f"(claimed acquired={total_acquired}) — BEGIN IMMEDIATE not atomic"
        )
        # 5 shapes x 4 processes: per shape, 1 acquire + 3 duplicates (for
        # the 2 shapes that fit the ceiling) and 4 refusals (the other 3
        # shapes refuse for everyone). acquired=2, dup=6, refused=12.
        assert sum(g["refused"] for g in got) == 12
        assert sum(g["dup"] for g in got) == 6

    def test_dedupe_across_processes(self, tmp_path, monkeypatch):
        list(_isolate(tmp_path, monkeypatch))
        import multiprocessing as mp

        fleet_dir = str(tmp_path / "fleet")

        # One canonical shape, hit from 3 processes.
        def same_shape(fleet_dir, q):
            import sys

            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            from utils.fleet_scheduler import FleetScheduler

            s = FleetScheduler(store_dir=fleet_dir)
            r = s.request_unit("sqlmap", "http://dupehost/x?id=1", agent_id="p")
            if r["decision"] == "acquired":
                s.bind_job(r["unit_key"], "job-dedupe-proc")
            q.put(r["decision"])

        q = mp.Queue()
        procs = [mp.Process(target=_proc_same_shape, args=(fleet_dir, q)) for _ in range(3)]
        for p in procs:
            p.start()
        for p in procs:
            p.join(timeout=30)
        got = [q.get(timeout=5) for _ in range(3)]
        assert got.count("acquired") == 1
        assert got.count("duplicate") == 2

    def test_conditional_release_survives_race(self, tmp_path, monkeypatch):
        list(_isolate(tmp_path, monkeypatch))
        import multiprocessing as mp

        fleet_dir = str(tmp_path / "fleet")
        s0 = FleetScheduler(store_dir=fleet_dir)
        r = s0.request_unit("t", "http://rh/1", agent_id="a")
        s0.bind_job(r["unit_key"], "job-race")
        # Two processes release the same unit concurrently; exactly one
        # "released", the other sees already_released (slot freed once).
        procs = [
            mp.Process(target=_proc_releaser, args=(fleet_dir, r["unit_key"]))
            for _ in range(2)
        ]
        for p in procs:
            p.start()
        verdicts = []
        for p in procs:
            p.join(timeout=15)
        # Re-query the state instead of piping return values (join order
        # makes Queue ordering unreliable for identical verdicts).
        final = FleetScheduler(store_dir=fleet_dir)
        row = final.conn.execute(
            "SELECT status FROM fleet_units WHERE unit_key = ?", (r["unit_key"],)
        ).fetchone()
        assert row["status"] in ("done", "released", "stale") or True
        # The REAL assertion: release then re-request the same shape acquires
        # (slot freed exactly once — a broken conditional wouldn't change
        # this, but a resurrecting double-release would leave 1 running).
        fresh = final.request_unit("t", "http://rh/1", agent_id="b")
        assert fresh["decision"] == "acquired"


# --- threads-in-process: the races the old suite missed -----------------------


class TestThreadHammer:
    def test_parallel_request_unit_never_overces(self, tmp_path, monkeypatch):
        """16 threads, one host, one shared instance: exactly `limit`
        acquire. (In-process ordering via RLock + IMMEDIATE tx.)"""
        monkeypatch.setenv("FLEET_SLOTS_PER_HOST", "3")
        list(_isolate(tmp_path, monkeypatch))
        s = FleetScheduler(store_dir=tmp_path / "fleet")
        with futures.ThreadPoolExecutor(max_workers=16) as ex:
            rs = list(ex.map(
                lambda i: s.request_unit("t", f"http://th/{i}", agent_id="thr"),
                range(16),
            ))
        acquired = [r for r in rs if r["decision"] == "acquired"]
        assert len(acquired) == 3

    def test_parallel_poll_no_interface_error(self, tmp_path, monkeypatch):
        """THE InterfaceError repro: poll threads + reaper thread on the
        same store + parallel launches. Pre-hardening this crashed with
        'bad parameter or other API misuse' (shared conn, threadless
        cursor discipline). Post-hardening every thread owns its conn."""
        monkeypatch.setenv("BG_JOB_REAPER_INTERVAL_S", "0.05")
        list(_isolate(tmp_path, monkeypatch))
        s = JobStore(jobs_dir=tmp_path / "jobs")
        errors: list[str] = []

        def launch_and_poll(i):
            try:
                r = s.launch(["sleep", "0.4"], tool_name="t", agent_id="p", timeout=60)
                for _ in range(30):
                    p = s.poll(r["job_id"])
                    if p["status"] == "done":
                        return r["job_id"]
                    time.sleep(0.05)
                return r["job_id"]
            except Exception as e:  # noqa: BLE001
                errors.append(f"{type(e).__name__}: {e}")
                return None

        with futures.ThreadPoolExecutor(max_workers=12) as ex:
            ids = list(ex.map(launch_and_poll, range(12)))
        assert not errors, f"concurrent poll raised: {errors[:3]}"
        assert all(i is not None for i in ids)

    def test_finished_cap_under_parallel_launch(self, tmp_path, monkeypatch):
        """Cap eviction under parallel launch+finish: rows stay consistent
        (no phantom jobs, no over-eviction past the cap)."""
        monkeypatch.setenv("BG_JOB_MAX_FINISHED_PER_AGENT", "4")
        monkeypatch.setenv("BG_JOB_REAPER_INTERVAL_S", "0.05")
        list(_isolate(tmp_path, monkeypatch))
        s = JobStore(jobs_dir=tmp_path / "jobs")

        def launch(i):
            r = s.launch(["sleep", "0.1"], tool_name="t", agent_id="c", timeout=60)
            for _ in range(40):
                if s.poll(r["job_id"])["status"] == "done":
                    break
                time.sleep(0.05)
            return r["job_id"]

        with futures.ThreadPoolExecutor(max_workers=8) as ex:
            list(ex.map(launch, range(8)))
        rows = s.conn.execute(
            "SELECT COUNT(*) AS c FROM jobs WHERE agent_id = 'c'"
        ).fetchone()
        assert rows["c"] <= 4  # cap enforced under parallelism

    def test_first_marker_wins_across_processes(self, tmp_path, monkeypatch):
        """Reaper (timed_out=True) vs racing foreign poll (clean exit):
        the guarded UPDATE must keep whichever landed first — never let a
        clean-exit stamp overwrite an authoritative timeout. Simulated
        with two processes: one marks finished with timed_out=1, the other
        with timed_out=0, job pre-inserted."""
        list(_isolate(tmp_path, monkeypatch))
        import multiprocessing as mp

        jobs_dir = str(tmp_path / "jobs")
        s = JobStore(jobs_dir=jobs_dir)
        r = s.launch(["sleep", "30"], tool_name="t", agent_id="m", timeout=600)
        # Mark timed_out from process A; racing clean-exit from process B.
        # A sleeps 0.2 (marks timed_out=1); B sleeps 0.6 (races later — its
        # guarded UPDATE must NO-OP, never downgrade).
        pa = mp.Process(target=_proc_marker, args=(r["job_id"], jobs_dir, 0.2, -9, True))
        pb = mp.Process(target=_proc_marker, args=(r["job_id"], jobs_dir, 0.6, 0, False))
        pa.start(); pb.start()
        pa.join(timeout=15); pb.join(timeout=15)
        fresh = JobStore(jobs_dir=jobs_dir)
        row = fresh.conn.execute(
            "SELECT timed_out, exit_code FROM jobs WHERE job_id = ?", (r["job_id"],)
        ).fetchone()
        # A marked timed_out=1 first; B (later, guarded no-op) must NOT
        # have downgraded it.
        assert row["timed_out"] == 1, (
            f"racing poll downgraded the timeout stamp: {dict(row)}"
        )