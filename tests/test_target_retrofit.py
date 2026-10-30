"""Tier-1 retrofit tests: ``launch_job(target=...)`` into the remaining
single-target launchers plus the generic poll-side fleet release in
``poll_job`` (scale-doctrine §14 Tier 1 as tests; the sqlmap adapter, §10,
is the reference pattern).

Every traffic-sending launcher shares the per-host courtesy contract:
- the call passes ``target=`` so dedupe/slots apply to single-target runs;
- a ``duplicate``/``refused`` decision envelope returns VERBATIM (no
  launch, no post-launch decoration);
- a finished job frees its slot at the first done-poll, through
  ``poll_job`` — tools never re-implement the release.
"""

import os
import time

import pytest

from utils.fleet_scheduler import (
    get_scheduler,
    release_units_for_job,
    reset_scheduler,
)

STUB_NMAP = r"""#!/bin/bash
sleep "${STUB_SLEEP:-0.3}"
echo "Host 192.168.99.7 is up"
echo "80/tcp open  http"
exit 0
"""


@pytest.fixture
def fleet_env(tmp_path, monkeypatch):
    """Isolated everything: scheduler, job store, WORKSPACE_ROOT, optional
    stub-bin dir fresh per test."""
    state = tmp_path / "state"
    state.mkdir(parents=True, exist_ok=True)  # must exist BEFORE env is read
    monkeypatch.setenv("WORKSPACE_ROOT", str(state))
    monkeypatch.setenv("FLEET_STORE_DIR", str(tmp_path / "fleet"))
    monkeypatch.setenv("BG_JOB_STORE_DIR", str(tmp_path / "jobs"))
    monkeypatch.setenv("BG_JOB_REAPER_INTERVAL_S", "0.2")
    monkeypatch.setattr(
        "constants.resolve_workspace_root", lambda: state, raising=False
    )
    bindir = tmp_path / "bin"
    bindir.mkdir()
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
    reset_scheduler()
    from utils.job_store import reset_store

    reset_store()
    yield {"state": state, "bindir": bindir}
    reset_scheduler()
    reset_store()


def _drain(job_id, timeout=10):
    from utils.background_job import poll_job

    deadline = time.time() + timeout
    while time.time() < deadline:
        p = poll_job(job_id)
        if p["status"] == "done":
            return p
        time.sleep(0.2)
    return poll_job(job_id)


def _running_units():
    sched = get_scheduler()
    return sched.conn.execute(
        "SELECT unit_key, job_id FROM fleet_units WHERE status = 'running'"
    ).fetchall()


# --- the generic poll-side release (choke point in poll_job) --------------------


def test_release_units_for_job_no_store_is_noop(fleet_env):
    # No fleet db on disk: releases nothing and never CONJURES fleet.db.
    fleety = fleet_env["state"].parent / "fleet"
    assert not fleety.exists()
    assert release_units_for_job("job-never-launched") == 0
    assert not fleety.exists()


def test_done_poll_releases_fleet_unit(fleet_env):
    """launch_job(target=...) + poll_job: the unit frees its slot at the
    FIRST done observation — tools never re-implement the release."""
    stub = fleet_env["bindir"] / "nmap"
    stub.write_text(STUB_NMAP)
    stub.chmod(0o755)

    from auxiliaries.nmap import run_nmap

    res = run_nmap("192.168.99.7", options="-p 80")
    assert res["status"] == "running"
    assert res.get("unit_key", "").startswith("nmap:192.168.99.7")
    assert len(_running_units()) == 1  # slot held while the scan runs

    _drain(res["job_id"])
    assert _running_units() == []  # released by the done-poll itself


def test_launch_duplicate_returns_running_job(fleet_env):
    """Same canonical unit still running → duplicate, no second process."""
    stub = fleet_env["bindir"] / "nmap"
    stub.write_text("#!/bin/bash\nsleep 5\n")  # stays running for the test
    stub.chmod(0o755)

    from auxiliaries.nmap import run_nmap

    first = run_nmap("192.168.99.7", options="-p 80")
    assert first["status"] == "running"
    second = run_nmap("192.168.99.7", options="-p 80")
    assert second["status"] == "duplicate"
    assert second["job_id"] == first["job_id"]
    # only ONE job row exists — no second process was spawned
    from utils.job_store import get_store

    assert len(get_store().list_jobs(limit=10)) == 1


# --- per-launcher target= plumbing (launch_job stubbed, no binaries) ------------


def test_nmap_passes_target_kwarg(fleet_env, monkeypatch):
    from auxiliaries import nmap as nmap_mod

    seen = {}

    def fake_launch(*args, **kwargs):
        seen.update(kwargs)
        return {"job_id": "n1", "status": "running", "log_file": "/tmp/x"}

    monkeypatch.setattr(nmap_mod, "launch_job", fake_launch)
    res = nmap_mod.run_nmap("192.168.90.114", options="-p 445 -sV")
    assert seen["tool_name"] == "nmap"
    assert seen["target"] == "192.168.90.114"
    assert res["status"] == "running"  # verbatim envelope passthrough


def test_nmap_verbatim_on_duplicate(fleet_env, monkeypatch):
    from auxiliaries import nmap as nmap_mod

    dup_env = {
        "status": "duplicate",
        "job_id": "n-live",
        "unit_key": "nmap:192.168.90.114:/:<hash>",
        "message": "unit already running",
    }
    monkeypatch.setattr(nmap_mod, "launch_job", lambda *a, **k: dict(dup_env))
    res = nmap_mod.run_nmap("192.168.90.114")
    # run_nmap has NO post-launch decoration — verbatim is automatic
    assert res == dup_env


def test_ffuf_passes_target_kwarg(fleet_env, monkeypatch):
    from payloads import ffuf as ffuf_mod

    wl = fleet_env["state"] / "wl.txt"
    wl.write_text("backup\nadmin\ndocs\n")
    seen = {}

    def fake_launch(*args, **kwargs):
        seen.update(kwargs)
        return {"job_id": "f1", "status": "running", "log_file": "/tmp/x"}

    monkeypatch.setattr(ffuf_mod, "launch_job", fake_launch)
    url = "http://192.168.56.106/FUZZ"
    res = ffuf_mod.run_ffuf(url, wordlist=str(wl))
    assert seen["tool_name"] == "ffuf"
    assert seen["target"] == url
    assert res["status"] == "running"


def test_ffuf_verbatim_on_duplicate(fleet_env, monkeypatch):
    from payloads import ffuf as ffuf_mod

    dup_env = {
        "status": "duplicate",
        "job_id": "f-live",
        "unit_key": "ffuf:192.168.56.106:/FUZZ:<hash>",
        "message": "unit already running",
    }
    monkeypatch.setattr(ffuf_mod, "launch_job", lambda *a, **k: dict(dup_env))
    res = ffuf_mod.run_ffuf("http://192.168.56.106/FUZZ")
    # post-launch decoration (note/wordlist keys) must NOT land on it
    assert res == dup_env


def test_hydra_passes_target_kwarg(fleet_env, monkeypatch):
    from payloads import hydra as hydra_mod

    seen = {}

    def fake_launch(*args, **kwargs):
        seen.update(kwargs)
        return {"job_id": "h1", "status": "running", "log_file": "/tmp/x"}

    monkeypatch.setattr(hydra_mod, "launch_job", fake_launch)
    res = hydra_mod.run_hydra("ssh://192.168.56.106", options="-l admin -p secret")
    assert seen["tool_name"] == "hydra"
    assert seen["target"] == "ssh://192.168.56.106"
    assert res["status"] == "running"


def test_hydra_verbatim_on_duplicate(fleet_env, monkeypatch):
    from payloads import hydra as hydra_mod

    dup_env = {
        "status": "duplicate",
        "job_id": "h-live",
        "unit_key": "hydra:192.168.56.106:/:<hash>",
        "message": "unit already running",
    }
    monkeypatch.setattr(hydra_mod, "launch_job", lambda *a, **k: dict(dup_env))
    res = hydra_mod.run_hydra("ssh://192.168.56.106", options="-l admin -p secret")
    # default-cred-injection metadata must NOT land on a no-launch envelope
    assert res == dup_env