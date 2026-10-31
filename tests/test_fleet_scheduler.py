"""Fleet scheduler tests — dedupe, slot ceilings, auth-adjacent serialization,
crash-stale reclaim, canonical keys. Doctrine §3 rules 4/6/7 as tests."""

import time

import pytest

from utils.fleet_scheduler import (
    FleetScheduler,
    canonical_unit_key,
    get_scheduler,
    is_auth_adjacent,
    reset_scheduler,
)


@pytest.fixture
def sched(tmp_path, monkeypatch):
    """Isolated scheduler + isolated job store (sweep_stale reads it)."""
    monkeypatch.setenv("FLEET_STORE_DIR", str(tmp_path / "fleet"))
    monkeypatch.setenv("BG_JOB_STORE_DIR", str(tmp_path / "jobs"))
    reset_scheduler()
    from utils.job_store import reset_store

    reset_store()
    s = FleetScheduler(store_dir=tmp_path / "fleet")
    yield s
    reset_scheduler()
    reset_store()


# --- canonical keys (rule 4 + §4a body-shape rule) ------------------------------


def test_fleet_db_heals_tight_umask_modes(tmp_path):
    """2026-10-31: fleet.db minted 0644 group-read-only (tight-umask
    process) — fleet rows are cross-actor BY DESIGN ('dedupe is the
    point'), so the other actor's write would die with SQLITE_READONLY.
    The store __init__ reconciles db + sidecars group-rw (state_perms)."""
    import os
    import sqlite3

    base = tmp_path / "fleet"
    base.mkdir()
    db = base / "fleet.db"
    _c = sqlite3.connect(str(db))  # mint under THIS test's umask
    _c.close()
    os.chmod(str(db), 0o644)
    assert not os.stat(str(db)).st_mode & 0o020

    s = FleetScheduler(store_dir=base)
    assert os.stat(str(db)).st_mode & 0o060 == 0o060
    # The WAL sidecars minted inside __init__ inherit the healed mode.
    assert os.stat(str(base / "fleet.db-wal")).st_mode & 0o060 == 0o060


def test_key_ignores_query_values_but_not_param_names():
    a = canonical_unit_key("sqlmap", "http://h/x?id=1&tok=ABCD")
    b = canonical_unit_key("sqlmap", "http://h/x?id=999&tok=ZZZZ")
    assert a == b  # same shape, values differ → same unit


def test_key_order_insensitive_params_and_body_fields():
    a = canonical_unit_key("sqlmap", "http://h/x?b=1&a=2", body="user=x&pass=y")
    b = canonical_unit_key("sqlmap", "http://h/x?a=2&b=1", body="pass=z&user=w")
    assert a == b


def test_key_changes_with_endpoint_or_param_set():
    a = canonical_unit_key("sqlmap", "http://h/x?id=1")
    b = canonical_unit_key("sqlmap", "http://h/admin?id=1")
    c = canonical_unit_key("sqlmap", "http://h/x?id=1&extra=2")
    assert len({a, b, c}) == 3


def test_key_trailing_slash_normalized_and_tool_safe():
    assert canonical_unit_key("sqlmap", "http://h/x") == canonical_unit_key("sqlmap", "http://h/x/")
    k = canonical_unit_key("tool/with$chars", "http://h/x")
    assert k.startswith("tool-with-chars:") or k.startswith("tool-with-chars")


def test_auth_adjacent_class():
    assert is_auth_adjacent("http://h/login")
    assert is_auth_adjacent("http://h/api/session/check")
    assert is_auth_adjacent("user=admin")  # body fields count
    assert not is_auth_adjacent("http://h/products?page=2")


# --- dedupe ----------------------------------------------------------------------


def test_duplicate_unit_returns_existing_job_ref(sched, tmp_path):
    # Use a REAL job-row bind so sweep_stale can verify the job is still
    # running (a fabricated job_id would be reclaimed only at TTL by
    # design — missing rows are not proof of completion).
    import os

    from utils.job_store import JobStore

    jobs = JobStore(jobs_dir=tmp_path / "jobs")
    first = sched.request_unit("sqlmap", "http://h/x?id=1", agent_id="a1")
    j = jobs.launch(["sleep", "5"], tool_name="sqlmap", agent_id="a1", timeout=600)
    sched.bind_job(first["unit_key"], j["job_id"])
    second = sched.request_unit("sqlmap", "http://h/x?id=2", agent_id="a2")  # same shape
    assert second["decision"] == "duplicate"
    assert second["job_id"] == j["job_id"]


def test_different_units_same_host_acquire_independently(sched):
    r1 = sched.request_unit("sqlmap", "http://h/x?id=1", agent_id="a1")
    r2 = sched.request_unit("sqlmap", "http://h/y", agent_id="a2")
    assert r1["decision"] == "acquired" and r2["decision"] == "acquired"


# --- slots (rule 6) ----------------------------------------------------------------


def test_default_two_slots_then_refusal(sched, monkeypatch):
    monkeypatch.setenv("FLEET_SLOTS_PER_HOST", "2")
    assert sched.request_unit("t", "http://h/1", agent_id="a")["decision"] == "acquired"
    assert sched.request_unit("t", "http://h/2", agent_id="a")["decision"] == "acquired"
    third = sched.request_unit("t", "http://h/3", agent_id="a")
    assert third["decision"] == "refused"
    assert third["reason"] == "slots_exhausted"


def test_override_raises_with_warning_but_ceiling_is_absolute(sched, monkeypatch):
    monkeypatch.setenv("FLEET_SLOTS_PER_HOST", "2")
    for i in range(1, 3):
        assert sched.request_unit("t", f"http://h/{i}", agent_id="a")["decision"] == "acquired"
    warn = sched.request_unit("t", "http://h/3", agent_id="a", override_slots=4)
    assert warn["decision"] == "acquired"
    assert "override" in warn.get("warning", "")
    fourth = sched.request_unit("t", "http://h/4", agent_id="a", override_slots=4)
    assert fourth["decision"] == "acquired"  # 4 == ceiling
    fifth = sched.request_unit("t", "http://h/5", agent_id="a", override_slots=9)
    assert fifth["decision"] == "refused"
    assert fifth["reason"] == "slots_exhausted"


def test_release_frees_slot(sched):
    r1 = sched.request_unit("t", "http://h/1", agent_id="a")
    sched.request_unit("t", "http://h/2", agent_id="a")
    assert sched.release_unit(r1["unit_key"], agent_id="a")["status"] == "released"
    assert sched.request_unit("t", "http://h/3", agent_id="a")["decision"] == "acquired"


def test_cross_agent_release_refused_without_force(sched):
    r1 = sched.request_unit("t", "http://h/1", agent_id="owner")
    other = sched.release_unit(r1["unit_key"], agent_id="intruder")
    assert other["status"] == "refused"
    assert sched.release_unit(r1["unit_key"], agent_id=None, force=True)["status"] == "released"


# --- auth-adjacent serialization (rule 7) -------------------------------------------


def test_auth_adjacent_holds_host_exclusively(sched):
    assert sched.request_unit("t", "http://h/login", agent_id="a")["decision"] == "acquired"
    plain = sched.request_unit("t", "http://h/products", agent_id="b")
    assert plain["decision"] == "refused"
    assert plain["reason"] == "host_serialized_auth"


def test_plain_unit_blocks_later_auth_adjacent(sched):
    assert sched.request_unit("t", "http://h/products", agent_id="a")["decision"] == "acquired"
    later = sched.request_unit("t", "http://h/login", agent_id="b")
    assert later["decision"] == "refused"
    assert later["reason"] == "host_serialized_auth"


def test_auth_adjacent_ok_once_host_drains(sched):
    r = sched.request_unit("t", "http://h/login", agent_id="a")
    sched.release_unit(r["unit_key"], agent_id="a")
    assert sched.request_unit("t", "http://h/login", agent_id="a")["decision"] == "acquired"


def test_different_hosts_unaffected(sched):
    assert sched.request_unit("t", "http://h1/login", agent_id="a")["decision"] == "acquired"
    assert sched.request_unit("t", "http://h2/login", agent_id="b")["decision"] == "acquired"


# --- stale reclaim (rule 4 crash discipline) ----------------------------------------


def test_sweep_reclaims_unit_with_finished_job(sched, tmp_path, monkeypatch):
    monkeypatch.setenv("BG_JOB_REAPER_INTERVAL_S", "0.2")
    from utils.job_store import JobStore

    jobs = JobStore(jobs_dir=tmp_path / "jobs")
    r = sched.request_unit("t", "http://h/1", agent_id="a")
    j = jobs.launch(["sleep", "0.2"], tool_name="t", agent_id="a", timeout=60)
    sched.bind_job(r["unit_key"], j["job_id"])
    deadline = time.time() + 6
    while time.time() < deadline and jobs.poll(j["job_id"])["status"] != "done":
        time.sleep(0.1)
    out = sched.sweep_stale()
    assert r["unit_key"] in out["stale_reclaimed"]
    # Freed slot: a new unit on the host acquires.
    assert sched.request_unit("t", "http://h/2", agent_id="b")["decision"] == "acquired"


def test_sweep_reclaims_jobless_units_after_grace(sched, monkeypatch):
    monkeypatch.setenv("FLEET_BIND_GRACE_S", "0.5")
    r = sched.request_unit("t", "http://h/1", agent_id="a")  # never bind_job'ed
    assert r["decision"] == "acquired"  # fresh acquire survives (grace window)
    time.sleep(0.6)
    out = sched.sweep_stale()
    assert r["unit_key"] in out["stale_reclaimed"]


def test_sweep_keeps_healthy_running_jobs(sched, tmp_path, monkeypatch):
    monkeypatch.setenv("BG_JOB_REAPER_INTERVAL_S", "0.2")
    from utils.job_store import JobStore

    jobs = JobStore(jobs_dir=tmp_path / "jobs")
    r = sched.request_unit("t", "http://h/1", agent_id="a")
    j = jobs.launch(["sleep", "5"], tool_name="t", agent_id="a", timeout=600)
    sched.bind_job(r["unit_key"], j["job_id"])
    out = sched.sweep_stale()
    assert r["unit_key"] not in out["stale_reclaimed"]


# --- observability -------------------------------------------------------------------


def test_host_pressure_reports_running_and_agents(sched):
    sched.request_unit("t", "http://h/1", agent_id="a1")
    sched.request_unit("t", "http://h/2", agent_id="a2")
    pressure = sched.host_pressure("h")
    entry = pressure["hosts"]["h"]
    assert entry["running"] == 2
    assert entry["agents"] == ["a1", "a2"]
    assert entry["default_slots"] == 2 and entry["ceiling"] == 4


def test_singleton_env_respects_reset(monkeypatch):
    # Without an override the singleton caches; with FLEET_STORE_DIR set it
    # constructs fresh per call BY DESIGN (tests rely on that isolation).
    monkeypatch.delenv("FLEET_STORE_DIR", raising=False)
    reset_scheduler()
    a = get_scheduler()
    b = get_scheduler()
    assert a is b
    monkeypatch.setenv("FLEET_STORE_DIR", "/tmp/fleet-iso-xyz")
    c = get_scheduler()
    assert c is not a
    reset_scheduler()

# --- numeric-span identity (2026-10-31): CIDR sweeps vs member hosts ---------------


def test_cidr_key_spelling_normalized():
    a = canonical_unit_key("sqlmap", "10.0.1.0/24")
    b = canonical_unit_key("sqlmap", "10.0.1.5/24")
    c = canonical_unit_key("sqlmap", "10.0.1.0-10.0.1.255")
    assert a == b == c  # same 256 addresses, different spellings
    assert a != canonical_unit_key("sqlmap", "10.0.0.0/24")  # different net


def test_sweep_and_member_ip_contend_on_slots(sched, monkeypatch):
    monkeypatch.setenv("FLEET_SLOTS_PER_HOST", "1")
    sweep = sched.request_unit("t", "10.0.0.0/24", agent_id="a")
    assert sweep["decision"] == "acquired"
    inside = sched.request_unit("t", "10.0.0.7", agent_id="b")
    assert inside["decision"] == "refused"
    assert inside["reason"] == "slots_exhausted"


def test_member_ip_first_blocks_sweep_too(sched, monkeypatch):
    # Both directions: slot accounting must be symmetric.
    monkeypatch.setenv("FLEET_SLOTS_PER_HOST", "1")
    assert sched.request_unit("t", "10.0.0.7", agent_id="a")["decision"] == "acquired"
    sweep = sched.request_unit("t", "10.0.0.0/24", agent_id="b")
    assert sweep["decision"] == "refused"
    assert sweep["reason"] == "slots_exhausted"
    assert sweep["running_units"]  # the member unit is named


def test_range_shorthand_overlaps_member_host(sched, monkeypatch):
    monkeypatch.setenv("FLEET_SLOTS_PER_HOST", "1")
    assert sched.request_unit("t", "10.0.0.5-30", agent_id="a")["decision"] == "acquired"
    mid = sched.request_unit("t", "10.0.0.6", agent_id="b")
    assert mid["decision"] == "refused"
    # A host OUTSIDE the range is unaffected.
    assert sched.request_unit("t", "10.0.0.31", agent_id="b")["decision"] == "acquired"


def test_disjoint_cidrs_do_not_contend(sched, monkeypatch):
    monkeypatch.setenv("FLEET_SLOTS_PER_HOST", "1")
    assert sched.request_unit("t", "10.0.0.0/24", agent_id="a")["decision"] == "acquired"
    assert sched.request_unit("t", "10.0.1.0/24", agent_id="b")["decision"] == "acquired"


def test_hostname_targets_keep_name_axis(sched, monkeypatch):
    # Numeric overlap accounting must not bleed into hostname targets.
    monkeypatch.setenv("FLEET_SLOTS_PER_HOST", "1")
    assert sched.request_unit("t", "10.0.0.0/24", agent_id="a")["decision"] == "acquired"
    assert sched.request_unit("t", "http://h.example.com/x", agent_id="b")["decision"] == "acquired"


def test_duplicate_numeric_spellings_dedupe(sched, tmp_path):
    from utils.job_store import JobStore

    jobs = JobStore(jobs_dir=tmp_path / "jobs")
    first = sched.request_unit("sqlmap", "10.0.0.7", agent_id="a1")
    assert first["decision"] == "acquired"
    j = jobs.launch(["sleep", "5"], tool_name="sqlmap", agent_id="a1", timeout=600)
    sched.bind_job(first["unit_key"], j["job_id"])
    again = sched.request_unit("sqlmap", "10.0.0.7/32", agent_id="a2")
    assert again["decision"] == "duplicate"
    assert again["job_id"] == j["job_id"]


def test_auth_exclusivity_covers_overlapping_sweep(sched, monkeypatch):
    # Rule 7 across the overlap axis: an auth unit on a member host blocks
    # a sweep of the range that contains it (and vice versa).
    monkeypatch.setenv("FLEET_SLOTS_PER_HOST", "2")
    blocked = sched.request_unit("t", "http://10.0.0.7/login", agent_id="a")
    assert blocked["decision"] == "acquired"  # auth-adjacent, holds its span
    sweep = sched.request_unit("t", "10.0.0.0/24", agent_id="b")
    assert sweep["decision"] == "refused"
    assert sweep["reason"] == "host_serialized_auth"
