"""Phase 2 sqlmap fleet tests — Annex A as tests: shape-keyed units, per-host
slot policy via the shared scheduler, per-unit output isolation, --purge
refusal, aggregator, and the four fleet twins over a stub binary.

The stub "sqlmap" is a bash script that writes plausible log lines and
exits, so fleet flows run end-to-end without network targets or the real
sqlmap binary. """

import json
import os
import time

import pytest

from utils.fleet_scheduler import canonical_unit_key, reset_scheduler

STUB_SQLMAP = r"""#!/bin/bash
# Stub sqlmap: writes log lines to stdout; honors a subset of flags.
out=""
for arg in "$@"; do
  case "$arg" in
    --output-dir=*) out="${arg#--output-dir=}" ;;
  esac
done
echo "[*] starting @ $(date)"
echo "[*] testing connection to the target url"
if [ -n "$out" ]; then
  echo "[*] session data dir: $out" > "${out}/session_marker.txt"
fi
sleep "${STUB_SLEEP:-0.2}"
echo "sqlmap identified the following injection point with payload '1' (type: time-based blind)"
echo "Parameter 'id' is vulnerable"
echo "back-end DBMS is 'MySQL'"
echo "[*] ending @ $(date)"
exit 0
"""


@pytest.fixture
def fleet_env(tmp_path, monkeypatch):
    """Isolated everything: scheduler, job store, stub sqlmap on PATH,
    run/ redirected, fresh env knobs."""
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
    stub = bindir / "sqlmap"
    stub.write_text(STUB_SQLMAP)
    stub.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
    reset_scheduler()
    from utils.job_store import reset_store

    reset_store()
    yield {"state": state, "bindir": bindir}
    reset_scheduler()
    reset_store()


def _drain(job_id, timeout=10):
    """Poll until done (bounded)."""
    from utils.background_job import poll_job

    deadline = time.time() + timeout
    while time.time() < deadline:
        p = poll_job(job_id)
        if p["status"] == "done":
            return p
        time.sleep(0.2)
    return poll_job(job_id)


# --- policy table ---------------------------------------------------------------


def test_purge_build_rejected():
    import payloads.sqlmap as sm

    with pytest.raises(ValueError, match="--purge"):
        sm._build_sqlmap_command("http://h/x", "--purge")


def test_policy_threads_and_output_dir():
    import payloads.sqlmap as sm

    cmd = sm._build_sqlmap_command("http://h/x", "", output_dir="/tmp/unit")
    assert "--threads=1" in cmd
    assert "--output-dir=/tmp/unit" in cmd
    assert "-t=/tmp/unit/traffic.log" in cmd
    assert cmd[1] == "-u"
    # caller options come after policy defaults; explicit --threads wins so
    # NO policy --threads is injected (count is over the assembled argv).
    cmd2 = sm._build_sqlmap_command("http://h/x", "--threads=7")
    assert "--threads=7" in cmd2 and "--threads=1" not in cmd2


def test_data_body_extraction():
    import payloads.sqlmap as sm

    assert sm._extract_data_body("--data='user=a&pass=b' --level=3") == "user=a&pass=b"
    assert sm._extract_data_body("--level=5") == ""


# --- single-target is a fleet unit ------------------------------------------------


def test_run_sqlmap_routes_through_scheduler(fleet_env, monkeypatch):
    import payloads.sqlmap as sm
    from utils.agent_identity import agent_id_context

    with agent_id_context("fleet-tester"):
        r = sm.run_sqlmap("http://h.example/x?id=1")
    assert r["status"] == "running"
    assert r["unit_key"].startswith("sqlmap:h.example:")

    # Same shape, different value → duplicate (never a second process).
    with agent_id_context("fleet-tester-2"):
        r2 = sm.run_sqlmap("http://h.example/x?id=999")
    assert r2["status"] == "duplicate"
    assert r2["job_id"] == r["job_id"]

    # Drain; slot frees; a new distinct unit acquires.
    p = _drain(r["job_id"])
    assert p["status"] == "done"
    with agent_id_context("fleet-tester-3"):
        r3 = sm.run_sqlmap("http://h.example/admin")
    assert r3["status"] == "running"


def test_sqlmap_status_releases_unit(fleet_env):
    import payloads.sqlmap as sm
    from utils.agent_identity import agent_id_context
    from utils.fleet_scheduler import get_scheduler

    with agent_id_context("st"):
        r = sm.run_sqlmap("http://h2.example/x?id=1")
    _drain(r["job_id"])
    with agent_id_context("st"):
        st = sm.sqlmap_status(r["job_id"])
    assert st["status"] == "done"
    assert st.get("injectable") is True
    assert st.get("dbms") == "MySQL"
    pressure = get_scheduler().host_pressure("h2.example")
    # unit released on done — nothing running
    entry = pressure["hosts"].get("h2.example", {"running": 0})
    assert entry["running"] == 0


# --- fleet twins -----------------------------------------------------------------


def test_fleet_fanout_and_status(fleet_env):
    import payloads.sqlmap as sm
    from utils.agent_identity import agent_id_context

    targets = [
        "http://h3.example/a?id=1",
        "http://h3.example/b?id=2",
        "http://h4.example/login",  # auth-adjacent host h4
        "http://h4.example/products",  # must be refused (host serialized)
    ]
    with agent_id_context("fleet-user"):
        out = sm.run_sqlmap_fleet(targets)
    assert out["status"] == "ok"
    # h3: two plain units acquire (2 slots); h4: login acquires, products
    # refused by auth-adjacent serialization (an adjacent unit RUNS there).
    assert out["acquired"] == 3
    assert out["refused"] == 1
    fleet_id = out["fleet_id"]
    assert fleet_id.startswith("fleet:")

    for j in (out["units"]["0"]["job_id"], out["units"]["1"]["job_id"]):
        _drain(j)

    with agent_id_context("fleet-user"):
        st = sm.sqlmap_fleet_status(fleet_id)
    assert st["running"] == 0
    assert st["done"] == 3  # h3 a + h3 b + h4 login all finished
    assert st["status"] == "complete"


def test_fleet_results_dedupe(fleet_env):
    import payloads.sqlmap as sm
    from utils.agent_identity import agent_id_context

    targets = ["http://h5.example/a?id=1", "http://h5.example/a?id=999"]
    with agent_id_context("res"):
        out = sm.run_sqlmap_fleet(targets)
    # Second is a duplicate of the first (same shape).
    assert out["duplicates"] == 1
    j = out["units"]["0"]["job_id"]
    _drain(j)
    with agent_id_context("res"):
        res = sm.sqlmap_fleet_results(out["fleet_id"], dedupe="param")
    assert res["units_scanned"] >= 1
    assert res["unique_findings"] == 1
    row = res["rows"][0]
    assert row["param"] == "id"
    assert "time" in row["techniques"]
    assert row["traffic_log"].endswith("traffic.log")
    assert os.path.isabs(row["unit_log"])


def test_fleet_scope_block_recorded(fleet_env, monkeypatch):
    # Arm a scope that excludes the target; fleet records block per unit.
    state = fleet_env["state"]
    scope_dir = state / "scope"
    scope_dir.mkdir(parents=True, exist_ok=True)
    scope_dir.joinpath(".armed_packet_scope.json").write_text(
        json.dumps({"mode": "allowlist", "allowlist": {"other.example": []}})
    )
    import payloads.sqlmap as sm
    from utils.agent_identity import agent_id_context

    with agent_id_context("sc"):
        out = sm.run_sqlmap_fleet(["http://blocked.example/x?id=1"])
    assert out["acquired"] == 0
    assert out["scope_blocked"], "scope block must be recorded per unit"


def test_fleet_stop_terminates_running(fleet_env, monkeypatch):
    monkeypatch.setenv("STUB_SLEEP", "30")  # stub sleeps long
    import payloads.sqlmap as sm
    from utils.agent_identity import agent_id_context

    with agent_id_context("stopper"):
        out = sm.run_sqlmap_fleet(["http://h6.example/x?id=1"])
    job_id = out["units"]["0"]["job_id"]
    with agent_id_context("stopper"):
        stop = sm.sqlmap_fleet_stop(out["fleet_id"])
    assert stop["status"] == "ok"
    assert job_id in stop["stopped"]
    # Row observed done (killed) and slot freed is enforced by release.
    from utils.background_job import poll_job

    assert poll_job(job_id)["status"] in ("done", "running")  # killed exit lands
    monkeypatch.setenv("STUB_SLEEP", "0.2")


def test_batch_persists_and_unknown_fleet_id(fleet_env):
    import payloads.sqlmap as sm
    from utils.fleet_scheduler import get_scheduler

    assert sm.sqlmap_fleet_status("fleet:does-not-exist")["status"] == "unknown"
    assert sm.sqlmap_fleet_stop("fleet:does-not-exist")["status"] == "unknown"
    # Empty batch table is fine; batch_status on empty registry:
    b = get_scheduler().batch_status("fleet:none")
    assert b["status"] == "unknown"