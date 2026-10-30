"""Burp fleet twins — worker-queue adapter tests.

Runs with NO live Burp: `_mcp_ready` is monkeypatched and the per-unit
child is a stub python worker pointed at via BURP_WORKER_PY (the same
seam operators get for offline testing).
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

from constants import framework_tool  # noqa: F401  (decorator smoke)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import payloads.burp_fleet as bf
from utils.worker_queue import content_key, get_worker_queue, reset_worker_queue

REQ_TXT = (
    "POST /login HTTP/1.1\n"
    "Host: labhost.example\n"
    "Content-Type: application/x-www-form-urlencoded\n\n"
    "user=admin&pass=x\n"
)

STUB_WORKER = '''\
import json, os, sys, time
from pathlib import Path
man = json.loads(Path(sys.argv[sys.argv.index("--manifest") + 1]).read_text())
for i in range(int(man.get("retries", 1))):
    print(f"BURP-RETRY i={i + 1} status_code={man['port']} ok=true", flush=True)
time.sleep(float(os.getenv("STUB_SLEEP", "0.2")))
print("BURP-VERDICT json=" + json.dumps(
    {"attempts": int(man.get("retries", 1)), "ok": int(man.get("retries", 1)),
     "status_codes": [int(man["port"])]}, sort_keys=True), flush=True)
'''


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("WORKER_QUEUE_DIR", str(tmp_path / "wq"))
    monkeypatch.setenv("BG_JOB_STORE_DIR", str(tmp_path / "jobs"))
    monkeypatch.setenv("BG_JOB_REAPER_INTERVAL_S", "0.2")
    monkeypatch.setenv("WORKER_QUEUE_BIND_GRACE_S", "60")
    monkeypatch.setenv("WORKER_QUEUE_RAM_FLOOR", "64")
    monkeypatch.setenv("BURP_FLEET_UNIT_DIR", str(tmp_path / "units"))
    monkeypatch.setenv("BURP_DROP_DIR", str(tmp_path / "burp_drop"))
    monkeypatch.setenv("BURP_JVM_PID", "")  # no JVM on the test box
    (tmp_path / "burp_drop").mkdir()
    stub = tmp_path / "stub_worker.py"
    stub.write_text(STUB_WORKER)
    monkeypatch.setenv("BURP_WORKER_PY", str(stub))
    monkeypatch.setattr(bf, "_mcp_ready", lambda: (True, ""))
    # Isolate from the operator's live armed scope (strict program mode on
    # a real box would block every unit); the dedicated scope test re-applies
    # a block.
    from utils import scope_gate

    monkeypatch.setattr(scope_gate, "check_scan", lambda host, **kw: (True, ""))
    reset_worker_queue()
    from utils.job_store import reset_store

    reset_store()
    yield tmp_path
    reset_worker_queue()
    reset_store()


def _request_file(tmp_path: Path, name: str, text: str = REQ_TXT) -> Path:
    p = tmp_path / "burp_drop" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def test_unit_key_is_manifest_bytes(env):
    """Byte-identity doctrine: the same request content at two different
    paths keys identically; a retries change re-keys honestly."""
    a = _request_file(env, "a.txt")
    b = env / "renamed" / "b.txt"
    b.parent.mkdir()
    b.write_text(REQ_TXT)  # same bytes, different name/directory
    ma = bf._make_manifest(a, "labhost.example", 80, False, 1)
    mb = bf._make_manifest(b, "labhost.example", 80, False, 1)
    assert ma.read_bytes() == mb.read_bytes()
    assert content_key("burp", str(ma)) == content_key("burp", str(mb))
    assert ma == mb  # deterministic name
    mc = bf._make_manifest(a, "labhost.example", 80, False, 3)
    assert content_key("burp", str(ma)) != content_key("burp", str(mc))


def test_replay_fleet_launches_dedupe_and_verdict(env):
    (env / "burp_drop" / "r1.txt").write_text(REQ_TXT)
    (env / "burp_drop" / "r2.txt").write_text(REQ_TXT)  # same bytes → same unit key
    res = bf.burp_replay_fleet(requests="r1.txt", host="", port=80, https=False)
    assert res["status"] == "ok"
    assert res["decision_counts"].get("launched") == 1
    fid = res["fleet_id"]
    queue = get_worker_queue()
    rows = queue.units_by_note(fid)
    assert len(rows) == 1
    unit_key = rows[0]["unit_key"]

    # Re-request the same bytes → duplicate (running), never a twin launch.
    again = bf.burp_replay_fleet(requests="r1.txt")
    dupe = again["units"][0]
    assert dupe["decision"] == "duplicate"
    assert dupe["state"] == "running"

    # Drain: poll to done, parse the verdict from the log tail.
    verdict = None
    for _ in range(100):
        poll = queue.poll_unit(unit_key)
        if poll["status"] == "done":
            recent = poll.get("recent_lines") or []
            verdict = bf._parse_burp_verdict("\n".join(recent))
            assert verdict["attempts"] == 1
            assert verdict["ok"] == 1
            assert "codes:" in verdict["verdict"]
            break
        queue.advance_queue()
        time.sleep(0.05)
    assert verdict is not None, f"unit never reached done; last poll={poll}"

    # Release sweep runs inside status; rows settle to finished with job_id.
    status = bf.burp_replay_status(fid)
    assert status["counts"].get("finished", status["counts"].get("done", 0)) >= 1
    entry = status["units"][0]
    assert entry.get("job_id")
    assert entry.get("host") == "labhost.example"
    assert entry.get("request_line", "").startswith("POST /login")

    # A finished row re-requested → finished-duplicate pointing at the run.
    fin = bf.burp_replay_fleet(requests="r1.txt")["units"][0]
    assert fin["decision"] == "duplicate"
    assert fin["state"] == "finished"
    assert fin.get("job_id")

    status2 = bf.burp_replay_status(fid)
    assert status2["status"] == "ok"
    assert "burp_jvm" in status2


def test_replay_scope_blocked_never_launches(env, monkeypatch):
    from utils import scope_gate

    _request_file(env, "r1.txt")
    monkeypatch.setattr(scope_gate, "check_scan", lambda host, **kw: (False, "out of armed scope"))
    res = bf.burp_replay_fleet(requests="r1.txt")
    assert res["status"] == "nothing-to-do"
    assert res["decision_counts"].get("blocked") == 1
    assert res["scope_blocked"] and "out of armed scope" in res["scope_blocked"][0]
    assert get_worker_queue().units_by_note(res["fleet_id"]) == []


def test_missing_spec_and_input_refusals(env):
    _request_file(env, "r1.txt")
    res = bf.burp_replay_fleet(requests="ghost.txt")
    assert res["units"][0]["decision"] == "refused"
    assert res["units"][0]["reason"] == "input_not_found"
    empty = bf.burp_replay_fleet(requests="")
    assert empty["status"] == "error"
    big = bf.burp_replay_fleet(requests="r1.txt", memory_budget=4096)
    assert big["status"] == "error" and "ceiling" in big["error"]
    bad_retries = bf.burp_replay_fleet(requests="r1.txt", retries="lots")
    assert bad_retries["status"] == "error"
    # MCP down → early refusal before any unit admission.
    orig = bf._mcp_ready
    try:
        bf._mcp_ready = lambda: (False, "connection refused")
        down = bf.burp_replay_fleet(requests="r1.txt")
        assert down["status"] == "error"
        assert "burp MCP" in down["error"]
    finally:
        bf._mcp_ready = orig


def test_verdict_parser_shapes():
    good = (
        "BURP-RETRY i=1 status_code=200 elapsed_ms=12 ok=true\n"
        "BURP-VERDICT json={\"attempts\": 1, \"ok\": 1, \"status_codes\": [200]}"
    )
    assert bf._parse_burp_verdict(good)["ok"] == 1
    ab = bf._parse_burp_verdict(
        "BURP-VERDICT json={\"aborted\": \"scope gate: blocked\"}"
    )
    assert ab["aborted"] and ab["verdict"].startswith("aborted")
    assert bf._parse_burp_verdict("no structured output")["attempts"] is None


def test_status_unknown_fleet(env):
    res = bf.burp_replay_status("burpfleet:nope")
    assert res["status"] == "unknown"


def test_stop_running_units(env, monkeypatch):
    monkeypatch.setenv("STUB_SLEEP", "2.5")
    _request_file(env, "r1.txt")
    _request_file(env, "r2.txt", REQ_TXT.replace("/login", "/admin"))
    res = bf.burp_replay_fleet(requests="r1.txt, r2.txt")
    assert res["decision_counts"].get("launched") == 2
    fid = res["fleet_id"]
    time.sleep(0.3)  # let both launch
    stop = bf.burp_replay_stop(fid)
    assert stop["status"] == "ok"
    assert len(stop["stopped_jobs"]) == 2
    queue = get_worker_queue()
    for k in [u["unit_key"] for u in queue.units_by_note(fid)]:
        assert queue.poll_unit(k)["status"] == "cancelled"