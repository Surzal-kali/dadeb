"""Prelaunch guard + CLI + postgres doctor-provider (bootstrap's front door).

The `daharness` CLI used to silently launch the stack on ANY argument
(including --help) and double-bind the TCP lanes of a unit-managed box —
these tests pin the guard's refusal matrix, the arg surface, the compact
doctor print, and the postgres provider's three down-stories. Nothing here
contacts real services: probes are redirected to throwaway listeners and
closed ports.
"""

import shutil
import socket
import struct

import pytest

import bootstrap
from auxiliaries.framework_status import _check_postgres


def _make_closed_port():
    """An unused TCP port: bind to claim the tuple, close, return the number."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def closed_port():
    return _make_closed_port()


@pytest.fixture
def tcp_listener():
    """Real bound+listening socket on an ephemeral port (answers connect())."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    port = s.getsockname()[1]
    yield port
    s.close()


def _probes(overrides):
    base = {name: False for name, _ in bootstrap.SERVICES_STACK}
    base.update(overrides)
    return base


# ---------------------------------------------------------------- probes


def test_stack_probe_down_ports(monkeypatch, closed_port, tmp_path):
    monkeypatch.setattr(bootstrap, "GATEWAY_PORT", closed_port)
    monkeypatch.setattr(bootstrap, "ZAP_PORT", closed_port)
    monkeypatch.setattr(bootstrap, "MSF_RPC_PORT", closed_port)
    dead = tmp_path / "no-such.sock"
    monkeypatch.setattr(bootstrap, "brain_socket_path", lambda: str(dead))
    live = bootstrap._stack_live_probes()
    assert live == {"brain": False, "gateway": False, "zap": False,
                    "msf": False}


def test_stack_probe_detects_real_listener(monkeypatch, tcp_listener,
                                           closed_port, tmp_path):
    monkeypatch.setattr(bootstrap, "GATEWAY_PORT", tcp_listener)
    monkeypatch.setattr(bootstrap, "ZAP_PORT", closed_port)
    monkeypatch.setattr(bootstrap, "MSF_RPC_PORT", closed_port)
    dead = tmp_path / "no-such.sock"
    monkeypatch.setattr(bootstrap, "brain_socket_path", lambda: str(dead))
    live = bootstrap._stack_live_probes()
    assert live["gateway"] is True
    assert live["zap"] is False


def test_stack_probe_detects_live_brain_socket(monkeypatch, tmp_path):
    """A connectable AF_UNIX path flips the brain probe."""
    sock_path = tmp_path / "brain.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(sock_path))
    server.listen(1)
    monkeypatch.setattr(bootstrap, "brain_socket_path",
                        lambda: str(sock_path))
    try:
        probe = bootstrap._stack_live_probes()
        assert probe["brain"] is True
    finally:
        server.close()
        sock_path.unlink(missing_ok=True)


# ---------------------------------------------------------------- guard


@pytest.mark.parametrize("up_member,unit,expected_rc", [
    (None, "active", 0),          # nothing live -> launch
    (None, None, 0),
    ("gateway", "active", 78),    # unit-managed box, partial stack -> wedged
    ("gateway", None, 1),         # foreign leftovers -> plain refuse
    ("brain", "active", 78),      # every member can trip the refusal
])
def test_guard_branches(up_member, unit, expected_rc, monkeypatch, capsys):
    up = _probes({} if up_member is None else {up_member: True})
    monkeypatch.setattr(bootstrap, "_stack_live_probes", lambda: up)
    monkeypatch.setattr(bootstrap, "_systemctl_is_active", lambda: unit)
    monkeypatch.delenv("INVOCATION_ID", raising=False)
    with capsys.disabled():
        rc = bootstrap._prelaunch_guard()
    assert rc == expected_rc


def test_guard_refuse_message_names_remediations(monkeypatch, capsys):
    monkeypatch.setattr(
        bootstrap, "_stack_live_probes",
        lambda: _probes({"brain": True, "gateway": True}),
    )
    monkeypatch.setattr(bootstrap, "_systemctl_is_active",
                        lambda: "active")
    monkeypatch.delenv("INVOCATION_ID", raising=False)
    rc = bootstrap._prelaunch_guard()
    out = capsys.readouterr().out
    assert rc == 78
    assert "systemctl stop daharness" in out
    assert "daharness --force" in out
    assert "daharness-repl" in out
    for label in ("brain socket", "API gateway", "OWASP ZAP", "msfrpcd"):
        assert label in out


def test_guard_refuse_no_unit_message(monkeypatch, capsys):
    monkeypatch.setattr(
        bootstrap, "_stack_live_probes", lambda: _probes({"msf": True}))
    monkeypatch.setattr(bootstrap, "_systemctl_is_active", lambda: None)
    monkeypatch.delenv("INVOCATION_ID", raising=False)
    rc = bootstrap._prelaunch_guard()
    out = capsys.readouterr().out
    assert rc == 1
    assert "Not managed by systemd" in out
    assert "daharness --force" in out


def test_guard_skips_itself_on_unit_lane(monkeypatch):
    """systemd sets INVOCATION_ID for every child — the unit own launches."""
    monkeypatch.setattr(
        bootstrap, "_stack_live_probes", lambda: _probes({"gateway": True}))
    monkeypatch.setenv("INVOCATION_ID", "smoke-unit")
    assert bootstrap._prelaunch_guard() == 0


def test_guard_force_bypasses_refusal(monkeypatch):
    monkeypatch.setattr(
        bootstrap, "_stack_live_probes", lambda: _probes({"zap": True}))
    monkeypatch.setattr(bootstrap, "_systemctl_is_active", lambda: "active")
    monkeypatch.delenv("INVOCATION_ID", raising=False)
    assert bootstrap._prelaunch_guard(force=True) == 0


# ---------------------------------------------------------------- CLI


def test_cli_defaults_and_flags(monkeypatch):
    parser = bootstrap._build_cli()
    args = parser.parse_args([])
    assert args.daemon is False
    assert args.force is False
    assert args.command is None
    args = parser.parse_args(["--daemon", "--force"])
    assert args.daemon is True
    assert args.force is True


def test_cli_doctor_command():
    args = bootstrap._build_cli().parse_args(["doctor"])
    assert args.command == "doctor"


def test_cli_doctor_provider_drilldown(monkeypatch, capsys):
    """`daharness doctor registry` routes the provider into framework_doctor
    (the wait-timeout error text advertises exactly this spelling)."""
    import auxiliaries.framework_status as fstat
    seen = {}
    fake = {"overall": "ok", "available": "1/1",
            "providers": {"registry": {"available": True,
                                     "reason": "answering", "remediation": "",
                                     "provider": "registry"}},
            "timestamp": "t"}

    def spy(provider=""):
        seen["p"] = provider
        return fake
    monkeypatch.setattr(fstat, "framework_doctor", spy)
    assert bootstrap._print_doctor(provider="registry") == 0
    assert seen["p"] == "registry"
    assert "registry" in capsys.readouterr().out


def test_cli_rejects_unknown_command(capsys):
    with pytest.raises(SystemExit):
        bootstrap._build_cli().parse_args(["frobnicate"])
    assert "invalid choice" in capsys.readouterr().err


def test_print_doctor_compact(monkeypatch, capsys):
    import auxiliaries.framework_status as fstat

    fake = {
        "overall": "degraded",
        "available": "7/8",
        "providers": {
            "r2": {"available": True, "reason": "r2 on PATH",
                   "remediation": "", "provider": "r2"},
            "msf": {"available": False, "reason": "RPC down",
                    "remediation": "start msfconsole + msgrpc",
                    "provider": "msf"},
        },
        "timestamp": "t",
    }
    monkeypatch.setattr(fstat, "framework_doctor", lambda provider="": fake)
    assert bootstrap._print_doctor() == 1  # degraded = scriptable non-zero
    out = capsys.readouterr().out
    assert "framework doctor — degraded (7/8 providers up)" in out
    assert "r2" in out and "up" in out
    assert "msf" in out and "RPC down" in out
    assert "start msfconsole + msgrpc" in out


def test_print_doctor_reports_failure(monkeypatch):
    import auxiliaries.framework_status as fstat

    monkeypatch.setattr(
        fstat, "framework_doctor",
        lambda provider="": {
            "overall": "down", "available": "0/1", "providers": {}})
    assert bootstrap._print_doctor() == 1


# ---------------------------------------------------------------- postgres


@pytest.fixture
def pg_env_path(tmp_path, monkeypatch):
    monkeypatch.setenv("DAHARNESS_PG_ENV", str(tmp_path / "pg.env"))
    return tmp_path / "pg.env"


@pytest.fixture
def pg_port(monkeypatch, closed_port):
    """Aim postgres's port probe at a harmless closed port per test."""
    monkeypatch.setenv("HARNESS_DB_PORT", str(closed_port))
    return closed_port


def test_postgres_up_answers(tmp_path, tcp_listener, pg_env_path, monkeypatch):
    monkeypatch.setenv("HARNESS_DB_PORT", str(tcp_listener))
    rec = _check_postgres()
    assert rec["provider"] == "postgres"
    assert rec["available"] is True
    assert "answering" in rec["reason"]


def test_postgres_tooling_absent(pg_port, pg_env_path, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda proc: None)
    rec = _check_postgres()
    assert rec["available"] is False
    assert "apt install postgresql" in rec["remediation"]
    assert "pip install -e" in rec["remediation"]


def test_postgres_never_initialized(pg_port, pg_env_path, monkeypatch):
    monkeypatch.setattr(
        shutil, "which",
        lambda proc: "/usr/bin/" + proc
        if proc in ("psql", "pg_createcluster") else None)
    rec = _check_postgres()
    assert rec["available"] is False
    assert "never initialized" in rec["reason"]
    assert rec["remediation"].startswith("sudo daharness-pg init")


def test_postgres_provisioned_but_down(pg_port, pg_env_path, monkeypatch):
    monkeypatch.setattr(
        shutil, "which",
        lambda proc: "/usr/bin/" + proc
        if proc in ("psql", "pg_createcluster") else None)
    pg_env_path.write_text("HARNESS_DB_PORT=5433\n")
    rec = _check_postgres()
    assert rec["available"] is False
    assert "not answering" in rec["reason"]
    assert "daharness-pg start" in rec["remediation"]


def test_postgres_up_answers_via_gateway(tcp_listener, pg_env_path, monkeypatch):
    """Container-lane path: HARNESS_DB_HOST pins the workbench-bridge
    gateway (172.28.0.1) — the doctor must probe that candidate, not the
    hardcoded 127.0.0.1 it used before alignment. tcp_listener binds
    127.0.0.1, so point HARNESS_DB_HOST back at loopback to simulate the
    gateway being reachable; this verifies the explicit-host pin is
    honored (the bug was the doctor ignoring it)."""
    monkeypatch.setenv("HARNESS_DB_HOST", "127.0.0.1")
    monkeypatch.setenv("HARNESS_DB_PORT", str(tcp_listener))
    rec = _check_postgres()
    assert rec["available"] is True
    assert "answering on 127.0.0.1" in rec["reason"]


def test_postgres_up_falls_back_to_gateway(tcp_listener, pg_env_path, monkeypatch):
    """Default order (no HARNESS_DB_HOST): 127.0.0.1 first, then
    172.28.0.1. A listener on 127.0.0.1 answers on the first candidate —
    the same path host lanes have always taken, now unchanged."""
    monkeypatch.delenv("HARNESS_DB_HOST", raising=False)
    monkeypatch.setenv("HARNESS_DB_PORT", str(tcp_listener))
    rec = _check_postgres()
    assert rec["available"] is True


def test_postgres_down_reports_all_candidates(pg_port, pg_env_path, monkeypatch):
    """When the cluster is down, the reason names every host tried so the
    operator can see both the loopback and gateway attempts."""
    monkeypatch.setattr(
        shutil, "which",
        lambda proc: "/usr/bin/" + proc
        if proc in ("psql", "pg_createcluster") else None)
    pg_env_path.write_text("HARNESS_DB_PORT=5433\n")
    rec = _check_postgres()
    assert rec["available"] is False
    reason = rec["reason"]
    assert "127.0.0.1" in reason and "172.28.0.1" in reason


def test_doctor_drills_into_postgres(monkeypatch):
    """provider='postgres' probes ONLY that lane and still shapes a report."""
    import auxiliaries.framework_status as fstat

    monkeypatch.setattr(
        fstat, "_check_postgres",
        lambda: {"available": True, "provider": "postgres",
                 "reason": "stub", "remediation": ""})
    report = fstat.framework_doctor(provider="postgres")
    assert set(report["providers"]) == {"postgres"}
    assert report["overall"] == "ok"
    assert report["available"] == "1/1"


def test_doctor_unknown_provider_names_postgres():
    from auxiliaries.framework_status import framework_doctor

    rec = framework_doctor(provider="bogus")["providers"]["_unknown_provider"]
    assert "postgres" in rec["remediation"]


# ------------------------------------------------------- state-root access


def test_doctor_snapshot_probe_degrades_on_permission(monkeypatch):
    """An operator lane outside the shared group cannot touch the state root;
    a doctor probe must degrade into a down record, never a traceback."""
    import auxiliaries.framework_status as fstat

    def denied():
        raise PermissionError(13, "Permission denied", "/var/lib/daharness/run")

    monkeypatch.setattr(fstat, "get_snapshot_store", denied)
    from auxiliaries.framework_status import framework_doctor
    rec = framework_doctor(provider="snapshot_cache")["providers"]["snapshot_cache"]
    assert rec["available"] is False
    assert "permission denied" in rec["reason"]
    assert "sudo daharness doctor" in rec["remediation"]
    assert "usermod -aG daharness" in rec["remediation"]


def test_doctor_sweep_survives_store_failure(monkeypatch):
    """The full sweep keeps a shaped report when the store blows up."""
    import auxiliaries.framework_status as fstat

    def boom():
        raise PermissionError(13, "Permission denied", "/var/lib/daharness/run")

    monkeypatch.setattr(fstat, "get_snapshot_store", boom)
    from auxiliaries.framework_status import framework_doctor
    report = framework_doctor()
    rec = report["providers"]["snapshot_cache"]
    assert rec["available"] is False
    assert set(report["providers"]) >= {"r2", "snapshot_cache"}  # sweep completed


def test_doctor_jadx_probe_uses_workspace_root(monkeypatch, tmp_path):
    """The apk drop-dir probe resolves like the tool (workspace root /
    postinst lane), NOT the read-only package tree (`__file__` math was the
    VM bug: doctor demanded /usr/share/daharness/apk while postinst created
    /var/lib/daharness/apk)."""
    import shutil as shutil_mod

    import auxiliaries.framework_status as fstat

    empty_ws = tmp_path / "ws"
    empty_ws.mkdir()
    real_which = shutil_mod.which
    monkeypatch.setattr(
        shutil_mod, "which",
        lambda cmd: "/usr/bin/jadx" if cmd == "jadx" else real_which(cmd))
    import auxiliaries.jadx as jadx_mod
    monkeypatch.setattr(jadx_mod, "APK_TARGETS_ROOT", str(empty_ws / "apk"))

    rec = fstat._check_jadx()
    assert rec["available"] is False
    assert str(empty_ws / "apk") in rec["reason"]
    assert "JADX_APK_TARGETS_ROOT" in rec["remediation"]

    (empty_ws / "apk").mkdir()
    rec = fstat._check_jadx()
    assert rec["available"] is True
    assert str(empty_ws / "apk") in rec["reason"]


@pytest.fixture
def masscan_on_path(monkeypatch):
    """Doctor sees masscan on PATH without depending on its install."""
    monkeypatch.setattr(
        "auxiliaries.framework_status._check_path",
        lambda cmd: {"available": True, "reason": "/usr/bin/masscan",
                     "remediation": ""},
    )
    monkeypatch.setattr(
        "auxiliaries.framework_status.shutil.which",
        lambda cmd: "/usr/bin/masscan",
    )


def test_masscan_probe_grades_setcapd_binary_capable(monkeypatch, masscan_on_path):
    """A setcap'd binary launches from an unprivileged lane: the probe that
    graded its own denied SOCK_RAW attempt reported 'may fail at launch,
    not at probe' for a scan that would actually have run."""
    import os as os_mod
    import auxiliaries.framework_status as fstat

    monkeypatch.setattr(os_mod, "geteuid", lambda: 1000)
    monkeypatch.setattr(fstat, "_process_raw_socket_ok", lambda: False)
    monkeypatch.setattr(
        fstat, "_read_file_cap_net_raw",
        lambda path: {"revision": 3, "effective_flag": True,
                      "cap_net_raw": True, "size": 24},
    )
    rec = fstat._check_masscan()
    assert rec["available"] is True
    assert "cap_net_raw" in rec["reason"]
    assert "denied" in rec["reason"]        # lane probe failure is stated
    assert rec["extra"]["lane_sock_raw"] is False
    assert rec["extra"]["file_caps"]["cap_net_raw"] is True


def test_masscan_probe_lane_socket_inherited(monkeypatch, masscan_on_path):
    """When the lane can create SOCK_RAW, launched subprocesses inherit it —
    the reason must name that source, not imply a hidden mismatch."""
    import os as os_mod
    import auxiliaries.framework_status as fstat

    monkeypatch.setattr(os_mod, "geteuid", lambda: 1000)
    monkeypatch.setattr(fstat, "_process_raw_socket_ok", lambda: True)
    monkeypatch.setattr(
        fstat, "_read_file_cap_net_raw",
        lambda path: {"decode_error": "no file capability applied (not setcap'd)"},
    )
    rec = fstat._check_masscan()
    assert rec["available"] is True
    assert "SOCK_RAW" in rec["reason"] and "inherit" in rec["reason"]


def test_masscan_probe_root_lane(monkeypatch, masscan_on_path):
    import os as os_mod
    import auxiliaries.framework_status as fstat

    monkeypatch.setattr(os_mod, "geteuid", lambda: 0)
    monkeypatch.setattr(fstat, "_process_raw_socket_ok", lambda: False)
    monkeypatch.setattr(
        fstat, "_read_file_cap_net_raw",
        lambda path: {"decode_error": "no file capability applied (not setcap'd)"},
    )
    rec = fstat._check_masscan()
    assert rec["available"] is True
    assert "root" in rec["reason"]


def test_masscan_probe_no_privilege_scopes_to_lane(monkeypatch, masscan_on_path):
    """No privilege anywhere on this lane: the verdict says the scan fails
    from THIS lane, never the old 'may fail at launch, not at probe' that
    its own failed probe contradicted."""
    import os as os_mod
    import auxiliaries.framework_status as fstat

    monkeypatch.setattr(os_mod, "geteuid", lambda: 1000)
    monkeypatch.setattr(fstat, "_process_raw_socket_ok", lambda: False)
    monkeypatch.setattr(
        fstat, "_read_file_cap_net_raw",
        lambda path: {"decode_error": "no file capability applied (not setcap'd)"},
    )
    rec = fstat._check_masscan()
    assert rec["available"] is False
    assert "not at probe" not in rec["reason"]
    assert "from this lane" in rec["reason"]
    assert "uid 1000" in rec["reason"]
    assert "sudo setcap cap_net_raw+ep" in rec["remediation"]


def test_parse_cap_xattr_setcapd_ep_is_effective():
    """cap_net_raw+ep (rev 3): permitted bit 13 plus the effective flag is
    an exec-time-capable grant."""
    from auxiliaries.framework_status import _parse_cap_xattr
    blob = struct.pack("<6I", 0x03000001, 1 << 13, 0, 0, 0, 1000)
    dec = _parse_cap_xattr(blob)
    assert dec["cap_net_raw"] is True
    assert dec["cap_net_raw_in_permitted"] is True
    assert dec["effective_flag"] is True
    assert dec["revision"] == 3


def test_parse_cap_xattr_bare_p_grant_is_inert():
    """``setcap cap_net_raw+p`` stores the bit but never reaches the
    effective set for an unprivileged exec — the probe must not upgrade it."""
    from auxiliaries.framework_status import _parse_cap_xattr
    blob = struct.pack("<4I", 0x02000000, 1 << 13, 0, 0)
    dec = _parse_cap_xattr(blob)
    assert dec["cap_net_raw"] is False
    assert dec["cap_net_raw_in_permitted"] is True
    assert dec["effective_flag"] is False


def test_parse_cap_xattr_other_cap_is_not_net_raw():
    """Only bit 13 counts: cap_net_bind_service+ep grades as not raw-capable."""
    from auxiliaries.framework_status import _parse_cap_xattr
    blob = struct.pack("<6I", 0x03000001, 1 << 10, 0, 0, 0, 1000)
    dec = _parse_cap_xattr(blob)
    assert dec["cap_net_raw"] is False


def test_parse_cap_xattr_rev1_and_junk():
    """Rev1 12-byte blobs decode; garbage sizes fail loudly, not by being
    silently read as 'no caps'."""
    from auxiliaries.framework_status import _parse_cap_xattr
    rev1 = _parse_cap_xattr(struct.pack("<3I", 0x01000001, 1 << 13, 0))
    assert rev1["cap_net_raw"] is True and rev1["revision"] == 1
    junk = _parse_cap_xattr(struct.pack("<2I", 0x02000001, 1 << 13))
    assert "decode_error" in junk


def test_print_doctor_sudo_hint_on_permission_error(monkeypatch, capsys):
    """`daharness doctor` on a locked state root prints the sudo fix,
    exits 77 — not a raw traceback (the operator ask, VM 2026-10-20)."""
    import auxiliaries.framework_status as fstat

    def denied(provider=""):
        raise PermissionError(13, "Permission denied", "/var/lib/daharness/run")

    monkeypatch.setattr(fstat, "framework_doctor", denied)
    rc = bootstrap._print_doctor()
    out = capsys.readouterr().out
    assert rc == 77
    assert "sudo daharness doctor" in out
    assert "Traceback" not in out


def test_doctor_gate_refuses_foreign_lane(monkeypatch, tmp_path):
    """A lane outside the state root's owner/group gets a refusal, not a
    blind sweep of shared state that would grade false downs."""
    import os as os_mod
    import auxiliaries.framework_status as fstat

    ws = tmp_path / "ws"
    ws.mkdir()
    monkeypatch.setenv("WORKSPACE_ROOT", str(ws))
    monkeypatch.setattr(os_mod, "geteuid", lambda: 424242)
    monkeypatch.setattr(os_mod, "getgroups", lambda: [4242])
    with pytest.raises(PermissionError, match="sudo daharness doctor"):
        fstat.framework_doctor()


def test_doctor_gate_allows_root(monkeypatch, tmp_path):
    import os as os_mod
    import auxiliaries.framework_status as fstat

    ws = tmp_path / "ws"
    ws.mkdir()
    monkeypatch.setenv("WORKSPACE_ROOT", str(ws))
    monkeypatch.setattr(os_mod, "geteuid", lambda: 0)
    monkeypatch.setattr(os_mod, "getgroups", lambda: [4242])
    report = fstat.framework_doctor()
    assert "providers" in report


def test_doctor_gate_allows_state_root_owner_group(monkeypatch, tmp_path):
    """Group membership is the designed operator share: the deb's state
    root is daharness:daharness 2770, and a re-logged group member runs
    the doctor unprivileged."""
    import os as os_mod
    import auxiliaries.framework_status as fstat

    ws = tmp_path / "ws"
    ws.mkdir()
    monkeypatch.setenv("WORKSPACE_ROOT", str(ws))
    monkeypatch.setattr(os_mod, "geteuid", lambda: 424242)
    monkeypatch.setattr(os_mod, "getgroups",
                        lambda: [os_mod.stat(ws).st_gid])
    report = fstat.framework_doctor()
    assert "providers" in report