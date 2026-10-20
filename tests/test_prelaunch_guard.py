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
    monkeypatch.setattr(bootstrap, "CHROMA_PORT", closed_port)
    dead = tmp_path / "no-such.sock"
    monkeypatch.setattr(bootstrap, "brain_socket_path", lambda: str(dead))
    live = bootstrap._stack_live_probes()
    assert live == {"brain": False, "gateway": False, "zap": False,
                    "msf": False, "chroma": False}


def test_stack_probe_detects_real_listener(monkeypatch, tcp_listener,
                                           closed_port, tmp_path):
    monkeypatch.setattr(bootstrap, "GATEWAY_PORT", tcp_listener)
    monkeypatch.setattr(bootstrap, "ZAP_PORT", closed_port)
    monkeypatch.setattr(bootstrap, "MSF_RPC_PORT", closed_port)
    monkeypatch.setattr(bootstrap, "CHROMA_PORT", closed_port)
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


def test_stack_probe_detects_chroma_listener(monkeypatch, tcp_listener,
                                             closed_port):
    """The chroma member probes the registry backend's TCP port."""
    monkeypatch.setattr(bootstrap, "CHROMA_PORT", tcp_listener)
    monkeypatch.setattr(bootstrap, "CHROMA_HOST", "127.0.0.1")
    monkeypatch.setattr(bootstrap, "GATEWAY_PORT", closed_port)
    monkeypatch.setattr(bootstrap, "ZAP_PORT", closed_port)
    monkeypatch.setattr(bootstrap, "MSF_RPC_PORT", closed_port)
    probe = bootstrap._stack_live_probes()
    assert probe["chroma"] is True


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
    for label in ("brain socket", "API gateway", "OWASP ZAP", "msfrpcd",
                  "chroma lane"):
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
    """`daharness doctor chroma` routes the provider into framework_doctor
    (the wait-timeout error text advertises exactly this spelling)."""
    import auxiliaries.framework_status as fstat
    seen = {}
    fake = {"overall": "ok", "available": "1/1",
            "providers": {"chroma": {"available": True,
                                     "reason": "answering", "remediation": "",
                                     "provider": "chroma"}},
            "timestamp": "t"}

    def spy(provider=""):
        seen["p"] = provider
        return fake
    monkeypatch.setattr(fstat, "framework_doctor", spy)
    assert bootstrap._print_doctor(provider="chroma") == 0
    assert seen["p"] == "chroma"
    assert "chroma" in capsys.readouterr().out


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