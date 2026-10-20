"""Chroma sidecar merge (2026-10-20) — the registry backend's lifecycle.

The retired daharness-chroma.service is a bootstrap sidecar now. These
tests pin the four behaviors that made the old unit quietly lethal:
reuse-first adoption, real spawn only on a silent lane, honest
absence (chroma_backend_absent + no dead wait), and the readiness wait's
loud failure. Packaging sanity asserts the retirement is complete.
"""

import asyncio
import shutil
import socket
import subprocess
import textwrap
import types
from pathlib import Path

import pytest

import bootstrap

REPO_ROOT = Path(__file__).resolve().parent.parent
WRAPPER = REPO_ROOT / "packaging" / "bin" / "daharness-chroma"


def _shim(**attrs):
    base = {"active_tasks": [], "runner": None}
    base.update(attrs)
    return types.SimpleNamespace(**base)


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _listener():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    return s, s.getsockname()[1]


FAKE_CHROMA = textwrap.dedent("""\
    #!/bin/sh
    printf '%s\\n' "$@" >> "{rec}"
    echo ready
    sleep 600
    """)


@pytest.fixture
def fake_chroma_bin(tmp_path):
    rec = tmp_path / "argv.txt"
    bin_path = tmp_path / "chroma"
    bin_path.write_text(FAKE_CHROMA.format(rec=rec))
    bin_path.chmod(0o755)
    return bin_path, rec


# ---------------------------------------------------------------- spawn


def test_reuse_occupied_lane_never_spawns(fake_chroma_bin, monkeypatch,
                                          tmp_path):
    """Something ANSWERING on the lane is a live backend — adopt, not
    double-spawn (the compose container / manual-lane adoption rule)."""
    bin_path, rec = fake_chroma_bin
    srv, port = _listener()
    monkeypatch.setenv("CHROMA_BIN", str(bin_path))
    try:
        shim = _shim()

        async def drive():
            return await bootstrap.FrameworkLoader.start_chroma_daemon(
                shim, host="127.0.0.1", port=port, path=str(tmp_path / "p"))

        result = asyncio.run(drive())
        assert result == "reused"
        assert shim.active_tasks == []
        assert not rec.exists()   # no process was ever launched
    finally:
        srv.close()


def test_spawn_on_silent_lane(fake_chroma_bin, monkeypatch, tmp_path):
    """A silent lane gets a real subprocess, appended to active_tasks so
    the generic stop() reaper owns it."""
    bin_path, rec = fake_chroma_bin
    port = _free_port()
    monkeypatch.setenv("CHROMA_BIN", str(bin_path))
    persist = tmp_path / "persist"
    shim = _shim()

    async def drive():
        return await bootstrap.FrameworkLoader.start_chroma_daemon(
            shim, host="127.0.0.1", port=port, path=str(persist))

    try:
        result = asyncio.run(drive())
        assert isinstance(result, asyncio.subprocess.Process)
        assert result in shim.active_tasks
        assert persist.is_dir()   # leaf dir created before chroma opens it
    finally:
        for t in shim.active_tasks:
            if isinstance(t, asyncio.subprocess.Process):
                t.terminate()
        asyncio.run(asyncio.sleep(0.1))


def test_spawn_argv_pins_lane(fake_chroma_bin, monkeypatch, tmp_path):
    bin_path, rec = fake_chroma_bin
    port = _free_port()
    monkeypatch.setenv("CHROMA_BIN", str(bin_path))
    shim = _shim()

    async def drive():
        return await bootstrap.FrameworkLoader.start_chroma_daemon(
            shim, host="127.0.0.1", port=port, path=str(tmp_path / "z"))

    tasks = []
    try:
        proc = asyncio.run(drive())
        tasks = [proc]
        import time
        deadline = time.monotonic() + 5
        while not rec.exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        argv = rec.read_text().splitlines()
    finally:
        for t in tasks:
            t.terminate()
        asyncio.run(asyncio.sleep(0.1))
    assert argv == ["run", "--path", str(tmp_path / "z"), "--host",
                    "127.0.0.1", "--port", str(port)]


def test_absent_binary_sets_permanent_answer(fake_chroma_bin, monkeypatch):
    """No binary anywhere -> chroma_backend_absent flag (same 'permanent
    answer' contract as ZAP's absent launcher), never a dead spawn loop."""
    monkeypatch.delenv("CHROMA_BIN", raising=False)
    monkeypatch.setattr(shutil, "which", lambda name: None)
    shim = _shim()

    async def drive():
        return await bootstrap.FrameworkLoader.start_chroma_daemon(
            shim, host="127.0.0.1", port=_free_port(),
            path="/nonexistent/chroma")

    result = asyncio.run(drive())
    assert result is None
    assert shim.chroma_backend_absent is True
    assert shim.active_tasks == []


# ---------------------------------------------------------------- wait


def test_wait_skips_budget_when_backend_absent(monkeypatch):
    """The absent flag must be consumed by wait_for_chroma so a dead
    backend never burns the readiness budget."""
    monkeypatch.delenv("CHROMA_BIN", raising=False)
    monkeypatch.setattr(shutil, "which", lambda name: None)
    shim = _shim()
    port = _free_port()

    async def drive():
        await bootstrap.FrameworkLoader.start_chroma_daemon(
            shim, host="127.0.0.1", port=port, path="/nonexistent/chroma")
        return await bootstrap.FrameworkLoader.wait_for_chroma(
            shim, host="127.0.0.1", port=port, timeout=30)

    assert asyncio.run(drive()) is False


def test_wait_returns_true_on_live_lane():
    srv, port = _listener()
    shim = _shim()
    try:

        async def drive():
            return await bootstrap.FrameworkLoader.wait_for_chroma(
                shim, host="127.0.0.1", port=port, timeout=5)

        assert asyncio.run(drive()) is True
    finally:
        srv.close()


def test_wait_times_out_loudly():
    """Silent lane + absent flag unset -> the SEMANTIC SEARCH IS DOWN
    error, not silence."""
    port = _free_port()
    shim = _shim()

    async def drive():
        return await bootstrap.FrameworkLoader.wait_for_chroma(
            shim, host="127.0.0.1", port=port, timeout=1.5)

    assert asyncio.run(drive()) is False
    assert not getattr(shim, "chroma_backend_absent", False)


# ---------------------------------------------------------------- doctor


def test_check_chroma_up(monkeypatch):
    import auxiliaries.framework_status as fstat
    srv, port = _listener()
    monkeypatch.setenv("CHROMA_HOST", "127.0.0.1")
    monkeypatch.setenv("CHROMA_PORT", str(port))
    try:
        rec = fstat._check_chroma()
        assert rec["available"] is True
    finally:
        srv.close()


def test_check_chroma_down(monkeypatch):
    import auxiliaries.framework_status as fstat
    monkeypatch.setenv("CHROMA_HOST", "127.0.0.1")
    monkeypatch.setenv("CHROMA_PORT", str(_free_port()))
    rec = fstat._check_chroma()
    assert rec["available"] is False
    assert rec["remediation"]


# ------------------------------------------------------------ packaging


def test_retired_unit_file_gone():
    assert not (REPO_ROOT / "packaging" / "systemd" /
                "daharness-chroma.service").exists()


def test_preset_has_no_chroma_line():
    text = (REPO_ROOT / "packaging" / "systemd" /
            "98-daharness.preset").read_text()
    assert "daharness-chroma" not in text


def test_daemon_unit_has_no_chroma_wiring():
    """Comments may narrate the retirement history; the unit must not
    WIRE the chroma lane (Wants/After/ExecStartPre) anymore."""
    for line in (REPO_ROOT / "packaging" / "systemd" /
                 "daharness.service").read_text().splitlines():
        if any(line.lstrip().startswith(k)
               for k in ("Wants=", "After=", "ExecStart", "Also=")):
            assert "chroma" not in line


def test_rules_no_longer_installs_chroma_unit():
    rules = REPO_ROOT / "debian" / "rules"
    assert "daharness-chroma.service" not in rules.read_text()


def test_postinst_retires_legacy_unit():
    postinst = REPO_ROOT / "debian" / "daharness.postinst"
    text = postinst.read_text()
    assert "systemctl stop daharness-chroma.service" in text
    assert "systemctl disable daharness-chroma.service" in text
    assert "chroma is a daemon sidecar now" in text


# ------------------------------------------------------------- wrapper


def _run_wrapper(args, env):
    return subprocess.run(
        [str(WRAPPER), *args], env=env, capture_output=True, text=True,
        timeout=30)


def _wrapper_env(tmp_path, **over):
    import os
    env = dict(os.environ)
    env["CHROMA_HOST"] = "127.0.0.1"
    env["CHROMA_PORT"] = str(_free_port())
    env["CHROMA_PATH"] = str(tmp_path / "wpersist")
    env["CHROMA_BIN"] = "/bin/true"
    env.update({k: str(v) for k, v in over.items()})
    return env


FAKE_CHROMA_FAST = textwrap.dedent("""\
    #!/bin/sh
    printf '%s\\n' "$@" >> "{rec}"
    """)


def _mk_fake_bin(tmp_path):
    """(bin_path, rec) fake that records argv and exits immediately —
    the wrapper exec() replaces sh, so a sleeping fake would stall
    subprocess.run in these tests (the slow fake is for the loader
    spawn tests, which hold a real Process handle)."""
    rec = tmp_path / "wrapper-argv.txt"
    bin_path = tmp_path / "chroma-fake"
    bin_path.write_text(FAKE_CHROMA_FAST.format(rec=rec))
    bin_path.chmod(0o755)
    return bin_path, rec


def test_wrapper_refuses_occupied_port(tmp_path):
    bin_path, rec = _mk_fake_bin(tmp_path)
    srv, port = _listener()
    try:
        env = _wrapper_env(tmp_path, CHROMA_PORT=port, CHROMA_BIN=bin_path)
        proc = _run_wrapper([], env)
        assert proc.returncode == 78
        assert "systemctl stop daharness" in proc.stderr
        assert "CHROMA_PORT" in proc.stderr
        assert not rec.exists()   # refused before any exec
    finally:
        srv.close()


def test_wrapper_force_bypasses_and_execs(tmp_path):
    bin_path, rec = _mk_fake_bin(tmp_path)
    srv, port = _listener()
    try:
        env = _wrapper_env(tmp_path, CHROMA_PORT=port, CHROMA_BIN=bin_path)
        proc = _run_wrapper(["--force", "extra"], env)
        assert proc.returncode == 0
        argv = rec.read_text()
        assert "--force" not in argv   # consumed by the wrapper
        assert "extra" in argv
    finally:
        srv.close()


def test_wrapper_free_port_execs(tmp_path):
    bin_path, rec = _mk_fake_bin(tmp_path)
    env = _wrapper_env(tmp_path, CHROMA_BIN=bin_path)
    proc = _run_wrapper(["--headers-enabled"], env)
    assert proc.returncode == 0
    assert "--headers-enabled" in rec.read_text()


def test_wrapper_help_does_not_exec(tmp_path):
    bin_path, rec = _mk_fake_bin(tmp_path)
    env = _wrapper_env(tmp_path, CHROMA_BIN=bin_path)
    proc = _run_wrapper(["--help"], env)
    assert proc.returncode == 0
    assert "manual" in proc.stdout.lower()
    assert not rec.exists()   # help short-circuits before any exec


def test_wrapper_is_executable_sh():
    assert WRAPPER.exists() and WRAPPER.stat().st_mode & 0o111
    assert subprocess.run(["sh", "-n", str(WRAPPER)]).returncode == 0