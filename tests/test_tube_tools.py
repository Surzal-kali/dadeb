"""Tests for the tube lane (payloads/tube.py) — raw protocol dialogue.

Covers handle-kind namespace validation, scope-gate enforcement at open and
re-check at send, banner capture on a send-first service, the full dialogue
round trip against a live in-test TCP server, and hex/base64 payload
encodings for binary sends.
"""

import socket
import threading

import pytest

from utils import scope_gate
from utils.handles import parse_handle


@pytest.fixture
def armed_scope_lab(state_root):
    """Arm the gate with a lab manifest blessing 127.0.0.0/8 loopback."""
    scope_dir = state_root / "scope"
    scope_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "handle": "lab-loopback",
        "platform": "lab",
        "in_scope": [{"asset_type": "CIDR", "asset_identifier": "127.0.0.0/8"}],
        "out_of_scope_assets": [],
    }
    (scope_dir / "lab_lab-loopback.json").write_text(json.dumps(manifest))
    scope_gate._CACHE.clear()
    res = scope_gate.arm("lab-loopback", platform="lab")
    assert res["ok"], res
    yield state_root
    scope_gate.disarm()
    scope_gate._CACHE.clear()


import json  # noqa: E402  (fixture above needs it; kept next to usage)


@pytest.fixture
def echo_server():
    """A tiny send-first echo server: banner on connect, echoes lines."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    received: list[bytes] = []
    stop = threading.Event()

    def serve():
        try:
            srv.settimeout(0.5)
            while not stop.is_set():
                try:
                    conn, _ = srv.accept()
                except socket.timeout:
                    continue
                # One long window for the WHOLE connection dialogue —
                # a per-recv 5s budget raced the client-side recv_until
                # timeout (both fired ~t+5s) and closed the conn out
                # from under the test's send (flaky hex test 2026-11-24).
                conn.settimeout(30)
                try:
                    conn.sendall(b"WELCOME line1\n> ")
                    while not stop.is_set():
                        data = conn.recv(4096)
                        if not data:
                            break
                        received.append(data)
                        conn.sendall(b"echo:" + data)
                except OSError:
                    pass
                finally:
                    conn.close()
        except OSError:
            pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield port, received
    stop.set()
    t.join(timeout=2)
    srv.close()


@pytest.fixture
def tube():
    """Import payloads.tube with a fresh SessionManager per test module."""
    from payloads import tube as tube_mod
    return tube_mod


class TestOpenAndGate:
    def test_open_gated_out_of_scope_refused(self, state_root, tube):
        # Gate armed against a manifest that does NOT include the target.
        # Framework convention (ssh_exec/nmap precedent): a refusal RAISES.
        scope_dir = state_root / "scope"
        scope_dir.mkdir(parents=True, exist_ok=True)
        manifest = {
            "handle": "lab-no-loopback",
            "platform": "lab",
            "in_scope": [{"asset_type": "CIDR", "asset_identifier": "203.0.113.0/24"}],
            "out_of_scope_assets": [],
        }
        (scope_dir / "lab_lab-no-loopback.json").write_text(json.dumps(manifest))
        scope_gate._CACHE.clear()
        try:
            assert scope_gate.arm("lab-no-loopback", platform="lab")["ok"]
            from payloads.tube import tube_open
            from utils.scope_gate import ScopeGateError
            with pytest.raises(ScopeGateError) as exc_info:
                tube_open("127.0.0.1", 9999)
            assert "not confirmed in-scope" in str(exc_info.value)
            # The error path carries the operator remediation hint.
            assert "scope add-ip" in str(exc_info.value)
        finally:
            scope_gate.disarm()
            scope_gate._CACHE.clear()

    def test_open_in_scope_loopback_passes(self, armed_scope_lab, tube):
        from payloads.tube import tube_open
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            res = tube_open("127.0.0.1", port)
            assert res["status"] == "ok", res
            kind, sid = parse_handle(res["handle"])
            assert kind == "tube"
        finally:
            srv.close()
            scope_gate.disarm()

    def test_open_validates_args(self, armed_scope_lab, tube):
        from payloads.tube import tube_open
        assert tube_open("", 80)["status"] == "Failed"
        assert tube_open("127.0.0.1", 0)["status"] == "Failed"
        assert tube_open("127.0.0.1", 70000)["status"] == "Failed"
        assert tube_open("127.0.0.1", 80, proto="sctp")["status"] == "Failed"


class TestDialogue:
    def test_banner_captured_on_open(self, armed_scope_lab, echo_server, tube):
        from payloads.tube import tube_open
        port, _ = echo_server
        res = tube_open("127.0.0.1", port)
        assert res["status"] == "ok", res
        assert res["banner"] is not None
        assert "WELCOME line1" in res["banner"]["text"]

    def test_send_recv_round_trip(self, armed_scope_lab, echo_server, tube):
        from payloads.tube import tube_open, tube_send, tube_recv_until
        port, received = echo_server
        res = tube_open("127.0.0.1", port)
        handle = res["handle"]
        sent = tube_send(handle, "PING\n")
        assert sent["status"] == "ok" and sent["sent"] == 5
        out = tube_recv_until(handle, expect="echo:", timeout=5)
        assert out["status"] == "ok", out
        assert out["terminator"] == "expect"
        assert "echo:PING" in out["payload"]["text"]

    def test_hex_encoding_binary_send(self, armed_scope_lab, echo_server, tube):
        from payloads.tube import tube_open, tube_send
        port, received = echo_server
        res = tube_open("127.0.0.1", port)
        handle = res["handle"]
        # NOTE: the banner was already harvested by tube_open (res["banner"]);
        # the server is waiting for our bytes, no dummy recv needed.
        sent = tube_send(handle, "41424344", encoding="hex")
        assert sent["status"] == "ok" and sent["sent"] == 4
        # Server received raw ABCD bytes — hex decoded before the wire.
        deadline = __import__("time").time() + 5
        while __import__("time").time() < deadline and b"ABCD" not in b"".join(received):
            __import__("time").sleep(0.05)
        assert b"ABCD" in b"".join(received)

    def test_b64_and_bad_encoding(self, armed_scope_lab, echo_server, tube):
        from payloads.tube import tube_open, tube_send
        port, _ = echo_server
        res = tube_open("127.0.0.1", port)
        handle = res["handle"]
        ok = tube_send(handle, "UElORw==", encoding="b64")  # "PING"
        assert ok["status"] == "ok" and ok["sent"] == 4
        bad = tube_send(handle, "!!", encoding="hex")
        assert bad["status"] == "Failed" and "hex" in bad["error"]

    def test_wrong_kind_handle_refused(self, armed_scope_lab, tube):
        from payloads.tube import tube_send
        res = tube_send("ssh:sess-0001", "hi")
        assert res["status"] == "Failed"
        assert "not a tube" in res["error"]

    def test_close(self, armed_scope_lab, echo_server, tube):
        from payloads.tube import tube_open, tube_close, tube_send
        port, _ = echo_server
        res = tube_open("127.0.0.1", port)
        handle = res["handle"]
        assert tube_close(handle)["status"] == "ok"
        # Post-close send fails honestly (session gone from the manager).
        after = tube_send(handle, "x")
        assert after["status"] == "Failed"


class TestSendGateRecheck:
    def test_send_refused_after_scope_change(self, state_root, armed_scope_lab, echo_server, tube):
        """Scope change mid-session applies at the next dispatch."""
        from payloads.tube import tube_open, tube_send
        from utils.scope_gate import ScopeGateError
        port, _ = echo_server
        res = tube_open("127.0.0.1", port)
        handle = res["handle"]
        assert res["status"] == "ok"
        # Re-arm on a manifest WITHOUT loopback (simulates the operator
        # switching to a remote-only program); the session's stored host is
        # re-checked per dispatch, so this send must now refuse.
        scope_dir = state_root / "scope"
        manifest = {
            "handle": "lab-remote-only",
            "platform": "lab",
            "in_scope": [{"asset_type": "CIDR", "asset_identifier": "203.0.113.0/24"}],
            "out_of_scope_assets": [],
        }
        (scope_dir / "lab_lab-remote-only.json").write_text(json.dumps(manifest))
        assert scope_gate.arm("lab-remote-only", platform="lab")["ok"]
        try:
            with pytest.raises(ScopeGateError) as exc_info:
                tube_send(handle, "hi\n")
            assert "not confirmed in-scope" in str(exc_info.value)
        finally:
            scope_gate.disarm()
            scope_gate._CACHE.clear()

    def test_send_allowed_while_scope_holds(self, armed_scope_lab, echo_server, tube):
        from payloads.tube import tube_open, tube_send
        port, _ = echo_server
        res = tube_open("127.0.0.1", port)
        sent = tube_send(res["handle"], "PING\n")
        assert sent["status"] == "ok"
        assert "127.0.0.1" in sent["scope"] or "in-scope" in sent["scope"]
