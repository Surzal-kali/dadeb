"""Header-argument shape handling for the web-session lane (Host bug 2026-11-22).

The bug this pins: ``_merge_headers`` assumed ``headers`` was always a dict
and died on ``AttributeError: 'str' object has no attribute 'items'`` the
first time a lane handed the tool a string — a JSON-encoded dict (the shape
the REPL's ``parse_flag_args`` and the MCP lane produce), a raw
``"Host: vhost\\nX-A: 1"`` block, or a pair list. The terminal symptom sent
every vhost-gated (Host-override) request to the hand-rolled Burp raw lane
instead. The preflight side gets the same pins for the 'object' schema
coercion path (str-with-{ JSON, pair lists).
"""

import pytest

from auxiliaries.web_session import _merge_headers, _normalize_header_pairs
from daharness.preflight import _coerce_arg_value


class TestNormalizeHeaderPairs:
    def test_dict_passthrough_and_stringify(self):
        out = _normalize_header_pairs({"Host": "earth.local", "X-A": 1})
        assert out == {"Host": "earth.local", "X-A": "1"}

    def test_json_string(self):
        out = _normalize_header_pairs('{"Host": "earth.local", "X-A": "1"}')
        assert out == {"Host": "earth.local", "X-A": "1"}

    def test_header_block_string(self):
        out = _normalize_header_pairs("Host: earth.local\nX-A: 1")
        assert out == {"Host": "earth.local", "X-A": "1"}

    def test_comma_kv_string(self):
        out = _normalize_header_pairs("Host: earth.local, X-A: 1")
        assert out == {"Host": "earth.local", "X-A": "1"}

    def test_pair_list(self):
        out = _normalize_header_pairs([["Host", "earth.local"], ["X-A", "1"]])
        assert out == {"Host": "earth.local", "X-A": "1"}

    def test_none_is_empty(self):
        assert _normalize_header_pairs(None) == {}

    def test_non_json_bare_word_refused(self):
        with pytest.raises(ValueError):
            _normalize_header_pairs("nonsense without a colon")


class TestMergeHeaders:
    def test_last_wins_across_shapes(self):
        merged = _merge_headers({"Host": "a.local"}, "Host: b.local")
        assert merged["Host"] == "b.local"

    def test_empty_extra_keeps_base(self):
        merged = _merge_headers({"X-A": "1"}, None)
        assert merged == {"X-A": "1"}

    def test_str_base_no_attributeerror(self):
        # The exact failing call from the incident report.
        merged = _merge_headers('{"Host": "earth.local"}', None)
        assert merged == {"Host": "earth.local"}


class TestPreflightObjectCoercion:
    def test_json_string_to_dict(self):
        v = _coerce_arg_value(
            "headers", '{"Host": "earth.local", "X-A": "1"}', "object"
        )
        assert v == {"Host": "earth.local", "X-A": "1"}

    def test_pair_list_to_dict(self):
        v = _coerce_arg_value(
            "headers", [["Host", "earth.local"], ["X-A", "1"]], "object"
        )
        assert v == {"Host": "earth.local", "X-A": "1"}

    def test_flat_list_is_not_dict(self):
        # A bare list the model meant as an array stays an array (unknown-key
        # and open-schema tools keep working); only 2-element-pair lists
        # coerce.
        v = _coerce_arg_value("paths", ["a", "b"], "array")
        assert v == ["a", "b"]

    def test_header_block_string_refused_cleanly(self):
        with pytest.raises(ValueError, match="object/dict"):
            _coerce_arg_value("headers", "Host: earth.local\nX-A: 1", "object")


class TestWireHeaderOverride:
    """The actual bug: a dict ``Host`` override must reach the wire verbatim
    (vhost-gated targets) — no re-derivation from the URL."""

    def test_host_override_ships_verbatim(self, monkeypatch, tmp_path):
        import json as _json
        import threading
        import http.server

        monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path / "workspace"))
        (tmp_path / "workspace" / "scope").mkdir(parents=True)
        (tmp_path / "workspace" / "scope" / ".armed_packet_scope.json").write_text(
            _json.dumps({
                "handle": "test-lab", "platform": "lab", "strict": True,
                "allowlist": {"127.0.0.0/8": ""},
            })
        )

        seen = {}

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen["host"] = self.headers.get("Host")
                body = b'{"ok":true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            from auxiliaries.web_session import _do_session_request

            env = _do_session_request(
                "GET", f"http://127.0.0.1:{port}/", headers={"Host": "earth.local"}
            )
            assert env["status"] == "Success"
            assert seen["host"] == "earth.local"
        finally:
            srv.shutdown()