"""Phase 0.5 — MCP initialize-time client identity tests.

Covers the /mcp identity lanes: the resolver chain
(``utils.agent_identity.resolve_mcp_call_identity``), the ASGI-layer
initialize hook (`gw._mcp_initialize_identity`), and the real
wire behavior — initialize pins the announcement, later ``tools/call``
requests resolve to it, and the ``agent_id`` tool argument keeps winning
(backwards compat).
"""

import threading
import time

import httpx
import pytest
from mcp.shared.context import RequestContext
from mcp.types import RequestParams

import api_gateway as gw
import utils.agent_identity as aid

# --- isolation: the handshake registry is process-global ----------------------


@pytest.fixture
def hs_clean():
    aid._MCP_HANDSHAKE.clear()
    yield
    aid._MCP_HANDSHAKE.clear()


# --- extract_meta_agent_id ----------------------------------------------------


def test_extract_meta_agent_id_from_dict():
    assert aid.extract_meta_agent_id({"agent_id": "kai9000"}) == "kai9000"


def test_extract_meta_agent_id_from_pydantic_model_extra():
    meta = RequestParams.Meta.model_validate({"agent_id": "kai9000"})
    assert aid.extract_meta_agent_id(meta) == "kai9000"


def test_extract_meta_agent_id_missing_or_none():
    assert aid.extract_meta_agent_id(None) is None
    assert aid.extract_meta_agent_id({}) is None
    assert aid.extract_meta_agent_id(RequestParams.Meta.model_validate({})) is None


def test_extract_meta_agent_id_blank_string_is_none():
    assert aid.extract_meta_agent_id({"agent_id": "   "}) is None


# --- mcp_fingerprint ----------------------------------------------------------


def test_mcp_fingerprint_normalizes_and_caps():
    assert aid.mcp_fingerprint(None, None) == ("", "")
    assert aid.mcp_fingerprint("10.0.0.5", "SomeUA/1.0") == ("10.0.0.5", "SomeUA/1.0")
    huge_ua = "u" * 400
    assert len(aid.mcp_fingerprint("1.2.3.4", huge_ua)[1]) == 256


def test_mcp_fingerprint_distinguishes_clients():
    a = aid.mcp_fingerprint("10.0.0.5", "ua-a")
    b = aid.mcp_fingerprint("10.0.0.6", "ua-a")
    c = aid.mcp_fingerprint("10.0.0.5", "ua-b")
    assert a != b and a != c


# --- handshake registry -------------------------------------------------------


class TestHandshakeRegistry:
    FP = ("10.0.0.5", "ua")

    def test_miss_then_hit_then_refresh(self, hs_clean):
        assert aid.lookup_mcp_handshake(self.FP) is None
        aid.register_mcp_handshake(self.FP, "kai9000", "declared")
        assert aid.lookup_mcp_handshake(self.FP) == ("kai9000", "declared")

    def test_ttl_expiry(self, hs_clean, monkeypatch):
        monkeypatch.setenv("MCP_HANDSHAKE_TTL_HOURS", "0.0000003")  # ~1ms
        aid.register_mcp_handshake(self.FP, "kai9000", "declared")
        time.sleep(0.02)
        assert aid.lookup_mcp_handshake(self.FP) is None

    def test_bad_ttl_env_falls_back_to_24h(self, monkeypatch):
        monkeypatch.setenv("MCP_HANDSHAKE_TTL_HOURS", "not-a-number")
        assert aid._mcp_handshake_ttl_hours() == 24.0

    def test_bounded_eviction(self, hs_clean):
        fingeprints = [(f"10.0.0.{i & 255}", f"ua-{i}") for i in range(aid._MCP_HANDSHAKE_MAX + 64)]
        for i, fp in enumerate(fingeprints):
            aid.register_mcp_handshake(fp, f"agent-{i}", "declared")
        assert len(aid._MCP_HANDSHAKE) <= aid._MCP_HANDSHAKE_MAX
        # The OLDEST entries are the ones dropped (evict from the front
        # of the registration time order), the newest survive.
        newest = aid.lookup_mcp_handshake(fingeprints[-1])
        newest_index = aid._MCP_HANDSHAKE_MAX + 64 - 1
        assert newest == (f"agent-{newest_index}", "declared")

    def test_register_requires_fingerprint_and_id(self, hs_clean):
        aid.register_mcp_handshake(None, "kai9000", "declared")
        aid.register_mcp_handshake(self.FP, "", "declared")
        assert not aid._MCP_HANDSHAKE


# --- resolve_mcp_call_identity (full precedence chain) ------------------------


class TestResolveMcpCallIdentity:
    FP = ("10.0.0.9", "ua-pin")

    @pytest.fixture(autouse=True)
    def _pin(self, hs_clean):
        aid.register_mcp_handshake(self.FP, "pinned-agent", "declared")

    def test_no_context_mints(self):
        agent_id, prov = aid.resolve_mcp_call_identity()
        assert prov == "minted" and agent_id.startswith(aid.ANON_PREFIX)

    def test_fallback_shared_gives_zero_bucket(self):
        assert aid.resolve_mcp_call_identity(
            fallback_shared=True, client_ip="10.9.9.9", user_agent="never-pinned"
        ) == (aid.SHARED_AGENT_ID, "shared")

    def test_pin_wins_when_no_per_call_signal(self):
        assert aid.resolve_mcp_call_identity(client_ip=self.FP[0], user_agent=self.FP[1]) == (
            "pinned-agent",
            "declared",
        )

    def test_argument_wins_over_pin(self):
        aid.resolve_mcp_call_identity(
            announced="argument-agent", call_meta={"agent_id": "meta-agent"},
            http_headers={"x-daharness-agent-id": "header-agent"},
            client_ip=self.FP[0], user_agent=self.FP[1],
        )[:2]
        assert aid.resolve_mcp_call_identity(
            announced="argument-agent", client_ip=self.FP[0], user_agent=self.FP[1],
        )[0] == "argument-agent"

    def test_meta_beats_header(self):
        got, prov = aid.resolve_mcp_call_identity(
            call_meta={"agent_id": "meta-agent"},
            http_headers={"x-daharness-agent-id": "header-agent"},
        )
        assert (got, prov) == ("meta-agent", "declared")

    def test_header_used_when_no_meta(self):
        assert aid.resolve_mcp_call_identity(
            http_headers={"x-daharness-agent-id": "header-agent"},
        ) == ("header-agent", "declared")

    def test_header_duck_typed_getter(self):
        # Starlette Headers isn't a plain dict; anything with .get works.
        class Headers:
            def get(self, key):
                return "starlette-agent" if key == "x-daharness-agent-id" else None

        assert aid.resolve_mcp_call_identity(http_headers=Headers())[0] == "starlette-agent"

    def test_shared_zero_argument_stays_shared(self):
        # The explicit "0" opt-in works on this lane too — same chain.
        assert aid.resolve_mcp_call_identity(announced="0") == (aid.SHARED_AGENT_ID, "shared")

    def test_unusable_announcement_falls_through_to_pin(self):
        # An announce-but-unusable per-call name (e.g. 'anon-spoofed') may
        # NOT take over a pinned identity silently... it resolves to a
        # fresh mint in resolve_agent_id — but the PIN should be consulted
        # only when there is NO announcement at all. So an unusable
        # announcement mints (never falls through to the pin).
        _minted, prov = aid.resolve_mcp_call_identity(
            announced="anon-spoofed", client_ip=self.FP[0], user_agent=self.FP[1],
        )
        assert prov == "minted"


# --- ASGI-layer helpers -------------------------------------------------------


def _init_scope(headers=None, client=None):
    return {
        "type": "http",
        "headers": headers or [],
        "client": client,
    }


class TestScopeHeaders:
    def test_bytes_and_str_headers(self):
        scope = _init_scope([(b"user-agent", b"ua"), ("x-custom", "v")])
        assert gw._scope_headers(scope) == {"user-agent": "ua", "x-custom": "v"}

    def test_empty_and_missing(self):
        assert gw._scope_headers(_init_scope()) == {}
        assert gw._scope_headers({}) == {}

    def test_malformed_scope_never_faults(self):
        assert gw._scope_headers({"headers": "junk"}) == {}
        # A broken value inside the loop aborts parsing but returns {} not raises.
        broken = _init_scope([b"junk", (b"fine", b"x")])
        assert isinstance(gw._scope_headers(broken), dict)


class TestMcpInitializeIdentity:
    FP_IP, FP_UA = "10.0.0.7", "wire-ua"

    def _scope(self, extra_headers=None):
        headers = [(b"user-agent", self.FP_UA.encode())] + (extra_headers or [])
        return _init_scope(headers, client=(self.FP_IP, 51000))

    def _init_cand(self, params_extra=None, client_info=None):
        params = {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "t", "version": "0"},
        }
        if client_info is not None:
            params["clientInfo"] = {"name": "t", "version": "0", **client_info}
        if params_extra is not None:
            params["_meta"] = params_extra
        return {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params}

    def test_non_initialize_is_inert(self, hs_clean):
        cand = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {}}
        assert gw._mcp_initialize_identity(self._scope(), cand) is None

    def test_header_announcement_registers(self, hs_clean):
        got = gw._mcp_initialize_identity(
            self._scope(extra_headers=[(b"x-daharness-agent-id", b"wire-agent")]),
            self._init_cand(),
        )
        assert got == "wire-agent"
        assert aid.lookup_mcp_handshake((self.FP_IP, self.FP_UA)) == ("wire-agent", "declared")

    def test_meta_announcement_registers(self, hs_clean):
        got = gw._mcp_initialize_identity(
            self._scope(), self._init_cand(params_extra={"agent_id": "meta-agent"})
        )
        assert got == "meta-agent"
        assert aid.lookup_mcp_handshake((self.FP_IP, self.FP_UA))[0] == "meta-agent"

    def test_clientinfo_announcement_registers(self, hs_clean):
        got = gw._mcp_initialize_identity(
            self._scope(), self._init_cand(client_info={"agent_id": "ci-agent"})
        )
        assert got == "ci-agent"
        assert aid.lookup_mcp_handshake((self.FP_IP, self.FP_UA))[0] == "ci-agent"

    def test_no_announcement_no_pin(self, hs_clean):
        got = gw._mcp_initialize_identity(self._scope(), self._init_cand())
        assert got is None
        # no pin for this fingerprint — non-announcing clients keep
        # today's per-call mint behavior
        assert aid.lookup_mcp_handshake((self.FP_IP, self.FP_UA)) is None

    def test_unusable_announcement_pins_the_mint(self, hs_clean):
        got = gw._mcp_initialize_identity(
            self._scope(extra_headers=[(b"x-daharness-agent-id", b"anon-spoofed")]),
            self._init_cand(),
        )
        assert got and got.startswith(aid.ANON_PREFIX)
        pinned_id, prov = aid.lookup_mcp_handshake((self.FP_IP, self.FP_UA))
        assert (pinned_id, prov) == (got, "minted")


# --- _mcp_call_identity degradation (outside any /mcp request) ----------------


def _stub_registry_with_record(recorder):
    class StubRegistry:
        async def find_tool_by_id(self, tool_id):
            return type(
                "M",
                (),
                {
                    "module_id": "stub.echo",
                    "module_path": "stub.echo",
                    "name": "stub.echo",
                    "external_sanitized_description": "stub",
                    "parameters": {"type": "object", "properties": {"msg": {"type": "string"}}},
                },
            )()

        async def execute_tool(self, manifest, arguments, *, session_id="0", agent_identity=None):
            recorder.append({"manifest": manifest, "arguments": arguments, "session_id": session_id})
            return {"status": "ok", "result": {"echo": arguments}}

    return StubRegistry()



    def test_no_request_context_argument_only(self):
        g = gw.APIGateway(_stub_registry_with_record([]), None)
        agent_id, prov = g._mcp_call_identity({"agent_id": "compat-agent"})
        assert (agent_id, prov) == ("compat-agent", "declared")

    def test_no_request_context_no_arg_mints(self):
        g = gw.APIGateway(_stub_registry_with_record([]), None)
        _agent_id, prov = g._mcp_call_identity({})
        assert prov == "minted"

    def test_scratch_lane_fallback_shared(self):
        from mcp.server.lowlevel import Server

        g = gw.APIGateway(_stub_registry_with_record([]), None)
        assert isinstance(g.mcp_server, Server)
        # Outside a request the context pull degrades to argument-only;
        # with no argument and an empty fingerprint map, the scratch lane
        # resolves to the legacy shared "0" bucket.
        assert g._mcp_call_identity({}, fallback_shared=True) == (aid.SHARED_AGENT_ID, "shared")

    def test_request_context_meta_lane(self):
        g = gw.APIGateway(_stub_registry_with_record([]), None)
        g.mcp_server.request_context = RequestContext(
            request=None, meta=RequestParams.Meta.model_validate({"agent_id": "ctx-agent"})
        )
        try:
            assert g._mcp_call_identity({}) == ("ctx-agent", "declared")
        finally:
            del g.mcp_server.request_context


# --- the /mcp wire (real uvicorn + httpx) -------------------------------------


class _StubRegistry:
    def __init__(self):
        self.calls = []

    async def find_tool_by_id(self, tool_id):
        if tool_id != " stub.echo".strip():
            pass
        return type(
            "M",
            (),
            {
                "module_id": "stub.echo",
                "module_path": "stub.echo",
                "name": "stub.echo",
                "external_sanitized_description": "stub",
                "parameters": {"type": "object", "properties": {"msg": {"type": "string"}}},
            },
        )()

    async def execute_tool(self, manifest, arguments, *, session_id="0", agent_identity=None):
        self.calls.append({"session_id": session_id, "agent_identity": agent_identity})
        return {"status": "ok", "result": {"echo": arguments.get("msg")}}


def _free_port():
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def wire_gateway(tmp_path, monkeypatch):
    # The scratch wire tests seed the store directly — construct one bound
    # to THIS throwaway tree and hand the process singleton back untouched
    # after. (Import-time _DEFAULT_* pins stop $WORKSPACE_ROOT from doing
    # it alone; ScratchStore's defaults were bound at def time.)
    ws = tmp_path / "ws"
    ws.mkdir()
    monkeypatch.setenv("WORKSPACE_ROOT", str(ws))
    import utils.scratch_store as scratch_store_mod

    saved_store = scratch_store_mod._store
    scratch_store_mod._store = scratch_store_mod.ScratchStore(
        db_path=str(ws / "scratch.db"), data_dir=str(ws / "scratch-data")
    )
    scratch_store_mod.get_store()
    import uvicorn

    registry = _StubRegistry()
    g = gw.APIGateway(registry, None)
    port = _free_port()
    config = uvicorn.Config(g.app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 15
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    if not server.started:
        server.should_exit = True
        thread.join(timeout=5)
        scratch_store_mod._store = saved_store
        raise RuntimeError("gateway did not start")

    yield g, f"http://127.0.0.1:{port}", registry

    server.should_exit = True
    thread.join(timeout=10)
    scratch_store_mod._store = saved_store


ACCEPT = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


def _initialize_payload(announce_meta=None, client_info=None):
    params = {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": client_info or {"name": "wire", "version": "0"}}
    if announce_meta is not None:
        params["_meta"] = announce_meta
    return {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params}


def _call_payload(tool_args=None, top_args=None, meta=None, req_id=20):
    arguments = {"tool_id": "stub.echo", "arguments": tool_args or {}}
    if top_args:
        arguments.update(top_args)
    body = {"jsonrpc": "2.0", "id": req_id, "method": "tools/call",
            "params": {"name": "tools_execute", "arguments": arguments}}
    if meta is not None:
        body["params"]["_meta"] = meta
    return body


class TestMcpWireIdentity:
    def test_initialize_announce_then_pinned_call(self, wire_gateway):
        _gw, base, registry = wire_gateway
        with httpx.Client(timeout=20) as client:
            # 1. announce at initialize via params._meta
            r = client.post(
                f"{base}/mcp", json=_initialize_payload({"agent_id": "mcp-wire-test"}),
                headers=ACCEPT,
            )
            assert r.status_code == 200
            init_body = r.json()
            assert "result" in init_body  # initialized cleanly
            # adoption channel: the resolved id rides the response header
            assert r.headers.get("x-daharness-agent-id") == "mcp-wire-test"

            # 2. tools/call with NO per-call announcement resolves to the pin
            r2 = client.post(f"{base}/mcp", json=_call_payload(), headers=ACCEPT)
            assert r2.status_code == 200
            result = r2.json()["result"]
            assert not result.get("isError"), result["content"]
            text = result["content"][0]["text"]
            assert '"mcp-wire-test"' in text  # identity block rides the envelope
            assert registry.calls and registry.calls[-1]["session_id"] == "mcp-wire-test"
            # the fingerprint pin was registered
            assert aid.lookup_mcp_handshake(("127.0.0.1", client.headers["user-agent"]))[0] ==(
                "mcp-wire-test"
            )

    def test_initialize_header_announcement(self, wire_gateway):
        _, base, _registry = wire_gateway
        with httpx.Client(timeout=20) as client:
            headers = {**ACCEPT, "x-daharness-agent-id": "hdr-announce"}
            r = client.post(f"{base}/mcp", json=_initialize_payload(), headers=headers)
            assert r.status_code == 200
            assert r.headers.get("x-daharness-agent-id") == "hdr-announce"

    def test_no_announce_initialize_returns_no_header(self, wire_gateway):
        _, base, _ = wire_gateway
        with httpx.Client(timeout=20) as client:
            r = client.post(f"{base}/mcp", json=_initialize_payload(), headers=ACCEPT)
            assert r.status_code == 200
            assert "x-daharness-agent-id" not in r.headers

    def test_tool_argument_wins_over_pin(self, wire_gateway):
        _, base, registry = wire_gateway
        with httpx.Client(timeout=20) as client:
            client.post(
                f"{base}/mcp", json=_initialize_payload({"agent_id": "mcp-wire-test"}),
                headers=ACCEPT,
            )
            r = client.post(
                f"{base}/mcp",
                json=_call_payload(top_args={"agent_id": "edge-case-override"}),
                headers=ACCEPT,
            )
            assert r.status_code == 200
            result = r.json()["result"]
            assert not result.get("isError"), result["content"]
            # backwards compat: the per-call tool argument always wins
            assert registry.calls[-1]["session_id"] == "edge-case-override"

    def test_call_meta_announcement_without_pin(self, wire_gateway):
        _, base, registry = wire_gateway
        with httpx.Client(timeout=20) as client:
            # Never initialize — announce per call through params._meta instead.
            r = client.post(
                f"{base}/mcp",
                # JSON-RPC params._meta (RequestParams.Meta, extra=allow)
                json=_call_payload(meta={"agent_id": "meta-on-call"}),
                headers=ACCEPT,
            )
            assert r.status_code == 200
            result = r.json()["result"]
            assert not result.get("isError"), result["content"]
            assert registry.calls[-1]["session_id"] == "meta-on-call"

    def test_scratch_lane_shared_tail_without_pin(self, wire_gateway, tmp_path):
        """A ref stored by ANOTHER agent is not reachable from an
        unannounced client — the scratch lane keeps the legacy ``"0"``
        bucket when no pin ever engaged (today's exact behavior)."""
        _, base, _ = wire_gateway
        from utils.scratch_store import get_store

        store = get_store()
        env = store.store({"k": "v"}, agent_id="other-agent", tool_id="stub.echo")
        assert env["scratch_ref"]
        with httpx.Client(timeout=20) as client:
            # different UA from the default used elsewhere -> no pin exists
            headers = {**ACCEPT, "user-agent": "never-pinned/1.0"}
            r = client.post(
                f"{base}/mcp",
                json={
                    "jsonrpc": "2.0", "id": 5, "method": "tools/call",
                    "params": {"name": "scratch_search",
                               "arguments": {"scratch_ref": env["scratch_ref"]}},
                },
                headers=headers,
            )
            assert r.status_code == 200
            result = r.json()["result"]
            assert result.get("isError"), "cross-agent scratch access should be refused"

    def test_scratch_lane_resolves_through_the_pin(self, wire_gateway):
        _, base, _ = wire_gateway
        from utils.scratch_store import get_store

        store = get_store()
        env = store.store({"k": "v"}, agent_id="mcp-wire-test", tool_id="stub.echo")
        with httpx.Client(timeout=20) as client:
            client.post(
                f"{base}/mcp", json=_initialize_payload({"agent_id": "mcp-wire-test"}),
                headers=ACCEPT,
            )
            r = client.post(
                f"{base}/mcp",
                json={
                    "jsonrpc": "2.0", "id": 6, "method": "tools/call",
                    "params": {"name": "scratch_search",
                               "arguments": {"scratch_ref": env["scratch_ref"]}},
                },
                headers=ACCEPT,
            )
            assert r.status_code == 200
            result = r.json()["result"]
            assert not result.get("isError"), result["content"]
            assert '"scratch:"' in result["content"][0]["text"] or "scratch" in result["content"][0]["text"]