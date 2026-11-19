"""Gateway fail-soft lane for the mcp wheel (0.2.0+pkg8).

The module-level mcp imports used to kill the whole gateway process on
any host without the wheel (bootstrap logged it and :5000 never bound).
Now the import degrades: REST stays up, /mcp answers an honest 503 and
/health grades the lane. This suite pins both postures:

- armed lane (the wheel imports): session manager + /mcp Route built,
  /health reports the lane ready — byte-identical to the pre-split
  build (the live identity suite in test_mcp_client_identity.py
  exercises the handlers themselves);
- absent-wheel lane (imports patched out): boot succeeds, REST + /health
  answer, /mcp 503s with the remediation text, _mcp_text degrades to a
  plain content list, and _error returns None.
"""

import json

import httpx
import pytest

# anyio's pytest plugin drives the async transport calls. The backend is
# pinned to asyncio via the anyio_backend fixture override — the trio
# parametrization dies on boxes without trio installed, and the gateway
# only ever serves asyncio/uvicorn.
pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"

import api_gateway as gw


# --------------------------------------------------------------------------- #
# helpers                                                                       #
# --------------------------------------------------------------------------- #


class _NoRegistry:
    """Registry-absent lane: APIGateway(tool_registry=None) takes this
    branch itself (registry_down_reason), so no registry stub is needed —
    but a marker makes the intent explicit if that ever changes."""


@pytest.fixture
def armed_gateway():
    gw_obj = gw.APIGateway(None, object())
    yield gw_obj


def _route(gw_obj, path):
    for route in gw_obj.app.router.routes:
        if getattr(route, "path", None) == path:
            return route
    return None


async def _call(gw_obj, method, path, json_body=None):
    """Drive the ASGI app via httpx's async transport (ASGITransport has no
    sync context manager on this httpx)."""
    transport = httpx.ASGITransport(app=gw_obj.app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver/"
    ) as client:
        return await client.request(method, path, json=json_body)


# --------------------------------------------------------------------------- #
# armed lane (mcp importable on this interpreter)                               #
# --------------------------------------------------------------------------- #


class TestArmedLane:
    def test_boot_builds_session_manager_and_route(self, armed_gateway):
        assert armed_gateway.session_manager is not None
        assert armed_gateway.mcp_server is not None
        route = _route(armed_gateway, "/mcp")
        assert route is not None
        assert isinstance(route.endpoint, gw._MCPEndpoint)

    async def test_health_reports_mcp_ready(self, armed_gateway):
        body = (await _call(armed_gateway, "GET", "/health")).json()
        assert body["status"] == "degraded"  # registry absent by harness design
        assert "down" in body["registry"]
        # The lane grade is the fail-soft contract: ready, with transport.
        assert body["mcp"].startswith("ready (streamable-HTTP")


# --------------------------------------------------------------------------- #
# absent-wheel lane (every mcp module-level name patched to None)               #
# --------------------------------------------------------------------------- #


@pytest.fixture
def absent_lane(monkeypatch):
    monkeypatch.setattr(gw, "Server", None)
    monkeypatch.setattr(gw, "StreamableHTTPSessionManager", None)
    monkeypatch.setattr(gw, "mcp_types", None)
    monkeypatch.setattr(gw, "_MCP_IMPORT_ERROR", ImportError("no mcp wheel"))
    gw_obj = gw.APIGateway(None, object())
    yield gw_obj


class TestAbsentWheelLane:
    def test_boot_survives_without_the_wheel(self, absent_lane):
        assert absent_lane.session_manager is None
        assert absent_lane.mcp_server is None
        # The /mcp route still exists — it serves the 503 shim.
        assert _route(absent_lane, "/mcp") is not None

    async def test_rest_lanes_stay_up(self, absent_lane):
        assert (await _call(absent_lane, "GET", "/health")).status_code == 200
        assert (
            await _call(absent_lane, "POST", "/tools/execute", {})
        ).status_code in (400, 422)

    async def test_health_grades_the_lane_unavailable(self, absent_lane):
        body = (await _call(absent_lane, "GET", "/health")).json()
        assert body["mcp"].startswith("unavailable")

    async def test_mcp_endpoint_answers_honest_503(self, absent_lane):
        resp = await _call(absent_lane, "POST", "/mcp", {"jsonrpc": "2.0", "id": 1})
        assert resp.status_code == 503
        assert "mcp wheel failed to import" in resp.json()["error"]
        assert "vendor" in resp.json()["error"]  # remediation points at the lane

    def test_mcp_text_degrades_to_plain_content(self, absent_lane):
        result = gw._mcp_text({"ok": True})
        assert result == [json.dumps({"ok": True})]

    def test_error_returns_none_without_the_wheel(self, absent_lane):
        assert gw.APIGateway._error("boom") is None
