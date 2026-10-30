"""Burp Suite MCP-server client + framework tools.

Talks to the official PortSwigger MCP Server BApp over its SSE (Server-Sent
Events) transport — a standard MCP server, NOT the stdio proxy jar that ships
alongside it for Claude Desktop compatibility.  The BApp runs *inside* a
running Burp Suite GUI instance (the operator's, not a daemon we launch) and
exposes an SSE endpoint at ``http://127.0.0.1:9876`` by default.  We connect
with the ``mcp`` Python SDK's ``sse_client`` transport and drive Burp's
Montoya API through the MCP tool surface.

Why MCP-over-SSE rather than the stdio proxy
--------------------------------------------
The BApp bundles ``mcp-proxy-all.jar`` purely because Claude Desktop only
speaks stdio.  Python can talk SSE directly — no JVM subprocess, no
stdin/stdout pipe management, no jar path resolution.  One long-lived SSE
connection serves every tool call (JSON-RPC requests are POSTed back over
HTTP to the endpoint URL the server advertises in its initial ``endpoint``
event).  Reconnect-on-drop is the only lifecycle concern.

What this gives us that ZAP doesn't (and vice-versa)
----------------------------------------------------
ZAP is the autonomous workhorse: spider, active scan, alerts, the whole
"crawl and attack" surface in one HTTP API.  Burp is the precision
instrument — the secretary reaches for it when it needs to:

  - Craft a specific HTTP/1.1 or HTTP/2 request with full header control
    (vhost-gated apps, custom auth, weird content types) and get the raw
    response back.  ``burp_send_request`` is the Burp-native equivalent of
    ``zap_send_raw`` but with HTTP/2 support and Burp's own HTTP stack
    (connection pool, upstream proxy, session handling rules).
  - Grep the live proxy history (``burp_get_proxy_history`` /
    ``burp_get_proxy_history_regex``) — the traffic the operator is
    generating in the Burp GUI *right now*, not just what a spider found.
    This is the "I saw something interesting while browsing" lane.
  - Hand a request to Repeater or Intruder (``burp_create_repeater_tab``,
    ``burp_send_to_intruder``) so the operator can continue the manual
    investigation in the GUI.
  - Read scanner issues (``burp_get_scanner_issues`` — Pro-only, gracefully
    absent on Community).

What this does NOT give us
--------------------------
  - **No active scan via MCP.** The BApp does not expose
    ``start_active_scan``.  Active scanning is still ZAP's job (or Burp's
    own Scanner UI, driven manually by the operator).  This is a clean
    division of labor, not a gap.
  - **No Collaborator via this BApp (for us).** Collaborator tools
    (``generate_collaborator_payload``, ``get_collaborator_interactions``)
    are Professional-edition only.  We run Community, so those tools never
    register on our Burp instance.  Use the framework's own OOB collaborator
    (``listeners.collaborator``) instead — it's the equivalent lane.
  - **No scope enforcement from Burp's side.** Unlike ZAP's ``mode=protect``
    (which hard-refuses out-of-scope requests at the daemon level), Burp's
    target scope is advisory — it controls what the spider/scanner touches
    but does not block ``sendRequest``.  The operator-armed scope gate
    (``utils.scope_gate.check_scan``) is the *real* enforcement layer here,
    called at the top of every traffic-bearing tool below, exactly like
    ``zap_send_raw`` and ``probe_web``.

Approval dialogs (operator config concern, not ours)
----------------------------------------------------
The BApp defaults to popping a Swing dialog for every HTTP request and
history read (``requireHttpRequestApproval=true`` /
``requireDataAccessApproval=true``).  In a headless dispatch lane that
dialog is invisible and the call hangs forever.  The operator must either
disable those toggles in the BApp's ``MCP`` tab or pre-approve targets via
the ``_autoApproveTargets`` config field.  We assume this is done — our
wrapper cannot detect or resolve a parked dialog.

Stateful singleton
------------------
``BurpMCPClient.get_instance()`` follows the same pattern as ``ZAPClient``
and ``MetasploitClient``: one shared client, one persistent SSE session,
reused across the Brain's instance cache and the in-process fallback.  The
session is lazily connected on first use and reconnected if the SSE stream
drops.

Sync wrappers, async client
---------------------------
The MCP SDK is async (``anyio`` under the hood).  The Brain dispatcher and
in-process fallback run sync tools in worker threads, so the ``@framework_tool``
wrappers here are **sync** and bridge to the async client via
``asyncio.run`` on a private loop — the same shape as the ZAP tools (sync
wrappers around a sync ``requests.Session``).  An async private loop is
simpler than a thread-pool bridge because the SSE connection is
single-streamed: one coroutine at a time, no concurrency benefit from a
shared loop.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any

# --- carved guts (tool surface never moves; plain-helper shims are lane-legal)
from auxiliaries._burp_mcp_api import (
    _BURP_ERROR_HINTS,
    BURP_MCP_CALL_TIMEOUT,
    BURP_MCP_CONNECT_TIMEOUT,
    BURP_MCP_READ_TIMEOUT,
    BURP_MCP_URL,
    BurpMCPError,
    _burp_error_guard,
    _host_from_raw_request,
    _scope_check,
)
from auxiliaries._burp_mcp_response import _burp_response_digest, _parse_burp_response
from constants import framework_tool


# ---------------------------------------------------------------------------
# Client — singleton holding one persistent MCP SSE session
# ---------------------------------------------------------------------------
class BurpMCPClient:
    """Single shared client; one persistent SSE session to the Burp BApp.

    The MCP SDK's ``sse_client`` is an async context manager that yields
    ``(read_stream, write_stream)``; ``ClientSession`` wraps those into a
    JSON-RPC client.  We hold the session open for the lifetime of the
    process inside a dedicated background asyncio loop (so sync
    ``@framework_tool`` wrappers can call into it via ``run_coroutine_threadsafe``
    without re-connecting per call).

    Reconnection: if the SSE stream drops (server restart, network blip),
    the next tool call detects the dead session and reconnects lazily.
    """

    _instance: BurpMCPClient | None = None
    _lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> BurpMCPClient:
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def __init__(self) -> None:
        self._url = BURP_MCP_URL
        self._session = None  # mcp.client.session.ClientSession
        self._cm_stack = None  # AsyncExitStack holding sse_client + ClientSession
        self._loop: asyncio.AbstractEventLoop | None = None
        self._loop_thread: threading.Thread | None = None
        self._connected = False
        self._connect_lock = threading.Lock()  # guards get_instance-style reentry
        # Async connect serialization, created lazily on the background loop
        # (asyncio.Lock binds to the running loop on first use). Without this,
        # concurrent _ensure_connected() callers each tear down the session
        # the previous one just opened (via _connect's _disconnect), livelocking
        # the single background loop and freezing every burp_* call.
        self._async_connect_lock: asyncio.Lock | None = None
        # Cached tool inventory (refreshed on connect / reconnect).
        self._available_tools: dict[str, Any] = {}

    # -- loop lifecycle ----------------------------------------------------

    def _ensure_loop(self) -> asyncio.AbstractEventLoop:
        """Start (or reuse) a dedicated background asyncio loop.

        The MCP SDK uses ``anyio`` task groups, so the loop must be running
        before we enter the ``sse_client`` context manager.  We run it in a
        daemon thread so it persists across sync tool calls.
        """
        if self._loop is not None and not self._loop.is_closed():
            return self._loop
        self._loop = asyncio.new_event_loop()
        self._loop_thread = threading.Thread(
            target=self._run_loop, daemon=True, name="burp-mcp-loop"
        )
        self._loop_thread.start()
        return self._loop

    def _run_loop(self) -> None:
        assert self._loop is not None
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _submit(self, coro, timeout: float | None = None) -> Any:
        """Run ``coro`` on the background loop and block for its result.

        On timeout the coroutine is *cancelled* so a wedged coroutine (e.g.
        a ``ClientSession.initialize()`` hanging on an unresponsive BApp) is
        torn down instead of pinning the single background loop forever —
        which would freeze every subsequent burp_* call and, through the
        Brain/gateway, Open Web UI itself.

        Implementation detail: ``run_coroutine_threadsafe`` returns a
        ``concurrent.futures.Future`` whose ``cancel()`` only prevents the
        callback from running — it does NOT cancel the underlying asyncio
        coroutine on the background loop.  A wedged coroutine (stuck inside
        ``session.call_tool`` or ``_connect``) would keep pinning the loop
        even after ``future.cancel()``.  To actually interrupt it, we wrap
        the coroutine in an ``asyncio.Task`` on the background loop and
        cancel that task — ``task.cancel()`` injects a ``CancelledError``
        at the next ``await`` point in the coroutine, unwinding it.
        """
        loop = self._ensure_loop()
        # Hold the asyncio Task in a mutable container so the cancel
        # callback (scheduled on timeout) can reach it.  The container is
        # per-call: each _submit invocation creates its own _task_holder.
        _task_holder: dict[str, Any] = {}

        async def _wrap():
            task = asyncio.ensure_future(coro)
            _task_holder["task"] = task
            return await task

        future = asyncio.run_coroutine_threadsafe(_wrap(), loop)
        try:
            return future.result(timeout=timeout)
        except TimeoutError:
            # Cancel the concurrent future (stops the result callback) AND
            # schedule task cancellation on the background loop so the
            # wedged coroutine is actually interrupted at its next await.
            future.cancel()

            async def _cancel_task():
                task = _task_holder.get("task")
                if task is not None and not task.done():
                    task.cancel()
                    try:
                        await task
                    except (asyncio.CancelledError, Exception):
                        pass #TODO: shouldn't we be logging instead of passing?

            cancel_fut = asyncio.run_coroutine_threadsafe(_cancel_task(), loop)
            try:
                cancel_fut.result(timeout=5)
            except Exception:
                pass  # TODO: shouldn't we be logging instead of passing?
            raise

    # -- connection lifecycle ----------------------------------------------

    async def _connect(self) -> None:
        """Open the SSE transport + ClientSession and run ``initialize()``.

        Uses an ``AsyncExitStack`` so we can keep the context managers alive
        across calls (they're async context managers, not plain objects).
        On failure, the stack is torn down so a retry starts clean.
        """
        from contextlib import AsyncExitStack
        from mcp.client.sse import sse_client
        from mcp.client.session import ClientSession

        # Tear down any stale session first.
        await self._disconnect()

        stack = AsyncExitStack()
        try:
            # Bound the ENTIRE connect (SSE handshake + ClientSession +
            # initialize()). The BApp can accept the TCP/SSE connection and
            # emit its ``endpoint`` event but then wedge on the JSON-RPC
            # ``initialize()`` POST (parked approval dialog, Burp GUI thread
            # blocked by the operator's manual work, target unreachable).
            # The MCP SDK sends that POST with NO read timeout — ``sse_client``'s
            # ``timeout`` param covers the SSE stream, not the initialize POST
            # — so without this bound ``initialize()`` hangs forever, pinning
            # the single background loop and freezing every burp_* call (and,
            # through the gateway/Brain, Open Web UI).
            async def _do_connect():
                read_stream, write_stream = await stack.enter_async_context(
                    sse_client(
                        self._url,
                        timeout=BURP_MCP_CONNECT_TIMEOUT,
                        sse_read_timeout=BURP_MCP_READ_TIMEOUT,
                    )
                )
                session = await stack.enter_async_context(
                    ClientSession(read_stream, write_stream)
                )
                await session.initialize()
                return session

            session = await asyncio.wait_for(
                _do_connect(), timeout=BURP_MCP_CONNECT_TIMEOUT
            )
            self._session = session
            self._cm_stack = stack
            self._connected = True
            # Cache the tool inventory so wrappers can probe availability
            # (e.g. Pro-only Collaborator tools).
            await self._refresh_tools() #TODO: isn't there a built in timeout error?
        except (TimeoutError, asyncio.CancelledError) as e:
            # Timeout: the BApp accepted the SSE connection but did not
            # complete the MCP handshake within BURP_MCP_CONNECT_TIMEOUT.
            # CancelledError: _submit's timeout fired and cancelled the
            # task — the connect coroutine is being unwound.  In both
            # cases, tear down the partial AsyncExitStack so a retry
            # starts clean.  Without this, a cancelled connect leaves the
            # sse_client / ClientSession context managers half-open,
            # pinning the background loop's task group forever.
            try:
                await stack.aclose()
            except Exception:
                pass #TODO: ANOTHER OPPORTUNITY FOR LOGGING BUT WE PASSED?!
            self._session = None
            self._cm_stack = None
            self._connected = False
            if isinstance(e, asyncio.CancelledError):
                # _submit cancelled the connect — don't masquerade as a
                # timeout.  Re-raise as a connect failure with a clear
                # message so the caller knows the connect was interrupted.
                raise BurpMCPError(
                    "connect_failed",
                    f"Connect to Burp MCP at {self._url} was cancelled "
                    f"(the _submit timeout fired during the handshake). "
                    "The partial session was torn down; the next call "
                    "will retry cleanly.",
                ) from e
            raise BurpMCPError(
                "connect_failed",
                f"Timed out connecting to Burp MCP at {self._url} within "
                f"{BURP_MCP_CONNECT_TIMEOUT:.0f}s. The BApp accepted the "
                "connection but did not complete the MCP handshake — usually "
                "a parked approval dialog or a wedged Burp GUI. Disable the "
                "BApp's requireHttpRequestApproval/requireDataAccessApproval "
                "toggles (or pre-approve the target) in the MCP tab, then call "
                "burp_reconnect.",
            ) from e
        except Exception as e:
            # Clean up the partial stack so a retry is clean.
            try:
                await stack.aclose()
            except Exception:
                pass #TODO: FIX
            self._session = None
            self._cm_stack = None
            self._connected = False
            raise BurpMCPError(
                "connect_failed",
                f"Could not connect to Burp MCP at {self._url}: {e}. "
                "Is Burp Suite running with the MCP Server BApp loaded and "
                "enabled? Check the MCP tab in Burp (Enabled checkbox) and "
                "that the host/port match BURP_MCP_HOST/BURP_MCP_PORT.",
            ) from e

    async def _disconnect(self) -> None:
        if self._cm_stack is not None:
            try:
                await self._cm_stack.aclose()
            except Exception:
                pass #TODO: FIX...i mean. shouldn't we do more for the end user than *pass* on error?
        self._cm_stack = None
        self._session = None
        self._connected = False
        self._available_tools = {}

    async def _refresh_tools(self) -> None:
        """Populate ``_available_tools`` from the server's ``tools/list``."""
        if self._session is None:
            return
        try:
            result = await self._session.list_tools()
            self._available_tools = {t.name: t for t in result.tools}
        except Exception:
            # Non-fatal: tool calls will still work; we just can't probe
            # availability.  Pro-only detection degrades to a runtime error.
            self._available_tools = {}

    async def _get_connect_lock(self) -> asyncio.Lock:
        """Lazily create the connect-serialization lock on the running loop."""
        if self._async_connect_lock is None:
            self._async_connect_lock = asyncio.Lock()
        return self._async_connect_lock

    async def _ensure_connected(self) -> Any:
        """Lazily connect, or reconnect if the session dropped.

        Serialized by an asyncio.Lock on the background loop so concurrent
        callers (the Brain's tool pool can fire several burp_* wrappers in
        parallel threads, each bridging to this loop via _submit) share ONE
        connect attempt. Without this, each caller's ``_connect`` would
        ``_disconnect`` the session a sibling just opened, livelocking the
        single background loop and freezing every burp_* call.
        """
        if self._session is not None and self._connected:
            return self._session
        lock = await self._get_connect_lock()
        async with lock:
            # Re-check inside the lock — the holder may have just connected.
            if self._session is not None and self._connected:
                return self._session
            await self._connect()
        return self._session

    # -- tool discovery / health -------------------------------------------

    def healthcheck(self) -> bool:
        """Return True if the Burp MCP server responds to a ping.

        Used by ``bootstrap.wait_for_burp_mcp`` during launch.  Never raises.
        """
        try:
            self._submit(self._healthcheck_coro(), timeout=BURP_MCP_CONNECT_TIMEOUT + 5)
            return True
        except Exception:
            return False

    async def _healthcheck_coro(self) -> None:
        await self._ensure_connected()
        if self._session is not None:
            await self._session.send_ping()

    def list_available_tools(self) -> list[str]:
        """Return the names of tools the connected Burp instance exposes.

        Pro-only tools (scanner issues, collaborator) are absent on Community.
        """
        if not self._connected:
            try:
                self._submit(self._ensure_connected(), timeout=BURP_MCP_CONNECT_TIMEOUT + 5)
            except Exception:
                return []
        return sorted(self._available_tools.keys())

    def has_tool(self, name: str) -> bool:
        """True when the connected Burp instance exposes ``name``."""
        return name in self._available_tools

    # -- tool call ---------------------------------------------------------

    async def _call_tool_coro(
        self, name: str, arguments: dict[str, Any], timeout: float | None
    ) -> Any:
        """Call one MCP tool and extract the text content from the result."""
        import mcp.types as types

        session = await self._ensure_connected()
        if name not in self._available_tools and self._available_tools:
            # Refresh once in case tools were added since connect (e.g. the
            # operator enabled config-editing mid-session).
            await self._refresh_tools()
        read_timeout = (
            __import__("datetime").timedelta(seconds=timeout)
            if timeout
            else None
        )
        try:
            result = await session.call_tool(
                name, arguments, read_timeout_seconds=read_timeout
            )
        except Exception as e:
            # Distinguish a per-call timeout (the SSE session is still
            # alive — only this one request exceeded its read_timeout) from
            # a genuine transport-level session death.  Conflating the two
            # was the root cause of the "blip" freezes: one slow target
            # triggered McpError(408) → _connected = False → every
            # subsequent burp_* call paid a full SSE reconnect (handshake +
            # initialize + tools/list, 2-10s), queued behind the connect
            # lock, burning their own _submit timeouts, cascading into
            # more reconnects.  The BApp processes requests concurrently
            # and the SSE stream survives a single call's timeout — we
            # verified this live — so the session must NOT be torn down.
            from mcp.shared.exceptions import McpError
            import httpx

            if isinstance(e, McpError) and e.error.code == httpx.codes.REQUEST_TIMEOUT:
                # Per-call timeout: the session is still valid.  Do NOT
                # set _connected = False.  Raise a distinct error code so
                # the hint can tell the secretary "the target was slow,
                # retry with a longer timeout" instead of "the session
                # dropped, reconnect."
                raise BurpMCPError(
                    "call_timeout",
                    f"{name}: Burp did not respond within {timeout}s "
                    f"(BURP_MCP_CALL_TIMEOUT). The SSE session is still "
                    "alive — this is a per-call timeout, not a connection "
                    "failure. The target may be unreachable or slow; "
                    "retry with a longer timeout or a different target.",
                ) from e

            # Genuine transport-level failure (ConnectionError, OSError,
            # anyio.ClosedResourceError, etc.) — the session IS dead.
            # Mark for reconnect on the next call.
            self._connected = False
            raise BurpMCPError("call_failed", f"{name}: {e}") from e

        if result.isError:
            # MCP error results carry text content with the error message.
            err_text = ""
            for block in (result.content or []):
                if isinstance(block, types.TextContent):
                    err_text += block.text
            raise BurpMCPError("tool_error", f"{name}: {err_text or 'unknown'}")

        # Extract text content.  Most BApp tools return a single TextContent.
        parts: list[str] = []
        for block in (result.content or []):
            if isinstance(block, types.TextContent):
                parts.append(block.text)
            else:
                parts.append(str(block))
        return "\n".join(parts)

    def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        timeout: float | None = BURP_MCP_CALL_TIMEOUT,
    ) -> str:
        """Sync entry point: call ``name`` with ``arguments``, return text.

        This is what the ``@framework_tool`` wrappers call.  Runs the async
        call on the background loop and blocks the calling (worker) thread.
        """
        return self._submit(
            self._call_tool_coro(name, arguments or {}, timeout),
            timeout=timeout + 10 if timeout else None,
        )

    def reconnect(self) -> dict[str, Any]:
        """Force a clean disconnect + reconnect of the SSE session.

        Call this after Burp was restarted (the old SSE stream is dead and
        the session ID is gone).  Tears down the stale ``AsyncExitStack`` and
        opens a fresh ``sse_client`` + ``ClientSession`` + ``initialize()``.
        Returns a structured result dict so the ``burp_reconnect`` wrapper
        can surface it directly.
        """
        try:
            self._submit(self._disconnect(), timeout=BURP_MCP_CONNECT_TIMEOUT + 5)
        except Exception:
            pass  # TODO: why pass when can log or do something else? why pass at all?
        try:
            self._submit(self._connect(), timeout=BURP_MCP_CONNECT_TIMEOUT + 5)
        except BurpMCPError as e:
            return {
                "status": "Failed",
                "reconnected": False,
                "error": str(e),
                "burp_code": e.code,
                "hint": _BURP_ERROR_HINTS.get(e.code, ""),
            }
        return {
            "status": "Success",
            "reconnected": True,
            "url": self._url,
            "tools_available": len(self._available_tools),
            "note": (
                "SSE session re-established. The old session ID was void "
                "when Burp closed; this opened a fresh connection."
            ),
        }


def _burp() -> BurpMCPClient:
    return BurpMCPClient.get_instance()


# ---------------------------------------------------------------------------
# @framework_tool wrappers
# ---------------------------------------------------------------------------

@framework_tool(
    "Send a raw HTTP/1.1 request through Burp Suite's HTTP sender with full "
    "control over method, path, headers, and body. The response is recorded "
    "in Burp's proxy history (grep it with burp_get_proxy_history_regex) and "
    "the passive scanner observes it. Use this when a target requires a "
    "specific Host header (vhost-gated apps), session cookies, CSRF tokens, "
    "or any hand-crafted request that zap_send_raw cannot express. HTTP/2 "
    "targets: prefer burp_send_http2_request. Burp's connection pool, "
    "upstream proxy, and session-handling rules all apply to the request. "
    "The response is parsed and HTML bodies are converted to clean markdown — "
    "no raw HTML tag soup enters the model context.",
    next_hints=["burp_get_proxy_history_regex", "report_finding"],
    tags=["web.probe"],
    result_digest=_burp_response_digest,
)
@_burp_error_guard
def burp_send_http1_request(
    content: str,
    target_hostname: str,
    target_port: int,
    uses_https: bool = False,
) -> dict[str, Any]:
    """Send a raw HTTP/1.1 request via Burp and return the response.

    ``\\n`` line endings in ``content`` are normalized to ``\\r\\n`` by the
    BApp (PortSwigger's ``normalizeHttpContent``), so plain-text requests
    are wire-legal.  Always include a ``Host:`` header for vhost-gated
    targets.

    The returned dict carries a *parsed* response (``status_code``,
    ``response_headers``, ``body_text`` — HTML converted to markdown, JSON
    pretty-printed, scripts/styles stripped).  The raw response is preserved
    in ``response_raw`` for the scratch store.  In ``digest`` mode only a
    compact one-liner enters context; the full response is retrievable from
    scratch with ``scratch_search``.

    Args:
        content: The raw HTTP/1.1 request, e.g.
            ``"GET /api/users HTTP/1.1\\nHost: target.local\\n\\n"``.
        target_hostname: The hostname Burp connects to (resolved and
            connected to independently of the Host header — this is the
            *network* target, the Host header is the *virtual* target).
        target_port: The TCP port (80, 443, 8080, etc.).
        uses_https: If True, Burp uses TLS for the connection. Set True for
            443/8443 and any HTTPS endpoint.
    """
    _scope_check(target_hostname)
    result = _burp().call_tool(
        "send_http1_request",
        {
            "content": content,
            "targetHostname": target_hostname,
            "targetPort": int(target_port),
            "usesHttps": bool(uses_https),
        },
    )
    parsed = _parse_burp_response(result)
    return {
        "status": "Success",
        "response": parsed,
        "note": (
            "Response parsed: status/headers/body_text (HTML->markdown). "
            "Request is in Burp's proxy history — grep it with "
            "burp_get_proxy_history_regex."
        ),
    }


@framework_tool(
    "Send an HTTP/2 request through Burp Suite with full control over "
    "pseudo-headers (:method, :path, :scheme, :authority), regular headers, "
    "and body. Use this by default for modern web targets that speak HTTP/2. "
    "Do NOT pass headers to the body parameter. The response is recorded in "
    "Burp's proxy history and the passive scanner observes it. The response "
    "is parsed and HTML bodies are converted to clean markdown — no raw HTML "
    "tag soup enters the model context.",
    next_hints=["burp_get_proxy_history_regex", "report_finding"],
    tags=["web.probe"],
    result_digest=_burp_response_digest,
)
@_burp_error_guard
def burp_send_http2_request(
    pseudo_headers: dict[str, str],
    target_hostname: str,
    target_port: int,
    uses_https: bool = True,
    headers: dict[str, str] | None = None,
    request_body: str = "",
) -> dict[str, Any]:
    """Send an HTTP/2 request via Burp and return the response.

    The returned dict carries a *parsed* response (``status_code``,
    ``response_headers``, ``body_text`` — HTML converted to markdown, JSON
    pretty-printed).  The raw response is in ``response_raw`` for scratch.

    Args:
        pseudo_headers: HTTP/2 pseudo-headers. Required keys: ``:method``,
            ``:path``, ``:scheme``, ``:authority``.  Example::

                {"method": "GET", ":path": "/api/v1/users",
                 ":scheme": "https", ":authority": "target.local"}

        target_hostname: The network target hostname Burp connects to.
        target_port: The TCP port (443 for HTTPS, 80 for HTTP).
        uses_https: If True (default), Burp uses TLS.
        headers: Optional regular (non-pseudo) headers, e.g.
            ``{"User-Agent": "...", "Cookie": "..."}``.
        request_body: The request body (for POST/PUT).  Do NOT put headers
            here — they go in the ``headers`` dict.
    """
    _scope_check(target_hostname)
    result = _burp().call_tool(
        "send_http2_request",
        {
            "pseudoHeaders": pseudo_headers,
            "headers": headers or {},
            "requestBody": request_body,
            "targetHostname": target_hostname,
            "targetPort": int(target_port),
            "usesHttps": bool(uses_https),
        },
    )
    parsed = _parse_burp_response(result)
    return {
        "status": "Success",
        "response": parsed,
        "note": (
            "Response parsed: status/headers/body_text (HTML->markdown). "
            "Request is in Burp's proxy history — grep it with "
            "burp_get_proxy_history_regex."
        ),
    }


@framework_tool(
    "Send a raw HTTP request through Burp Suite (auto-selects HTTP/1.1 or "
    "HTTP/2 based on the request shape). This is the convenience entry point "
    "when you don't want to think about protocol version: pass a raw "
    "HTTP/1.1 request and Burp handles the rest. For explicit HTTP/2 control "
    "use burp_send_http2_request. The response is recorded in Burp's proxy "
    "history. The response is parsed and HTML bodies are converted to clean "
    "markdown — no raw HTML tag soup enters the model context.",
    next_hints=["burp_get_proxy_history_regex", "report_finding"],
    tags=["web.probe"],
    result_digest=_burp_response_digest,
)
@_burp_error_guard
def burp_send_raw(raw_request: str, uses_https: bool = False) -> dict[str, Any]:
    """Send a raw HTTP/1.1 request via Burp, inferring the target from it.

    First line must be ``METHOD /path HTTP/1.1``; include a ``Host:`` header.
    The target host/port are extracted from the request for scope gating.

    The returned dict carries a *parsed* response (``status_code``,
    ``response_headers``, ``body_text`` — HTML converted to markdown).  The
    raw response is in ``response_raw`` for scratch.

    Args:
        raw_request: The raw request, e.g. ``"GET / HTTP/1.1\\nHost: "
            "earth.local\\n\\n"`` — always include a Host header for
            vhost-gated targets.
        uses_https: If True, Burp uses TLS (default False = plain HTTP).
    """
    host = _host_from_raw_request(raw_request)
    if not host:
        raise BurpMCPError(
            "invalid_request",
            "Could not extract a Host from the raw request. Include a "
            "'Host:' header or use an absolute-form request line.",
        )
    _scope_check(host)
    # Default port inference: 443 for https, 80 for http. The BApp's
    # send_http1_request needs an explicit port; if the Host header carries
    # one, use it, otherwise fall back to the scheme default.
    port = 443 if uses_https else 80
    for ln in raw_request.lstrip().splitlines():
        if ln.lower().startswith("host:"):
            host_part = ln.split(":", 1)[1].strip()
            if host_part.count(":") == 1:  # host:port
                try:
                    port = int(host_part.rsplit(":", 1)[1])
                except ValueError:
                    pass
            break
    result = _burp().call_tool(
        "send_http1_request",
        {
            "content": raw_request,
            "targetHostname": host,
            "targetPort": port,
            "usesHttps": bool(uses_https),
        },
    )
    parsed = _parse_burp_response(result)
    return {
        "status": "Success",
        "response": parsed,
        "host": host,
        "port": port,
        "note": (
            "Response parsed: status/headers/body_text (HTML->markdown). "
            "Grep it later with burp_get_proxy_history_regex."
        ),
    }


@framework_tool(
    "Get items from Burp's proxy HTTP history (the traffic flowing through "
    "Burp's proxy, including the operator's manual browsing and tool-sent "
    "requests). Paginated — use count + offset to page through. Each item is "
    "server-side truncated to 5KB; use burp_send_http1_request to re-fetch a "
    "full response if needed. This is the 'what has Burp seen' lane, "
    "complementary to zap_sites_tree (which shows what the spider found).",
    next_hints=["burp_get_proxy_history_regex", "report_finding"],
    tags=["recon.web"],
)
@_burp_error_guard
def burp_get_proxy_history(count: int = 20, offset: int = 0) -> dict[str, Any]:
    """Read paginated entries from Burp's proxy HTTP history.

    Args:
        count: Number of items to return (default 20).  The BApp paginates
            server-side; each item is truncated to 5KB.
        offset: Zero-based offset to start from (for paging).
    """
    result = _burp().call_tool(
        "get_proxy_http_history",
        {"count": int(count), "offset": int(offset)},
    )
    return {
        "status": "Success",
        "history": result,
        "count": count,
        "offset": offset,
        "note": (
            "Each item is truncated to 5KB by the BApp. To get a full "
            "response, re-send the request with burp_send_http1_request."
        ),
    }


@framework_tool(
    "Grep Burp's proxy HTTP history with a regex. Returns items whose "
    "request OR response matches the pattern. This is the Burp-native "
    "'find me every request that contains X' tool — use it to locate "
    "specific cookies, tokens, error strings, or parameter names across "
    "all traffic Burp has seen. Paginated. The BApp compiles the regex "
    "server-side (Java Pattern).",
    next_hints=["report_finding"],
    tags=["recon.web"],
)
@_burp_error_guard
def burp_get_proxy_history_regex(
    regex: str, count: int = 20, offset: int = 0,
) -> dict[str, Any]:
    """Grep Burp's proxy history with a server-side regex.

    Args:
        regex: A Java-compatible regex (``java.util.regex.Pattern`` syntax).
            Matched against both request and response of each history item.
        count: Number of matches to return (default 20).
        offset: Zero-based offset for paging.
    """
    result = _burp().call_tool(
        "get_proxy_http_history_regex",
        {"regex": regex, "count": int(count), "offset": int(offset)},
    )
    return {
        "status": "Success",
        "matches": result,
        "regex": regex,
        "count": count,
        "offset": offset,
    }


@framework_tool(
    "Get items from Burp's proxy WebSocket history. Paginated. Use this to "
    "inspect WebSocket traffic (messages, handshakes) that flowed through "
    "Burp's proxy.",
    tags=["recon.web"],
)
@_burp_error_guard
def burp_get_proxy_websocket_history(count: int = 20, offset: int = 0) -> dict[str, Any]:
    """Read paginated entries from Burp's proxy WebSocket history.

    Args:
        count: Number of items to return (default 20).
        offset: Zero-based offset for paging.
    """
    result = _burp().call_tool(
        "get_proxy_websocket_history",
        {"count": int(count), "offset": int(offset)},
    )
    return {
        "status": "Success",
        "history": result,
        "count": count,
        "offset": offset,
    }


@framework_tool(
    "Grep Burp's proxy WebSocket history with a regex. Returns matching "
    "WebSocket messages. Useful for finding specific payloads, tokens, or "
    "patterns in WebSocket traffic.",
    tags=["recon.web"],
)
@_burp_error_guard
def burp_get_proxy_websocket_history_regex(
    regex: str, count: int = 20, offset: int = 0,
) -> dict[str, Any]:
    """Grep Burp's WebSocket history with a server-side regex.

    Args:
        regex: A Java-compatible regex.
        count: Number of matches to return (default 20).
        offset: Zero-based offset for paging.
    """
    result = _burp().call_tool(
        "get_proxy_websocket_history_regex",
        {"regex": regex, "count": int(count), "offset": int(offset)},
    )
    return {
        "status": "Success",
        "matches": result,
        "regex": regex,
    }


@framework_tool(
    "Create a Repeater tab in Burp Suite with a raw HTTP/1.1 request. The "
    "operator can then manually modify and re-send the request in the Burp "
    "GUI. Use this to hand off an interesting request you found for manual "
    "investigation. Prefer burp_create_repeater_tab_http2 for modern HTTP/2 "
    "targets.",
    tags=["web.probe"],
)
@_burp_error_guard
def burp_create_repeater_tab(
    content: str,
    target_hostname: str,
    target_port: int,
    uses_https: bool = False,
    tab_name: str | None = None,
) -> dict[str, Any]:
    """Open a Repeater tab in Burp with the given HTTP/1.1 request.

    Args:
        content: The raw HTTP/1.1 request (``\\n`` line endings are
            normalized to ``\\r\\n`` by the BApp).
        target_hostname: The network target hostname.
        target_port: The TCP port.
        uses_https: If True, Burp uses TLS.
        tab_name: Optional name for the Repeater tab (Burp auto-generates
            one if omitted).
    """
    _scope_check(target_hostname)
    _burp().call_tool(
        "create_repeater_tab",
        {
            "content": content,
            "targetHostname": target_hostname,
            "targetPort": int(target_port),
            "usesHttps": bool(uses_https),
            **({"tabName": tab_name} if tab_name else {}),
        },
    )
    return {
        "status": "Success",
        "note": f"Repeater tab created in Burp Suite"
                + (f" ('{tab_name}')" if tab_name else "")
                + ". The operator can inspect/modify it in the Burp GUI.",
    }


@framework_tool(
    "Create an HTTP/2 Repeater tab in Burp Suite. Use this by default for "
    "modern web targets that speak HTTP/2. Do NOT pass headers to the body "
    "parameter.",
    tags=["web.probe"],
)
@_burp_error_guard
def burp_create_repeater_tab_http2(
    pseudo_headers: dict[str, str],
    target_hostname: str,
    target_port: int,
    uses_https: bool = True,
    headers: dict[str, str] | None = None,
    request_body: str = "",
    tab_name: str | None = None,
) -> dict[str, Any]:
    """Open an HTTP/2 Repeater tab in Burp with the given request.

    Args:
        pseudo_headers: HTTP/2 pseudo-headers (``:method``, ``:path``,
            ``:scheme``, ``:authority``).
        target_hostname: The network target hostname.
        target_port: The TCP port.
        uses_https: If True (default), Burp uses TLS.
        headers: Optional regular headers.
        request_body: The request body.
        tab_name: Optional name for the Repeater tab.
    """
    _scope_check(target_hostname)
    _burp().call_tool(
        "create_repeater_tab_http2",
        {
            "pseudoHeaders": pseudo_headers,
            "headers": headers or {},
            "requestBody": request_body,
            "targetHostname": target_hostname,
            "targetPort": int(target_port),
            "usesHttps": bool(uses_https),
            **({"tabName": tab_name} if tab_name else {}),
        },
    )
    return {
        "status": "Success",
        "note": f"HTTP/2 Repeater tab created in Burp Suite"
                + (f" ('{tab_name}')" if tab_name else "")
                + ". The operator can inspect/modify it in the Burp GUI.",
    }


@framework_tool(
    "Send an HTTP/1.1 request to Burp's Intruder tool for automated fuzzing. "
    "The operator can configure payload positions and run the attack in the "
    "Burp GUI. Use this to set up an Intruder attack from a discovered "
    "request.",
    tags=["web.fuzz"],
)
@_burp_error_guard
def burp_send_to_intruder(
    content: str,
    target_hostname: str,
    target_port: int,
    uses_https: bool = False,
    tab_name: str | None = None,
) -> dict[str, Any]:
    """Send a request to Burp's Intruder tool.

    Args:
        content: The raw HTTP/1.1 request.
        target_hostname: The network target hostname.
        target_port: The TCP port.
        uses_https: If True, Burp uses TLS.
        tab_name: Optional name for the Intruder tab.
    """
    _scope_check(target_hostname)
    _burp().call_tool(
        "send_to_intruder",
        {
            "content": content,
            "targetHostname": target_hostname,
            "targetPort": int(target_port),
            "usesHttps": bool(uses_https),
            **({"tabName": tab_name} if tab_name else {}),
        },
    )
    return {
        "status": "Success",
        "note": "Request sent to Burp Intruder. The operator can configure "
                "payload positions and launch the attack in the Burp GUI.",
    }


@framework_tool(
    "Enable or disable Burp Proxy's intercept (request interception). When "
    "enabled, Burp pauses every proxied request for manual review before "
    "forwarding. Use this to set up manual interception when you want the "
    "operator to inspect specific requests in real time.",
    tags=["infra"],
)
@_burp_error_guard
def burp_set_proxy_intercept(intercepting: bool) -> dict[str, Any]:
    """Toggle Burp Proxy intercept on or off.

    Args:
        intercepting: True to enable intercept (pause requests for manual
            review), False to disable (forward automatically).
    """
    _burp().call_tool(
        "set_proxy_intercept_state",
        {"intercepting": bool(intercepting)},
    )
    return {
        "status": "Success",
        "intercepting": intercepting,
        "note": f"Burp Proxy intercept is now {'ENABLED' if intercepting else 'DISABLED'}.",
    }


@framework_tool(
    "Pause or unpause Burp's task execution engine. When paused, active "
    "scans and other background tasks are suspended. Use this to temporarily "
    "halt Burp's background processing (e.g. to reduce load during a "
    "sensitive manual test).",
    tags=["infra"],
)
@_burp_error_guard
def burp_set_task_engine_state(running: bool) -> dict[str, Any]:
    """Set Burp's task execution engine state.

    Args:
        running: True to resume (running), False to pause.
    """
    _burp().call_tool(
        "set_task_execution_engine_state",
        {"running": bool(running)},
    )
    return {
        "status": "Success",
        "running": running,
        "note": f"Burp task execution engine is now {'RUNNING' if running else 'PAUSED'}.",
    }


@framework_tool(
    "URL-encode a string using Burp's URL encoder. Use this when you need "
    "to encode a payload for injection into a URL parameter and want Burp's "
    "exact encoding rules (which may differ from Python's urllib.quote).",
    tags=["infra"],
)
@_burp_error_guard
def burp_url_encode(content: str) -> dict[str, Any]:
    """URL-encode a string via Burp's encoder.

    Args:
        content: The string to URL-encode.
    """
    result = _burp().call_tool("url_encode", {"content": content})
    return {"status": "Success", "encoded": result}


@framework_tool(
    "URL-decode a string using Burp's URL decoder.",
    tags=["infra"],
)
@_burp_error_guard
def burp_url_decode(content: str) -> dict[str, Any]:
    """URL-decode a string via Burp's decoder.

    Args:
        content: The string to URL-decode.
    """
    result = _burp().call_tool("url_decode", {"content": content})
    return {"status": "Success", "decoded": result}


@framework_tool(
    "Base64-encode a string using Burp's encoder.",
    tags=["infra"],
)
@_burp_error_guard
def burp_base64_encode(content: str) -> dict[str, Any]:
    """Base64-encode a string via Burp's encoder.

    Args:
        content: The string to base64-encode.
    """
    result = _burp().call_tool("base64_encode", {"content": content})
    return {"status": "Success", "encoded": result}


@framework_tool(
    "Base64-decode a string using Burp's decoder.",
    tags=["infra"],
)
@_burp_error_guard
def burp_base64_decode(content: str) -> dict[str, Any]:
    """Base64-decode a string via Burp's decoder.

    Args:
        content: The base64 string to decode.
    """
    result = _burp().call_tool("base64_decode", {"content": content})
    return {"status": "Success", "decoded": result}


@framework_tool(
    "Output Burp's current project-level configuration as JSON. Use this to "
    "inspect Burp's settings (scope, scan config, session rules) to "
    "understand what the operator has configured. The schema returned here "
    "is the input schema for the import tools (if config-editing is enabled).",
    tags=["infra"],
)
@_burp_error_guard
def burp_output_project_options() -> dict[str, Any]:
    """Export Burp's project-level configuration as JSON."""
    result = _burp().call_tool("output_project_options")
    return {"status": "Success", "config": result}


@framework_tool(
    "Output Burp's current user-level configuration as JSON. User-level "
    "settings include platform-wide preferences (display, connections, "
    "upstream proxies) that apply across all projects.",
    tags=["infra"],
)
@_burp_error_guard
def burp_output_user_options() -> dict[str, Any]:
    """Export Burp's user-level configuration as JSON."""
    result = _burp().call_tool("output_user_options")
    return {"status": "Success", "config": result}


@framework_tool(
    "Get the list of MCP tools exposed by the connected Burp instance. Use "
    "this to probe what's available — Pro-only tools (scanner issues, "
    "collaborator) are absent on Community. Also useful to verify the "
    "connection is live after a Burp restart.",
    tags=["infra"],
)
@_burp_error_guard
def burp_list_tools() -> dict[str, Any]:
    """List the MCP tools the connected Burp instance exposes."""
    tools = _burp().list_available_tools()
    return {
        "status": "Success",
        "tools": tools,
        "count": len(tools),
        "note": (
            "Pro-only tools (get_scanner_issues, "
            "generate_collaborator_payload, get_collaborator_interactions) "
            "are absent on Community. Use the framework's own collaborator "
            "(listeners.collaborator) and ZAP's active scan + alerts for "
            "those lanes."
        ),
    }


@framework_tool(
    "Force a reconnect to the Burp MCP server. Call this when Burp was "
    "restarted or accidentally closed mid-hunt — the old SSE session is "
    "dead and every burp_* tool will fail with 'connect_failed' or "
    "'call_failed' until this runs. Tears down the stale session and opens "
    "a fresh one. Safe to call even if the connection is still live (it "
    "will just reconnect). Always returns a structured dict, never raises.",
    tags=["infra"],
)
@_burp_error_guard
def burp_reconnect() -> dict[str, Any]:
    """Re-establish the Burp MCP SSE session after a Burp restart/close.

    Use this when:
    - Burp was accidentally closed and reopened (the old SSE stream died).
    - ``burp_*`` tools started returning ``connect_failed`` or
      ``call_failed`` errors after working previously.
    - You want to refresh the available-tool inventory after the operator
      enabled/disabled a BApp feature (e.g. toggled config-editing).

    The client also auto-reconnects lazily on the next failed call, but this
    tool is the *explicit* fix — call it once, confirm the reconnect, then
    continue.  No target interaction, no scope gate needed.
    """
    return _burp().reconnect()


@framework_tool(
    "Check whether the Burp MCP server is reachable and responding. Returns "
    "connection status and available tool count. Use this to verify the "
    "Burp integration is live before calling burp_* tools, or to diagnose "
    "a dropped connection. Never raises — always returns a structured dict.",
    tags=["infra"],
)
@_burp_error_guard
def burp_health() -> dict[str, Any]:
    """Health check: is the Burp MCP server reachable?"""
    client = _burp()
    try:
        ok = client.healthcheck()
    except Exception:
        ok = False
    return {
        "status": "Success" if ok else "Failed",
        "reachable": ok,
        "url": BURP_MCP_URL,
        "tools_available": len(client.list_available_tools()) if ok else 0,
        "note": (
            "Burp MCP server is reachable." if ok
            else f"Burp MCP server at {BURP_MCP_URL} is not reachable. "
            "Is Burp running with the MCP Server BApp enabled?"
        ),
    }