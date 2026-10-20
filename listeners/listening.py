import asyncio
import argparse
import functools
import json
import os
import threading
import time
from asyncio import StreamReader, StreamWriter
from typing import Any, Dict, List, Optional

from listeners.thebrain import pack_message
from constants import framework_tool, brain_socket_path
from utils.handles import format_handle, parse_handle
from utils.session_manager import get_manager

_sm = get_manager()


# ---------------------------------------------------------------------------
# Read-back data store — the piece that was missing.
# ---------------------------------------------------------------------------

class ListenerDataStore:
    """Thread-safe store of received bytes and live client writers.

    Every chunk received by ``handle_client`` is appended here keyed by
    listener handle + client address.  ``read_listener`` polls it back so
    the Brain (or any caller) can retrieve what arrived on a listener
    *after* the fact — exactly the gap that ``TcpListener`` had before.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: List[Dict[str, Any]] = []
        # Map of listener_handle -> { peer_addr_str: StreamWriter }
        self._writers: Dict[str, Dict[str, StreamWriter]] = {}

    # -- received data ------------------------------------------------------

    def add_data(
        self, handle: str, peer: str, data: bytes,
        listener_port: Optional[int] = None,
    ) -> None:
        with self._lock:
            entry = {
                "handle": handle,
                "peer": peer,
                "data_hex": data.hex(),
                "data_text": data.decode(errors="replace"),
                "size": len(data),
                "ts": time.time(),
            }
            # Surface the port the listener is bound on (== the port the peer
            # dialed for a direct callback) per entry so the origin port is
            # never ambiguous.  This is the honest-attribution half of T2:
            # even with a shared pool, every entry carries its own port.
            if listener_port is not None:
                entry["listener_port"] = listener_port
            self._entries.append(entry)
            # FIFO cap: long-lived listeners never accumulate unbounded
            # history (each chunk is stored twice — hex + text — so this
            # bounds memory). Drop oldest, keep the most recent 500.
            if len(self._entries) > 500:
                del self._entries[: len(self._entries) - 500]

    def poll(
        self, handle: str = "", since: float = 0.0, limit: int = 0,
    ) -> List[Dict[str, Any]]:
        """Return received-data entries, optionally filtered.

        Args:
            handle: If non-empty, only entries from this listener handle.
            since:  Only entries at or after this Unix timestamp.
            limit:  If > 0, return at most the *last* N matching entries.
        """
        with self._lock:
            results = [
                e for e in self._entries
                if (not handle or e["handle"] == handle)
                and e["ts"] >= since
            ]
        if limit > 0:
            results = results[-limit:]
        return results

    def clear(self, handle: str = "") -> int:
        """Remove stored entries. Returns count removed."""
        with self._lock:
            if handle:
                before = len(self._entries)
                self._entries = [e for e in self._entries if e["handle"] != handle]
                return before - len(self._entries)
            else:
                n = len(self._entries)
                self._entries.clear()
                return n

    # -- live client writers (for send_to_listener) ------------------------

    def register_writer(self, handle: str, peer: str, writer: StreamWriter) -> None:
        with self._lock:
            self._writers.setdefault(handle, {})[peer] = writer

    def remove_writer(self, handle: str, peer: str) -> None:
        with self._lock:
            conns = self._writers.get(handle)
            if conns:
                conns.pop(peer, None)
                if not conns:
                    self._writers.pop(handle, None)

    def remove_writer_obj(self, handle: str, writer: StreamWriter) -> str:
        """Remove the writer entry matching ``writer`` (by identity) and
        return the peer string that was removed ("" if none matched).

        Used by send_to_listener's dead-peer path when the caller let the
        target be auto-selected (``peer=""``) and we therefore don't know the
        peer key offhand — we look it up by writer identity instead.
        """
        with self._lock:
            conns = self._writers.get(handle)
            if not conns:
                return ""
            for p, w in list(conns.items()):
                if w is writer:
                    del conns[p]
                    if not conns:
                        self._writers.pop(handle, None)
                    return p
            return ""

    def get_writer(self, handle: str, peer: str = "") -> Optional[StreamWriter]:
        with self._lock:
            conns = self._writers.get(handle)
            if not conns:
                return None
            if peer and peer in conns:
                return conns[peer]
            # No peer specified — return the first (most common case: one client)
            if conns:
                return next(iter(conns.values()))
            return None

    def list_clients(self, handle: str = "") -> Dict[str, List[str]]:
        with self._lock:
            if handle:
                return {handle: list(self._writers.get(handle, {}).keys())}
            return {h: list(c.keys()) for h, c in self._writers.items()}


# Module-level singleton — survives across tool calls within one process.
_data_store = ListenerDataStore()


# ---------------------------------------------------------------------------
# T1 — auto_answer: the exact bytes we write back to an HTTP probe before
# closing it.  Content-Length: 0 + Connection: close so the client (curl,
# wkhtmltopdf, any HTTP client) gets a terminated response and does NOT hang
# in the handler waiting for bytes that never come (the wedged-handler class).
# ---------------------------------------------------------------------------
_AUTO_ANSWER_404 = (
    b"HTTP/1.1 404 Not Found\r\n"
    b"Content-Length: 0\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)

# Methods we treat as "this is an HTTP client, answer it".  Kept to the three
# the spec names so a raw reverse shell (which never starts with these) is
# left untouched.
_HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ")


def _looks_like_http(data: bytes) -> bool:
    """True iff ``data`` begins with an HTTP request-line method we answer.

    We match ``b"GET "`` (with trailing space) rather than ``b"GET"`` so a
    shell command like ``getflag`` is never mistaken for an HTTP probe.
    """
    return data.startswith(_HTTP_METHODS)


def _drop_writer(handle: str, peer: str, writer: StreamWriter) -> str:
    """Remove a (possibly auto-selected) dead peer from connected_clients and
    best-effort close its socket.  Returns the peer string that was dropped.

    T3: a dying peer must be evicted from the registry so connected_clients
    stays coherent and the listener keeps serving everyone else.
    """
    dropped = peer
    if peer:
        _data_store.remove_writer(handle, peer)
    else:
        # Auto-targeted: find which peer this writer was bound to.
        dropped = _data_store.remove_writer_obj(handle, writer)
    try:
        writer.close()
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    return dropped or "client"


class TCPListener:
    def __init__(self, host='0.0.0.0', port=8888):
        self.host = host
        self.port = port
        self.brain_socket = str(brain_socket_path())
        # Handle of this listener's SessionManager entry, so close_listener can
        # find and stop it.  Set by open_listener after registering.  NOTE:
        # this is the *last* opened listener's handle only — a single
        # TCPListener instance is reused for every open_listener call (the
        # executor caches one instance per class), so per-listener state must
        # NOT live in flat instance attrs.  It lives in ``self._listeners``,
        # keyed by handle, and is bound into each connection's handler via
        # functools.partial so a connection on :1337 can never be mis-attributed
        # to the :1338 handle's buffer (the bug that cost the most time on box 22).
        self._handle = None
        # Per-handle config: handle -> {server, task, host, port, auto_answer}.
        # This is what makes handle↔port↔buffer an honest relationship instead
        # of an empirical guess.
        self._listeners: Dict[str, Dict[str, Any]] = {}

    @framework_tool("Send a message to the Brain via the Unix socket.")
    async def send_to_brain(self, event_type, session_id, data):
        try:
            reader, writer = await asyncio.open_unix_connection(self.brain_socket)
            # Send as "event|session_id|data", length-prefixed so thebrain.py
            # can read the exact message even if it's split across TCP frames
            payload = f"{event_type}|{session_id}|{data}"
            writer.write(pack_message(payload.encode()))
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            print(f"[!] Failed to send event to brain: {e}")

    async def start(self):
        server = await asyncio.start_server(self.handle_client, self.host, self.port)
        addr = server.sockets[0].getsockname()
        print(f"[*] Listening on {addr}... Press Ctrl+C to stop.")

        async with server:
            await server.serve_forever()
            
    async def handle_client(
        self,
        reader: StreamReader,
        writer: StreamWriter,
        _listener_handle: str = "",
        _listener_port: Optional[int] = None,
        _auto_answer: bool = False,
    ):
        """Per-connection read loop.

        ``_listener_handle`` / ``_listener_port`` / ``_auto_answer`` are bound
        in by ``open_listener`` via ``functools.partial`` so each connection is
        attributed to the *correct* listener even though one TCPListener
        instance serves many.  They are not part of the public tool schema.
        """
        addr = writer.get_extra_info('peername')
        peer_str = f"{addr[0]}:{addr[1]}" if addr else "unknown"
        session_id = hash(addr) & 0xFFFFFFFF
        # Fall back to the legacy flat attr only if a caller invoked us
        # without the partial binding (e.g. the standalone __main__ path).
        handle = _listener_handle or getattr(self, "_handle", None) or ""
        print(f"\n[+] New Session established: {addr} (ID: {session_id}) on "
              f"listener {handle or '?'}" +
              (f" (port {_listener_port})" if _listener_port else ""))

        # Register this client's writer so send_to_listener can reach it,
        # and so read_listener can report which peers are connected.
        _data_store.register_writer(handle, peer_str, writer)

        await self.send_to_brain("session_start", session_id, f"Connection from {addr}")

        # This creates a persistent session loop for each client
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break

                # 1) BUFFER FIRST — ordering is buffer → answer → close, so the
                #    exfil payload is always recoverable via read_listener even
                #    when we immediately 404 the probe (T1).
                _data_store.add_data(handle, peer_str, data, listener_port=_listener_port)

                message = data.decode(errors="replace").strip()
                print(f"[{addr}] Received: {message}")

                # 2) AUTO-ANSWER (T1): if this listener was opened with
                #    auto_answer=True and the inbound data looks like an HTTP
                #    request (starts with GET/POST/HEAD), answer 404 and close.
                #    Raw reverse shells / non-HTTP connects are left untouched
                #    so auto_answer never fires on a shell session.
                if _auto_answer and _looks_like_http(data):
                    try:
                        writer.write(_AUTO_ANSWER_404)
                        await writer.drain()
                    except (ConnectionResetError, BrokenPipeError, OSError) as e:
                        # Peer died before we could answer — it's still buffered,
                        # which is what matters.  Drop silently.
                        print(f"[-] auto_answer write to {addr} failed: {e}")
                    break  # finally closes + removes from connected_clients

                await self.send_to_brain("data_received", session_id, message)

                # NOTE: no auto-echo. With read-back in place, echoing
                # received bytes back into the socket creates a feedback
                # loop when the peer is a shell (the echo is parsed as a
                # command, re-read, re-echoed...). Drive the session with
                # send_to_listener instead; read responses with
                # read_listener.

        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            # T3: a dying peer must never take down the receiver.  Drop just
            # this peer, keep the listener alive, log one line.
            print(f"[-] Session {addr} dropped (peer died): {e}")
        except asyncio.CancelledError:
            # Listener is shutting down — let the finally clean up.  Do not
            # swallow; re-raise so the task cancellation propagates.
            raise
        except Exception as e:
            print(f"[!] Error in session {addr}: {e}")
        finally:
            _data_store.remove_writer(handle, peer_str)
            await self.send_to_brain("session_end", session_id, f"Closing {addr}")
            print(f"[*] Closing session {addr}")
            try:
                writer.close()
                await writer.wait_closed()
            except (ConnectionResetError, BrokenPipeError, OSError):
                pass  # peer already gone — nothing to close

    @framework_tool(
        "Open (bind) a TCP listener on host:port that waits for inbound "
        "connections. A *listener* is something YOU bind locally to RECEIVE a "
        "callback — e.g. for a reverse shell payload that connects back to "
        "you. This is different from a *backdoor* on the target: a backdoor is "
        "already running there and you pop it via a Metasploit exploit module "
        "(which returns an 'msf:' handle) — you do NOT bind a listener for "
        "that. open_listener returns immediately with a 'listener:' handle; "
        "the listener serves in the background. Use close_listener with the "
        "handle to stop it. Use list_sessions to see active listeners.\n\n"
        "Set auto_answer=True for *exfil-catch* listeners where the peer is an "
        "HTTP client (curl, wkhtmltopdf, a browser) that would otherwise hang "
        "waiting for a response and wedge its own handler. When set, inbound "
        "data that starts with GET/POST/HEAD is buffered (so you still recover "
        "it via read_listener) and then answered with HTTP/1.1 404 and the "
        "connection is closed — the client returns immediately instead of "
        "hanging. Raw (non-HTTP) connects such as reverse shells are left "
        "untouched, so auto_answer is safe to leave on for a mixed listener. "
        "Default is False (reverse-shell behaviour: never answer, drive via "
        "send_to_listener)."
    )
    async def open_listener(self, host, port, auto_answer: bool = False):
        """Bind a TCP listener and register it as a typed session.

        Returns immediately (does not block) with a 'listener:' handle.
        The listener keeps serving in the background.

        Args:
            host: Interface to bind on (e.g. '0.0.0.0').
            port: TCP port to listen on.
            auto_answer: If True, HTTP-looking inbound connects (GET/POST/HEAD)
                are answered with 404 and closed after buffering, so HTTP
                clients don't hang. Non-HTTP connects (reverse shells) are
                unaffected. Default False.
        """
        # Register in the SessionManager FIRST so we get the handle, then bind
        # that handle into the per-connection handler via functools.partial.
        # This is the T2 fix: each connection is attributed to the listener
        # that actually accepted it, not to whichever handle happens to live in
        # the shared instance's flat ``self._handle`` attr at read time (the
        # bug that sent :1337 probes into the :1338 buffer on box 22).
        sid = _sm.register(
            "listener",
            f"{host}:{port}",
            None,  # placeholder; replaced with the server object below
            host=host,
            port=port,
        )
        handle = format_handle("listener", sid)

        # Bind the handle + port + auto_answer into the handler so handle_client
        # never has to guess which listener a connection belongs to.
        handler = functools.partial(
            self.handle_client,
            _listener_handle=handle,
            _listener_port=port,
            _auto_answer=auto_answer,
        )
        server = await asyncio.start_server(handler, host, port)

        addr = server.sockets[0].getsockname()
        print(f"[*] Listening on {addr}... Press Ctrl+C to stop."
              + (" (auto_answer ON)" if auto_answer else ""))

        # Replace the placeholder client with the real server object so
        # close_listener can cancel/stop it via the SessionManager entry.
        session = _sm.get(sid)
        if session is not None:
            session.client = server

        # A listener is a *service*, not a computation: serve_forever() never
        # returns, so awaiting it here would hang whichever loop called this
        # tool.  Bind here, hand serving off to a background task, and report
        # back.  The serve wrapper (T3) logs one line if the accept loop ever
        # stops unexpectedly instead of dying silently.
        async def _serve():
            try:
                await server.serve_forever()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                print(f"[!] Listener {handle} accept loop stopped: {e}")

        self._server_task = asyncio.create_task(_serve())
        self._server = server
        self.host, self.port = addr[0], addr[1]
        self._handle = handle  # last-opened, backward compat only

        # Per-handle config so close_listener targets the RIGHT listener, not
        # whichever was opened last (the old self._server_task bug).
        self._listeners[handle] = {
            "server": server,
            "task": self._server_task,
            "host": addr[0],
            "port": addr[1],
            "auto_answer": auto_answer,
        }

        return (
            f"Listener started on {addr[0]}:{addr[1]} (handle: {handle}"
            + (", auto_answer=True" if auto_answer else "")
            + "). It is serving in the background and will receive inbound "
            "connections. Use close_listener with this handle to stop it, "
            "or list_sessions to see it alongside other sessions."
        )

    @framework_tool(
        "Stop and remove a background TCP listener that was started by "
        "open_listener. Pass the 'listener:' handle returned by open_listener.",
        accepted_handle_kinds=["listener"],
    )
    async def close_listener(self, handle):
        """Stop a bound listener and remove its session entry.

        Args:
            handle: The 'listener:' handle returned by open_listener.
        """
        kind, sid = parse_handle(handle)
        session = _sm.get(sid)
        if session is None:
            return f"Listener {handle} not found. Use list_sessions to see active listeners."
        server = session.client
        # Use the per-handle config (T2) so we cancel THIS listener's serve
        # task, not whichever listener was opened last.  Fall back to the
        # legacy flat attr for listeners opened before this fix landed.
        cfg = self._listeners.pop(handle, None)
        task = (cfg or {}).get("task") or getattr(self, "_server_task", None)
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            if cfg is None:
                self._server_task = None
        if server is not None:
            try:
                server.close()
                await server.wait_closed()
            except Exception:
                pass
        _sm.close(sid)
        if getattr(self, "_handle", None) == handle:
            self._handle = None
        # Purge stored data for this listener so it doesn't leak.
        _data_store.clear(handle)
        return f"Listener {handle} stopped."

    # ------------------------------------------------------------------
    # Read-back tools — the core addition that was missing.
    # ------------------------------------------------------------------

    @framework_tool(
        "Read back data received on a TCP listener. Returns a JSON list of "
        "entries, each with {handle, peer, listener_port, data_text, "
        "data_hex, size, ts}. listener_port is the port the receiving "
        "listener is bound on (the port the peer dialed), so the origin of "
        "every entry is unambiguous even when several listeners share one "
        "process. "
        "Pass the 'listener:' handle from open_listener to filter to one "
        "listener, or omit it to get data from ALL listeners. Use 'since' "
        "(Unix timestamp) to get only data after a point in time — typical "
        "usage: call read_listener, note the latest ts, send a command via "
        "send_to_listener, then read_listener again with since=last_ts to "
        "see only the new output. Use 'limit' to cap the number of entries "
        "returned (last N). Use clear_listener_data to wipe the buffer.",
        accepted_handle_kinds=["listener"],
        next_hints=["send_to_listener"],
    )
    def read_listener(self, handle: str = "", since: float = 0.0, limit: int = 50):
        """Retrieve data received by a listener (or all listeners).

        Args:
            handle: 'listener:' handle to filter, or empty for all listeners.
            since:  Only entries at or after this Unix timestamp (0 = all).
            limit:  If > 0, return at most the last N matching entries
                   (default 50; pass 0 for unlimited — not recommended on
                   long-lived listeners).
        """
        entries = _data_store.poll(handle=handle, since=since, limit=limit)
        clients = _data_store.list_clients(handle=handle) if handle else _data_store.list_clients()
        result = {
            "entries": entries,
            "connected_clients": clients,
            "total_entries": len(entries),
        }
        return json.dumps(result, indent=2)

    @framework_tool(
        "Send data to a client connected to a TCP listener. This is how you "
        "interact with a reverse shell: open_listener, wait for a callback, "
        "then send_to_listener with a command (e.g. 'id\\n'). Read the "
        "response with read_listener. If 'peer' is omitted and only one "
        "client is connected, it targets that client automatically. The data "
        "is sent as-is (no trailing newline added — include \\n yourself if "
        "the client expects it).\n\n"
        "Delivery semantics (honest, not optimistic): returns status 'Success' "
        "with a byte count when the write is known to have completed; status "
        "'Failed' when the peer is known dead (it is then dropped from "
        "connected_clients); status 'unknown_delivery' when a timeout/"
        "cancellation interrupted the write attempt and we cannot tell whether "
        "the bytes actually went out — in that case DO NOT assume failure: "
        "call read_listener first to check for a response before retrying, "
        "since a retry may double-execute a command on a live shell.",
        accepted_handle_kinds=["listener"],
        next_hints=["read_listener"],
    )
    async def send_to_listener(self, handle: str, data: str, peer: str = ""):
        """Send data to a connected client on a listener.

        Args:
            handle: The 'listener:' handle from open_listener.
            data:   String to send to the client (sent as UTF-8 bytes).
            peer:   Optional 'ip:port' of the specific client. If omitted,
                    targets the first (or only) connected client.
        """
        writer = _data_store.get_writer(handle, peer)
        if writer is None:
            clients = _data_store.list_clients(handle)
            return {
                "status": "Failed",
                "error": (
                    f"No connected client found on {handle}"
                    + (f" for peer {peer}" if peer else "")
                ),
                "connected_clients": clients,
            }

        payload = data.encode()
        # Bound the write attempt.  ``writer.write`` only buffers; ``drain`` is
        # the call that can block on a slow/dead peer.  A bounded drain lets us
        # distinguish "known done" from "interrupted, delivery unknown" (T4)
        # instead of reporting a timeout as a flat failure.
        send_timeout = float(os.getenv("LISTENER_SEND_TIMEOUT", "10"))

        try:
            writer.write(payload)
            await asyncio.wait_for(writer.drain(), timeout=send_timeout)
        except asyncio.TimeoutError:
            # The write was interrupted by a timeout — the bytes may already
            # have been delivered (observed twice live: "timed out" yet 64
            # bytes arrived).  Do NOT drop the peer and do NOT claim failure.
            return {
                "status": "unknown_delivery",
                "bytes_attempted": len(payload),
                "handle": handle,
                "peer": peer,
                "hint": "read_listener before retrying — the bytes may have "
                        "been delivered; a retry can double-execute on a live "
                        "shell.",
            }
        except asyncio.CancelledError:
            # Gateway-internal cancellation mid-write: same honest stance — we
            # don't know whether the bytes went out.  Return a result rather
            # than propagating so the caller gets actionable semantics instead
            # of an opaque timeout.
            return {
                "status": "unknown_delivery",
                "bytes_attempted": len(payload),
                "handle": handle,
                "peer": peer,
                "hint": "read_listener before retrying — the call was "
                        "cancelled mid-write and delivery is uncertain.",
            }
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            # KNOWN failure: the peer is dead.  Drop it so connected_clients
            # stays coherent and the listener stays alive (T3).
            dropped = _drop_writer(handle, peer, writer)
            return {
                "status": "Failed",
                "error": f"Peer {peer or 'client'} is unreachable: {e}",
                "handle": handle,
                "dropped_peer": dropped,
            }
        except Exception as e:
            # Unexpected — report failure but don't claim more than we know.
            return {
                "status": "Failed",
                "error": f"Send to {handle} failed: {e}",
                "handle": handle,
            }

        return {
            "status": "Success",
            "bytes": len(payload),
            "handle": handle,
            "peer": peer or "client",
        }

    @framework_tool(
        "Clear stored received-data entries for a listener (or all "
        "listeners). Useful to reset the readback buffer after you've "
        "consumed the output. Returns the number of entries removed.",
        accepted_handle_kinds=["listener"],
    )
    def clear_listener_data(self, handle: str = ""):
        """Clear the readback buffer for a listener or all listeners.

        Args:
            handle: 'listener:' handle, or empty to clear ALL listeners.
        """
        n = _data_store.clear(handle)
        return f"Cleared {n} stored data entries{' for ' + handle if handle else ''}."

    async def stop(self):
        """Stop the background listener started by ``open_listener``, if any
        (instance-level helper, not a framework tool)."""
        task = getattr(self, "_server_task", None)
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            self._server_task = None
            return "Listener stopped."
        return "No background listener running."
    async def background_task(self):
        while True:
            await asyncio.sleep(1)
            print("Background task running")

    async def main(self):
        parser = argparse.ArgumentParser(description="Multi-Client TCP Listener")
        parser.add_argument("port", type=int, help="Port to listen on")
        parser.add_argument("--host", default="0.0.0.0", help="Host to connect to")
        # buffer_size is handled inside handle_session read()
        args = parser.parse_args()

        # Run the listener and the background task concurrently
        try:
            await asyncio.gather(
                self.open_listener(args.host, args.port),
                self.background_task()
            )
        except KeyboardInterrupt:
            print("\n[!] Shutting down listener...")
        except Exception as e:
            print(f"[!] Listener encountered an error: {e}")
if __name__ == "__main__":
    listener = TCPListener()  # Replace with the actual class name
    import asyncio, argparse
    from asyncio import StreamReader, StreamWriter
    asyncio.run(listener.main())