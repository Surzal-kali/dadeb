"""Out-of-band (OOB) callback listener — a Burp Collaborator analog.

Multi-protocol listener that catches blind SSRF, blind XSS, and other OOB
callbacks.  Three protocols on one host:

  - HTTP  on TCP 80  — logs request path + source IP
  - HTTPS on TCP 443 — same, using the self-signed cert from utils/plugins/certs
  - DNS   on UDP 53  — answers ALL queries with a fixed IP, logs full QNAME

The payload ID rides in the subdomain: inject ``http://abc123.oob.lab/`` into
a blind SSRF, the vulnerable server does a DNS lookup for ``abc123.oob.lab``,
the DNS listener logs the QNAME, and the HTTP listener catches the subsequent
callback.  ``collab_poll`` returns both events correlated by the ID prefix.

Lab setup: the DNS listener on port 53 means no dnsmasq or /etc/hosts entry
is needed — it IS the resolver for *.oob.lab (and everything else).  For
real-world OOB with DNS-visibility, delegate a subdomain NS record to your
collaborator host (config, not code).

PUBLIC mode (COLLAB_PUBLIC_URL env)
-----------------------------------
When ``COLLAB_PUBLIC_URL`` is set (e.g. a Tailscale Funnel URL like
``https://<device>.<tailnet>.ts.net``), ``collab_generate`` returns
PATH-based PUBLIC callback URLs (``<public>/c/<id>/``) instead of
subdomain-based lab ones, and a token-gated redirect endpoint goes live at
``/r/<id>?to=<url>`` → 302 — which unlocks redirect-to-internal blind SSRF
(payloads that make the target follow our 302 into its own internal space).
The redirect is served by THIS listener; we never fetch ``to`` ourselves.
Funnel walkthrough (operator): ``tailscale funnel <COLLAB_HTTP_PORT>`` —
public HTTPS (TLS at Tailscale) → plain HTTP on 127.0.0.1:<COLLAB_HTTP_PORT>.
Funnel only serves HTTPS publicly and does NOT expose DNS-query events
(ts.net resolution happens at Tailscale's public DNS), so public mode is
HTTP-callback-only; subdomain mode keeps the DNS interaction signal.
Every callback (including public internet traffic) is appended to
``scope/collab_hits.jsonl`` as durable evidence (gitignored).

Requires root for ports 80, 443, and 53 (unneeded in funnel mode with
COLLAB_HTTP_PORT=8080).
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import socket
import ssl
import string
import struct
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from constants import framework_tool, resolve_workspace_root
from utils.handles import format_handle, parse_handle
from utils.session_manager import get_manager
from urllib.parse import parse_qs

_sm = get_manager()

# --- config ------------------------------------------------------------------

_COLLAB_DOMAIN = os.getenv("COLLAB_DOMAIN", "oob.lab")
_CERT_DIR = resolve_workspace_root() / "utils" / "plugins" / "certs"
_HTTP_PORT = int(os.getenv("COLLAB_HTTP_PORT", "80"))
_HTTPS_PORT = int(os.getenv("COLLAB_HTTPS_PORT", "443"))
_DNS_PORT = int(os.getenv("COLLAB_DNS_PORT", "53"))

# Public mode: a PUBLICLY-reachable HTTPS base URL for this listener (e.g.
# a Tailscale Funnel endpoint). Empty = lab subdomain mode (oob.lab only).
# See the module docstring for the funnel walkthrough + honest limits.
_PUBLIC_BASE_URL = os.getenv("COLLAB_PUBLIC_URL", "").strip().rstrip("/")

# Bounds so public-internet scanner noise can't grow without bound.
_STORE_CAP = 5000        # max in-memory callbacks kept for polling
_ACTIVE_ID_CAP = 1000    # max minted ids tracked for redirect validation
_MAX_REDIRECT_TO = 2048  # cap on the `to` value we will 302 to
_MAX_LOG_HEADERS = 16    # header lines captured per callback


def _detect_local_ip() -> str:
    """Best-effort detection of the local IP for DNS responses."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


# --- minimal DNS parser/builder ----------------------------------------------

def _parse_dns_qname(data: bytes) -> Optional[str]:
    """Extract the QNAME from a DNS query packet (labels → dotted string)."""
    if len(data) < 13:
        return None
    offset = 12  # skip 12-byte header
    labels: List[str] = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            break
        if length > 63 or offset + 1 + length > len(data):
            return None  # malformed or compression pointer (not in questions)
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(labels) if labels else None


def _build_dns_response(query: bytes, answer_ip: str) -> bytes:
    """Build a DNS A-record response for the given query."""
    # Header: copy query header, set QR=1 (response), AA=1, ANCOUNT=1
    header = bytearray(query[:12])
    header[2] |= 0x80  # QR
    header[3] |= 0x04  # AA
    header[6] = 0
    header[7] = 1  # ANCOUNT

    # Find the end of the question section
    q_end = 12
    while q_end < len(query) and query[q_end] != 0:
        q_end += query[q_end] + 1
    q_end += 5  # null byte + QTYPE(2) + QCLASS(2)

    # Answer: pointer to QNAME (0xC00C = offset 12), TYPE A, CLASS IN, TTL 60
    answer = struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4)
    answer += socket.inet_aton(answer_ip)

    return bytes(header) + query[12:q_end] + answer


# --- callback store ----------------------------------------------------------

class CallbackStore:
    """Thread-safe bounded list of received OOB callbacks + JSONL evidence."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._callbacks: List[Dict[str, Any]] = []

    def add(self, entry: Dict[str, Any]) -> None:
        with self._lock:
            self._callbacks.append(entry)
            if len(self._callbacks) > _STORE_CAP:
                del self._callbacks[: len(self._callbacks) - _STORE_CAP]
        self._append_jsonl(entry)

    @staticmethod
    def _append_jsonl(entry: Dict[str, Any]) -> None:
        """Best-effort durable evidence line under scope/ (gitignored).

        Never fatal: a full disk or read-only tree must not take down the
        listener — the in-memory store still serves collab_poll.
        """
        try:
            hits = (resolve_workspace_root() / "scope"
                    / "collab_hits.jsonl")
            hits.parent.mkdir(parents=True, exist_ok=True)
            with hits.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except Exception:
            pass

    def poll(self, since: float = 0.0) -> List[Dict[str, Any]]:
        with self._lock:
            return [cb for cb in self._callbacks if cb["ts"] >= since]

    def clear(self) -> None:
        with self._lock:
            self._callbacks.clear()


# --- DNS protocol (asyncio DatagramProtocol) ---------------------------------

class _DNSProtocol(asyncio.DatagramProtocol):
    def __init__(self, store: CallbackStore, answer_ip: str):
        self._store = store
        self._answer_ip = answer_ip
        self._transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self._transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:  # type: ignore[override]
        qname = _parse_dns_qname(data)
        if qname:
            self._store.add({
                "proto": "dns",
                "src_ip": addr[0],
                "qname": qname,
                "ts": time.time(),
            })
        try:
            response = _build_dns_response(data, self._answer_ip)
            if self._transport:
                self._transport.sendto(response, addr)
        except Exception:
            pass  # malformed query — log what we can, don't crash


# --- collaborator listener ---------------------------------------------------

class CollaboratorListener:
    """Multi-protocol OOB callback listener."""

    def __init__(self) -> None:
        self.store = CallbackStore()
        self.local_ip = _detect_local_ip()
        self.domain = _COLLAB_DOMAIN
        # ids minted via generate(), for the token-gated /r/<id> redirect
        # endpoint (public-internet requests to unknown ids get 404, so the
        # endpoint can't be abused as an open redirector).
        self.active_ids: Dict[str, float] = {}
        self._http_server: Optional[asyncio.base_events.Server] = None
        self._https_server: Optional[asyncio.base_events.Server] = None
        self._dns_transport: Optional[asyncio.DatagramTransport] = None
        self._tasks: List[asyncio.Task] = []
        self._handle: Optional[str] = None

    def redirect_decision(self, path: str) -> Tuple[str, str, str]:
        """Token-gated redirect endpoint decision for ``/r/<id>?to=<url>``.

        Prefix-tolerant: matches ``/r/<id>`` AND path-prefixed forms such as
        ``/collab/r/<id>`` (when COLLAB_PUBLIC_URL includes a funnel
        ``--set-path`` mount) — the LAST segment exactly equal to ``r`` marks
        the endpoint, the next segment is the id. Minted ids are 8-char
        lowercase+digits, so a bare ``r`` segment can only be our marker.

        Returns ``(status, location, rid)``:
          - (302, <to>, id)  — active id + http(s) `to` within the size cap
          - (404, "", "")   — path is /r/... but the id was never minted here
                               (or the path is not a redirect request at all)
          - (200, "", id)    — active id but no/invalid `to` (log-only callback)
        The 302 is served by THIS listener; we never fetch `to` ourselves.
        """
        pure = path.split("?", 1)[0]
        seg = [s for s in pure.split("/") if s]
        if "r" not in seg:
            return ("", "", "")
        i = len(seg) - 1 - seg[::-1].index("r")  # last bare "r" segment
        if i + 1 >= len(seg):
            return ("", "", "")
        rid = seg[i + 1]
        if rid not in self.active_ids:
            return ("404", "", "")
        to = parse_qs(path.split("?", 1)[1]) if "?" in path else {}
        to_val = (to.get("to", [""])[0] or "").strip()[:_MAX_REDIRECT_TO]
        if not to_val.lower().startswith(("http://", "https://")):
            return ("200", "", rid)
        return ("302", to_val, rid)

    # -- HTTP / HTTPS handlers ------------------------------------------------

    async def _handle_http(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
        proto: str = "http",
    ) -> None:
        addr = writer.get_extra_info("peername")
        try:
            # Read until end of HTTP headers (\r\n\r\n) so a fragmented
            # request still yields a complete request line + headers.
            # readuntil raises IncompleteReadError (stream closed early,
            # .partial has what arrived) or LimitOverrunError (headers
            # exceeded the 64K StreamReader limit).
            try:
                data = await asyncio.wait_for(
                    reader.readuntil(b"\r\n\r\n"), timeout=10
                )
            except asyncio.IncompleteReadError as e:
                data = e.partial
            except asyncio.LimitOverrunError:
                data = await reader.read(8192)
            text = data.decode("ascii", errors="replace")
            lines = text.split("\r\n")
            request_line = lines[0] if lines else ""
            parts = request_line.split()
            path = parts[1] if len(parts) > 1 else "/"

            # Capture Host header and User-Agent for identification, plus the
            # first N raw header lines (public-internet hits: the funnel
            # connects from localhost, so headers are the only forensics).
            host = ""
            ua = ""
            header_lines: List[str] = []
            for line in lines[1:]:
                if not line:
                    continue
                if len(header_lines) < _MAX_LOG_HEADERS:
                    header_lines.append(line[:256])
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip()
                elif line.lower().startswith("user-agent:"):
                    ua = line.split(":", 1)[1].strip()

            entry: Dict[str, Any] = {
                "proto": proto,
                "src_ip": addr[0] if addr else "?",
                "path": path,
                "host": host,
                "user_agent": ua,
                "excerpt": request_line[:256],
                "ts": time.time(),
            }
            if header_lines:
                entry["headers"] = header_lines
            # Token-gated redirect endpoint (public mode's main superpower:
            # redirect-to-internal blind SSRF). Log BEFORE responding so the
            # 302 itself is always in the record.
            status, location, rid = self.redirect_decision(path)
            if status == "302":
                entry["redirect_to"] = location
                entry["response"] = 302
                body = b"\n"
                resp = (
                    b"HTTP/1.1 302 Found\r\n"
                    b"Location: " + location.encode("ascii", errors="ignore")
                    + b"\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                    b"Connection: close\r\n"
                    b"\r\n" + body
                )
            elif status == "404":
                entry["redirect_refused"] = True
                body = b"\n"
                resp = (
                    b"HTTP/1.1 404 Not Found\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                    b"Connection: close\r\n"
                    b"\r\n" + body
                )
            else:
                body = b"OK\n"
                resp = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                    b"Connection: close\r\n"
                    b"\r\n" + body
                )
            self.store.add(entry)
            writer.write(resp)
            await writer.drain()
        except (asyncio.TimeoutError, ConnectionResetError, OSError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    # -- lifecycle ------------------------------------------------------------

    async def start(self) -> str:
        """Start HTTP, HTTPS, and DNS servers. Returns a collab: handle."""
        loop = asyncio.get_running_loop()

        # HTTP
        self._http_server = await asyncio.start_server(
            self._handle_http, "0.0.0.0", _HTTP_PORT,
        )

        # HTTPS (reuse certs from utils/plugins/certs)
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cert = _CERT_DIR / "cert.pem"
        key = _CERT_DIR / "key.pem"
        if cert.is_file() and key.is_file():
            ssl_ctx.load_cert_chain(str(cert), str(key))
            self._https_server = await asyncio.start_server(
                lambda r, w: self._handle_http(r, w, proto="https"),
                "0.0.0.0", _HTTPS_PORT,
                ssl=ssl_ctx,
            )
        # If certs are missing, skip HTTPS (don't crash — HTTP + DNS still work)

        # DNS
        self._dns_transport, _ = await loop.create_datagram_endpoint(
            lambda: _DNSProtocol(self.store, self.local_ip),
            local_addr=("0.0.0.0", _DNS_PORT),
        )

        # Background serve tasks
        self._tasks.append(asyncio.create_task(self._http_server.serve_forever()))
        if self._https_server:
            self._tasks.append(asyncio.create_task(self._https_server.serve_forever()))

        # Register in SessionManager
        sid = _sm.register(
            "collab",
            f"{self.local_ip} (http:{_HTTP_PORT} https:{_HTTPS_PORT} dns:{_DNS_PORT})",
            self,
            domain=self.domain,
            ip=self.local_ip,
        )
        self._handle = format_handle("collab", sid)
        return self._handle

    async def stop(self) -> str:
        """Stop all servers and clean up."""
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._tasks.clear()

        if self._http_server:
            self._http_server.close()
            await self._http_server.wait_closed()
        if self._https_server:
            self._https_server.close()
            await self._https_server.wait_closed()
        if self._dns_transport:
            self._dns_transport.close()

        # Minted ids die with the listener — /r/<id> stops 302ing.
        self.active_ids.clear()

        if self._handle:
            kind, sid = parse_handle(self._handle)
            _sm.close(sid)
            self._handle = None
        return "Collaborator stopped."

    def generate(self) -> Dict[str, str]:
        """Generate a unique callback ID and return {id, url, dns_name, mode, base}.

        Subdomain mode (default): url = http://<id>.<domain>/ — the id rides in
        the subdomain so a DNS lookup alone is a visible interaction.
        Public mode (COLLAB_PUBLIC_URL set): url = <public>/c/<id>/ — path-based,
        because the public TLS endpoint is a single host (e.g. a ts.net Funnel
        name) where subdomains do not resolve; DNS-query visibility is lost
        (honest limit), HTTP callbacks remain.
        """
        cid = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(8))
        dns_name = f"{cid}.{self.domain}"
        result: Dict[str, str] = {
            "id": cid,
            "url": f"http://{dns_name}/",
            "dns_name": dns_name,
        }
        if _PUBLIC_BASE_URL:
            result["url"] = f"{_PUBLIC_BASE_URL}/c/{cid}/"
            result["mode"] = "public"
            result["base"] = _PUBLIC_BASE_URL
        else:
            result["mode"] = "subdomain"
            result["base"] = ""
        # Track for the /r/<id> redirect gate; bounded, oldest dropped.
        self.active_ids[cid] = time.time()
        if len(self.active_ids) > _ACTIVE_ID_CAP:
            oldest = sorted(self.active_ids.items(), key=lambda kv: kv[1])
            for k, _v in oldest[: len(self.active_ids) - _ACTIVE_ID_CAP]:
                self.active_ids.pop(k, None)
        return result


# --- module-level singleton --------------------------------------------------

_collab: Optional[CollaboratorListener] = None


def _get_collab() -> CollaboratorListener:
    global _collab
    if _collab is None:
        raise RuntimeError(
            "Collaborator not started. Use collab_start first."
        )
    return _collab


# --- framework tools ---------------------------------------------------------

@framework_tool(
    "Start the OOB collaborator listener (HTTP on 80, HTTPS on 443, DNS on "
    "UDP 53; or COLLAB_HTTP_PORT in funnel mode). Requires root on the "
    "privileged defaults. Once started, use collab_generate to get unique "
    "callback URLs/DNS names to inject into blind SSRF/XSS payloads, and "
    "collab_poll to check for received callbacks. Returns a 'collab:' handle. "
    "When COLLAB_PUBLIC_URL is set, callbacks are PUBLIC path-based URLs on "
    "that host and the /r/<id>?to=<url> 302 redirect endpoint is live. The "
    "listener runs in the background — use collab_stop to stop it.",
    next_hints=["collab_generate"],
)
async def collab_start():
    """Start the multi-protocol OOB collaborator listener.

    Returns a 'collab:' handle. Servers run as background asyncio tasks.
    """
    global _collab
    if _collab is not None and _collab._handle is not None:
        return (
            f"Collaborator already running (handle: {_collab._handle}). "
            "Use collab_generate for callback URLs, collab_poll to check results."
        )
    _collab = CollaboratorListener()
    handle = await _collab.start()
    domain_note = (
        f"Domain: {_PUBLIC_BASE_URL} (public mode; lab DNS "
        f"*.{_COLLAB_DOMAIN} still answers locally). "
        if _PUBLIC_BASE_URL
        else f"Domain: {_collab.domain}. "
    )
    public_note = (
        f"Callbacks: {_PUBLIC_BASE_URL}/c/<id>/ — redirect endpoint: "
        f"{_PUBLIC_BASE_URL}/r/<id>?to=<url> (302). "
        if _PUBLIC_BASE_URL
        else "Lab subdomain mode (no COLLAB_PUBLIC_URL) — DNS+HTTP on "
        f"*.{_COLLAB_DOMAIN}. "
    )
    return (
        f"Collaborator started on {_collab.local_ip} "
        f"(http:{_HTTP_PORT} https:{_HTTPS_PORT} dns:{_DNS_PORT}). "
        f"Handle: {handle}. {domain_note}{public_note}"
        "Use collab_generate to get callback URLs to inject."
    )


@framework_tool(
    "Generate a unique OOB callback URL for injecting into blind SSRF/XSS "
    "payloads. Returns {id, url, dns_name, mode, base}. In lab subdomain "
    "mode the id rides in the subdomain — when the target resolves the DNS "
    "name, the collaborator logs the full qname so you can correlate the "
    "callback to this payload. In PUBLIC mode (COLLAB_PUBLIC_URL set) the "
    "url is path-based on the public host (works from internet-facing "
    "targets); the /r/<id>?to=<url> path 302s (use it for redirect-to-internal "
    "payloads). Example: inject the url into a blind SSRF, then collab_poll "
    "to see the callback.",
    next_hints=["collab_poll"],
)
def collab_generate():
    """Generate a unique callback ID, URL, and DNS name."""
    c = _get_collab()
    result = c.generate()
    return json.dumps(result)


@framework_tool(
    "Poll the collaborator for received OOB callbacks since a timestamp. "
    "Returns a list of {proto, src_ip, qname/path, ts, excerpt}. proto is "
    "'dns', 'http', or 'https'. If since is omitted or 0, returns ALL "
    "callbacks. Pass the id from collab_generate to filter — only callbacks "
    "whose qname (DNS), host, or path (HTTP) contains that id are returned, "
    "giving per-payload correlation without eyeballing every qname.",
    next_hints=["report_finding"],
)
def collab_poll(since: float = 0.0, id: str = ""):
    """Poll for OOB callbacks received since the given Unix timestamp.

    Args:
        since: Unix timestamp (float). Only callbacks at or after this time
               are returned. 0 = all callbacks.
        id: Optional payload ID from collab_generate. If given, only
            callbacks whose qname, host, or path contains this ID are
            returned — per-payload correlation.
    """
    c = _get_collab()
    callbacks = c.store.poll(since)
    if id:
        id_lower = id.lower()
        callbacks = [
            cb for cb in callbacks
            if id_lower in (cb.get("qname") or "").lower()
            or id_lower in (cb.get("host") or "").lower()
            or id_lower in (cb.get("path") or "").lower()
        ]
    return json.dumps(callbacks, indent=2)


@framework_tool(
    "Stop the OOB collaborator listener and free its ports. Pass the "
    "'collab:' handle returned by collab_start.",
    accepted_handle_kinds=["collab"],
)
async def collab_stop(handle: str = ""):
    """Stop the collaborator listener.

    Args:
        handle: The 'collab:' handle from collab_start. If provided, must
                match the current listener's handle — a stale handle from
                an old session is refused rather than murdering the new
                listener. If omitted, stops the current singleton.
    """
    global _collab
    if _collab is None:
        return "Collaborator not running."
    if handle and _collab._handle and handle != _collab._handle:
        return (
            f"Refusing to stop: handle {handle!r} does not match the current "
            f"listener's handle {_collab._handle!r}. This handle may be stale "
            "from a previous session."
        )
    msg = await _collab.stop()
    _collab = None
    return msg
