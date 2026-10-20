"""Scapy packet-crafting tools, exposed to the Brain as @framework_tool callables.

The ``PacketCraft`` / ``PacketUtils`` classes below are the raw engine.  The
module-level ``@framework_tool`` functions further down are the *integration
surface*: each one is a thin wrapper that minted a manifest entry at discovery
time (see ``daharness/registry.py``) so the secretary can call it like any
other framework tool (nmap, paramiko, etc.).

Design notes
------------
* Craft tools return a compact text blob containing a scapy ``summary()`` and
  the packet's ``hex``.  The hex is the currency passed to ``send_packet``,
  ``send_and_receive_packet`` (send + reply capture in one gated call),
  ``dissect_packet``, ``modify_packet``, and ``save_packet`` — there is no
  session handle because a crafted packet is stateless (unlike an SSH or MSF
  session).  ``next_hints`` and ``_CHAIN_NEXT`` nudge the model from a craft
  result to ``send_packet``.
* ``send``/``sniff`` need root (raw sockets); craft/dissect do not.  Craft and
  dissection tools are therefore safe to call unprivileged and are the common
  path; send/sniff will simply error if the Brain worker isn't root.
* The capture/send interface defaults to ``PACKET_CRAFT`` (env, loaded via
  loaddotenv) or ``enp92s0``, resolved per-call (not at import) so .env edits
  take effect without re-import.  Every packet tool takes an ``interface``
  parameter; craft tools accept it for schema uniformity but ignore it
  (crafting never touches the wire).
* Source-IP rule (2026-09-20): ``src_ip`` in the craft family MUST be THIS
  host's real routable IP on the target's network — replies go there, so a
  spoofed, unroutable, or guessed source means the reply goes elsewhere and
  ``send_and_receive_packet`` returns its no-reply envelope.  If the proper
  source IP is unknown, ASK THE OPERATOR — never guess or auto-derive it.
"""

import os
from pathlib import Path

import scapy.all as scapy
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6  # NOT re-exported by scapy.layers.inet
from scapy.layers.l2 import Ether, ARP, Dot1Q
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS, DNSQR, DNSRR
import random
import string
import time
import cryptography
from scapy.all import sr1, srp1, send, sniff, hexdump, Raw, sendp

from constants import framework_tool
from .scope_gate import check_send, ScopeGateError

# Default capture/send interface for the packet tools.  Env name is
# PACKET_CRAFT (set in .env; loaded by loaddotenv at stack boot).  Resolved
# at call time via _default_interface() so .env edits apply without re-import.
PACKET_INTERFACE_ENV = "PACKET_CRAFT"
DEFAULT_INTERFACE = "enp92s0"

# Pcap output directory — mirrors the msfvenom dropbox pattern: gitignored,
# env-overridable, resolved at call time so .env edits apply without re-import.
_REPO_ROOT = Path(__file__).resolve().parents[1]
PCAP_DIR = Path(os.getenv("PCAP_DIR", str(_REPO_ROOT / "pcaps")))
PCAP_MAX_PACKETS_PER_FILE = int(os.getenv("PCAP_MAX_PACKETS_PER_FILE", "100000"))
PCAP_MAX_FILE_MB = int(os.getenv("PCAP_MAX_FILE_MB", "512"))


def _pcap_dir() -> Path:
    """Resolve the pcap output directory at call time (env edits take effect
    without re-import)."""
    return Path(os.getenv("PCAP_DIR", str(_REPO_ROOT / "pcaps")))


def _pcap_max_packets() -> int:
    return int(os.getenv("PCAP_MAX_PACKETS_PER_FILE", "100000"))


def _pcap_max_file_mb() -> int:
    return int(os.getenv("PCAP_MAX_FILE_MB", "512"))


def _default_interface() -> str:
    """Resolve the default packet interface at call time.

    Precedence: ``PACKET_CRAFT`` (env, set in .env) -> ``DEFAULT_INTERFACE``.
    Read per-call instead of at import so loaddotenv/.env edits take effect.
    """
    return os.getenv(PACKET_INTERFACE_ENV) or DEFAULT_INTERFACE
#[ ]TODO:  Needs to take advantage of poor cryptography, it's just sitting there {muy importante now that its on mcp}


# --- module-local helpers -------------------------------------------------

# Singleton engine instance.  Lazy so importing this module during discovery
# never opens a socket or touches an interface.
_craft_instance: "PacketCraft | None" = None


def _craft(interface: str = "") -> "PacketCraft":
    """Return the shared PacketCraft engine, bound to ``interface`` if given
    (empty string = the ``PACKET_CRAFT``/``DEFAULT_INTERFACE`` default).
    Rebinds only when the requested interface differs from the bound one."""
    global _craft_instance
    iface = interface or _default_interface()
    if _craft_instance is None or _craft_instance.interface != iface:
        _craft_instance = PacketCraft(iface)
    return _craft_instance


def _packet_to_hex(packet: scapy.Packet) -> str:
    """Serialise a crafted packet to a hex string for round-trip through the
    model / send / dissect tools."""
    return bytes(packet).hex()


def _packet_from_hex(hex_string: str) -> scapy.Packet:
    """Reconstruct a packet from a hex string.

    Discriminates L2 (Ethernet frame) from L3 (bare IP) by attempting an
    ``Ether`` parse and checking for a recognised network layer — NOT by the
    first byte's nibble.  The high nibble of a destination MAC collides with
    the IPv4 version nibble: Apple ``4c:…``, Cisco ``40:``/``48:`` OUIs all
    start ``4x:``, so the old ``(raw[0] >> 4) == 4`` test silently misparsed
    real frames as garbage IP (e.g. ``4c:1f:cc:…`` → ``8.0.69.0 > 0.47.0.1
    ah frag:17``) with no exception, producing a packet that could never be
    sent or dissected meaningfully.

    A bare L3 craft output (``IP()/…``, first byte ``0x45``) mis-parses
    under ``Ether`` with a garbage EtherType, so none of the recognised
    layers appear and we fall through to the ``IP`` parse (version nibble 6
    routes to ``IPv6`` — a bare IPv6 packet fed to ``IP()`` silently misparses
    as garbage IPv4).  An L2 frame carrying IP/IPv6/ARP/DHCP/VLAN parses
    cleanly under ``Ether`` and is returned
    as-is.  This keeps the round-trip consistent with
    :meth:`PacketUtils.import_packet_hex`, which delegates here.
    """
    raw = bytes.fromhex(hex_string.strip())
    try:
        frame = Ether(raw)
        if IP in frame or IPv6 in frame or ARP in frame or DHCP in frame or Dot1Q in frame:
            return frame
    except Exception:
        pass
    # Bare L3: an IPv6 header always starts with version nibble 6 — after the
    # Ether attempt failed to recognise a layer, route on the version nibble.
    # This is safe where the old MAC-nibble test was not: the ambiguous
    # dst-MAC-OUI-vs-version collision only matters for distinguishing L2
    # frames, and the Ether parse has already been tried and rejected.  A bare
    # IPv6 packet fed to IP() silently misparses as garbage IPv4 (e.g. v6/TCP
    # → '0.0.0.0 > 0.0.0.0 hopopt frag:1600') whose unspecified-ish dst would
    # bypass the scope gate — so the v6 check must come first.
    if raw and (raw[0] >> 4) == 6:
        return IPv6(raw)
    return IP(raw)


def _packet_dst(packet: scapy.Packet) -> "str | None":
    """Extract the routable destination a send is directed at, for the scope
    gate.  Returns the destination IP for IPv4/IPv6 packets, the target
    protocol address (``pdst``) for ARP, or ``None`` for frames that carry no
    directed host IP (pure L2).  ``None`` and non-routable (broadcast/multicast/...)
    destinations are never gated — only routable unicast IPs directed at a
    real host are.  See :func:`utils.scope_gate.check_send`.
    """
    if IP in packet:
        return packet[IP].dst
    if IPv6 in packet:
        return packet[IPv6].dst
    if ARP in packet:
        return packet[ARP].pdst
    return None


def _craft_result(packet: scapy.Packet) -> str:
    """Standard craft-tool return: summary + hex the model can forward."""
    return (
        f"Packet crafted: {packet.summary()}\n"
        f"hex: {_packet_to_hex(packet)}\n"
        f"Pass the hex to send_packet (to transmit), send_and_receive_packet "
        f"(to transmit and capture the reply in one call), dissect_packet "
        f"(to inspect), or modify_packet (to change fields)."
    )


def _payload_bytes(payload: str | bytes | None) -> bytes:
    """Coerce a model-supplied payload (usually a str) into bytes."""
    if payload is None or payload == "":
        return b""
    if isinstance(payload, bytes):
        return payload
    return payload.encode("utf-8", errors="replace")
class PacketUtils:
    def dissect_packet(self, packet: scapy.Packet):
        """Dissect a packet."""
        packet.show()

    def extract_payload(self, packet: scapy.Packet) -> bytes:
        """Extract the payload from a packet."""
        if Raw in packet:
            return bytes(packet[Raw].load)
        return b""

    def modify_packet(self, packet: scapy.Packet, **kwargs) -> scapy.Packet:
        """Modify fields of a packet."""
        for field, value in kwargs.items():
            if hasattr(packet, field):
                setattr(packet, field, value)
        return packet

    def random_string(self, length: int = 10) -> str:
        """Generate a random string of specified length."""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def export_packet_hex(self, packet: scapy.Packet) -> str | None:
        """Export a packet in hexadecimal format."""
        return hexdump(packet, dump=True)

    def import_packet_hex(self, hex_string: str) -> scapy.Packet:
        """Import a packet from a hexadecimal string.

        Delegates to :func:`_packet_from_hex` so the same hex round-trips to
        the same packet regardless of which tool touches it.  Previously this
        used an inconsistent ``startswith(b'\\x00\\x00')`` discriminator, so
        the same hex string could resolve to different packets here vs.
        ``send_packet``/``dissect_packet``.
        """
        return _packet_from_hex(hex_string)

    def wait_for_packet(self, filter: str = "", timeout: int = 30, interface: str = "") -> scapy.Packet | None:
        """Wait for a packet matching the filter.

        ``interface`` (empty = PACKET_CRAFT env / DEFAULT_INTERFACE) was
        previously ignored here — this method sniffed the module-global
        default no matter what the caller passed.  Now honoured.
        """
        packets = sniff(iface=interface or _default_interface(), filter=filter, count=1, timeout=timeout)
        return packets[0] if packets else None

class PacketCraft:
    def __init__(self, interface: str = ""):
        self.interface = interface or _default_interface()
        self.utils = PacketUtils()

    def icmp_echo_request(self, src_ip: str, dst_ip: str, payload: bytes = b"") -> scapy.Packet:
        """Craft an ICMP Echo Request packet."""
        packet = IP(src=src_ip, dst=dst_ip) / ICMP(type=8) / Raw(load=payload)
        return packet

    def icmp_echo_reply(self, src_ip: str, dst_ip: str, payload: bytes = b"") -> scapy.Packet:
        """Craft an ICMP Echo Reply packet."""
        packet = IP(src=src_ip, dst=dst_ip) / ICMP(type=0) / Raw(load=payload)
        return packet

    def craft_http_request(self, src_ip: str, dst_ip: str, method: str = "GET", path: str = "/", headers: list[tuple[str, str]] = [], payload: bytes = b"") -> scapy.Packet:
        """Craft an HTTP request packet."""
        headers_dict = dict(headers)
        http_layer = HTTPRequest(
            Method=method,
            Path=path,
            Host=headers_dict.get("Host", ""),
            User_Agent=headers_dict.get("User-Agent", ""),
            Accept=headers_dict.get("Accept", ""),
            Accept_Encoding=headers_dict.get("Accept-Encoding", ""),
            Accept_Language=headers_dict.get("Accept-Language", "")
        )
        packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(1024, 65535), dport=80, flags="PA") / http_layer / Raw(load=payload)
        return packet

    def craft_http_response(self, src_ip: str, dst_ip: str, status_code: int = 200, reason: str = "OK", headers: dict | None = None, payload: bytes = b"") -> scapy.Packet:
        """Craft an HTTP response packet."""
        if headers is None:
            headers = {}
        http_layer = HTTPResponse(
            Status_Code=status_code,
            Reason_Phrase=reason,
            Server=headers.get("Server", ""),
            Content_Type=headers.get("Content-Type", ""),
            Content_Length=str(len(payload))
        )
        packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(1024, 65535), dport=80, flags="PA") / http_layer / Raw(load=payload)
        return packet

    def craft_dns_response(self, src_ip: str, dst_ip: str, query_name: str, answer_ip: str) -> scapy.Packet:
        """Craft a DNS response packet."""
        dns_layer = DNS(
            id=random.randint(0, 65535),
            qr=1,
            aa=1,
            qd=DNSQR(qname=query_name),
            an=DNSRR(rrname=query_name, rdata=answer_ip)
        )
        packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=random.randint(1024, 65535), dport=53) / dns_layer
        return packet

    def craft_dns_response_multi(self, src_ip: str, dst_ip: str, query_name: str, answer_ips: list[str]) -> scapy.Packet:
        """Craft a DNS response packet with multiple answers."""
        dns_layer = DNS(
            id=random.randint(0, 65535),
            qr=1,
            aa=1,
            qd=DNSQR(qname=query_name),
            an=DNSRR(rrname=query_name, rdata=answer_ips[0])
        )
        for ip in answer_ips[1:]:
            dns_layer.an /= DNSRR(rrname=query_name, rdata=ip)
        packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=random.randint(1024, 65535), dport=53) / dns_layer
        return packet

    def craft_tcp_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, flags: str = "S", payload: bytes = b"") -> scapy.Packet:
        """Craft a TCP packet."""
        packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags=flags) / Raw(load=payload)
        return packet

    def craft_udp_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes = b"") -> scapy.Packet:
        """Craft a UDP packet."""
        packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / Raw(load=payload)
        return packet

    def craft_arp_packet(self, src_mac: str, dst_mac: str, src_ip: str, dst_ip: str) -> scapy.Packet:
        """Craft an ARP packet."""
        packet = Ether(src=src_mac, dst=dst_mac) / ARP(hwsrc=src_mac, psrc=src_ip, hwdst=dst_mac, pdst=dst_ip)
        return packet

    def vlan_frame(self, src_mac: str, dst_mac: str, vlan_id: int, payload: bytes = b"") -> scapy.Packet:
        """Craft a VLAN frame."""
        packet = Ether(src=src_mac, dst=dst_mac) / Dot1Q(vlan=vlan_id) / Raw(load=payload)
        return packet

    def craft_icmp_packet(self, src_ip: str, dst_ip: str, payload: bytes = b"") -> scapy.Packet:
        """Craft an ICMP packet."""
        packet = IP(src=src_ip, dst=dst_ip) / ICMP() / Raw(load=payload)
        return packet

    def craft_dns_query(self, src_ip: str, dst_ip: str, query_name: str) -> scapy.Packet:
        """Craft a DNS query packet."""
        packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=random.randint(1024, 65535), dport=53) / DNS(rd=1, qd=DNSQR(qname=query_name))
        return packet

    def craft_arp_request(self, src_mac: str, src_ip: str, target_ip: str) -> scapy.Packet:
        """Craft an ARP request packet."""
        packet = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(hwsrc=src_mac, psrc=src_ip, hwdst="00:00:00:00:00:00", pdst=target_ip, op=1)
        return packet

    def dhcp_discover(self, src_mac: str) -> scapy.Packet:
        """Craft a DHCP discover packet."""
        packet = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(chaddr=src_mac.replace(":", "")) / DHCP(options=[("message-type", "discover"), "end"])
        return packet

    def craft_mDNS_query(self, src_ip: str, dst_ip: str, query_name: str) -> scapy.Packet:
        """Craft an mDNS query packet."""
        packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=random.randint(1024, 65535), dport=5353) / DNS(rd=1, qd=DNSQR(qname=query_name))
        return packet

    def send_packet(self, packet: scapy.Packet, count: int = 1, interval: float = 0.1):
        """Send a packet multiple times with a specified interval.

        Uses :func:`send` for L3 packets (``IP()/IPv6()/…``) so scapy wraps the L2
        header, and :func:`sendp` for L2 frames that already carry an
        Ethernet header.  Feeding a bare IP packet to ``sendp`` silently
        emits a frame whose Ethernet header is the first 14 bytes of the
        IP header — a no-op that looks like success.

        Honours the operator-armed scope gate (see scope_gate.py): refuses
        to transmit to a destination not confirmed in-scope when a scope is
        armed.
        """
        _ok, _reason = check_send(_packet_dst(packet))
        if not _ok:
            raise ScopeGateError(f"scope gate: {_reason}")
        send_fn = send if isinstance(packet, (IP, IPv6)) else sendp
        for _ in range(count):
            send_fn(packet, iface=self.interface, verbose=False)
            time.sleep(interval)

    def send_and_receive(self, packet: scapy.Packet, timeout: int = 5):
        """Send ONE packet and capture its reply (scapy ``sr1``/``srp1``).

        L3 packets (``IP()/IPv6()/...``) go via ``sr1`` (scapy wraps the L2
        header and routes); L2 frames (``Ether()/...``) go via ``srp1`` on
        ``self.interface``.  Honours the operator-armed scope gate BEFORE
        firing (same as :meth:`send_packet`).  Returns the reply packet, or
        ``None`` when nothing came back within ``timeout`` seconds.
        """
        _ok, _reason = check_send(_packet_dst(packet))
        if not _ok:
            raise ScopeGateError(f"scope gate: {_reason}")
        recv_fn = sr1 if isinstance(packet, (IP, IPv6)) else srp1
        return recv_fn(packet, iface=self.interface, timeout=timeout, verbose=False)

    def sniff_packets(self, filter: str = "", count: int = 10, timeout: int = 30):
        """Sniff packets on the specified interface."""
        packets = sniff(iface=self.interface, filter=filter, count=count, timeout=timeout)
        return packets

    def save_packet(self, packet: scapy.Packet, filename: str):
        """Save a packet to a file."""
        scapy.wrpcap(filename, packet)

    def load_packet(self, filename: str) -> scapy.Packet | None:
        """Load a packet from a file."""
        packets = scapy.rdpcap(filename)
        return packets[0] if packets else None


# ===========================================================================
# @framework_tool integration surface
# ===========================================================================
# Everything above is the raw engine.  Everything below is what the Brain sees.
#
# Convention (same as nmap / paramiko_client): one @framework_tool function per
# capability, module-level, with a docstring whose first line is the capability
# blurb used as the semantic-search embedding text.  Craft tools return a text
# blob carrying the packet's hex so it can be forwarded to send / dissect /
# modify / save.  There are NO session handles here — a packet is stateless.

# --- ICMP -----------------------------------------------------------------

@framework_tool(
    "Craft an ICMP Echo Request (ping) packet. Returns the packet hex to pass "
    "to send_packet, dissect_packet, or modify_packet.",
    next_hints=["send_packet with the returned hex"],
)
def craft_icmp_echo(src_ip: str, dst_ip: str, payload: str = "", interface: str = ""):
    """Craft an ICMP Echo Request (type 8) packet.

    Args:
        src_ip: This host's REAL routable IP on the target network (replies go here); ask the operator if unknown.
        dst_ip: Destination IP address.
        payload: Optional payload text (encoded to bytes).
        interface: Interface override for schema consistency with the send/sniff tools; ignored while crafting (crafting never touches the wire).
    """
    pkt = _craft().icmp_echo_request(src_ip, dst_ip, _payload_bytes(payload))
    return _craft_result(pkt)


@framework_tool(
    "Craft a generic ICMP packet (configurable via modify_packet afterwards). "
    "Returns the packet hex.",
    next_hints=["send_packet with the returned hex", "modify_packet to set ICMP type/code"],
)
def craft_icmp_packet(src_ip: str, dst_ip: str, payload: str = "", interface: str = ""):
    """Craft a generic ICMP packet (type/code left at scapy defaults).

    Args:
        src_ip: This host's REAL routable IP on the target network (replies go here); ask the operator if unknown.
        dst_ip: Destination IP address.
        payload: Optional payload text.
        interface: Interface override for schema consistency with the send/sniff tools; ignored while crafting (crafting never touches the wire).
    """
    pkt = _craft().craft_icmp_packet(src_ip, dst_ip, _payload_bytes(payload))
    return _craft_result(pkt)


# --- TCP / UDP ------------------------------------------------------------

@framework_tool(
    "Craft a raw TCP packet with chosen flags (e.g. 'S' SYN, 'A' ACK, 'F' FIN, "
    "'R' RST, 'PA' PSH-ACK). Returns the packet hex.",
    next_hints=["send_packet with the returned hex"],
)
def craft_tcp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, flags: str = "S", payload: str = "", interface: str = ""):
    """Craft a TCP/IP packet.

    Args:
        src_ip: This host's REAL routable IP on the target network (replies go here); ask the operator if unknown.
        dst_ip: Destination IP address.
        src_port: Source TCP port.
        dst_port: Destination TCP port.
        flags: TCP flag string (S, A, F, R, P, PA, SA, ...).
        payload: Optional payload text.
        interface: Interface override for schema consistency with the send/sniff tools; ignored while crafting (crafting never touches the wire).
    """
    pkt = _craft().craft_tcp_packet(src_ip, dst_ip, int(src_port), int(dst_port), flags, _payload_bytes(payload))
    return _craft_result(pkt)


@framework_tool(
    "Craft a raw UDP packet. Returns the packet hex.",
    next_hints=["send_packet with the returned hex"],
)
def craft_udp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: str = "", interface: str = ""):
    """Craft a UDP/IP packet.

    Args:
        src_ip: This host's REAL routable IP on the target network (replies go here); ask the operator if unknown.
        dst_ip: Destination IP address.
        src_port: Source UDP port.
        dst_port: Destination UDP port.
        payload: Optional payload text.
        interface: Interface override for schema consistency with the send/sniff tools; ignored while crafting (crafting never touches the wire).
    """
    pkt = _craft().craft_udp_packet(src_ip, dst_ip, int(src_port), int(dst_port), _payload_bytes(payload))
    return _craft_result(pkt)


# --- ARP / L2 / VLAN ------------------------------------------------------

@framework_tool(
    "Craft an ARP request (broadcast) to resolve a target IP's MAC. Returns "
    "the packet hex (an L2/Ether frame — send with send_packet).",
    next_hints=["send_packet with the returned hex"],
)
def craft_arp_request(src_mac: str, src_ip: str, target_ip: str, interface: str = ""):
    """Craft a broadcast ARP request.

    Args:
        src_mac: Source MAC address (e.g. 'aa:bb:cc:dd:ee:ff').
        src_ip: Source IP (sender protocol address).
        target_ip: IP whose MAC you want to resolve.
        interface: Interface override for schema consistency with the send/sniff tools; ignored while crafting (crafting never touches the wire).
    """
    pkt = _craft().craft_arp_request(src_mac, src_ip, target_ip)
    return _craft_result(pkt)


@framework_tool(
    "Craft a directed ARP packet (request or reply depending on op set later). "
    "Returns the packet hex.",
    next_hints=["send_packet with the returned hex", "modify_packet to set ARP op"],
)
def craft_arp_packet(src_mac: str, dst_mac: str, src_ip: str, dst_ip: str, interface: str = ""):
    """Craft a directed ARP packet between two MAC/IP pairs.

    Args:
        src_mac: Sender MAC.
        dst_mac: Target MAC.
        src_ip: Sender IP.
        dst_ip: Target IP.
        interface: Interface override for schema consistency with the send/sniff tools; ignored while crafting (crafting never touches the wire).
    """
    pkt = _craft().craft_arp_packet(src_mac, dst_mac, src_ip, dst_ip)
    return _craft_result(pkt)


@framework_tool(
    "Craft an 802.1Q VLAN-tagged Ethernet frame. Returns the packet hex.",
    next_hints=["send_packet with the returned hex"],
)
def craft_vlan_frame(src_mac: str, dst_mac: str, vlan_id: int, payload: str = "", interface: str = ""):
    """Craft a VLAN-tagged frame.

    Args:
        src_mac: Source MAC.
        dst_mac: Destination MAC.
        vlan_id: 802.1Q VLAN tag (0-4095).
        payload: Optional payload text.
        interface: Interface override for schema consistency with the send/sniff tools; ignored while crafting (crafting never touches the wire).
    """
    pkt = _craft().vlan_frame(src_mac, dst_mac, int(vlan_id), _payload_bytes(payload))
    return _craft_result(pkt)


@framework_tool(
    "Craft a DHCP Discover packet (L2 broadcast). Returns the packet hex.",
    next_hints=["send_packet with the returned hex"],
)
def craft_dhcp_discover(src_mac: str, interface: str = ""):
    """Craft a DHCP DISCOVER.

    Args:
        src_mac: Client MAC address.
        interface: Interface override for schema consistency with the send/sniff tools; ignored while crafting (crafting never touches the wire).
    """
    pkt = _craft().dhcp_discover(src_mac)
    return _craft_result(pkt)


# --- DNS / mDNS -----------------------------------------------------------

@framework_tool(
    "Craft a DNS request packet (UDP/53) for a domain name. Returns the packet hex.",
    next_hints=["send_packet with the returned hex"],
)
def craft_dns_query(src_ip: str, dst_ip: str, query_name: str, interface: str = ""):
    """Craft a DNS query.

    Args:
        src_ip: Source IP.
        dst_ip: DNS server IP.
        query_name: Name to resolve (e.g. 'example.com').
        interface: Interface override for schema consistency with the send/sniff tools; ignored while crafting (crafting never touches the wire).
    """
    pkt = _craft().craft_dns_query(src_ip, dst_ip, query_name)
    return _craft_result(pkt)


@framework_tool(
    "Craft a forged DNS response (authoritative, single answer). Useful for "
    "DNS spoofing / cache-poisoning demos. Returns the packet hex.",
    next_hints=["send_packet with the returned hex", "report_finding"],
)
def craft_dns_response(src_ip: str, dst_ip: str, query_name: str, answer_ip: str, interface: str = ""):
    """Craft a forged DNS response with one answer record.

    Args:
        src_ip: Spoofed resolver IP.
        dst_ip: Victim IP.
        query_name: Query name to answer.
        answer_ip: IP to put in the answer record.
        interface: Interface override for schema consistency with the send/sniff tools; ignored while crafting (crafting never touches the wire).
    """
    pkt = _craft().craft_dns_response(src_ip, dst_ip, query_name, answer_ip)
    return _craft_result(pkt)


@framework_tool(
    "Craft a forged DNS response with multiple answer records (round-robin / "
    "rotating spoof). Returns the packet hex.",
    next_hints=["send_packet with the returned hex", "report_finding"],
)
def craft_dns_response_multi(src_ip: str, dst_ip: str, query_name: str, answer_ips: list, interface: str = ""):
    """Craft a forged DNS response with several answer records.

    Args:
        src_ip: Spoofed resolver IP.
        dst_ip: Victim IP.
        query_name: Query name to answer.
        answer_ips: List of IPs to put in the answer records.
        interface: Interface override for schema consistency with the send/sniff tools; ignored while crafting (crafting never touches the wire).
    """
    ips = [str(ip) for ip in answer_ips]
    pkt = _craft().craft_dns_response_multi(src_ip, dst_ip, query_name, ips)
    return _craft_result(pkt)


@framework_tool(
    "Craft an mDNS request packet (UDP/5353) for a domain name. Returns the packet hex.",
    next_hints=["send_packet with the returned hex"],
)
def craft_mdns_query(src_ip: str, dst_ip: str, query_name: str, interface: str = ""):
    """Craft an mDNS query.

    Args:
        src_ip: Source IP.
        dst_ip: mDNS target (usually 224.0.0.251).
        query_name: Name to query (e.g. '_http._tcp.local').
        interface: Interface override for schema consistency with the send/sniff tools; ignored while crafting (crafting never touches the wire).
    """
    pkt = _craft().craft_mDNS_query(src_ip, dst_ip, query_name)
    return _craft_result(pkt)


# --- HTTP -----------------------------------------------------------------

@framework_tool(
    "Craft an HTTP request packet (TCP/80). Returns the packet hex.",
    next_hints=["send_packet with the returned hex"],
)
def craft_http_request(src_ip: str, dst_ip: str, method: str = "GET", path: str = "/", host: str = "", user_agent: str = "", payload: str = "", interface: str = ""):
    """Craft an HTTP request packet.

    Args:
        src_ip: Source IP.
        dst_ip: Destination IP (web server).
        method: HTTP method (GET, POST, ...).
        path: Request path.
        host: Host header value.
        user_agent: User-Agent header value.
        payload: Optional body text.
        interface: Interface override for schema consistency with the send/sniff tools; ignored while crafting (crafting never touches the wire).
    """
    headers = [("Host", host), ("User-Agent", user_agent)]
    pkt = _craft().craft_http_request(
        src_ip, dst_ip, method=method, path=path, headers=headers, payload=_payload_bytes(payload)
    )
    return _craft_result(pkt)


@framework_tool(
    "Craft an HTTP response packet (TCP/80). Returns the packet hex.",
    next_hints=["send_packet with the returned hex"],
)
def craft_http_response(src_ip: str, dst_ip: str, status_code: int = 200, reason: str = "OK", content_type: str = "text/html", payload: str = "", interface: str = ""):
    """Craft an HTTP response packet.

    Args:
        src_ip: Server IP.
        dst_ip: Client IP.
        status_code: HTTP status code.
        reason: Reason phrase.
        content_type: Content-Type header value.
        payload: Optional body text.
        interface: Interface override for schema consistency with the send/sniff tools; ignored while crafting (crafting never touches the wire).
    """
    body = _payload_bytes(payload)
    pkt = _craft().craft_http_response(
        src_ip, dst_ip, status_code=int(status_code), reason=reason,
        headers={"Content-Type": content_type}, payload=body,
    )
    return _craft_result(pkt)


# --- Transport / capture / analysis --------------------------------------

@framework_tool(
    "Send a previously crafted packet (by hex) on the wire. Requires root "
    "(raw sockets). Pass the hex returned by any craft_* tool.",
    next_hints=[
        "send_and_receive_packet to fire and capture the reply in one call",
        "sniff_packets to capture replies",
        "dissect_packet to inspect a reply",
    ],
)
def send_packet(hex: str, count: int = 1, interval: float = 0.1, interface: str = ""):
    """Send a crafted packet one or more times.

    Args:
        hex: Packet hex string from a craft_* tool.
        count: Number of times to send.
        interval: Seconds between sends.
        interface: Interface to transmit on; defaults to PACKET_CRAFT env (fallback enp92s0).
    """
    # Scope gate: refuses sends to out-of-scope destinations when an operator
    # has armed a bug-bounty scope from the Tool REPL.  No-op in lab mode.
    # Done BEFORE the try so a block raises (surfaces as Failed on both
    # dispatch paths) instead of being caught and returned as a string the
    # Brain relabels Success.  See utils/scope_gate.py.
    pkt = _packet_from_hex(hex)
    _ok, _reason = check_send(_packet_dst(pkt))
    if not _ok:
        raise ScopeGateError(f"scope gate: {_reason}")
    try:
        iface = interface or _default_interface()
        # L3 craft output (IP()/...) must go via send() so scapy wraps the
        # Ethernet header itself; sendp() on a bare IP packet emits a frame
        # whose "Ethernet header" is the first 14 bytes of the IP header
        # (dst MAC 45:00:00:00:00:00) — the switch floods it, no host
        # accepts it, and the tool still reports "Sent N packet(s)".
        send_fn = send if isinstance(pkt, (IP, IPv6)) else sendp
        for _ in range(int(count)):
            send_fn(pkt, iface=iface, verbose=False)
            time.sleep(float(interval))
        return f"Sent {count} packet(s) on {iface}: {pkt.summary()}"
    except PermissionError as e:
        return (
            f"send_packet requires root/raw-socket capability: {e}. "
            "Run the Brain worker as root, or use craft_* + dissect_packet "
            "for offline analysis."
        )
    except Exception as e:
        return f"send_packet error: {e}"


@framework_tool(
    "Send a crafted packet (by hex) and capture its reply in the SAME call "
    "(scapy sr1/srp1): ICMP echo->echo reply, TCP SYN->SYN-ACK/RST, DNS "
    "query->response, ARP request->reply. Returns the reply's summary + hex "
    "for dissect_packet. Requires root.",
    next_hints=[
        "dissect_packet with the reply hex to inspect the reply fully",
        "modify_packet on the reply hex to craft a follow-up probe",
    ],
)
def send_and_receive_packet(hex: str, timeout: int = 5, interface: str = ""):
    """Send ONE packet and capture its reply in one gated call.

    Single-probe semantics (scapy sr1/srp1): one packet out, first matching
    reply back. For bursts or promiscuous capture use send_packet +
    sniff_packets. Gate: the same check_send runs BEFORE the probe fires
    (identical to send_packet) — refusals raise ScopeGateError; the inbound
    reply itself is not gated (receive-only).

    Source-IP note: the probe's src_ip is chosen in the craft_* call and MUST
    be this host's real routable IP on the target network — a spoofed or
    unknown source means the reply never arrives (no-reply envelope). Ask
    the operator if the proper source IP is unknown.

    Args:
        hex: Packet hex string from a craft_* tool.
        timeout: Seconds to wait for the reply (minimum 1).
        interface: Interface to transmit/listen on; defaults to PACKET_CRAFT env (fallback enp92s0).
    """
    # Scope gate BEFORE the try (same as send_packet): a block must RAISE and
    # surface as Failed on both dispatch paths, never be caught into a string
    # the Brain relabels Success.  The reply is inbound receive — the gate
    # covers the outbound probe destination only.
    pkt = _packet_from_hex(hex)
    _ok, _reason = check_send(_packet_dst(pkt))
    if not _ok:
        raise ScopeGateError(f"scope gate: {_reason}")
    try:
        iface = interface or _default_interface()
        wait = max(1, int(timeout))
        t0 = time.monotonic()
        # Same L3/L2 split as send_packet: sr1 for bare IP/IPv6 (scapy wraps
        # the Ethernet header + routes), srp1 for frames that already carry
        # an Ether header (sendp on a bare IP packet would emit a
        # garbage-frame no-op that looks like success).
        recv_fn = sr1 if isinstance(pkt, (IP, IPv6)) else srp1
        reply = recv_fn(pkt, iface=iface, timeout=wait, verbose=False)
        elapsed = time.monotonic() - t0
        if reply is None:
            return (
                f"Sent 1 packet on {iface} ({pkt.summary()}); no reply within "
                f"{wait}s. Target may be down, filtered, or this probe type "
                f"gets no reply."
            )
        return (
            f"Sent 1 packet on {iface}: {pkt.summary()}\n"
            f"Reply after {elapsed:.2f}s: {reply.summary()}\n"
            f"reply hex: {_packet_to_hex(reply)}\n"
            f"Pass the reply hex to dissect_packet (full breakdown) or "
            f"modify_packet (to craft a follow-up)."
        )
    except PermissionError as e:
        return (
            f"send_and_receive_packet requires root/raw-socket capability: {e}. "
            "Run the Brain worker as root, or use craft_* + dissect_packet "
            "for offline analysis."
        )
    except Exception as e:
        return f"send_and_receive_packet error: {e}"


@framework_tool(
    "Sniff packets on an interface with an optional BPF filter. Returns a "
    "text summary of each captured packet (with its hex for dissection). "
    "Requires root.",
    next_hints=["dissect_packet with a captured hex to inspect a packet fully"],
)
def sniff_packets(filter: str = "", count: int = 10, timeout: int = 30, interface: str = ""):
    """Sniff packets and return a readable summary list.

    Args:
        filter: BPF filter string (e.g. 'tcp port 80', 'icmp').
        count: Number of packets to capture.
        timeout: Capture timeout in seconds.
        interface: Interface to capture on; defaults to PACKET_CRAFT env (fallback enp92s0).
    """
    try:
        iface = interface or _default_interface()
        pkts = _craft(iface).sniff_packets(filter=filter, count=int(count), timeout=int(timeout))
        if not pkts:
            return f"No packets captured on {iface} (filter={filter!r})."
        lines = [f"Captured {len(pkts)} packet(s) on {iface}:"]
        for i, p in enumerate(pkts, 1):
            lines.append(f"  [{i}] {p.summary()}  hex={_packet_to_hex(p)}")
        return "\n".join(lines)
    except PermissionError as e:
        return f"sniff_packets requires root/raw-socket capability: {e}."
    except Exception as e:
        return f"sniff_packets error: {e}"


@framework_tool(
    "Dissect a packet (by hex) into a full field-by-field breakdown. No root "
    "needed — pure parsing.",
)
def dissect_packet(hex: str):
    """Dissect a packet hex string into a full scapy show() breakdown.

    Args:
        hex: Packet hex string from a craft_* or sniff_packets tool.
    """
    try:
        pkt = _packet_from_hex(hex)
        show = pkt.show(dump=True)
        return f"{pkt.summary()}\n{show}"
    except Exception as e:
        return f"dissect_packet error: {e}"


@framework_tool(
    "Modify one or more fields on a crafted packet (by hex) and return the new "
    "hex. Pass fields as a JSON object mapping field names to values, e.g. "
    "{\"ttl\": 1, \"flags\": \"RA\"}. No root needed.",
    next_hints=["send_packet with the new hex", "dissect_packet to verify"],
)
def modify_packet(hex: str, fields: dict):
    """Modify fields on a packet and return the updated hex.

    Args:
        hex: Packet hex string to modify.
        fields: JSON object of field-name -> value to set on the packet.
    """
    try:
        pkt = _packet_from_hex(hex)
        # Coerce values: scapy fields are typed; str is accepted for most.
        coerced = {k: v for k, v in fields.items()}
        pkt = _craft().utils.modify_packet(pkt, **coerced)
        return _craft_result(pkt)
    except Exception as e:
        return f"modify_packet error: {e}"


@framework_tool(
    "Export a packet (by hex) as a formatted hexdump for human review. No root "
    "needed.",
)
def export_packet_hex(hex: str):
    """Return a formatted hexdump of a packet.

    Args:
        hex: Packet hex string.
    """
    try:
        pkt = _packet_from_hex(hex)
        dump = hexdump(pkt, dump=True)
        return f"{pkt.summary()}\n{dump}"
    except Exception as e:
        return f"export_packet_hex error: {e}"


@framework_tool(
    "Save a packet (by hex) to a pcap file for later analysis or evidence. No "
    "root needed.",
    next_hints=["report_finding to record the saved pcap path"],
)
def save_packet(hex: str, filename: str):
    """Save a packet to a pcap file.

    Args:
        hex: Packet hex string.
        filename: Output .pcap path.
    """
    try:
        pkt = _packet_from_hex(hex)
        scapy.wrpcap(filename, pkt)
        return f"Saved packet ({pkt.summary()}) to {filename}"
    except Exception as e:
        return f"save_packet error: {e}"


@framework_tool(
    "Load the first packet from a pcap file and return its hex + summary. No "
    "root needed.",
    next_hints=["dissect_packet with the returned hex"],
)
def load_packet(filename: str):
    """Load the first packet from a pcap file.

    Args:
        filename: .pcap path to read.
    """
    try:
        pkts = scapy.rdpcap(filename)
        if not pkts:
            return f"No packets in {filename}."
        pkt = pkts[0]
        return _craft_result(pkt)
    except Exception as e:
        return f"load_packet error: {e}"


@framework_tool(
    "Wait for a single packet matching a BPF filter on the default interface "
    "and return its hex + summary. Requires root.",
    next_hints=["dissect_packet with the returned hex"],
)
def wait_for_packet(filter: str = "", timeout: int = 30, interface: str = ""):
    """Wait for one matching packet.

    Args:
        filter: BPF filter string.
        timeout: Seconds to wait.
        interface: Interface to capture on; defaults to PACKET_CRAFT env (fallback enp92s0).
    """
    try:
        iface = interface or _default_interface()
        pkt = _craft(iface).utils.wait_for_packet(filter=filter, timeout=int(timeout), interface=iface)
        if pkt is None:
            return f"No packet matched filter={filter!r} within {timeout}s on {iface}."
        return _craft_result(pkt)
    except PermissionError as e:
        return f"wait_for_packet requires root/raw-socket capability: {e}."
    except Exception as e:
        return f"wait_for_packet error: {e}"


# ===========================================================================
# Pcap forensic lane — batch save / sniff-to-pcap / load-all / list
# ===========================================================================
#
# The single-packet save_packet / load_packet tools above are fine for
# quick one-off use, but they can't build a multi-packet capture (wrpcap
# overwrites, not appends) and load_packet returns only packet [0].  The
# four tools below close that gap, mirroring the msfvenom dropbox pattern:
#
#   pcaps/        gitignored output root (override via PCAP_DIR env)
#   save_pcap     hex list -> multi-packet .pcap in one call
#   sniff_to_pcap sniff + auto-save the whole capture to pcaps/ in one call
#   load_pcap     load ALL packets from a .pcap (paged summaries + hex)
#   list_pcaps    browse saved captures with sizes, packet counts, timestamps

import datetime
import hashlib


def _safe_pcap_name(filename: str) -> str:
    """Sanitize a user-supplied filename for the pcaps/ directory.

    Strips path separators (the file always lands in PCAP_DIR), appends .pcap
    if no extension, and rejects empty names.
    """
    name = os.path.basename(filename.strip())
    if not name:
        raise ValueError("filename is empty after sanitizing")
    if not name.lower().endswith(".pcap"):
        name += ".pcap"
    return name


@framework_tool(
    "Save multiple packets (by hex list) to a pcap file for forensic analysis "
    "or evidence. Writes a multi-packet .pcap in one call — no root needed. "
    "File lands in the pcaps/ directory (override via PCAP_DIR). Returns the "
    "absolute path, packet count, and sha256.",
    tags=["net.raw"],
    next_hints=[
        "list_pcaps to browse saved captures",
        "load_pcap to read the packets back",
        "report_finding to record the saved pcap path as evidence",
    ],
)
def save_pcap(hexes: list, filename: str = ""):
    """Save a batch of packets to a pcap file in pcaps/.

    Args:
        hexes: List of packet hex strings (from sniff_packets, craft_*,
               send_and_receive_packet replies, etc.).
        filename: Output filename (no path separators — the file always
                  lands in the PCAP_DIR). If omitted, auto-generates a
                  timestamped name. .pcap extension added if missing.
    """
    try:
        if not hexes:
            return "save_pcap: no packets to save (hexes list is empty)."
        cap = _pcap_dir()
        cap.mkdir(parents=True, exist_ok=True)
        if filename:
            name = _safe_pcap_name(filename)
        else:
            name = f"cap_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        out_path = cap / name

        packets = [_packet_from_hex(h) for h in hexes]
        scapy.wrpcap(str(out_path), packets)

        file_bytes = out_path.read_bytes()
        return (
            f"Saved {len(packets)} packet(s) to {out_path}\n"
            f"  size: {len(file_bytes)} bytes\n"
            f"  sha256: {hashlib.sha256(file_bytes).hexdigest()}\n"
            f"  packets: {len(packets)}\n"
            f"Use load_pcap('{name}') to read them back, or "
            f"dissect_packet on any packet's hex for a full breakdown."
        )
    except ValueError as e:
        return f"save_pcap error: {e}"
    except Exception as e:
        return f"save_pcap error: {e}"


@framework_tool(
    "Sniff packets on an interface and save the entire capture to a pcap file "
    "in one call. Returns a summary + the absolute pcap path for later "
    "analysis. Requires root (raw sockets). The capture auto-saves to pcaps/ "
    "(override via PCAP_DIR).",
    tags=["net.raw"],
    next_hints=[
        "load_pcap to read and page through the captured packets",
        "dissect_packet on any packet hex for a full field breakdown",
        "list_pcaps to browse all saved captures",
        "report_finding to record the saved pcap path as evidence",
    ],
)
def sniff_to_pcap(
    filter: str = "",
    count: int = 50,
    timeout: int = 60,
    interface: str = "",
    filename: str = "",
):
    """Sniff packets and save the whole capture to a pcap file.

    Args:
        filter: BPF filter string (e.g. 'tcp port 80', 'icmp', 'host 10.0.0.1').
        count: Number of packets to capture (capped at PCAP_MAX_PACKETS_PER_FILE).
        timeout: Capture timeout in seconds.
        interface: Interface to capture on; defaults to PACKET_CRAFT env (fallback enp92s0).
        filename: Output filename (no path separators — lands in PCAP_DIR).
                  If omitted, auto-generates a timestamped name.
    """
    try:
        iface = interface or _default_interface()
        max_pkts = _pcap_max_packets()
        cap_count = min(int(count), max_pkts)
        pkts = _craft(iface).sniff_packets(
            filter=filter, count=cap_count, timeout=int(timeout)
        )
        if not pkts:
            return (
                f"No packets captured on {iface} (filter={filter!r}). "
                f"No pcap file written."
            )

        cap = _pcap_dir()
        cap.mkdir(parents=True, exist_ok=True)
        if filename:
            name = _safe_pcap_name(filename)
        else:
            name = f"cap_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        out_path = cap / name

        scapy.wrpcap(str(out_path), pkts)
        file_bytes = out_path.read_bytes()

        lines = [
            f"Captured and saved {len(pkts)} packet(s) to {out_path}",
            f"  interface: {iface}",
            f"  filter: {filter!r}",
            f"  size: {len(file_bytes)} bytes",
            f"  sha256: {hashlib.sha256(file_bytes).hexdigest()}",
            f"  packets: {len(pkts)}",
            f"",
            f"Packet summaries (first {min(len(pkts), 20)}):",
        ]
        for i, p in enumerate(pkts[:20], 1):
            lines.append(f"  [{i}] {p.summary()}  hex={_packet_to_hex(p)}")
        if len(pkts) > 20:
            lines.append(f"  ... ({len(pkts) - 20} more — use load_pcap to page through)")
        lines.append(
            f"\nUse load_pcap('{name}') to page through all packets, "
            f"or dissect_packet on any hex for a full breakdown."
        )
        return "\n".join(lines)
    except PermissionError as e:
        return f"sniff_to_pcap requires root/raw-socket capability: {e}."
    except ValueError as e:
        return f"sniff_to_pcap error: {e}"
    except Exception as e:
        return f"sniff_to_pcap error: {e}"


@framework_tool(
    "Load ALL packets from a pcap file and return paged summaries with hex. "
    "No root needed — pure file parsing. Use offset/limit to page through "
    "large captures. Returns packet count, page range, and per-packet hex "
    "for dissect_packet.",
    tags=["net.raw"],
    next_hints=[
        "dissect_packet with any returned hex for a full field breakdown",
        "list_pcaps to browse other saved captures",
    ],
)
def load_pcap(filename: str, offset: int = 0, limit: int = 50):
    """Load packets from a pcap file with pagination.

    Args:
        filename: .pcap path. A bare name (no path separators) is resolved
                  against the PCAP_DIR (e.g. 'cap_20260101_120000.pcap').
                  An absolute or relative path with separators is used as-is.
        limit: Maximum number of packets to return per page (default 50).
        offset: Zero-based packet index to start from (default 0).
    """
    try:
        # Resolve path: bare name -> PCAP_DIR; has separators -> as-is
        if os.path.sep in filename or "/" in filename:
            fpath = Path(filename)
        else:
            fpath = _pcap_dir() / filename

        if not fpath.exists():
            return f"load_pcap: file not found: {fpath}"

        # Size guard to avoid blowing up the Brain wire frame
        max_mb = _pcap_max_file_mb()
        file_size = fpath.stat().st_size
        if file_size > max_mb * 1024 * 1024:
            return (
                f"load_pcap: {fpath.name} is {file_size / 1024 / 1024:.1f} MiB "
                f"(cap is {max_mb} MiB). Use tcpdump/tshark directly or raise "
                f"PCAP_MAX_FILE_MB."
            )

        pkts = scapy.rdpcap(str(fpath))
        total = len(pkts)
        if total == 0:
            return f"No packets in {fpath}."

        off = max(0, int(offset))
        lim = max(1, int(limit))
        page = pkts[off : off + lim]

        lines = [
            f"Loaded {total} packet(s) from {fpath.name} "
            f"(showing {off}–{off + len(page) - 1} of {total}):",
            f"  size: {file_size} bytes",
            f"",
        ]
        for i, p in enumerate(page, off + 1):
            lines.append(f"  [{i}] {p.summary()}  hex={_packet_to_hex(p)}")

        if off + len(page) < total:
            next_off = off + len(page)
            lines.append(
                f"\n  ... {total - next_off} more — "
                f"load_pcap('{fpath.name}', offset={next_off}, limit={lim}) "
                f"for the next page."
            )
        else:
            lines.append(f"\n  End of capture ({total} packets total).")
        lines.append(
            f"Use dissect_packet with any hex above for a full field breakdown."
        )
        return "\n".join(lines)
    except Exception as e:
        return f"load_pcap error: {e}"


@framework_tool(
    "List saved pcap captures in the pcaps/ directory with file sizes, packet "
    "counts, and timestamps. No root needed. Browse forensic captures and "
    "recover pcap paths from earlier turns.",
    tags=["net.raw"],
    next_hints=[
        "load_pcap to read and page through a capture",
        "dissect_packet on any packet hex for a full breakdown",
    ],
)
def list_pcaps():
    """List pcap files in the PCAP_DIR with metadata."""
    try:
        cap = _pcap_dir()
        cap.mkdir(parents=True, exist_ok=True)
        # Filter out .gitkeep and README.md
        pcap_files = sorted(
            (p for p in cap.iterdir()
             if p.is_file() and p.name.lower().endswith(".pcap")),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if not pcap_files:
            return (
                f"No pcap files in {cap}. Use sniff_to_pcap or save_pcap to "
                f"create one."
            )

        lines = [f"Pcap captures in {cap} ({len(pcap_files)} file(s)):", ""]
        for p in pcap_files:
            st = p.stat()
            size = st.st_size
            mtime = datetime.datetime.fromtimestamp(
                st.st_mtime
            ).strftime("%Y-%m-%d %H:%M:%S")
            # Try to get packet count without loading the full file into
            # memory — rdpcap is lazy (it reads the index), so this is cheap.
            try:
                pkts = scapy.rdpcap(str(p))
                pkt_count = len(pkts)
            except Exception:
                pkt_count = "?"

            if size < 1024:
                size_str = f"{size} B"
            elif size < 1024 * 1024:
                size_str = f"{size / 1024:.1f} KiB"
            else:
                size_str = f"{size / 1024 / 1024:.1f} MiB"

            lines.append(
                f"  {p.name}  {size_str}  {pkt_count} pkts  {mtime}"
            )

        lines.append(
            f"\nUse load_pcap('<name>.pcap') to page through packets, "
            f"or dissect_packet on any hex for a full breakdown."
        )
        return "\n".join(lines)
    except Exception as e:
        return f"list_pcaps error: {e}"
