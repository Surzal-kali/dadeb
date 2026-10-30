#!/usr/bin/env python3
"""Minimal wire-compat smoke test for the Rust Brain (milestone 1).

Speaks the SAME length-prefixed framing as listeners/thebrain.py
(pack_message/read_message): a 4-byte big-endian length header + payload.
Connects to the Unix socket, sends one event, prints the framed reply.

Usage:  python3 smoke.py [socket_path]
"""
import socket
import struct
import sys

SOCK = sys.argv[1] if len(sys.argv) > 1 else "run/brain.sock"


def pack(payload: bytes) -> bytes:
    return struct.pack("!I", len(payload)) + payload


def read_msg(s: socket.socket) -> bytes:
    (n,) = struct.unpack("!I", s.recv(4))
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def send(sock_path: str, message: bytes) -> str:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock_path)
    try:
        s.sendall(pack(message))
        return read_msg(s).decode(errors="replace")
    finally:
        s.close()


if __name__ == "__main__":
    for msg in (
        b'CALL_TOOL|0|nmap.scan|{"target":"10.0.0.1"}',
        b"SCAN_TOOLS|0|auxiliaries",
        b"PING|7|hello",
        b"garbage-no-pipes",
    ):
        reply = send(SOCK, msg)
        print(f"{msg.decode():45s} -> {reply}")
