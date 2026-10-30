#!/usr/bin/env python3
"""Minimal wire-compat smoke test for the Rust Brain.

Speaks the SAME length-prefixed framing as listeners/thebrain.py
(pack_message/read_message): a 4-byte big-endian length header + payload.
Connects to the brain's Unix socket, sends one event per connection, prints the
framed reply.

Milestone 2: the brain forwards tool events to the Python worker, so with both
the brain and worker.py running, demo.* calls return real execution envelopes.

Usage:  python3 smoke.py [brain_socket_path]
        (use the path the brain printed after 'listening on')
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
        b"CALL_TOOL|0|demo.add|[2,3]",              # -> result 5
        b'CALL_TOOL|0|demo.echo|{"hi":"there"}',    # -> kwargs echoed
        b"CALL_TOOL|0|demo.sysinfo",                # -> worker pid + python version
        b"SCAN_TOOLS|0|",                           # -> SCAN_COMPLETE|demo...
        b"CALL_TOOL|0|nope.notatool",               # -> not-found envelope
        b"garbage-no-pipes",                        # -> rejected by the brain
    ):
        reply = send(SOCK, msg)
        print(f"{msg.decode():42s} -> {reply}")
