"""Example dacustoms tool — a simple port knocker.

This is a reference for how to write a @framework_tool function in your
.dacustoms directory.  Copy it, rename it, make it yours.

Usage from the framework:
    The model discovers this as ``dacustoms.example_port_knock.knock``.
    The ``dacustoms.`` prefix stamps it as user-authored.
"""

from constants import framework_tool


@framework_tool(
    "Knock on a sequence of TCP ports on the target (port knocking). "
    "Sends a SYN to each port in order with a small delay. "
    "Useful for triggering firewalls that open a port after a knock sequence."
)
def knock(target: str, ports: str, delay: float = 0.5) -> dict:
    """Knock on a sequence of TCP ports on the target.

    Args:
        target: The target host (IP or hostname).
        ports: Comma-separated list of ports to knock (e.g. "7000,8000,9000").
        delay: Seconds between knocks (default 0.5).
    """
    import socket
    import time

    port_list = [int(p.strip()) for p in ports.split(",") if p.strip()]
    results = []
    for port in port_list:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(delay)
            s.connect_ex((target, port))
            s.close()
            results.append({"port": port, "sent": True})
        except OSError as exc:
            results.append({"port": port, "sent": False, "error": str(exc)})
        time.sleep(delay)

    return {
        "status": "ok",
        "target": target,
        "knocks": results,
    }