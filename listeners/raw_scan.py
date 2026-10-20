import os
import ctypes
from pathlib import Path

from constants import framework_tool

LIB_PATH = Path(__file__).resolve().parent / "plugins" / "raw_scan.so"

def load_lib():
    lib = ctypes.CDLL(str(LIB_PATH))
    lib.raw_syn_scan.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_uint16,
        ctypes.c_int,
    ]
    lib.raw_syn_scan.restype = ctypes.c_int
    return lib

@framework_tool("Perform a raw SYN scan on a target IP and port.")
def syn_scan(target_ip: str, port: int, source_ip: str | None = None, timeout_ms: int = 250):
    from utils.scope_gate import check_scan, ScopeGateError
    _sc_ok, _sc_reason = check_scan(target_ip)
    if not _sc_ok:
        raise ScopeGateError(f"scope gate: {_sc_reason}")
    lib = load_lib()
    if os.geteuid() != 0:
        return {
            "status": "error",
            "reason": "raw socket access requires root or CAP_NET_RAW",
            "target": target_ip,
            "port": port,
        }
    source = source_ip.encode() if source_ip else b"0.0.0.0"
    code = lib.raw_syn_scan(source, target_ip.encode(), port, timeout_ms)
    if code == 1:
        return {"status": "open", "target": target_ip, "port": port}
    if code == 0:
        return {"status": "closed_or_filtered", "target": target_ip, "port": port}
    return {"status": "error", "target": target_ip, "port": port}