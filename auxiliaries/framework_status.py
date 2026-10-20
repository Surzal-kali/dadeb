"""Framework health check tool — owns the 'health check' / 'framework status' vocabulary.

This module exists to be the rightful owner of the words 'health check',
'framework status', and 'system health' in the tool vector space.  Without
a dedicated tool carrying that vocabulary, a vague intent like 'framework
health status check' resolved to whatever sibling happened to win the
cosine tie (verified live: it ran a ZAP spider-status read).  By giving
these words a single rightful home with a distinctive, non-colliding
description, the router dispatches health intents here instead of to a
wrong sibling.

The tool probes the framework's key subsystems and returns a structured
JSON report.  It is read-only and side-effect-free — safe to call at any
point in a session to verify the harness is alive.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import time
from pathlib import Path
from typing import Any, Dict, List

from constants import framework_tool, resolve_workspace_root, brain_socket_path
from utils.snapshot_cache import get_snapshot_store


def _check_tcp(host: str, port: int, timeout: float = 2.0) -> bool:
    """TCP connect probe — True if the port accepts a connection."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def _check_unix_socket(path: str) -> bool:
    """Unix domain socket probe — True only if something is actually LISTENING.

    ``Path.is_socket()`` is a lie for stale sockets: the kernel does not unlink
    a socket file when its owner dies, so a killed sidecar leaves a file that
    passes ``is_socket()`` while every ``connect()`` bounces off it.  Probe with
    a real connection instead — mirrors bootstrap's ``_brain_ready()``.
    """
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(2.0)
            s.connect(path)
            return True
    except (FileNotFoundError, ConnectionRefusedError, socket.timeout, OSError):
        return False


@framework_tool(
    "Report the operational health of the penetration testing framework: "
    "Brain sidecar socket, Ollama LLM/embedding endpoints, ChromaDB vector "
    "store, ZAP daemon, and SQLite findings database. Returns a structured "
    "JSON report with per-subsystem up/down verdicts and the tool count "
    "in the registry. Use this to verify the harness is alive before "
    "starting an engagement or after a crash."
)
def framework_health() -> Dict[str, Any]:
    """Probe framework subsystems and return a health report.

    Checks:
    - Brain sidecar UDS socket (checkout run/brain.sock, via brain_socket_path())
    - Ollama API at the configured OLLAMA_BASE_URL
    - ChromaDB at the configured CHROMA_HOST:CHROMA_PORT
    - ZAP daemon at the configured ZAP_PORT
    - SQLite findings database at ids.db

    Returns a dict with ``overall`` (``"ok"`` / ``"degraded"``), a
    ``subsystems`` map of name -> {``up``: bool, ``detail``: str}, and
    ``tool_count`` if ChromaDB is reachable.
    """
    ollama_base = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
    # Strip /v1 for the raw API probe.
    ollama_raw = ollama_base.rstrip("/")
    if ollama_raw.endswith("/v1"):
        ollama_raw = ollama_raw[:-3]
    ollama_host = "localhost"
    ollama_port = 11434
    try:
        from urllib.parse import urlparse
        parsed = urlparse(ollama_raw)
        ollama_host = parsed.hostname or "localhost"
        ollama_port = parsed.port or 11434
    except Exception:
        pass

    chroma_host = os.getenv("CHROMA_HOST", "localhost")
    chroma_port = int(os.getenv("CHROMA_PORT", "9000"))
    zap_port = int(os.getenv("ZAP_PORT", "8090"))

    workspace = resolve_workspace_root()
    db_path = workspace / "ids.db"

    subsystems: Dict[str, Dict[str, Any]] = {}

    # Brain sidecar
    brain_sock = str(brain_socket_path())
    brain_up = _check_unix_socket(brain_sock)
    subsystems["brain_sidecar"] = {
        "up": brain_up,
        "detail": f"{brain_sock} reachable" if brain_up else "socket not found — sidecar is down",
    }

    # Ollama
    ollama_up = _check_tcp(ollama_host, ollama_port)
    subsystems["ollama"] = {
        "up": ollama_up,
        "detail": f"{ollama_host}:{ollama_port} (LLM + embedding)" if ollama_up else f"unreachable at {ollama_host}:{ollama_port}",
    }

    # ChromaDB
    chroma_up = _check_tcp(chroma_host, chroma_port)
    tool_count = None
    if chroma_up:
        try:
            import chromadb
            client = chromadb.HttpClient(host=chroma_host, port=chroma_port)
            coll = client.get_or_create_collection(
                name="tool_inventory",
                embedding_function=type("DummyEF", (), {
                    "__call__": lambda self, input: [[0.0] * 768],
                    "name": lambda self: "dummy",
                })(),
            )
            tool_count = len(coll.get(include=[]).get("ids", []))
        except Exception as exc:
            chroma_up = False
            subsystems["chromadb"] = {"up": False, "detail": f"reachable but error: {exc}"}
    subsystems.setdefault("chromadb", {
        "up": chroma_up,
        "detail": f"{chroma_host}:{chroma_port}" if chroma_up else f"unreachable at {chroma_host}:{chroma_port}",
    })
    if tool_count is not None:
        subsystems["chromadb"]["tool_count"] = tool_count

    # ZAP daemon
    zap_up = _check_tcp("127.0.0.1", zap_port)
    subsystems["zap_daemon"] = {
        "up": zap_up,
        "detail": f"127.0.0.1:{zap_port}" if zap_up else f"not listening on 127.0.0.1:{zap_port}",
    }

    # SQLite findings DB — lazily create on a fresh checkout so the health
    # probe reports it as up instead of "not found" on a new install.
    try:
        from daharness.findings import ensure_ids_db
        ensure_ids_db(str(db_path))
        db_exists = True
    except Exception:
        db_exists = False
    db_up = db_exists
    if db_exists:
        try:
            import sqlite3
            conn = sqlite3.connect(str(db_path), timeout=2.0)
            conn.execute("SELECT 1 FROM findings LIMIT 1")
            conn.close()
        except Exception as exc:
            db_up = False
            subsystems["findings_db"] = {"up": False, "detail": f"exists but error: {exc}"}
    subsystems.setdefault("findings_db", {
        "up": db_up,
        "detail": str(db_path) if db_up else f"could not create/open {db_path}",
    })

    up_count = sum(1 for v in subsystems.values() if v["up"])
    total = len(subsystems)
    overall = "ok" if up_count == total else ("degraded" if up_count > 0 else "down")

    return {
        "overall": overall,
        "subsystems_up": f"{up_count}/{total}",
        "subsystems": subsystems,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }


# ---------------------------------------------------------------------------
# framework_doctor — capability probes for the analysis/attack tooling lanes
# ---------------------------------------------------------------------------
# REA-style doctor (morluto/rea: "rea doctor --provider X"): framework_health
# answers "is the harness alive"; framework_doctor answers "can I actually
# run X".  Every probe returns {available, reason, remediation} so the
# secretary can read the same remediation when a tool later fails with the
# matching error (pdg's "run: r2pm -ci r2ghidra", masscan's raw-socket trap,
# jadx's Java requirement).

def _check_path(cmd: str) -> Dict[str, Any]:
    """PATH probe for a CLI tool, with install-string remediation."""
    import shutil
    path = shutil.which(cmd)
    if path:
        return {"available": True, "reason": path, "remediation": ""}
    return {
        "available": False,
        "reason": f"{cmd} not found on PATH",
        "remediation": f"install {cmd} (apt/dnf/pacman or upstream installer)",
    }


def _check_r2() -> Dict[str, Any]:
    """r2 binary + r2ghidra decompiler + drop folder, in one provider record."""
    r2 = _check_path("r2")
    if not r2["available"]:
        r2["remediation"] = "install radare2 (apt install radare2 / r2pm setup)"
        return r2
    try:
        from auxiliaries.radare2 import _r2ghidra_available, BINARY_TARGETS_ROOT
        plugin_ok = _r2ghidra_available()
    except Exception as exc:
        plugin_ok = False
        r2["extra"] = {"plugin_probe_error": str(exc)}
    drop_ok = os.path.isdir(BINARY_TARGETS_ROOT)
    available = plugin_ok and drop_ok
    if available:
        reason = f"r2 on PATH; r2ghidra plugin loadable; drop dir {BINARY_TARGETS_ROOT}"
    elif not plugin_ok:
        reason = "r2 on PATH but the r2ghidra decompiler plugin is missing (pdg will refuse)"
        r2["remediation"] = "run: r2pm -ci r2ghidra"
    else:
        reason = f"r2 + plugin OK but drop dir {BINARY_TARGETS_ROOT} is missing"
        r2["remediation"] = f"create {BINARY_TARGETS_ROOT} or set R2_BINARY_TARGETS_ROOT"
    return {**r2, "available": available, "reason": reason}


def _check_jadx() -> Dict[str, Any]:
    """jadx + Java runtime + apk drop folder."""
    jadx = _check_path("jadx")
    if not jadx["available"]:
        jadx["remediation"] = "install jadx (apt install jadx or the upstream release zip; needs JDK 11+)"
        return jadx
    java_ok = shutil.which("java") is not None
    apk_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "apk")
    apk_ok = os.path.isdir(apk_dir)
    if java_ok and apk_ok:
        return {**jadx, "available": True,
                "reason": f"jadx on PATH; java present; drop dir {apk_dir}"}
    if not java_ok:
        return {**jadx, "available": False,
                "reason": "jadx on PATH but no java runtime",
                "remediation": "install a JDK 11+ (apt install default-jdk)"}
    return {**jadx, "available": False,
            "reason": f"jadx + java OK but drop dir {apk_dir} is missing",
            "remediation": f"create {apk_dir} (APK targets go there)"}


def _check_masscan() -> Dict[str, Any]:
    """masscan + raw-socket capability (classic doctor-worthy runtime trap)."""
    m = _check_path("masscan")
    if not m["available"]:
        return m
    raw_ok = False
    try:
        import socket as _s
        s = _s.socket(_s.AF_INET, _s.SOCK_RAW, _s.IPPROTO_TCP)
        s.close()
        raw_ok = True
    except (PermissionError, OSError):
        raw_ok = False
    if raw_ok:
        return {**m, "available": True, "reason": "masscan on PATH; SOCK_RAW creatable"}
    return {**m, "available": False,
            "reason": "masscan on PATH but raw sockets are not permitted — masscan will fail at launch, not at probe",
            "remediation": "run under root/CAP_NET_RAW (sudo setcap cap_net_raw+ep $(which masscan))"}


def _check_msf() -> Dict[str, Any]:
    """msfconsole/msfvenom on PATH + msfrpcd RPC port answering."""
    console = _check_path("msfconsole")
    venompresent = _check_path("msfvenom")
    rpc_port = int(os.getenv("MSF_RPC_PORT", "55553"))
    rpc_up = _check_tcp("127.0.0.1", rpc_port, timeout=1.0)
    progs_ok = console["available"] and venompresent["available"]
    if progs_ok and rpc_up:
        return {"available": True,
                "reason": f"msfconsole + msfvenom on PATH; RPC answering on 127.0.0.1:{rpc_port}",
                "remediation": ""}
    if not progs_ok:
        missing = [c for c, p in (("msfconsole", console), ("msfvenom", venompresent)) if not p["available"]]
        return {"available": False,
                "reason": f"missing on PATH: {', '.join(missing)}",
                "remediation": "install the metasploit-framework package"}
    return {"available": False,
            "reason": f"msf binaries present but RPC not answering on 127.0.0.1:{rpc_port}",
            "remediation": "start the framework (python bootstrap.py) or msfrpcd manually"}


def _check_scan_tools() -> List[Dict[str, Any]]:
    """Pure-PATH probes for the scanner lane (nmap/ffuf/hydra/sqlmap)."""
    out = []
    for cmd in ("nmap", "ffuf", "hydra", "sqlmap"):
        rec = _check_path(cmd)
        rec["provider"] = cmd
        out.append(rec)
    return out


def _check_secretary_model() -> Dict[str, Any]:
    """Is SECRETARY_MODEL actually pulled on the Ollama host?"""
    model = os.getenv("SECRETARY_MODEL", "ornith-1.5:35b")
    base = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
    raw = base.rstrip("/")
    if raw.endswith("/v1"):
        raw = raw[:-3]
    try:
        import urllib.request
        with urllib.request.urlopen(f"{raw}/api/tags", timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        models = {m.get("name", "") for m in data.get("models", [])}
        if model in models or any(m.split(":")[0] == model.split(":")[0] for m in models):
            return {"available": True, "provider": "secretary_model",
                    "reason": f"{model} present on the Ollama host", "remediation": ""}
        return {"available": False, "provider": "secretary_model",
                "reason": f"{model} not found on the Ollama host",
                "remediation": f"run: ollama pull {model}"}
    except Exception as exc:
        return {"available": False, "provider": "secretary_model",
                "reason": f"Ollama API unreachable at {raw}: {exc}",
                "remediation": "start ollama or fix OLLAMA_BASE_URL"}


PROVIDER_KEYS = ("r2", "jadx", "masscan", "msf", "scanners",
                 "secretary_model", "snapshot_cache")


@framework_tool(
    "Run capability probes for the framework's analysis and attack tooling "
    "lanes (REA-style doctor): r2 + r2ghidra plugin, jadx + java, masscan + "
    "raw-socket capability, msfconsole/msfvenom + RPC port, the scanner "
    "tools (nmap/ffuf/hydra/sqlmap), the secretary model on the Ollama "
    "host, plus the snapshot cache stats. Each probe returns "
    "available/reason/remediation so a 'can I run X' question is answered "
    "before X is attempted. Pass provider to drill into one lane "
    "(r2|jadx|masscan|msf|scanners|secretary_model|snapshot_cache)."
)
def framework_doctor(provider: str = "") -> Dict[str, Any]:
    """Probe per-lane capability and return a doctor report.

    Args:
        provider: Optional single lane to probe
            (r2|jadx|masscan|msf|scanners|secretary_model).  Empty = full sweep.
    """
    p = (provider or "").strip().lower()
    providers: Dict[str, Any] = {}

    if p in ("", "r2"):
        providers["r2"] = _check_r2()
    if p in ("", "jadx"):
        providers["jadx"] = _check_jadx()
    if p in ("", "masscan"):
        providers["masscan"] = _check_masscan()
    if p in ("", "msf"):
        providers["msf"] = _check_msf()
    if p in ("", "scanners"):
        for rec in _check_scan_tools():
            providers[rec["provider"]] = rec
    if p in ("", "secretary_model"):
        providers["secretary_model"] = _check_secretary_model()
    if p in ("", "snapshot_cache"):
        snap = get_snapshot_store().stats()
        providers["snapshot_cache"] = {
            "available": not snap.get("error", False),
            "provider": "snapshot_cache",
            "reason": (
                f"{snap.get('entries', 0)} entries, {snap.get('hits', 0)} hits"
            ),
            "remediation": "",
        }

    # Contract: every record carries its own provider name (the shape tests
    # assert it, and downstream consumers format it from the record alone).
    for name, rec in providers.items():
        rec.setdefault("provider", name)

    unknown = p not in ("",) + PROVIDER_KEYS
    if unknown:
        providers["_unknown_provider"] = {
            "available": False, "provider": p,
            "reason": f"unknown provider {p!r}",
            "remediation": "pick one of: r2, jadx, masscan, msf, scanners, secretary_model",
        }

    ok = sum(1 for v in providers.values() if v.get("available"))
    return {
        "overall": "ok" if ok == len(providers) else (
            "degraded" if ok else "down"),
        "available": f"{ok}/{len(providers)}",
        "providers": providers,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
