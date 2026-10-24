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

import errno
import os
import shutil
import socket
import struct
import time
from typing import Any

from constants import framework_tool, resolve_workspace_root, brain_socket_path
from daharness.embedding import resolve_embed_url, embed_model
from utils.snapshot_cache import get_snapshot_store


def _check_tcp(host: str, port: int, timeout: float = 2.0) -> bool:
    """TCP connect probe — True if the port accepts a connection."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, TimeoutError):
        return False


def _check_unix_socket(path: str) -> tuple:
    """Unix domain socket probe — ``(up, note)``.

    ``Path.is_socket()`` is a lie for stale sockets: the kernel does not unlink
    a socket file when its owner dies, so a killed sidecar leaves a file that
    passes ``is_socket()`` while every ``connect()`` bounces off it.  Probe with
    a real connection instead — mirrors bootstrap's ``_brain_ready()``.

    ``note`` explains a ``False`` result so the caller can tell an actual
    outage from a lane that merely lacks permission to see the socket
    (operator lane vs. system-profile service user).
    """
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(2.0)
            s.connect(path)
            return True, None
    except PermissionError:
        # Socket/directory exists but this lane lacks search or connect
        # rights — the operator-lane view of a service-user-owned state root.
        return False, "permission-denied"
    except FileNotFoundError:
        return False, "not-found"
    except (ConnectionRefusedError, TimeoutError):
        return False, "stale"
    except OSError as exc:
        return False, f"error:{exc.errno or type(exc).__name__}"


def _embed_env_note() -> str:
    """Pointer for the embedding endpoint configuration.

    The harness's only live consumer of an embedding endpoint is the
    tool registry + memory lanes (daharness/embedding.py), which ride
    ``EMBED_URL`` — NOT ``OLLAMA_BASE_URL`` (that knob is the driving-LLM/
    health endpoint only and was decoupled from embeddings).  This note
    surfaces the resolved endpoint + model so the operator can tell at a
    glance whether the semantic lanes are pointing at the right place.
    """
    url = resolve_embed_url()
    model = embed_model()
    explicit = "EMBED_URL set" if os.getenv("EMBED_URL", "").strip() else "EMBED_URL unset — default"
    return f" ({explicit}; model={model}; {url})"


@framework_tool(
    "Report the operational health of the penetration testing framework: "
    "Brain sidecar socket, embedding endpoint (EMBED_URL), tool registry "
    "(SQLite vector store), ZAP daemon, and SQLite findings database. "
    "Returns a structured "
    "JSON report with per-subsystem up/down verdicts and the tool count "
    "in the registry. Use this to verify the harness is alive before "
    "starting an engagement or after a crash."
)
def framework_health() -> dict[str, Any]:
    """Probe framework subsystems and return a health report.

    Checks:
    - Brain sidecar UDS socket (checkout run/brain.sock, via brain_socket_path())
    - Embedding endpoint at the configured EMBED_URL (daharness/embedding.py)
    - Tool registry (SQLite vector store at tool_registry.db)
    - ZAP daemon at the configured ZAP_PORT
    - SQLite findings database at ids.db

    Returns a dict with ``overall`` (``"ok"`` / ``"degraded"``), a
    ``subsystems`` map of name -> {``up``: bool, ``detail``: str}, and
    ``tool_count`` if the registry DB is reachable.  Subsystems that failed only
    because this lane lacks permission to see them (operator lane looking at
    a service-user-owned state root) carry ``lane_blocked: true`` — a
    permission mismatch reported honestly, not an outage claim.
    """
    # Embedding endpoint — the harness's semantic lanes (tool registry +
    # memory) ride EMBED_URL, NOT OLLAMA_BASE_URL (that knob was decoupled
    # from embeddings and is the driving-LLM/health endpoint only).
    embed_url = resolve_embed_url()
    embed_env_note = _embed_env_note()
    embed_host = "localhost"
    embed_port = 11434
    try:
        from urllib.parse import urlparse
        _eparsed = urlparse(embed_url)
        embed_host = _eparsed.hostname or "localhost"
        # Ollama native /api/embed → 11434; OpenAI-compatible /v1/embeddings
        # → 443 (https) or 80 (http) when the port is not explicit.
        embed_port = _eparsed.port or (443 if _eparsed.scheme == "https" else 80)
    except Exception:
        pass

    zap_port = int(os.getenv("ZAP_PORT", "8090"))

    workspace = resolve_workspace_root()
    db_path = workspace / "ids.db"

    subsystems: dict[str, dict[str, Any]] = {}

    # Brain sidecar
    brain_sock = str(brain_socket_path())
    brain_up, brain_note = _check_unix_socket(brain_sock)
    if brain_up:
        brain_detail, brain_blocked = f"{brain_sock} reachable", False
    elif brain_note == "permission-denied":
        brain_blocked = True
        brain_detail = (
            f"{brain_sock} exists but this lane lacks permission to reach it — "
            "socket/directory owned by another user (system profile runs the state "
            "root as the service user). Probe via the gateway/MCP lane or as that "
            "user; this is a lane-permission mismatch, not an outage. System-profile "
            "repair: `sudo usermod -aG daharness $USER` then re-login (or `newgrp "
            "daharness`) and `ls -ld /run/daharness` (expect daharness:daharness, "
            "mode 0770)."
        )
    elif brain_note == "not-found":
        brain_detail, brain_blocked = "socket not found — sidecar is down", False
    else:
        brain_detail, brain_blocked = (
            f"{brain_sock} not accepting connections — sidecar is down or socket is stale",
            False,
        )
    brain_entry = {"up": brain_up, "detail": brain_detail}
    if brain_blocked:
        brain_entry["lane_blocked"] = True
    subsystems["brain_sidecar"] = brain_entry

    # Embedding endpoint — the harness's semantic lanes (tool registry +
    # memory) post embeddings to EMBED_URL (daharness/embedding.py).  This
    # is NOT the driving-LLM endpoint (OLLAMA_BASE_URL is external and
    # decoupled); it is the endpoint the registry and memory lanes actually
    # depend on for vector search.
    embed_up = _check_tcp(embed_host, embed_port)
    subsystems["embedding"] = {
        "up": embed_up,
        "detail": (
            f"{embed_host}:{embed_port} (embeddings){embed_env_note}"
            if embed_up
            else f"unreachable at {embed_host}:{embed_port}{embed_env_note}"
        ),
    }

    # Tool registry — SQLite-backed vector store (no server process).
    # The registry DB lives under the workspace root alongside ids.db.
    tool_count = None
    registry_up = False
    registry_db_path = None
    try:
        from daharness.registry import ToolRegistry
        registry_db_path = ToolRegistry._registry_db_path()
        if registry_db_path.exists():
            import sqlite3
            conn = sqlite3.connect(str(registry_db_path), timeout=2.0)
            row = conn.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='vs_tool_inventory'"
            ).fetchone()
            if row and row[0] > 0:
                count_row = conn.execute(
                    "SELECT COUNT(*) FROM vs_tool_inventory"
                ).fetchone()
                tool_count = int(count_row[0]) if count_row else 0
                registry_up = True
            conn.close()
        # If the DB doesn't exist yet, the registry is "down" (not indexed).
        # This is an honest state, not an error — run `daharness-index` or
        # `python -m daharness.core` to build it.
    except Exception as exc:
        registry_up = False
        subsystems["tool_registry"] = {
            "up": False,
            "detail": f"error opening registry DB: {exc}",
        }
    subsystems.setdefault("tool_registry", {
        "up": registry_up,
        "detail": (
            f"{registry_db_path} ({tool_count} tools)" if registry_up and tool_count is not None
            else str(registry_db_path) if registry_up
            else f"not indexed — run `daharness-index` or `python -m daharness.core`"
        ),
    })
    if tool_count is not None:
        subsystems["tool_registry"]["tool_count"] = tool_count

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
    except Exception as exc:
        db_exists = False
        wk_readable = os.access(str(workspace), os.R_OK) and os.access(str(workspace), os.X_OK)
        db_readable = os.path.exists(str(db_path)) and os.access(str(db_path), os.R_OK)
        if not wk_readable or (os.path.exists(str(db_path)) and not db_readable):
            # This lane can't even search the state root — the classic
            # operator-vs-service-user mismatch on the system profile, not an
            # outage. Report the permission truth instead of "could not open".
            subsystems["findings_db"] = {
                "up": False,
                "lane_blocked": True,
                "detail": (
                    f"{db_path} not readable from this lane (permission denied — state root "
                    "owned by another user, e.g. the system-profile service user). Probe via "
                    "the gateway/MCP lane or run as that user; this is a lane-permission "
                    "mismatch, not an outage. Repair: the deb shapes the state root "
                    "daharness:daharness 2770 (setgid) — verify with `ls -ld "
                    "/var/lib/daharness` and re-run provisioning if the shape differs."
                ),
            }
        else:
            # Spell out WHY the creation failed — a bare "could not
            # create/open" once masked a chromadb import error picked up
            # through daharness/__init__'s registry import chain, which is
            # nothing like a permission problem on the DB itself.
            subsystems["findings_db"] = {
                "up": False,
                "detail": f"could not create/open {db_path} ({exc})",
            }
    db_up = db_exists
    if db_exists:
        try:
            import sqlite3
            conn = sqlite3.connect(str(db_path), timeout=2.0)
            conn.execute("SELECT 1 FROM findings LIMIT 1")
            conn.close()
        except Exception as exc:
            db_up = False
            if not os.access(str(db_path), os.R_OK):
                subsystems["findings_db"] = {
                    "up": False,
                    "lane_blocked": True,
                    "detail": (
                        f"{db_path} exists but is unreadable from this lane (permission denied — "
                        "owned by another user); probe via the gateway/MCP lane or as that user. "
                        "Repair: verify group membership (`id -nG`) and the state-root shape "
                        "(`ls -ld /var/lib/daharness` — expect daharness:daharness 2770 setgid)."
                    ),
                }
            else:
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

def _check_path(cmd: str) -> dict[str, Any]:
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


def _check_r2() -> dict[str, Any]:
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


def _check_jadx() -> dict[str, Any]:
    """jadx + Java runtime + apk drop folder."""
    jadx = _check_path("jadx")
    if not jadx["available"]:
        jadx["remediation"] = "install jadx (apt install jadx or the upstream release zip; needs JDK 11+)"
        return jadx
    java_ok = shutil.which("java") is not None
    try:
        from auxiliaries.jadx import APK_TARGETS_ROOT
    except Exception as exc:
        APK_TARGETS_ROOT = None
        jadx["extra"] = {"apk_root_probe_error": str(exc)}
    apk_ok = bool(APK_TARGETS_ROOT) and os.path.isdir(APK_TARGETS_ROOT)
    if java_ok and apk_ok:
        return {**jadx, "available": True,
                "reason": f"jadx on PATH; java present; drop dir {APK_TARGETS_ROOT}"}
    if not java_ok:
        return {**jadx, "available": False,
                "reason": "jadx on PATH but no java runtime",
                "remediation": "install a JDK 11+ (apt install default-jdk)"}
    return {**jadx, "available": False,
            "reason": f"jadx + java OK but drop dir {APK_TARGETS_ROOT} is missing",
            "remediation": f"create {APK_TARGETS_ROOT} or set JADX_APK_TARGETS_ROOT"}


# run_masscan launches the masscan BINARY as a plain subprocess, so scan
# capability rides the binary (file caps) or the launching lane (root euid /
# ambient caps) — not the doctor process's own SOCK_RAW probe.  Grading the
# probe lane lied in both directions: a setcap'd binary got "may fail at
# launch" while the setcap'd launch runs fine from an unprivileged lane, and
# a privileged probe could green-light a scan lane it can't see.

# Linux security.capability xattr (uapi/linux/capability.h): little-endian
# u32s — magic_etc (revision in the top byte, VFS_CAP_FLAGS_EFFECTIVE in
# bit 0), then permitted/inheritable pairs; rev 3 appends rootid.
_CAP_XATTR_SIZES = (12, 20, 24)   # XATTR_CAPS_SZ_1/2/3
_VFS_CAP_REVISIONS = (1, 2, 3)
_CAP_NET_RAW_BIT = 13
_CAP_EFFECTIVE_FLAG = 0x000001


def _parse_cap_xattr(blob: bytes) -> dict[str, Any]:
    """Decode a security.capability blob into exec-time-relevant facts.

    A file capability reaches the effective set at exec only when the
    kernel's effective flag rides the blob — ``setcap cap_net_raw+ep``,
    not a bare ``+p`` grant (that one is stored but inert for
    unprivileged callers).
    """
    if len(blob) % 4 or len(blob) < 12:
        return {"size": len(blob),
                "decode_error": f"unexpected blob size {len(blob)}"}
    words = struct.unpack("<%dI" % (len(blob) // 4), blob)
    magic_etc = words[0]
    revision = (magic_etc >> 24) & 0xFF
    if revision not in _VFS_CAP_REVISIONS:
        return {"size": len(blob), "magic": f"0x{magic_etc:08x}",
                "decode_error": f"unrecognized revision {revision}"}
    net_raw = bool(words[1] & (1 << _CAP_NET_RAW_BIT))
    effective = bool(magic_etc & _CAP_EFFECTIVE_FLAG)
    return {"size": len(blob), "revision": revision,
            "effective_flag": effective,
            "cap_net_raw_in_permitted": net_raw,
            "cap_net_raw": net_raw and effective}


def _read_file_cap_net_raw(path: str) -> dict[str, Any]:
    """Exec-effective cap_net_raw evidence carried by the BINARY itself."""
    try:
        return _parse_cap_xattr(os.getxattr(path, "security.capability"))
    except OSError as exc:
        if exc.errno == errno.ENODATA:
            return {"decode_error": "no file capability applied (not setcap'd)"}
        return {"decode_error": f"{type(exc).__name__}: {exc}"}


def _process_raw_socket_ok() -> bool:
    """Can a subprocess launched from THIS lane open a raw socket?

    Children inherit the launching lane's effective caps, so a plain
    subprocess launch is capable whenever this process (root or ambient
    caps) can open SOCK_RAW.  When this probe is denied, the launch can
    still be capable through file capabilities on the binary — the setcap
    case this lane must not grade as broken.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.close()
        return True
    except (PermissionError, OSError):
        return False


def _masscan_launch_capability(euid: int, lane_raw: bool,
                               file_caps: dict[str, Any]) -> tuple[bool, str]:
    """Grade masscan's LAUNCH from the privilege sources the launch uses.

    Returns ``(capable, reason)``; the reason names the deciding source so
    the report never claims a launch failure the evidence doesn't support.
    """
    setcap_capable = bool(file_caps.get("cap_net_raw"))
    if setcap_capable and (lane_raw or euid == 0):
        return True, ("masscan on PATH; binary carries a setcap'd "
                      "cap_net_raw and this lane can also open SOCK_RAW")
    if setcap_capable:
        return True, ("masscan on PATH; binary carries a setcap'd "
                      "cap_net_raw — subprocess launches scan fine even "
                      "though this lane's own SOCK_RAW probe is denied "
                      "(file caps ride the binary, not the lane)")
    if lane_raw:
        return True, ("masscan on PATH; this lane can create SOCK_RAW "
                      "(launched subprocesses inherit it)")
    if euid == 0:
        return True, ("masscan on PATH; running as root (uid 0) — "
                      "raw sockets creatable")
    return False, (
        f"masscan on PATH but no raw-socket privilege on this lane: uid {euid} "
        "can't create SOCK_RAW and the binary carries no cap_net_raw file "
        "capability — a scan launched from this lane fails at launch; if "
        "scans launch from a different lane, grade that one "
        "(sudo daharness doctor)")


def _check_masscan() -> dict[str, Any]:
    """masscan + raw-socket capability, graded on the LAUNCH path.

    The old probe graded the doctor process's own SOCK_RAW attempt and
    reported "may fail at launch, not at probe" while the probe itself had
    failed — the honest question is whether a plain-subprocess ``masscan``
    launch can open a raw socket: root euid, a SOCK_RAW-capable lane, or an
    exec-effective cap_net_raw file capability on the binary.  Per-source
    evidence rides in ``extra``.
    """
    m = _check_path("masscan")
    if not m["available"]:
        return m
    path = shutil.which("masscan") or "masscan"
    euid = os.geteuid()
    lane_raw = _process_raw_socket_ok()
    file_caps = _read_file_cap_net_raw(path)
    capable, reason = _masscan_launch_capability(euid, lane_raw, file_caps)
    extra = {"euid": euid, "lane_sock_raw": lane_raw, "file_caps": file_caps}
    if capable:
        return {**m, "available": True, "reason": reason, "extra": extra}
    return {**m, "available": False, "reason": reason, "extra": extra,
            "remediation": ("sudo setcap cap_net_raw+ep $(which masscan); "
                            "or run the lane as root / grant it CAP_NET_RAW "
                            "(systemd AmbientCapabilities=CAP_NET_RAW)")}


def _check_msf() -> dict[str, Any]:
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


def _check_scan_tools() -> list[dict[str, Any]]:
    """Pure-PATH probes for the scanner lane (nmap/ffuf/hydra/sqlmap)."""
    out = []
    for cmd in ("nmap", "ffuf", "hydra", "sqlmap"):
        rec = _check_path(cmd)
        rec["provider"] = cmd
        out.append(rec)
    return out


def _check_registry() -> dict[str, Any]:
    """Tool registry — SQLite-backed vector store (no server process).

    ONE probe question: does the registry DB file exist and answer? If the
    file is missing, the registry hasn't been indexed yet. If it's present
    but unreadable, the lane lacks permission. The registry's semantic
    search / the gateway's find_best_tool / indexing all ride on this file.
    """
    rec: dict[str, Any] = {"provider": "registry", "remediation": ""}
    try:
        from daharness.registry import ToolRegistry
        db_path = ToolRegistry._registry_db_path()
    except Exception as exc:
        rec["available"] = False
        rec["reason"] = f"could not resolve registry DB path: {exc}"
        rec["remediation"] = "run from the framework root"
        return rec
    if not db_path.exists():
        rec["available"] = False
        rec["reason"] = (
            f"registry DB not found at {db_path} — the tool registry "
            f"hasn't been indexed yet"
        )
        rec["remediation"] = (
            "run `daharness-index` or `python -m daharness.core` to build "
            "the registry (needs EMBED_URL for embeddings)"
        )
        return rec
    try:
        import sqlite3
        conn = sqlite3.connect(str(db_path), timeout=2.0)
        row = conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' "
            "AND name='vs_tool_inventory'"
        ).fetchone()
        if row and row[0] > 0:
            count = conn.execute(
                "SELECT COUNT(*) FROM vs_tool_inventory"
            ).fetchone()[0]
            conn.close()
            rec["available"] = True
            rec["reason"] = f"registry DB at {db_path} ({count} tools)"
            return rec
        conn.close()
    except Exception as exc:
        rec["available"] = False
        rec["reason"] = f"registry DB exists but unreadable: {exc}"
        rec["remediation"] = "check workspace-root permissions (daharness group)"
        return rec
    rec["available"] = False
    rec["reason"] = f"registry DB at {db_path} exists but has no tool_inventory table"
    rec["remediation"] = "re-index: `daharness-index` or `python -m daharness.core`"
    return rec


def _pg_host_candidates() -> list[str]:
    """Postgres endpoints to probe, ordered — mirrors utils.engagement's
    _host_candidates so the doctor and the engagement lane resolve the
    cluster the same way. An explicit HARNESS_DB_HOST pins the single
    candidate (except the wildcard binds 0.0.0.0/::/* which name no
    client endpoint); the default order is 127.0.0.1 (host lanes hit on
    the first try) then 172.28.0.1 (the workbench-bridge gateway, how
    every published container lane reaches the host-native cluster).
    The compose-era 'postgres' service name retired 2026-10-21 with the
    compose postgres service.
    """
    explicit = os.getenv("HARNESS_DB_HOST", "").strip()
    if explicit and explicit not in ("0.0.0.0", "::", "*"):
        return [explicit]
    return ["127.0.0.1", "172.28.0.1"]


def _check_postgres() -> dict[str, Any]:
    """Engagement-cobweb Postgres lane (deb wrapper: daharness-pg, :5433).

    available = the lane port is ANSWERING (cluster up). Down states split
    into exactly one fixable story each: tooling absent (dev box), init
    never run (no pg.env), provisioned but stopped — so the remediation
    line always names the command the operator can copy verbatim
    (daharness-pg init / start), matching the wrapper's own usage text.

    Host resolution mirrors utils.engagement._host_candidates so the
    doctor sees the same cluster the engagement lane does: host lanes hit
    127.0.0.1; container lanes (jupyter/code-server) reach the
    host-native cluster through the workbench-bridge gateway
    172.28.0.1. Before this alignment the doctor hardcoded 127.0.0.1 and
    reported postgres down from every container even when the cluster
    was healthy — the last framework_doctor false-down in the stack.
    """
    import shutil
    import socket as _socket

    port = int(os.getenv("HARNESS_DB_PORT", "5433"))
    env_file = os.getenv("DAHARNESS_PG_ENV", "/etc/daharness/pg.env")
    candidates = _pg_host_candidates()
    up = False
    host = candidates[0]
    for cand in candidates:
        try:
            with _socket.create_connection((cand, port), timeout=1.0):
                up = True
                host = cand
                break
        except OSError:
            pass

    base: dict[str, Any] = {"provider": "postgres", "remediation": ""}
    if up:
        base["available"] = True
        base["reason"] = f"cluster answering on {host}:{port}"
        return base

    if not (shutil.which("psql") and shutil.which("pg_createcluster")):
        base["available"] = False
        base["reason"] = (
            "postgres tooling absent on this lane (psql/pg_createcluster "
            "not in PATH)"
        )
        base["remediation"] = (
            "deb lane: apt install postgresql && sudo daharness-pg init — "
            "dev lane: pip install -e \".[db]\" and provision a cluster "
            "whose roles/schemas match packaging/postgres/init/ "
            "(daharness-pg init is the reference implementation)"
        )
        return base

    if not os.path.exists(env_file):
        base["available"] = False
        base["reason"] = (
            f"postgres present but the lane was never initialized (no "
            f"{env_file})"
        )
        base["remediation"] = (
            "sudo daharness-pg init — provisions the dedicated 'daharness' "
            f"cluster on :{port}, mints lane roles + purge function, writes "
            f"{env_file}"
        )
        return base

    base["available"] = False
    base["reason"] = (
        f"cluster provisioned (pg.env present) but not answering on "
        f"{port} (tried {', '.join(candidates)})"
    )
    base["remediation"] = (
        "sudo daharness-pg start (init re-runs idempotently to repair)"
    )
    return base


PROVIDER_KEYS = ("r2", "jadx", "masscan", "msf", "scanners",
                 "snapshot_cache", "postgres", "registry", "customs")


def _check_customs() -> dict[str, Any]:
    """Tier-1 syntax check of operator-authored .dacustoms modules.

    Walks the customs dir with ``ast.parse`` (zero execution — a health
    probe must never import a module that opens sockets).  Reports per-file
    status so the operator sees exactly which file has a syntax error and
    on which line.  Also traces the full finder registration chain so the
    operator can tell "my module is in the wrong folder" from "the import
    machinery never wired up."
    """
    try:
        from dacustoms_finder import finder_status
        from constants import dacustoms_dir
    except Exception as exc:
        return {
            "available": False, "provider": "customs",
            "reason": f"dacustoms_finder not importable: {exc}",
            "remediation": "run from the framework root",
        }

    fst = finder_status()

    # If the finder isn't registered, report exactly why — don't fall
    # through to a misleading "dir doesn't exist" when the real reason
    # is "disabled" or "boot ordering."
    if not fst["registered"]:
        return {
            "available": False, "provider": "customs",
            "reason": fst["reason"],
            "remediation": (
                f"mkdir -p {fst['dir']} && touch {fst['dir']}/__init__.py"
                if fst["dir"] is not None
                else "check framework root is on sys.path"
            ),
            "finder_status": fst,
        }

    d = dacustoms_dir()
    if d is None:
        return {
            "available": False, "provider": "customs",
            "reason": "dacustoms lane disabled (DACUSTOMS_DIR=off)",
            "remediation": "mkdir -p ~/.dacustoms && touch ~/.dacustoms/__init__.py",
        }
    if not d.is_dir():
        return {
            "available": False, "provider": "customs",
            "reason": f"customs dir {d} does not exist",
            "remediation": f"mkdir -p {d} && touch {d}/__init__.py",
        }

    import ast
    files_checked: list[dict[str, Any]] = []
    syntax_errors: list[str] = []
    ok_count = 0

    for py in sorted(d.rglob("*.py")):
        if "__pycache__" in py.parts:
            continue
        rel = py.relative_to(d)
        try:
            source = py.read_text(errors="replace")
            ast.parse(source, filename=str(py))
            files_checked.append({"file": str(rel), "status": "ok"})
            ok_count += 1
        except SyntaxError as exc:
            detail = f"{exc.msg}"
            if exc.lineno:
                detail = f"line {exc.lineno}: {exc.msg}"
            files_checked.append({
                "file": str(rel), "status": "syntax_error",
                "line": exc.lineno, "detail": detail,
            })
            syntax_errors.append(f"{rel}:{exc.lineno} — {exc.msg}")

    init_present = (d / "__init__.py").is_file()
    if not init_present:
        syntax_errors.insert(
            0, f"__init__.py missing in {d} — the dacustoms.* prefix won't resolve"
        )

    available = init_present and not syntax_errors
    if available:
        reason = f"{ok_count} module{'s' if ok_count != 1 else ''} checked, all clean"
        remediation = ""
    else:
        reason = f"{ok_count} ok, {len(syntax_errors)} issue{'s' if len(syntax_errors) != 1 else ''}"
        remediation = "; ".join(syntax_errors)

    return {
        "available": available, "provider": "customs",
        "reason": reason,
        "remediation": remediation,
        "files": files_checked,
        "init_present": init_present,
        "dir": str(d),
    }


def _doctor_gate_error() -> str:
    """Refusal message when this lane can't honestly grade the state, else ''.

    The doctor's verdicts assume this lane sees what the service lane sees
    (the deb's /var/lib/daharness is the daharness service user's 2770
    state root). An operator lane outside the owner/group probes blind
    (dirs unreadable, stores unopenable) and reports false downs while
    ``sudo daharness doctor`` is all green — so instead of grading blind,
    the doctor refuses and names the fix. Root, the state-root owner, and
    owner-group members pass; a missing root is also allowed (the probes
    will report absence honestly instead of lying).
    """
    try:
        root = resolve_workspace_root()
        st = root.stat()
    except OSError:
        return ""
    if os.geteuid() == 0 or st.st_uid == os.geteuid() or st.st_gid in os.getgroups():
        return ""
    try:
        import grp
        gname = grp.getgrgid(st.st_gid).gr_name
    except (ImportError, KeyError):
        gname = f"gid {st.st_gid}"
    return (
        f"daharness doctor must run as root, as the owner of {root}, or as "
        f"a member of the '{gname}' group — a non-privileged lane probes "
        f"blind and reports false downs.\n"
        "  run: sudo daharness doctor\n"
        "  (shared-state alternative: sudo usermod -aG "
        f"{gname} <user>, then re-login or `newgrp {gname}`)"
    )


@framework_tool(
    "Run capability probes for the framework's analysis and attack tooling "
    "lanes (REA-style doctor): r2 + r2ghidra plugin, jadx + java, masscan + "
    "raw-socket capability, msfconsole/msfvenom + RPC port, the scanner "
    "tools (nmap/ffuf/hydra/sqlmap), the snapshot cache stats, the tool registry "
    "(SQLite vector store), the engagement-cobweb Postgres lane, and the "
    "operator-authored .dacustoms modules (tier-1 syntax check). Each probe "
    "returns available/reason/remediation so a 'can I run X' question is "
    "answered before X is attempted. Pass provider to drill into one lane "
    "(r2|jadx|masscan|msf|scanners|snapshot_cache|postgres|registry|customs). "
    "doctor refuses lanes that do not share the framework state root (root, "
    "its owner, or a member of its group) — a non-privileged lane probes "
    "blind and reports false downs, so it gets the refusal and the "
    "remediation instead of a lying report."
)
def framework_doctor(provider: str = "") -> dict[str, Any]:
    """Probe per-lane capability and return a doctor report.

    Args:
        provider: Optional single lane to probe
            (r2|jadx|masscan|msf|scanners|snapshot_cache|
            postgres|registry|customs).  Empty = full sweep.
    """
    gate = _doctor_gate_error()
    if gate:
        raise PermissionError(gate)
    p = (provider or "").strip().lower()
    providers: dict[str, Any] = {}

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
    if p in ("", "snapshot_cache"):
        try:
            snap = get_snapshot_store().stats()
        except PermissionError as exc:
            # The deb lane's state root is the daharness service user's home
            # (/var/lib/daharness, 2770). An operator lane outside the shared
            # group can neither read nor create run/ there — a lane-permission
            # mismatch, not an outage: say which, and name the fix.
            providers["snapshot_cache"] = {
                "available": False, "provider": "snapshot_cache",
                "reason": (
                    f"store not accessible on this lane (permission denied: "
                    f"{getattr(exc, 'filename', None) or 'state root'}) — the "
                    "state root is owned by the daharness service lane"
                ),
                "remediation": (
                    "sudo daharness doctor — or gain shared-state access: "
                    "sudo usermod -aG daharness <user> (re-login or "
                    "`newgrp daharness` applies it)"
                ),
            }
        except Exception as exc:
            # A doctor probe must degrade into a report, never a traceback.
            providers["snapshot_cache"] = {
                "available": False, "provider": "snapshot_cache",
                "reason": f"store unavailable on this lane: "
                          f"{type(exc).__name__}: {exc}",
                "remediation": "sudo daharness doctor",
            }
        else:
            providers["snapshot_cache"] = {
                "available": not snap.get("error", False),
                "provider": "snapshot_cache",
                "reason": (
                    f"{snap.get('entries', 0)} entries, "
                    f"{snap.get('hits', 0)} hits"
                ),
                "remediation": "",
            }
    if p in ("", "registry"):
        providers["registry"] = _check_registry()
    if p in ("", "postgres"):
        providers["postgres"] = _check_postgres()
    if p in ("", "customs"):
        providers["customs"] = _check_customs()

    # Contract: every record carries its own provider name (the shape tests
    # assert it, and downstream consumers format it from the record alone).
    for name, rec in providers.items():
        rec.setdefault("provider", name)

    unknown = p not in ("",) + PROVIDER_KEYS
    if unknown:
        providers["_unknown_provider"] = {
            "available": False, "provider": p,
            "reason": f"unknown provider {p!r}",
            "remediation": "pick one of: r2, jadx, masscan, msf, scanners, "
                           "snapshot_cache, postgres, registry, customs",
        }

    ok = sum(1 for v in providers.values() if v.get("available"))
    return {
        "overall": "ok" if ok == len(providers) else (
            "degraded" if ok else "down"),
        "available": f"{ok}/{len(providers)}",
        "providers": providers,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
