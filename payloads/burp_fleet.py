"""Burp fleet twins — worker-queue adapter (Phase 3 annex).

The interactive ``burp_*`` tools stay the lane for single request/response
work; these twins exist for the workload shape that hurts next: replaying
MANY captured requests without burning the turn budget on N sequential
MCP calls, with content-keyed dedupe so the same request bytes never run
twice (finished runs come back as finished-duplicates pointing at the
completed job).

Measured constraints (2026-10-30, live lane) that shape this adapter:

- The MCP BApp exposes 24 request-crafting tools and NO scan surface —
  there is no ``start_active_scan``. Active scanning stays ZAP's job.
- ONE Burp JVM is already running (measured VmHWM ~961 MiB essentially
  idle). It is SHARED INFRA, not a per-unit spawn: a unit's queue claim
  is the child worker's RAM (default 128 MiB), not the JVM's — claiming
  the JVM's footprint per unit would double-count a long-lived consumer
  on every admission. The JVM's live RSS/VmHWM is reported by the status
  lens instead, so the operator watches the real consumer.

Unit anatomy: each unit = manifest JSON (request text embedded, host/
port/https/retries) + a child python worker (`burp_worker.py`) that
replays it through the MCP lane per attempt, writing structured
``BURP-RETRY``/``BURP-VERDICT`` lines into its job log. The queue keys
on the manifest BYTES (content_key("burp", manifest)) — identical
request + same target + same retries is one unit wherever the file
lives; changing anything re-keys honestly. Re-running a finished unit
returns the finished-duplicate envelope (same bytes ran already); copy
or edit the request file for a genuinely new unit. Manifests embed the
RAW request (its Cookie/Authorization headers included), so they are
written 0600 under a 0700 dir and age out on an mtime TTL window
(``BURP_FLEET_UNIT_TTL_HOURS``, default 48h, 0 disables) — GC runs
anchored at the manifest-write path; a re-request deterministically
rewrites an aged-out manifest.

Scope gate: per unit, BEFORE admission — the request's Host header is
checked with the operator-armed gate (same as the interactive lane).
Replay without an armed scope is refused.
"""

from __future__ import annotations
import logging

import hashlib
import json
import os
import re
import secrets
import sys
import threading
import time
from pathlib import Path
from typing import Any

from constants import framework_tool, resolve_workspace_root
from utils.worker_queue import content_key, get_worker_queue

# Per-unit memory budget (MiB) — the CHILD worker's claim (a python
# child + one parsed response at a time), NOT the JVM's footprint.
_BURP_FLEET_BUDGET_DEFAULT = 128
_BURP_FLEET_BUDGET_CAP = 1024

_UNIT_DIR = "run/burp_fleet/units"

# Manifest GC (2026-10-31): unit manifests embed the RAW captured request
# (Cookie/Authorization headers included) — sensitive material sitting in
# world-readable 0644 files under run/, never deleted. Two fixes, both
# anchored at the manifest-write path:
# - restrictive perms: dir 0700, files 0600 (scratch-store convention);
#   pre-existing legacy 0644 files are chmod'd on their next idempotent
#   rewrite of the same content.
# - mtime-based GC on a BURP_FLEET_UNIT_TTL_HOURS window (default 48h,
#   0 disables; BG_LOG_GC precedent) — manifests are byte-deterministic,
#   so a re-request deterministically rewrites the aged-out file. The GC
#   pass is throttled by BURP_FLEET_UNIT_GC_INTERVAL_S (default 30 min)
#   at module level like the job store's log GC.
_BURP_UNIT_TTL_HOURS_DEFAULT = 48.0
_BURP_UNIT_GC_INTERVAL_DEFAULT = 1800.0
_MANIFEST_GC_LAST = 0.0
_MANIFEST_GC_LOCK = threading.Lock()


def _unit_dir() -> Path:
    override = os.getenv("BURP_FLEET_UNIT_DIR", "").strip()
    if override:
        return Path(override)
    return resolve_workspace_root() / _UNIT_DIR


def _unit_ttl_hours() -> float:
    raw = os.getenv("BURP_FLEET_UNIT_TTL_HOURS", "").strip()
    return float(raw) if raw else _BURP_UNIT_TTL_HOURS_DEFAULT


def _unit_gc_interval() -> float:
    raw = os.getenv("BURP_FLEET_UNIT_GC_INTERVAL_S", "").strip()
    return float(raw) if raw else _BURP_UNIT_GC_INTERVAL_DEFAULT


def _gc_manifests(base: Path, force: bool = False) -> int:
    """Delete unit manifests older than the TTL window (mtime-based).
    Throttled at module level; errors never break the write path.
    Returns the number of files removed (0 when the window or the
    throttle suppresses the pass)."""
    global _MANIFEST_GC_LAST
    window = _unit_ttl_hours()
    if window <= 0:
        return 0
    now = time.time()
    if not force:
        with _MANIFEST_GC_LOCK:
            if now - _MANIFEST_GC_LAST < _unit_gc_interval():
                return 0
            _MANIFEST_GC_LAST = now
    cutoff = now - window * 3600
    removed = 0
    try:
        for candidate in base.glob("*.json"):
            try:
                if candidate.stat().st_mtime < cutoff:
                    candidate.unlink()
                    removed += 1
            except OSError:
                continue
    except OSError:
        pass
    return removed


def _worker_path() -> Path:
    """Fleet worker script (env override exists for stubbed tests)."""
    override = os.getenv("BURP_WORKER_PY", "").strip()
    if override:
        return Path(override)
    return Path(__file__).resolve().parent / "burp_worker.py"


def _burp_jvm_pressure() -> dict[str, Any]:
    """Live footprint of the shared Burp JVM, for the status lens. Never
    claimed into the queue — this is what the JVM ALREADY costs, not a
    per-unit spawn."""
    pid_raw = os.getenv("BURP_JVM_PID", "").strip()
    pid = int(pid_raw) if pid_raw.isdigit() else _find_burp_pid()
    if not pid:
        return {
            "available": False,
            "pid": None,
            "hint": "no java process carrying burpsuite.jar found; set BURP_JVM_PID",
        }
    stats: dict[str, Any] = {"available": True, "pid": pid}
    try:
        with open(f"/proc/{pid}/status", encoding="ascii") as fh:
            for line in fh:
                if line.startswith(("VmRSS:", "VmHWM:")):
                    kib = int(line.split()[1])
                    stats["rss_mib" if line.startswith("VmRSS") else "peak_rss_mib"] = \
                        round(kib / 1024.0, 1)
    except OSError:
        stats["available"] = False
    return stats


def _find_burp_pid() -> int | None:
    """Cheap /proc cmdline walk (a few hundred pids) — no pgrep dep."""
    for proc_dir in Path("/proc").iterdir():
        if not proc_dir.name.isdigit():
            continue
        try:
            cmdline = (proc_dir / "cmdline").read_bytes().split(b"\0")
            if any(b"burpsuite.jar" in a for a in cmdline):
                return int(proc_dir.name)
        except OSError:
            continue
    return None


def _make_manifest(request_path: Path, host: str, port: int, https: bool,
                   retries: int) -> Path:
    """Write the unit manifest: request CONTENT embedded (not referenced
    by path, so identical request bytes at different filenames produce
    byte-identical manifests — the content-key doctrine holds), plus the
    target + retries that define unit meaning. Deterministically named
    from its own sha256, so a re-request idempotently rewrites it.

    Sensitive by construction (the raw request carries its headers —
    Cookies, Authorization) — the dir is 0700 and the file 0600 (scratch-
    store convention; legacy 0644 files are chmod'd here too), and old
    manifests age out on a TTL window (see _gc_manifests)."""
    raw = request_path.read_text(encoding="utf-8", errors="replace")
    manifest = {
        "v": 1,
        "request": raw,
        "host": host,
        "port": int(port),
        "https": bool(https),
        "retries": int(retries),
    }
    blob = json.dumps(manifest, sort_keys=True).encode("utf-8")
    base = _unit_dir()
    base.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(base, 0o700)
    except OSError:
        pass
    path = base / f"{hashlib.sha256(blob).hexdigest()[:12]}.json"
    if not path.exists():
        path.write_bytes(blob)
    try:
        # Normalize perms even for the idempotent skip (legacy 0644 files
        # heal here without a re-index or a purge).
        os.chmod(path, 0o600)
    except OSError:
        pass
    _gc_manifests(base)
    return path


def _resolve_requests(spec: str) -> list[dict[str, Any]]:
    """Resolve a comma/newline-separated requests list against the burp
    drop folder (bare names) or absolute paths — the apk/ convention.
    ``BURP_DROP_DIR`` relocates the folder (read-only workspace lanes)."""
    override = os.getenv("BURP_DROP_DIR", "").strip()
    drop = Path(override) if override else (resolve_workspace_root() / "burp")
    out: list[dict[str, Any]] = []
    for raw_token in spec.replace("\n", ",").split(","):
        token = (raw_token or "").strip()
        if not token:
            continue
        path = Path(token)
        if not path.is_absolute():
            path = drop / token
        if path.is_file():
            out.append({"spec": token, "path": path.resolve(), "error": None})
        else:
            out.append({"spec": token, "path": None,
                        "error": f"not found (drop folder: {drop})"})
    return out


def _mcp_ready() -> tuple[bool, str]:
    """Is the Burp BApp MCP lane actually up? (monkeypatched in tests)"""
    from auxiliaries.burp_mcp import BurpMCPClient

    try:
        return BurpMCPClient.get_instance().healthcheck(), ""
    except Exception as e:
        return False, f"burp MCP transport error: {e}"


def _parse_burp_verdict(log_text: str) -> dict[str, Any]:
    """Verdict from the worker's structured log lines. Conservative:
    counts only self-reported BURP-RETRY outcomes; never invents a
    response code."""
    m = re.search(r"^BURP-VERDICT json=(\{.*\})\s*$", log_text, re.MULTILINE)
    if m:
        try:
            v = json.loads(m.group(1))
            attempts = int(v.get("attempts") or 0)
            ok = int(v.get("ok") or 0)
            aborted = v.get("aborted")
            if aborted:
                verdict = f"aborted: {aborted}"
            elif attempts and ok == attempts:
                codes = v.get("status_codes") or []
                verdict = f"replayed {ok}/{attempts} (codes: {codes})"
            else:
                verdict = f"replayed {ok}/{attempts} with errors"
            return {"attempts": attempts, "ok": ok, "aborted": aborted,
                    "verdict": verdict}
        except (json.JSONDecodeError, TypeError, ValueError):
            pass
    retries = re.findall(r"^BURP-RETRY ", log_text, re.MULTILINE)
    if retries:
        n = len(retries)
        return {"attempts": n, "ok": None,
                "verdict": f"{n} attempt line(s), no verdict line"}
    return {"attempts": None, "ok": None, "verdict": None}


def _register_parser() -> None:
    from utils.background_job import register_verdict_parser

    register_verdict_parser("burp", _parse_burp_verdict)


@framework_tool(
    "BATCH-replay RAW HTTP request files through the live Burp MCP BApp in "
    "the background: one worker-queue unit per request (content-deduped), "
    "each unit a child worker that sends the request verbatim retries times "
    "via Burp (send_http1_request) and logs structured BURP-RETRY/BURP-VERDICT "
    "lines. Scope-gated per request Host BEFORE admission. NOT a scanner — "
    "the BApp has no active-scan surface; scanning stays ZAP's job. Units "
    "claim only the child's RAM (default 128 MiB); the shared Burp JVM is "
    "reported by burp_replay_status, not claimed.",
    tags=["recon.web", "web.fuzz"],
    next_hints=["burp_replay_status"],
)
def burp_replay_fleet(
    requests: str,
    host: str = "",
    port: int = 80,
    https: bool = False,
    retries: int = 1,
    memory_budget: int = _BURP_FLEET_BUDGET_DEFAULT,
) -> dict[str, Any]:
    """Queue one replay unit per raw request file.

    Args:
        requests: Comma/newline-separated raw request file names or paths;
            bare names resolve against the burp drop folder (workspace
            root /burp/, same convention as apk/). Each file is ONE raw
            HTTP request (with a Host: header — the BApp normalizes CRLF).
        host: Network target hostname. Default: parsed from each request's
            Host: header (absolute-form request targets also work).
        port: Network target TCP port (default 80).
        https: True = the network connection is TLS (443/8443 etc.).
        retries: Replay each request this many times verbatim (1-64;
            capped). Changing retries changes unit meaning — a new
            content key, not a dedupe hit.
        memory_budget: The CHILD worker's claim in MiB (default 128, hard
            ceiling 1024). The shared JVM's footprint is NOT claimed per
            unit; watch it on burp_replay_status.

    Returns per-unit decisions (launched/queued/duplicate/blocked/refused)
    bound by one fleet_id; poll with burp_replay_status.
    """
    if not requests or not requests.strip():
        return {"status": "error", "error": "no requests given"}
    try:
        port = int(port)
    except (TypeError, ValueError):
        return {"status": "error", "error": f"port must be an integer, got {port!r}"}
    if not (0 < port < 65536):
        return {"status": "error", "error": f"port {port} out of range"}
    try:
        retries = int(retries)
    except (TypeError, ValueError):
        return {"status": "error", "error": f"retries must be an integer, got {retries!r}"}
    retries = max(1, min(64, retries))
    try:
        memory_budget = int(memory_budget)
    except (TypeError, ValueError):
        return {"status": "error", "error": f"memory_budget must be an integer MiB, got {memory_budget!r}"}
    if memory_budget <= 0:
        return {"status": "error", "error": "memory_budget must be positive"}
    if memory_budget > _BURP_FLEET_BUDGET_CAP:
        return {
            "status": "error",
            "error": (
                f"memory_budget {memory_budget} MiB exceeds the ceiling "
                f"{_BURP_FLEET_BUDGET_CAP} MiB — a unit's child never "
                "grows that large; the JVM's footprint is the lens' job"
            ),
        }

    ready, ready_error = _mcp_ready()
    if not ready:
        return {
            "status": "error",
            "error": (
                f"burp MCP lane not available: {ready_error or 'healthcheck failed'}. "
                "Start Burp with the MCP Server BApp enabled "
                "(127.0.0.1:9876 default; BURP_MCP_HOST/PORT override)."
            ),
        }

    resolved = _resolve_requests(requests)
    if not resolved:
        return {"status": "error", "error": "no requests in the list"}

    from auxiliaries.burp_mcp import _host_from_raw_request
    from utils.scope_gate import check_scan

    queue = get_worker_queue()
    from utils.agent_identity import current_agent_id

    agent_id = current_agent_id()
    batch_id = f"burpfleet:{secrets.token_hex(6)}"
    worker = _worker_path()
    units: list[dict[str, Any]] = []
    scope_blocks: list[str] = []

    for row in resolved:
        if row["path"] is None:
            units.append({
                "target": row["spec"],
                "decision": "refused",
                "reason": "input_not_found",
                "message": row["error"],
            })
            continue
        try:
            raw = row["path"].read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            units.append({
                "target": row["spec"], "decision": "refused",
                "reason": "unreadable", "message": str(e),
            })
            continue
        unit_host = (host or "").strip() or _host_from_raw_request(raw) or ""
        if not unit_host:
            units.append({
                "target": row["spec"], "decision": "refused",
                "reason": "no_target_host",
                "message": "no Host: header — pass host= explicitly",
            })
            continue
        ok, reason = check_scan(unit_host)
        if not ok:
            scope_blocks.append(f"{row['spec']} ({unit_host}): {reason}")
            units.append({
                "target": row["spec"], "decision": "blocked",
                "host": unit_host, "reason": reason,
            })
            continue
        manifest = _make_manifest(row["path"], unit_host, port, https, retries)
        argv = [sys.executable, str(worker), "--manifest", str(manifest)]
        decision = queue.request_unit(
            "burp",
            str(manifest),
            agent_id=agent_id,
            memory_budget=memory_budget,
            command=argv,
            note=batch_id,
        )
        entry: dict[str, Any] = {
            "target": row["spec"],
            "host": unit_host,
            "manifest": str(manifest),
            "decision": decision["decision"],
            "unit_key": decision.get("unit_key"),
            "memory_budget": memory_budget,
        }
        if decision["decision"] == "launched":
            entry["job_id"] = decision.get("job_id")
        elif decision["decision"] == "duplicate":
            entry["state"] = decision.get("state")
            if decision.get("job_id"):
                entry["job_id"] = decision["job_id"]
            if decision.get("position") is not None:
                entry["position"] = decision["position"]
        elif decision["decision"] == "queued":
            entry["position"] = decision.get("position")
        elif decision["decision"] == "refused":
            entry["reason"] = decision.get("reason")
            entry["message"] = decision.get("message")
        units.append(entry)

    counts: dict[str, int] = {}
    for u in units:
        counts[u["decision"]] = counts.get(u["decision"], 0) + 1
    acct = queue.account()
    return {
        "status": "ok" if counts.get("launched") or counts.get("queued") or counts.get("duplicate") else "nothing-to-do",
        "fleet_id": batch_id,
        "requested": len(resolved),
        "decision_counts": counts,
        "scope_blocked": scope_blocks,
        "units": units,
        "pool": {
            "slots": acct["slots"],
            "free_ram_mib": acct["free_ram_mib"],
            "ram_floor_mib": acct["ram_floor_mib"],
            "budget_capacity_mib": acct["budget_capacity_mib"],
        },
        "burp_jvm": _burp_jvm_pressure(),
        "message": (
            f"{counts.get('launched', 0)} launched, {counts.get('queued', 0)} "
            f"queued, {counts.get('duplicate', 0)} deduped, "
            f"{counts.get('blocked', 0)} scope-blocked. Poll "
            f"burp_replay_status('{batch_id}') once to confirm launch."
        ),
        "next_hints": ["burp_replay_status"],
    }


@framework_tool(
    "Poll a Burp replay fleet: per-unit running/done/verdict state across "
    "the batch (verdicts come from the workers' BURP-VERDICT log lines), "
    "plus the shared Burp JVM's live footprint (reported; not claimed). "
    "Piggybacks the queue sweep so finished slots free on this call.",
    tags=["recon.web", "infra"],
    next_hints=["burp_replay_stop"],
)
def burp_replay_status(fleet_id: str) -> dict[str, Any]:
    """Status of every unit in one replay fleet batch.

    Args:
        fleet_id: The ``fleet_id`` returned by ``burp_replay_fleet``.
    """
    queue = get_worker_queue()
    rows = queue.units_by_note(fleet_id)
    if not rows:
        return {
            "status": "unknown",
            "fleet_id": fleet_id,
            "error": (
                f"no live units carry batch {fleet_id!r} — either unknown, "
                "completed-and-aged-out, or already stopped"
            ),
        }
    from utils.job_store import get_store

    out: dict[str, Any] = {
        "status": "ok",
        "fleet_id": fleet_id,
        "units": [],
        "counts": {},
        "burp_jvm": _burp_jvm_pressure(),
    }
    counts: dict[str, int] = {}
    for r in rows:
        poll = queue.poll_unit(r["unit_key"])
        state = poll.get("status", "unknown")
        counts[state] = counts.get(state, 0) + 1
        entry: dict[str, Any] = {
            "unit_key": r["unit_key"],
            "manifest": r["target"],
            "status": state,
            "memory_budget": r["memory_budget"],
        }
        if state in ("running", "done", "launching"):
            entry["job_id"] = poll.get("job_id")
            entry["log_file"] = poll.get("log_file")
            if poll.get("recent_lines"):
                entry["recent_lines"] = poll["recent_lines"]
        elif state == "finished" and r["job_id"]:
            # Poll_unit's finished branch has dropped the job handle; the
            # completed job's log stays retrievable via that job_id.
            entry["job_id"] = r["job_id"]
            entry["message"] = (
                f"completed (job {r['job_id']}) — its log is retrievable "
                "via the job's poll envelope"
            )
        if state == "queued":
            entry["position"] = poll.get("position")
        if state in ("done", "finished") and r["target"].endswith(".json"):
            # Display the unit's meaning (the manifest is on disk until
            # swept). finished rows arrive here because the release sweep
            # settles a done unit before this status read — the manifest
            # decoration must not vanish on the terminal transition.
            try:
                man = json.loads(Path(r["target"]).read_text(encoding="utf-8"))
                entry["host"] = man.get("host")
                entry["port"] = man.get("port")
                entry["retries"] = man.get("retries")
                first = (man.get("request") or "").strip().splitlines()
                if first:
                    entry["request_line"] = first[0][:120]
            except Exception:
                logging.getLogger(__name__).debug(
                    "swallowed exception in burp_replay_status", exc_info=True)
            recent = poll.get("recent_lines") or []
            verdict = _parse_burp_verdict("\n".join(str(x) for x in recent))
            if verdict.get("verdict"):
                entry["verdict"] = verdict
        if poll.get("peak_rss_mib"):
            entry["peak_rss_mib"] = poll["peak_rss_mib"]
        out["units"].append(entry)
    adv = queue.advance_queue()
    acct = queue.account()
    out["pool"] = {
        "slots": acct["slots"],
        "running_claims_mib": acct["running_claims_mib"],
        "free_ram_mib": acct["free_ram_mib"],
        "ram_floor_mib": acct["ram_floor_mib"],
    }
    out["counts"] = counts
    running = counts.get("running", 0) + counts.get("launching", 0)
    queued = counts.get("queued", 0)
    if running == 0 and queued == 0:
        out["message"] = (
            f"all units settled ({counts.get('finished', 0) + counts.get('done', 0)} "
            f"finished, {counts.get('cancelled', 0)} cancelled) — read verdicts "
            "above; replay-again needs NEW request bytes (different content key)"
        )
    else:
        out["message"] = (
            f"{running} running/launching, {queued} queued. Poll again only "
            "when the user requests an update."
        )
    return out


@framework_tool(
    "Stop one or every running/queued unit of a Burp replay fleet batch "
    "(same-agent ownership; force=True is the operator-level cross-agent "
    "override). Running child workers are terminated via the job store; "
    "queued units are cancelled.",
    tags=["recon.web", "infra"],
)
def burp_replay_stop(fleet_id: str, force: bool = False) -> dict[str, Any]:
    """Stop a replay fleet batch's running/queued units.

    Args:
        fleet_id: The ``fleet_id`` from ``burp_replay_fleet``.
        force: Operator-level crossing of agent ownership.
    """
    queue = get_worker_queue()
    rows = queue.units_by_note(fleet_id)
    if not rows:
        return {"status": "unknown", "fleet_id": fleet_id,
                "error": f"no live units carry batch {fleet_id!r}"}
    from utils.agent_identity import current_agent_id

    caller = current_agent_id()
    stopped, cancelled, skipped, refused = [], [], [], []
    for r in rows:
        if r["status"] == "launched" and r["job_id"]:
            # Free the unit row FIRST (a stop is a release; cancelled is
            # the operator-stop state) — releasing after the job-store
            # stop races the reaper's done-observation, which would stamp
            # the killed unit 'finished'. A stop failure here stays
            # honest in `refused` — the row is already terminal and the
            # job's kill can be retried.
            released = queue.release_unit(r["unit_key"], agent_id=caller, force=force)
            if released.get("status") == "refused":
                refused.append(r["unit_key"])
                continue
            from utils.job_store import get_store

            result = get_store().stop(r["job_id"], force=force)
            if result.get("status") == "ok":
                stopped.append(r["job_id"])
            else:
                refused.append(r["unit_key"])
            continue
        if r["status"] == "queued":
            res = queue.cancel_unit(r["unit_key"], agent_id=caller, force=force)
            if res.get("status") == "cancelled":
                cancelled.append(r["unit_key"])
            elif res.get("status") == "refused":
                refused.append(r["unit_key"])
            else:
                skipped.append(r["unit_key"])
            continue
        skipped.append(r["unit_key"])
    queue.advance_queue()
    return {
        "status": "ok",
        "fleet_id": fleet_id,
        "stopped_jobs": stopped,
        "cancelled_queued": cancelled,
        "skipped": skipped,
        "refused": refused,
        "message": (
            f"{len(stopped)} job(s) terminated, {len(cancelled)} queued cancelled."
            + (f" {len(refused)} refused (ownership — pass force=True)."
               if refused else "")
        ),
    }


_register_parser()