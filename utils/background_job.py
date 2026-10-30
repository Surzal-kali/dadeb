"""Shared background-job helper for long-running CLI tools -- store-backed.

Several framework tools launch external processes that can run for minutes
to tens of minutes (nmap, sqlmap, amass, gobuster).  Blocking on
``subprocess.run`` holds the entire secretary turn open for the process's
full runtime and fights the turn timeout no matter how large the budget.

This module factors out the job-launch + poll pattern that sqlmap pioneered
(see ``payloads/sqlmap.py``) into a reusable helper so nmap, amass, gobuster
and friends inherit it without each reimplementing the machinery:

- ``launch_job`` starts a ``subprocess.Popen`` (detached, stdin=/dev/null),
  records the job in the durable store (``utils/job_store.py``: SQLite
  metadata under ``run/jobs/``, agent-scoped, ONE reaper thread), and
  returns a ``job_id`` + metadata immediately.
- ``poll_job`` reads the log, checks liveness, tails recent lines, and
  returns a structured ``status: "running" | "done"`` dict.
- ``get_job`` / ``terminate_job`` are exposed for callers that need direct
  access (e.g. hash_crack's hashfile watcher needs the live Popen handle).

Phase 0 (2026-10-29): the flat process-local registry this module used to
own (``_JOBS`` dict, ``_MAX_JOBS = 64`` cap evicting only finished jobs,
one reaper THREAD per job, ``/tmp`` log sidecars, ``os.listdir`` scan per
cross-process poll) is replaced by the store. Same signatures, same
envelope keys; jobs are owned by the resolved caller identity and are
pollable from any lane (gateway/Brain/REPL) because state is on disk.

Callers that want tool-specific verdict parsing (sqlmap's injectable
detection, nmap's open-port extraction) pass a ``verdict_parser``
callable to ``launch_job``; parsers register per tool on the store and
are applied by polls in THIS process (closures don't survive a restart —
same as pre-v2). Tools that don't need a verdict simply omit it.
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Optional
from collections.abc import Callable

from utils.job_store import (
    JobStore,
    current_agent_id,
    get_store,
    reset_store,
)

# Legacy log-dir fallback, read PER CALL. $BG_JOB_LOG_DIR is honored by
# launch_job as an explicit per-call override (tests set it; the a1fae22
# import-time-capture regression is why this is never cached at import).
# The store's DEFAULT log location is run/jobs/<tool>/ — never /tmp.
_LOG_DIR_FALLBACK = "/tmp"


def _log_dir() -> str:
    """Return the log dir per call: $BG_JOB_LOG_DIR when set, else /tmp."""
    return os.getenv("BG_JOB_LOG_DIR", "").strip() or _LOG_DIR_FALLBACK


# Verdict-parser registration rides the store (utils/job_store.py): tool
# modules register log-text parsers at import time, keyed by tool name,
# so jobs launched in one process get parsed verdicts in THIS process
# (parsers are closures — they don't survive a restart, same as pre-v2).


def register_verdict_parser(tool_name: str, parser: Callable[[str], dict[str, Any]]) -> None:
    """Register a verdict parser for a tool used by ``poll_job``.

    Called by tool modules at import time (module-level, after the parser
    function is defined). The Brain's startup scan imports those modules,
    so parsers are registered before any ``CALL_TOOL`` can arrive.
    """
    get_store().register_parser(tool_name, parser)


def launch_job(
    command: list[str],
    *,
    tool_name: str,
    timeout: float = 1800.0,
    log_dir: str | None = None,
    verdict_parser: Callable[[str], dict[str, Any]] | None = None,
    env: dict[str, str] | None = None,
    agent_id: str | None = None,
    target: str | None = None,
    fleet_body: str = "",
    override_slots: int | None = None,
) -> dict[str, Any]:
    """Launch a background subprocess and return immediately with a job_id.

    Parameters
    ----------
    command
        Argv list (never a shell string).  Passed to ``subprocess.Popen``
        with ``shell=False``; the child detaches into its own session so
        the store's reaper can kill the tree surgically and an orphaned
        scan stays observable.
    tool_name
        Short identifier used in log file names (e.g. ``"nmap"``,
        ``"sqlmap"``).
    timeout
        Wall-clock cap in seconds.  The store's ONE reaper thread
        terminates the process tree if it exceeds this; the next poll
        observes the timeout.
    log_dir
        Optional per-call log directory. Defaults to the store's
        ``run/jobs/<tool>/`` — never ``/tmp``.
    verdict_parser
        Optional callable that takes the full log text and returns a dict
        of parsed results (e.g. ``{"injectable": True}``).  Applied by
        ``poll_job`` in this process; tools that don't need verdict
        parsing omit it.
    env
        Optional environment dict for the subprocess.  Defaults to the
        current environment.
    agent_id
        Optional explicit owner identity; defaults to the resolved ambient
        identity the dispatch lane set (executor/gateway). Anonymous
        callers are minted upstream — no silent shared-session default.
    target
        Optional fleet-accounting axis (URL/host/path). When present the
        unit goes through ``utils.fleet_scheduler.request_unit`` FIRST:
        ``duplicate`` returns the running unit's job_id to poll instead of
        launching; ``refused`` returns the structured refusal; on
        ``acquired`` the job launches and binds inline. Traffic-sending
        callers pass this so the per-host courtesy contract (scale-doctrine
        rule 6) covers every launch, fleet or not.
    fleet_body
        Request-body shape hint for the canonical key (field NAMES, never
        values) — matters only for targets whose identity includes POST
        params.
    override_slots
        Explicit slot-raise request (scheduler stamps a warning; the
        absolute ceiling cannot be exceeded).

    Returns
    -------
    dict
        Without ``target``: the classic launch envelope —
        ``{"job_id", "status": "running", ...}``.  With ``target``: the
        launch envelope carries the fleet decision fields (``unit_key``,
        ``slot_contract``); a ``duplicate``/``refused`` decision replaces
        it with a no-launch envelope (``status: "duplicate"`` /
        ``status: "refused"`` + ``reason``) that callers return to the
        model verbatim.
    """
    store = get_store()
    owner = agent_id or current_agent_id()
    if verdict_parser is not None:
        store.register_parser(tool_name, verdict_parser)

    # --- Fleet accounting (optional lane): scheduler decides BEFORE spawn.
    if target:
        from utils.fleet_scheduler import get_scheduler

        decision = get_scheduler().request_unit(
            tool_name,
            target,
            agent_id=owner,
            body=fleet_body or "",
            override_slots=override_slots,
        )
        if decision["decision"] == "duplicate":
            return {
                "status": "duplicate",
                "job_id": decision.get("job_id"),
                "unit_key": decision.get("unit_key"),
                "started_by": decision.get("agent_id"),
                "started": decision.get("started"),
                "message": decision.get(
                    "message",
                    "an identical unit is already running; poll its job_id",
                ),
            }
        if decision["decision"] == "refused":
            return {
                "status": "refused",
                "reason": decision.get("reason"),
                "unit_key": decision.get("unit_key"),
                "message": decision.get("message", "scheduler refused the unit"),
                "detail": {
                    k: v
                    for k, v in decision.items()
                    if k not in ("decision", "message")
                },
            }

    result = store.launch(
        command,
        tool_name=tool_name,
        agent_id=owner,
        timeout=timeout,
        log_dir=log_dir,
        env=env,
    )
    if target:
        from utils.fleet_scheduler import get_scheduler

        scheduler = get_scheduler()
        scheduler.bind_job(decision["unit_key"], result["job_id"])
        result["unit_key"] = decision["unit_key"]
        if decision.get("warning"):
            result["warning"] = decision["warning"]
    return result


def poll_job(job_id: str, *, tool_name: str = "") -> dict[str, Any]:
    """Poll a background job: running/done, recent log lines, parsed verdict.

    Parameters
    ----------
    job_id
        The ``job_id`` returned by ``launch_job``.
    tool_name
        Kept for pre-v2 signature compatibility (the store resolves the row
        by the indexed job_id key — no log-dir scan, works from any lane
        that can read the store).
    """
    return get_store().poll(job_id)


# --- lifecycle + introspection -------------------------------------------------


def get_job(job_id: str) -> dict[str, Any] | None:
    """Direct access to a job row (custom poll logic). When THIS process
    launched the job, ``"proc"`` in the returned dict is the live
    ``subprocess.Popen`` (hash_crack's hashfile watcher must ``wait()`` on
    the real child object)."""
    return get_store().get(job_id)


def get_job_pid(job_id: str) -> int | None:
    """Live pid for a job row (watchers that only need the pid)."""
    return get_store().get_pid(job_id)


def terminate_job(job_id: str, *, force: bool = False) -> bool:
    """Terminate a running job by id.  Same-agent ownership applies;
    ``force=True`` is the operator-level cross-agent override.  Returns
    True if a job was found and terminated."""
    result = get_store().stop(job_id, force=force)
    return result.get("status") == "ok"


def list_jobs(agent_id: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    """Recent jobs for one agent (or all agents — operator tooling view)."""
    return get_store().list_jobs(agent_id=agent_id, limit=limit)


def job_stats() -> dict[str, Any]:
    """Store statistics (running/total counts) — doctor probe surface."""
    return get_store().stats()


# --- internals kept for import compatibility ----------------------------------


def _read_log(path: str) -> str:
    """Legacy shim — the job store's log reader (kept for import parity)."""
    return JobStore._read_log(path)


def _tail(text: str, n: int) -> list[str]:
    """Legacy shim — the job store's tail helper (kept for import parity)."""
    return JobStore._tail(text, n)


def _cleanup_job(job_id: str) -> None:
    """Legacy no-op: the pre-v2 registry evicted finished jobs from an
    in-process dict and closed log handles; the store owns both concerns
    (TTL sweep + handle lifecycle). Kept so stale internal imports break
    loudly nowhere — internal callers only, not the public surface."""
    return None
