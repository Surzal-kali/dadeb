"""Shared background-job helper for long-running CLI tools.

Several framework tools launch external processes that can run for minutes
to tens of minutes (nmap, sqlmap, amass, gobuster).  Blocking on
``subprocess.run`` holds the entire secretary turn open for the process's
full runtime and fights the turn timeout no matter how large the budget.

This module factors out the job-launch + poll pattern that sqlmap pioneered
(see ``payloads/sqlmap.py``) into a reusable helper so nmap, amass, gobuster
and friends inherit it without each reimplementing the machinery:

- ``launch_job`` starts a ``subprocess.Popen`` (detached, stdin=/dev/null),
  writes a JSON sidecar to disk (so polls survive a harness restart), starts
  a reaper thread for the wall-clock cap, and returns a ``job_id`` + metadata
  immediately.
- ``poll_job`` reads the log, checks liveness, tails recent lines, and
  returns a structured ``status: "running" | "done"`` dict.
- ``get_job`` / ``terminate_job`` are exposed for callers that need direct
  access (e.g. a custom verdict parser).

Callers that want tool-specific verdict parsing (sqlmap's injectable
detection, nmap's open-port extraction) pass a ``verdict_parser`` callable
to ``launch_job``; it is stored on the entry and called by ``poll_job``
with the full log text.  Tools that don't need a verdict simply omit it.

The in-process ``_JOBS`` dict is the fast path (live Popen handle); the
disk sidecar is the durable fallback for cross-process / post-restart
polls.  The job cap prevents unbounded memory growth in long sessions.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


# In-process job registry.  One entry per live or recently-finished job so
# the secretary can poll across turns.  Capped to avoid unbounded growth.
_MAX_JOBS = 64
_JOBS: "Dict[str, Dict[str, Any]]" = {}
_JOBS_LOCK = threading.Lock()

# Default log directory for per-job output.  Read PER CALL everywhere (see
# launch_job/_reconstruct_job/_find_job_tool): tests set $BG_JOB_LOG_DIR just
# before importing the tool modules and the import-time capture bug (a1fae22
# regression) is why the hashfile-survives tests fail in full-suite order.
# This constant is only the fallback when the var is unset at call time.
_LOG_DIR_FALLBACK = "/tmp"


def _log_dir() -> str:
    """Return the log dir per call: $BG_JOB_LOG_DIR when set, else /tmp.

    Read at CALL time, never cached at import — a module that imported this
    one earlier (test order, plugin load order) must not pin a stale dir.
    """
    return os.getenv("BG_JOB_LOG_DIR", "").strip() or _LOG_DIR_FALLBACK


# Verdict-parser registry.  Each tool module registers its log-text parser
# here at import time so jobs launched in one process can be polled with
# parseable verdicts after the originating closure is unavailable (e.g. the
# job entry was evicted from ``_JOBS`` and poll_job fell back to a disk
# sidecar reconstruction).  Keyed by ``tool_name`` — the same value passed
# to ``launch_job(..., tool_name=...)`` and stored in the disk sidecar's
# ``"tool"`` field.
_VERDICT_PARSERS: "Dict[str, Callable[[str], Dict[str, Any]]]" = {}
_VERDICT_PARSERS_LOCK = threading.Lock()


def register_verdict_parser(tool_name: str, parser: Callable[[str], Dict[str, Any]]) -> None:
    """Register a verdict parser for a tool used by ``poll_job`` fallbacks.

    Called by tool modules at import time (module-level, after the parser
    function is defined).  The Brain's startup scan imports those modules,
    so parsers are registered before any ``CALL_TOOL`` can arrive.
    """
    with _VERDICT_PARSERS_LOCK:
        _VERDICT_PARSERS[tool_name] = parser


def _lookup_verdict_parser(tool_name: str) -> "Optional[Callable[[str], Dict[str, Any]]]":
    """Return the registered verdict parser for ``tool_name``, or None."""
    with _VERDICT_PARSERS_LOCK:
        return _VERDICT_PARSERS.get(tool_name)


def _find_job_tool(job_id: str) -> "Optional[str]":
    """Discover the tool name for a job by scanning the log dir for its sidecar.

    The disk sidecar is named ``<tool>_<job_id>.meta`` and contains a
    ``"tool"`` field.  We scan the log dir for any file matching
    ``*_<job_id>.meta``, read the ``tool`` field, and return it.  This lets
    a poller find a job even when it isn't in this process's ``_JOBS``.
    """
    log_dir = _log_dir()
    try:
        candidates = [
            os.path.join(log_dir, f)
            for f in os.listdir(log_dir)
            if f.endswith(f"_{job_id}.meta")
        ]
    except OSError:
        return None
    for meta_path in candidates:
        try:
            with open(meta_path) as f:
                meta = json.load(f)
            if meta.get("job_id") == job_id:
                return meta.get("tool") or meta.get("tool_name")
        except (OSError, json.JSONDecodeError):
            continue
    return None


def launch_job(
    command: List[str],
    *,
    tool_name: str,
    timeout: float = 1800.0,
    log_dir: Optional[str] = None,
    verdict_parser: Optional[Callable[[str], Dict[str, Any]]] = None,
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Launch a background subprocess and return immediately with a job_id.

    Parameters
    ----------
    command
        Argv list (never a shell string).  Passed to ``subprocess.Popen``
        with ``shell=False``.
    tool_name
        Short identifier used in log file names (e.g. ``"nmap"``,
        ``"sqlmap"``).
    timeout
        Wall-clock cap in seconds.  A reaper thread terminates the process
        if it exceeds this; the next poll observes the timeout.
    log_dir
        Directory for per-job log + metadata sidecar.  Defaults to
        ``$BG_JOB_LOG_DIR`` or ``/tmp``.
    verdict_parser
        Optional callable that takes the full log text and returns a dict
        of parsed results (e.g. ``{"injectable": True}``).  Called by
        ``poll_job``; tools that don't need verdict parsing omit it.
    env
        Optional environment dict for the subprocess.  Defaults to the
        current environment.

    Returns
    -------
    dict
        ``{"job_id", "status": "running", "log_file", "tool", "started",
        "message"}`` — the caller hands ``job_id`` to its poll function.
    """
    log_dir = log_dir or _log_dir()
    Path(log_dir).mkdir(parents=True, exist_ok=True)

    job_id = uuid.uuid4().hex[:8]
    log_path = os.path.join(log_dir, f"{tool_name}_{job_id}.log")
    meta_path = os.path.join(log_dir, f"{tool_name}_{job_id}.meta")
    started = time.time()

    log_fh = open(log_path, "w", buffering=1)  # line-buffered for live polls
    proc = subprocess.Popen(
        command,
        stdout=log_fh,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        text=True,
        start_new_session=True,  # detach so orphaned scans keep running
        env=env,
    )

    entry: Dict[str, Any] = {
        "job_id": job_id,
        "tool": tool_name,
        "command": command,
        "log_file": log_path,
        "meta_file": meta_path,
        "started": started,
        "cap": float(timeout),
        "proc": proc,
        "log_fh": log_fh,
        "timed_out": False,
        "verdict_parser": verdict_parser,
    }

    # Disk sidecar for durability across restarts.
    try:
        with open(meta_path, "w") as f:
            json.dump(
                {
                    "job_id": job_id,
                    "tool": tool_name,
                    "command": command,
                    "log_file": log_path,
                    "started": started,
                    "cap": float(timeout),
                    "pid": proc.pid,
                },
                f,
            )
    except OSError:
        pass

    def _reaper(p: subprocess.Popen, fh: Any, jid: str, cap: float) -> None:
        try:
            p.wait(timeout=cap)
        except subprocess.TimeoutExpired:
            _terminate_proc(p)
            with _JOBS_LOCK:
                j = _JOBS.get(jid)
                if j:
                    j["timed_out"] = True
            try:
                fh.write(f"\n[{tool_name} reaper] exceeded {cap:.0f}s wall-clock; terminated\n")
            except Exception:
                pass

    t = threading.Thread(
        target=_reaper, args=(proc, log_fh, job_id, float(timeout)), daemon=True
    )
    entry["_reaper"] = t
    t.start()

    with _JOBS_LOCK:
        _JOBS[job_id] = entry
        if len(_JOBS) > _MAX_JOBS:
            finished = sorted(
                (k for k, v in _JOBS.items() if v["proc"].poll() is not None),
                key=lambda k: _JOBS[k]["started"],
            )
            for k in finished[: len(_JOBS) - _MAX_JOBS]:
                _cleanup_job(k)

    return {
        "job_id": job_id,
        "status": "running",
        "log_file": log_path,
        "tool": tool_name,
        "started": started,
        "message": (
            "launch accepted; perform one status poll to confirm the job is "
            "running, then hand off to the user. Do not poll repeatedly; "
            f"call {tool_name}_status(job_id) again only when the user requests "
            "an update."
        ),
    }


def poll_job(job_id: str, *, tool_name: str = "") -> Dict[str, Any]:
    """Poll a background job: returns running/done, recent log lines, and an
    optional parsed verdict.

    Parameters
    ----------
    job_id
        The ``job_id`` returned by ``launch_job``.
    tool_name
        Used to locate the disk sidecar when the job isn't in this process's
        ``_JOBS`` (e.g. after a restart).  If empty, only the in-process
        registry is consulted.
    """
    with _JOBS_LOCK:
        entry = _JOBS.get(job_id)

    if entry is None and tool_name:
        entry = _reconstruct_job(job_id, tool_name)

    if entry is None:
        return {
            "job_id": job_id,
            "status": "unknown",
            "error": f"no {tool_name or 'background'} job with id {job_id!r} (it may have been evicted)",
        }

    # Defensive: never serve data for a different job_id than requested.
    # This catches any path where the entry's job_id diverges from the
    # lookup key (corrupt sidecar, race, etc.) — return "unknown" instead
    # of silently returning another job's results.
    if entry.get("job_id") != job_id:
        return {
            "job_id": job_id,
            "status": "unknown",
            "error": f"job id mismatch: requested {job_id!r} but entry has {entry.get('job_id')!r}",
        }

    proc: Optional[subprocess.Popen] = entry.get("proc")
    rc: Optional[int]
    if proc is not None:
        rc = proc.poll()
    else:
        rc = _pid_status(entry)
    elapsed = time.time() - entry["started"]
    timed_out = entry.get("timed_out", False)

    # Poll-side cap enforcement (defense-in-depth alongside the reaper).
    cap = float(entry.get("cap", 0) or 0)
    if rc is None and not timed_out and cap and elapsed > cap:
        _terminate_job(entry)
        timed_out = True
        if proc is not None:
            rc = proc.poll()
        else:
            rc = _pid_status(entry)
        try:
            with open(entry["log_file"], "a") as fh:
                fh.write(f"\n[{entry.get('tool', 'bg')} poll-reaper] exceeded {cap:.0f}s wall-clock; terminated\n")
        except OSError:
            pass

    log_text = _read_log(entry["log_file"])
    recent = _tail(log_text, 20)

    if rc is None and not timed_out:
        status = "running"
    else:
        status = "done"

    result: Dict[str, Any] = {
        "job_id": job_id,
        "status": status,
        "exit_code": rc if rc is not None else None,
        "elapsed": round(elapsed, 1),
        "timed_out": timed_out,
        "recent_lines": recent,
        "log_file": entry["log_file"],
    }

    # Tool-specific verdict parsing.  Try the entry's own parser first
    # (the live closure set at launch time); if the entry was reconstructed
    # from disk (no parser), fall back to the registry so tools polled
    # across restarts still get parsed verdicts.
    parser = entry.get("verdict_parser")
    if not callable(parser):
        tool = entry.get("tool", "")
        if tool:
            parser = _lookup_verdict_parser(tool)
    if callable(parser):
        try:
            verdict = parser(log_text)
            if isinstance(verdict, dict):
                result.update(verdict)
        except Exception:
            pass

    if status == "done":
        result["full_output"] = log_text[-8000:]
    return result


def get_job(job_id: str) -> Optional[Dict[str, Any]]:
    """Direct access to a job entry (for custom poll logic)."""
    with _JOBS_LOCK:
        return _JOBS.get(job_id)


def terminate_job(job_id: str) -> bool:
    """Terminate a running job by id.  Returns True if a job was found."""
    with _JOBS_LOCK:
        entry = _JOBS.get(job_id)
    if entry is None:
        return False
    _terminate_job(entry)
    return True


# --- internals ---------------------------------------------------------------


def _read_log(path: str) -> str:
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def _reconstruct_job(job_id: str, tool_name: str) -> Optional[Dict[str, Any]]:
    """Rebuild a job entry from the disk sidecar after a restart."""
    meta_path = os.path.join(_log_dir(), f"{tool_name}_{job_id}.meta")
    try:
        with open(meta_path) as f:
            meta = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    # Defensive: verify the meta file's job_id matches the one requested.
    # A mismatch (corrupt sidecar, wrong file) must never silently serve
    # another job's data — return None so poll_job reports "unknown".
    if meta.get("job_id") != job_id:
        return None
    return {
        "job_id": job_id,
        "tool": meta.get("tool", tool_name),
        "command": meta.get("command", []),
        "log_file": meta.get("log_file", os.path.join(_log_dir(), f"{tool_name}_{job_id}.log")),
        "meta_file": meta_path,
        "started": meta.get("started", time.time()),
        "cap": meta.get("cap", 1800.0),
        "proc": None,
        "pid": meta.get("pid"),
        "log_fh": None,
        "timed_out": False,
        "verdict_parser": None,
        "_reconstructed": True,
    }


def _terminate_job(entry: Dict[str, Any]) -> None:
    proc: Optional[subprocess.Popen] = entry.get("proc")
    if proc is not None:
        _terminate_proc(proc)
        return
    pid = entry.get("pid")
    if not pid:
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except (ProcessLookupError, OSError):
        return
    for _ in range(20):
        try:
            os.kill(pid, 0)
        except (ProcessLookupError, OSError):
            return
        time.sleep(0.25)
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


def _terminate_proc(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def _pid_status(entry: Dict[str, Any]) -> Optional[int]:
    """For a reconstructed job: return exit code if exited, None if running."""
    pid = entry.get("pid")
    if pid is not None:
        try:
            os.kill(pid, 0)
            return None
        except ProcessLookupError:
            return 0
        except PermissionError:
            return None
    log_text = _read_log(entry["log_file"])
    # Heuristic: many CLI tools don't write an explicit end marker, so a
    # dead pid is the primary signal.  When there's no pid, we can't tell.
    return 0 if pid is not None else None


def _tail(text: str, n: int) -> List[str]:
    lines = [ln for ln in text.splitlines() if ln.strip()]
    ansi = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
    lines = [ansi.sub("", ln).strip() for ln in lines]
    lines = [ln for ln in lines if ln]
    return lines[-n:]


def _cleanup_job(job_id: str) -> None:
    entry = _JOBS.pop(job_id, None)
    if not entry:
        return
    try:
        entry["log_fh"].close()
    except Exception:
        pass
