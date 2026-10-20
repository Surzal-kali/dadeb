"""sqlmap launcher + pollable status, mirroring the ZAP start/poll model.

sqlmap is inherently long-running: a real crawl+scan over many injectable
parameters can take minutes to tens of minutes. A *blocking* ``run_sqlmap``
holds the entire secretary turn open for the scan's full runtime and fights
the turn timeout no matter how large the budget. Instead this module uses the
same shape the ZAP tools already use (``zap_spider`` returns a scan id,
``zap_spider_status`` polls it):

- ``run_sqlmap(target_url, options)`` launches sqlmap as a background
  ``subprocess.Popen`` and returns immediately with a ``job_id`` plus a log
  file path. The secretary turn is NOT held open.
- ``sqlmap_status(job_id)`` polls the job: checks whether the process is
  still alive, tails the log, and parses a verdict (injectable / not
  injectable / still running) so the model can decide whether to keep
  polling or call ``report_finding``.

Non-interactivity is enforced defensively on two layers:

1. ``--batch`` is auto-injected when the caller omits it (sqlmap otherwise
   prompts on stdin: "do you want to test this URL? [Y/n/q]", ...).
2. ``stdin=subprocess.DEVNULL`` so any future unsuppressed prompt reads EOF
   and never blocks.

A wall-clock cap (``SQLMAP_TIMEOUT``, default 1800s) reaps a wedged scan via
a ``threading.Timer`` so the subprocess can't run forever; the poll then
reports the timeout with the partial log.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

from constants import framework_tool
from utils.background_job import register_verdict_parser


# In-process job registry. One entry per live or recently-finished scan so the
# secretary can poll across turns. Capped to avoid unbounded growth in long
# sessions; oldest finished jobs are evicted first.
_MAX_JOBS = 64
_JOBS: "Dict[str, Dict[str, Any]]" = {}
_JOBS_LOCK = threading.Lock()

# Log directory for per-job sqlmap output. Created lazily.
_LOG_DIR = os.getenv("SQLMAP_LOG_DIR", "/tmp")


def _inject_batch(extra: List[str]) -> List[str]:
    """Prepend/append ``--batch`` if the caller didn't already pass it."""
    if any(a in ("--batch", "-batch") or a.startswith("--batch=") for a in extra):
        return extra
    return extra + ["--batch"]


def _parse_verdict(log_text: str) -> Dict[str, Any]:
    """Best-effort verdict from sqlmap's log output.

    Returns a dict with ``injectable`` (bool), ``dbms`` (str|None), and
    ``verdict`` (human-readable line). Conservative: only flips
    ``injectable`` True on sqlmap's explicit confirmation lines, never on the
    heuristic "might be injectable" line.
    """
    dbms = None
    # Capture just the bare DBMS name, not the "[Y/n]" prompt sqlmap appends on
    # the same line. "back-end DBMS is 'MySQL'. Do you want to skip..." ->
    # "MySQL".
    m = re.search(r"back-end DBMS is '?([A-Za-z][A-Za-z0-9 _]*)'?", log_text, re.IGNORECASE)
    if m:
        dbms = m.group(1).strip()
    injectable = None  # None = unknown, True/False once sqlmap decides
    if re.search(r"sqlmap identified the following injection point", log_text, re.IGNORECASE) \
       or re.search(r"the back-end DBMS is .+ and it is injectable", log_text, re.IGNORECASE) \
       or re.search(r"parameter '[^']+' is vulnerable", log_text, re.IGNORECASE):
        injectable = True
    if re.search(r"all tested parameters do not appear to be injectable", log_text, re.IGNORECASE) \
       or re.search(r"does not seem to be injectable", log_text, re.IGNORECASE):
        injectable = False
    verdict = None
    for pat in (
        r"sqlmap identified the following injection point.*",
        r"parameter '[^']+' is vulnerable.*",
        r"all tested parameters do not appear to be injectable.*",
    ):
        mm = re.search(pat, log_text, re.IGNORECASE)
        if mm:
            verdict = mm.group(0).strip()
            break
    return {"injectable": injectable, "dbms": dbms, "verdict": verdict}


register_verdict_parser("sqlmap", _parse_verdict)


@framework_tool(
    "Launch a sqlmap scan against a target URL in the background; returns a "
    "job_id you poll with sqlmap_status. Non-interactive (--batch is forced). "
    "Use this for SQL INJECTION testing through a web parameter. If you "
    "already have valid database credentials, do NOT use this - the db_* "
    "tools (db_connect / db_exec_batch / db_schema_farm, net.services) speak "
    "the protocol directly and are faster, quieter and structured.",
    next_hints=["sqlmap_status"],
)
def run_sqlmap(target_url: str, options: str = "") -> Dict[str, Any]:
    """Launch sqlmap against ``target_url`` and return immediately.

    Lane note (2026-09-22): sqlmap = injection testing (attack verb). Direct
    database access with known credentials is a different lane - use the
    db_* tools in auxiliaries/db_client.py (db_connect / db_exec_batch /
    db_schema_farm), which speak MySQL/MSSQL/PostgreSQL wire protocols with
    the credentials and need no injectable parameter.

    "sqlmap runs as a detached background subprocess writing to a per-job log
    file; this call does NOT block on the scan. Perform one status poll to
    confirm it is running, then hand off to the user. Poll again only when the
    user requests an update.

    ``--batch`` is forced (appended if not already in ``options``) so sqlmap
    never blocks on an interactive prompt, and stdin is /dev/null as a
    second defense. Pass ``--dbs``, ``--current-db``, ``--dump``, etc. to
    enumerate once a scan reports injectable.

    Args:
        target_url: The target URL to test for SQL injection. For POST params,
            pass the URL here and the body via ``options`` with ``--data=...``
            (e.g. ``"--data='user=admin&pass=x' --level=3"``).
        options: Additional sqlmap command-line options as a single string
            (e.g. ``"--data='username=test&password=x' --level=3 --risk=2"``).
            Quoted sub-phrases are preserved by shlex. ``--batch`` is injected
            automatically if absent.
    """
    # Scope gate (operator-armed from the Tool REPL; no-op when disarmed).
    # Active SQLi payload traffic — this tool must honour the gate like every
    # other traffic-sending module (2026-09-19 gap: was ungated).
    from utils.scope_gate import check_scan, ScopeGateError
    _sc_ok, _sc_reason = check_scan(target_url)
    if not _sc_ok:
        raise ScopeGateError(f"scope gate: {_sc_reason}")

    # -u takes the URL as its own argv element; never interpolate it into a
    # shell string.
    extra = shlex.split(options) if options else []
    extra = _inject_batch(extra)
    command = ["sqlmap", "-u", target_url, *extra]

    job_id = uuid.uuid4().hex[:8]
    log_path = os.path.join(_LOG_DIR, f"sqlmap_{job_id}.log")
    meta_path = os.path.join(_LOG_DIR, f"sqlmap_{job_id}.meta")
    started = time.time()

    cap = float(os.getenv("SQLMAP_TIMEOUT", "1800"))

    log_fh = open(log_path, "w", buffering=1)  # line-buffered so polls see live progress
    proc = subprocess.Popen(
        command,
        stdout=log_fh,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        text=True,
        # Detach into its own session so the scan keeps running even if the
        # launcher thread/process dies unexpectedly -- the poll reads the log
        # and reaps via the reaper timer, so an orphaned scan is still
        # observable and bounded, not silently killed with its parent.
        start_new_session=True,
    )

    entry: Dict[str, Any] = {
        "job_id": job_id,
        "target": target_url,
        "options": options,
        "log_file": log_path,
        "meta_file": meta_path,
        "started": started,
        "cap": cap,
        "proc": proc,
        "log_fh": log_fh,
        "timed_out": False,
    }

    # Disk sidecar so a job survives a harness restart and can be polled from
    # a different process. The in-process _JOBS entry is the fast path (live
    # Popen handle); the sidecar is the durable fallback (log + pid).
    import json as _json
    try:
        with open(meta_path, "w") as f:
            _json.dump(
                {
                    "job_id": job_id,
                    "tool": "sqlmap",
                    "target": target_url,
                    "options": options,
                    "log_file": log_path,
                    "started": started,
                    "cap": cap,
                    "pid": proc.pid,
                },
                f,
            )
    except OSError:
        pass

    # Reap the subprocess if it exceeds the wall-clock cap so a wedged scan
    # can't run forever. The timer does NOT block the caller; it fires later
    # in a daemon thread and the next poll observes the timeout.
    def _reaper(p: subprocess.Popen, fh: Any, jid: str) -> None:
        try:
            p.wait(timeout=cap)
        except subprocess.TimeoutExpired:
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
            with _JOBS_LOCK:
                j = _JOBS.get(jid)
                if j:
                    j["timed_out"] = True
            try:
                fh.write(f"\n[sqlmap reaper] exceeded {cap:.0f}s wall-clock; terminated\n")
            except Exception:
                pass

    t = threading.Thread(target=_reaper, args=(proc, log_fh, job_id), daemon=True)
    entry["_reaper"] = t
    t.start()

    with _JOBS_LOCK:
        _JOBS[job_id] = entry
        # Evict oldest finished jobs if we've grown past the cap.
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
        "target": target_url,
        "started": started,
        "message": (
            "launch accepted; perform one status poll to confirm the job is "
            "running, then hand off to the user. Poll again only when the "
            "user requests an update."
        ),
    }


@framework_tool(
    "Poll a sqlmap scan job: returns running/done, a parsed injectable "
    "verdict, the detected DBMS, and recent log lines. Call once only when "
    "the user requests an update; never poll repeatedly until done. The DBMS "
    "name in the verdict pairs with the direct "
    "db_* tools (db_connect / db_schema_farm) once credentials are known - "
    "sqlmap itself stays the injection lane only.",
    next_hints=["sqlmap_status", "report_finding"],
)
def sqlmap_status(job_id: str) -> Dict[str, Any]:
    """Poll the status of a scan launched by ``run_sqlmap``.

    Reads the job's log file, checks whether the subprocess is still alive,
    and parses sqlmap's output for a verdict. Returns ``status: "running"``
    while the scan is in progress and ``status: "done"`` once the process has
    exited (or been reaped by the wall-clock cap).

    Args:
        job_id: The ``job_id`` returned by ``run_sqlmap``.
    """
    with _JOBS_LOCK:
        entry = _JOBS.get(job_id)

    # Durable fallback: if the job isn't in this process's _JOBS (e.g. it was
    # started before a harness restart, or this is a different process), try
    # to reconstruct it from the disk sidecar. We never get a live Popen
    # handle back, but the log file + the recorded pid are enough to tell
    # running from done and to parse a verdict.
    if entry is None:
        entry = _reconstruct_job(job_id)

    if entry is None:
        return {
            "job_id": job_id,
            "status": "unknown",
            "error": f"no sqlmap job with id {job_id!r} (it may have been evicted)",
        }

    proc: Optional[subprocess.Popen] = entry.get("proc")
    rc: Optional[int]
    if proc is not None:
        rc = proc.poll()
    else:
        # Reconstructed job: infer liveness from the recorded pid and the log.
        rc = _pid_status(entry)
    elapsed = time.time() - entry["started"]
    timed_out = entry.get("timed_out", False)

    # Poll-side cap enforcement (defense-in-depth alongside the launcher's
    # reaper thread). The reaper lives in the launcher process; if that
    # process has exited (or restarted), the reaper is gone and an
    # over-running scan would otherwise run forever. Whoever polls reaps it
    # here, so the cap is honoured even across harness restarts.
    cap = float(entry.get("cap", 0) or 0)
    if rc is None and not timed_out and cap and elapsed > cap:
        _terminate_job(entry)
        timed_out = True
        if proc is not None:
            rc = proc.poll()
        else:
            rc = _pid_status(entry)  # now dead -> exit code
        try:
            with open(entry["log_file"], "a") as fh:
                fh.write(f"\n[sqlmap poll-reaper] exceeded {cap:.0f}s wall-clock; terminated\n")
        except OSError:
            pass

    log_text = _read_log(entry["log_file"])
    parsed = _parse_verdict(log_text)
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
        "injectable": parsed["injectable"],
        "dbms": parsed["dbms"],
        "verdict": parsed["verdict"],
        "timed_out": timed_out,
        "recent_lines": recent,
        "log_file": entry["log_file"],
    }
    if status == "done":
        # Surface the full output on completion so the secretary has the
        # evidence needed for report_finding, but cap it so a giant dump
        # doesn't blow out the model context.
        result["full_output"] = log_text[-8000:]
    return result


# --- internals ---------------------------------------------------------------


def _read_log(path: str) -> str:
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def _reconstruct_job(job_id: str) -> Optional[Dict[str, Any]]:
    """Rebuild a job entry from the disk sidecar when it's not in _JOBS.

    Used after a harness restart (or from a different process) so polls keep
    working. There is no live Popen handle, so liveness is inferred from the
    recorded pid (``os.kill(pid, 0)``) plus sqlmap's ``[*] ending @`` log line.
    """
    import json as _json
    meta_path = os.path.join(_LOG_DIR, f"sqlmap_{job_id}.meta")
    try:
        with open(meta_path) as f:
            meta = _json.load(f)
    except (OSError, _json.JSONDecodeError):
        return None
    return {
        "job_id": job_id,
        "target": meta.get("target", ""),
        "options": meta.get("options", ""),
        "log_file": meta.get("log_file", os.path.join(_LOG_DIR, f"sqlmap_{job_id}.log")),
        "meta_file": meta_path,
        "started": meta.get("started", time.time()),
        "cap": meta.get("cap", float(os.getenv("SQLMAP_TIMEOUT", "1800"))),
        "proc": None,  # no live handle
        "pid": meta.get("pid"),
        "log_fh": None,
        "timed_out": False,
        "_reconstructed": True,
    }


def _terminate_job(entry: Dict[str, Any]) -> None:
    """Terminate a running sqlmap job: terminate() then kill() the live Popen,
    or, for a reconstructed job with only a pid, send SIGTERM/SIGKILL directly.
    """
    proc: Optional[subprocess.Popen] = entry.get("proc")
    if proc is not None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        return
    pid = entry.get("pid")
    if not pid:
        return
    import signal
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except OSError:
        return
    # Give it a moment to die, then SIGKILL if still alive.
    for _ in range(20):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        except OSError:
            return
        time.sleep(0.25)
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


def _pid_status(entry: Dict[str, Any]) -> Optional[int]:
    """For a reconstructed job: return the process exit code if it has exited,
    or None if it's still running. Falls back to the log's ``ending`` marker
    when the pid is gone but we can't read an exit code.
    """
    pid = entry.get("pid")
    log_text = _read_log(entry["log_file"])
    if pid is not None:
        try:
            os.kill(pid, 0)  # signal 0 = liveness probe, no signal sent
            # Process still alive.
            return None
        except ProcessLookupError:
            # Exited. We can't recover the exact exit code without waitpid on
            # our own child (this isn't our child), so report 0 to mean "done".
            return 0 if "[*] ending @" not in log_text else 0
        except PermissionError:
            # Exists but not ours to signal -- treat as still running.
            return None
    # No pid recorded: rely on sqlmap's own completion marker.
    return 0 if "[*] ending @" in log_text else None


def _tail(text: str, n: int) -> List[str]:
    lines = [ln for ln in text.splitlines() if ln.strip()]
    # Strip ANSI escape sequences sqlmap emits for its terminal cursor moves.
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
