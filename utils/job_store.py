"""Job store v2 — durable, agent-scoped background-job registry (Phase 0).

The pre-v2 store (`utils/background_job.py`) was a flat process-local dict
(``_MAX_JOBS = 64``), no agent ownership, one reaper THREAD per job, log
sidecars in ``/tmp`` with an ``os.listdir`` scan per cross-process poll.
At 2-3 actors that was a wart; at 30 actors it is the component that dies
first (cap eviction shadows live jobs -> other lanes see
``status: unknown (evicted)`` for running work).

This store clones the scratch-store conventions (scratch.db RFC shape):

  run/jobs/jobs.db     SQLite metadata — ownership, status, indexes
  run/jobs/<tool>/     per-job log files (never /tmp; survives restarts)

Design facts:

- **Ownership**: every row carries the resolved ``agent_id``; polls read
  any visible row but job-wide lifecycle calls (stop) are same-agent
  unless ``force=True`` (operator-level — the execution_tracker's kill
  fence is the precedent). Anonymous ids are minted upstream by
  ``utils/agent_identity.py``; a NOT NULL column here has NO default.
- **Eviction**: TTL sweep + per-agent finished-job cap. Running jobs are
  never evicted for capacity.
- **Reaping**: ONE background reaper thread per store polls running
  processes (wall-clock caps); no thread per job. The reaper marks
  timeouts; a poll-side cap check remains as defense-in-depth. A running
  subprocess's liveness is one ``os.kill(pid, 0)`` — cross-process,
  restart-safe.
- **Cross-lane**: any lane (gateway, Brain, REPL, kernel) can launch and
  any other can poll — state is on disk, like the cookie jar.
- **Compat**: ``utils/background_job.py`` keeps its exact public surface
  (``launch_job`` / ``poll_job`` / ``get_job`` / ``terminate_job`` /
  ``register_verdict_parser``) as a thin wrapper over this store, so the
  eight tool modules that consume it change zero lines.
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
import weakref
from pathlib import Path
from typing import Any, Callable

from constants import resolve_workspace_root

_DEFAULT_ROOT = resolve_workspace_root()
_DEFAULT_JOBS_DIR = _DEFAULT_ROOT / "run" / "jobs"
_DEFAULT_DB = _DEFAULT_JOBS_DIR / "jobs.db"

_SCHEMA_VERSION = 2

# Env knobs (per house convention; read per call so tests can re-point).
_JOBS_TTL_HOURS_DEFAULT = 24
_REAPER_INTERVAL_S_DEFAULT = 2.0

# Process-liveness poll cadence inside a single terminate() await-grace loop.
_TERMINATE_GRACE_S = 5.0

_REAPER_THREAD: threading.Thread | None = None
_REAPER_WAKE = threading.Event()
# Live store instances the single background reaper services. Weak — a
# store dropped by its owner (per-test instances) stops being reaped.
_ACTIVE_STORES: "weakref.WeakSet[JobStore]" = weakref.WeakSet()
_ACTIVE_LOCK = threading.Lock()


def _jobs_root() -> Path:
    override = os.getenv("BG_JOB_STORE_DIR", "").strip()
    return Path(override) if override else _DEFAULT_JOBS_DIR


def _ttl_hours() -> float:
    raw = os.getenv("BG_JOB_TTL_HOURS", "").strip()
    return float(raw) if raw else _JOBS_TTL_HOURS_DEFAULT


def _reaper_interval() -> float:
    raw = os.getenv("BG_JOB_REAPER_INTERVAL_S", "").strip()
    return float(raw) if raw else _REAPER_INTERVAL_S_DEFAULT


def _terminate_proc_tree(pid: int) -> None:
    """SIGTERM the process group (jobs spawn with start_new_session=True,
    so the pgid == pid), grace-wait, then SIGKILL stragglers. Surgical:
    never a global sweep, matching scale-doctrine rule 3.

    Grace detection has a zombie trap: a dead-but-unreaped child answers
    ``os.kill(pid, 0)`` successfully (the pid entry stays until waitpid).
    So each grace tick ALSO tries a nonblocking waitpid — for our own
    children that reaps the zombie instantly and ends the wait; for
    foreign pids the EINVAL/ChildError is ignored and kill(pid,0) decides.
    """
    try:
        os.killpg(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            os.kill(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            return
    import errno

    deadline = time.monotonic() + _TERMINATE_GRACE_S
    while time.monotonic() < deadline:
        # Reap if it's our child (WNOHANG: 0 = still running, pid = reaped).
        try:
            wpid, _status = os.waitpid(pid, os.WNOHANG)
            if wpid == pid:
                return  # reaped — fully dead, no zombie trap
        except (ChildProcessError, OSError) as exc:
            if getattr(exc, "errno", None) == errno.ECHILD:
                pass  # not our child — fall through to the pid probe
            else:
                pass  # transient; the probe decides
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return  # exited (and someone else reaped it)
        except (PermissionError, OSError):
            return  # alive but not signalable further
        time.sleep(0.2)
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass


def _pid_alive(pid: int | None) -> bool | None:
    """True/False when a pid exists, None when unknown (no pid recorded)."""
    if not pid:
        return None
    try:
        os.kill(int(pid), 0)
        return True
    except ProcessLookupError:
        return False
    except (PermissionError, OSError, ValueError):
        return True  # exists but not signalable — treat as alive


# Verdict parsers are PROCESS-WIDE registrations (tool modules register at
# import time; any store instance in this process applies them by tool
# name) — deliberately NOT per-instance state: the env-override singleton
# dance would otherwise fragment the registry between the launching and
# polling store instances (found the hard way 2026-10-29: launch registered
# 'sqlmap' on instance A; the poll looked it up on instance B and parsed
# nothing).
_PARSERS: dict[str, Callable[[str], dict[str, Any]]] = {}
_PARSERS_LOCK = threading.Lock()


class JobStore:
    """SQLite-backed background-job registry.

    One connection, ``check_same_thread=False``, busy_timeout, WAL — the
    gateway / Brain / REPL lanes hit it concurrently.
    """

    def __init__(self, jobs_dir: str | Path = _DEFAULT_JOBS_DIR):
        self.jobs_dir = Path(jobs_dir)
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.jobs_dir, 0o700)
        except OSError:
            pass
        self.db_path = str(self.jobs_dir / "jobs.db")
        import sqlite3

        self.conn = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA busy_timeout=10000")
        self.conn.execute("PRAGMA journal_mode=WAL")
        self._lock = threading.RLock()
        # Live handles for THIS process's jobs: the Popen (for a watcher
        # that must wait() on the real child — hash_crack's hashfile
        # lifecycle) and the open log fh (closed when the job finishes).
        # Cross-process/restarted polls get the row + pid instead — that is
        # enough to distinguish running from done (the pre-v2 design's
        # goal, now with an indexed lookup).
        self._live_proc: dict[str, subprocess.Popen] = {}
        self._live_log_fh: dict[str, Any] = {}
        self._live_lock = threading.Lock()
        self._init_tables()
        self._ensure_reaper()

    # -- schema ---------------------------------------------------------------

    def _init_tables(self) -> None:
        with self._lock:
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS jobs (
                    job_id      TEXT PRIMARY KEY,
                    agent_id    TEXT NOT NULL,
                    tool        TEXT NOT NULL,
                    command     TEXT NOT NULL,
                    log_file    TEXT NOT NULL,
                    jobs_dir    TEXT NOT NULL,
                    pid         INTEGER,
                    started     REAL NOT NULL,
                    cap         REAL NOT NULL DEFAULT 0,
                    timed_out   INTEGER NOT NULL DEFAULT 0,
                    exit_code   INTEGER,
                    finished_at REAL,
                    verdict     TEXT
                )
                """
            )
            self.conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_jobs_agent_started "
                "ON jobs(agent_id, started DESC)"
            )
            self.conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_jobs_running "
                "ON jobs(agent_id) WHERE exit_code IS NULL"
            )
            self.conn.commit()

    # -- registration ----------------------------------------------------------

    def register_parser(self, tool_name: str, parser: Callable[[str], dict[str, Any]]) -> None:
        with _PARSERS_LOCK:
            _PARSERS[tool_name] = parser

    def launch(
        self,
        command: list[str],
        *,
        tool_name: str,
        agent_id: str,
        timeout: float = 1800.0,
        log_dir: str | None = None,
        env: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Spawn the subprocess, record the row, return the launch envelope.

        The subprocess detaches into its own session (pgid == pid) so the
        reaper can kill the tree surgically and orphans stay observable.
        Returns immediately — no wall-clock is spent on the child.
        """
        if not agent_id:
            raise ValueError("job store requires a resolved agent_id (no silent shared default)")
        tool_name = tool_name or "job"
        base = Path(log_dir) if log_dir else self.jobs_dir / tool_name
        base.mkdir(parents=True, exist_ok=True)

        job_id = uuid.uuid4().hex[:12]
        log_path = base / f"{tool_name}_{job_id}.log"
        started = time.time()
        cap = float(timeout or 0)

        log_fh = open(log_path, "w", buffering=1)  # line-buffered for live polls
        proc = subprocess.Popen(
            command,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            text=True,
            start_new_session=True,
            env=env,
        )
        with self._live_lock:
            self._live_proc[job_id] = proc
            self._live_log_fh[job_id] = log_fh

        with self._lock:
            self.conn.execute(
                """
                INSERT INTO jobs
                    (job_id, agent_id, tool, command, log_file, jobs_dir,
                     pid, started, cap)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job_id, agent_id, tool_name, json.dumps(command),
                    str(log_path), str(base),
                    proc.pid, started, cap,
                ),
            )
            self.conn.commit()
        self._enforce_caps(agent_id)
        _REAPER_WAKE.set()

        return {
            "job_id": job_id,
            "agent_id": agent_id,
            "status": "running",
            "log_file": str(log_path),
            "tool": tool_name,
            "started": started,
            "pid": proc.pid,
            "message": (
                "launch accepted; perform one status poll to confirm the job is "
                "running, then hand off to the user. Do not poll repeatedly; "
                f"call {tool_name}_status(job_id) again only when the user requests "
                "an update."
            ),
        }

    # -- polling ----------------------------------------------------------------

    def _row(self, job_id: str) -> Any:
        return self.conn.execute(
            "SELECT * FROM jobs WHERE job_id = ?", (job_id,)
        ).fetchone()

    def _observe(self, row: Any) -> Any:
        """Update the row's exit state from process liveness; return the row.

        Two observation paths, in order:
        1. **Live Popen** (this process launched the job): ``poll()`` does
           the real ``waitpid`` — the zombie gets reaped and we can record
           the genuine exit code. Pre-v2 relied on exactly this; without
           it a finished child stays a zombie and ``os.kill(pid, 0)``
           keeps reporting it alive forever.
        2. **Row pid** (cross-lane / post-restart poll): the child is NOT
           ours to wait on, so liveness is the ``os.kill(pid, 0)`` probe;
           a vanished pid marks the row done (exit code unknown → -1).
           Zombies from other processes report alive — that is correct:
           their owning process must reap them (our reaper does, via the
           kill-tree path; a completed foreign child is picked up when
           its lane's process reaps or its row hits TTL).
        """
        job_id = row["job_id"]
        with self._live_lock:
            proc = self._live_proc.get(job_id)
        if proc is not None:
            rc = proc.poll()  # reaps the zombie in-process
            fresh = self._row(job_id) or row
            if rc is not None and fresh["exit_code"] is None:
                self._mark_finished(job_id, exit_code=int(rc), timed_out=False)
                return self._row(job_id) or row
            return fresh
        pid = row["pid"]
        alive = _pid_alive(pid)
        if row["exit_code"] is None and alive is False:
            self._mark_finished(job_id, exit_code=-1, timed_out=False)
            return self._row(job_id) or row
        return row

    def _mark_finished(self, job_id: str, *, exit_code: int, timed_out: bool) -> None:
        """Stamp the finish. First marker wins: the UPDATE is guarded on
        ``exit_code IS NULL`` so a racing poll()'s clean-exit observation
        can NEVER overwrite the reaper's authoritative timed_out=True (a
        cap kill must read as a timeout, not a clean exit) — and vice
        versa. Callers that observe an already-finished row keep its flag.
        """
        with self._lock:
            cur = self.conn.execute(
                "UPDATE jobs SET exit_code = ?, finished_at = ?, "
                "timed_out = ? WHERE job_id = ? AND exit_code IS NULL",
                (exit_code, time.time(), 1 if timed_out else 0, job_id),
            )
            self.conn.commit()
        self._close_live_handles(job_id)

    def _close_live_handles(self, job_id: str) -> None:
        with self._live_lock:
            fh = self._live_log_fh.pop(job_id, None)
            self._live_proc.pop(job_id, None)
        if fh is not None:
            try:
                fh.close()
            except Exception:
                pass

    def poll(self, job_id: str, *, tail: int = 20) -> dict[str, Any]:
        """Status poll: running/done/unknown, log tail, parsed verdict."""
        row = self._row(job_id)
        if row is None:
            return {
                "job_id": job_id,
                "status": "unknown",
                "error": f"no background job with id {job_id!r}",
            }

        row = self._observe(row)
        exit_code = row["exit_code"]
        timed_out = bool(row["timed_out"])
        started = row["started"]
        cap = float(row["cap"] or 0)
        elapsed = time.time() - started

        # Poll-side cap enforcement (defense-in-depth alongside the reaper).
        # A cap kill IS a timeout, not an operator stop: mark the finish
        # WITH the timed_out flag directly (guarded UPDATE — first marker
        # wins, so a racing reaper's authoritative stamp is never
        # downgraded), then kill the tree.
        if exit_code is None and not timed_out and cap > 0 and elapsed > cap:
            self._mark_finished(job_id, exit_code=-9, timed_out=True)
            _terminate_proc_tree(int(row["pid"]))
            row = self._row(job_id) or row
            exit_code = row["exit_code"]
            timed_out = bool(row["timed_out"]) or True
            try:
                with open(row["log_file"], "a") as fh:
                    fh.write(
                        f"\n[{row['tool']} poll-reaper] exceeded {cap:.0f}s "
                        "wall-clock; terminated\n"
                    )
            except OSError:
                pass

        log_text = self._read_log(row["log_file"])
        recent = self._tail(log_text, tail)
        status = "running" if (exit_code is None and not timed_out) else "done"

        result: dict[str, Any] = {
            "job_id": job_id,
            "agent_id": row["agent_id"],
            "status": status,
            "exit_code": None if exit_code is None else int(exit_code),
            "elapsed": round(elapsed, 1),
            "timed_out": timed_out,
            "recent_lines": recent,
            "log_file": row["log_file"],
            "tool": row["tool"],
        }

        parser = self._get_parser(row["tool"])
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

    # -- lifecycle ---------------------------------------------------------------

    def stop(self, job_id: str, *, force: bool = False) -> dict[str, Any]:
        """Terminate a job's process tree.

        Same-agent by default; ``force=True`` is the operator-level cross
        agent override (execution-tracker kill-fence precedent).
        """
        row = self._row(job_id)
        if row is None:
            return {"status": "Failed", "error": f"no job {job_id!r}"}
        caller = current_agent_id()
        if not force and row["agent_id"] != caller:
            return {
                "status": "Failed",
                "error": (
                    f"job {job_id!r} belongs to agent '{row['agent_id']}' "
                    f"(you are '{caller}'). Use force=True to cross agents — "
                    "that is an operator-level action."
                ),
            }
        _terminate_proc_tree(int(row["pid"]))
        self._mark_finished(job_id, exit_code=-9, timed_out=False)
        return {"status": "ok", "job_id": job_id, "agent_id": row["agent_id"]}

    def get(self, job_id: str) -> dict[str, Any] | None:
        """Direct row access (custom poll logic). When THIS process holds
        the live handle, ``"proc"`` carries the real ``Popen`` (hash_crack's
        hashfile watcher must ``wait()`` on the actual child object)."""
        row = self._row(job_id)
        if row is None:
            return None
        out = dict(row)
        with self._live_lock:
            proc = self._live_proc.get(job_id)
        if proc is not None:
            out["proc"] = proc
        return out

    def get_pid(self, job_id: str) -> int | None:
        row = self._row(job_id)
        return int(row["pid"]) if row is not None and row["pid"] else None

    def list_jobs(self, agent_id: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        """Recent jobs for one agent (or all agents when ``agent_id`` is None
        — operator/tooling view). Running jobs first."""
        if agent_id:
            rows = self.conn.execute(
                "SELECT * FROM jobs WHERE agent_id = ? ORDER BY started DESC LIMIT ?",
                (agent_id, limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM jobs ORDER BY started DESC LIMIT ?", (limit,)
            ).fetchall()
        out = []
        for r in rows:
            out.append({
                "job_id": r["job_id"],
                "agent_id": r["agent_id"],
                "tool": r["tool"],
                "status": "running" if self._is_running(r) else "done",
                "started": r["started"],
                "timed_out": bool(r["timed_out"]),
                "log_file": r["log_file"],
            })
        return out

    def stats(self) -> dict[str, Any]:
        row = self.conn.execute(
            "SELECT COUNT(*) AS total, "
            "SUM(CASE WHEN exit_code IS NULL THEN 1 ELSE 0 END) AS running "
            "FROM jobs"
        ).fetchone()
        return {"total": row["total"], "running": row["running"] or 0,
                "db": self.db_path, "jobs_dir": str(self.jobs_dir)}

    def _is_running(self, row: Any) -> bool:
        if row["exit_code"] is not None:
            return False
        alive = _pid_alive(row["pid"])
        return bool(alive) if alive is not None else True

    # -- caps + sweeps ------------------------------------------------------------

    def _enforce_caps(self, agent_id: str) -> None:
        """Per-agent finished-job cap (env ``BG_JOB_MAX_FINISHED_PER_AGENT``,
        default 128). Running jobs are NEVER evicted. TTL sweep piggybacks."""
        try:
            max_finished = int(os.getenv("BG_JOB_MAX_FINISHED_PER_AGENT", "128"))
        except ValueError:
            max_finished = 128
        with self._lock:
            rows = self.conn.execute(
                "SELECT job_id, pid FROM jobs WHERE agent_id = ? "
                "AND exit_code IS NOT NULL ORDER BY started DESC",
                (agent_id,),
            ).fetchall()
            for r in rows[max_finished:]:
                self.conn.execute("DELETE FROM jobs WHERE job_id = ?", (r["job_id"],))
            cutoff = time.time() - _ttl_hours() * 3600
            self.conn.execute(
                "DELETE FROM jobs WHERE finished_at IS NOT NULL AND finished_at < ?",
                (cutoff,),
            )
            self.conn.commit()

    def sweep(self) -> dict[str, int]:  # pragma: no cover - thin wrapper
        """Manual TTL sweep (cleanup tooling); returns row counts."""
        cutoff = time.time() - _ttl_hours() * 3600
        with self._lock:
            cur = self.conn.execute(
                "DELETE FROM jobs WHERE finished_at IS NOT NULL AND finished_at < ?",
                (cutoff,),
            )
            self.conn.commit()
            return {"expired": cur.rowcount}

    # -- reaper -------------------------------------------------------------------

    def _ensure_reaper(self) -> None:
        """Register this store for the ONE background reaper thread — no
        thread per job, no thread per store (per-test instances share it)."""
        global _REAPER_THREAD
        with _ACTIVE_LOCK:
            _ACTIVE_STORES.add(self)
            if _REAPER_THREAD is not None and _REAPER_THREAD.is_alive():
                return
        _REAPER_THREAD = threading.Thread(
            target=self._reaper_loop, name="job-store-reaper", daemon=True
        )
        _REAPER_THREAD.start()

    @staticmethod
    def _reaper_loop() -> None:
        interval = _reaper_interval()
        while True:
            _REAPER_WAKE.wait(timeout=interval)
            _REAPER_WAKE.clear()
            with _ACTIVE_LOCK:
                stores = list(_ACTIVE_STORES)
            for store in stores:
                try:
                    store._reaper_pass()
                except Exception:
                    import logging

                    logging.getLogger(__name__).debug(
                        "[jobs] reaper pass failed", exc_info=True
                    )

    def _reaper_pass(self) -> None:
        rows = self.conn.execute(
            "SELECT job_id, pid, started, cap FROM jobs WHERE exit_code IS NULL"
        ).fetchall()
        now = time.time()
        for r in rows:
            cap = float(r["cap"] or 0)
            over = cap > 0 and now - r["started"] > cap
            if not over:
                self._observe(r)
                continue
            # Cap exceeded. Mark FIRST, kill SECOND: the guarded UPDATE
            # (exit_code IS NULL) claims the finish while it's still
            # unclaimed — a racing poll() reaping the killed child can
            # only stamp a clean exit if it wins the claim, and the mark
            # here IS the timeout stamp. Killing after the mark also
            # closes the window where a wedged terminate-grace could
            # leave the row running-with-no-cap-owner.
            self._mark_finished(r["job_id"], exit_code=-9, timed_out=True)
            _terminate_proc_tree(int(r["pid"]))
            try:
                row = self._row(r["job_id"])
                if row is not None:
                    with open(row["log_file"], "a") as fh:
                        fh.write(
                            f"\n[{row['tool']} reaper] exceeded {cap:.0f}s "
                            "wall-clock; terminated\n"
                        )
            except OSError:
                pass

    # -- helpers -------------------------------------------------------------------

    def _get_parser(self, tool_name: str) -> Callable[[str], dict[str, Any]] | None:
        with _PARSERS_LOCK:
            return _PARSERS.get(tool_name)

    @staticmethod
    def _read_log(path: str) -> str:
        try:
            with open(path, errors="replace") as f:
                return f.read()
        except OSError:
            return ""

    @staticmethod
    def _tail(text: str, n: int) -> list[str]:
        lines = [ln for ln in text.splitlines() if ln.strip()]
        ansi = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
        lines = [ansi.sub("", ln).strip() for ln in lines]
        return [ln for ln in lines if ln][-n:]


def current_agent_id() -> str:
    """Identity the caller is asserting (ambient contextvar first; the
    executor/lane set it). Kept local to avoid a circular import — the
    value semantics match ``utils.agent_identity.current_agent_id``."""
    try:
        from utils.agent_identity import current_agent_id as _cia
        return _cia()
    except Exception:
        return "0"


# --- Module-level singleton (lazy) ----------------------------------------------

_store: JobStore | None = None
_store_key: str = ""


def get_store() -> JobStore:
    """Process-wide job store singleton. Env ``BG_JOB_STORE_DIR`` re-points
    the whole store (tests); the singleton caches PER OVERRIDE VALUE so
    repeated calls in one process share the instance (parsers, live
    handles). A new override value rebuilds; ``reset_store`` forces it."""
    global _store, _store_key
    override = os.getenv("BG_JOB_STORE_DIR", "").strip()
    if override:
        if _store is not None and _store_key == override:
            return _store
        _store = JobStore(jobs_dir=override)
        _store_key = override
        return _store
    if _store is None:
        _store = JobStore()
        _store_key = ""
    return _store


def reset_store() -> None:
    """Test hook: forget the singleton so the next get_store() re-reads env."""
    global _store, _store_key
    _store = None
    _store_key = ""