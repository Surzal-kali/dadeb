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

# Log garbage collect (2026-10-29): ROWS are collected (TTL sweep + per-agent
# finished cap) but the LOG FILES they pointed at under run/jobs/<tool>/ were
# never deleted — an unbounded disk leak on a busy fleet. BG_LOG_GC_HOURS is
# the keep-window for files of collected rows (keep it comfortably above
# BG_JOB_TTL_HOURS so a row that is still known is never GC'd early);
# BG_LOG_GC_INTERVAL_S throttles repeated passes. Files younger than the
# window keep existing even if their row is already gone — so a still-writing
# job of a not-yet-collected row, or an unflushed writer of a very fresh row,
# is never truncated out from under its process.
_JOBS_LOG_GC_HOURS_DEFAULT = 48.0
_JOBS_LOG_GC_INTERVAL_DEFAULT = 1800.0

# Debounced GC state (module-level, not per-store: any instance's pass
# counts). Zero = never ran — the first pass after import proceeds.
_LOG_GC_LAST = 0.0
_LOG_GC_LOCK = threading.Lock()

# Process-liveness poll cadence inside a single terminate() await-grace loop.
_TERMINATE_GRACE_S = 5.0

_REAPER_THREAD: threading.Thread | None = None
_REAPER_WAKE = threading.Event()
# Live store instances the single background reaper services. Weak — a
# store dropped by its owner (per-test instances) stops being reaped.
_ACTIVE_STORES: "weakref.WeakSet[JobStore]" = weakref.WeakSet()
_ACTIVE_LOCK = threading.Lock()

# Live children OF THIS PROCESS, process-scoped — deliberately NOT
# per-instance. The env-keyed singleton may legitimately rebuild mid-flight
# (its env reads race fixture teardown lanes), and every JobStore instance
# created for a directory coexists with every other while the reaper holds
# them; but a launched child is this PROCESS's child no matter which
# instance did the Popen. A per-instance live-proc register meant the
# observation path (_observe) could poll through an instance that never saw
# the Popen and fall to the cross-lane pid probe — which reports the
# unreaped zombie ALIVE forever, stalling every drain that touches that
# job (found live 2026-10-30: two instances in one fixture window, launch
# on one, polls on the other, exit never observed). One registry + one
# lock; any instance's poll can reap any child this process launched.
_LIVE_CHILD_PROCS: dict[str, subprocess.Popen] = {}
_LIVE_LOG_FHS: dict[str, Any] = {}
_LIVE_CHILDREN_LOCK = threading.Lock()


def _jobs_root() -> Path:
    override = os.getenv("BG_JOB_STORE_DIR", "").strip()
    return Path(override) if override else _DEFAULT_JOBS_DIR


def _ttl_hours() -> float:
    raw = os.getenv("BG_JOB_TTL_HOURS", "").strip()
    return float(raw) if raw else _JOBS_TTL_HOURS_DEFAULT


def _reaper_interval() -> float:
    raw = os.getenv("BG_JOB_REAPER_INTERVAL_S", "").strip()
    return float(raw) if raw else _REAPER_INTERVAL_S_DEFAULT


def _log_gc_hours() -> float:
    raw = os.getenv("BG_LOG_GC_HOURS", "").strip()
    return float(raw) if raw else _JOBS_LOG_GC_HOURS_DEFAULT


def _log_gc_interval() -> float:
    raw = os.getenv("BG_LOG_GC_INTERVAL_S", "").strip()
    return float(raw) if raw else _JOBS_LOG_GC_INTERVAL_DEFAULT


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

    Concurrency model (2026-10-29 hardening — matched to fleet_scheduler):
    - **Per-thread connections** (threadlocal): the pre-hardening shared
      connection (``check_same_thread=False``) raced the reaper thread
      against poll threads on ONE cursor set — the InterfaceError seen in
      the TTL test was this. ``self.conn`` stays valid: a property that
      returns the CALLING thread's own connection.
    - **Autocommit mode** (``isolation_level=None``): no implicit tx
      hiding multi-statement writes; every multi-write critical section
      takes ``BEGIN IMMEDIATE`` explicitly — sqlite's file lock is the
      cross-process mutex (gateway vs Brain vs REPL are separate
      processes).
    - Single-statement writes (INSERT row, guarded finish-stamp) rely on
      sqlite's statement atomicity under autocommit; the guarded
      (``AND exit_code IS NULL``) shape keeps first-marker-wins semantics
      working across processes.
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

        self._sqlite3 = sqlite3
        self.db_lock = threading.RLock()
        self._local = threading.local()
        self._bootstrap = sqlite3.connect(
            self.db_path, timeout=30.0, check_same_thread=False,
            isolation_level=None,
        )
        self._bootstrap.row_factory = sqlite3.Row
        self._bootstrap.execute("PRAGMA busy_timeout=30000")
        self._bootstrap.execute("PRAGMA journal_mode=WAL")
        # Live-handle note: the Popen + log fh are process-scoped module
        # registries (_LIVE_CHILD_PROCS / _LIVE_LOG_FHS, module level), NOT
        # per-instance — see their comment there. This instance holds only
        # row-facing state; observation and handle-closing work identically
        # from any instance (the env-keyed singleton rebuilds, so instance
        # identity is not a reliable handle owner).
        # Worker-queue instance bound to THIS store (Phase 3). Resolved lazily
        # on the first launch that lands in this store, and cached for the
        # store's lifetime: the reaper thread later reads it without ANY env
        # dependency (the env-keyed singleton raced the teardown boundary).
        self._worker_queue: Any = None
        self._init_tables()
        self._ensure_reaper()

    def _advance_worker_queue(self) -> None:
        """Bound advance: resolve + cache the worker-queue at first use (the
        first launch happens inside the owning fixture's env window), then
        re-read it per reaper pass with zero env reads."""
        if self._worker_queue is None:
            try:
                from utils.worker_queue import get_worker_queue

                self._worker_queue = get_worker_queue()
            except Exception:
                return  # no queue constructible — skip, don't loop back later
        self._worker_queue.advance_queue()

    @property
    def conn(self):
        """The CALLING thread's connection (created on first use).

        External callers that read ``store.conn`` directly keep working —
        and get a connection they own, so a concurrent writer can never
        trip their cursor mid-read (the InterfaceError class). They use it
        read-only; all write paths go through the scheduler-facing API.
        """
        c = getattr(self._local, "conn", None)
        if c is None:
            c = self._sqlite3.connect(
                self.db_path, timeout=30.0, check_same_thread=True,
                isolation_level=None,
            )
            c.row_factory = self._sqlite3.Row
            c.execute("PRAGMA busy_timeout=30000")
            c.execute("PRAGMA journal_mode=WAL")
            self._local.conn = c
        return c

    def _immediate(self) -> None:
        """Open a cross-process-atomic write section (BEGIN IMMEDIATE —
        eager RESERVED lock; busy_timeout starves the contender politely
        instead of failing)."""
        self.conn.execute("BEGIN IMMEDIATE")

    def _commit(self) -> None:
        self.conn.execute("COMMIT")

    def _rollback(self) -> None:
        self.conn.execute("ROLLBACK")

    # -- schema ---------------------------------------------------------------

    def _init_tables(self) -> None:
        # Bootstrap conn, autocommit — single-threaded construction moment.
        c = self._bootstrap
        c.execute(
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
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_jobs_agent_started "
            "ON jobs(agent_id, started DESC)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_jobs_running "
            "ON jobs(agent_id) WHERE exit_code IS NULL"
        )

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

        Failure discipline: if the post-spawn row INSERT fails (locked DB,
        disk full, killed lane), the already-spawned child is terminated,
        reaped and deregistered — a launch can never leave an UNRECORDED
        running process behind (invisible job, permanently held slot,
        prompt-blocking stdin) — and no row is ever written for a child
        whose process failed to spawn.
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
        try:
            proc = subprocess.Popen(
                command,
                stdout=log_fh,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                text=True,
                start_new_session=True,
                env=env,
            )
        except BaseException:
            # Spawn failed (bad argv / missing binary): no process exists,
            # but neither the log handle nor its file may leak — a job that
            # never was leaves no sidecar.
            log_fh.close()
            try:
                log_path.unlink()
            except OSError:
                pass
            raise
        # Register the live handles BEFORE the row INSERT (the reaper
        # consults them from the moment the row appears). On an INSERT
        # failure the launch is rolled DOWN: kill the spawned tree first
        # (it must not outlive a rejected launch), close the log, then
        # drop the handles.
        with _LIVE_CHILDREN_LOCK:
            _LIVE_CHILD_PROCS[job_id] = proc
            _LIVE_LOG_FHS[job_id] = log_fh
        with self.db_lock:
            self._immediate()
            try:
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
                self._commit()
            except BaseException:
                try:
                    self._rollback()
                except Exception:
                    pass
                _terminate_proc_tree(proc.pid)
                try:
                    proc.wait(timeout=5)  # reap — no zombie, no ghost pid
                except Exception:
                    pass
                try:
                    log_fh.close()
                except Exception:
                    pass
                with _LIVE_CHILDREN_LOCK:
                    _LIVE_CHILD_PROCS.pop(job_id, None)
                    _LIVE_LOG_FHS.pop(job_id, None)
                # Do NOT write the row: an envelope with a pid but no row
                # would hand the model a job_id every poll answers with
                # "unknown". Fail honestly instead.
                raise
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
        with _LIVE_CHILDREN_LOCK:
            proc = _LIVE_CHILD_PROCS.get(job_id)
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
        with self.db_lock:
            self._immediate()
            try:
                cur = self.conn.execute(
                    "UPDATE jobs SET exit_code = ?, finished_at = ?, "
                    "timed_out = ? WHERE job_id = ? AND exit_code IS NULL",
                    (exit_code, time.time(), 1 if timed_out else 0, job_id),
                )
                self._commit()
            except BaseException:
                try:
                    self._rollback()
                except Exception:
                    pass
                raise
        self._close_live_handles(job_id)

    def _close_live_handles(self, job_id: str) -> None:
        with _LIVE_CHILDREN_LOCK:
            fh = _LIVE_LOG_FHS.pop(job_id, None)
            _LIVE_CHILD_PROCS.pop(job_id, None)
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

        # Finished-cap enforcement on the done transition: launch-time-only
        # enforcement missed jobs that finished while the agent kept
        # launching (8 finished rows survived with cap=4 in the concurrency
        # hammer). Observing done is the point where a slot actually frees.
        if status == "done":
            self._enforce_caps(row["agent_id"])

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
            # Live pid while running (row-stamped for cross-lane polls) —
            # /proc readers (worker-queue VmHWM sampling, watchers) need it
            # without reaching into the raw row.
            "pid": row["pid"],
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
        with _LIVE_CHILDREN_LOCK:
            proc = _LIVE_CHILD_PROCS.get(job_id)
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
        with self.db_lock:
            self._immediate()
            try:
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
                self._commit()
            except BaseException:
                try:
                    self._rollback()
                except Exception:
                    pass
                raise
        # Row collection ran (cap / TTL) — piggyback the log GC. Throttled;
        # never raises; a GC failure cannot break launch/poll.
        self._log_garbage_collect()

    # -- log garbage collect ------------------------------------------------------

    def _log_garbage_collect(self, *, force: bool = False) -> dict[str, Any]:
        """Collect LOG FILES of jobs whose ROWS are already gone.

        The rows are collected (TTL sweep + per-agent finished-cap) but the
        runner log files under ``run/jobs/<tool>/`` they point at were never
        deleted — an unbounded disk leak on a busy fleet. This closes it with
        the same discipline as the row collection: never break the lane.

        - **Mtime, not rows**: deletion is decided by the file's own age
          against the keep-window (``BG_LOG_GC_HOURS``, default 48h, read
          per call). Files younger than the window keep existing even if
          their row is already gone — so an unflushed writer of a very
          fresh row is never truncated, and a log of a not-yet-collected
          row is never removed before the row's TTL.
        - **Order**: file first, then the empty per-tool dir (an active
          tool's dir reappears on its next launch).
        - **Throttled**: at most one real pass per
          ``BG_LOG_GC_INTERVAL_S`` (default 30 min) per process beyond the
          anchor points. ``force=True`` bypasses the wait — tooling that
          wants a pass NOW gets one — but a completed pass counts toward
          the interval either way, so back-to-back invocations (a tooling
          call right after an anchored pass) never scan twice.
        - Log files written to an explicit per-call ``log_dir`` live
          OUTSIDE the store's tree — their owning tool collects them.

        Runs anchored at row-collection points (``_enforce_caps`` and the
        reaper pass). A lane that is neither launching nor reaping jobs can
        also call :func:`garbage_collect_logs` — otherwise its local files
        wait for the next anchor pass, the same residency caveat as the
        row sweeps. Every step is best-effort, never raises.
        """
        try:
            gc_hours = _log_gc_hours()
        except ValueError:
            gc_hours = _JOBS_LOG_GC_HOURS_DEFAULT
        if gc_hours <= 0:
            return {"deleted": 0, "disabled": True}
        global _LOG_GC_LAST
        with _LOG_GC_LOCK:
            if time.time() - _LOG_GC_LAST < _log_gc_interval() and not force:
                return {"deleted": 0, "skipped": "interval"}
            _LOG_GC_LAST = time.time()
        cutoff = time.time() - gc_hours * 3600
        deleted = 0
        try:
            for tool_dir in self.jobs_dir.iterdir():
                try:
                    if not tool_dir.is_dir():
                        continue  # jobs.db / WAL sidecars
                    for log in tool_dir.iterdir():
                        try:
                            st = log.stat()
                        except OSError:
                            continue
                        if not log.is_file() or st.st_mtime > cutoff:
                            continue
                        try:
                            log.unlink()
                            deleted += 1
                        except OSError:
                            pass
                    try:
                        next(tool_dir.iterdir())
                    except StopIteration:
                        try:
                            tool_dir.rmdir()
                        except OSError:
                            pass
                except OSError:
                    pass
        except OSError:
            pass
        return {"deleted": deleted}

    def sweep(self) -> dict[str, int]:  # pragma: no cover - thin wrapper
        """Manual TTL sweep (cleanup tooling); returns row counts."""
        cutoff = time.time() - _ttl_hours() * 3600
        with self.db_lock:
            self._immediate()
            try:
                cur = self.conn.execute(
                    "DELETE FROM jobs WHERE finished_at IS NOT NULL AND finished_at < ?",
                    (cutoff,),
                )
                self._commit()
                return {"expired": cur.rowcount}
            except BaseException:
                try:
                    self._rollback()
                except Exception:
                    pass
                raise

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
        # Advance the worker queue (Phase 3): free finished-launched
        # worker slots and launch-promote queued heads. Best-effort, one
        # pass per reaper tick — never breaks job reaping.
        #
        # Bound to THIS store, not the env-keyed singleton: the reaper
        # thread is process-global and its env reads race the test
        # fixtures' patch/unpatch (found live 2026-10-30 — reaper-driven
        # advance_queue hit the wrong queue DB across a fixture boundary).
        # The queue instance is resolved ONCE per store from the env at
        # first launch (launch() runs inside the live fixture window), so
        # later env changes can never re-point a running store's advance.
        try:
            self._advance_worker_queue()
        except Exception:
            import logging

            logging.getLogger(__name__).debug(
                "[jobs] worker-queue advance failed", exc_info=True
            )
        self._log_garbage_collect()

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


def garbage_collect_logs(force: bool = False) -> dict[str, Any]:
    """Operator/tooling entry for the log-file garbage collect (docs: the
    ``_log_garbage_collect`` method). Idle lanes that never launch jobs can
    run this instead of waiting for the next launch-anchored pass."""
    return get_store()._log_garbage_collect(force=force)