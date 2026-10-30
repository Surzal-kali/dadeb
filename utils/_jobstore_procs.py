"""PID-liveness and kill-tree primitives for the background-job store.

Surgical process discipline for ``utils/job_store.py``: /proc starttime
ticks (the PID-reuse fence), zombie-aware terminate grace, and the
kill path itself. Pure /proc + os-level functions — no store state,
no env knobs. Callers decide when it is safe to signal; this module
decides what is safe to signal."""
from __future__ import annotations

import os
import signal
import time

# Process-liveness poll cadence inside a single terminate() await-grace loop.
_TERMINATE_GRACE_S = 5.0


def _terminate_proc_tree(
    pid: int, *, pid_start: float | None = None, started: float | None = None
) -> bool:
    """SIGTERM the process group (jobs spawn with start_new_session=True,
    so the pgid == pid), grace-wait, then SIGKILL stragglers. Surgical:
    never a global sweep, matching scale-doctrine rule 3.

    PID-fence: when the stored pid now belongs to a DIFFERENT process
    (start mismatch against the row's recorded /proc starttime ticks —
    legacy rows fall back to the ``started`` epoch estimate), nothing is
    signalled and False is returned — killing an innocent process that
    recycled the pid is the one unrecoverable outcome here.

    Grace detection has a zombie trap: a dead-but-unreaped child answers
    ``os.kill(pid, 0)`` successfully (the pid entry stays until waitpid).
    So each grace tick ALSO tries a nonblocking waitpid — for our own
    children that reaps the zombie instantly and ends the wait; for
    foreign pids the EINVAL/ChildError is ignored and kill(pid,0) decides.
    """
    if _pid_matches(pid, pid_start, started) is False:
        return False  # pid was recycled — refuse to signal the new occupant
    try:
        os.killpg(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            os.kill(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            return True
    import errno

    deadline = time.monotonic() + _TERMINATE_GRACE_S
    while time.monotonic() < deadline:
        # Reap if it's our child (WNOHANG: 0 = still running, pid = reaped).
        try:
            wpid, _status = os.waitpid(pid, os.WNOHANG)
            if wpid == pid:
                return True  # reaped — fully dead, no zombie trap
        except (ChildProcessError, OSError) as exc:
            if getattr(exc, "errno", None) == errno.ECHILD:
                pass  # not our child — fall through to the pid probe
            else:
                pass  # transient; the probe decides
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True  # exited (and someone else reaped it)
        except (PermissionError, OSError):
            return True  # alive but not signalable further
        time.sleep(0.2)
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass
    return True


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


def _clock_ticks_per_second() -> float:
    try:
        return float(os.sysconf(os.sysconf_names["SC_CLK_TCK"]))
    except (KeyError, ValueError, OSError, AttributeError):
        return 100.0  # Linux default


def _proc_boot_epoch() -> float | None:
    """Boot time (epoch seconds) from the btime line of /proc/stat."""
    try:
        with open("/proc/stat", "r") as fh:
            for line in fh:
                if line.startswith("btime "):
                    return float(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return None


def _proc_start_ticks(pid: int | None) -> float | None:
    """Field 22 of /proc/<pid>/stat — the process's starttime in clock
    ticks since boot. Comm (field 2) may contain spaces and parens, so
    parse after the LAST ')'. Raw ticks are deliberately preferred over
    a btime-derived epoch (jiffies freeze across suspend while the wall
    clock advances, so ONLY the raw-tick compare is suspension-immune)."""
    if not pid:
        return None
    try:
        with open(f"/proc/{int(pid)}/stat", "rb") as fh:
            data = fh.read().decode("utf-8", "replace")
    except (OSError, ValueError):
        return None
    rparen = data.rfind(")")
    if rparen < 0:
        return None
    fields = data[rparen + 1 :].split()
    if len(fields) < 20:
        return None
    try:
        return float(fields[19])
    except ValueError:
        return None


def _epoch_from_ticks(
    ticks: float, btime: float | None = None
) -> float | None:
    """Epoch estimate for a starttime-ticks value (legacy rows only)."""
    if btime is None:
        btime = _proc_boot_epoch()
    if btime is None:
        return None
    return btime + ticks / _clock_ticks_per_second()


_PID_START_LEGACY_TOL_S = 3.0


def _pid_matches(
    pid: int | None,
    pid_start: float | None = None,
    started: float | None = None,
) -> bool | None:
    """Does the pid recorded on a row still name the SAME process?

    - New rows store raw ``/proc`` starttime ticks (``pid_start``): the
      compare is exact and definitive — False means the pid was reused
      by a different process.
    - Legacy rows (``pid_start`` NULL) fall back to an epoch estimate
      from the ticks against the row's ``started`` timestamp with a
      small tolerance (wall-clock skew between Popen and the row write).
      Suspend in the window can skew the estimate, so a legacy mismatch
      is trusted only in the SAFE direction (refusing to signal), never
      for stamping a live row finished.
    - ``None`` (no pid, /proc missing, /proc/stat unreadable) — cannot
      verify; callers keep today's behavior.
    """
    ticks = _proc_start_ticks(pid)
    if ticks is None:
        return None
    if pid_start is not None:
        return abs(ticks - float(pid_start)) < 0.5
    if started is not None:
        est = _epoch_from_ticks(ticks)
        if est is None:
            return None
        return abs(est - float(started)) <= _PID_START_LEGACY_TOL_S
    return None