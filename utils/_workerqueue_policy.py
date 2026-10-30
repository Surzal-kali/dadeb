"""Admission-policy knobs and resource reads for the worker queue.

Everything the pool consults per admission decision that is not the
database itself: env-driven slot/queue/TTL knobs (re-read per call so
tests and operator overrides apply live), the /proc memory gates, the
kernel VmHWM sampler that feeds the RSS evidence ledger, and the heap
pin that rides a unit's launch env.

NOTE (patch-safety contract): ``free_ram_mib`` / ``_total_ram_mib`` /
``_ram_floor_mib`` deliberately STAY in ``utils/worker_queue.py`` — tests
monkeypatch them on the facade module, and facade-defined callers resolve
module globals at call time. Anything moved here must never call those
facade names internally."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from constants import resolve_workspace_root

_DEFAULT_ROOT = resolve_workspace_root()

_WORKER_SLOTS_DEFAULT = 2
_WORKER_QUEUE_MAX_DEFAULT = 16

# Queued rows older than this are swept (a queue entry is a REQUEST, not a
# commitment; the operator re-requests rather than inheriting a stale one).
_QUEUE_TTL_HOURS_DEFAULT = 24

# Recorded peak-RSS evidence lifetime — this outlives the ledger rows
# (finished rows age out weekly; the evidence the queue is supposed to
# LEARN from must not evaporate with them).
_EVIDENCE_TTL_HOURS_DEFAULT = 720.0


def _store_dir() -> Path:
    override = os.getenv("WORKER_QUEUE_DIR", "").strip()
    if override:
        return Path(override)
    return _DEFAULT_ROOT / "run" / "worker_queue"


def _slots() -> int:
    raw = os.getenv("WORKER_QUEUE_SLOTS", "").strip()
    try:
        val = int(raw) if raw else _WORKER_SLOTS_DEFAULT
    except ValueError:
        val = _WORKER_SLOTS_DEFAULT
    return max(1, val)


def _max_queued() -> int:
    raw = os.getenv("WORKER_QUEUE_MAX_Q", "").strip()
    try:
        val = int(raw) if raw else _WORKER_QUEUE_MAX_DEFAULT
    except ValueError:
        val = _WORKER_QUEUE_MAX_DEFAULT
    return max(1, val)


def _queue_ttl_hours() -> float:
    raw = os.getenv("WORKER_QUEUE_TTL_HOURS", "").strip()
    try:
        return float(raw) if raw else _QUEUE_TTL_HOURS_DEFAULT
    except ValueError:
        return _QUEUE_TTL_HOURS_DEFAULT


def _evidence_ttl_hours() -> float:
    raw = os.getenv("WORKER_QUEUE_EVIDENCE_TTL_HOURS", "").strip()
    try:
        return float(raw) if raw else _EVIDENCE_TTL_HOURS_DEFAULT
    except ValueError:
        return _EVIDENCE_TTL_HOURS_DEFAULT


def _rss_hwm_mib(pid: Any) -> float | None:
    """Peak resident set (VmHWM) of ONE process, in MiB.

    VmHWM is the kernel's own high-water mark — reading it once answers
    "worst footprint so far" with zero sampling bias; we never have to
    track growth ourselves. Only the MAIN pid of the unit's process tree
    is measured (the JVM that owns the job — its threads share its RSS;
    transient helpers are noise). Returns None when the pid exited
    (its /proc entry is gone — this is why the evidence for a fast unit
    comes from the samples taken WHILE it ran) or the read fails.
    """
    try:
        pid_n = int(pid or 0)
    except (TypeError, ValueError):
        return None
    if pid_n <= 0:
        return None
    try:
        with open(f"/proc/{pid_n}/status", encoding="ascii") as fh:
            for line in fh:
                if line.startswith("VmHWM:"):
                    return int(line.split()[1]) / 1024.0
    except (OSError, ValueError, IndexError):
        return None
    return None


def heap_pin_env(memory_budget: int, extra: dict[str, str] | None = None) -> dict[str, str]:
    """Build the launch env that PINS the worker's heap claim.

    ``JAVA_OPTS='-Xms<micromin>m -Xmx<memory_budget>m'`` — appended AFTER
    the jadx launcher script's ``DEFAULT_JVM_OPTS`` (which carries
    ``-XX:MaxRAMPercentage=70.0``); the JVM honours the LAST -X flag, so
    the explicit -Xmx overrides the percentage claim. The budget row and
    the kernel therefore agree: the pool admits N x budget, and each
    worker is hard-capped at its own budget. Caller env merges UNDER
    the pin (the pin wins — that's the point).
    """
    merged = dict(extra or {})
    pin = f"-Xms32m -Xmx{int(memory_budget)}m"
    existing = merged.get("JAVA_OPTS", "").strip()
    merged["JAVA_OPTS"] = (existing + " " + pin).strip() if existing else pin
    return merged