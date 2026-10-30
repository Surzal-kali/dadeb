"""Single background reaper thread for the job store (utils/job_store.py).

One thread per process services every live JobStore instance — no thread
per job, no thread per store. Stores self-register on construction; a
store dropped by its owner (per-test instances) is a WeakSet entry that
stops being reaped naturally. The reaper loop calls each registered
store's ``_reaper_pass()``; the per-store sweep logic stays on the store
(the thread infrastructure is the only thing that lives here)."""
from __future__ import annotations

import threading
import weakref
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - annotations only, never imported at runtime
    from utils.job_store import JobStore

_REAPER_THREAD: threading.Thread | None = None
_REAPER_WAKE = threading.Event()
# Live store instances the single background reaper services. Weak — a
# store dropped by its owner (per-test instances) stops being reaped.
_ACTIVE_STORES: "weakref.WeakSet[JobStore]" = weakref.WeakSet()
_ACTIVE_LOCK = threading.Lock()


def register(store: "JobStore") -> None:
    """Register this store for the ONE background reaper thread."""
    global _REAPER_THREAD
    with _ACTIVE_LOCK:
        _ACTIVE_STORES.add(store)
        if _REAPER_THREAD is not None and _REAPER_THREAD.is_alive():
            return
    _REAPER_THREAD = threading.Thread(
        target=_reaper_loop, name="job-store-reaper", daemon=True
    )
    _REAPER_THREAD.start()


def wake() -> None:
    """Nudge the reaper (an anchored event — a launch wants the next pass soon)."""
    _REAPER_WAKE.set()


def _reaper_loop() -> None:
    # Interval env read rides the facade knob (BG_JOB_REAPER_INTERVAL_S,
    # re-read per thread start); lazy import — this thread only starts
    # from job_store.register(), so the facade is fully loaded by then.
    from utils.job_store import _reaper_interval

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