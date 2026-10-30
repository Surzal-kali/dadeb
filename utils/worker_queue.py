"""Worker queue — bounded-memory process pool over the job store (Phase 3).

Doctrine §13 (scaling.txt): Arch-D units (jadx per-APK, Burp per-app-JVM)
are constrained by LOCAL MEMORY, not by target-host courtesy. The fleet
scheduler's accounting axis is the target host; here the axis is the
WORKER POOL on the operator box. Not a process supervisor — units launch
via ``utils/job_store`` exactly like fleet units; this module answers ONE
question per request and owns queue bookkeeping:

    "May this work START now (memory + slots), is it ALREADY running or
    queued under its dedupe key, or must it wait in the queue — and who
    advances the queue when a worker frees up?"

Design constraints, evidence-backed (2026-10-30):

- **Real jadx units hit multi-GB RSS** — upstream issues report >9 GB for
  a ~150 MB APK (TikTok, #2457), 11.35 GB for a 200 MB jar (#2170),
  >35 GB unchecked on a large app (#2189); synthetic small corpora sit at
  ~300 MB (measured on this box, VmHWM, flat across -j 1..16). So the
  per-unit memory claim is NOT a constant: the operator sets it per
  request (``memory_budget``) and the pool admits against measured FREE
  memory.
- **jadx's default JVM policy is uncoordinated**: the launcher sets
  ``-XX:MaxRAMPercentage=70.0``, computed by EACH JVM against TOTAL
  physical RAM — N concurrent instances each believe they may take 70%
  of the box (they don't coordinate). The queue therefore PINS each
  launch's heap centrally: the stored env gets
  ``JAVA_OPTS="… -Xmx<memory_budget>m"`` (last-wins on the JVM command
  line, after the launcher script's DEFAULT_JVM_OPTS) — the row's
  budget IS the worker's claim, not a percentage of the box.
- **Admission is arithmetic, not vibes**: a unit starts only when
  (a) a pool slot is free and (b) free RAM minus the pool's reservation
  floor covers the running claims PLUS this unit's budget. A unit that
  fails either is QUEUED, not refused — the lossy failure the queue
  exists to prevent is OOM-killing a STARTED unit (its work dies
  mid-decompile); waiting costs nothing but time.
- **Claims are evidence-backed, not operator-guessed** (RSS feedback,
  2026-10-30): every running unit's peak RSS is read from the kernel's
  VmHWM high-water mark at each observation point (poll_unit +
  advance_queue's release loop), and a finished unit's measured worst
  footprint is recorded into a small evidence table (one row per
  content key, MAX-of-runs, 30d TTL — deliberately outliving the
  weekly ledger rows). Future admissions of the SAME content bytes add
  the measured NATIVE OVERHEAD of the recording run
  (``recorded_peak - recorded_pin``, the pair kept from the same run)
  to this run's declared budget: a JVM's RSS is its -Xmx pin plus a
  roughly-fixed native overhead (metaspace, code cache, GC structures,
  thread stacks), so the claim tracks the heap the way real memory
  scales — "lower the budget" stays an honest remedy and only a pin
  above ``capacity - measured_overhead`` refuses permanently. Legacy
  evidence rows without a recorded pin fall back to the old
  ``max(budget, recorded_peak)`` absolute model. The claim is stamped
  additively on the envelope
  (``claim_mib``/``evidence_peak_mib`` — a plain-budget envelope stays
  byte-identical). The ``-Xmx`` heap PIN stays the operator's declared
  budget — evidence is accounting, not JVM config; the envelope
  suggests raising it. An evidence-backed claim above
  total-minus-floor refuses like any other permanent impossibility (a
  box that cannot back these bytes' MEASURED appetite will not admit
  them with a token claim and queue-wedge instead).
- **Hard caps keep the queue honest** (2026-10-30 review): a budget
  above total RAM minus the floor is a PERMANENT impossibility — free
  RAM is bounded by total, so queueing it would wedge the FIFO forever;
  such requests are refused (``budget_impossible``) and advance_queue
  cancels any legacy row like that instead of blocking behind it. When
  free RAM is UNMEASURABLE (``/proc/meminfo`` unreadable) admission
  FAILS CLOSED (``memory_unmeasurable``) — an unverifiable claim is a
  refusal, not a maybe. Transient shortfalls (slots, free-RAM-now)
  still queue.
- **Two clocks** (2026-10-30 review): ``requested`` is the queue-ENTRY
  time and is never rewritten on promotion (fairness order); the
  bind-grace sweep reads the ``launching_at`` claim stamp instead —
  measured from entry, a long-queued unit would be killed at the
  instant it finally launches.
- **Launch is inline and atomic** (the fleet-scheduler roll-down
  precedent): admission claims the row (\'launching\'), launches through
  the job store OUTSIDE the DB transaction, then binds — an INSERT-fail
  class error deletes the claim (no phantom row); a bind never happens
  for a child that failed to spawn. Queued units are LAUNCHED BY THE
  QUEUE itself on ``advance_queue()`` (runs on the job-store reaper pass
  + from any poller): the row stores the resolved argv + env, so
  promotion needs no tool code in any lane.

Concurrency primitives (Annex E rule of record): per-thread connections,
autocommit + explicit ``BEGIN IMMEDIATE`` critical sections for every
multi-statement sequence, guarded UPDATEs where races are possible
(queue-advance is a conditional UPDATE claiming ``queued → launching``
— first promoter wins; the loser sees an empty claim count and moves on).

Knobs (env, read per call):
- ``WORKER_QUEUE_DIR``      store dir (default ``run/worker_queue``; env
  override re-points the whole store for tests)
- ``WORKER_QUEUE_SLOTS``    max concurrently RUNNING units (default 2)
- ``WORKER_QUEUE_RAM_FLOOR`` minimum FREE RAM the pool itself needs to
  admit/keep running units, in MiB (default: 25% of total RAM, min 2048)
- ``WORKER_QUEUE_MAX_Q``    max queued rows per tool (default 16; a queue
  that deep means the operator should rethink the pool size)
- ``WORKER_QUEUE_EVIDENCE_TTL_HOURS``  how long recorded peak-RSS evidence
  stays (default 720 = 30 days; the ledger row TTLs are separate)
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from utils._workerqueue_keys import content_key
from utils._workerqueue_policy import (
    _evidence_ttl_hours,
    _max_queued,
    _queue_ttl_hours,
    _rss_hwm_mib,
    _slots,
    _store_dir,
    heap_pin_env,
)

# Decision statuses (queue rows): 'queued' -> 'launching' -> (job store
# owns running/done/failed from here); terminals: 'cancelled' (operator
# stop / crash reclaim), 'finished' (ran, exited, slot freed — SUCCESS)
# and 'failed' (job died: crash, OOM, timeout — a failed unit is a
# tombstone that never dedupes; re-request re-admits it fresh, 2026-10-30
# code review).
_QUEUE_STATUS = ("queued", "launching", "launched", "cancelled", "finished",
                 "failed")

def _total_ram_mib() -> int:
    """Total physical RAM in MiB (best effort; 0 = unknown)."""
    try:
        with open("/proc/meminfo", encoding="ascii") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    return 0


def free_ram_mib() -> int:
    """Currently AVAILABLE RAM in MiB — the admission gate's numerator.

    ``MemAvailable`` (not ``MemFree``): it counts reclaimable page cache,
    which is what the kernel would actually hand a new JVM. Best-effort:
    on an exotic platform without the field, fall back to
    ``MemFree`` + ``Cached``; on failure return 0 (which degrades the
    admission gate to "cannot admit" — the conservative reading).
    """
    fields: dict[str, int] = {}
    try:
        with open("/proc/meminfo", encoding="ascii") as fh:
            for line in fh:
                key, _, rest = line.partition(":")
                fields[key.strip()] = int(rest.split()[0]) // 1024
    except (OSError, ValueError, IndexError):
        return 0
    if "MemAvailable" in fields:
        return fields["MemAvailable"]
    return max(0, fields.get("MemFree", 0) + fields.get("Cached", 0))


def _ram_floor_mib() -> int:
    """Pool-wide floor: FREE memory that must remain for the REST of the
    box when the pool is fully loaded. Default 25% of total, min 2 GiB —
    the operator's own tooling/lane must not starve because decompiles
    filled the box."""
    raw = os.getenv("WORKER_QUEUE_RAM_FLOOR", "").strip()
    if raw:
        try:
            return max(0, int(raw))
        except ValueError:
            pass
    total = _total_ram_mib()
    if total <= 0:
        return 2048
    return max(2048, total // 4)


# --- store ------------------------------------------------------------------


def _set_wal(c: sqlite3.Connection) -> None:
    """Tolerate the first-converter WAL race (see fleet_scheduler._set_wal)."""
    for attempt in range(3):
        try:
            c.execute("PRAGMA journal_mode=WAL")
            return
        except sqlite3.OperationalError:
            row = c.execute("PRAGMA journal_mode").fetchone()
            if row is not None and (row[0] or "").lower() == "wal":
                return
            time.sleep(0.05 * (attempt + 1))
    row = c.execute("PRAGMA journal_mode").fetchone()
    if row is None or (row[0] or "").lower() != "wal":
        c.execute("PRAGMA journal_mode=WAL")  # surface the real error


class WorkerQueue:
    """SQLite-backed bounded-memory queue over the job store.

    Concurrency model: per-thread connections, autocommit + BEGIN
    IMMEDIATE critical sections, guarded UPDATEs (Annex E, same as the
    job/fleet stores; the claim UPDATE in ``advance_queue`` is the
    cross-race point: two lanes promoting the SAME queued row must
    yield exactly one launch).
    """

    def __init__(self, store_dir: str | Path | None = None):
        base = Path(store_dir) if store_dir else _store_dir()
        base.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(base, 0o700)
        except OSError:
            pass
        self.db_path = str(base / "worker_queue.db")
        self._sqlite3 = sqlite3
        self.db_lock = threading.RLock()
        self._local = threading.local()
        self._bootstrap = sqlite3.connect(
            self.db_path, timeout=30.0, check_same_thread=False,
            isolation_level=None,
        )
        self._bootstrap.row_factory = sqlite3.Row
        self._bootstrap.execute("PRAGMA busy_timeout=30000")
        _set_wal(self._bootstrap)
        self._init_table()

    @property
    def conn(self):
        """The CALLING thread's connection (Annex E convention; external
        readers that touch ``.conn`` directly get one they own)."""
        c = getattr(self._local, "conn", None)
        if c is None:
            c = self._sqlite3.connect(
                self.db_path, timeout=30.0, check_same_thread=True,
                isolation_level=None,
            )
            c.row_factory = self._sqlite3.Row
            c.execute("PRAGMA busy_timeout=30000")
            _set_wal(c)
            self._local.conn = c
        return c

    def _immediate(self) -> None:
        self.conn.execute("BEGIN IMMEDIATE")

    def _commit(self) -> None:
        self.conn.execute("COMMIT")

    def _rollback(self) -> None:
        self.conn.execute("ROLLBACK")

    def _add_column(self, c: Any, ddl: str, table: str = "worker_units") -> None:
        """Race-tolerant schema migration: run ``ALTER TABLE ADD COLUMN``
        and tolerate ONLY the duplicate-column error another concurrent
        migration may have already fixed. Any other failure re-raises."""
        try:
            c.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")
        except sqlite3.OperationalError as exc:
            if "duplicate column" not in str(exc).lower():
                raise

    def _init_table(self) -> None:
        c = self._bootstrap
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS worker_units (
                unit_key       TEXT NOT NULL,
                tool           TEXT NOT NULL,
                target         TEXT NOT NULL,
                agent_id       TEXT NOT NULL,
                status         TEXT NOT NULL,          -- queued|launching|launched|cancelled
                memory_budget  INTEGER NOT NULL,       -- MiB pinned per worker
                command        TEXT NOT NULL,          -- JSON argv, stored so PROMOTION needs no tool code
                env            TEXT,                   -- JSON env dict (JAVA_OPTS heap pin)
                job_id         TEXT,
                queued_at      REAL NOT NULL,
                requested      REAL,                   -- first request ts (fairness order; never rewritten)
                launching_at   REAL,                   -- queued->launching claim ts (the bind-grace clock)
                launched_at    REAL,
                log_file       TEXT,
                note           TEXT,
                PRIMARY KEY (unit_key)
            )
            """
        )
        # Legacy-store migration: launching_at and peak_rss_mib postdate the
        # first schema. Race-tolerant ALTERs — check-then-ALTER has a TOCTOU
        # window (two instances starting together both pass the check and one
        # ALTER crashes on the duplicate), so just ALTER and tolerate the
        # winner's duplicate-column error (2026-10-30 code review).
        self._add_column(c, "launching_at REAL")
        self._add_column(c, "peak_rss_mib REAL")
        # The operator's REQUESTED budget (the heap pin), kept beside the
        # accounting claim: the RSS-feedback delta model needs the pin of
        # the recording run, since memory_budget alone holds the
        # (already-escalated) claim and would compound on re-reads.
        self._add_column(c, "budget_requested REAL")
        # Peak-RSS evidence (the RSS-feedback ledger): one row per content
        # key, MAX-of-runs — the WORST measured peak is what future
        # admissions must defend against. Deliberately separate from the
        # live ledger: finished rows age out weekly, evidence keeps
        # informing for a month.
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS worker_rss (
                unit_key      TEXT PRIMARY KEY,
                tool          TEXT NOT NULL,
                peak_rss_mib  REAL NOT NULL,
                memory_budget REAL NOT NULL,   -- the claim the finishing unit ran under
                budget_requested REAL,         -- the requested budget (heap pin) of that run; NULL = legacy row
                runs          INTEGER NOT NULL DEFAULT 1,
                finished_at   REAL NOT NULL,
                updated_at    REAL NOT NULL
            )
            """
        )
        self._add_column(c, "budget_requested REAL", table="worker_rss")
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_wq_status_req "
            "ON worker_units(status, requested)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_wq_tool_status "
            "ON worker_units(tool, status)"
        )

    # -- launch plumbing (the queue launches its own promoted units) ----------

    def _launch_claim(self, row: Any) -> dict[str, Any] | None:
        """Launch a claimed 'launching' row via the job store. Returns the
        launch envelope or None on failure (the claim is deleted — no
        phantom row). The env's JAVA_OPTS heap pin comes from the row."""
        from utils.job_store import get_store

        try:
            env = json.loads(row["env"] or "{}")
            command = json.loads(row["command"])
            try:
                timeout = float(os.getenv("WORKER_QUEUE_TIMEOUT", "").strip() or 3600.0)
            except ValueError:
                timeout = 3600.0
            # MERGE into the caller's environment — never replace it. A
            # Popen(env=replacement) gives the child ONLY the new dict: no
            # PATH (execvp then falls back to the compiled-in default and
            # silently ignores both the monkeypatched test stub and the
            # operator's custom bin dir), no HOME/TMPDIR/LANG. Found live
            # 2026-10-30: queue-launched units resolved /usr/bin/jadx
            # instead of the PATH stub, so JVM boot time (2-6s, worse under
            # load) replaced the 0.2s stub — the flake that looked like a
            # scheduling bug. The pin still WINS: it was merged last into
            # the row env, so it stays last in JAVA_OPTS.
            merged_env = dict(os.environ)
            merged_env.update(env)
            result = get_store().launch(
                command,
                tool_name=f"{row['tool']}_queue",
                agent_id=row["agent_id"],
                env=merged_env,
                timeout=timeout,
            )
        except Exception as exc:
            # Launch failed (spawn error / store down): delete the claim —
            # a 'launching' claim with no child is a Phantom (the row would
            # hold a slot forever). The caller's request is lost; honest
            # failure beats a wedged claim.
            self._delete_claim(row["unit_key"], f"launch failed: {exc}")
            return None
        bound = self.bind_unit(row["unit_key"], result["job_id"], result.get("log_file"))
        if bound.get("status") != "ok":
            # Rare: claim got cancelled between launch and bind (operator
            # cancelled + racing). The job runs but the pool never counted
            # it — kill it; slots must not leak.
            try:
                from utils.job_store import get_store as _gs

                _gs().stop(result["job_id"], force=True)
            except Exception:
                pass
            return None
        return result

    def _delete_claim(self, unit_key: str, reason: str) -> None:
        with self.db_lock:
            self._immediate()
            try:
                self.conn.execute(
                    "DELETE FROM worker_units WHERE unit_key = ? "
                    "AND status = 'launching' AND job_id IS NULL",
                    (unit_key,),
                )
                self._commit()
            except BaseException:
                try:
                    self._rollback()
                except Exception:
                    pass

    # -- admission ------------------------------------------------------------

    def rss_evidence_for(self, unit_key: str) -> dict[str, Any] | None:
        """Recorded peak-RSS evidence for a content key (None when this
        content's bytes never ran here, or their evidence aged out)."""
        r = self.conn.execute(
            "SELECT unit_key, tool, peak_rss_mib, memory_budget, "
            "budget_requested, runs, finished_at, updated_at "
            "FROM worker_rss WHERE unit_key = ?",
            (unit_key,),
        ).fetchone()
        return dict(r) if r is not None else None

    def rss_evidence(self) -> list[dict[str, Any]]:
        """The whole evidence table, newest first (small — one row per
        content key ever measured)."""
        rows = self.conn.execute(
            "SELECT unit_key, tool, peak_rss_mib, memory_budget, "
            "budget_requested, runs, finished_at, updated_at "
            "FROM worker_rss ORDER BY updated_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def _sample_unit_peak(self, unit_key: str, pid: Any) -> float | None:
        """Raise a unit's `peak_rss_mib` to the kernel's current VmHWM.
        Monotonic-by-construction (VmHWM never regresses), the guarded
        UPDATE tolerates double samples. Autocommit single statement —
        safe inside poll paths that hold no transaction. Returns the peak
        seen (None when the pid is gone — the LAST stored sample stands)."""
        peak = _rss_hwm_mib(pid)
        if peak is None:
            return None
        self.conn.execute(
            "UPDATE worker_units SET peak_rss_mib = ? WHERE unit_key = ? "
            "AND (peak_rss_mib IS NULL OR peak_rss_mib < ?)",
            (peak, unit_key, peak),
        )
        return peak

    def _record_evidence(self, unit_key: str) -> None:
        """Upsert one content key's evidence at finish: the unit's sampled
        peak next to the requested budget (heap pin) it ran under.
        MAX-of-runs — future admissions must defend against the worst
        measured peak of these bytes, not the most recent one. The
        (peak, pin) pair is kept FROM THE SAME RUN: a higher peak bumps
        both sides together, because the delta claim model reads the
        overhead as ``peak - pin`` and mixing pins between runs would
        invent overhead. A unit that finished without a single live
        sample (too fast even for one reaper pass) has no evidence to
        give — no row is written."""
        row = self.conn.execute(
            "SELECT tool, memory_budget, budget_requested, peak_rss_mib "
            "FROM worker_units WHERE unit_key = ?",
            (unit_key,),
        ).fetchone()
        if row is None or row["peak_rss_mib"] is None:
            return
        now = time.time()
        self.conn.execute(
            "INSERT INTO worker_rss (unit_key, tool, peak_rss_mib, "
            "memory_budget, budget_requested, runs, finished_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, 1, ?, ?) "
            "ON CONFLICT(unit_key) DO UPDATE SET "
            "memory_budget = excluded.memory_budget, "
            "runs = worker_rss.runs + 1, updated_at = excluded.updated_at, "
            "budget_requested = CASE "
            "WHEN COALESCE(excluded.peak_rss_mib, 0) > "
            "COALESCE(worker_rss.peak_rss_mib, 0) "
            "THEN excluded.budget_requested "
            "ELSE COALESCE(worker_rss.budget_requested, "
            "excluded.budget_requested) END, "
            "peak_rss_mib = MAX(COALESCE(worker_rss.peak_rss_mib, 0), "
            "excluded.peak_rss_mib)",
            (unit_key, row["tool"], row["peak_rss_mib"],
             row["memory_budget"], row["budget_requested"], now, now),
        )

    def _effective_claim(
        self, unit_key: str, memory_budget: int
    ) -> tuple[int, float | None]:
        """Evidence-backed admission claim, DELTA MODEL: a JVM's resident
        footprint is its heap pin (-Xmx) plus a roughly-fixed native
        overhead (metaspace, code cache, GC structures, thread stacks),
        so the measured overhead of a past run
        ``recorded_peak - recorded_pin`` is added to THIS run's pin —
        the claim tracks the heap pin the way real memory scales, and
        "lower the budget" is an honest remedy again (only a pin above
        ``capacity - measured_overhead`` refuses). Legacy evidence rows
        that predate ``budget_requested`` fall back to the old
        absolute-peak model (claim = max(budget, recorded_peak)). Returns
        ``(claim_mib, evidence_peak_mib)``; evidence_peak is None when no
        evidence exists or the measurement did not overrule the guess.
        The -Xmx heap PIN deliberately stays the operator's declared
        budget — evidence is ACCOUNTING, not a config override."""
        evidence = self.rss_evidence_for(unit_key)
        peak = evidence["peak_rss_mib"] if evidence else None
        if peak is None:
            return memory_budget, None
        pin = evidence.get("budget_requested") if evidence else None
        if pin is not None and pin > 0:
            claim = memory_budget + max(0.0, float(peak) - float(pin))
            if claim > memory_budget:
                return int(round(claim)), float(peak)
            return memory_budget, None
        if float(peak) > memory_budget:
            return int(round(float(peak))), float(peak)
        return memory_budget, None

    def account(self) -> dict[str, Any]:
        """Pool accounting snapshot: slots, running claims, free RAM,
        floor, and the max budget the pool could EVER admit. Pure
        observation — admission math lives here so callers and tests see
        ONE formula."""
        rows = self.conn.execute(
            "SELECT COALESCE(SUM(memory_budget), 0) AS claimed "
            "FROM worker_units WHERE status IN ('launching','launched')"
        ).fetchone()
        total = _total_ram_mib()
        floor = _ram_floor_mib()
        return {
            "tool": None,
            "slots": _slots(),
            "running_claims_mib": rows["claimed"] or 0,
            "ram_floor_mib": floor,
            "free_ram_mib": free_ram_mib(),
            "total_ram_mib": total,
            # Total minus floor: even an idle box can never back more than
            # this (free RAM is bounded by total). None when total RAM
            # itself is unmeasurable — then only the live free check runs.
            "budget_capacity_mib": (total - floor) if total > 0 else None,
        }

    def request_unit(
        self,
        tool: str,
        target: str,
        *,
        agent_id: str,
        memory_budget: int,
        command: list[str],
        env: dict[str, str] | None = None,
        note: str = "",
    ) -> dict[str, Any]:
        """Ask to START one Arch-D unit. Decision envelope — one shape per
        decision, no relabelling downstream:

        - ``{"decision": "duplicate", "state": "running"|"launching"|
          "queued", ...}`` — dedupe hit: a LIVE twin owns the content
          key. Its ref is in the envelope (``job_id`` when running/
          launching, ``position`` when queued) — poll it, never launch
          a new unit for the same bytes.
        - ``{"decision": "queued", "position": N}`` — THIS request waits
          for resources; the queue launch-promotes the head when it
          fits. Poll via ``poll_unit``.
        - ``{"decision": "launched", "job_id": ...}`` — admitted; the
          queue launched it inline (claim → job-store launch → bind,
          atomic here).
        - ``{"decision": "refused", "reason": ...}`` — policy refusals:
          ``budget_impossible`` (budget above total RAM − pool floor:
          even an idle box can never back it, a PERMANENT impossibility —
          queueing would wedge the FIFO forever), ``memory_unmeasurable``
          (free RAM unreadable — the admission gate fails closed),
          ``queue_full``, ``launch_failed``.

        Admission (the one formula, in order):
        1. Dedupe on content key — a live twin wins, labelled duplicate.
        2. Hard caps — permanent impossibility and unmeasurable free RAM
           refuse; nothing else ever waits in the queue forever.
        3. Slots: running < ``WORKER_QUEUE_SLOTS``.
        4. Memory math: running_claims + budget <= usable, where usable =
           free_ram_now - ram_floor (the pool's reservation for the rest
           of the box). Passing 2 but failing 3/4 ⇒ QUEUED (transient
           pressure, not policy — waiting is cheap, OOM is not).
        """
        if not agent_id:
            raise ValueError("worker queue requires a resolved agent_id")
        if memory_budget <= 0:
            raise ValueError("memory_budget must be a positive MiB integer")
        unit_key = content_key(tool, target, argv=command)
        now = time.time()
        # Heap pin decided HERE (centrally): the row's env carries it, the
        # launcher never overrides a budget at launch time. The PIN stays
        # the operator's declared budget even when evidence bumps the
        # claim (below) — pin is JVM config, claim is accounting.
        launch_env = heap_pin_env(memory_budget, env)
        # Evidence-backed claim: a past run of these exact bytes sets the
        # floor of what admission must be able to back (RSS feedback —
        # the operator's guess is overruled by the measurement, not
        # silently: the envelope stamps both values).
        with self.db_lock:
            self._immediate()
            try:
                claim_mib, evidence_peak = self._effective_claim(
                    unit_key, memory_budget
                )
                existing = self.conn.execute(
                    "SELECT * FROM worker_units WHERE unit_key = ?", (unit_key,)
                ).fetchone()
                # --- dedupe: an existing LIVE unit owns the key ---
                # (launching/launched/queued — a finished/cancelled/failed
                # row is terminal and falls through below.)
                if existing is not None and existing["status"] in (
                    "launching", "launched", "queued"
                ):
                    out = self._existing_envelope(existing)
                    self._commit()
                    return out
                # A finished identical unit still owns its key: same bytes
                # already ran to completion, so re-running is waste — point
                # at the finished run (its results stay retrievable by
                # job_id). Returning the row (not falling through) also
                # keeps the INSERT from colliding on the PK, which used to
                # raise IntegrityError here (found live 2026-10-30).
                if existing is not None and existing["status"] == "finished":
                    out = self._existing_envelope(existing)
                    self._commit()
                    return out
                # A cancelled row retracts the prior decision — a
                # re-request is a fresh one. A FAILED row is the same
                # retraction with a stronger reason: failures must not
                # dedupe (2026-10-30 code review) — every job the job
                # store marked done/failed used to leave a tombstone that
                # deduped, and release/cancel then refused to clear it, so
                # a crashed run was permanently un-retryable. Drop the
                # terminal row so the fresh INSERT can reuse the key
                # (release_unit's fresh-row promise).
                if existing is not None and existing["status"] in (
                    "cancelled", "failed"
                ):
                    self.conn.execute(
                        "DELETE FROM worker_units WHERE unit_key = ? AND "
                        "status IN ('cancelled','failed')",
                        (unit_key,),
                    )

                # --- admission arithmetic ---
                acct = self.account()
                # --- hard caps: refuse what queueing can never fix ---
                cap = acct["budget_capacity_mib"]
                if cap is not None and claim_mib > cap:
                    self._commit()
                    msg = (
                        f"claim {claim_mib} MiB exceeds this box's admission "
                        f"capacity ({acct['total_ram_mib']} MiB total - "
                        f"{acct['ram_floor_mib']} MiB pool floor = {cap} MiB)"
                    )
                    if evidence_peak is not None:
                        overhead = claim_mib - memory_budget
                        msg += (
                            f" — the requested budget was {memory_budget} MiB "
                            f"but a past run of these bytes measured "
                            f"{overhead:.0f} MiB above its heap pin "
                            f"(VmHWM {evidence_peak:.0f} MiB) and the claim "
                            "tracks that overhead"
                        )
                        msg += (
                            f"; a budget at or below {cap - overhead:.0f} MiB "
                            "would admit"
                        )
                    msg += (
                        ". Free RAM can never exceed total, so no amount of "
                        "queueing can admit it — lower the "
                        "budget or WORKER_QUEUE_RAM_FLOOR."
                    )
                    return {
                        "decision": "refused",
                        "reason": "budget_impossible",
                        "unit_key": unit_key,
                        "memory_budget": memory_budget,
                        "claim_mib": claim_mib,
                        "evidence_peak_mib": evidence_peak,
                        "budget_capacity_mib": cap,
                        "message": msg,
                    }
                if acct["free_ram_mib"] <= 0:
                    self._commit()
                    return {
                        "decision": "refused",
                        "reason": "memory_unmeasurable",
                        "unit_key": unit_key,
                        "message": (
                            "free RAM could not be measured (/proc/meminfo "
                            "missing or unparsable) — the admission gate "
                            "cannot be verified, so it fails closed instead "
                            "of queueing a unit that may never launch"
                        ),
                    }
                running = self.conn.execute(
                    "SELECT unit_key FROM worker_units "
                    "WHERE status IN ('launching','launched')"
                ).fetchall()
                n_running = len(running)
                claims = self.conn.execute(
                    "SELECT COALESCE(SUM(memory_budget), 0) AS c FROM worker_units "
                    "WHERE status IN ('launching','launched')"
                ).fetchone()["c"]
                usable = max(0, acct["free_ram_mib"] - acct["ram_floor_mib"])
                admissible = (
                    n_running < acct["slots"]
                    and claims + claim_mib <= usable
                    and acct["free_ram_mib"] - acct["ram_floor_mib"] >= claim_mib
                )

                queued_n = self.conn.execute(
                    "SELECT COUNT(*) AS n FROM worker_units WHERE status = 'queued'"
                ).fetchone()["n"]
                if not admissible and queued_n >= _max_queued():
                    out = {
                        "decision": "refused",
                        "reason": "queue_full",
                        "unit_key": unit_key,
                        "queue_depth": queued_n,
                        "queue_cap": _max_queued(),
                        "message": (
                            f"worker queue at cap ({queued_n}/{_max_queued()} "
                            "queued) and no slot fits — cancel stale queued rows, "
                            "raise WORKER_QUEUE_MAX_Q, raise WORKER_QUEUE_SLOTS, "
                            "or reduce per-unit memory budgets"
                        ),
                    }
                    self._commit()
                    return out

                if admissible:
                    # Claim INSIDE the tx (a racing duplicate must see the
                    # claim and dedupe), launch OUTSIDE it (the job store's
                    # own IMMEDIATE txs must not nest ours), bind right
                    # after. Insert-fail/launch-fail deletes the claim.
                    self.conn.execute(
                        "INSERT INTO worker_units "
                        "(unit_key, tool, target, agent_id, status, "
                        " memory_budget, budget_requested, command, env, "
                        " queued_at, requested, launching_at, note) "
                        "VALUES (?, ?, ?, ?, 'launching', ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            unit_key, tool, target, agent_id, claim_mib,
                            memory_budget,
                            json.dumps(command), json.dumps(launch_env),
                            now, now, now, note or "",
                        ),
                    )
                    self._commit()
                else:
                    # --- queued for resources (or slots) ---
                    self.conn.execute(
                        "INSERT INTO worker_units "
                        "(unit_key, tool, target, agent_id, status, "
                        " memory_budget, budget_requested, command, env, "
                        " queued_at, requested, note) "
                        "VALUES (?, ?, ?, ?, 'queued', ?, ?, ?, ?, ?, ?, ?)",
                        (
                            unit_key, tool, target, agent_id, claim_mib,
                            memory_budget,
                            json.dumps(command), json.dumps(launch_env),
                            now, now, note or "",
                        ),
                    )
                    position = self._queue_position(now, unit_key)
                    self._commit()
                    out = {
                        "decision": "queued",
                        "unit_key": unit_key,
                        "position": position,
                        "memory_budget": memory_budget,
                        "message": (
                            f"queued at position {position} — pool full or memory "
                            "short; the queue advances itself (job-store reaper "
                            "pass). Heap will be pinned via JAVA_OPTS when launched."
                        ),
                    }
                    self._stamp_claim(out, claim_mib, memory_budget, evidence_peak)
                    return out
            except BaseException:
                try:
                    self._rollback()
                except Exception:
                    pass
                raise

        # --- admitted: launch OUTSIDE the DB tx (the claim row is committed) ---
        claim = self.conn.execute(
            "SELECT * FROM worker_units WHERE unit_key = ?", (unit_key,)
        ).fetchone()
        launched = self._launch_claim(claim)
        if launched is None:
            # The claim was deleted (launch failed) — honest failure.
            out = {
                "decision": "refused",
                "reason": "launch_failed",
                "unit_key": unit_key,
                "message": (
                    "admitted but the launch failed (see job-store state); no "
                    "slot is held. Re-request after fixing the cause."
                ),
            }
            return out
        out = {
            "decision": "launched",
            "unit_key": unit_key,
            "job_id": launched["job_id"],
            "log_file": launched.get("log_file"),
            "memory_budget": memory_budget,
            "JAVA_OPTS": launch_env.get("JAVA_OPTS"),
            "message": (
                f"admitted and launched (job {launched['job_id']}); heap pinned "
                f"via JAVA_OPTS=-Xmx{memory_budget}m. Poll with poll_unit or "
                "poll_job."
            ),
        }
        self._stamp_claim(out, claim_mib, memory_budget, evidence_peak)
        return out

    def _stamp_claim(
        self,
        out: dict[str, Any],
        claim_mib: int,
        memory_budget: int,
        evidence_peak: float | None,
    ) -> None:
        """Additive envelope stamps for an evidence-backed claim — added
        only when the recorded peak actually overruled the guess (a
        plain-budget envelope stays byte-identical to pre-evidence shape)."""
        if evidence_peak is None or claim_mib <= memory_budget:
            return
        out["claim_mib"] = claim_mib
        out["evidence_peak_mib"] = evidence_peak
        overhead = claim_mib - memory_budget
        out["message"] += (
            f" (claim raised from {memory_budget} to {claim_mib} MiB — a past "
            f"run of this content measured {overhead:.0f} MiB above its heap "
            f"pin (VmHWM {evidence_peak:.0f} MiB); raise memory_budget if the "
            "heap pin should follow)"
        )

    def _queue_position(self, requested: float, unit_key: str) -> int:
        """1-based position of a queued row under the head's deterministic
        order — ``requested`` first, ``unit_key`` breaks exact ties (rows
        stamped in the same ``time.time()`` tick must not race on insertion
        luck). Every position count and the head SELECT share this order."""
        return self.conn.execute(
            "SELECT COUNT(*) AS n FROM worker_units WHERE status = 'queued' "
            "AND (requested < ? OR (requested = ? AND unit_key <= ?))",
            (requested, requested, unit_key),
        ).fetchone()["n"]

    def _existing_envelope(self, row: Any) -> dict[str, Any]:
        """Decision envelope for a dedupe hit. The decision is ALWAYS
        ``duplicate`` — a live twin owns the key — and ``state`` carries
        its lifecycle (queued|launching|running) so callers label the hit
        honestly instead of mistaking someone else's launch for a fresh
        one."""
        if row["status"] == "finished":
            job_id = row["job_id"] or ""
            return {
                "decision": "duplicate",
                "state": "finished",
                "unit_key": row["unit_key"],
                "job_id": job_id,
                "memory_budget": row["memory_budget"],
                "agent_id": row["agent_id"],
                "message": (
                    "identical unit already ran to completion "
                    f"(job {job_id}, by {row['agent_id']}) — its results stay "
                    "retrievable by job_id; identical input bytes need not "
                    "run again"
                ),
            }
        if row["status"] == "queued":
            position = self._queue_position(row["requested"], row["unit_key"])
            return {
                "decision": "duplicate",
                "state": "queued",
                "unit_key": row["unit_key"],
                "position": position,
                "memory_budget": row["memory_budget"],
                "agent_id": row["agent_id"],
                "message": (
                    "identical unit already queued "
                    f"(position {position}, by {row['agent_id']}) — poll the "
                    "queue, don't re-request"
                ),
            }
        if row["job_id"]:
            return {
                "decision": "duplicate",
                "state": "running",
                "unit_key": row["unit_key"],
                "job_id": row["job_id"],
                "memory_budget": row["memory_budget"],
                "agent_id": row["agent_id"],
                "message": (
                    "identical unit already running "
                    f"(job {row['job_id']}, by {row['agent_id']}) — poll "
                    "job_id, never launch a twin"
                ),
            }
        return {
            "decision": "duplicate",
            "state": "launching",
            "unit_key": row["unit_key"],
            "memory_budget": row["memory_budget"],
            "agent_id": row["agent_id"],
            "message": (
                "identical unit already claimed but not yet bound to a job "
                f"(by {row['agent_id']}) — its launch is in flight; the "
                "bind-grace sweep reclaims it if the launcher died"
            ),
        }

    def bind_unit(self, unit_key: str, job_id: str, log_file: str | None = None) -> dict[str, Any]:
        """Attach the launched job_id to a claimed 'launching' row.

        Conditional: only a 'launching' row binds (a racing sweep may have
        cancelled a wedged claim — the caller sees no-such-unit rather
        than resurrecting a cancelled row)."""
        with self.db_lock:
            self._immediate()
            try:
                cur = self.conn.execute(
                    "UPDATE worker_units SET job_id = ?, launched_at = ?, "
                    "log_file = COALESCE(?, log_file), status = 'launched' "
                    "WHERE unit_key = ? AND status = 'launching'",
                    (job_id, time.time(), log_file, unit_key),
                )
                changed = cur.rowcount
                self._commit()
            except BaseException:
                try:
                    self._rollback()
                except Exception:
                    pass
                raise
        if changed == 0:
            return {"status": "no such claim", "unit_key": unit_key}
        return {"status": "ok", "unit_key": unit_key, "job_id": job_id}

    def _terminal_job_tail(self, row: sqlite3.Row, tail: int) -> list[str] | None:
        """Log tail of a terminal unit's job, so finished/failed envelopes
        keep the output their status text points at (the release sweep can
        settle a unit before any live poll observed the log)."""
        if not row["job_id"]:
            return None
        try:
            from utils.job_store import get_store

            return get_store().poll(row["job_id"], tail=tail).get("recent_lines")
        except Exception:
            return None

    def poll_unit(self, unit_key: str, *, tail: int = 10) -> dict[str, Any]:
        """Poll one unit across its whole lifecycle:
        queued (position) → running/done (via the job store) → released.
        Terminal envelopes (finished/failed) still carry their job's log
        tail — adapters read results off the status lane after release."""
        row = self.conn.execute(
            "SELECT * FROM worker_units WHERE unit_key = ?", (unit_key,)
        ).fetchone()
        if row is None:
            return {
                "unit_key": unit_key,
                "status": "unknown",
                "error": f"no worker unit {unit_key!r}",
            }
        out: dict[str, Any] = {
            "unit_key": unit_key,
            "tool": row["tool"],
            "target": row["target"],
            "agent_id": row["agent_id"],
            "memory_budget": row["memory_budget"],
            "queued_at": row["queued_at"],
        }
        if row["status"] == "queued":
            position = self._queue_position(row["requested"], row["unit_key"])
            out.update({
                "status": "queued",
                "position": position,
                "message": (
                    f"queued at position {position}; the reaper advances the "
                    "queue when a running unit finishes"
                ),
            })
            return out
        if row["status"] == "cancelled":
            out.update({"status": "cancelled", "message": "unit was cancelled"})
            return out
        if row["status"] == "failed":
            out.update({
                "status": "failed",
                "job_id": row["job_id"],
                "peak_rss_mib": row["peak_rss_mib"],
                "message": (
                    "unit's job died (crash, OOM kill, or timeout) — its log "
                    "tail follows; a failed unit never dedupes, so "
                    "re-request runs a fresh attempt"
                ),
            })
            recent = self._terminal_job_tail(row, tail)
            if recent is not None:
                out["recent_lines"] = recent
            return out
        if row["status"] == "finished":
            out.update({
                "status": "finished",
                "peak_rss_mib": row["peak_rss_mib"],
                "message": (
                    "unit ran to completion and its slot was freed — the "
                    "workspace artifacts remain; re-request to re-run"
                ),
            })
            if row["peak_rss_mib"] is not None:
                out["message"] += (
                    f" Measured peak RSS: {row['peak_rss_mib']:.0f} MiB "
                    "(recorded as admission evidence for this content key)."
                )
            recent = self._terminal_job_tail(row, tail)
            if recent is not None:
                out["recent_lines"] = recent
            return out
        if row["status"] == "launching" and row["job_id"] is None:
            out.update({
                "status": "launching",
                "message": "claimed but not yet bound to a job — retry shortly",
            })
            return out
        # launched: let the JOB STORE report running/done + log tail.
        from utils.job_store import get_store

        poll = get_store().poll(row["job_id"], tail=tail)
        # Sample the unit's peak WHILE it runs — the kernel's VmHWM, read
        # at this observation (and at every reaper pass), so a finished
        # unit carries its measured worst footprint on the row.
        peak_observed = self._sample_unit_peak(row["unit_key"], poll.get("pid"))
        if peak_observed is not None:
            row = self.conn.execute(
                "SELECT * FROM worker_units WHERE unit_key = ?", (unit_key,)
            ).fetchone()
        out.update({
            "status": poll.get("status", "unknown"),
            "job_id": row["job_id"],
            "log_file": poll.get("log_file"),
            "recent_lines": poll.get("recent_lines"),
            "exit_code": poll.get("exit_code"),
            "elapsed": poll.get("elapsed"),
            "peak_rss_mib": row["peak_rss_mib"],
        })
        if poll.get("status") == "done":
            out["message"] = (
                "unit finished — the release sweep (advance_queue) will free "
                "its slot and promote the next queued unit"
            )
        return out

    def release_unit(self, unit_key: str, *, agent_id: str | None = None, force: bool = False) -> dict[str, Any]:
        """Release a unit's slot explicitly (owner or force=True).

        Called when the operator stops a unit or a lane knows the work is
        over. Conditional UPDATE: a racing double-release no-ops on the
        second. Marks the row ``cancelled`` — TERMINAL, and deliberately
        distinct from ``finished`` (the advance-sweep's release-on-done,
        which records SUCCESSFUL completion). A re-run re-dedupes on the
        content key with a FRESH row (the same bytes are re-analysed; the
        old row's slot is freed).
        """
        with self.db_lock:
            self._immediate()
            try:
                row = self.conn.execute(
                    "SELECT agent_id, status FROM worker_units WHERE unit_key = ?",
                    (unit_key,),
                ).fetchone()
                if row is None:
                    self._commit()
                    return {"status": "no such unit", "unit_key": unit_key}
                if not force and agent_id is not None and row["agent_id"] != agent_id:
                    self._commit()
                    return {
                        "status": "refused",
                        "error": (
                            f"unit owned by '{row['agent_id']}' (you are "
                            f"{agent_id!r}); cross-agent release needs force=True"
                        ),
                    }
                # A FAILED row is a dead tombstone (job already exited):
                # clearing it is deletion, not status churn — release_unit
                # must not return "already_released" for a failed row or a
                # caller could never clear it (2026-10-30 code review).
                if row["status"] == "failed":
                    self.conn.execute(
                        "DELETE FROM worker_units WHERE unit_key = ? AND "
                        "status = 'failed'",
                        (unit_key,),
                    )
                    self._commit()
                    return {"status": "released", "unit_key": unit_key}
                cur = self.conn.execute(
                    "UPDATE worker_units SET status = 'cancelled' "
                    "WHERE unit_key = ? AND status IN ('launching','launched',"
                    "'queued')",
                    (unit_key,),
                )
                changed = cur.rowcount
                self._commit()
            except BaseException:
                try:
                    self._rollback()
                except Exception:
                    pass
                raise
        if changed == 0:
            return {"status": "already_released", "unit_key": unit_key}
        return {"status": "released", "unit_key": unit_key}

    def cancel_unit(self, unit_key: str, *, agent_id: str | None = None, force: bool = False) -> dict[str, Any]:
        """Cancel a queued unit (never launched — nothing to terminate)."""
        with self.db_lock:
            self._immediate()
            try:
                row = self.conn.execute(
                    "SELECT agent_id, status, job_id FROM worker_units "
                    "WHERE unit_key = ?",
                    (unit_key,),
                ).fetchone()
                if row is None:
                    self._commit()
                    return {"status": "no such unit", "unit_key": unit_key}
                if not force and agent_id is not None and row["agent_id"] != agent_id:
                    self._commit()
                    return {
                        "status": "refused",
                        "error": (
                            f"unit owned by '{row['agent_id']}' (you are "
                            f"{agent_id!r}); cross-agent cancel needs force=True"
                        ),
                    }
                # A FAILED row is a dead tombstone: its job is already gone,
                # so the launched-job refusal below must not trap it — the
                # release sweep already marked the row and nothing else can
                # clear it (2026-10-30 code review). DELETE instead.
                if row["status"] == "failed":
                    self.conn.execute(
                        "DELETE FROM worker_units WHERE unit_key = ? AND "
                        "status = 'failed'",
                        (unit_key,),
                    )
                    self._commit()
                    return {"status": "cancelled", "unit_key": unit_key}
                if row["job_id"]:
                    self._commit()
                    return {
                        "status": "refused",
                        "error": (
                            "unit already launched — cancel the JOB "
                            "(terminate_job) instead; the release sweep then "
                            "frees the slot"
                        ),
                    }
                cur = self.conn.execute(
                    "UPDATE worker_units SET status = 'cancelled' "
                    "WHERE unit_key = ? AND status = 'queued'",
                    (unit_key,),
                )
                changed = cur.rowcount
                self._commit()
            except BaseException:
                try:
                    self._rollback()
                except Exception:
                    pass
                raise
        if changed == 0:
            return {"status": "already_cancelled", "unit_key": unit_key}
        return {"status": "cancelled", "unit_key": unit_key}

    # -- queue advance + sweeps -------------------------------------------------

    def advance_queue(self) -> dict[str, Any]:
        """Free the slots of LAUNCHED units whose jobs are FINISHED, then
        promote head-of-queue units whose admission now fits.

        FIFO order is ``(requested, unit_key)`` — deterministic even when
        two rows share a timestamp tick (positions agree with the head).
        A head whose budget is a PERMANENT impossibility (> total − floor)
        is cancelled and skipped: keeping it would wedge every unit
        behind it forever (transient shortfalls still stop the FIFO).

        Claim protocol (Annex E guarded-UPDATE rule): the promotion claim
        is a conditional UPDATE ``queued -> launching`` (stamping
        ``launching_at``) on the row's PK — two lanes sweeping the same
        queue yield exactly one promoter per row (the loser's claim
        touches 0 rows and skips the launch).

        Runs on EVERY reaper pass (wired at ``JobStore._reaper_pass``) and
        is safe to call manually (a poll lane can advance the queue when
        the reaper is wedged). Best-effort: never raises.
        """
        out: dict[str, Any] = {"freed": 0, "promoted": 0, "launch_failed": 0,
                               "blocked": 0, "impossible": 0}
        try:
            acct = self.account()
            usable = max(0, acct["free_ram_mib"] - acct["ram_floor_mib"])
        except Exception:
            return out

        # 1. Release finished launched jobs (first-releaser-wins). Use
        # poll(), NOT get(): only the poll path OBSERVES the process
        # (reaps + stamps exit_code on the row) — a get()-only sweep
        # would see exit_code NULL forever on a finished job whose row
        # nobody polled, and the slot would leak until TTL.
        try:
            from utils.job_store import get_store

            jobs = get_store()
            rows = self.conn.execute(
                "SELECT unit_key, job_id, tool FROM worker_units "
                "WHERE status = 'launched'"
            ).fetchall()
            for r in rows:
                poll = jobs.poll(r["job_id"])
                poll_status = poll.get("status")
                if poll_status in ("done", "failed"):
                    # Sample one last time (harmless when the pid is
                    # already gone — the last live sample stands), then
                    # record the unit's measured peak as evidence for
                    # future admissions of the same content bytes. A
                    # FAILED unit's peak is the OOM data the pool exists
                    # to learn from — record it before release too.
                    self._sample_unit_peak(r["unit_key"], poll.get("pid"))
                    self._record_evidence(r["unit_key"])
                    terminal = "finished" if poll_status == "done" else "failed"
                    cur = self.conn.execute(
                        "UPDATE worker_units SET status = ? "
                        "WHERE unit_key = ? AND status = 'launched'",
                        (terminal, r["unit_key"]),
                    )
                    out["freed"] += cur.rowcount
                else:
                    # Running: raise the row's peak to the kernel's
                    # current VmHWM before the process exits and takes
                    # its /proc entry with it.
                    self._sample_unit_peak(r["unit_key"], poll.get("pid"))
        except Exception:
            pass  # job store down: promotions can still happen if slots free

        # 1b. TTL sweep of ancient queued rows (a request is not a promise;
        #     the operator re-requests rather than inheriting a stale one).
        try:
            cutoff = time.time() - _queue_ttl_hours() * 3600
            cur = self.conn.execute(
                "DELETE FROM worker_units WHERE status = 'queued' "
                "AND queued_at < ?",
                (cutoff,),
            )
            out["ttl_swept"] = cur.rowcount
            # Terminal rows (cancelled + finished + failed) age out too —
            # history lives in the journal; this table is a live ledger,
            # not an archive. Failed rows need the same aging (they're
            # tombstones once the model saw them; re-requests delete them
            # earlier). Ageing window = 7d past the queue-entry cutoff
            # (cutoff already encodes the queue TTL), i.e. terminal rows
            # live ~7d + 24h from queued_at — the "weekly ledger row" the
            # docs promise.
            self.conn.execute(
                "DELETE FROM worker_units WHERE status IN ('cancelled',"
                "'finished','failed') "
                "AND queued_at < ?",
                (cutoff - 7 * 86400,),
            )
            # Peak-RSS evidence ages out too (30d default) — long enough
            # that finished rows always age out FIRST and the evidence
            # outlives them; old measurements stop constraining new runs.
            cur = self.conn.execute(
                "DELETE FROM worker_rss WHERE updated_at < ?",
                (time.time() - _evidence_ttl_hours() * 3600,),
            )
            out["evidence_swept"] = cur.rowcount
        except Exception:
            pass

        # 2. Launch-promote head-of-queue while admission fits (FIFO).

        # Promotion is the queue's over-commit danger point, so the whole
        # read → check → claim sequence runs under ONE ``BEGIN IMMEDIATE``
        # transaction under ``db_lock`` (the same discipline as
        # ``request_unit``'s admission tx — 2026-10-30 code review): two
        # lanes reading claims/slots in separate autocommit statements
        # could BOTH pass stale arithmetic and each launch a head,
        # committing two claims over the pool's memory cap together — the
        # exact OOM the queue exists to prevent. The write lock serializes
        # the arithmetic WITH the claim: the second lane re-runs its math
        # against a ledger that already includes the first lane's claim.
        # The launch itself stays OUTSIDE the tx — the job store's own
        # IMMEDIATE sections must never nest inside ours.
        try:
            self.sweep_stale()  # crashed-launcher claims first
            while True:
                with self.db_lock:
                    self._immediate()
                    try:
                        acct = self.account()
                        head = self.conn.execute(
                            "SELECT * FROM worker_units WHERE status = 'queued' "
                            "ORDER BY requested, unit_key LIMIT 1"
                        ).fetchone()
                        if head is None:
                            self._commit()
                            break
                        # A head whose claim exceeds the box's admission
                        # capacity (total - floor) can NEVER fit — strict
                        # FIFO would wedge the whole queue behind it
                        # forever. Cancel it and keep walking (transient
                        # shortfalls below still stop the FIFO). The claim
                        # is evidence-backed (RSS feedback): a head whose
                        # recorded peak outruns capacity is cancelled the
                        # same way.
                        cap = acct["budget_capacity_mib"]
                        head_effective, _evidence_peak = self._effective_claim(
                            head["unit_key"], head["memory_budget"]
                        )
                        if cap is not None and head_effective > cap:
                            cur = self.conn.execute(
                                "UPDATE worker_units SET status = 'cancelled' "
                                "WHERE unit_key = ? AND status = 'queued'",
                                (head["unit_key"],),
                            )
                            if cur.rowcount:
                                out["impossible"] += 1
                            self._commit()
                            continue
                        running = self.conn.execute(
                            "SELECT unit_key FROM worker_units "
                            "WHERE status IN ('launching','launched')"
                        ).fetchall()
                        claims = self.conn.execute(
                            "SELECT COALESCE(SUM(memory_budget), 0) AS c "
                            "FROM worker_units WHERE status IN ('launching','launched')"
                        ).fetchone()["c"]
                        usable = max(0, acct["free_ram_mib"] - acct["ram_floor_mib"])
                        if (len(running) >= acct["slots"]
                                or claims + head_effective > usable):
                            out["blocked"] += 1
                            self._commit()
                            break  # FIFO stop: head blocks, so nothing behind it
                        # Claim (conditional): exactly one lane wins this
                        # update. launching_at stamps the CLAIM clock —
                        # sweep_stale reads it, never the queue-entry
                        # time, or a long-queued unit would be killed at
                        # the instant it finally launches.
                        cur = self.conn.execute(
                            "UPDATE worker_units SET status = 'launching', "
                            "launching_at = ? "
                            "WHERE unit_key = ? AND status = 'queued'",
                            (time.time(), head["unit_key"]),
                        )
                        if cur.rowcount == 0:
                            self._commit()
                            continue  # lane lost a race inside its own tx — re-read
                        fresh = self.conn.execute(
                            "SELECT * FROM worker_units WHERE unit_key = ?",
                            (head["unit_key"],),
                        ).fetchone()
                        self._commit()
                    except BaseException:
                        try:
                            self._rollback()
                        except Exception:
                            pass
                        raise
                # TX committed and the claim is durable: launch outside it.
                result = self._launch_claim(fresh)
                if result is None:
                    out["launch_failed"] += 1
                    # The claim was deleted; the loop would re-read the SAME
                    # failing argv and spin. One launch attempt per pass:
                    # the next reaper (2s) retries if the failure was
                    # transient, but a persistent failure cannot wedge the
                    # reaper thread.
                    break
                out["promoted"] += 1
        except Exception:
            pass
        return out

    def sweep_stale(self) -> dict[str, Any]:
        """Crash-stale reclaim: a 'launching' claim whose launch never
        bound (launch failed between claim and bind) is reclaimed after
        the bind-grace window (``WORKER_QUEUE_BIND_GRACE_S``, default 600
        — the request→bind is sub-second in process). Mirrors the fleet
        scheduler's bind-grace discipline.

        The grace is measured from the ``launching_at`` claim stamp — set
        when ``queued → launching`` — NOT from ``requested`` (the
        queue-entry clock, never rewritten on promotion): the entry time
        of a long-queued unit is ancient by the time it finally launches,
        and measuring from it would kill the unit at the instant of its
        launch. Rows without a stamp (pre-migration) fall back to
        ``requested``."""
        try:
            grace = float(os.getenv("WORKER_QUEUE_BIND_GRACE_S", "").strip() or 600.0)
        except ValueError:
            grace = 600.0
        cutoff = time.time() - grace
        reclaimed: list[str] = []
        try:
            rows = self.conn.execute(
                "SELECT unit_key FROM worker_units "
                "WHERE status = 'launching' "
                "AND COALESCE(launching_at, requested) < ?",
                (cutoff,),
            ).fetchall()
            for r in rows:
                cur = self.conn.execute(
                    "UPDATE worker_units SET status = 'cancelled' "
                    "WHERE unit_key = ? AND status = 'launching'",
                    (r["unit_key"],),
                )
                if cur.rowcount:
                    reclaimed.append(r["unit_key"])
        except Exception:
            pass
        return {"reclaimed": reclaimed, "count": len(reclaimed)}

    def host_pressure(self) -> dict[str, Any]:
        """Pool observability: slots/claims/free RAM + every unit row."""
        acct = self.account()
        rows = self.conn.execute(
            "SELECT unit_key, tool, target, agent_id, status, memory_budget, "
            "peak_rss_mib, job_id, requested, queued_at, launching_at "
            "FROM worker_units ORDER BY queued_at DESC LIMIT 100"
        ).fetchall()
        return {
            "slots": acct["slots"],
            "running_claims_mib": acct["running_claims_mib"],
            "ram_floor_mib": acct["ram_floor_mib"],
            "free_ram_mib": acct["free_ram_mib"],
            "total_ram_mib": acct["total_ram_mib"],
            "budget_capacity_mib": acct["budget_capacity_mib"],
            "units": [dict(r) for r in rows],
            "db": self.db_path,
        }

    def units_by_note(self, note: str) -> list[dict[str, Any]]:
        """Every live ledger row stamped with ``note`` (an adapter's batch
        handle, e.g. a jadx ``fleet_id``), in queue order. The queue-side
        batch API — adapter twins read this instead of reaching into
        ``.conn`` directly."""
        rows = self.conn.execute(
            "SELECT * FROM worker_units WHERE note = ? "
            "ORDER BY requested, unit_key",
            (note,),
        ).fetchall()
        return [dict(r) for r in rows]

    def close(self) -> None:
        try:
            self._bootstrap.close()
            c = getattr(self._local, "conn", None)
            if c is not None:
                c.close()
        except Exception:
            pass


# --- module-level singleton (scratch-store pattern) ---------------------------

_queue: WorkerQueue | None = None
_queue_key: str = ""


def get_worker_queue() -> WorkerQueue:
    """Process-wide worker-queue singleton. ``WORKER_QUEUE_DIR`` re-points
    the store (tests use it + ``reset_worker_queue`` for isolation); the
    singleton caches PER OVERRIDE VALUE so repeated calls in one process
    share the instance (one promotion thread-owner, consistent state)."""
    global _queue, _queue_key
    override = os.getenv("WORKER_QUEUE_DIR", "").strip()
    if override:
        if _queue is not None and _queue_key == override:
            return _queue
        _queue = WorkerQueue(store_dir=override)
        _queue_key = override
        return _queue
    if _queue is None:
        _queue = WorkerQueue()
        _queue_key = ""
    return _queue


def reset_worker_queue() -> None:
    """Test hook: forget the singleton (next get re-reads env)."""
    global _queue
    _queue = None