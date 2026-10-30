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
"""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from constants import resolve_workspace_root

_DEFAULT_ROOT = resolve_workspace_root()

# Decision statuses (queue rows): 'queued' -> 'launching' -> (job store
# owns running/done from here); terminals: 'cancelled' (operator stop /
# crash reclaim) and 'finished' (ran, exited, slot freed — success).
_QUEUE_STATUS = ("queued", "launching", "launched", "cancelled", "finished")

_WORKER_SLOTS_DEFAULT = 2
_WORKER_QUEUE_MAX_DEFAULT = 16

# Queued rows older than this are swept (a queue entry is a REQUEST, not a
# commitment; the operator re-requests rather than inheriting a stale one).
_QUEUE_TTL_HOURS_DEFAULT = 24


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


def _queue_ttl_hours() -> float:
    raw = os.getenv("WORKER_QUEUE_TTL_HOURS", "").strip()
    try:
        return float(raw) if raw else _QUEUE_TTL_HOURS_DEFAULT
    except ValueError:
        return _QUEUE_TTL_HOURS_DEFAULT


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


# --- canonical key (content-keyed; the snapshot-cache precedent) ----------


def content_key(tool: str, path: str) -> str:
    """Canonical worker-queue key: ``<tool>:c<sha256[:12]>`` of the BYTES.

    Content, not path: identical APK bytes at a different filename are the
    same unit (re-drop with a new name must dedupe, not double-launch).
    Unreadable/missing files fall back to a path+size key so the request
    still resolves (the launch will fail honestly on the missing input —
    an unhashable blob must not break the request pipeline).
    """
    import hashlib

    safe_tool = "".join(
        c if c.isalnum() or c in "_.-" else "-" for c in (tool or "unit").lower()
    )
    digest = None
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        digest = h.hexdigest()[:12]
    except OSError:
        pass
    if digest:
        return f"{safe_tool}:c{digest}"
    try:
        st = os.stat(path)
        path_fallback = f"{os.path.basename(path)}:{st.st_size}"
    except OSError:
        path_fallback = secrets.token_hex(6)
    return f"{safe_tool}:p{hashlib.sha1(path_fallback.encode('utf-8', 'replace')).hexdigest()[:12]}"


# --- store ------------------------------------------------------------------


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
        self._bootstrap.execute("PRAGMA journal_mode=WAL")
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
            c.execute("PRAGMA journal_mode=WAL")
            self._local.conn = c
        return c

    def _immediate(self) -> None:
        self.conn.execute("BEGIN IMMEDIATE")

    def _commit(self) -> None:
        self.conn.execute("COMMIT")

    def _rollback(self) -> None:
        self.conn.execute("ROLLBACK")

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
                requested      REAL,                   -- first request ts (fairness order)
                launched_at    REAL,
                log_file       TEXT,
                note           TEXT,
                PRIMARY KEY (unit_key)
            )
            """
        )
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

    def account(self) -> dict[str, Any]:
        """Pool accounting snapshot: slots, running claims, free RAM,
        floor. Pure observation — admission math lives here so callers
        and tests see ONE formula."""
        rows = self.conn.execute(
            "SELECT COALESCE(SUM(memory_budget), 0) AS claimed "
            "FROM worker_units WHERE status IN ('launching','launched')"
        ).fetchone()
        return {
            "tool": None,
            "slots": _slots(),
            "running_claims_mib": rows["claimed"] or 0,
            "ram_floor_mib": _ram_floor_mib(),
            "free_ram_mib": free_ram_mib(),
            "total_ram_mib": _total_ram_mib(),
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
        """Ask to START one Arch-D unit. Decision envelope:

        - ``{"decision": "running", ...}`` — dedupe hit on an ALREADY
          RUNNING unit: poll its job_id (never launch a twin).
        - ``{"decision": "queued", "position": N}`` — dedupe hit on a
          QUEUED unit, or this request was queued for resources. Poll
          the queue (``poll_unit``) — the reaper launch-promotes it when
          the head fits.
        - ``{"decision": "running"}`` again with a fresh job_id — no, one
          decision per shape: ``{"decision": "launched"}`` — admitted,
          the queue LAUNCHED it inline (claim → job-store launch →
          bind, atomic here); ``job_id`` is in the envelope.
        - ``{"decision": "refused", "reason": "queue_full"}`` — the queue
          itself is deep-capped; the envelope says what to do.

        Admission (the one formula, in order):
        1. Dedupe on content key — running/queued wins over ad-hoc re-run.
        2. Slots: running < ``WORKER_QUEUE_SLOTS``.
        3. Memory math: running_claims + budget <= usable, where usable =
           free_ram_now - ram_floor (the pool's reservation for the rest
           of the box), and free_now - floor >= budget directly.
        Passing 1, failing 2 or 3 ⇒ QUEUED (memory/slot pressure, not
        policy).
        """
        if not agent_id:
            raise ValueError("worker queue requires a resolved agent_id")
        if memory_budget <= 0:
            raise ValueError("memory_budget must be a positive MiB integer")
        unit_key = content_key(tool, target)
        now = time.time()
        # Heap pin decided HERE (centrally): the row's env carries it, the
        # launcher never overrides a budget at launch time.
        launch_env = heap_pin_env(memory_budget, env)

        with self.db_lock:
            self._immediate()
            try:
                existing = self.conn.execute(
                    "SELECT * FROM worker_units WHERE unit_key = ?", (unit_key,)
                ).fetchone()
                # --- dedupe: an existing non-terminal unit owns the key ---
                if existing is not None and existing["status"] not in (
                    "cancelled", "finished"
                ):
                    out = self._existing_envelope(existing)
                    self._commit()
                    return out

                # --- admission arithmetic ---
                acct = self.account()
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
                    and claims + memory_budget <= usable
                    and acct["free_ram_mib"] - acct["ram_floor_mib"] >= memory_budget
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
                        " memory_budget, command, env, queued_at, requested, note) "
                        "VALUES (?, ?, ?, ?, 'launching', ?, ?, ?, ?, ?, ?)",
                        (
                            unit_key, tool, target, agent_id, memory_budget,
                            json.dumps(command), json.dumps(launch_env),
                            now, now, note or "",
                        ),
                    )
                    self._commit()
                else:
                    # --- queued for resources (or slots) ---
                    self.conn.execute(
                        "INSERT INTO worker_units "
                        "(unit_key, tool, target, agent_id, status, "
                        " memory_budget, command, env, queued_at, requested, note) "
                        "VALUES (?, ?, ?, ?, 'queued', ?, ?, ?, ?, ?, ?)",
                        (
                            unit_key, tool, target, agent_id, memory_budget,
                            json.dumps(command), json.dumps(launch_env),
                            now, now, note or "",
                        ),
                    )
                    position = self.conn.execute(
                        "SELECT COUNT(*) AS n FROM worker_units "
                        "WHERE status = 'queued' AND requested <= ?", (now,)
                    ).fetchone()["n"]
                    self._commit()
                    return {
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
        return out

    def _existing_envelope(self, row: Any) -> dict[str, Any]:
        """Decision envelope for a dedupe hit (running or queued)."""
        if row["status"] == "queued":
            position = self.conn.execute(
                "SELECT COUNT(*) AS n FROM worker_units "
                "WHERE status = 'queued' AND requested <= ?",
                (row["requested"],),
            ).fetchone()["n"]
            return {
                "decision": "queued",
                "unit_key": row["unit_key"],
                "position": position,
                "memory_budget": row["memory_budget"],
                "message": (
                    "identical unit already queued "
                    f"(position {position}, by {row['agent_id']}) — poll it, "
                    "don't re-request"
                ),
            }
        state = "launched" if row["job_id"] else "launching"
        out = {
            "decision": "launched" if row["job_id"] else "launching",
            "unit_key": row["unit_key"],
            "job_id": row["job_id"],
            "memory_budget": row["memory_budget"],
            "agent_id": row["agent_id"],
            "message": (
                "identical unit already running "
                f"(job {row['job_id'] or '<binding>'}, by {row['agent_id']}) — "
                "poll its job, never launch a twin"
            ),
        }
        if row["status"] == "launching" and row["job_id"] is None:
            # A launcher died between claim and bind: fleet bind-grace
            # semantics apply — the sweep reclaims it; report the state.
            out["decision"] = "launching"
        return out

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

    def poll_unit(self, unit_key: str, *, tail: int = 10) -> dict[str, Any]:
        """Poll one unit across its whole lifecycle:
        queued (position) → running/done (via the job store) → released."""
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
            position = self.conn.execute(
                "SELECT COUNT(*) AS n FROM worker_units "
                "WHERE status = 'queued' AND requested <= ?",
                (row["requested"],),
            ).fetchone()["n"]
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
        if row["status"] == "finished":
            out.update({
                "status": "finished",
                "message": (
                    "unit ran to completion and its slot was freed — the "
                    "workspace artifacts remain; re-request to re-run"
                ),
            })
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
        out.update({
            "status": poll.get("status", "unknown"),
            "job_id": row["job_id"],
            "log_file": poll.get("log_file"),
            "recent_lines": poll.get("recent_lines"),
            "exit_code": poll.get("exit_code"),
            "elapsed": poll.get("elapsed"),
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

        Claim protocol (Annex E guarded-UPDATE rule): the promotion claim
        is a conditional UPDATE ``queued -> launching`` on the row's PK —
        two lanes sweeping the same queue yield exactly one promoter per
        row (the loser's claim touches 0 rows and skips the launch).

        Runs on EVERY reaper pass (wired at ``JobStore._reaper_pass``) and
        is safe to call manually (a poll lane can advance the queue when
        the reaper is wedged). Best-effort: never raises.
        """
        out: dict[str, Any] = {"freed": 0, "promoted": 0, "launch_failed": 0,
                               "blocked": 0}
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
                "SELECT unit_key, job_id FROM worker_units "
                "WHERE status = 'launched'"
            ).fetchall()
            for r in rows:
                state = jobs.poll(r["job_id"]).get("status")
                if state == "done":
                    cur = self.conn.execute(
                        "UPDATE worker_units SET status = 'finished' "
                        "WHERE unit_key = ? AND status = 'launched'",
                        (r["unit_key"],),
                    )
                    out["freed"] += cur.rowcount
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
            # Terminal rows (cancelled + finished) age out too — history
            # lives in the journal; this table is a live ledger, not an
            # archive.
            self.conn.execute(
                "DELETE FROM worker_units WHERE status IN ('cancelled'," 
                "'finished') "
                "AND queued_at < ?",
                (cutoff - 7 * 3600,),
            )
        except Exception:
            pass

        # 2. Launch-promote head-of-queue while admission fits (FIFO).
        try:
            self.sweep_stale()  # crashed-launcher claims first
            while True:
                acct = self.account()
                head = self.conn.execute(
                    "SELECT * FROM worker_units WHERE status = 'queued' "
                    "ORDER BY requested, queued_at LIMIT 1"
                ).fetchone()
                if head is None:
                    break
                running = self.conn.execute(
                    "SELECT unit_key FROM worker_units "
                    "WHERE status IN ('launching','launched')"
                ).fetchall()
                claims = self.conn.execute(
                    "SELECT COALESCE(SUM(memory_budget), 0) AS c "
                    "FROM worker_units WHERE status IN ('launching','launched')"
                ).fetchone()["c"]
                usable = max(0, acct["free_ram_mib"] - acct["ram_floor_mib"])
                if len(running) >= acct["slots"]:
                    out["blocked"] += 1
                    break  # FIFO: head blocks, so no further promotion
                if claims + head["memory_budget"] > usable:
                    out["blocked"] += 1
                    break  # head's budget doesn't fit — strict FIFO stop
                # Claim (conditional): exactly one lane wins this update.
                cur = self.conn.execute(
                    "UPDATE worker_units SET status = 'launching' "
                    "WHERE unit_key = ? AND status = 'queued'",
                    (head["unit_key"],),
                )
                if cur.rowcount == 0:
                    continue  # another lane claimed it — re-read the head
                fresh = self.conn.execute(
                    "SELECT * FROM worker_units WHERE unit_key = ?",
                    (head["unit_key"],),
                ).fetchone()
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
        scheduler's bind-grace discipline."""
        try:
            grace = float(os.getenv("WORKER_QUEUE_BIND_GRACE_S", "").strip() or 600.0)
        except ValueError:
            grace = 600.0
        cutoff = time.time() - grace
        reclaimed: list[str] = []
        try:
            rows = self.conn.execute(
                "SELECT unit_key FROM worker_units "
                "WHERE status = 'launching' AND requested < ?",
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
            "job_id, requested, queued_at FROM worker_units "
            "ORDER BY queued_at DESC LIMIT 100"
        ).fetchall()
        return {
            "slots": acct["slots"],
            "running_claims_mib": acct["running_claims_mib"],
            "ram_floor_mib": acct["ram_floor_mib"],
            "free_ram_mib": acct["free_ram_mib"],
            "total_ram_mib": acct["total_ram_mib"],
            "units": [dict(r) for r in rows],
            "db": self.db_path,
        }

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