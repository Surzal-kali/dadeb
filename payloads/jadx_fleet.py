"""jadx fleet twins — Arch-D worker-queue adapter (Phase 3, doctrine §13).

The blocking ``run_jadx`` stays the primary lane for single targets (a
sub-minute manifest/class pull does not need a queue). These twins exist
for the WORKLOAD shape that hurt first: decompiling MANY APKs, where N
concurrent JVMs each defaulting to ``-XX:MaxRAMPercentage=70.0`` would
multiply-claim the same 70% of the box (upstream reports of 9-35 GB RSS
on real apps made this arithmetic, not theoretical).

What each twin does:

- ``jadx_fleet(targets)`` — one worker-queue unit per APK (content-keyed
  on sha256: identical bytes at a different filename dedupe). Each
  request carries a per-unit memory budget (MiB) — the queue pins the
  launched JVM's heap to it (``JAVA_OPTS=-Xmx<budget>m``, last-wins over
  the launcher script's percentage policy) and only admits units whose
  measured budgets fit inside FREE RAM minus the pool's reservation
  floor. Units that do not fit are QUEUED and launch-promoted by the
  job-store reaper pass as slots free.
- ``jadx_fleet_status(fleet_id)`` — per-unit queued/position/running/
  done across the batch; releases finished slots via the queue sweep.
- ``jadx_fleet_stop(fleet_id, force)`` — terminate running/queued units
  of one batch, ownership-fenced.

The twins ride ``utils/worker_queue`` (the bounded-memory pool), which in
turn launches through ``utils/job_store`` — so polling, logs, caps and
cross-lane visibility are the Phase-0 machinery, and the queue adds only
the memory-axis admission + heap pinning + FIFO promotion.

Scope gate: NONE — identical to run_jadx, this lane parses local files
the operator dropped into ``apk/``; it opens no sockets and contacts no
target.
"""

from __future__ import annotations

import os
import shlex
import secrets
from typing import Any

from constants import framework_tool
from utils.worker_queue import (
    content_key,
    get_worker_queue,
    heap_pin_env,
)

# Per-unit default memory budget (MiB). NOT derived from total RAM: the
# evidence-backed baseline is the measured synthetic peak (~300 MB) with
# 2x headroom, and the operator raises it per APK for big real targets
# (upstream: medium apps 1-4 GB, large tails 10 GB+).
_JADX_FLEET_BUDGET_DEFAULT = 640
_JADX_FLEET_BUDGET_CAP = 16 * 1024  # hard ceiling: 16 GiB per unit

# Default -j per queued unit: half the box's cores, clamped 1..8, so a
# 2-slot pool never oversubscribes the CPU while a decompile runs.
_JADX_FLEET_THREADS_DEFAULT = max(1, min(8, (os.cpu_count() or 4) // 2))


def _jadx_bin() -> str | None:
    from auxiliaries.jadx import resolve_jadx_bin

    return resolve_jadx_bin()


def _resolve_targets(targets_spec: str) -> list[dict[str, Any]]:
    """Resolve a comma/newline-separated targets list against the drop
    folder. Returns resolution rows {spec, path|None, error}."""
    from auxiliaries.jadx import resolve_apk_target

    out: list[dict[str, Any]] = []
    for raw in targets_spec.replace("\n", ",").split(","):
        spec = raw.strip()
        if not spec:
            continue
        resolved = resolve_apk_target(spec)
        if resolved is None:
            out.append({"spec": spec, "path": None, "error": "not found"})
        else:
            out.append({"spec": spec, "path": resolved, "error": None})
    return out


@framework_tool(
    "BATCH-decompile MULTIPLE APKs in the background through the bounded-"
    "memory worker queue: one unit per target (content-deduped), each "
    "launched with its heap pinned to the unit's memory budget and admitted "
    "only when the measured FREE RAM can back it; units that don't fit queue "
    "up and launch as slots free. Use for MANY targets; single-target "
    "decompile stays run_jadx(verb='decompile'). Offline lane (no scope "
    "gate) — parses local apk/ drop-folder files only.",
    tags=["recon.binary", "infra"],
    next_hints=["jadx_fleet_status"],
)
def jadx_fleet(
    targets: str,
    memory_budget: int = _JADX_FLEET_BUDGET_DEFAULT,
    threads: int | None = None,
    deobf: bool = False,
    no_res: bool = False,
) -> dict[str, Any]:
    """Queue one background decompile per target (bounded-memory pool).

    Args:
        targets: Comma/newline-separated target names or paths, resolved
            against the apk drop folder (bare names auto-resolve, same as
            ``run_jadx``).
        memory_budget: Per-unit JVM heap clamp in MiB (default 640). The
            queue pins ``JAVA_OPTS=-Xmx<budget>m`` on each launch and
            admits units only while running budgets stay within measured
            free RAM minus the pool floor. Raise for big real APKs
            (upstream evidence: medium apps 1-4 GB; large tails 10 GB+) —
            transient shortfalls simply queue more, but a budget above the
            box's total RAM minus the pool floor is refused outright (the
            pool can never admit it, no matter how long it waits).
        threads: ``-j`` per unit, clamped 1..16 (default: half the box's
            cores, max 8 — the pool bounds processes; -j tunes threads
            WITHIN one).
        deobf: Add ``--deobf`` to each unit (rename obfuscated classes).
        no_res: Add ``-r`` (skip resource decode; sources only).

    Returns per-unit decisions: ``launched`` (job_id to poll), ``queued``
    (position; launches as slots free), ``duplicate`` (identical bytes
    already running/queued — poll the given ref), ``refused`` (queue
    full, impossible budget, launch or input error), plus a ``fleet_id``
    binding the batch for status/stop.
    """
    try:
        memory_budget = int(memory_budget)
    except (TypeError, ValueError):
        return {
            "status": "error",
            "error": f"memory_budget must be an integer MiB, got {memory_budget!r}",
        }
    if memory_budget <= 0:
        return {"status": "error", "error": "memory_budget must be positive"}
    if memory_budget > _JADX_FLEET_BUDGET_CAP:
        return {
            "status": "error",
            "error": (
                f"memory_budget {memory_budget} MiB exceeds the hard ceiling "
                f"{_JADX_FLEET_BUDGET_CAP} MiB (16 GiB/unit); split the target "
                "or raise fewer units"
            ),
        }
    if threads is not None:
        try:
            threads = max(1, min(16, int(threads)))
        except (TypeError, ValueError):
            return {"status": "error", "error": f"threads must be an integer, got {threads!r}"}
    else:
        threads = _JADX_FLEET_THREADS_DEFAULT

    jadx_bin = _jadx_bin()
    if jadx_bin is None:
        return {
            "status": "error",
            "error": (
                "jadx not found — install the 1.5.x release bundle and put "
                "bin/jadx on PATH, or set JADX_BIN"
            ),
        }
    from auxiliaries.jadx import _java_available

    if not _java_available():
        return {
            "status": "error",
            "error": "jadx found but no Java runtime on PATH (needs Java 11+ JRE)",
        }

    resolved = _resolve_targets(targets)
    if not resolved:
        return {"status": "error", "error": "no targets in the list"}

    queue = get_worker_queue()
    from utils.agent_identity import current_agent_id

    agent_id = current_agent_id()
    batch_id = f"jxfleet:{secrets.token_hex(6)}"
    units: list[dict[str, Any]] = []

    for row in resolved:
        if row["path"] is None:
            units.append({
                "target": row["spec"],
                "decision": "refused",
                "reason": "input_not_found",
                "message": f"target {row['spec']!r} not found in the apk drop folder",
            })
            continue
        # Compose the exact argv the queue will launch on promotion. The
        # workspace is the SAME per-target cache run_jadx uses, so a
        # fleet decompile and a later run_jadx grep share one tree.
        from auxiliaries.jadx import _workspace_for

        ws = _workspace_for(row["path"])
        os.makedirs(ws, exist_ok=True)
        argv = [
            jadx_bin, "--log-level", "ERROR", "-j", str(threads),
            "-d", ws,
        ]
        if no_res:
            argv.append("-r")
        if deobf:
            argv.append("--deobf")
        argv.append(row["path"])

        decision = queue.request_unit(
            "jadx",
            row["path"],
            agent_id=agent_id,
            memory_budget=memory_budget,
            command=argv,
            note=batch_id,
        )
        entry: dict[str, Any] = {
            "target": row["spec"],
            "unit_key": decision.get("unit_key"),
            "decision": decision["decision"],
            "memory_budget": memory_budget,
        }
        if decision["decision"] == "launched":
            entry["job_id"] = decision.get("job_id")
        elif decision["decision"] == "duplicate":
            # The queue labels dedupe hits `duplicate` itself (state:
            # queued|launching|running) — entry carries the twin's ref.
            entry["state"] = decision.get("state")
            if decision.get("job_id"):
                entry["job_id"] = decision["job_id"]
            if decision.get("position") is not None:
                entry["position"] = decision["position"]
        elif decision["decision"] == "queued":
            entry["position"] = decision.get("position")
        elif decision["decision"] == "refused":
            entry["reason"] = decision.get("reason")
            entry["message"] = decision.get("message")
        units.append(entry)

    # The fleet_id is a client-side batch handle (the queue is the ledger).
    counts: dict[str, int] = {}
    for u in units:
        counts[u["decision"]] = counts.get(u["decision"], 0) + 1
    acct = queue.account()
    return {
        "status": "ok",
        "fleet_id": batch_id,
        "requested": len(resolved),
        "decision_counts": counts,
        "units": units,
        "pool": {
            "slots": acct["slots"],
            "free_ram_mib": acct["free_ram_mib"],
            "ram_floor_mib": acct["ram_floor_mib"],
            "budget_capacity_mib": acct["budget_capacity_mib"],
        },
        "message": (
            f"{counts.get('launched', 0)} launched, {counts.get('queued', 0)} "
            f"queued, {counts.get('duplicate', 0)} deduped, "
            f"{counts.get('refused', 0)} refused. Poll with "
            "jadx_fleet_status(fleet_id) — queued units launch as slots free."
        ),
        "next_hints": ["jadx_fleet_status", "run_jadx grep on finished workspaces"],
    }


@framework_tool(
    "Poll a jadx fleet batch: per-unit queued/position/running/done state "
    "across the worker queue. Queued units launch automatically as slots "
    "free (job-store reaper pass) — no caller action needed. Finished units' "
    "decompiled workspaces are immediately usable by run_jadx(grep/read/tree).",
    tags=["recon.binary", "infra"],
    next_hints=["jadx_fleet_stop", "run_jadx"],
)
def jadx_fleet_status(fleet_id: str) -> dict[str, Any]:
    """Status of every unit in one fleet batch.

    Args:
        fleet_id: The ``fleet_id`` returned by ``jadx_fleet``.
    """
    queue = get_worker_queue()
    rows = queue.units_by_note(fleet_id)
    if not rows:
        # The batch may have finished + aged out of the live ledger; report
        # unknown rather than silently empty.
        return {
            "status": "unknown",
            "fleet_id": fleet_id,
            "error": (
                f"no live units carry batch {fleet_id!r} — either unknown, "
                "completed-and-swept, or already aged out (queued rows older "
                "than the TTL are swept). Re-check run_jadx workspaces."
            ),
        }
    out: dict[str, Any] = {
        "status": "ok",
        "fleet_id": fleet_id,
        "units": [],
        "pool": {},
    }
    counts: dict[str, int] = {}
    for r in rows:
        poll = queue.poll_unit(r["unit_key"])
        state = poll.get("status", "unknown")
        counts[state] = counts.get(state, 0) + 1
        entry: dict[str, Any] = {
            "unit_key": r["unit_key"],
            "target": r["target"],
            "status": state,
            "memory_budget": r["memory_budget"],
        }
        if state == "queued":
            entry["position"] = poll.get("position")
        elif state in ("running", "done", "launching"):
            entry["job_id"] = poll.get("job_id")
            entry["log_file"] = poll.get("log_file")
            if state == "done":
                from auxiliaries.jadx import _workspace_for, _workspace_state

                # The row's target IS the absolute input path the fleet
                # request already resolved — never re-resolve it against
                # the drop folder (an APK removed after decompile must
                # not hide the workspace it produced).
                path = r["target"]
                ws = _workspace_for(path)
                st = _workspace_state(ws, path)
                entry["workspace"] = ws
                entry["workspace_done"] = bool(st["exists"] and st["has_sources"])
        out["units"].append(entry)
    # Piggyback the queue sweep — finished units free their slots so the
    # next queued unit promotes on THIS status call, not just on reaper.
    adv = queue.advance_queue()
    acct = queue.account()
    out["pool"] = {
        "slots": acct["slots"],
        "running_claims_mib": acct["running_claims_mib"],
        "free_ram_mib": acct["free_ram_mib"],
        "ram_floor_mib": acct["ram_floor_mib"],
    }
    out["counts"] = counts
    out["sweep"] = {
        "freed": adv.get("freed", 0),
        "promoted": adv.get("promoted", 0),
        "blocked": adv.get("blocked", 0),
        "impossible": adv.get("impossible", 0),
    }
    running = counts.get("running", 0) + counts.get("launching", 0)
    queued = counts.get("queued", 0)
    if running == 0 and queued == 0:
        finished = counts.get("finished", 0) + counts.get("done", 0)
        out["message"] = (
            f"all units settled ({finished} finished, "
            f"{counts.get('cancelled', 0)} cancelled — check each unit's "
            "workspace (finished ones have source trees) and proceed with "
            "run_jadx(grep/read/tree)"
        )
    else:
        out["message"] = (
            f"{running} running/launching, {queued} queued. Poll again only "
            "when the user requests an update."
        )
    return out


@framework_tool(
    "Stop one or every running/queued unit of a jadx fleet batch (same-agent "
    "ownership; force=True is the operator-level cross-agent override). "
    "Running units are terminated via the job store; queued units are "
    "cancelled. Slots free immediately and the next QUEUED unit promotes on "
    "the next queue advance.",
    tags=["recon.binary", "infra"],
)
def jadx_fleet_stop(fleet_id: str, force: bool = False) -> dict[str, Any]:
    """Stop a fleet batch's running/queued units.

    Args:
        fleet_id: The ``fleet_id`` from ``jadx_fleet``.
        force: Operator-level crossing of agent ownership.
    """
    queue = get_worker_queue()
    rows = queue.units_by_note(fleet_id)
    if not rows:
        return {
            "status": "unknown",
            "fleet_id": fleet_id,
            "error": f"no live units carry batch {fleet_id!r}",
        }
    from utils.agent_identity import current_agent_id

    caller = current_agent_id()
    stopped, cancelled, skipped, refused = [], [], [], []
    for r in rows:
        if r["status"] in ("launched",) and r["job_id"]:
            from utils.job_store import get_store

            result = get_store().stop(r["job_id"], force=force)
            if result.get("status") == "ok":
                stopped.append(r["job_id"])
            else:
                refused.append(r["unit_key"])
            continue
        if r["status"] == "queued":
            res = queue.cancel_unit(r["unit_key"], agent_id=caller, force=force)
            if res.get("status") == "cancelled":
                cancelled.append(r["unit_key"])
            elif res.get("status") == "refused":
                refused.append(r["unit_key"])
            else:
                skipped.append(r["unit_key"])
            continue
        skipped.append(r["unit_key"])
    queue.advance_queue()
    return {
        "status": "ok",
        "fleet_id": fleet_id,
        "stopped_jobs": stopped,
        "cancelled_queued": cancelled,
        "skipped": skipped,
        "refused": refused,
        "message": (
            f"{len(stopped)} job(s) terminated, {len(cancelled)} queued "
            "cancelled." + (
                f" {len(refused)} refused (ownership — pass force=True)."
                if refused else ""
            )
        ),
    }


@framework_tool(
    "Show worker-queue pool pressure for bounded-memory decompile lanes: "
    "slots, running memory claims, measured free RAM, the reservation floor, "
    "and every live unit row. Use BEFORE launching big-APK decompiles to see "
    "whether the pool can actually back the budgets you plan to request.",
    tags=["infra"],
)
def worker_queue_status() -> dict[str, Any]:
    """Worker-queue pool observability (slots, claims, free RAM, rows)."""
    return get_worker_queue().host_pressure()