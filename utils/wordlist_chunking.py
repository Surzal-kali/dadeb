"""Wordlist-shaped budget chunking (evasion_upgrade.md §2, U2 lane).

Engine-side helpers — no argparse, no @framework_tool, no model-lane
surface (§8.2: the model lane stays read-only; these mint/advance from
the executor's tool body, the drain, and the status lens only).

The lane: a wordlist tool whose true request vector exceeds the
constitution's max_single never launches whole. The tool body:

1. **single** — lines fit: launch as today (the estimator now declares
   the honest line count).
2. **plan** — lines fit only when sliced: mint ONE queue plan (zero
   traffic this call), return a ``chunk_plan`` envelope, and let the
   operator drain pay out the work in slice-sized queue items, lazily
   minting the next window as sibling chunks VERIFIED-finish.
3. **chunk** — this call IS one slice: slice the wordlist at dispatch
   into ``run/wordlist_chunks/<plan>/<i>.txt``, launch through the
   normal job path, and map fleet duplicate/transient refusals back
   into the queue (requeue the SAME chunk, never a second debit).

Shared with the estimator: :func:`lane_decision` is the ONE predicate
the estimator and the wrapper both read, so preflight and body can
never disagree about plan-vs-single-shot (§2 principle).
"""

from __future__ import annotations

import logging
import math
import os
import secrets
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Argument keys the chunk lane owns (never collide with tool-native args;
# the wrapper strips nothing — ffuf has no such flag names).
CHUNK_PLAN_ID = "chunk_plan_id"
CHUNK_INDEX = "chunk_index"
CHUNK_OFFSET = "chunk_offset"
CHUNK_SLICE = "chunk_slice"
CHUNK_TOTAL = "chunk_total_chunks"
CHUNK_KEYS = (CHUNK_PLAN_ID, CHUNK_INDEX, CHUNK_OFFSET, CHUNK_SLICE,
              CHUNK_TOTAL)

_PLAN_PREFIX = "wp-"
_SLICE_DIR = "wordlist_chunks"          # under the workspace run/ root


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int, *, minimum: int = 1) -> int:
    try:
        return max(minimum, int(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return default


def plan_window_default() -> int:
    """Chunks minted per window (§2.1 lazy frontier) — defaults to the
    drain batch so a fresh window is exactly one tick's appetite."""
    return _env_int("BUDGET_PLAN_WINDOW", 8, minimum=1)


def plan_enabled() -> bool:
    return _env_bool("BUDGET_WORDLIST_CHUNK", True)


def plan_ttl_hours() -> float:
    try:
        return max(0.1, float(os.environ.get("BUDGET_PLAN_TTL_HOURS", 24.0)))
    except (TypeError, ValueError):
        return 24.0


def read_wordlist_lines(path: str | os.PathLike) -> int:
    """Streamed line count — the wordlist never loads wholesale (some
    SecLists members are tens of MB). A missing/unreadable path is 0;
    the caller treats 0 as not-a-wordlist-affair."""
    try:
        with open(path, "rb") as fh:
            n = 0
            for _ in fh:
                n += 1
            return n
    except OSError:
        logger.debug("swallowed open in read_wordlist_lines (%r)",
                     str(path), exc_info=True)
        return 0


def slice_bounds(chunk_index: int, chunk_size: int, total_lines: int
                 ) -> tuple[int, int]:
    """0-based (offset, size) of a chunk — the pure arithmetic shared by
    the minter, the slicer, and the envelope."""
    offset = chunk_index * chunk_size
    size = min(chunk_size, max(0, total_lines - offset))
    return offset, size


def run_dir() -> Path:
    from constants import resolve_workspace_root
    return Path(resolve_workspace_root()) / "run" / _SLICE_DIR


# --- the shared predicate ----------------------------------------------------

def resolved_ffuf_wordlist(arguments: dict | None) -> str | None:
    """Mirrors run_ffuf's body resolution (wordlists.py is the single
    source): explicit path resolved, else the SecLists ``ffuf`` default.
    None = not resolvable (the tool body then errors out on its own)."""
    from utils.wordlists import resolve_default_wordlist, resolve_wordlist
    args = arguments if isinstance(arguments, dict) else {}
    wl = str(args.get("wordlist") or "").strip()
    if wl:
        try:
            return resolve_wordlist(wl)
        except Exception:
            logger.debug("swallowed wordlist resolve", exc_info=True)
            return None
    try:
        return resolve_default_wordlist("ffuf")
    except Exception:
        logger.debug("swallowed default wordlist resolve", exc_info=True)
        return None


def max_single_vector() -> dict[str, float] | None:
    """The constitution's max_single (never-fit ceiling per dim), or None
    when the budget machinery is unreadable (fail-open is NOT honest here —
    callers must treat None as 'lane cannot decide', not as single-shot)."""
    try:
        from utils.ration import constitution
        return constitution().max_single()
    except Exception as exc:
        logger.debug("swallowed constitution read in max_single_vector",
                     exc_info=True)
        return None


def lane_decision(tool_id: str, arguments: dict | None,
                  wordlist: str | os.PathLike | None) -> dict | None:
    """ONE predicate the estimator and the tool body both read (§2).

    Returns, in order:
    - ``None`` — the lane cannot/should not decide (budget disabled,
      tool unregistered, chunking off, no wordlist, empty list, or an
      unreadable constitution): the caller behaves exactly as the
      pre-lane tool did.
    - ``{"mode": "chunk", ...}`` — the arguments carry chunk keys; this
      dispatch IS one plan slice (the estimator then declares the
      slice's vector; the body slices + launches).
    - ``{"mode": "single", "lines": n}`` — everything fits in one call.
    - ``{"mode": "plan", "lines": n, "slices": {...}}`` — the true
      vector is never-fit; the body must mint a plan and return the
      ``chunk_plan`` envelope (a zero-emission dispatch).
    """
    if not plan_enabled():
        return None
    from utils.ration import WORDLIST_TOOL_VECTORS
    arguments = arguments if isinstance(arguments, dict) else {}
    if arguments.get(CHUNK_PLAN_ID):
        try:
            decision = {
                "mode": "chunk",
                "plan_id": str(arguments[CHUNK_PLAN_ID]),
                "chunk_index": max(0, int(arguments.get(CHUNK_INDEX, 0))),
                "chunk_offset": max(0, int(arguments.get(CHUNK_OFFSET, 0))),
                "chunk_size": max(1, int(arguments.get(CHUNK_SLICE, 0))),
                "total_chunks": max(1, int(arguments.get(CHUNK_TOTAL, 1))),
            }
        except (TypeError, ValueError):
            logger.debug("malformed chunk keys in lane_decision", exc_info=True)
            return None
        decision["decl"] = {
            d: (None if (v is None or v <= 0)
                else decision["chunk_size"] * v)
            for d, v in WORDLIST_TOOL_VECTORS.get(tool_id, {}).items()}
        return decision
    if not wordlist or not _budget_lane_ready(tool_id):
        return None
    lines = read_wordlist_lines(wordlist)
    if lines <= 0:
        return None
    ms = max_single_vector()
    if ms is None:
        return None
    vector = WORDLIST_TOOL_VECTORS.get(tool_id)
    if vector is None:
        return None
    fits_in_one = all(
        (v is None or v <= 0 or lines * v <= ms.get(d, math.inf))
        for d, v in vector.items())
    if fits_in_one:
        return {"mode": "single", "lines": lines, "wordlist": str(wordlist),
                "decl": {d: (None if (v is None or v <= 0) else lines * v)
                         for d, v in vector.items()}}
    # Sliced: chunk size = the largest n where EVERY dim's n×per-unit
    # stays under max_single (§2.2 — min across dims, clamped ≥1); the
    # binding dim is the tightest one. pkg7: the slice then shrinks to
    # what ONE epoch funds (min over dims of refill_per_epoch ÷ per-unit)
    # whenever tighter — the burst-ceiling slice emptied a funded chunk
    # at the tool's own wire speed while the ledger refilled exactly one
    # epoch per chunk (bursts separated by dead air). An epoch-funded
    # slice is payable the moment it is minted, and epoch_pacing spreads
    # it across that epoch instead of bursting it.
    best_dim, best_n = None, lines
    for d, v in vector.items():
        if v is None or v <= 0:
            continue
        cap = ms.get(d, math.inf)
        if not math.isfinite(cap):
            continue     # unbounded dim cannot bind (pkg7: partial max_single)
        n = max(1, int(math.floor(cap / v)))
        if n < best_n or (n == best_n and best_dim is None):
            best_n, best_dim = n, d
    chunk_size = max(1, best_n)
    pace_epoch_s = None
    funding = epoch_funding()
    if funding is not None:
        epoch_s, refills = funding
        for d, v in vector.items():
            if v is None or v <= 0:
                continue
            refill = refills.get(d, 0.0)
            if refill <= 0:
                continue
            n = max(1, int(math.floor(refill / v)))
            if n < chunk_size:
                chunk_size, best_dim, pace_epoch_s = n, d, epoch_s
    total_chunks = int(math.ceil(lines / chunk_size))
    return {"mode": "plan", "lines": lines, "chunk_size": chunk_size,
            "pace_epoch_s": pace_epoch_s,
            "total_chunks": total_chunks, "wordlist": str(wordlist),
            "binding_dim": best_dim or "requests",
            "window": min(total_chunks, plan_window_default()),
            "slices": {d: (None if (v is None or v <= 0)
                           else chunk_size * v)
                       for d, v in vector.items()}}


def epoch_funding() -> tuple[float, dict[str, float]] | None:
    """``(epoch_seconds, {dim: refill_per_epoch})`` from the LIVE law, or
    ``None`` when the constitution is unreadable — callers must keep the
    max_single slice in that case, never guess (same contract as
    max_single_vector)."""
    try:
        from utils.ration import constitution
        c = constitution()
        policy = c.policy()
    except Exception:
        logger.debug("swallowed constitution read in epoch_funding",
                     exc_info=True)
        return None
    refills = {d: float(spec.get("refill_per_epoch", 0.0))
               for d, spec in policy.items()}
    return float(c.epoch_s), refills


def epoch_pacing(slice_lines: int) -> dict | None:
    """The wire leg of the drum (pkg7): pace ONE chunk's requests across
    the epoch that funds it. ffuf's ``-rate`` is an integer req/s, so the
    rate floors at 1 — a slower law (slice/epoch < 1) still gets 1/s, and
    per-epoch funding governs launch cadence, not ffuf's burst pool.
    ``None`` = constitution unreadable (launch stays unshaped)."""
    if slice_lines <= 0:
        return None
    funding = epoch_funding()
    if funding is None:
        return None
    epoch_s, _refills = funding
    if epoch_s <= 0:
        return None
    rate = max(1, int(math.floor(slice_lines / epoch_s)))
    return {"rate_per_second": rate, "epoch_s": epoch_s}


def _budget_lane_ready(tool_id: str) -> bool:
    """True when the budget economy will actually police this dispatch
    (BUDGET_ENABLED + estimator engaged) — otherwise chunking is a
    pointless re-implementation of the same blast."""
    try:
        from utils.ration import _env_bool, DEFAULT_ENABLED
        if not _env_bool("BUDGET_ENABLED", DEFAULT_ENABLED):
            return False
    except Exception:
        logger.debug("swallowed env probe in _budget_lane_ready",
                     exc_info=True)
        return False
    try:
        from utils.ration import _estimator_engaged
        return _estimator_engaged(tool_id)
    except Exception:
        logger.debug("swallowed engaged probe in _budget_lane_ready",
                     exc_info=True)
        return False


# --- plan minting + advance --------------------------------------------------

def mint_wordlist_plan(tool_id: str, arguments: dict, decision: dict, *,
                       decl: dict, dims: dict, agent_id: str,
                       engagement: str | None, priority: int = 0) -> dict:
    """Mint the plan row + the FIRST window of chunk queue items.

    The plan (and its items) carry the tool's ORIGINAL arguments verbatim
    plus chunk keys — the drain re-dispatches through the full chokepoint
    (gate → estimator slice-vector → body slice → launch), never around
    it. Returns the plan row dict."""
    from utils.ration import get_ration_store
    store = get_ration_store()
    plan_id = f"{_PLAN_PREFIX}{secrets.token_hex(6)}"
    now = None
    plan = store.plan_insert(
        plan_id=plan_id, tool=tool_id, arguments=arguments, decl=decl,
        dims=dims, wordlist=str(decision.get("wordlist") or ""),
        lines=int(decision["lines"]), chunk_size=int(decision["chunk_size"]),
        total_chunks=int(decision["total_chunks"]),
        binding_dim=str(decision["binding_dim"]),
        window=int(decision["window"]), agent_id=agent_id,
        engagement=engagement, priority=priority,
        ttl_hours=plan_ttl_hours())
    _mint_window(store, plan, now=now)
    return store.plan_get(plan_id)


def _mint_window(store, plan: dict, *, now: float | None = None) -> int:
    """Mint the next absent chunk indices up to ``window`` outstanding or
    in-flight items (§2.1 lazy frontier: window W, not all 23K)."""
    counts = store.plan_counts(plan["plan_id"])
    active = sum(counts.get(s, 0)
                 for s in ("queued", "launching", "launched"))
    window = max(1, int(plan["window"]))
    total = int(plan["total_chunks"])
    minted = 0
    while active + minted < window:
        idx = store.plan_next_index(plan["plan_id"])
        if idx is None or idx >= total:
            break
        offset, size = slice_bounds(idx, int(plan["chunk_size"]),
                                    int(plan["lines"]))
        chunk_meta = {
            "plan_id": plan["plan_id"], "chunk_index": idx,
            "chunk_offset": offset, "chunk_size": size,
            "total_chunks": total, "binding_dim": plan["binding_dim"],
            "wordlist": plan["wordlist"],
        }
        store.enqueue_item(
            tool=plan["tool"], arguments=_chunk_arguments(plan, idx),
            decl=plan["declared"], dims=plan["dims"],
            reason=(f"wordlist plan {plan['plan_id']} chunk {idx + 1}/"
                    f"{total} (bind: {plan['binding_dim']})"),
            agent_id=plan["agent_id"], engagement=plan["engagement"],
            priority=int(plan["priority"] or 0),
            ttl_hours=plan_ttl_hours(),
            parent_plan_id=plan["plan_id"], chunk_index=idx,
            chunk_meta=chunk_meta, now=now)
        minted += 1
    return minted


def _chunk_arguments(plan: dict, chunk_index: int) -> dict:
    args = dict(plan["arguments"] or {})
    offset, size = slice_bounds(chunk_index, int(plan["chunk_size"]),
                                int(plan["lines"]))
    args.update({
        CHUNK_PLAN_ID: plan["plan_id"],
        CHUNK_INDEX: chunk_index,
        CHUNK_OFFSET: offset,
        CHUNK_SLICE: size,
        CHUNK_TOTAL: int(plan["total_chunks"]),
    })
    return args


def mint_window(plan_id: str, *, now: float | None = None) -> int:
    """Public entry for the drain/status lens: mint the next lazy window."""
    from utils.ration import get_ration_store
    store = get_ration_store()
    plan = store.plan_get(plan_id)
    if plan is None or plan.get("state") != "open":
        return 0
    return _mint_window(store, plan, now=now)


def plan_view(plan_id: str) -> dict | None:
    from utils.ration import get_ration_store
    return get_ration_store().plan_get(plan_id)


def advance_plans(*, now: float | None = None, limit: int = 8) -> dict:
    """Observe launched chunk jobs (VERIFIED via poll_job only — a missing
    job row is never proof of completion, fleet doctrine), finish their
    queue items, mint the next window, and settle fully-minted plans.

    Called at the start of every operator drain tick and from the status
    lens — engine-side, never from a model lane."""
    from utils.ration import get_ration_store
    store = get_ration_store()
    plans = [dict(r) for r in store.conn.execute(
        "SELECT plan_id FROM queue_plans WHERE state='open' "
        "ORDER BY requested LIMIT ?", (limit,))]
    out = {"observed": 0, "finished": 0, "minted": 0, "settled": [],
           "expired": [], "failed_plans": []}
    ttl_s = plan_ttl_hours() * 3600.0
    for prow in plans:
        plan_id = prow["plan_id"]
        plan = store.plan_get(plan_id)
        if plan is None or plan.get("state") != "open":
            continue
        latest = float(plan.get("requested") or 0.0)
        for chunk in store.plan_chunks(plan_id):
            latest = max(latest, float(chunk.get("requested") or 0.0))
        if now is not None and (now - latest) > ttl_s:
            # §2.5 TTL: measured from the LAST minted window, not the plan
            # mint time (a lazy frontier under a slow drain would otherwise
            # expire mid-work); launch-side items still expire their own
            # 24h window TTLs in sweep_expired.
            store.cancel_plan(plan_id, note="no activity past TTL")
            out["expired"].append(plan_id)
            continue
        for chunk in store.plan_chunks(plan_id, status="launched"):
            ref = chunk.get("job_ref")
            if not ref:
                # drain bound nothing — a crash-stale claim; back to queued
                store.release_item(chunk["qid"])
                out["observed"] += 1
                continue
            try:
                from utils.background_job import poll_job
                env = poll_job(ref) or {}
                status = str(env.get("status") or "")
            except Exception:
                logger.debug("swallowed poll in advance_plans (%s)", ref,
                             exc_info=True)
                continue
            out["observed"] += 1
            if status.lower() in ("done", "failed"):
                # §4 P0 rollup (2026-11-07): harvest the verdict envelope at
                # observation time — the log file it points at is TTL-swept,
                # so the plan lens needs its own copy to roll up results.
                try:
                    store.record_plan_verdict(
                        plan_id, chunk["qid"],
                        chunk_index=int(chunk.get("chunk_index") or 0),
                        job_ref=str(ref or ""), envelope=dict(env))
                except Exception:
                    logger.debug("swallowed plan-verdict record (%s)", ref,
                                 exc_info=True)
                store.finish_item(chunk["qid"])
                out["finished"] += 1
        out["minted"] += mint_window(plan_id, now=now)
        counts = store.plan_counts(plan_id)
        total = int(counts.get("total_chunks") or 0)
        minted = int(counts.get("minted") or 0)
        finished = int(counts.get("finished") or 0)
        if total > 0 and minted >= total and finished >= total:
            store.plan_set_state(plan_id, "finished")
            out["settled"].append(plan_id)
            continue
        # Dead-plan seam close (2026-11-06): bounded-failure exits cancel
        # chunks; when EVERY minted chunk is terminal (finished/cancelled/
        # failed) and the whole frontier is minted, the plan is unrunnable —
        # settle it 'failed' with the terminal chunk's note surfaced in the
        # advance result, instead of an eternally 'open' plan nothing will
        # ever drain or mint. budget_queue_status then reads the truth.
        cancelled = int(counts.get("cancelled") or 0)
        failed = int(counts.get("failed") or 0)
        done = finished + cancelled + failed
        if total > 0 and minted >= total and done >= total:
            reason = "all chunks terminal without completion"
            for chunk in store.plan_chunks(plan_id, status="failed") + \
                    store.plan_chunks(plan_id, status="cancelled"):
                if chunk.get("notes_json"):
                    reason = f"chunk {chunk['qid']}: {chunk['notes_json']}"
                    break
            store.plan_set_state(plan_id, "failed")
            out["failed_plans"].append({"plan_id": plan_id,
                                        "reason": reason})
    return out


# --- dispatch-time slicing ---------------------------------------------------

def write_slice(plan_id: str, chunk_index: int, wordlist: str | os.PathLike,
                offset: int, size: int) -> Path:
    """Materialize THIS chunk's lines as run/<_SLICE_DIR>/<plan>/<i>.txt at
    dispatch time (§2.2: slices happen at dispatch, not minting)."""
    src = Path(wordlist)
    dest = run_dir() / plan_id
    dest.mkdir(parents=True, exist_ok=True)
    out = dest / f"{chunk_index}.txt"
    tmp = out.with_suffix(out.suffix + ".tmp")
    with open(src, "rb") as fh:
        with open(tmp, "wb") as w:
            for lineno, line in enumerate(fh):
                if lineno < offset:
                    continue
                if lineno >= offset + size:
                    break
                w.write(line)
            w.flush()
            os.fsync(w.fileno())
    os.replace(tmp, out)
    try:
        os.chmod(out, 0o600)
    except OSError:
        logger.debug("swallowed chmod in write_slice", exc_info=True)
    return out


def requeued_envelope(plan_id: str, *, chunk_index: int, total: int,
                      reason: str, sibling_job_id: str | None = None,
                      requeue_note: str = "") -> dict:
    """The honest envelope a chunk dispatch returns when its launch hit a
    fleet duplicate (the sibling unit owns this work) or a TRANSIENT
    fleet refusal: the chunk is re-enqueued in the plan's queue, NOTHING
    was launched from this attempt, and the operator drain keeps paying.

    Deliberately NOT keying ``job_id``/``jobId`` — the discharge's job-id
    bind scan would mistake a sibling's live job for ours."""
    from utils.ration import get_ration_store
    store = get_ration_store()
    item = store.get_item_by_plan_chunk(plan_id, chunk_index)
    if item is None:
        # the plan row vanished (purged/expired between dispatch and
        # requeue) — nothing to requeue; report honestly instead.
        return {"status": "chunk_plan_lost", "plan_id": plan_id,
                "chunk_index": chunk_index, "total_chunks": total,
                "reason": reason}
    out = {
        "status": "requeued", "requeued": True,
        "plan_id": plan_id, "chunk_index": chunk_index,
        "total_chunks": total, "queue_id": item["qid"],
        "reason": reason,
        "note": (requeue_note
                 or "chunk re-enqueued in its plan; the drain will retry "
                    "it in due order — do NOT relaunch this chunk by hand"),
    }
    return out


__all__ = [
    "CHUNK_KEYS", "CHUNK_PLAN_ID", "CHUNK_INDEX", "CHUNK_OFFSET",
    "CHUNK_SLICE", "CHUNK_TOTAL", "advance_plans", "lane_decision",
    "mint_window", "mint_wordlist_plan", "plan_enabled",
    "plan_ttl_hours", "plan_window_default", "read_wordlist_lines",
    "requeued_envelope", "slice_bounds", "write_slice",
]
