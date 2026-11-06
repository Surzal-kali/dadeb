"""Ration engine — the budget/deferral policy layer (evasion_design.md).

The store (``utils/ration_store.py``) owns persistence and the atomic
cascade; THIS module owns policy:

- **BudgetVector arithmetic** — the 4 dims (requests / packets /
  auth_events / bytes), ``covers`` semantics, credit-line dims (``None``
  = open-ended for this call, never blocks, stamped on the emission row).
- **Constitution** (§8) — config-authored node policy: per-dim ceiling
  (burst capacity), ``refill_per_epoch`` (steady replenish), ``floor``
  (HOLD-mode minimum — **floor-0 is forbidden**, §6.2), and
  ``max_single_call`` REJECT thresholds. Authored via env knobs
  (``BUDGET_CONSTITUTION`` inline JSON / ``BUDGET_CONSTITUTION_FILE``) with
  honest code defaults; validation failures raise and callers convert to
  the fail-closed Unknown verdict — a broken constitution NEVER degrades
  to green.
- **L0 estimator registry** (§4.2) — per-tool declared cost vectors, three
  bases: ``measured`` (the tool knows exactly) / ``estimation`` (honest
  computed guess, seeds tripwire) / ``credit_line`` (open-ended — drawn at
  admission, true-up at L1). An unregistered tool runs full credit-line
  mode. Under-keying is ALWAYS the conservative failure (§4.2 rule).
- **Preflight routing** (§3 step 2, read-only) — budget REJECT
  (never-fit), budget ENQUEUE (short; duplicate=satisfied at enqueue), or
  ADMIT (caller proceeds to fleet, then the atomic debit).
- **Operator skeleton** (§7, REPL-owned) — the drain loop over due queue
  items with the duplicate=satisfied check, the Brain no-retry rule (a
  timed-out dispatch is NOT re-enqueued), and the per-tick batch cap.
  Jittered cadence + release epochs land in Phase C; the floor interval
  is already honored.

Phase A note (build gate): the engine is NOT yet wired into
``daharness/executor.py`` — the dispatch chokepoint integration is the
Phase B surface. ``BUDGET_ENABLED`` gates the wiring, not this module
(exercises the engine in tests regardless? no — preflight respects the
knob; tests turn it on explicitly).

No numpy in this engine (pure stdlib; §13 decision 2026-11-03).
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlparse
import ipaddress
import random
import re as _re

from constants import framework_tool
from utils.ration_store import (DIMS, HARD_CLASSES, QUIET_CLASSES, RationStore,
                                SOFT_CLASSES)

logger = logging.getLogger(__name__)

_IPV4_RE = _re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _lazy_fleet():
    """Shared fleet helpers (span normalization + WAL race fix) — lazy so the
    ration engine import stays cheap and cycle-free."""
    from utils.fleet_scheduler import _numeric_axis, _numeric_span, _set_wal
    return _numeric_axis, _numeric_span, _set_wal

# Budget knob for the whole engine (kill-switch + A/B). Default ON per the
# design (ALWAYS L0); flip to 0 to shelve enforcement without uninstalling.
DEFAULT_ENABLED = True

_EPOCH_S_DEFAULT = 3600.0
_QUEUE_TTL_H_DEFAULT = 24.0
_DRAIN_BATCH_DEFAULT = 8
# Cadence between operator ticks lands Phase C (jittered controller loop);
# kept as the named knob the docstring promised so the constant stays the
# single place to set the floor.
_DRAIN_MIN_INTERVAL_S_DEFAULT = 2.0
_PRINCIPAL_WINDOW_H_DEFAULT = 168.0


def _env_float(name: str, default: float, *, minimum: float | None = None) -> float:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        v = float(raw)
    except ValueError:
        raise ValueError(f"{name}={raw!r} is not a number") from None
    if minimum is not None and v < minimum:
        raise ValueError(f"{name}={v} below minimum {minimum}")
    return v


def _env_int(name: str, default: int, *, minimum: int | None = None) -> int:
    return int(_env_float(name, float(default), minimum=None if minimum is None else float(minimum)))


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw not in ("0", "false", "no", "off")


class BudgetStillShort(Exception):
    """Raised by a drain dispatcher when a drain dispatch returned the ration
    gate's ``budget_deferred`` envelope. The queue item must survive — it is
    NEVER consumed as 'finished' by an envelope that just re-deferred."""

    def __init__(self, *, queue_id: str | None = None, message: str = ""):
        self.queue_id = queue_id
        super().__init__(message or f"budget still short (minted {queue_id})")


class BudgetRefused(Exception):
    """Raised by a drain dispatcher when a drain dispatch returned the
    ration gate's ``budget_refused`` envelope (never-fit / fail-closed
    store): the item can never run, so operator_tick cancels it with an
    honest note instead of looping it until TTL."""

    def __init__(self, *, reason: str = "", message: str = ""):
        self.reason = reason
        super().__init__(message or f"budget refused: {reason}")


# Credit-line draws (§7.1): an open emission true-ups at job release; a draw
# with no deterministic actuals honest-closes (declared stands, never
# guessed). ``BUDGET_DRAW_TTL_HOURS`` is the backstop for draws whose job
# never reconciled.
_DRAW_TTL_H_DEFAULT = 24.0


# ─── Constitution (§8) ────────────────────────────────────────────────────────

_DIM_DEFAULTS = {
    "requests":    {"ceiling": 600.0, "refill_per_epoch": 100.0, "floor": 2.0},
    "packets":     {"ceiling": 2_000_000.0, "refill_per_epoch": 250_000.0, "floor": 500.0},
    "auth_events": {"ceiling": 60.0, "refill_per_epoch": 5.0, "floor": 0.2},
    "bytes":       {"ceiling": 268_435_456.0, "refill_per_epoch": 33_554_432.0,
                    "floor": 262_144.0},
}
_MAX_SINGLE_CALL = {
    "requests": 600.0,
    "packets": 2_000_000.0,
    "auth_events": 60.0,
    "bytes": 268_435_456.0,
}


@dataclass(frozen=True)
class Constitution:
    """Immutable node policy the engine stamps onto every node."""

    defaults: dict[str, dict[str, float]]
    max_single_call: dict[str, float]
    epoch_s: float

    def policy(self) -> dict[str, dict[str, float]]:
        return {d: dict(self.defaults[d]) for d in DIMS}

    def max_single(self) -> dict[str, float]:
        return dict(self.max_single_call)

    @staticmethod
    def validate(defaults: dict, max_single: dict, epoch_s: float) -> None:
        """Floor-0 is FORBIDDEN (permanent-HOLD bug, §6.2); refill-0 strands a
        drained node forever; a single call larger than the burst is never-fit
        material (that's max_single_call's job, and it must not exceed the
        burst ceiling it would have to draw from)."""
        for d in DIMS:
            spec = defaults.get(d)
            if not spec:
                raise ValueError(f"constitution missing dim {d!r}")
            for k in ("ceiling", "refill_per_epoch", "floor"):
                if k not in spec or not isinstance(spec[k], (int, float)):
                    raise ValueError(f"constitution {d}.{k} missing/not numeric")
            if spec["ceiling"] <= 0:
                raise ValueError(f"constitution {d}.ceiling must be > 0")
            if spec["floor"] <= 0:
                raise ValueError(
                    f"constitution {d}.floor must be > 0 "
                    "(floor-0 = permanent-HOLD bug; §6.2)")
            if spec["refill_per_epoch"] <= 0:
                raise ValueError(f"constitution {d}.refill_per_epoch must be > 0")
            ms = max_single.get(d)
            if ms is not None:
                if not isinstance(ms, (int, float)) or ms <= 0:
                    raise ValueError(f"constitution max_single_call.{d} invalid")
                if ms > spec["ceiling"]:
                    raise ValueError(
                        f"max_single_call.{d}={ms} exceeds burst ceiling "
                        f"{spec['ceiling']} — a single call can never fit")
        if epoch_s <= 0:
            raise ValueError("epoch_s must be > 0")


def constitution(
    *, now: float | None = None
) -> Constitution:
    """The constitution, built from env at CALL time (lane convention:
    per-call env reads make tests and operator edits take effect without a
    process restart). Raises on invalid authoring — callers convert to the
    fail-closed Unknown verdict, never green."""
    epoch_s = _env_float("BUDGET_EPOCH_SECONDS", _EPOCH_S_DEFAULT, minimum=1.0)
    defaults = {d: dict(_DIM_DEFAULTS[d]) for d in DIMS}
    max_single = dict(_MAX_SINGLE_CALL)
    raw = os.getenv("BUDGET_CONSTITUTION", "").strip()
    raw_file = os.getenv("BUDGET_CONSTITUTION_FILE", "").strip()
    overrides = None
    if raw_file:
        with open(raw_file) as fh:
            overrides = json.load(fh)
    elif raw:
        overrides = json.loads(raw)
    if isinstance(overrides, dict):
        user_defaults = overrides.get("defaults") or {}
        for d, spec in user_defaults.items():
            if d in DIMS and isinstance(spec, dict):
                cur = dict(defaults[d])
                cur.update({k: spec[k] for k in cur if k in spec})
                defaults[d] = cur
        user_max = overrides.get("max_single_call") or {}
        for d, v in user_max.items():
            if d in DIMS and v is not None:
                max_single[d] = float(v)
    Constitution.validate(defaults, max_single, epoch_s)
    return Constitution(defaults=defaults, max_single_call=max_single,
                        epoch_s=epoch_s)


# ─── BudgetVector ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class BudgetVector:
    """Declared per-dim cost. A dim of ``None`` = open-ended for this
    emission (credit-line mode: always admit, L1 true-up fixes later)."""

    requests: int | None = None
    packets: int | None = None
    auth_events: int | None = None
    bytes: int | None = None

    def as_dict(self) -> dict:
        return {d: getattr(self, d) for d in DIMS}

    def __post_init__(self) -> None:
        for d in DIMS:
            v = getattr(self, d)
            if v is not None and (not isinstance(v, (int, float)) or v < 0):
                raise ValueError(f"BudgetVector.{d} must be >= 0 or None")


# ─── L0 estimator registry (§4.2) ────────────────────────────────────────────

@dataclass(frozen=True)
class Estimator:
    tool_id: str
    basis: str           # "measured" | "estimation" | "credit_line"
    fn: Callable[[str | None, dict], dict]
    name: str


_ESTIMATORS: dict[str, Estimator] = {}
# RLock, not Lock: ensure_seed_estimators holds this while decorating, and
# register_estimator's body takes it again on the same thread — a plain Lock
# self-deadlocks there (same class as the brain_sessions 2026-10-29 lesson).
_ESTIMATORS_LOCK = threading.RLock()
_SEEDED = threading.Event()


def register_estimator(tool_id: str, *, basis: str = "estimation",
                       name: str | None = None):
    """Register a declaration fn for ``tool_id``:
    ``fn(target, arguments) -> {dim: int|None}``."""
    if basis not in ("measured", "estimation", "credit_line"):
        raise ValueError(f"bad estimator basis {basis!r}")

    def deco(fn: Callable[[str | None, dict], dict]) -> Callable:
        with _ESTIMATORS_LOCK:
            _ESTIMATORS[tool_id] = Estimator(
                tool_id=tool_id, basis=basis,
                fn=fn, name=name or fn.__name__)
        return fn
    return deco


def resolve_declaration(
    tool_id: str, target: str | None, arguments: dict | None
) -> tuple[dict, str, str]:
    """The declared vector + (estimator name, basis) for a dispatch.
    Unregistered tools run FULL credit-line mode (all-open-ended) — the
    honest default: never guessed, always metered at L1."""
    arguments = arguments or {}
    with _ESTIMATORS_LOCK:
        est = _ESTIMATORS.get(tool_id)
    if est is None:
        return ({d: None for d in DIMS}, "unregistered", "credit_line")
    try:
        decl = est.fn(target, arguments)
    except Exception as exc:
        logger.warning("[ration] estimator %s failed (%s) — credit-line",
                       est.name, exc)
        return ({d: None for d in DIMS}, f"{est.name}@error", "credit_line")
    clean = {d: (None if decl.get(d) is None
                 else max(0, int(decl[d]))) for d in DIMS}
    return clean, est.name, est.basis


def _count_ports(spec: str) -> int:
    """Honest nmap -p port-count for the estimation seed (no nmap import)."""
    spec = (spec or "").strip().strip('"\'')
    if not spec:
        return 1000  # nmap's default top-1000s port probe
    total = 0
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            try:
                lo, hi = int(a or 1), int(b or 65535)
            except ValueError:
                return 65535  # can't parse → assume worst
            total += max(0, hi - lo + 1)
        else:
            try:
                total += 1
            except ValueError:
                return 65535
    return min(total, 65535)


def _target_host_count(target: str | None) -> int:
    """Approximate address count of a numeric target (span-aware, via the
    fleet's shared span normalizer — no fork); hostnames count as 1."""
    if not target:
        return 1
    _numeric_axis, _numeric_span, _ = _lazy_fleet()
    span = _numeric_span(target)
    if span is None:
        return 1
    lo, hi = span
    return max(1, hi - lo + 1)


def ensure_seed_estimators() -> None:
    """Idempotent registration of the Chapter-B seed families. Seeds err
    OPEN (None dims) — under-keying beats over-claiming (§4.2)."""
    if _SEEDED.is_set():
        return
    with _ESTIMATORS_LOCK:
        if _SEEDED.is_set():
            return

        @register_estimator("auxiliaries.web_session.session_get",
                            basis="measured", name="web_session_get")
        def _sess_get(target, arguments):  # one measured request per call
            return {"requests": 1, "packets": None, "auth_events": None,
                    "bytes": None}

        @register_estimator("auxiliaries.web_session.session_post",
                            basis="measured", name="web_session_post")
        def _sess_post(target, arguments):
            return {"requests": 1, "packets": None, "auth_events": None,
                    "bytes": None}

        @register_estimator("auxiliaries.web_session.session_request",
                            basis="measured", name="web_session_request")
        def _sess_req(target, arguments):
            return {"requests": 1, "packets": None, "auth_events": None,
                    "bytes": None}

        @register_estimator("auxiliaries.nmap.run_nmap",
                            basis="estimation", name="nmap_ports")
        def _nmap(target, arguments):
            options = str(arguments.get("options") or "")
            m = None
            for flag in ("-p", "--ports"):
                idx = options.find(flag)
                if idx != -1 and options[idx:idx + len(flag)]:
                    rest = options[idx + len(flag):].lstrip()
                    if rest.startswith("="):
                        rest = rest[1:]
                    m = rest.split()[0] if rest.split() else ""
                    break
            ports = _count_ports(m)
            hosts = _target_host_count(target)
            return {"requests": 0, "packets": hosts * ports,
                    "auth_events": 0, "bytes": None}

        @register_estimator("auxiliaries.masscan.run_masscan",
                            basis="credit_line", name="masscan_open")
        def _masscan(target, arguments):
            return {d: None for d in DIMS}  # rate × walltime unknown upfront

        @register_estimator("auxiliaries.ffuf.run_ffuf",
                            basis="credit_line", name="ffuf_open")
        def _ffuf(target, arguments):
            return {d: None for d in DIMS}  # wordlist-size dependent

        @register_estimator("auxiliaries.hydra.run_hydra",
                            basis="credit_line", name="hydra_open")
        def _hydra(target, arguments):
            return {d: None for d in DIMS}  # auth-traffic; open-ended

        @register_estimator("payloads.sqlmap.run_sqlmap",
                            basis="credit_line", name="sqlmap_open")
        def _sqlmap(target, arguments):
            return {d: None for d in DIMS}  # fleet lane; open-ended timing

        _SEEDED.set()


# ─── Dims resolution (§4.2 node identity) ────────────────────────────────────

_TARGET_KEYS = ("target", "url", "host", "rhost", "target_url", "target_host")


def find_target(arguments: dict | None) -> str | None:
    args = arguments or {}
    for k in _TARGET_KEYS:
        v = args.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def dims_for_target(target: str | None, *, principal: str | None = None,
                    exit_id: str | None = None,
                    entry_partition: str | None = None) -> dict:
    """Node identity from a dispatch target (§4.2), reusing the fleet's span
    normalizer (never fork a second span normalizer, §3):

    - ``host_axis``: numeric → the fleet's canonical span label (a bare IP
      or a CIDR/range collapsed); URL-embedded numeric hosts keep only the
      host; hostname → lowercased (no DNS, ever).
    - ``range_axis``: the bare single IP's containing /24 (a sweep of that
      /24 and its member hosts contend on the same range node). None when
      the host axis IS a multi-address span (sweeps debit the host node;
      range=None avoids double-debiting one node) or the host is a name.
    - ``principal`` / ``exit_id`` / ``entry_partition``: carried through."""
    t = (target or "").strip()
    _numeric_axis, _numeric_span, _ = _lazy_fleet()
    host_axis = range_axis = None
    span = None
    if t:
        if "://" in t:
            try:
                h = (urlparse(t).hostname or "").lower()
            except ValueError:
                h = None
            if h:
                if _IPV4_RE.match(h):
                    host_axis = str(ipaddress.IPv4Address(h))
                    span = (int(ipaddress.IPv4Address(h)),) * 2
                else:
                    host_axis = h
        else:
            span = _numeric_span(t)
            if span is not None:
                host_axis = _numeric_axis(t)
            else:
                # hostname: lowercased, NO DNS, ever (no resolution)
                host_axis = t.lower()
    if span is not None and host_axis is not None:
        lo, hi = span
        if hi == lo:
            net = ipaddress.ip_network(
                f"{ipaddress.IPv4Address(lo)}/24", strict=False)
            label = f"{net.network_address}-{net.broadcast_address}"
            range_axis = None if label == host_axis else label
    return {"engagement": None, "entry_partition": entry_partition or "default",
            "exit_id": exit_id, "range_axis": range_axis,
            "host_axis": host_axis, "principal": principal}


# ─── The engine ──────────────────────────────────────────────────────────────

# ─── Controller (§8.1 posture machine, §8.2 authority rails) ─────────────────

CONTROLLER_STATES = ("normal", "soft_signal", "throttled", "backoff",
                     "cooldown")
CONTROLLER_PACING = {"normal": 1.0, "soft_signal": 0.7, "throttled": 0.4,
                     "backoff": 0.2, "cooldown": 0.1}


class Controller:
    """Per-host posture state machine (§8.1). Authority split (§8.2): the
    controller may slow traffic within its transition budget; ONLY the
    operator may speed it up or stop it. Hysteresis (k consecutive reactive
    emissions) means one 429 never throttles — sustained pressure does.
    Quiet decay: one level back per sustained reaction-free window, never
    a jump to green."""

    def __init__(self, store: RationStore, *, hysteresis_k: int | None = None,
                 quiet_window_s: float | None = None,
                 max_transitions_h: int | None = None,
                 now_fn: Callable[[], float] = time.time):
        self.store = store
        self.hysteresis_k = (hysteresis_k if hysteresis_k is not None
                             else _env_int("BUDGET_CTRL_HYSTERESIS_K", 2,
                                           minimum=1))
        self.quiet_window_s = (quiet_window_s if quiet_window_s is not None
                               else _env_float("BUDGET_CTRL_QUIET_WINDOW_S",
                                               120.0, minimum=1.0))
        self.max_transitions_h = (
            max_transitions_h if max_transitions_h is not None
            else _env_int("BUDGET_CTRL_MAX_TRANSITIONS_H", 12, minimum=1))
        self.now_fn = now_fn

    @staticmethod
    def _node_key(engagement: str | None, host_axis: str | None) -> str:
        return "\x1f".join((engagement or "global", host_axis or "global"))

    def _state_row(self, key: str) -> dict:
        rows = self.store.get_controller_states(node_key=key)
        return dict(rows.get(key, {}).get("requests")
                    or {"state": "normal", "streak": 0, "quiet_since": None,
                        "entered": self.now_fn(),
                        "transitions_hour": []})

    def _advance_window_ok(self, rec: dict, now: float) -> bool:
        ring = [t for t in rec.get("transitions_hour", [])
                if now - float(t) < 3600.0]
        if len(ring) >= self.max_transitions_h:
            logger.warning("[ration] controller authority limit reached "
                           "(%d transitions/h) — posture transition "
                           "refused (§8.2)", len(ring))
            return False
        ring.append(now)
        rec["transitions_hour"] = ring
        return True

    def observe(self, *, engagement: str | None, host_axis: str | None,
                response_class: str | None = None,
                signals: dict | None = None,
                now: float | None = None) -> dict:
        """Feed one emission outcome to the machine. Reaction classes move
        the streak; a k-streak advances ONE level (hysteresis §8.1); a
        sustained quiet window decays ONE level. Returns the record."""
        now = now if now is not None else self.now_fn()
        key = self._node_key(engagement, host_axis)
        rec = self._state_row(key)
        rc = (response_class or "").strip().lower()
        sig_names = {str(k).lower() for k in (signals or {})}
        hard = rc in HARD_CLASSES or bool(
            sig_names & {"reset", "rst", "429", "403_count", "tarpit"})
        soft = rc in SOFT_CLASSES or bool(
            sig_names & {"challenge", "cookie", "latency", "shaping"})
        reactive = hard or soft
        rec["state"] = rec["state"] if rec["state"] in CONTROLLER_STATES \
            else "normal"
        if reactive:
            rec["streak"] = int(rec.get("streak") or 0) + 1
            rec["quiet_since"] = None
            if rec["streak"] >= self.hysteresis_k and rec["state"] != "cooldown":
                idx = CONTROLLER_STATES.index(rec["state"])
                deeper = CONTROLLER_STATES[min(idx + 1, len(CONTROLLER_STATES) - 1)]
                if self._advance_window_ok(rec, now):
                    rec["state"] = deeper
                    rec["entered"] = now
                    rec["streak"] = 0
                    if soft and not hard and deeper == "backoff":
                        # ambiguous shaping never reaches backoff on soft
                        # evidence alone (§8.1: throttle is enough)
                        rec["state"] = "throttled"
            elif rec["state"] == "cooldown" and not hard:
                # ambiguous traffic cannot DEEPEN cooldown
                pass
        else:
            quiet_since = rec.get("quiet_since")
            if quiet_since is None:
                rec["quiet_since"] = now
            elif now - float(quiet_since) >= self.quiet_window_s \
                    and rec["state"] != "normal":
                idx = CONTROLLER_STATES.index(rec["state"])
                if self._advance_window_ok(rec, now):
                    rec["state"] = CONTROLLER_STATES[idx - 1]
                    rec["entered"] = now
                    rec["streak"] = 0
                    rec["quiet_since"] = now  # next decay needs a full window
        self.store.set_controller_state(
            key, "requests", state=rec["state"],
            streak=int(rec.get("streak") or 0), quiet_since=rec.get("quiet_since"),
            entered=float(rec.get("entered") or now),
            transitions_hour=list(rec.get("transitions_hour") or []))
        return rec

    def pacing(self, *, engagement: str | None = None,
               host_axis: str | None = None,
               now: float | None = None) -> float:
        """§7.3 release pacing for a host's lanes (0.1..1.0; NEVER 0 — full
        stop is operator-only per §8.2). Includes the tripwire-bound
        auto-throttle within authority: a spent lower bound reads as a
        tripwire already sprung — pace at throttled at most."""
        key = self._node_key(engagement, host_axis)
        rec = self._state_row(key)
        factor = CONTROLLER_PACING.get(rec.get("state", "normal"), 1.0)
        now = now if now is not None else self.now_fn()
        try:
            iv = [i for i in self.store.tripwire_intervals(
                engagement=engagement, host_axis=host_axis)
                if i.get("lower") is not None]
            if iv:
                win = max(float(i["window_seconds"]) for i in iv)
                spent = self.store.window_spend(
                    host_axis, engagement=engagement, before_ts=now,
                    window_seconds=win)
                lower = max(float(i["lower"]) for i in iv)
                if spent >= lower and factor > CONTROLLER_PACING["throttled"]:
                    factor = CONTROLLER_PACING["throttled"]
        except Exception:
            logger.debug("swallowed exception in pacing(tripwire consult)",
                         exc_info=True)
        return factor


class RationEngine:
    """Policy layer tying constitution + estimator registry + store together.

    Envelope rule (§7.4): every deferred/unknown decision is an INSTRUCTION
    envelope (decision + reason + what to call next), never a transient
    failure to be retried blindly."""

    def __init__(self, store: RationStore | None = None):
        ensure_seed_estimators()
        self.store = store or get_ration_store()
        self.controller = Controller(self.store)

    # -- constitution / policy ------------------------------------------------

    def constitution(self) -> Constitution | None:
        try:
            return constitution()
        except Exception as exc:
            logger.error("[ration] constitution invalid — engine fail-closed "
                         "until the operator fixes it: %s", exc)
            return None

    def _policy(self, c: Constitution) -> dict:
        return c.policy()

    # -- preflight (read-only routing, §3 step 2) ------------------------------

    def preflight(self, tool_id: str, arguments: dict | None, *,
                  now: float | None = None,
                  satisfied_check: Callable[[str, dict], Any] | None = None,
                  agent_id: str | None = None,
                  engagement: str | None = None,
                  exit_id: str | None = None,
                  entry_partition: str | None = None) -> dict:
        """Budget preflight for a dispatch. Returns:

        - ``{"decision": "disabled"}`` when BUDGET_ENABLED=0,
        - ``{"decision": "unknown", "fail_closed": True}`` — constitution
          or store unreadable (traffic-sending dims fail-closed, never green),
        - ``{"decision": "reject"}`` — never-fit declaration,
        - ``{"decision": "satisfied", "job_id": ...}`` — a live duplicate is
          already running for this canonical work (no second debit),
        - ``{"decision": "enqueue", "queue_id": qid, ...}`` — short;
          the envelope carries the do-not-retry instruction,
        - ``{"decision": "admit", ...}`` — caller proceeds; the DEBIT is a
          separate atomic call (fleet-acquired ordering, §3)."""
        now = now if now is not None else time.time()
        if not _env_bool("BUDGET_ENABLED", DEFAULT_ENABLED):
            return {"decision": "disabled"}
        try:
            const = self.constitution()
            if const is None:
                return {"decision": "unknown", "fail_closed": True,
                        "reason": "constitution invalid — fix "
                                  "BUDGET_CONSTITUTION(_FILE); traffic dims "
                                  "refused until then"}
        except Exception as exc:
            return {"decision": "unknown", "fail_closed": True,
                    "reason": f"constitution build failed: {exc!r}"}
        decl, est_name, basis = resolve_declaration(
            tool_id, find_target(arguments), arguments)
        target = find_target(arguments)
        dims = dims_for_target(target, principal=None, exit_id=exit_id,
                               entry_partition=entry_partition)
        try:
            decided = self.store.admit_vector(
                decl, dims, policy=self._policy(const),
                epoch_s=const.epoch_s, max_single=const.max_single(),
                now=now, engagement=engagement)
        except Exception as exc:
            logger.debug("swallowed exception in preflight(admit)", exc_info=True)
            return {"decision": "unknown", "fail_closed": True,
                    "reason": f"store unreadable: {exc!r}"}
        decided["tool_id"] = tool_id
        decided["declared"] = decl
        decided["declared_basis"] = basis
        decided["estimator"] = est_name
        decided["dims"] = dims
        decision = decided.get("decision")
        if satisfied_check is not None:
            job = satisfied_check(tool_id, arguments or {})
            if job is not None:
                # duplicate=satisfied (fleet contract): live job wins, no
                # enqueue, no second debit
                return {"decision": "satisfied", "job_id": str(job),
                        "tool_id": tool_id, "declared": decl,
                        "declared_basis": basis, "estimator": est_name,
                        "dims": dims}
        if decision == "enqueue":
            qid = self.store.enqueue_item(
                tool=tool_id, arguments=arguments or {}, decl=decl, dims=dims,
                reason="budget_short", agent_id=agent_id or "0",
                engagement=engagement,
                ttl_hours=_env_float("BUDGET_QUEUE_TTL_HOURS",
                                     _QUEUE_TTL_H_DEFAULT, minimum=0.1),
                now=now)
            self.store.sweep_expired(now=now)
            decided.update({
                "queue_id": qid,
                "instruction": ("budget short — do NOT retry this call; the "
                                "item is queued and the operator tick will "
                                "drain it (poll budget_status / queue_status)"),
            })
        return decided

    # -- atomic debit (§3 step 4) ----------------------------------------------

    def dispatch_debit(self, tool_id: str, arguments: dict | None, *,
                       now: float | None = None, agent_id: str | None = None,
                       engagement: str | None = None,
                       principal: str | None = None, exit_id: str | None = None,
                       entry_partition: str | None = None,
                       queue_ref: str | None = None, job_ref: str | None = None,
                       posture: dict | None = None,
                       signals: dict | None = None) -> dict:
        """The atomic cascade debit — call AFTER the fleet unit is acquired,
        immediately before execution (§3). Returns the debit receipt
        (``committed`` True/False; commit includes the emission row)."""
        now = now if now is not None else time.time()
        target = find_target(arguments)
        dims = dims_for_target(target, principal=principal, exit_id=exit_id,
                               entry_partition=entry_partition)
        dims["tool"] = tool_id
        try:
            const = self.constitution()
            if const is None:
                return {"committed": False, "decision": "unknown",
                        "fail_closed": True, "known": False,
                        "reason": "constitution invalid — dispatch refused"}
            decl, est_name, basis = resolve_declaration(
                tool_id, target, arguments)
            receipt = self.store.debit_vector(
                decl, dims, tool=tool_id, policy=self._policy(const),
                epoch_s=const.epoch_s, max_single=const.max_single(),
                now=now, engagement=engagement, agent_id=agent_id,
                estimator=est_name, declared_basis=basis,
                emit_meta={"signals": signals, "posture": posture,
                           "job_ref": job_ref, "queue_ref": queue_ref,
                           "budget_phase": "phase_a"})
            receipt["declared_basis"] = basis
            if receipt.get("committed") and principal:
                self.store.touch_principal(
                    host_axis=dims["host_axis"] or "", principal=principal,
                    engagement=engagement, now=now)
            if receipt.get("committed"):
                # the operator tick may already be waiting — opportunistically
                # surface when the queue drains (Phase C re-anchors epochs)
                self.store.sweep_expired(now=now)
            return receipt
        except Exception as exc:
            logger.debug("swallowed exception in dispatch_debit", exc_info=True)
            return {"committed": False, "decision": "unknown",
                    "fail_closed": True, "known": False,
                    "reason": f"budget preflight failed: {exc!r}"}

    # -- operator tick (§7 skeleton; jitter lands Phase C) ----------------------

    async def operator_tick(self, *, dispatch: Callable[[dict], dict] | None = None,
                      satisfied_check: Callable[[str, dict], Any] | None = None,
                      now: float | None = None, batch: int | None = None,
                      engagement: str | None = None,
                      sleep_fn: Callable[[float], None] | None = None) -> dict:
        """One operator drain pass over due queue items (operator lane ONLY —
        the REPL/daemon operator, not the model).

        ``dispatch(item)`` must return ``{"job_id": ...}`` (the item binds),
        ``{"brain_timeout": True}`` (the item is flagged for HUMAN action and
        NOT re-enqueued — §7.3 discipline), or raise (queued item survives
        for the next tick). May also be a coroutine/awaitable — the REPL
        drains through the async run_tool lane — which is awaited here.
        ``satisfied_check(item) -> job_id`` implements duplicate=satisfied at
        drain: no second debit, the live job wins."""
        now = now if now is not None else time.time()
        batch = batch or _env_int("BUDGET_DRAIN_BATCH", _DRAIN_BATCH_DEFAULT,
                                  minimum=1)
        results: list[dict] = []
        self.store.sweep_expired(now=now)
        # §6.2: automatic HOLD ⇄ NORMAL per node from the live backlog — the
        # refill economy of one host never freezes another host's. A held
        # node re-normalizing with empty backlog stamps a JITTERED epoch
        # anchor so refill resumes only after the drain window.
        try:
            const = self.constitution()
            epoch_s = const.epoch_s if const is not None else _EPOCH_S_DEFAULT
        except Exception:
            logger.debug("swallowed constitution read in operator_tick",
                         exc_info=True)
            epoch_s = _EPOCH_S_DEFAULT
        spread = _env_float("BUDGET_JITTER_SPREAD", 0.15, minimum=0.0)
        self.store.apply_backlog_modes(
            now, epoch_s, jitter_lo=epoch_s * (1.0 - spread),
            jitter_hi=epoch_s * (1.0 + spread))
        items = self.store.due_items(now=now)
        # §7.3 pacing: the tick scales itself to the controller posture —
        # throttle = smaller batch + jittered inter-release gaps; the floor
        # (cooldown≈0.1) still admits a trickle. Operator pins win via the
        # store's manual_phase (§8.2: only the operator stops traffic).
        def _sleep(_s: float) -> None:
            time.sleep(_s)
        sleep_fn = sleep_fn or _sleep
        release_base = _env_float("BUDGET_RELEASE_JITTER_S",
                                  _DRAIN_MIN_INTERVAL_S_DEFAULT, minimum=0.0)
        release_cap = _env_float("BUDGET_RELEASE_JITTER_CAP_S", 2.0,
                                 minimum=0.01)
        dispatched = 0
        first_pacing: float | None = None
        _eff_batch = batch
        for item in items:
            if dispatched >= batch:
                break
            if first_pacing is not None and dispatched >= _eff_batch:
                break
            if first_pacing is not None and dispatched >= max(
                    1, int(batch * first_pacing)):
                break
            qid = item["qid"]
            item_dims = json.loads(item["dims_json"] or "{}")
            try:
                pacing = self.controller.pacing(
                    engagement=item["engagement"]
                    if item["engagement"] else None,
                    host_axis=item_dims.get("host_axis"), now=now)
            except Exception:
                logger.debug("swallowed pacing read in drain", exc_info=True)
                pacing = 1.0
            if pacing <= (CONTROLLER_PACING["cooldown"] + 1e-9):
                results.append({"qid": qid, "decision": "held_cooldown",
                                "pacing": pacing})
                continue
            if first_pacing is None:
                first_pacing = pacing
                _eff_batch = max(1, int(batch * first_pacing))
            if item.get("no_reenqueue"):
                # Brain-timed-out drain dispatches stay OUT (§7.3): never
                # auto-re-enqueued; flagged for human inspection.
                self.store.cancel_item(qid, note="no_reenqueue flag — "
                                                 "human inspection required")
                results.append({"qid": qid, "decision": "flagged_for_human"})
                dispatched += 1
                continue
            if satisfied_check is not None:
                job = satisfied_check(item["tool"],
                                      json.loads(item["arguments_json"]))
                if job is not None:
                    self.store.bind_item(qid, str(job))
                    results.append({"qid": qid, "decision": "satisfied",
                                    "job_id": str(job)})
                    dispatched += 1
                    continue
            if dispatch is None:
                return {"decision": "noop", "reason": "no dispatcher wired",
                        "backlog": len(items), "results": results}
            try:
                out = dispatch(item)
                if hasattr(out, "__await__"):
                    out = await out
                out = out or {}
            except BudgetStillShort as exc:
                # The chokepoint re-deferred this dispatch (still short): the
                # gate minted a FRESH queue item; keep the ORIGINAL queued
                # and cancel the minted dup so one intent stays one row
                # (TTL-sweep otherwise doubles the work item).
                if exc.queue_id and exc.queue_id != qid:
                    try:
                        self.store.cancel_item(
                            exc.queue_id,
                            note=f"deferred again at drain — original {qid} kept")
                    except Exception:
                        logger.debug("swallowed dup-cancel at drain",
                                     exc_info=True)
                results.append({"qid": qid, "decision": "still_short"})
                dispatched += 1
                continue
            except BudgetRefused as exc:
                # never-fit / fail-closed: the item can never run — consume
                # as cancelled with an honest note (looping it to TTL would
                # only re-print the same refusal every tick).
                self.store.cancel_item(qid, note=f"budget refused — {exc.reason}")
                results.append({"qid": qid, "decision": "refused_cancelled",
                                "reason": exc.reason})
                dispatched += 1
                continue
            except Exception as exc:
                logger.warning("[ration] drain dispatch raised (%s) — "
                               "item stays queued for the next tick", exc)
                results.append({"qid": qid, "decision": "dispatch_failed",
                                "error": str(exc)})
                dispatched += 1
                continue
            if out.get("brain_timeout"):
                # item consumed as flagged — NOT re-enqueued
                self.store.cancel_item(qid, note="brain_timeout — no auto "
                                                 "re-enqueue (may still run)")
                results.append({"qid": qid, "decision": "brain_timeout_flagged"})
                dispatched += 1
                continue
            if out.get("finished"):
                # in-line dispatch (operator REPL drain): the tool ran and
                # returned its result synchronously — nothing to bind, the
                # item is consumed as done
                self.store.finish_item(qid)
                results.append({"qid": qid, "decision": "dispatched_inline"})
                dispatched += 1
                continue
            if out.get("job_id"):
                self.store.bind_item(qid, str(out["job_id"]))
                results.append({"qid": qid, "decision": "dispatched",
                                "job_id": str(out["job_id"])})
            else:
                results.append({"qid": qid, "decision": "dispatch",
                                "note": "dispatcher returned no job_id"})
            # §6.1 release-side jitter: entropy BETWEEN launches, scaled by
            # the host's pacing (slower under throttle), capped. The drained
            # items are traffic too — the chokepoint is never bypassed.
            # Sync sleep callables return None; asyncio.sleep is awaitable —
            # both work, the loop never freezes.
            dispatched += 1
            if release_base > 0.0 and dispatched < _eff_batch:
                delay = min(random.uniform(0.0, release_base) * (1.0 / pacing),
                            release_cap)
                if delay > 0.0:
                    out_s = sleep_fn(delay)
                    if hasattr(out_s, "__await__"):
                        await out_s
        return {"decision": "drained", "results": results,
                "backlog_remaining": max(0, len(items) - len(results))}

    # -- L1 reconcile (§10) -----------------------------------------------------

    def reconcile(self, receipt: dict, actual: dict, *,
                  response_class: str | None = None,
                  signals: dict | None = None) -> dict | None:
        """L1 true-up on a debit receipt. Tripwire seeds update on any
        actuals; drift stamps APPEND (never rewrite the declared vector)."""
        emission_id = receipt.get("emission_id")
        if not isinstance(emission_id, int):
            return None
        out = self.store.reconcile_emission(
            emission_id, actual, response_class=response_class,
            signals=signals)
        if out is None:
            return None
        if out.get("tripped"):
            logger.warning("[ration] drift tripped (emission %s) — declared "
                           "%s, actual %s", emission_id, out["declared"], actual)
        # tripwire seeds update on ANY actuals (moving average, §15 hook) —
        # drift is the alarm, the seed is the meter.
        self.store.upsert_tripwire(
            receipt.get("tool") or receipt.get("tool_id") or "unknown", actual)
        # §8 lane: emissions feed BOTH the per-host tripwire interval
        # hypotheses (onset caps upper; sustained clean runs raise lower)
        # and the controller posture machine (reactions advance under
        # hysteresis; quiet decays). Cheap string classification, no model.
        host_axis = out.get("host_axis")
        if host_axis is not None:
            engagement = out.get("engagement")
            rc = (response_class or "").strip().lower()
            ts = out.get("ts")
            if rc and rc not in QUIET_CLASSES:
                spend = self.store.window_spend(
                    host_axis, engagement=engagement, before_ts=ts,
                    window_seconds=_env_float("BUDGET_TRIPWIRE_WINDOW_S",
                                              300.0, minimum=1.0))
                self.store.tripwire_interval(
                    engagement, host_axis, "requests", upper=float(spend),
                    window_seconds=_env_float("BUDGET_TRIPWIRE_WINDOW_S",
                                              300.0, minimum=1.0),
                    provenance="onset", now=ts)
            elif rc in QUIET_CLASSES:
                run = self.store.clean_run(host_axis, engagement=engagement)
                if run >= 3:
                    self.store.tripwire_interval(
                        engagement, host_axis, "requests", lower=float(run),
                        window_seconds=_env_float("BUDGET_TRIPWIRE_WINDOW_S",
                                                  300.0, minimum=1.0),
                        provenance="clean_run", now=ts)
            self.controller.observe(
                engagement=engagement, host_axis=host_axis,
                response_class=response_class, signals=signals, now=ts)
        return out

    def compensate(self, receipt: dict, declared: dict, why: str,
                   *, now: float | None = None) -> dict | None:
        """Reverse a committed cascade debit (duplicate/refused fleet
        verdicts, §11.2 note): the declared vector is paid back to every
        debited level EXACTLY, and the emission row is stamped
        ``drift=2 / drift_note='compensated:<why>'`` so the ledger reads
        honestly. Only used for dispatches that provably did NOT run the
        declared traffic — a Brain timeout stays charged (it may still be
        running)."""
        emission_id = receipt.get("emission_id")
        if not isinstance(emission_id, int):
            return None
        refund = {d: (declared or {}).get(d) for d in DIMS}
        if all(v is None for v in refund.values()):
            return None
        refunded = []
        for trace in receipt.get("traces") or []:
            key = trace.get("node_key")
            if not key:
                continue
            try:
                self.store.refund_node(key, refund)
                refunded.append(key)
            except Exception as exc:
                logger.debug("swallowed refund error on %s", key, exc_info=True)
        try:
            self.store.stamp_compensation(emission_id, why)
        except Exception as exc:
            logger.debug("swallowing compensation stamp failed", exc_info=True)
        return {"emission_id": emission_id, "refunded": refunded, "why": why}

    # -- status ----------------------------------------------------------------

    def status(self, *, now: float | None = None) -> dict:
        now = now if now is not None else time.time()
        snap = self.store.status_snapshot(now=now)
        try:
            const = self.constitution()
            epoch_s = const.epoch_s if const is not None else _EPOCH_S_DEFAULT
        except Exception:
            logger.debug("swallowed constitution read in status", exc_info=True)
            epoch_s = _EPOCH_S_DEFAULT
        return {**snap,
                "backlog": len(self.store.due_items(now=now, limit=10**6)),
                "stalls": self.store.stall_report(now, epoch_s),
                "controller": {key: dims for key, dims
                               in self.store.get_controller_states().items()}}


# ─── Singletons ───────────────────────────────────────────────────────────────

def get_ration_store() -> RationStore:
    """Process-wide ration store; ``BUDGET_STORE_DIR`` re-points it (tests).
    Singleton cached PER OVERRIDE VALUE (job_store pattern)."""
    global _store_inst, _store_key
    override = os.getenv("BUDGET_STORE_DIR", "").strip()
    if override:
        if _store_inst is not None and _store_key == override:
            return _store_inst
        _store_inst = RationStore(store_dir=override)
        _store_key = override
        return _store_inst
    if _store_inst is None:
        _store_inst = RationStore()
        _store_key = ""
    return _store_inst


def reset_ration_store() -> None:
    """Test hook: forget the store singleton (next get re-reads env)."""
    global _store_inst, _store_key
    if _store_inst is not None:
        try:
            _store_inst.close()
        except Exception:
            logging.getLogger(__name__).debug(
                "swallowed close error in reset_ration_store", exc_info=True)
    _store_inst = None
    _store_key = ""


_ENGINE: RationEngine | None = None


def get_engine() -> RationEngine:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = RationEngine()
    return _ENGINE


def reset_engine() -> None:
    """Test hook."""
    global _ENGINE
    _ENGINE = None
    reset_ration_store()


_store_inst: RationStore | None = None
_store_key: str = ""


# ─── LLM-facing status twins (terminal lane, §15 Phase B) ────────────────────
#
# Phase A left these as a store-level snapshot only. These twins are the
# model-visible surface: the terminal lane (never budgeted — see
# utils/tool_budget.py DEFAULT_TERMINAL_ALLOWLIST) so a throttled model can
# still read its own throttle and write itself up. They are READ-ONLY: the
# operator levers (set_phase, purge, drain) stay REPL-only, mirroring the
# scope gate's model-refusal doctrine — the model observes, the operator
# steers.

@framework_tool(
    "Read the traffic-budget state: the ration ledger's nodes (per-dim "
    "remaining vs ceiling at every cascade level), the deferral-queue "
    "depth, and whether the budget system is armed. Call this before "
    "planning traffic-heavy chains (nmap sweeps, masscan scans, ffuf "
    "fuzzes): a budget_exhausted/enqueue decision elsewhere in this turn "
    "is explained here, and a node near empty tells you WHY you may get "
    "deferred instead of sent. Read-only — no traffic is sent.",
    tags=["infra"])
def budget_status() -> str:
    """Budget ledger snapshot for the model lane (budget_status twin).

    Returns:
        Human-readable status block: enabled flag, constitution epoch,
        nodes with per-dim remaining/ceiling (top spend by dim), queue
        counts by state, and backlog depth.
    """
    try:
        engine = get_engine()
    except Exception as exc:
        logging.getLogger(__name__).debug(
            "swallowed exception in budget_status", exc_info=True)
        return f"budget: UNREADABLE (fail-closed) — {exc!r}"
    snap = engine.store.status_snapshot()
    enabled = _env_bool("BUDGET_ENABLED", DEFAULT_ENABLED)
    lines = [f"budget: {'ARMED' if enabled else 'DISABLED (kill switch)'} — "
             f"epoch={_env_float('BUDGET_EPOCH_SECONDS', _EPOCH_S_DEFAULT):.0f}s"]
    nodes = snap["nodes"]
    rem_col = {"requests": "remaining_requests",
               "packets": "remaining_packets",
               "auth_events": "remaining_auth",
               "bytes": "remaining_bytes"}
    near = []
    for n in nodes:
        ceilings = json.loads(n["ceiling_json"] or "{}")
        if n.get("mode") == "hold":
            near.append(f"  HOLD {n['node_key'][:60]!r}")
            continue
        for d in DIMS:
            rem = n.get(rem_col[d])
            ceil = ceilings.get(d)
            if ceil and rem is not None:
                frac = float(rem) / float(ceil)
                if frac < 0.25:
                    near.append(f"  LOW  {d}: {int(rem)}/{int(ceil)} "
                                f"on {n['node_key'][:60]!r} ({frac:.0%} left)")
    lines.append(f"nodes: {len(nodes)}")
    lines += near[:8] or ["  all cascades healthy (>=25% remaining)"]
    q = ", ".join(f"{r['status']}={r['n']}" for r in snap["queue"]) or "empty"
    lines.append(f"queue: {q}")
    lines.append(f"backlog (drain-eligible): {engine.status()['backlog']}")
    # §12 observability: controller posture + the HOLD-stall alarm
    # (operator-visible, NON-auto-escalating — escalate yourself).
    try:
        st = engine.store.stall_report(time.time(), _env_float(
            "BUDGET_EPOCH_SECONDS", _EPOCH_S_DEFAULT))
        for s in st[:8]:
            lines.append(f"  STALL {s['host_axis'] or 'global'}: held "
                         f"{s['held_s'] if s['held_s'] is not None else '?'}s, "
                         f"oldest queued {s['oldest_queued_s']}s with no "
                         "drain progress — investigate")
    except Exception as exc:
        logging.getLogger(__name__).debug(
            "swallowed exception in budget_status(stall)", exc_info=True)
    try:
        ctrl = engine.store.get_controller_states()
        if ctrl:
            summary = {}
            for host, dims in ctrl.items():
                for dim, rec in dims.items():
                    summary.setdefault(rec["state"], 0)
                    summary[rec["state"]] += 1
            parts = [f"{k}×{v}" for k, v in sorted(summary.items())]
            pacing = [f"{host.split(chr(31))[-1]}→"
                      f"{CONTROLLER_PACING.get(rec['state'], 1.0):.2f}"
                      for host, dims in ctrl.items()
                      for rec in dims.values()
                      if rec["state"] != "normal"]
            lines.append(f"ctrl: {' '.join(parts)} (pacing floor "
                         f"{CONTROLLER_PACING['cooldown']:.2f}"
                         + (f"; paced: {' '.join(pacing[:4])}" if pacing
                            else "") + ")")
    except Exception as exc:
        logging.getLogger(__name__).debug(
            "swallowed exception in budget_status(ctrl)", exc_info=True)
    try:
        reserves = snap.get("reserves") or []
        if reserves:
            released = [r for r in reserves if r.get("released") is not None]
            frozen = [r for r in reserves if r.get("released") is None]
            tot = {}
            for r in released:
                for d, v in (r.get("remaining") or {}).items():
                    try:
                        tot[d] = tot.get(d, 0.0) + float(v)
                    except (TypeError, ValueError):
                        continue
            tv = ", ".join(f"{d}={int(v)}" for d, v in sorted(tot.items())) \
                or "drained"
            lines.append(f"reserves: {len(reserves)} token(s) — "
                         f"{len(released)} released [{tv}] free-form usable, "
                         f"{len(frozen)} frozen (operator tag releases)")
    except Exception as exc:
        logging.getLogger(__name__).debug(
            "swallowed exception in budget_status(reserves)", exc_info=True)
    try:
        draws = snap.get("open_draws") or []
        if draws:
            lines.append(f"open credit-line draws: {len(draws)} "
                         "(drawn now, true-up at job release; never invented)")
    except Exception as exc:
        logging.getLogger(__name__).debug(
            "swallowed exception in budget_status(draws)", exc_info=True)
    lines.append("note: budget short → work is DEFERRED to this queue; do "
                 "NOT retry the rejected call, check here or wait for the "
                 "operator drain.")
    return "\n".join(lines)


@framework_tool(
    "Inspect the ration deferral queue: tools that were budget-deferred "
    "(decision=enqueue) instead of running, FIFO with priority. Every item "
    "carries its qid, tool, original arguments, shortfall reason, and "
    "launch/finish state — use it to track a deferred call end-to-end "
    "instead of retrying the rejected tool call. Read-only; draining is an "
    "operator action.",
    tags=["infra"])
def budget_queue_status(tool: str = "",
                        state: str = "queued",
                        limit: int = 20) -> str:
    """Ration deferral-queue listing for the model lane.

    Args:
        tool: Case-insensitive substring filter on the tool id; empty = all.
        state: queued|launched|finished|cancelled|all (default queued).
        limit: Max rows returned (default 20).

    Returns:
        Formatted backlog rows and a state-count summary.
    """
    store = get_ration_store()
    limit = max(1, int(limit))
    if state and state != "all":
        rows = store.conn.execute(
            "SELECT * FROM queue_items WHERE status=? AND "
            "(tool LIKE ? OR arguments_json LIKE ?) "
            "ORDER BY priority DESC, requested ASC LIMIT ?",
            (state, f"%{tool}%", f"%{tool}%", limit)).fetchall() \
            if tool else store.conn.execute(
            "SELECT * FROM queue_items WHERE status=? ORDER BY priority DESC,"
            " requested ASC LIMIT ?", (state, limit)).fetchall()
    else:
        rows = store.conn.execute(
            "SELECT * FROM queue_items WHERE tool LIKE ? ORDER BY priority "
            "DESC, requested ASC LIMIT ?", (f"%{tool}%", limit)).fetchall() \
            if tool else store.conn.execute(
            "SELECT * FROM queue_items ORDER BY priority DESC, requested "
            "ASC LIMIT ?", (limit,)).fetchall()
    now = time.time()
    out = []
    for r in rows:
        d = dict(r)
        age = max(0, now - float(d.get("requested") or now)) / 60.0
        out.append(
            f"  {d['qid']} [{d['status']}] {d['tool']} "
            f"prio={d['priority']} waited={age:.1f}m "
            f"job={d.get('job_ref') or '-'} reason={d['reason']}"
            + (f" notes={d['notes_json']}" if d.get("notes_json") else ""))
    counts = store.conn.execute(
        "SELECT status, COUNT(*) n FROM queue_items GROUP BY status"
    ).fetchall()
    summary = ", ".join(f"{c['status']}={c['n']}" for c in counts) or "empty"
    body = "\n".join(out[:int(limit)]) if out else "  (queue empty)"
    return f"queue [{summary}]:\n{body}"


# ─── Executor chokepoint integration (§3, §15 Phase D) ───────────────────────
#
# ``ration_gate`` sits in ``daharness/executor.py`` AFTER the scope-disable
# block and BEFORE dispatch; ``ration_discharge`` runs after. Because
# replkit.core.run_tool funnels EVERY lane (gateway REST, MCP, REPL, kernel,
# operator drain) through executor.execute_tool, one chokepoint covers all
# front doors. Gate rules (§13):
#
# - kill switch off → None (ration never engages);
# - tool not in the estimator registry (the traffic vocabulary) → None —
#   internal/budget tools carry zero traffic semantics and never mint;
# - registered + admit → the gate performs the atomic DEBIT itself right
#   before dispatch (declare-and-reconcile), returning a gate_state the
#   caller must pass to ``ration_discharge``;
# - registered + never-fit → budget_refused envelope (no dispatch);
# - registered + short → budget_deferred envelope (no dispatch; item queued);
# - store/constitution unreadable → budget_refused with ``fail_closed``
#   (§5: registered traffic dims never degrade to green).
#
# Dispatch failures do NOT compensate: an attempt WAS made and the debit
# stands (a Brain timeout may still be running — compensation would invite a
# duplicate). Only duplicate/refused fleet verdicts compensate.

_GATE_DEBIT_STAMP = {
    # result envelope stamp: the model sees that the call was budgeted
}


def _estimator_engaged(tool_id: str) -> bool:
    with _ESTIMATORS_LOCK:
        return tool_id in _ESTIMATORS


def _current_engagement() -> str | None:
    try:
        from utils.engagement import current_slug
        return current_slug()
    except Exception:
        logger.debug("[ration] engagement slug unavailable (non-fatal)",
                     exc_info=True)
        return None


def _budget_envelope(tool_id: str, *, status: str, reason: str | None = None,
                     queue_id: str | None = None, fail_closed: bool = False,
                     declared: dict | None = None,
                     arguments: dict | None = None) -> dict:
    env = {"status": status, "tool_id": tool_id,
           "arguments": arguments or {}, "declared": declared}
    if status == "budget_deferred":
        env.update({
            "decision": "enqueue",
            "queue_id": queue_id,
            "defer_reason": "budget_short",
            "instruction": ("budget short — do NOT retry this call; the item "
                            "is queued and the operator tick will drain it "
                            "(check budget_status / budget_queue_status)"),
        })
    else:
        env.update({
            "decision": "reject",
            "instruction": ("dispatch refused by the budget constitution — "
                            "this can never fit; raise it with the operator"),
        })
    if fail_closed:
        env["fail_closed"] = True
    if reason:
        env["reason"] = reason
    return env


def _gate_state(tool_id: str, receipt: dict, decl: dict, dims: dict, *,
                agent_id: str | None, engagement: str | None,
                basis: str, estimator: str) -> dict:
    """Proceed-state for a debited call: the executor passes this to
    :func:`ration_discharge` after dispatch (compensate on duplicate/refused,
    bind job refs, reconcile deterministic inline actuals)."""
    return {"gate": "debited", "tool_id": tool_id, "receipt": receipt,
            "declared": decl, "dims": dims, "agent_id": agent_id,
            "engagement": engagement, "declared_basis": basis,
            "estimator": estimator}


def _queue_defer(engine: RationEngine, tool_id: str, arguments: dict | None,
                 decl: dict, dims: dict, *, agent_id: str | None,
                 engagement: str | None, reason: str = "budget_short",
                 now: float | None = None) -> str:
    now = now if now is not None else time.time()
    qid = engine.store.enqueue_item(
        tool=tool_id, arguments=arguments or {}, decl=decl, dims=dims,
        reason=reason, agent_id=agent_id or "0", engagement=engagement,
        ttl_hours=_env_float("BUDGET_QUEUE_TTL_HOURS", _QUEUE_TTL_H_DEFAULT,
                             minimum=0.1),
        now=now)
    engine.store.sweep_expired(now=now)
    return qid


def ration_gate(tool_id: str, arguments: dict | None, *,
                agent_id: str | None = None, session_id: str | None = None,
                now: float | None = None) -> dict | None:
    """The dispatch chokepoint's budget step. Returns:

    - ``None`` — ration does not engage (disabled / unregistered tool);
    - ``{"gate": "debited", ...}`` — debit committed, dispatch may proceed
      (caller MUST pass this to :func:`ration_discharge` afterwards);
    - envelope dict ``{"status": "budget_deferred"|"budget_refused", ...}`` —
      no dispatch; the callee returns it verbatim.

    Never raises: a gate machinery failure for a REGISTERED tool is a
    fail-closed refusal envelope, never a silent pass (§13).
    """
    now = now if now is not None else time.time()
    if not _env_bool("BUDGET_ENABLED", DEFAULT_ENABLED):
        return None
    if not _estimator_engaged(tool_id):
        return None
    engagement = _current_engagement()
    try:
        engine = get_engine()
    except Exception as exc:
        logger.debug("swallowed exception in ration_gate(engine)", exc_info=True)
        return _budget_envelope(
            tool_id, status="budget_refused", fail_closed=True,
            reason=f"budget store unavailable — dispatch refused "
                   f"(fail-closed): {exc!r}", arguments=arguments)
    try:
        decision = engine.preflight(tool_id, arguments, now=now,
                                    agent_id=agent_id, engagement=engagement)
    except Exception as exc:
        logger.debug("swallowed exception in ration_gate(preflight)",
                     exc_info=True)
        return _budget_envelope(
            tool_id, status="budget_refused", fail_closed=True,
            reason=f"budget preflight failure — dispatch refused "
                   f"(fail-closed): {exc!r}", arguments=arguments)
    d = decision.get("decision")
    if d == "disabled":
        return None
    if d == "reject":
        return _budget_envelope(
            tool_id, status="budget_refused",
            reason=decision.get("reason")
            or "declared vector never fits under the constitution ceiling — "
               "raise it with the operator",
            declared=decision.get("declared"), arguments=arguments)
    if d == "unknown":
        return _budget_envelope(
            tool_id, status="budget_refused", fail_closed=True,
            reason=decision.get("reason")
            or "budget store unreadable — traffic dims fail-closed (§13)",
            declared=decision.get("declared"), arguments=arguments)
    if d == "enqueue":
        qid = decision.get("queue_id")
        return _budget_envelope(
            tool_id, status="budget_deferred", queue_id=qid,
            declared=decision.get("declared"), arguments=arguments)
    if d != "admit":
        return _budget_envelope(
            tool_id, status="budget_refused", fail_closed=True,
            reason=f"unknown ration decision {d!r}", arguments=arguments)
    # admit: the debit IS the spend reservation — atomic, before dispatch
    receipt = engine.dispatch_debit(
        tool_id, arguments, now=now, agent_id=agent_id,
        engagement=engagement)
    if not receipt.get("committed"):
        rd = receipt.get("decision")
        target = find_target(arguments)
        dims = dims_for_target(target)
        decl = resolve_declaration(tool_id, target, arguments)[0]
        if rd == "reject":
            return _budget_envelope(
                tool_id, status="budget_refused",
                reason=receipt.get("reason")
                or "declared vector never fits under the constitution ceiling",
                declared=decl, arguments=arguments)
        if rd == "unknown":
            return _budget_envelope(
                tool_id, status="budget_refused", fail_closed=True,
                reason=receipt.get("reason")
                or "budget store error during debit — dispatch refused",
                declared=decl, arguments=arguments)
        qid = _queue_def(engine, tool_id, arguments, decl, dims,
                         agent_id=agent_id, engagement=engagement, now=now)
        return _budget_envelope(
            tool_id, status="budget_deferred", queue_id=qid,
            declared=decl, arguments=arguments)
    return _gate_state(
        tool_id, receipt, decision.get("declared") or {},
        decision.get("dims") or {}, agent_id=agent_id, engagement=engagement,
        basis=decision.get("declared_basis") or "estimated",
        estimator=decision.get("estimator") or "unknown")


def _find_job_id(result: dict) -> str | None:
    """Shallow scan (envelope + inner result) for a launched background job
    id — binds the emission's ``job_ref`` so the §7.1 draw closes at release."""
    for probe in (result, result.get("result")):
        if isinstance(probe, dict):
            jid = probe.get("job_id") or probe.get("jobId")
            if isinstance(jid, (str, int)) and str(jid).strip():
                return str(jid)
    return None


_INLINE_HARVEST_TOOLS = (
    # deterministic inline (non-job) traffic tools and their harvests;
    # job-launching estimators reconcile through ``reconcile_poll_job``
    # instead — never guessed for the latter.
    "auxiliaries.web_session.session_get",
    "auxiliaries.web_session.session_post",
    "auxiliaries.web_session.session_request",
)


def _harvest_inline_actuals(tool_id: str, result: dict) -> dict | None:
    """Deterministic actuals for inline dispatches (§10 L1 true-up). Only
    counts real request numbers the result itself carries — never inventions."""
    if tool_id not in _INLINE_HARVEST_TOOLS:
        return None
    inner = result.get("result") if isinstance(result.get("result"), dict) \
        else result
    hops = inner.get("hops")
    if isinstance(hops, list):
        return {"requests": len(hops)}          # every redirect hop IS traffic
    code = inner.get("status_code")
    if code is not None:
        return {"requests": 1}                  # one request was actually sent
    return None


def ration_discharge(gate_state: dict | None, result: dict | None) -> dict | None:
    """Post-dispatch discharge for a debited call (§3 step 6):

    1. duplicate/refused fleet verdicts → :meth:`RationEngine.compensate`
       (the live unit carries its own debit; ours is reversed);
    2. otherwise a launched ``job_id`` binds ``job_ref`` on the emission
       (the credit-line draw closes at poll/release);
    3. inline deterministic tools reconcile actuals immediately.

    Discharge NEVER alters the dispatch result's fate — every step is
    guarded; wrapper bugs degrade to a debug note, store failures already
    decided the gate side."""
    if not gate_state:
        return None
    receipt = gate_state.get("receipt") or {}
    tool_id = gate_state.get("tool_id") or ""
    try:
        engine = get_engine()
    except Exception as exc:
        logger.debug("swallowed exception in ration_discharge(engine)",
                     exc_info=True)
        return {"discharge": "skipped", "reason": f"engine unavailable: {exc!r}"}
    result = result if isinstance(result, dict) else {}
    status = str(result.get("status") or "").strip().lower()
    if status == "duplicate":
        return engine.compensate(receipt, gate_state.get("declared") or {},
                                 "duplicate — live unit holds this work; "
                                 "our debit reversed")
    if status == "refused":
        why = result.get("reason") or result.get("error") or "no reason"
        return engine.compensate(receipt, gate_state.get("declared") or {},
                                 f"refused ({why}); debit reversed")
    emission_id = receipt.get("emission_id")
    if not isinstance(emission_id, int):
        return {"discharge": "no emission"}
    job_id = _find_job_id(result)
    if job_id:
        try:
            engine.store.bind_emission_job(emission_id, job_id)
        except Exception as exc:
            logger.debug("swallowed job_ref bind (emission %s)", emission_id,
                         exc_info=True)
        return {"discharge": "job-bound", "job_ref": job_id,
                "emission_id": emission_id}
    actual = _harvest_inline_actuals(tool_id, result)
    if actual is not None:
        try:
            out = engine.reconcile(receipt, actual)
            return {"discharge": "reconciled", "actual": actual,
                    "drift": (out or {}).get("drift"),
                    "emission_id": emission_id}
        except Exception as exc:
            logger.debug("swallowed reconcile (emission %s)", emission_id,
                         exc_info=True)
            return {"discharge": "reconciled_failed", "reason": str(exc)}
    return {"discharge": "open", "emission_id": emission_id}


_ACTUAL_KEYS = ("requests", "requests_made", "attempts", "sent",
                "total_attempts")


def _harvest_poll_actuals(result: dict | None) -> dict | None:
    """Deterministic numeric actuals from a job's verdict dictionaries —
    bounded shallow scan, first numeric hit wins (§10: never invent)."""
    if not isinstance(result, dict):
        return None
    stack, seen = [result], 0
    while stack and seen < 8:
        cur = stack.pop()
        seen += 1
        for k, v in cur.items():
            if isinstance(v, dict):
                stack.append(v)
                continue
            if isinstance(v, (int, float)) and v > 0 and k in _ACTUAL_KEYS:
                return {"requests": float(v)}
    return None


def reconcile_poll_job(job_id: str, poll_result: dict | None = None, *,
                       now: float | None = None) -> dict | None:
    """§7.1 draw-lifetime hook: called by ``poll_job`` on its first ``done``
    observation. Every open credit-line draw bound to this job either
    reconciles with deterministic verdict actuals or honest-closes (declared
    stands). Best-effort: a bug here must never break polling."""
    try:
        engine = get_engine()
    except Exception:
        logger.debug("swallowed engine unavailable in reconcile_poll_job",
                     exc_info=True)
        return None
    try:
        draws = engine.store.draws_for_job(str(job_id))
        if not draws:
            return {"draws": []}
        actual = _harvest_poll_actuals(poll_result)
        closed = []
        for draw in draws:
            if actual is not None:
                try:
                    out = engine.reconcile(
                        {"emission_id": draw["emission_id"],
                         "tool": draw["tool"]}, actual)
                    closed.append({"emission_id": draw["emission_id"],
                                   "reconciled": True,
                                   "actual": actual,
                                   "drift": (out or {}).get("drift")})
                    continue
                except Exception:
                    logger.debug(
                        "swallowed reconcile in draw close", exc_info=True)
            if engine.store.close_draw(
                    draw["emission_id"],
                    "closed at job release; no deterministic actuals — "
                    "declared stands"):
                closed.append({"emission_id": draw["emission_id"],
                               "closed": True})
        return {"job_ref": str(job_id), "draws": closed,
                "actual": actual}
    except Exception as exc:
        logger.debug("swallowed exception in reconcile_poll_job", exc_info=True)
        return {"error": f"draw reconcile skipped: {exc!r}"}


def sweep_draws(*, jobs_getter=None, now: float | None = None) -> int:
    """Backstop for open credit-line draws (§7.1): a draw whose bound job row
    is gone honest-closes ('job row gone'), an UNBOUND draw past the TTL
    honest-closes ('staled'). No numbers are ever invented; budget_status
    surfaces the count. Returns rows closed."""
    now = now if now is not None else time.time()
    ttl_s = _env_float("BUDGET_DRAW_TTL_HOURS", _DRAW_TTL_H_DEFAULT,
                       minimum=0.1) * 3600.0
    try:
        store = get_ration_store()
        draws = store.open_draws(limit=200)
    except Exception:
        logger.debug("swallowed store unavailable in sweep_draws",
                     exc_info=True)
        return 0
    if jobs_getter is None:
        def jobs_getter(jid: str):
            try:
                from utils.background_job import get_job
                return get_job(jid)
            except Exception:
                logger.debug("swallowed jobs lookup in sweep_draws",
                             exc_info=True)
                return None            # indeterminate — leave the draw open
    closed = 0
    for draw in draws:
        jref = draw.get("job_ref")
        if jref:
            try:
                if jobs_getter(str(jref)) is not None:
                    continue           # job alive/known — reconciles at poll
            except Exception:
                logger.debug("swallowed jobs getter error in sweep_draws",
                             exc_info=True)
                continue
            note = "closed: job row gone — declared stands, never invented"
        else:
            if (now - float(draw.get("ts") or now)) <= ttl_s:
                continue
            note = "closed: staled unbound draw past TTL — declared stands"
        try:
            closed += 1 if store.close_draw(draw["emission_id"], note) else 0
        except Exception:
            logger.debug("swallowed close in sweep_draws", exc_info=True)
    return closed


def ration_dwell(host: str | None, *, now: float | None = None) -> float:
    """§11 posture seam: extra dwell when the controller's pacing degrades a
    host — jittered ``uniform(0, cap) * (1/pacing - 1)`` capped at
    ``BUDGET_DWELL_CAP_S`` (≤ HostFloor's own clamp so a paced lane never
    exceeds its floor contract twice). Zero always when disarmed/disabled/
    pacing healthy. Returns seconds actually slept.

    Sync sleep is SAFE here: web tools are sync and run in worker threads
    (never an async-await freezing the event loop)."""
    try:
        if not _env_bool("BUDGET_ENABLED", DEFAULT_ENABLED):
            return 0.0
        if not host:
            return 0.0
        try:
            engagement = _current_engagement()
        except Exception:
            logger.debug("swallowed engagement read in ration_dwell",
                         exc_info=True)
            engagement = None
        engine = get_engine()
        ha = dims_for_target(host).get("host_axis") or host
        try:
            pacing = engine.controller.pacing(
                engagement=engagement, host_axis=ha, now=now)
        except Exception:
            logger.debug("swallowed pacing read in ration_dwell", exc_info=True)
            return 0.0
        if pacing >= 0.999:
            return 0.0
        cap = min(_env_float("BUDGET_DWELL_CAP_S", 15.0, minimum=0.1), 15.0)
        dwell = min(random.uniform(0.0, cap) * (1.0 / max(pacing, 0.1) - 1.0),
                    cap)
        if dwell > 0.0:
            time.sleep(dwell)
        return dwell
    except Exception:
        logger.debug("swallowed exception in ration_dwell (no dwell)",
                     exc_info=True)
        return 0.0
