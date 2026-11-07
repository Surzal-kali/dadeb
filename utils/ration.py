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

Coverage boundary (§3 v0.3): this economy covers ONLY chokepoint-routed
agent-driven traffic — the gate→dispatch→discharge seam in
``daharness/executor.py`` and its poll/discharge hooks. Human kernel-lane
IO and hand-run terminal work inherit HUMAN authority
(gate-follows-actor) and are OUTSIDE the economy — the model can never be
delegated a rule that binds its operator.

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

_EPOCH_S_DEFAULT = 300.0
_QUEUE_TTL_H_DEFAULT = 24.0
_DRAIN_BATCH_DEFAULT = 2
# Bounded-failure exit (2026-11-06 seam close): how many consecutive
# dispatch_failed ticks an item may survive before it is consumed as
# 'failed' with the last error surfaced. 0 = fail on the first raise.
_RETRY_MAX_DEFAULT = 3
# Cadence between operator ticks lands Phase C (jittered controller loop);
# kept as the named knob the docstring promised so the constant stays the
# single place to set the floor.
_DRAIN_MIN_INTERVAL_S_DEFAULT = 2.0
_PRINCIPAL_WINDOW_H_DEFAULT = 168.0


def _env_float(name: str, default: float, *, minimum: float | None = None) -> float:
    # Inline "# comment" suffixes are stripped before parse: the deb service
    # lane reads its env via systemd EnvironmentFile, which (unlike
    # python-dotenv) keeps trailing comments inside the value — the packaged
    # /etc/daharness/daharness.env examples carry them on active rows.
    raw = os.getenv(name, "").split("#", 1)[0].strip()
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
    raw = os.getenv(name, "").split("#", 1)[0].strip().lower()
    if not raw:
        return default
    return raw not in ("0", "false", "no", "off")


_MONO_ANCHOR: tuple[float, float] = (time.monotonic(), time.time())
"""Captured eagerly at IMPORT (never lazily): a faked/poisoned ``time.time``
inside a test window must never become the anchor — every later ``budget_now``
call would inherit the fantasy epoch for the life of the process."""


def budget_now() -> float:
    """§6.3 M4 clock discipline: wall-clock value derived from a MONOTONIC
    delta — a wall-clock suspend or NTP step can never GRANT credit (faked
    forward jump) nor withhold it (backward jump); with
    ``BUDGET_MONO_CLOCK=0`` every call collapses to plain ``time.time()``
    for tests that want raw wall time.

    Linux caveat stated honestly: ``CLOCK_MONOTONIC`` EXCLUDES suspend, so
    a suspended process grants nothing across its own sleep — the lane
    could not have emitted traffic while it was frozen, so the suspended
    interval is honest dead time, not confiscated budget."""
    if not _env_bool("BUDGET_MONO_CLOCK", True):
        return time.time()
    mono0, wall0 = _MONO_ANCHOR
    return wall0 + max(0.0, time.monotonic() - mono0)


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
    "requests":    {"ceiling": 600.0, "refill_per_epoch": 150.0, "floor": 2.0},
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

# Drum-steady release band (2026-11-07 lab profile): the no-env law authors
# a 1.5-6.0s jitter window between drain releases — entropy BETWEEN launches
# is the drum, not a fixed cadence. An authoring may override it; authoring
# {min: 0, max: 0} DECLINES the band (operator_tick falls back to env pacing).
_RELEASE_JITTER_DEFAULT = {"min": 1.5, "max": 6.0}


@dataclass(frozen=True)
class Constitution:
    """Immutable node policy the engine stamps onto every node.

    M2 (Appendix A YAML sketch): the optional keys map 1:1 from the sketched
    constitution document — ``release_jitter``, ``controller`` authority
    bounds, ``reserve_partitions`` sizing, ``cdn_origin_keys`` M5 pins,
    ``reserve_tag_wildcards`` §9 tags, and ``store`` (``sqlite`` — the sole
    leg; no postgres key exists). All are validated fail-closed at load."""

    defaults: dict[str, dict[str, float]]
    max_single_call: dict[str, float]
    epoch_s: float
    release_jitter: dict[str, float] | None = None   # {"min": s, "max": s};
                                                      # the no-env law carries
                                                      # _RELEASE_JITTER_DEFAULT
                                                      # (drum band); {0,0}
                                                      # declines it
    controller: dict[str, Any] | None = None          # authority bounds
    reserve_partitions: dict[str, Any] | None = None  # entry/exit sizing
    cdn_origin_keys: dict[str, str] | None = None     # M5 dimension pins
    reserve_tag_wildcards: tuple[str, ...] = ()       # §9/L2 wildcard tags
    store_backend: str = "sqlite"                     # the sole leg (M2)
    source: str = "code"                              # provenance verdict:
                                                      # code | inline | file <path>

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


_ALLOWED_CONST_KEYS = (
    "defaults", "per_dim", "max_single_call", "epoch_seconds",
    "release_jitter", "controller", "reserve_partitions",
    "cdn_origin_keys", "reserve_tag_wildcards", "store")


def _parse_per_dim(per_dim: Any) -> dict[str, dict[str, float]]:
    """M2 ``per_dim`` form: ``{dim: {ceiling, floor, [refill_per_epoch]}}``.
    Ceiling + floor REQUIRED, refill optional (inherits the code default) —
    unknown keys are authoring errors (fail-closed, never silently dropped)."""
    if not isinstance(per_dim, dict):
        raise ValueError("constitution per_dim must be a map of dim -> spec")
    out: dict[str, dict[str, float]] = {}
    for d, spec in per_dim.items():
        if d not in DIMS:
            raise ValueError(f"constitution per_dim has unknown dim {d!r} "
                             f"(known: {', '.join(DIMS)})")
        if not isinstance(spec, dict):
            raise ValueError(f"constitution per_dim.{d} must be a map")
        cur: dict[str, float] = {}
        for k in ("ceiling", "floor"):
            if k not in spec or isinstance(spec[k], bool) \
                    or not isinstance(spec[k], (int, float)):
                raise ValueError(
                    f"constitution per_dim.{d}.{k} missing/not numeric "
                    "(M2 form requires ceiling + floor)")
            cur[k] = float(spec[k])
        refill = spec.get("refill_per_epoch", spec.get("refill"))
        if refill is not None:
            if isinstance(refill, bool) or not isinstance(refill, (int, float)):
                raise ValueError(
                    f"constitution per_dim.{d}.refill not numeric")
            cur["refill_per_epoch"] = float(refill)
        extra = set(spec) - {"ceiling", "floor", "refill_per_epoch", "refill"}
        if extra:
            raise ValueError(f"constitution per_dim.{d} has unknown "
                             f"key(s) {sorted(extra)}")
        out[d] = cur
    return out


def _parse_release_jitter(rj: Any) -> dict[str, float] | None:
    if rj is None:
        return None
    if not isinstance(rj, dict) or "min" not in rj or "max" not in rj:
        raise ValueError('constitution release_jitter must be {min: s, max: s}')
    lo, hi = float(rj["min"]), float(rj["max"])
    if lo < 0 or hi < lo:
        raise ValueError("constitution release_jitter needs 0 <= min <= max")
    return {"min": lo, "max": hi}


def _parse_controller(cb: Any) -> dict[str, Any] | None:
    if cb is None:
        return None
    if not isinstance(cb, dict):
        raise ValueError("constitution controller must be a map")
    allowed = {"max_transitions_per_hour", "max_throttle_down", "max_speed_up"}
    extra = set(cb) - allowed
    if extra:
        raise ValueError(f"constitution controller has unknown key(s) "
                         f"{sorted(extra)}")
    out: dict[str, Any] = {}
    tr = cb.get("max_transitions_per_hour")
    if tr is not None:
        if isinstance(tr, bool) or not isinstance(tr, (int, float)) or tr < 1:
            raise ValueError("constitution controller."
                             "max_transitions_per_hour must be a number >= 1")
        out["max_transitions_per_hour"] = int(tr)
    for k in ("max_throttle_down", "max_speed_up"):
        v = cb.get(k)
        if v is None:
            continue
        if v not in CONTROLLER_STATES:
            raise ValueError(f"constitution controller.{k}={v!r} is not a "
                             f"controller state "
                             f"({', '.join(CONTROLLER_STATES)})")
        out[k] = v
    return out or None


def _parse_partitions(rp: Any) -> dict[str, Any] | None:
    if rp is None:
        return None
    if not isinstance(rp, dict) or not rp:
        raise ValueError("constitution reserve_partitions must be a map of "
                         "partition -> spec")
    for k, v in rp.items():
        if not isinstance(v, dict):
            raise ValueError(
                f"constitution reserve_partitions.{k} must be a map")
    return rp


def _parse_cdn_keys(spec: Any) -> dict[str, str] | None:
    """M5: ``[origin-label, ...]`` or ``{pattern: origin-label}`` — the
    config that pins a CDN-fronted host's dimension identity to the
    DEFENDER'S per-origin counters instead of the edge-IP span."""
    if spec is None:
        return None
    if isinstance(spec, list):
        pairs = [(str(s), str(s)) for s in spec]
    elif isinstance(spec, dict):
        pairs = [(str(k), str(v) if v is not None else "") for k, v in
                 spec.items()]
    else:
        raise ValueError("constitution cdn_origin_keys must be a list of "
                         "labels or a {pattern: label} map")
    out: dict[str, str] = {}
    for pattern, label in pairs:
        p = pattern.strip()
        label = (label or "").strip() or p
        if not p or not label:
            raise ValueError("constitution cdn_origin_keys has an empty "
                             "pattern or label")
        out[p] = label
    return out or None


def _parse_wildcards(spec: Any) -> tuple[str, ...]:
    if spec is None:
        return ()
    if not isinstance(spec, (list, tuple)):
        raise ValueError("constitution reserve_tag_wildcards must be a "
                         "list of tags")
    return tuple(str(t).strip().lower() for t in spec if str(t).strip())


def constitution(
    *, now: float | None = None
) -> Constitution:
    """The constitution, built from env at CALL time (lane convention:
    per-call env reads make tests and operator edits take effect without a
    process restart). Raises on invalid authoring — callers convert to the
    fail-closed Unknown verdict, never green.

    M2 authoring forms are accepted ON TOP of the legacy form: a JSON (or
    .yml/.yaml file) document may carry ``per_dim`` (the Appendix A sketch),
    ``epoch_seconds``, ``release_jitter``, the ``controller`` bounds,
    ``reserve_partitions``, ``cdn_origin_keys`` (M5), the
    ``reserve_tag_wildcards`` list (§9/L2), and ``store`` — which must be
    ``sqlite`` (the sole leg; no postgres key exists). Unknown top-level
    keys raise — authored config is never silently reinterpreted."""
    epoch_s = _env_float("BUDGET_EPOCH_SECONDS", _EPOCH_S_DEFAULT, minimum=1.0)
    defaults = {d: dict(_DIM_DEFAULTS[d]) for d in DIMS}
    max_single = dict(_MAX_SINGLE_CALL)
    raw = os.getenv("BUDGET_CONSTITUTION", "").strip()
    raw_file = os.getenv("BUDGET_CONSTITUTION_FILE", "").strip()
    source = f"file {raw_file}" if raw_file else (
        "inline" if raw else "code")  # provenance verdict for the viewer
    overrides: Any = None
    if raw_file:
        with open(raw_file) as fh:
            text = fh.read()
        try:
            overrides = json.loads(text)
        except json.JSONDecodeError:
            if raw_file.lower().endswith((".yml", ".yaml")):
                import yaml  # optional dep; JSON needs no reader
                overrides = yaml.safe_load(text)
            else:
                raise
    elif raw:
        overrides = json.loads(raw)
    rj: dict[str, float] | None = dict(_RELEASE_JITTER_DEFAULT)
    ctrl: dict[str, Any] | None = None
    parts: dict[str, Any] | None = None
    cdn: dict[str, str] | None = None
    wild: tuple[str, ...] = ()
    if isinstance(overrides, dict):
        unknown = [k for k in overrides if k not in _ALLOWED_CONST_KEYS]
        if unknown:
            raise ValueError(f"constitution has unknown key(s) {unknown} "
                             f"(known: {', '.join(_ALLOWED_CONST_KEYS)})")
        if overrides.get("per_dim") and overrides.get("defaults"):
            raise ValueError("constitution mixes 'per_dim' and legacy "
                             "'defaults' — pick one authoring form")
        user_defaults = overrides.get("defaults") or {}
        for d, spec in user_defaults.items():
            if d in DIMS and isinstance(spec, dict):
                cur = dict(defaults[d])
                cur.update({k: spec[k] for k in cur if k in spec})
                defaults[d] = cur
        for d, spec in _parse_per_dim(overrides.get("per_dim") or {}).items():
            cur = dict(defaults[d])
            cur.update(spec)
            defaults[d] = cur
        user_max = overrides.get("max_single_call") or {}
        for d, v in user_max.items():
            if d in DIMS and v is not None:
                max_single[d] = float(v)
        es = overrides.get("epoch_seconds")
        if es is not None:
            if isinstance(es, bool) or not isinstance(es, (int, float)) \
                    or float(es) <= 0:
                raise ValueError("constitution epoch_seconds must be a "
                                 "positive number")
            epoch_s = float(es)
        authored_rj = _parse_release_jitter(overrides.get("release_jitter"))
        if authored_rj is not None:
            rj = authored_rj  # band absent in the authoring keeps the drum
        ctrl = _parse_controller(overrides.get("controller"))
        parts = _parse_partitions(overrides.get("reserve_partitions"))
        cdn = _parse_cdn_keys(overrides.get("cdn_origin_keys"))
        wild = _parse_wildcards(overrides.get("reserve_tag_wildcards"))
        store_b = overrides.get("store")
        if store_b is not None and str(store_b).strip().lower() != "sqlite":
            raise ValueError(
                f"constitution store must be 'sqlite' (the sole leg — "
                f"no postgres key exists; got {store_b!r})")
    Constitution.validate(defaults, max_single, epoch_s)
    return Constitution(defaults=defaults, max_single_call=max_single,
                        epoch_s=epoch_s, release_jitter=rj, controller=ctrl,
                        reserve_partitions=parts, cdn_origin_keys=cdn,
                        reserve_tag_wildcards=wild, store_backend="sqlite",
                        source=source)


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
    ensure_seed_estimators()  # cold-start ordering — see _estimator_engaged
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


# evasion_upgrade.md §2.2: per-line consumption vectors for wordlist-shaped
# tools. Declared requests = line count (1 hit ≈ 1 request); bytes = lines
# × WORDLIST_FILL_BYTES (request + response ≈ 8 KiB). The chunk lane's
# slice arithmetic min()s these over max_single — the binding dim is the
# tightest one (§2.2).
WORDLIST_FILL_BYTES = 8192.0
WORDLIST_TOOL_VECTORS = {
    "payloads.ffuf.run_ffuf": {"requests": 1.0, "packets": None,
                               "auth_events": None, "bytes": WORDLIST_FILL_BYTES},
}


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

        @register_estimator("payloads.ffuf.run_ffuf", basis="estimation",
                            name="ffuf_lines")
        def _ffuf(target, arguments):
            # U2 wordlist economics (§2): `lane_decision` is the ONE
            # predicate the estimator and the tool body both read, so
            # preflight and body can never disagree about plan vs
            # single-shot. Single-shot declares its true line vector; a
            # plan issue is a ZERO dispatch (spend lands per chunk
            # through the drain); a chunk dispatch declares its slice.
            # Lane off / no wordlist / unreadable constitution → open
            # credit line (the legacy shape).
            from utils import wordlist_chunking as wlc
            if not wlc.plan_enabled():
                return {d: None for d in DIMS}
            decision = wlc.lane_decision(
                "payloads.ffuf.run_ffuf", arguments,
                wlc.resolved_ffuf_wordlist(arguments))
            if decision is None:
                return {d: None for d in DIMS}
            if decision["mode"] == "plan":
                return {"requests": 0.0, "packets": None,
                        "auth_events": None, "bytes": 0.0}
            return dict(decision["decl"])

        @register_estimator("payloads.hydra.run_hydra", basis="credit_line",
                            name="hydra_open")
        def _hydra(target, arguments):
            return {d: None for d in DIMS}  # auth-traffic; open-ended

        @register_estimator("auxiliaries.web_login_brute.web_login_brute",
                            basis="credit_line", name="web_login_brute_open")
        def _wlb(target, arguments):
            return {d: None for d in DIMS}  # wordlist-dependent; open-ended

        @register_estimator(
            "payloads.metasploiting.MetasploitClient.dispatch_metasploit",
            basis="credit_line", name="msf_dispatch_open")
        def _msf(target, arguments):
            return {d: None for d in DIMS}  # msf module traffic; open-ended

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


def _cdn_origin_keys() -> dict[str, str]:
    """M5 dimension identity overrides: ``BUDGET_CDN_ORIGIN_KEYS`` env (JSON
    ``{pattern: label}`` or label list) FIRST, else the constitution block;
    both absent → empty. A parse failure raises (authored-honest; callers
    convert to the fail-closed path) — a typo'd pin list whose host keys
    would silently key traffic by edge-IP instead of origin is exactly the
    bug M5 exists to kill."""
    raw = os.getenv("BUDGET_CDN_ORIGIN_KEYS", "").strip()
    if raw:
        spec = json.loads(raw)
        keys = _parse_cdn_keys(spec)
        if not keys:
            raise ValueError("BUDGET_CDN_ORIGIN_KEYS parses to no labels")
        return keys
    try:
        c = constitution()
    except Exception:
        return {}                # broken constitution has its own loud path
    return c.cdn_origin_keys or {}


def _cdn_pin(host_axis: str | None) -> str | None:
    """The defender-side origin label for a host, when one is pinned. Match
    is suffix-or-equal (``*.pattern`` in the appendix sketch collapses to
    the pattern itself); a pinned host drops its mechanical range_axis —
    defender counters are per-ORIGIN, not per edge-IP (M5)."""
    if not host_axis:
        return None
    keys = _cdn_origin_keys()
    if not keys:
        return None
    host = host_axis.lower().strip()
    for pattern, label in keys.items():
        p = pattern.strip().lower()
        if p.startswith("*."):
            p = p[2:]
        p = p.lstrip(".").rstrip(".")
        if p and (host == p or host.endswith("." + p)):
            return label
    return None


def dims_for_target(target: str | None, *, principal: str | None = None,
                    exit_id: str | None = None,
                    entry_partition: str | None = None) -> dict:
    """Node identity from a dispatch target (§4.2), reusing the fleet's span
    normalizer (never fork a second span normalizer, §3):

    - ``host_axis``: numeric → the fleet's canonical span label (a bare IP
      or a CIDR/range collapsed); URL-embedded numeric hosts keep only the
      host; hostname → lowercased (no DNS, ever). M5: a CDN-pinned host
      resolves to its configured ORIGIN key instead — defender counters
      are per-origin, not per edge-IP.
    - ``range_axis``: the bare single IP's containing /24 (a sweep of that
      /24 and its member hosts contend on the same range node). None when
      the host axis IS a multi-address span (sweeps debit the host node;
      range=None avoids double-debiting one node), the host is a name, OR
      the host is CDN-pinned (the origin key replaces span identity).
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
    origin = _cdn_pin(host_axis)
    if origin:
        # M5: the pinned ORIGIN key becomes the dimension identity; the
        # mechanical edge-IP span axis is dropped for this dimension.
        host_axis = origin
        range_axis = None
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
                 now_fn: Callable[[], float] | None = None):
        self.store = store
        self.hysteresis_k = (hysteresis_k if hysteresis_k is not None
                             else _env_int("BUDGET_CTRL_HYSTERESIS_K", 2,
                                           minimum=1))
        self.quiet_window_s = (quiet_window_s if quiet_window_s is not None
                               else _env_float("BUDGET_CTRL_QUIET_WINDOW_S",
                                               120.0, minimum=1.0))
        # M2 authority bounds (constitution controller block; env fallback).
        bound_src: dict[str, Any] | None = None
        try:
            bound_src = constitution().controller
        except Exception:
            logger.debug("swallowed constitution read for controller bounds",
                         exc_info=True)
        bound_src = bound_src or {}
        self.max_transitions_h = (
            max_transitions_h if max_transitions_h is not None
            else int(bound_src.get("max_transitions_per_hour")
                     or _env_int("BUDGET_CTRL_MAX_TRANSITIONS_H", 12,
                                 minimum=1)))
        self.max_throttle_down = (bound_src.get("max_throttle_down")
                                  or "cooldown")
        self.max_speed_up = bound_src.get("max_speed_up") or "normal"
        if self.max_throttle_down not in CONTROLLER_STATES:
            self.max_throttle_down = "cooldown"
        if self.max_speed_up not in CONTROLLER_STATES:
            self.max_speed_up = "normal"
        self.now_fn = now_fn if now_fn is not None else budget_now

    @property
    def _deepest_allowed_idx(self) -> int:
        return CONTROLLER_STATES.index(self.max_throttle_down)

    @property
    def _highest_allowed_idx(self) -> int:
        return CONTROLLER_STATES.index(self.max_speed_up)

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
                # M2 authority bound: the controller may NEVER deepen past
                # max_throttle_down even on hard evidence.
                deeper = CONTROLLER_STATES[min(
                    idx + 1, len(CONTROLLER_STATES) - 1,
                    self._deepest_allowed_idx)]
                if deeper != rec["state"] and self._advance_window_ok(rec, now):
                    # capped at the current depth: no posture change, no
                    # transition-slot burn (§8.2) — the streak simply keeps
                    # counting honest evidence.
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
                    if idx <= self._highest_allowed_idx:
                        # M2 authority bound: already at/below the fastest
                        # sanctioned recovery level — operator review, not
                        # quiet-stretch decay, moves it again.
                        target_idx = idx
                    else:
                        target_idx = idx - 1
                    # M2 authority bound: recovery NEVER rises above
                    # max_speed_up — a constitution that says the fastest
                    # sanctioned recovery is `throttled` stays there until
                    # operator review regardless of quiet stretches.
                    rec["state"] = CONTROLLER_STATES[target_idx]
                    rec["entered"] = now
                    rec["streak"] = 0
                    rec["quiet_since"] = now  # next decay needs a full window
        self.store.set_controller_state(
            key, "requests", state=rec["state"],
            streak=int(rec.get("streak") or 0), quiet_since=rec.get("quiet_since"),
            entered=float(rec.get("entered") or now),
            transitions_hour=list(rec.get("transitions_hour") or []))
        return rec

    def verdict(self, *, engagement: str | None = None,
                host_axis: str | None = None,
                now: float | None = None,
                window_s: float | None = None) -> str:
        """§8.3 H2 span-provenance verdict for a host lane — how much the
        controller's observation can be TRUSTED:

        - ``measured``: request-level spans landed in the window (the
          web/session lane saw per-request events) — tight tripwire bounds
          drive the auto-throttle.
        - ``aggregate``: only batch SUMMARY spans (nmap/masscan emit one
          per draw) — loose bounds only.
        - ``unknown``: NO spans — no observed request-level truth; the
          tight conservative bounds hold and the lane verdicts Unknown-ish
          (the honesty rule: unobserved is unmeasured)."""
        now = now if now is not None else self.now_fn()
        window_s = window_s or max(self.quiet_window_s, 300.0)
        try:
            return self._verdict_impl(engagement, host_axis, now)
        except Exception:
            logger.debug("swallowed span consult in verdict", exc_info=True)
            return "unknown"

    def _verdict_impl(self, engagement, host_axis, now: float,
                      window_s: float | None = None) -> str:
        window_s = window_s or max(self.quiet_window_s, 300.0)
        spans = self.store.span_summary(
            host_axis=host_axis, engagement=engagement, before_ts=now,
            window_s=window_s)
        if spans.get("request"):
            return "measured"
        if spans.get("aggregate"):
            return "aggregate"
        return "unknown"

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
                # §8.3 H2 two-tier ledger: span provenance weights the
                # bound's confidence. Request-level spans (and no spans at
                # all — unknown keeps the conservative default) drive the
                # tight bounds; AGGREGATE-only evidence widens the deadband
                # so a coarse batch summary cannot slam the throttle on
                # sparse data.
                if spent >= lower:
                    wide = 1.0
                    if self._verdict_impl(
                            engagement, host_axis, now,
                            window_s=max(self.quiet_window_s, win)) == \
                            "aggregate":
                        wide = _env_float("BUDGET_SPAN_AGG_DEADBAND", 4.0,
                                          minimum=1.0)
                    if spent >= lower * wide and factor > \
                            CONTROLLER_PACING["throttled"]:
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
                  entry_partition: str | None = None,
                  operator_release: bool = False) -> dict:
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
        now = now if now is not None else budget_now()
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
        try:
            dims = dims_for_target(target, principal=None, exit_id=exit_id,
                                   entry_partition=entry_partition)
        except Exception as exc:
            # L3: the engine's OWN config fault (e.g. unparseable CDN pin
            # list) is admission fail-closed too — no escape hatch exists.
            logger.debug("swallowed dims error in preflight", exc_info=True)
            return {"decision": "unknown", "fail_closed": True,
                    "reason": f"target dimensioning failed (fail-closed): "
                              f"{exc!r}"}
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
        # §6.2 (v0.4 fix): HOLD gates FRESH lanes — admit or enqueue, either
        # way the fresh dispatch yields to the operator drain. The operator
        # lane (operator_release) passes; the drain re-admits every tick.
        # No queue row is minted for a held fresh dispatch — the drain owns it.
        if (not operator_release and isinstance(decision, str)
                and decision in ("admit", "enqueue") and any(
                    r["mode"] == "hold" for r in self.store.conn.execute(
                        "SELECT mode FROM nodes"))):
            decided["decision"] = "held_pending"  # gate has its own branch
            decided["instruction"] = (
                "node in HOLD (backlog drain pending) - do NOT retry; "
                "the operator tick already owns this item")
            return decided
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
        now = now if now is not None else budget_now()
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
        now = now if now is not None else budget_now()
        batch = batch or _env_int("BUDGET_DRAIN_BATCH", _DRAIN_BATCH_DEFAULT,
                                  minimum=1)
        results: list[dict] = []
        self.store.sweep_expired(now=now)
        # §6.2: automatic HOLD ⇄ NORMAL per node from the live backlog — the
        # refill economy of one host never freezes another host's. A held
        # node re-normalizing with empty backlog stamps a JITTERED epoch
        # anchor so refill resumes only after the drain window.
        authored_jitter: dict | None = None
        try:
            const = self.constitution()
            epoch_s = const.epoch_s if const is not None else _EPOCH_S_DEFAULT
            # M2 release_jitter: {min,max} seconds between releases, authored
            # in the constitution — overrides BUDGET_RELEASE_JITTER_S when
            # present.
            authored_jitter = const.release_jitter if const else None
        except Exception:
            logger.debug("swallowed constitution read in operator_tick",
                         exc_info=True)
            epoch_s = _EPOCH_S_DEFAULT
        spread = _env_float("BUDGET_JITTER_SPREAD", 0.15, minimum=0.0)
        self.store.apply_backlog_modes(
            now, epoch_s, jitter_lo=epoch_s * (1.0 - spread),
            jitter_hi=epoch_s * (1.0 + spread))
        # U2: observe wordlist-plan chunk jobs BEFORE selecting the batch —
        # finished siblings free their slots and mint the next lazy window
        # so the same tick can carry the plan forward. The advance summary
        # rides the tick result (pacemaker state file + doctor lens).
        _adv: dict = {}
        try:
            from utils.wordlist_chunking import advance_plans
            _adv = advance_plans(now=now) or {}
        except Exception:
            logger.debug("swallowed plan advance in operator_tick",
                         exc_info=True)
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
                # Bounded-failure seam close (2026-11-06): a dispatch that
                # RAISES is often deterministic (ScopeGateError, tool
                # misconfig, bad transport) — looping it to TTL wedges the
                # queue for 24h with zero surface. Each failure stamps an
                # attempt; past BUDGET_RETRY_MAX the item EXITS as 'failed'
                # with the last error on the row (budget_queue_status and
                # the tick result both say why). Transient hiccups still
                # get their full retry budget; the drain is never silent.
                attempts = 0
                try:
                    attempts = self.store.stamp_attempt(
                        qid, f"dispatch_failed: {exc}")
                except Exception:
                    logger.debug("swallowed attempt stamp at drain",
                                 exc_info=True)
                max_retries = _env_int("BUDGET_RETRY_MAX", _RETRY_MAX_DEFAULT,
                                       minimum=0)
                if attempts > max_retries:
                    try:
                        self.store.fail_item(
                            qid, f"retry budget exhausted ({attempts} "
                            f"attempts; max {max_retries}) — last error: "
                            f"{exc}")
                        results.append({"qid": qid,
                                        "decision": "failed_exhausted",
                                        "error": str(exc)})
                    except Exception:
                        logger.debug("swallowed fail-exit at drain",
                                     exc_info=True)
                        results.append({"qid": qid,
                                        "decision": "dispatch_failed",
                                        "error": str(exc)})
                else:
                    logger.warning("[ration] drain dispatch raised (%s) — "
                                   "item stays queued for the next tick "
                                   "(attempt %s/%s)", exc, attempts,
                                   max_retries)
                    results.append({"qid": qid,
                                    "decision": "dispatch_failed",
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
            if out.get("requeued"):
                # U2 wordlist lane: the chunk's launch hit a fleet duplicate
                # (the sibling unit owns this work) or a TRANSIENT fleet
                # refusal — the wrapper re-enqueued the SAME chunk and the
                # plan keeps advancing elsewhere. Nothing to bind; the churn
                # counts against the batch like still_short so a plan in
                # fleet-contended territory cannot burn endless ticks
                # silently (§2.5).
                results.append({"qid": qid, "decision": "requeued",
                                "plan_id": out.get("plan_id"),
                                "reason": out.get("reason")})
                dispatched += 1
                continue
            if out.get("plan_minted"):
                # §3.2 seam (2026-11-07): a dispatch minted a wordlist plan
                # at drain. The dispatcher maps it to plan_minted (never
                # finished/requeued) and the ENGINE decides fate by
                # re-deriving chunk-keyed-ness from the item's OWN args
                # (authoritative; the envelope's phantom flag is only
                # observability):
                #   keyed   → PHANTOM mint: a chunk re-decided plan mode
                #             whole-wordlist (deterministic arg-loss — the
                #             plan's minter would do it the same every
                #             pass). Fail the item on FIRST observation and
                #             cancel the minted plan; no retry budget — a
                #             retry's only product is another empty plan.
                #   unkeyed → legitimate conversion: the whole-wordlist
                #             item minted the plan its work lives in;
                #             consumed as done-converted, chunk queue
                #             carries it under BUDGET_DRAIN_BATCH pacing.
                _keyed = False
                try:
                    from utils.budget_drain import item_carries_chunk_keys
                    _keyed = item_carries_chunk_keys(item)
                except Exception:
                    logger.debug("swallowed keyed-ness probe at drain",
                                 exc_info=True)
                _pid = str(out.get("plan_id") or "")
                if _keyed:
                    self.store.fail_item(
                        qid, f"phantom plan re-mint at drain — plan {_pid} "
                             f"re-decided plan mode for a chunk-keyed item; "
                             f"phantom plan cancelled; item failed "
                             f"(deterministic arg-loss)")
                    try:
                        self.store.cancel_plan(
                            _pid, note=f"phantom mint from keyed item {qid}")
                    except Exception:
                        logger.debug("swallowed phantom-plan cancel",
                                     exc_info=True)
                    results.append({"qid": qid,
                                    "decision": "failed_phantom_plan",
                                    "plan_id": _pid})
                    dispatched += 1
                    continue
                self.store.cancel_item(
                    qid, note=(f"converted to plan {_pid} — work continues "
                               f"as its chunk items; poll "
                               f"budget_queue_status(plan_id=\"{_pid}\")"))
                results.append({"qid": qid, "decision": "converted_to_plan",
                                "plan_id": _pid})
                dispatched += 1
                continue
            if str(out.get("status") or "").strip().lower() == "failed":
                # Failed-envelope seam close (2026-11-06): run_tool wraps
                # every raised tool-body error (incl. ScopeGateError) as a
                # {"status": "Failed"} envelope instead of raising — lanes
                # that don't map exceptions would otherwise consume the
                # item as an inline success. Same bounded-ledger fate as a
                # dispatch raise: attempts increment, past BUDGET_RETRY_MAX
                # the item EXITS as 'failed' with the tool's error text.
                _ferr = str(out.get("error") or "tool returned Failed")
                attempts = 0
                try:
                    attempts = self.store.stamp_attempt(
                        qid, f"tool error: {_ferr}")
                except Exception:
                    logger.debug("swallowed attempt stamp (Failed envelope)",
                                 exc_info=True)
                max_retries = _env_int("BUDGET_RETRY_MAX", _RETRY_MAX_DEFAULT,
                                       minimum=0)
                if attempts > max_retries:
                    try:
                        self.store.fail_item(
                            qid, f"retry budget exhausted ({attempts} "
                            f"attempts; max {max_retries}) — last error: "
                            f"{_ferr}")
                        results.append({"qid": qid,
                                        "decision": "failed_exhausted",
                                        "error": _ferr})
                    except Exception:
                        logger.debug("swallowed fail-exit (Failed envelope)",
                                     exc_info=True)
                        results.append({"qid": qid, "decision": "tool_failed",
                                        "error": _ferr})
                else:
                    results.append({"qid": qid, "decision": "tool_failed",
                                    "error": _ferr})
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
            if dispatched >= _eff_batch:
                continue
            if authored_jitter and (authored_jitter["min"] > 0.0
                                    or authored_jitter["max"] > 0.0):
                # M2 constitution-authored release band: the min is the
                # floor interval, the max the spread — pacing scaling and
                # the cap still apply (cap lifts only to fit the authored
                # max).
                delay = min(
                    authored_jitter["min"] + random.uniform(
                        0.0, max(0.0, authored_jitter["max"]
                                 - authored_jitter["min"]))
                    * (1.0 / pacing),
                    max(release_cap, authored_jitter["max"]))
            elif release_base > 0.0:
                delay = min(random.uniform(0.0, release_base)
                            * (1.0 / pacing), release_cap)
            else:
                # declined band {0,0} + no env pacing → no inter-release gap
                continue
            if delay > 0.0:
                out_s = sleep_fn(delay)
                if hasattr(out_s, "__await__"):
                    await out_s
        return {"decision": "drained", "results": results,
                "backlog_remaining": max(0, len(items) - len(results)),
                "advance": {"settled": list(_adv.get("settled") or []),
                            "failed_plans": list(_adv.get("failed_plans")
                                                 or [])}}

    # -- L1 reconcile (§10) -----------------------------------------------------

    def reconcile(self, receipt: dict, actual: dict, *,
                  response_class: str | None = None,
                  signals: dict | None = None,
                  settle: bool = False,
                  settle_note: str = "") -> dict | None:
        """L1 true-up on a debit receipt. Tripwire seeds update on any
        actuals; drift stamps APPEND (never rewrite the declared vector).

        §5 M3/§7.1 METER (v0.3): actuals beyond the advance-charged
        declared vector charge as consumed (reconcile to ``max(L0, L1)``
        per dim — actuals may run UNDER declaration and never refund);
        a credit-line draw's lifecycle advances hold → metering → settled
        here (``settle=True`` at the release point)."""
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
        # §7.1 METER: charge the max(L0, L1) delta through the cascade. The
        # meter can NEVER break a reconcile — an exhausted mid-flight draw
        # is reported, not raised.
        try:
            const = self.constitution()
            if const is not None:
                mout = self.store.meter_draw(
                    emission_id, actual, policy=self._policy(const),
                    epoch_s=const.epoch_s, now=budget_now(),
                    settle=settle, settle_note=settle_note)
                if mout:
                    out["meter"] = mout
                    if mout.get("exhausted"):
                        logger.warning(
                            "[ration] credit-line draw %s exhausted mid-"
                            "flight — tool must END (non-resumable crawls "
                            "end; resumables pause via twins)", emission_id)
        except Exception:
            logger.debug("swallowed meter stage in reconcile", exc_info=True)
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
        now = now if now is not None else budget_now()
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
    try:
        exhausted = snap.get("exhausted_draws")
        if exhausted:
            lines.append(f"exhausted credit-line draws: {exhausted} "
                         "(died mid-flight — the tool must END; resumables "
                         "pause via their status/cancel twins)")
    except Exception as exc:
        logging.getLogger(__name__).debug(
            "swallowed exception in budget_status(exhausted)", exc_info=True)
    # §10 H2: span-provenance verdict per active lane — the confidence the
    # controller currently weighs (measured = request-level, aggregate =
    # batch summaries, unknown = pacing stays conservative).
    try:
        lanes = engine.store.span_lanes()
        if lanes:
            for lane in lanes[:4]:
                lines.append(
                    "spans: {eng} on {host} — {req} request / {agg} "
                    "aggregate (prov {verdict})".format(
                        eng=lane["engagement"], host=lane["host_axis"],
                        req=lane["request_spans"],
                        agg=lane["aggregate_spans"],
                        verdict=("measured" if lane["request_spans"]
                                 else "aggregate" if lane["aggregate_spans"]
                                 else "unknown")))
    except Exception as exc:
        logging.getLogger(__name__).debug(
            "swallowed exception in budget_status(spans)", exc_info=True)
    try:
        const = engine.constitution()
        if const is not None and getattr(const, "reserve_partitions", None):
            parts = ", ".join(sorted(const.reserve_partitions))
            lines.append(f"reserve partitions (advisory): {parts} — operator "
                         "sizes the entry/exit split beyond the token tags")
    except Exception as exc:
        logging.getLogger(__name__).debug(
            "swallowed exception in budget_status(partitions)", exc_info=True)
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
                        limit: int = 20,
                        plan_id: str = "") -> str:
    """Ration deferral-queue listing for the model lane.

    NOTE (L4): TTL expiry of deferred items is notification-silent — the
    item simply stops appearing once expired; there is NO push event. Poll
    this status lane to notice the disappearance.

    Args:
        tool: Case-insensitive substring filter on the tool id; empty = all.
        state: queued|launched|finished|cancelled|failed|all (default
            queued). 'failed' = items that exhausted BUDGET_RETRY_MAX and
            exited the queue with their last error on the row (§2.6).
        limit: Max rows returned (default 20).
        plan_id: wordlist-plan lens (U2): observe + advance that plan's
            chunk ladder first, then report its frontier arithmetic.

    Returns:
        Formatted backlog rows (plus a plan section) and a state-count
        summary.
    """
    store = get_ration_store()
    limit = max(1, int(limit))
    plan_section = ""
    if plan_id:
        try:
            from utils.wordlist_chunking import advance_plans
            advance_plans()
        except Exception:
            logger.debug(
                "swallowed plan advance in budget_queue_status",
                exc_info=True)
        plan = store.plan_get(plan_id)
        if plan is None:
            plan_section = f"plan {plan_id}: not found"
        else:
            counts = store.plan_counts(plan_id)
            total = int(counts.get("total_chunks") or 0)
            minted = int(counts.get("minted") or 0)
            lines_n = int(plan.get("lines") or 0)
            plan_section = (
                f"plan {plan_id} [{plan.get('state')}] {plan['tool']} "
                f"wordlist={plan['wordlist']} lines={lines_n} "
                f"chunk_size={plan['chunk_size']} "
                f"({plan['binding_dim']}-bound) "
                f"total={total} minted={minted} "
                + " ".join(f"{k}={v}" for k, v in sorted(counts.items())
                           if k not in ("total_chunks", "minted")))
            if plan.get("state") == "failed":
                # Dead-plan traceability (2026-11-06 seam close): the lens
                # names the WHY on the settled plan so a drained-dead plan
                # is never a bare 'failed' with no story.
                term_rows = store.plan_chunks(plan_id, status="failed") + \
                    store.plan_chunks(plan_id, status="cancelled")
                for c in term_rows[:1]:
                    if c.get("notes_json"):
                        plan_section += f" — {c['notes_json']}"
            chunk_rows = store.plan_chunks(plan_id)
            for c in chunk_rows[:limit]:
                meta = json.loads(c.get("chunk_meta_json") or "{}")
                plan_section += (
                    f"\n  {c['qid']} [{c['status']}] chunk "
                    f"{int(c.get('chunk_index') or 0) + 1}/{total} "
                    f"lines#{meta.get('chunk_offset')}-{meta.get('chunk_size')} "
                    f"job={c.get('job_ref') or '-'}")
            if len(chunk_rows) > limit:
                plan_section += f"\n  … {len(chunk_rows) - limit} more chunks"
            # §4 P0 verdict rollup (2026-11-07): terminal chunks carry their
            # poll-time verdict parser output in plan_verdicts, so a settled
            # plan reads its results here long after the job logs TTL out.
            try:
                verdicts = store.plan_verdicts(plan_id)
            except Exception:
                logger.debug("swallowed plan-verdict read in lens",
                             exc_info=True)
                verdicts = []
            for v in verdicts[:limit]:
                payload = {}
                try:
                    payload = json.loads(v.get("verdict_json") or "{}")
                except (TypeError, ValueError):
                    payload = {}
                findings = payload.get("findings") or []
                samples = []
                for f in findings[:5]:
                    if isinstance(f, dict):
                        samples.append(str(f.get("path") or f.get("url") or "?"))
                fc = payload.get("findings_count")
                try:
                    fc_n = int(fc) if fc is not None else len(findings)
                except (TypeError, ValueError):
                    fc_n = len(findings)
                plan_section += (
                    f"\n  verdict {v['qid']} chunk"
                    f" {int(v.get('chunk_index') or 0) + 1}/{total}"
                    f" [{v.get('status') or '-'}] findings={fc_n}"
                    + (" sample=" + ",".join(x for x in samples if x)
                       if samples else ""))
    rows_sql = None
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
        pos = ""
        if d["status"] == "queued" and d.get("qid"):
            _p = store.queued_position(d["qid"])
            if _p is not None:
                pos = f" pos={_p}"  # standing in the drain's launch order
        # §2.6: a bounded-failing item shows its attempts + last error
        # INLINE, so a wedged row is diagnosable from the lens on tick 1.
        _att = int(d.get("attempts") or 0)
        _att_s = f" attempts={_att}" if _att else ""
        out.append(
            f"  {d['qid']} [{d['status']}]{pos} {d['tool']} "
            f"prio={d['priority']} waited={age:.1f}m{_att_s} "
            f"job={d.get('job_ref') or '-'} reason={d['reason']}"
            + (f" notes={d['notes_json']}" if d.get("notes_json") else ""))
    counts = store.conn.execute(
        "SELECT status, COUNT(*) n FROM queue_items GROUP BY status"
    ).fetchall()
    summary = ", ".join(f"{c['status']}={c['n']}" for c in counts) or "empty"
    body = "\n".join(out[:int(limit)]) if out else "  (queue empty)"
    header = "queue" if not plan_section else f"{plan_section}\nqueue"
    return f"{header} [{summary}]:\n{body}"


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
    # Seed FIRST (cold-start ordering, 2026-11-06 ffuf circle-back): the
    # registry used to fill ONLY inside RationEngine.__init__ — but every
    # consult site (ration_gate, the U2 lane's _budget_lane_ready)
    # checked engagement BEFORE ever constructing the engine, so a fresh
    # process (the Brain above all: its body-side plan-mode branch gates
    # exactly here) consulted a permanently empty registry, engaged
    # nothing, and never reached the code that would seed it. The seed is
    # idempotent (Event-guarded) and near-free after the first call.
    ensure_seed_estimators()
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
                     arguments: dict | None = None,
                     instruction: str | None = None) -> dict:
    env = {"status": status, "tool_id": tool_id,
           "arguments": arguments or {}, "declared": declared}
    if status == "budget_deferred":
        if instruction is None:
            # Standing-in-line ground truth: drain-order position when a
            # queue row really exists. Cosmetics never block the envelope
            # (swallowed, logged) — an unpositioned honest instruction is
            # better than a refused deferred dispatch.
            _pos = ""
            if queue_id:
                try:
                    _p = get_ration_store().queued_position(queue_id)
                    if _p is not None:
                        _pos = f" (position {_p} in queue)"
                except Exception:
                    logger.debug("swallowed position read in envelope",
                                 exc_info=True)
            instruction = ("budget short — do NOT retry this call; the item "
                           "is queued and the operator tick will drain it "
                           "(check budget_status / budget_queue_status)"
                           + _pos)
        # instruction is NOT None here only when a caller with different
        # semantics passes it (e.g. held_pending has NO queue row —
        # "the item is queued" would be a lie).
        env.update({
            "decision": "enqueue",
            "queue_id": queue_id,
            "defer_reason": "budget_short",
            "instruction": instruction,
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
    now = now if now is not None else budget_now()
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
                operator_release: bool = False,
                now: float | None = None) -> dict | None:
    """The dispatch chokepoint's budget step. Returns:

    - ``None`` — ration does not engage (disabled / unregistered tool);
      ``operator_release=True`` is the operator drain's release marker: the
      drain lane passes the HOLD admission block (fresh dispatches still
      defer — §6.2); every other lane leaves it False.
    - ``{"gate": "debited", ...}`` — debit committed, dispatch may proceed
      (caller MUST pass this to :func:`ration_discharge` afterwards);
    - envelope dict ``{"status": "budget_deferred"|"budget_refused", ...}`` —
      no dispatch; the callee returns it verbatim.

    Never raises: a gate machinery failure for a REGISTERED tool is a
    fail-closed refusal envelope, never a silent pass (§13).
    """
    now = now if now is not None else budget_now()
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
                                    agent_id=agent_id, engagement=engagement,
                                    operator_release=operator_release)
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
    if d == "held_pending":
        return _budget_envelope(
            tool_id, status="budget_deferred",
            reason=decision.get("reason") or
            "node in HOLD — backlog drain pending (held_pending)",
            instruction=("node HOLD — dispatch withheld for the backlog "
                         "drain; this call is NOT queued and no qid exists "
                         "(the drain re-reads your request every tick while "
                         "the node is held). Poll budget_status; if the "
                         "operator later drains past your request, a fresh "
                         "envelope with a qid will arrive."),
            declared=decision.get("declared"), arguments=arguments)
    if d == "enqueue":
        qid = decision.get("queue_id")
        return _budget_envelope(
            tool_id, status="budget_deferred", queue_id=qid,
            reason=("node in HOLD — backlog drain pending; the operator tick "
                    "already owns this item (held_pending)"
                    if decision.get("held_pending") else None),
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


def _span_rc(status_code: Any) -> str:
    """Coarse per-span response class for the two-tier ledger (§10)."""
    try:
        sc = int(status_code)
    except (TypeError, ValueError):
        return ""
    return "2xx" if 200 <= sc <= 299 else str(sc)


def _record_inline_spans(engine: "RationEngine", receipt: dict,
                         gate_state: dict, result: dict) -> int:
    """§10 two-tier ledger (H2): the web/session lane SEES per-request
    events — attach one ``request``-provenance span per hop so the
    controller (§8.3) can weight its tripwire bounds as measured. Best
    effort; spans never break a discharge."""
    emission_id = receipt.get("emission_id")
    if not isinstance(emission_id, int):
        return 0
    inner = result.get("result") if isinstance(result.get("result"), dict) \
        else result
    if not isinstance(inner, dict):
        return 0
    events: list[tuple[str | None, str]] = []
    hops = inner.get("hops")
    if isinstance(hops, list):
        events = [((h or {}).get("status") if isinstance(h, dict) else None,
                   (h or {}).get("url") if isinstance(h, dict) else None)
                  for h in hops if h is not None]
    elif inner.get("status_code") is not None:
        events = [(inner.get("status_code"), inner.get("url"))]
    if not events:
        return 0
    gate_dims = gate_state.get("dims") or {}
    host_axis = gate_dims.get("host_axis")
    engagement = gate_state.get("engagement") or gate_dims.get("engagement")
    tool = (receipt.get("tool") or receipt.get("tool_id")
            or gate_state.get("tool_id") or "")
    n = 0
    now = budget_now()
    for status_code, _url in events:
        try:
            engine.store.record_span(
                emission_id, provenance="request",
                response_class=_span_rc(status_code),
                host_axis=host_axis, engagement=engagement, tool=tool,
                ts=now)
            n += 1
        except Exception:
            logger.debug("swallowed span record (emission %s)", emission_id,
                         exc_info=True)
            break
    return n


def _record_batch_span(engine: "RationEngine", draw: dict,
                       actual: dict, poll_result: dict | None) -> dict | None:
    """§10 two-tier ledger (H2): batch tools (nmap/masscan/...) never see
    per-request events — ONE aggregate SUMMARY span per draw at release
    (window count + coarse outcome), provenance ``aggregate``, so the
    controller's tight tripwire path never over-trusts it (§8.3)."""
    emission_id = draw.get("emission_id")
    if not isinstance(emission_id, int):
        return None
    status = str((poll_result or {}).get("status") or "").strip().lower()
    rc = {"done": "ok"}.get(status, "timeout" if "timeout" in status
                            else ("failed" if status in ("failed", "error",
                                                         "cancelled")
                                  else "unknown"))
    try:
        ref = engine.store.record_span(
            emission_id, provenance="aggregate", response_class=rc,
            window_count=float(actual.get("requests") or 0.0),
            host_axis=draw.get("host_axis"), engagement=draw.get("engagement"),
            tool=draw.get("tool"), detail={"job_id": draw.get("job_ref")})
        return ref
    except Exception:
        logger.debug("swallowed aggregate span (emission %s)", emission_id,
                     exc_info=True)
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
    if status == "requeued":
        # U2 chunk lane: this attempt launched NO traffic of its own (the
        # sibling fleet unit owns the work, or the refusal was transient
        # and the chunk is re-queued in its plan). The retry debits fresh,
        # so reverse the attempt's debit — otherwise every requeue cycle
        # leaks a slice.
        try:
            return engine.compensate(
                receipt, gate_state.get("declared") or {},
                "requeued — no traffic this attempt; debit reversed "
                "(the drain re-runs the chunk)")
        except Exception as exc:
            logger.debug("swallowed requeue compensation", exc_info=True)
            return {"discharge": "requeue_compensate_failed",
                    "reason": str(exc)}
    if status in ("chunk_plan",):
        # U2 wordlist lane: the PLAN-ISSUE dispatch declared a zero vector
        # (§2.1 — no traffic in this call; spend lands per chunk through
        # the drain). There is nothing to meter: settle the emission at
        # once so no zero-draw lingers in open_draws.
        emission_id = receipt.get("emission_id")
        try:
            engine.reconcile(
                receipt, {}, settle=True,
                settle_note="wordlist plan issued — spend lands per chunk")
            return {"discharge": "plan_issued",
                    "emission_id": (emission_id
                                    if isinstance(emission_id, int) else None)}
        except Exception as exc:
            logger.debug("swallowed plan-issue settle (emission %s)",
                         emission_id, exc_info=True)
            return {"discharge": "plan_settle_failed", "reason": str(exc)}
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
        # §10 H2: the session lane saw per-request events — attach request
        # spans BEFORE the settle so the controller's next consult reads
        # measured provenance.
        spans_recorded = 0
        try:
            spans_recorded = _record_inline_spans(engine, receipt,
                                                  gate_state, result)
        except Exception:
            logger.debug("swallowed inline span recording (emission %s)",
                         emission_id, exc_info=True)
        try:
            out = engine.reconcile(
                receipt, actual, settle=True,
                settle_note="settled at inline release — unused credit "
                            "beyond the metered total released")
            return {"discharge": "reconciled", "actual": actual,
                    "spans": spans_recorded,
                    "meter": (out or {}).get("meter"),
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


def meter_poll_job(job_id: str, poll_result: dict | None = None) -> dict:
    """§7.1 METER hook for NON-terminal polls: every poll of an in-flight
    job bills the deterministic-actuals delta (``max(L0, L1)`` per dim, M3)
    through the cascade. A draw that exhausts mid-flight reports so — the
    tool must END (non-resumable crawls end; resumables pause via their own
    status/cancel twins). Best-effort: a bug here must never break polling.
    Partial actuals do NOT stamp reconcile/drift evidence — only the
    terminal reconcile does that."""
    try:
        engine = get_engine()
    except Exception:
        logger.debug("swallowed engine unavailable in meter_poll_job",
                     exc_info=True)
        return {"draws": []}
    try:
        draws = engine.store.draws_for_job(str(job_id))
        if not draws:
            return {"job_ref": str(job_id), "draws": []}
        actual = _harvest_poll_actuals(poll_result)
        if actual is None:
            return {"job_ref": str(job_id), "draws": [], "actual": None}
        const = engine.constitution()
        metered = []
        if const is not None:
            policy = engine._policy(const)
            for draw in draws:
                try:
                    mout = engine.store.meter_draw(
                        draw["emission_id"], actual, policy=policy,
                        epoch_s=const.epoch_s, now=budget_now())
                    metered.append({"emission_id": draw["emission_id"],
                                    "meter": mout or {}})
                except Exception:
                    logger.debug("swallowed meter in poll (emission %s)",
                                 draw["emission_id"], exc_info=True)
        return {"job_ref": str(job_id), "draws": metered, "actual": actual}
    except Exception as exc:
        logger.debug("swallowed exception in meter_poll_job", exc_info=True)
        return {"error": f"meter skipped: {exc!r}"}


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
                         "tool": draw["tool"]}, actual,
                        settle=True,
                        settle_note="settled at job release — unused credit "
                                    "beyond the metered total released")
                    _record_batch_span(engine, draw, actual, poll_result)
                    closed.append({"emission_id": draw["emission_id"],
                                   "reconciled": True,
                                   "actual": actual,
                                   "meter": (out or {}).get("meter"),
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
    now = now if now is not None else budget_now()
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
            closed += 1 if store.close_draw(
                draw["emission_id"], note,
                meter_state="expired") else 0   # §7.1 HOLD expiry
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
