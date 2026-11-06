"""Pure-sqlite3 budget ledger for the ration engine (evasion_design.md §13).

SQLite IS the truth, even when the Postgres mirror is up — the dispatch
path never depends on PG (write-behind mirror lands later, team mode only).
Store location: ``<workspace>/run/budget/budget.db`` (scratch-store
conventions), re-pointed by ``BUDGET_STORE_DIR`` for tests/lanes.

What lives here (Phase A):
- **nodes** — one row per node key (engagement, entry partition, exit,
  range, host, principal) with a 4-dim remaining token balance, per-dim
  policy (ceiling / refill / floor) stamped from the engine's constitution,
  and a phase mode (``normal`` / ``hold``).
- **queue_items** — the deferral queue (§7.2): queued / launching /
  launched / finished / cancelled, with a defer reason
  (``budget_short`` | ``host_busy``), agent + engagement attribution, an
  optional ``job_ref`` once bound, and a TTL (``expires_at``).
- **emissions** — the append-only per-emission ledger (§10): declared vs
  actual vectors, estimation basis, drilldown signals, budget phase, L1
  drift stamps. Retro-corrections are APPENDED (``drift_*`` columns);
  nothing is rewritten.
- **tripwire_estimates** — per-tool moving-average true-ups (seeds for the
  Phase C tripwire learning).
- **principals** — (engagement, host, principal, last_seen) rows backing
  the ``distinct_principals`` window counter (§4.3).

Transactions the whole engine leans on:
- ``admit_vector`` — READ-ONLY preflight: projects accrual + coverage per
  cascade level without writing (routing happens before every debit).
- ``debit_vector`` — the atomic cascade (§5): BEGIN IMMEDIATE → accrue +
  check ALL levels → either debit every level and append the emission row
  in the SAME transaction, or roll back everything. A shortfall never
  leaves a partial debit, and a debit is never ledger-less.
- **Fail-closed** (§13): a store that cannot be read returns
  ``{"decision": "unknown", "fail_closed": True}`` from ``admit_vector``
  and hard-fails ``debit_vector`` — sensor-degraded dims are treated
  conservative, never green.

Dims and their fixed order live in ``utils/ration.DIMS`` (import lazily to
keep the store importable standalone). A dim value of ``None`` in a declared
vector means *open-ended for this call* — the credit-line mode: admission
trivially covers it, the emission row is stamped ``credit_line``, and the
L1 true-up is what fixes the estimate later. None dims never block.

Numerics are pure stdlib (floats + sqlite); no numpy in this ledger by
decision (§13, 2026-11-03: counters are ints/deque-material, numpy stays
with the embedding lanes).
"""

from __future__ import annotations

import json
import logging
import os
import random
import secrets
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable

from constants import resolve_workspace_root

logger = logging.getLogger(__name__)

# Fixed dimension order for every vector in the engine (§4.1). JSON blobs
# keep this order stable end-to-end.
DIMS = ("requests", "packets", "auth_events", "bytes")

# Signal vocabulary (§8.1). QUIET = reaction-free responses (clean-run
# material, decays the controller back); HARD = unambiguous congestion or
# reaction (resets, 429s, count-driven 403s, tarpits); everything else =
# soft/ambiguous shaping. classification is cheap string matching on the
# response_class — no embedding, no model in the loop (§8.3 substrate).
QUIET_CLASSES = {"", "2xx", "200", "ok", "success", "pass", "none"}
HARD_CLASSES = {"reset", "rst", "429", "403_count", "tarpit", "timeout"}
SOFT_CLASSES = {"latency_delta", "challenge", "cookie_issuance", "shaped"}


def _lazy_fleet():
    """Shared fleet helpers (span normalization + the WAL race fix) — lazy so
    importing the ration store never drags the scheduler's module state in."""
    from utils.fleet_scheduler import _numeric_axis, _numeric_span, _set_wal

    return _numeric_axis, _numeric_span, _set_wal


def _node_key(engagement, entry, exit_id, range_axis, host_axis, principal) -> str:
    """Deterministic node key from the dims tuple (§4.2). NUL-separated and
    full-text so no spelling can collide (engagement 'a' + host 'b' can
    never equal engagement 'ab')."""
    return "\x1f".join(
        str(p) if p is not None else "" for p in
        (engagement, entry, exit_id, range_axis, host_axis, principal)
    )


_SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
    node_key TEXT PRIMARY KEY,
    engagement TEXT, entry_partition TEXT, exit_id TEXT,
    range_axis TEXT, host_axis TEXT, principal TEXT,
    mode TEXT NOT NULL DEFAULT 'normal',
    remaining_requests REAL NOT NULL, remaining_packets REAL,
    remaining_auth REAL, remaining_bytes REAL,
    ceiling_json TEXT NOT NULL, floor_json TEXT NOT NULL,
    refill_json TEXT NOT NULL,
    last_refill REAL NOT NULL,
    epoch_anchor REAL,
    manual_phase TEXT
);
CREATE TABLE IF NOT EXISTS queue_items (
    qid TEXT PRIMARY KEY,
    tool TEXT NOT NULL, arguments_json TEXT NOT NULL,
    declared_json TEXT NOT NULL, dims_json TEXT NOT NULL,
    reason TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'queued',
    priority INTEGER NOT NULL DEFAULT 0,
    agent_id TEXT NOT NULL, engagement TEXT,
    job_ref TEXT, no_reenqueue INTEGER NOT NULL DEFAULT 0,
    requested REAL NOT NULL, expires_at REAL NOT NULL,
    notes_json TEXT
);
CREATE TABLE IF NOT EXISTS emissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL, tool TEXT NOT NULL,
    engagement TEXT, agent_id TEXT NOT NULL,
    entry_partition TEXT, exit_id TEXT, range_axis TEXT,
    host_axis TEXT, principal TEXT,
    declared_json TEXT NOT NULL, declared_basis TEXT NOT NULL,
    estimator TEXT,
    actual_json TEXT, response_class TEXT,
    signals_json TEXT, posture_json TEXT,
    job_ref TEXT, queue_ref TEXT, budget_phase TEXT,
    drift INTEGER NOT NULL DEFAULT 0,
    drift_note TEXT,
    -- §7.1 credit-line lifecycle (v0.3): hold → metering → settled | expired
    -- | exhausted. NULL = legacy/pre-migration row or a measured (non-draw)
    -- emission that never carried a lifecycle.
    meter_state TEXT,
    -- §5/v0.3 debit-direction rule: cumulative per-dim charged total kept on
    -- the row so meter polls are idempotent (target = max(L0, L1)).
    metered_json TEXT
);
CREATE INDEX IF NOT EXISTS emissions_tool_ts ON emissions (tool, ts);
CREATE INDEX IF NOT EXISTS emissions_engagement ON emissions (engagement) WHERE engagement IS NOT NULL;
CREATE TABLE IF NOT EXISTS tripwire_estimates (
    tool TEXT PRIMARY KEY, per_dim_json TEXT NOT NULL,
    samples INTEGER NOT NULL DEFAULT 0, updated REAL
);
CREATE TABLE IF NOT EXISTS principals (
    engagement TEXT, host_axis TEXT NOT NULL, principal TEXT NOT NULL,
    first_seen REAL NOT NULL, last_seen REAL NOT NULL,
    PRIMARY KEY (engagement, host_axis, principal)
);
CREATE TABLE IF NOT EXISTS tripwire_intervals (
    -- §8.3: per-engagement, per-host BOTH-SIDED tripwire hypotheses
    -- (requests-window and friends). Onset observations cap `upper`;
    -- sustained reaction-free runs raise `lower`. Engagement purge wipes.
    engagement TEXT, host_axis TEXT NOT NULL, kind TEXT NOT NULL,
    lower REAL, upper REAL,
    window_seconds REAL NOT NULL,
    samples INTEGER NOT NULL DEFAULT 0,
    provenance TEXT, updated REAL NOT NULL,
    PRIMARY KEY (engagement, host_axis, kind)
);
CREATE TABLE IF NOT EXISTS controller_state (
    -- §8.1: per-node, per-dim posture state machine (normal → soft-signal
    -- → throttled → back-off → cooldown) with hysteresis counters.
    node_key TEXT NOT NULL, dim TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'normal',
    streak INTEGER NOT NULL DEFAULT 0,
    quiet_since REAL,
    entered REAL NOT NULL,
    transitions_hour TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (node_key, dim)
);
CREATE TABLE IF NOT EXISTS reserves (
    -- §9: operator-minted (REPL-only) per-engagement funds. A token is
    -- FROZEN (released IS NULL) until the operator tags it for free-form
    -- consumption; released tokens may back any dispatch whose dims match
    -- (None = wildcard) and whose shortfall the cascade cannot pay.
    token_id TEXT PRIMARY KEY,
    engagement TEXT,
    partition TEXT NOT NULL,
    dims_json TEXT NOT NULL,
    tag TEXT,
    max_vector_json TEXT NOT NULL,
    remaining_json TEXT NOT NULL,
    ttl_expiry REAL,
    released REAL,
    note TEXT, ts REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS reserves_engagement ON reserves (engagement) WHERE engagement IS NOT NULL;
CREATE TABLE IF NOT EXISTS signal_spans (
    -- §10 two-tier emission ledger (v0.3): per-request truth attached by
    -- tools that SEE per-request events (web/session lane: ffuf, ZAP,
    -- curl-loop, session lane); batch tools (nmap/masscan) emit SUMMARY
    -- spans only — window count + coarse outcome — provenance-tagged
    -- 'aggregate'. Confidence MATERIAL for the controller (§8.3): spans
    -- never block a dispatch and are never the throttle accounting basis
    -- (that stays window_spend/emission-rows).
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    emission_ref INTEGER NOT NULL,
    ts REAL NOT NULL,
    response_class TEXT,
    provenance TEXT NOT NULL,
    window_count REAL,
    host_axis TEXT, engagement TEXT, tool TEXT,
    detail_json TEXT
);
CREATE INDEX IF NOT EXISTS signal_spans_host_ts ON signal_spans (host_axis, ts);
CREATE INDEX IF NOT EXISTS signal_spans_ref ON signal_spans (emission_ref);
"""


def _policy_json(policy: dict) -> str:
    return json.dumps(policy, sort_keys=True)


class RationStore:
    """SQLite store for the ration engine. Thread-safe via threadlocal
    connections (job_store pattern); every public op re-opens cleanly if the
    connection died."""

    def __init__(self, *, store_dir: str | os.PathLike[str] | None = None):
        base = store_dir or os.getenv("BUDGET_STORE_DIR", "").strip()
        self.dir = Path(base).resolve() if base else (
            resolve_workspace_root() / "run" / "budget"
        )
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise RuntimeError(
                f"ration store dir unusable: {self.dir} ({exc})"
            ) from exc
        self.db_path = self.dir / "budget.db"
        self._local = threading.local()
        # Cross-lane mode heal BEFORE the first connect, not just after: a
        # db minted 0644/0640 by a tighter-umask lane (live 2026-11-05:
        # budget.db 644 daharness:daharness minted mid-service) makes the
        # first WAL pragma die with "attempt to write a readonly
        # database" — when this process OWNS the file (or runs as root)
        # it can heal itself here; a non-owner lane's chmod is a silent
        # no-op per state_perms doctrine and the owner lane or the deb
        # postinst sweep heals instead (that sweep covers all run/*.db to
        # depth 2 since 2026-11-05).
        from utils.state_perms import reconcile_sqlite_modes
        try:
            reconcile_sqlite_modes(self.db_path)
        except OSError:
            logging.getLogger(__name__).debug(
                "swallowed exception in RationStore.__init__ (perm reconcile)",
                exc_info=True)
        self._ensure_schema()

    # --- connection plumbing -------------------------------------------------

    @property
    def conn(self) -> sqlite3.Connection:
        c = getattr(self._local, "conn", None)
        if c is None:
            c = sqlite3.connect(str(self.db_path), timeout=30)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA busy_timeout=30000")
            _, _, _set_wal = _lazy_fleet()
            _set_wal(c)
            self._local.conn = c
        return c

    def _ensure_schema(self) -> None:
        try:
            self.conn.executescript(_SCHEMA)
        except sqlite3.OperationalError as exc:
            if "readonly" not in str(exc).lower():
                raise
            # The classic cross-lane state defect: this db is not
            # group-writable and this lane can't fix it (daharness-owned,
            # operator group-member, UMask 0007 wrapper or not). Tell the
            # operator the ONE-LINE fix instead of a bare WAL traceback
            # from a store open (live 2026-11-05 REPL report).
            raise RuntimeError(
                f"ration store is read-only from this lane: {self.db_path}\n"
                f"  fix: sudo chmod g+rw {self.db_path}*   "
                f"(or reinstall the deb — the postinst run/ sweep heals it)"
            ) from exc
        cols = {r[1] for r in self.conn.execute(
            "PRAGMA table_info(nodes)")}
        for name in ("epoch_anchor", "manual_phase"):
            if name not in cols:
                self.conn.execute(
                    f"ALTER TABLE nodes ADD COLUMN {name} "
                    + ("REAL" if name == "epoch_anchor" else "TEXT"))
        ecols = {r[1] for r in self.conn.execute(
            "PRAGMA table_info(emissions)")}
        # §7.1 lifecycle (meter_state/metered_json) migrations ship after the
        # table existed in the wild; new db's carry them in _SCHEMA directly.
        if "meter_state" not in ecols:
            self.conn.execute("ALTER TABLE emissions ADD COLUMN meter_state TEXT")
        if "metered_json" not in ecols:
            self.conn.execute("ALTER TABLE emissions ADD COLUMN metered_json TEXT")
        self.conn.commit()
        # Post-WAL heal per state_perms doctrine: the pragma above minted
        # (or would have minted) the -wal/-shm sidecars, which inherit the
        # main db's mode — reconcile them alongside it.
        from utils.state_perms import reconcile_sqlite_modes
        try:
            reconcile_sqlite_modes(self.db_path)
        except OSError:
            logging.getLogger(__name__).debug(
                "swallowed exception in _ensure_schema (perm reconcile)",
                exc_info=True)

    def close(self) -> None:
        c = getattr(self._local, "conn", None)
        if c is not None:
            try:
                c.close()
            except sqlite3.Error:
                logging.getLogger(__name__).debug(
                    "swallowed close error", exc_info=True)
            self._local.conn = None

    # --- policy + accrual math (shared by read-only and debit paths) ----------

    @staticmethod
    def _accrue(node: sqlite3.Row, now: float, epoch_s: float) -> dict:
        """Projected per-dim balances after lazy accrual (pure — used read-only
        by preflight and mutably by debit). Accrual is pro-rata against the
        per-epoch refill rate, clamped to the burst ceiling; HOLD-mode nodes
        accrue at the constitutional floor rate instead (never zero — §6.2).

        §6.3 clock discipline (v0.3): a single accrual touch grants at most
        ``BUDGET_ACCRUE_TICK_EPOCHS`` (default 1.0) epochs of refill — a
        wall-clock suspend or NTP step can never mint a catch-up burst, and
        elapsed never goes negative across a backward step (credit is never
        withheld, only bounded)."""
        now = now if now is not None else time.time()
        ceiling = {d: float(json.loads(node["ceiling_json"]).get(d, 0)) for d in DIMS}
        refill = {d: float(json.loads(node["refill_json"]).get(d, 0.0)) for d in DIMS}
        floor = {d: float(json.loads(node["floor_json"]).get(d, 0.0)) for d in DIMS}
        # §6.2 epoch re-anchor: a hold→normal transition stamps a future
        # epoch_anchor; NO pro-rata accrual happens before it (the clock
        # starts after the drain). After it passes, accrual counts from the
        # anchor forward.
        anchor = float(node["epoch_anchor"] or 0.0)
        last = float(node["last_refill"])
        rem_col = {"requests": "remaining_requests", "packets": "remaining_packets",
                   "auth_events": "remaining_auth", "bytes": "remaining_bytes"}
        if anchor and float(now) < anchor:
            out = {}
            for d in DIMS:
                rem = float(node[rem_col[d]] or 0.0)
                out[d] = {"remaining": rem, "ceiling": ceiling[d],
                          "rate": refill[d], "floor": floor[d],
                          "anchored": True}
            return out
        start = max(last, anchor)
        try:
            tick_epochs = float(os.getenv("BUDGET_ACCRUE_TICK_EPOCHS", "1.0"))
        except ValueError:
            tick_epochs = 1.0
        if tick_epochs <= 0:
            tick_epochs = 1.0
        # elapsed rides a wall-vs-monotonic delta the CALLER already resolved
        # (ration.budget_now); the per-tick cap is the only grant bound here.
        elapsed = min(max(0.0, float(now) - start), tick_epochs * epoch_s)
        if node["mode"] == "hold":
            refill = dict(floor)
        out = {}
        for d in DIMS:
            rem = float(node[rem_col[d]] or 0.0)
            rem = min(ceiling[d], rem + refill[d] * (elapsed / max(1e-9, epoch_s)))
            out[d] = {"remaining": rem, "ceiling": ceiling[d],
                      "rate": refill[d], "floor": floor[d]}
        return out

    @staticmethod
    def _covers(balances: dict, decl: dict) -> bool:
        """Appendix A ``covers()``: per-dim remaining ≥ requested."""
        return all(
            decl[d] is None or balances[d]["remaining"] >= decl[d]
            for d in DIMS
        )

    @staticmethod
    def _never_fits(balances: dict, decl: dict, max_single: dict) -> bool:
        """A declaration that cannot EVER fit under the ceiling (burst
        capacity) at this level is never-fit → REJECT routing at preflight.
        Credit-line dims (None) never reject."""
        return any(
            decl[d] is not None and (
                decl[d] > balances[d]["ceiling"] or decl[d] > max_single.get(d, float("inf"))
            )
            for d in DIMS
        )

    def _levels(self, dims: dict) -> list[tuple[str, dict]]:
        """Cascade levels, leaf → global (§5).
        dims: {engagement, entry_partition, exit_id, range_axis, host_axis,
        principal}. Each entry: (label, node dims subset). Each level's key
        EXCLUDES the wider axis it sits inside (a host node is host-scoped —
        not re-keyed per containing range; the range node is range-scoped —
        not re-keyed per member host) so no two levels ever collapse onto
        one node row."""
        levels = []
        if dims.get("principal"):
            levels.append(("principal", {**dims, "principal": dims["principal"]}))
        levels.append(("host", {**dims, "principal": None, "range_axis": None}))
        if dims.get("range_axis"):
            levels.append(("range", {**dims, "principal": None,
                                     "host_axis": None}))
        if dims.get("exit_id"):
            levels.append(("exit", {**dims, "principal": None,
                                    "range_axis": None}))
        levels.append(("global", {**dims, "principal": None, "range_axis": None,
                                  "host_axis": None, "exit_id": None}))
        return levels

    def _node_row(self, key: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM nodes WHERE node_key=?", (key,)).fetchone()

    def _upsert_node(self, key, dims, policy, now) -> None:
        """Ensure the node exists and carries the CURRENT constitution
        (policy re-mint on every touch; balances carry across re-mints)."""
        row = self._node_row(key)
        if row is None:
            self.conn.execute(
                "INSERT INTO nodes (node_key, engagement, entry_partition, "
                "exit_id, range_axis, host_axis, principal, mode, "
                "remaining_requests, remaining_packets, remaining_auth, "
                "remaining_bytes, ceiling_json, floor_json, refill_json, "
                "last_refill) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (key, dims.get("engagement"), dims.get("entry_partition"),
                 dims.get("exit_id"), dims.get("range_axis"),
                 dims.get("host_axis"), dims.get("principal"), "normal",
                 *[policy[d]["ceiling"] for d in DIMS],
                 _policy_json({d: policy[d]["ceiling"] for d in DIMS}),
                 _policy_json({d: policy[d]["floor"] for d in DIMS}),
                 _policy_json({d: policy[d]["refill_per_epoch"] for d in DIMS}),
                 now))
            return
        # Constitution changed → policy re-stamp; balances carry.
        self.conn.execute(
            "UPDATE nodes SET ceiling_json=?, floor_json=?, refill_json=? "
            "WHERE node_key=?",
            (_policy_json({d: policy[d]["ceiling"] for d in DIMS}),
             _policy_json({d: policy[d]["floor"] for d in DIMS}),
             _policy_json({d: policy[d]["refill_per_epoch"] for d in DIMS}),
             key))

    # --- admission (read-only preflight, §3 step 2) --------------------------

    def admit_vector(self, decl: dict, dims: dict, *,
                     policy: dict, epoch_s: float,
                     max_single: dict, now: float | None = None,
                     engagement: str | None = None) -> dict:
        """READ-ONLY admission routing. Returns one of:
        ``{"decision": "admit", ...}`` / ``{"decision": "enqueue",
        "shortfall": {...}}`` / ``{"decision": "reject", ...}`` /
        ``{"decision": "unknown", "fail_closed": True, ...}``.

        Never writes: preflight projects accrual in read-only mode and the
        routing decision stands even though nothing is persisted yet."""
        return self._admit_impl(decl, dims, policy=policy, epoch_s=epoch_s,
                                max_single=max_single, now=now,
                                engagement=engagement)

    def _admit_impl(self, decl, dims, *, policy, epoch_s, max_single, now,
                    engagement) -> dict:
        now = now if now is not None else time.time()
        decl = {d: decl.get(d) for d in DIMS}
        levels = self._levels(dims)
        try:
            rows = []
            verdict = "admit"
            shortfall = {}
            deficit = {}
            short_levels = []
            never_fit = []
            for label, ldims in levels:
                key = _node_key(engagement if label != "global" else engagement,
                                ldims.get("entry_partition"),
                                ldims.get("exit_id"), ldims.get("range_axis"),
                                ldims.get("host_axis"), ldims.get("principal"))
                node = self._node_row(key)
                balances = (self._accrue(node, now, epoch_s)
                            if node is not None
                            else {d: {"remaining": policy[d]["ceiling"],
                                      "ceiling": policy[d]["ceiling"],
                                      "rate": policy[d]["refill_per_epoch"],
                                      "floor": policy[d]["floor"]} for d in DIMS})
                rows.append((label, key, node, balances))
                if self._never_fits(balances, decl, max_single):
                    never_fit.append(label)
                    continue
                for d in DIMS:
                    if decl[d] is None:
                        continue
                    if balances[d]["remaining"] < decl[d]:
                        if verdict == "admit":
                            shortfall = {
                                d: round(balances[d]["ceiling"]
                                         - balances[d]["remaining"], 6)
                                for d in DIMS
                                if decl[d] is not None
                                and balances[d]["remaining"] < decl[d]}
                            verdict = "enqueue"
                        short_levels.append(label)
                        deficit[d] = deficit.get(d, 0.0) + round(
                            decl[d] - balances[d]["remaining"], 6)
            if never_fit:
                return {"decision": "reject", "level": never_fit,
                        "declared": decl}
            if verdict == "enqueue":
                cover = self._released_reserve_cover(
                    deficit, dims={**dims, "engagement": engagement},
                    engagement=engagement, now=now)
                if cover is not None:
                    return {"decision": "admit", "reserve_cover": cover,
                            "projected": {label: balances
                                          for label, _, _, balances in rows}}
                return {"decision": "enqueue", "shortfall": shortfall,
                        "declared": decl}
            return {"decision": "admit",
                    "projected": {label: balances for label, _, _, balances in rows}}
        except Exception as exc:
            logging.getLogger(__name__).debug(
                "swallowed exception in admit_vector", exc_info=True)
            return {"decision": "unknown", "fail_closed": True,
                    "known": False, "reason": f"store unreadable: {exc!r}"}

    # --- atomic cascade debit + emission append (§3 step 4, §5) --------------

    def debit_vector(self, decl, dims, *, tool: str, policy, epoch_s,
                     max_single, now=None,
                     engagement=None, agent_id=None, estimator=None,
                     declared_basis="estimated", emit_meta=None) -> dict:
        """The atomic cascade: accrue + check ALL levels, then EITHER debit
        every level AND append the emission row (same transaction) or roll
        back everything. Fail-closed: store errors hard-fail the debit."""
        now = now if now is not None else time.time()
        decl = {d: decl.get(d) for d in DIMS}
        dims = dict(dims)
        dims.setdefault("engagement", engagement)
        credit_line = any(decl[d] is None for d in DIMS)
        declared_basis = "credit_line" if credit_line else declared_basis
        for d in DIMS:
            v = decl[d]
            if v is not None and (v > policy[d]["ceiling"]
                                  or v > max_single.get(d, v)):
                # never-fit is not a waiting problem (enqueue would never
                # satisfy it) — refuse here too, not just at preflight.
                return {"committed": False, "decision": "reject",
                        "level": "config", "tool": tool,
                        "shortfall_dims": [d],
                        "reason": f"declared {d}={v} exceeds ceiling "
                                  f"{policy[d]['ceiling']}/max_single "
                                  f"{max_single.get(d)} — raise the "
                                  "constitution; this can never fit"}
        try:
            c = self.conn
            c.execute("BEGIN IMMEDIATE")
            try:
                traces = []
                debit_vals = {d: decl[d] for d in DIMS if decl[d] is not None}
                deficit: dict[str, float] = {}
                short_levels: list[str] = []
                for label, ldims in self._levels(dims):
                    key = _node_key(engagement, ldims.get("entry_partition"),
                                    ldims.get("exit_id"), ldims.get("range_axis"),
                                    ldims.get("host_axis"), ldims.get("principal"))
                    if self._node_row(key) is None:
                        self._upsert_node(key, {**dims, **ldims}, policy, now)
                    node = self._node_row(key)
                    balances = self._accrue(node, now, epoch_s)
                    updates = {}
                    for d in DIMS:
                        if d not in debit_vals:
                            continue
                        avail = balances[d]["remaining"]
                        if avail < debit_vals[d]:
                            deficit[d] = deficit.get(d, 0.0) + round(
                                debit_vals[d] - avail, 6)
                            short_levels.append(label)
                            updates[d] = round(avail - min(avail, decl[d]), 6)
                        else:
                            updates[d] = round(avail - decl[d], 6)
                    if updates:
                        c.execute(
                            "UPDATE nodes SET remaining_requests=?, "
                            "remaining_packets=?, remaining_auth=?, "
                            "remaining_bytes=?, last_refill=? WHERE node_key=?",
                            (updates.get(DIMS[0],
                                         balances[DIMS[0]]["remaining"]),
                             updates.get(DIMS[1],
                                         balances[DIMS[1]]["remaining"]),
                             updates.get(DIMS[2],
                                         balances[DIMS[2]]["remaining"]),
                             updates.get(DIMS[3],
                                         balances[DIMS[3]]["remaining"]),
                             now, key))
                    traces.append({"level": label, "node_key": key,
                                   "balances_after": {
                                       d: (updates[d] if d in updates
                                           else balances[d]["remaining"])
                                       for d in DIMS}})
                reserve_cover = None
                if deficit:
                    reserve_cover = self._released_reserve_cover(
                        deficit, dims=dims, engagement=engagement, now=now)
                    if reserve_cover is None:
                        c.rollback()
                        return {"committed": False, "decision": "enqueue",
                                "level": short_levels[0],
                                "shortfall_dims": sorted(deficit),
                                "q_hint": "enqueue",
                                "reason": f"budget_short@{short_levels[0]}"}
                    self._consume_reserve(reserve_cover["token_id"],
                                          reserve_cover["consume"])
                cur = c.execute(
                    "INSERT INTO emissions (ts, tool, engagement, agent_id, "
                    "entry_partition, exit_id, range_axis, host_axis, principal, "
                    "declared_json, declared_basis, estimator, actual_json, "
                    "response_class, signals_json, posture_json, job_ref, "
                    "queue_ref, budget_phase, drift, meter_state) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,"
                    "?,?,NULL,NULL,?,?,NULL,NULL,?,0,?)",
                    (now, tool, engagement, agent_id or "0",
                     dims.get("entry_partition"), dims.get("exit_id"),
                     dims.get("range_axis"), dims.get("host_axis"),
                     dims.get("principal"), json.dumps(decl, sort_keys=True),
                     declared_basis, estimator,
                     _opt_json((emit_meta or {}).get("signals")),
                     _opt_json((emit_meta or {}).get("posture")),
                     (emit_meta or {}).get("budget_phase"),
                     # §7.1 lifecycle: the draw opens in HOLD; METER starts
                     # at the first metered actual; measured (non-draw)
                     # emissions carry no lifecycle.
                     "hold" if credit_line else None,
                     ))
                emission_id = int(cur.lastrowid)
                c.commit()
                out = {"committed": True, "decision": "debit",
                       "emission_id": emission_id, "tool": tool,
                       "traces": traces, "credit_line": credit_line}
                if reserve_cover is not None:
                    out["reserve_cover"] = reserve_cover
                return out
            except Exception:
                try:
                    c.rollback()
                except sqlite3.Error:
                    logging.getLogger(__name__).debug(
                        "swallowed rollback error in debit_vector", exc_info=True)
                raise
        except Exception as exc:
            logging.getLogger(__name__).debug(
                "swallowed exception in debit_vector (fail-closed)", exc_info=True)
            return {"committed": False, "decision": "unknown",
                    "fail_closed": True, "known": False,
                    "reason": "store error during debit — dispatch refused "
                              "(fail-closed; see budget store logs)"}

    # --- queue (§7.2/§7.3, Phase A skeleton) ---------------------------------

    def enqueue_item(self, *, tool: str, arguments: dict, decl: dict,
                     dims: dict, reason: str, agent_id: str,
                     engagement: str | None, priority: int = 0,
                     ttl_hours: float = 24.0,
                     no_reenqueue: bool = False,
                     now: float | None = None) -> str:
        now = now if now is not None else time.time()
        qid = f"q-{uuid.uuid4().hex[:12]}"
        self.conn.execute(
            "INSERT INTO queue_items (qid, tool, arguments_json, declared_json, "
            "dims_json, reason, status, priority, agent_id, engagement, "
            "no_reenqueue, requested, expires_at) VALUES (?,?,?,?,?,?,"
            "'queued',?,?,?,?,?,?)",
            (qid, tool, json.dumps(arguments or {}, sort_keys=True),
             json.dumps({d: (decl or {}).get(d) for d in DIMS}, sort_keys=True),
             json.dumps(dims, sort_keys=True), reason, priority,
             agent_id, engagement, 1 if no_reenqueue else 0, now,
             now + ttl_hours * 3600.0))
        self.conn.commit()
        return qid

    def sweep_expired(self, now: float | None = None) -> int:
        """Past-TTL queued items → cancelled (§7.2: launched items are never
        cancelled by TTL — only their fleet unit / budget path governs)."""
        now = now if now is not None else time.time()
        cur = self.conn.execute(
            "UPDATE queue_items SET status='cancelled', "
            "notes_json='expires_at passed' WHERE status='queued' "
            "AND expires_at < ?", (now,))
        self.conn.commit()
        return int(cur.rowcount)

    def due_items(self, *, now: float | None = None,
                  axis: str | None = None, limit: int = 64) -> list[dict]:
        """The backlog, drain-order: due (not expired), FIFO by
        (priority DESC, requested ASC) — the operator's tick reads this."""
        now = now if now is not None else time.time()
        sql = ("SELECT * FROM queue_items WHERE status='queued' AND "
               "expires_at >= ?")
        if axis:
            sql += " AND (dims_json LIKE ? OR dims_json LIKE ?)"
        sql += " ORDER BY priority DESC, requested ASC LIMIT ?"
        params: list[Any] = [now]
        if axis:
            params += [f"%\"host_axis\": \"{axis}\"%", f"%\"range_axis\": \"{axis}\"%"]
        params.append(limit)
        return [dict(r) for r in self.conn.execute(sql, params)]

    def list_items(self, *, state: str | None = None, tool: str | None = None,
                   limit: int = 64) -> list[dict]:
        """Observability listing (REPL): any state, optional tool substring —
        newest first (due_items is drain-order; this is history-order)."""
        sql = "SELECT * FROM queue_items"
        where, params = [], []
        if state:
            where.append("status=?")
            params.append(state)
        if tool:
            where.append("tool LIKE ?")
            params.append(f"%{tool}%")
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY requested DESC LIMIT ?"
        params.append(limit)
        return [dict(r) for r in self.conn.execute(sql, params)]

    def queued_position(self, qid: str) -> int | None:
        """1-based standing of a queued item under the drain's EXACT order
        (priority DESC, requested ASC — mirroring budget_queue_status and
        operator_tick's launch selection), or None when the item is not
        currently queued (drained/expired/cancelled)."""
        me = self.conn.execute(
            "SELECT priority, requested FROM queue_items "
            "WHERE qid=? AND status='queued'", (qid,)).fetchone()
        if me is None:
            return None
        (ahead,) = self.conn.execute(
            "SELECT COUNT(*) FROM queue_items WHERE status='queued' AND "
            "(priority > ? OR (priority = ? AND requested < ?))",
            (me["priority"], me["priority"], me["requested"])).fetchone()
        return int(ahead) + 1

    def bind_item(self, qid: str, job_ref: str) -> None:
        cur = self.conn.execute(
            "UPDATE queue_items SET status='launched', job_ref=? WHERE "
            "qid=? AND status IN ('queued','launching')", (job_ref, qid))
        self.conn.commit()
        if cur.rowcount == 0:
            logging.getLogger(__name__).debug(
                "swallowed exception in bind_item (stale bind)", exc_info=True)

    def finish_item(self, qid: str) -> None:
        self.conn.execute(
            "UPDATE queue_items SET status='finished' WHERE qid=?", (qid,))
        self.conn.commit()

    def cancel_item(self, qid: str, note: str = "cancelled") -> None:
        self.conn.execute(
            "UPDATE queue_items SET status='cancelled', notes_json=? "
            "WHERE qid=?", (note, qid))
        self.conn.commit()

    def get_item(self, qid: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM queue_items WHERE qid=?", (qid,)).fetchone()
        return dict(row) if row is not None else None

    # --- reserves (§9) --------------------------------------------------------
    # Operator-minted funds for engagement backlog. Mint/release are
    # REPL-only (operator-lane config authority, §8.2); consumption is
    # free-form once released, enforced here by matching.

    def mint_reserve(self, *, partition: str, dims: dict, max_vector: dict,
                     tag: str | None = None, ttl_hours: float | None = None,
                     engagement: str | None = None,
                     note: str | None = None, now: float | None = None) -> dict:
        now = now if now is not None else time.time()
        token_id = "resv:" + secrets.token_hex(16)
        dims = json.loads(json.dumps(dims or {}), parse_float=float)
        max_vector = {d: float(max_vector.get(d) or 0.0) for d in DIMS}
        if all(v == 0.0 for v in max_vector.values()):
            raise ValueError("reserve max_vector covers nothing")
        remaining = dict(max_vector)
        ttl = (now + ttl_hours * 3600.0) if ttl_hours else None
        self.conn.execute(
            "INSERT INTO reserves (token_id, engagement, partition, dims_json,"
            " tag, max_vector_json, remaining_json, ttl_expiry, released,"
            " note, ts) VALUES (?,?,?,?,?,?,?,?,NULL,?,?)",
            (token_id, engagement, partition,
             json.dumps(dims, sort_keys=True), tag,
             json.dumps(max_vector, sort_keys=True),
             json.dumps(remaining, sort_keys=True), ttl, note, now))
        self.conn.commit()
        return {"token_id": token_id, "partition": partition,
                "frozen": True, "max_vector": max_vector,
                "ttl_expiry": ttl}

    def release_reserve(self, token_id: str, *, release: bool = True,
                        now: float | None = None) -> dict | None:
        now = now if now is not None else time.time()
        cur = self.conn.execute(
            "UPDATE reserves SET released=? WHERE token_id=?",
            (now if release else None, token_id))
        self.conn.commit()
        if cur.rowcount == 0:
            return None
        row = self.conn.execute(
            "SELECT token_id, released, remaining_json FROM reserves WHERE "
            "token_id=?", (token_id,)).fetchone()
        out = dict(row)
        out["remaining"] = json.loads(row["remaining_json"])
        out.pop("remaining_json", None)
        return out

    def list_reserves(self, *, engagement: str | None = None,
                      include_expired: bool = True) -> list[dict]:
        sql = "SELECT * FROM reserves"
        where = []
        if engagement:
            where.append("engagement=?")
            params: list = [engagement]
        else:
            params = []
        if not include_expired:
            where.append(
                "(ttl_expiry IS NULL OR ttl_expiry > ?)")
            params.append(time.time())
        sql += (" WHERE " + " AND ".join(where)) if where else ""
        sql += " ORDER BY ts DESC"
        rows = [dict(r) for r in self.conn.execute(sql, params)]
        for r in rows:
            r["dims"] = json.loads(r.pop("dims_json") or "{}")
            r["max_vector"] = json.loads(r.pop("max_vector_json") or "{}")
            r["remaining"] = json.loads(r.pop("remaining_json") or "{}")
        return rows

    def sweep_reserves(self, now: float | None = None) -> int:
        now = now if now is not None else time.time()
        cur = self.conn.execute(
            "DELETE FROM reserves WHERE ttl_expiry IS NOT NULL AND "
            "ttl_expiry <= ?", (now,))
        self.conn.commit()
        return cur.rowcount

    _RESERVE_DIM_COLS = ("entry_partition", "exit_id", "range_axis",
                         "host_axis", "principal")

    def _reserve_match(self, r: sqlite3.Row, *, dims: dict,
                       engagement: str | None) -> bool:
        want_eng = r["engagement"]
        if want_eng is not None and want_eng != (engagement
                                                 or dims.get("engagement")):
            return False
        tdims = json.loads(r["dims_json"] or "{}")
        if not isinstance(tdims, dict):
            return False
        for col in self._RESERVE_DIM_COLS:
            want = tdims.get(col)
            if want is not None and dims.get(col) != want:
                return False
        return True

    _WILD_TAGS_ENV = "BUDGET_RESERVE_WILD_TAGS"

    @staticmethod
    def _wild_tags() -> tuple[str, ...]:
        """§9/L2: released-token tags that may cover ANY deficit
        (exact-dims OR tag-wildcard, config-declared). Env override first,
        else the constitution's ``reserve_tag_wildcards``. Resolution
        failure ⇒ NO wildcards (stricter, never looser)."""
        raw = os.getenv(RationStore._WILD_TAGS_ENV, "").strip()
        if raw:
            return tuple(t.strip().lower() for t in raw.split(",") if t.strip())
        try:
            from utils.ration import constitution as _constitution
            return tuple(
                t.strip().lower() for t in
                (_constitution().reserve_tag_wildcards or ()) if t and t.strip())
        except Exception:
            return ()

    def _released_reserve_cover(self, deficit: dict, *, dims: dict,
                                engagement: str | None,
                                now: float) -> dict | None:
        if not deficit:
            return None
        wild = self._wild_tags()
        for r in self.conn.execute(
                "SELECT * FROM reserves WHERE released IS NOT NULL AND"
                " (ttl_expiry IS NULL OR ttl_expiry > ?) ORDER BY ts",
                (now,)):
            # L2: a released token whose operator tag is in the config's
            # wildcard list covers whatever it holds irrespective of dims —
            # but engagement binding STILL applies (never funds a sibling
            # engagement from this one's reserve).
            tagged_wild = (r["tag"] or "").strip().lower() in wild
            if not tagged_wild and not self._reserve_match(
                    r, dims=dims, engagement=engagement):
                continue
            # Engagement binding applies to wildcards too: a wildcard tag
            # skips the DIMS match, never the engagement one.
            if tagged_wild and r["engagement"] is not None and \
                    r["engagement"] != (engagement
                                        or dims.get("engagement")):
                continue
            remaining = json.loads(r["remaining_json"] or "{}")
            consume = {d: amt for d, amt in deficit.items()}
            if not all(float(remaining.get(d) or 0.0) >= amt
                       for d, amt in consume.items()):
                continue
            return {"token_id": r["token_id"], "consume": consume,
                    "wildcard_tag": r["tag"] if tagged_wild else None}
        return None

    def _consume_reserve(self, token_id: str, deficit: dict) -> None:
        row = self.conn.execute(
            "SELECT remaining_json FROM reserves WHERE token_id=?",
            (token_id,)).fetchone()
        if row is None:
            return
        remaining = json.loads(row["remaining_json"] or "{}")
        for d, amt in deficit.items():
            remaining[d] = round(float(remaining.get(d) or 0.0) - amt, 6)
        self.conn.execute(
            "UPDATE reserves SET remaining_json=? WHERE token_id=?",
            (json.dumps(remaining, sort_keys=True), token_id))

    # --- debit compensation (§11.2 note) --------------------------------------
    # A duplicate/refused fleet verdict reverses its cascade debit exactly;
    # the emission row keeps drift=2 + a note so the ledger reads honestly.

    def refund_node(self, node_key: str, refund: dict) -> None:
        """Pay a declared vector back to one node exactly (compensation,
        §11.2). Refunds only non-None dims; never credits a missing node."""
        row = self._node_row(node_key)
        if row is None:
            return
        rem_col = {"requests": "remaining_requests",
                   "packets": "remaining_packets",
                   "auth_events": "remaining_auth",
                   "bytes": "remaining_bytes"}
        sets, vals = [], []
        for d in DIMS:
            if refund.get(d) is None:
                continue
            sets.append(f"{rem_col[d]}=?")
            vals.append(round(float(row[rem_col[d]] or 0.0)
                              + float(refund[d]), 6))
        if not sets:
            return
        vals.append(node_key)
        self.conn.execute(
            f"UPDATE nodes SET {', '.join(sets)} WHERE node_key=?", vals)
        self.conn.commit()

    def stamp_compensation(self, emission_id: int, why: str) -> None:
        """drift=2 stamp: the debit was reversed after the fact (duplicate/
        refused dispatch). Untouched for rows already reconciled."""
        self.conn.execute(
            "UPDATE emissions SET drift=2, drift_note=? WHERE id=? AND "
            "actual_json IS NULL",
            (f"compensated:{why}", emission_id))
        self.conn.commit()

    # --- draw lifecycle (§7.1) -------------------------------------------------
    # A credit-line draw is the emission row it minted: open while
    # actual_json IS NULL. poll reconcile closes or reconciles it; this
    # sweep is the backstop.

    def open_draws(self, *, engagement: str | None = None,
                   limit: int = 50) -> list[dict]:
        # open = credit-line, never true-up'd, not compensated (drift=2 —
        # the debit was reversed) and not already honest-closed ('closed…'
        # note: poll-release or sweep backstop). §7.1 lifecycle: a draw is
        # open while still in HOLD (waiting to start) or METER (billing as
        # consumed) — exhausted (mid-flight credit death) and expired
        # (hold TTL) draws are closed history too. Closed draws are history.
        sql = ("SELECT id, tool, ts, engagement, declared_json,"
               " declared_basis, job_ref, drift_note, meter_state FROM"
               " emissions WHERE"
               " declared_basis='credit_line' AND actual_json IS NULL AND"
               " (meter_state IS NULL OR meter_state IN ('hold','metering'))"
               " AND (drift IS NULL OR drift=0) AND"
               " (drift_note IS NULL OR drift_note NOT LIKE 'closed%')")
        params: list = []
        if engagement:
            sql += " AND engagement=?"
            params.append(engagement)
        sql += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        rows = [dict(r) for r in self.conn.execute(sql, params)]
        for r in rows:
            r["declared"] = json.loads(r.pop("declared_json") or "{}")
            r["emission_id"] = r.pop("id")
        return rows

    def close_draw(self, emission_id: int, note: str, *,
                   meter_state: str | None = None) -> bool:
        cur = self.conn.execute(
            "UPDATE emissions SET drift_note=?, meter_state=COALESCE(?, "
            "meter_state) WHERE id=? AND"
            " actual_json IS NULL AND declared_basis='credit_line'",
            (note, meter_state, emission_id))
        self.conn.commit()
        return cur.rowcount > 0

    def bind_emission_job(self, emission_id: int, job_ref: str) -> bool:
        cur = self.conn.execute(
            "UPDATE emissions SET job_ref=? WHERE id=?",
            (job_ref, emission_id))
        self.conn.commit()
        return cur.rowcount > 0

    def draws_for_job(self, job_ref: str) -> list[dict]:
        rows = [dict(r) for r in self.conn.execute(
            "SELECT id, tool, declared_json, declared_basis, engagement,"
            " host_axis, drift_note, meter_state, job_ref FROM emissions"
            " WHERE job_ref=? AND"
            " declared_basis='credit_line' AND actual_json IS NULL AND"
            " (meter_state IS NULL OR meter_state IN ('hold','metering'))"
            " AND (drift IS NULL OR drift != 2) AND"
            " (drift_note IS NULL OR drift_note NOT LIKE 'closed%')",
            (job_ref,))]
        for r in rows:
            r["declared"] = json.loads(r.pop("declared_json") or "{}")
            r["emission_id"] = r.pop("id")
        return rows

    # --- credit-line lifecycle (§7.1 v0.3): draw → HOLD → METER → SETTLE ----

    _METER_OPEN_STATES = (None, "hold", "metering")

    def meter_draw(self, emission_id: int, target: dict, *,
                   policy: dict, epoch_s: float,
                   now: float | None = None,
                   settle: bool = False, settle_note: str = "") -> dict | None:
        """§7.1 METER + §5 debit-direction rule: the cumulative charged
        target per dim is ``max(L0 declared, L1 actual)`` — actuals may run
        UNDER declaration (nmap retransmits, redirect chains) and never
        refund; overage charges as consumed. Drift either direction is a
        logged signal (notes; the >1.05× overage also trips ``drift=1`` at
        :meth:`reconcile_emission`).

        Idempotent: the row's ``metered_json`` carries the cumulative
        charged total, so repeat polls charge only the delta. Any cascade
        level unable to pay the delta mid-flight stamps the draw
        ``meter_state='exhausted'`` (credit-line rows ONLY — the tool must
        END: non-resumable crawls end, resumables pause via their own
        status/cancel twins) and charges nothing that tick; the NEXT poll
        with a higher target retries honestly (cumulative idempotence).
        Measured (non-draw) emissions that run short leave the lifecycle
        untouched but report the shortfall — they were already fully
        charged at debit time."""
        now = now if now is not None else time.time()
        row = self.conn.execute(
            "SELECT * FROM emissions WHERE id=?", (emission_id,)).fetchone()
        if row is None:
            return None
        declared = json.loads(row["declared_json"] or "{}")
        dims = {"engagement": row["engagement"],
                "entry_partition": row["entry_partition"],
                "exit_id": row["exit_id"], "range_axis": row["range_axis"],
                "host_axis": row["host_axis"], "principal": row["principal"]}
        is_credit = row["declared_basis"] == "credit_line"
        metered = (json.loads(row["metered_json"])
                   if row["metered_json"] else None)
        if not isinstance(metered, dict):
            # first meter: what the debit already charged in advance
            metered = {d: (float(declared[d])
                           if declared.get(d) is not None else 0.0)
                       for d in DIMS}
        cum = {d: round(float(metered.get(d) or 0.0), 6) for d in DIMS}
        charge: dict[str, float] = {}
        for d in DIMS:
            decl_v = declared.get(d)
            act_v = target.get(d)
            tgt = 0.0
            if decl_v is not None:
                tgt = float(decl_v)
            if act_v is not None:
                try:
                    tgt = max(tgt, float(act_v))
                except (TypeError, ValueError):
                    pass          # non-numeric actual never invents a charge
            delta = round(tgt - cum[d], 6)
            if delta > 0:
                charge[d] = delta
        rem_col = {"requests": "remaining_requests",
                   "packets": "remaining_packets",
                   "auth_events": "remaining_auth",
                   "bytes": "remaining_bytes"}
        if not charge:
            self.conn.execute(
                "UPDATE emissions SET metered_json=?, meter_state=CASE WHEN"
                " meter_state='hold' THEN 'metering' ELSE meter_state END"
                " WHERE id=?", (json.dumps(cum, sort_keys=True), emission_id))
            if settle and is_credit and \
                    row["meter_state"] not in ("exhausted", "settled",
                                               "expired"):
                # SETTLE at the release point even when the terminal true-up
                # charges nothing (actuals ran under the declared advance).
                self.conn.execute(
                    "UPDATE emissions SET meter_state='settled', "
                    "drift_note=COALESCE(NULLIF(?, ''), drift_note) WHERE"
                    " id=?", (settle_note, emission_id))
            self.conn.commit()
            return {"emission_id": emission_id, "charged": False,
                    "exhausted": False, "ledger_short": False,
                    "settled": bool(settle and is_credit),
                    "metered": cum, "meter_state": self.conn.execute(
                        "SELECT meter_state FROM emissions WHERE id=?",
                        (emission_id,)).fetchone()[0]}
        c = self.conn
        c.execute("BEGIN IMMEDIATE")
        try:
            traces, deficit, short_levels = [], {}, []
            for label, ldims in self._levels(dims):
                key = _node_key(row["engagement"], ldims.get("entry_partition"),
                                ldims.get("exit_id"), ldims.get("range_axis"),
                                ldims.get("host_axis"), ldims.get("principal"))
                self._upsert_node(key, {**dims, **ldims}, policy, now)
                node = self._node_row(key)
                balances = self._accrue(node, now, epoch_s)
                updates = {}
                for d in DIMS:
                    if d not in charge:
                        continue
                    avail = balances[d]["remaining"]
                    if avail < charge[d]:
                        deficit[d] = deficit.get(d, 0.0) + round(
                            charge[d] - avail, 6)
                        short_levels.append(label)
                    updates[d] = round(
                        max(0.0, avail) - min(max(0.0, avail), charge[d]), 6)
                if updates:
                    c.execute(
                        "UPDATE nodes SET remaining_requests=?, "
                        "remaining_packets=?, remaining_auth=?, "
                        "remaining_bytes=?, last_refill=? WHERE node_key=?",
                        (updates.get(DIMS[0], balances[DIMS[0]]["remaining"]),
                         updates.get(DIMS[1], balances[DIMS[1]]["remaining"]),
                         updates.get(DIMS[2], balances[DIMS[2]]["remaining"]),
                         updates.get(DIMS[3], balances[DIMS[3]]["remaining"]),
                         now, key))
                traces.append({"level": label, "node_key": key,
                               "charged": {d: updates.get(d, 0.0)
                                           for d in DIMS if d in charge}})
            if deficit:
                try:
                    c.rollback()
                except sqlite3.Error:
                    logging.getLogger(__name__).debug(
                        "swallowed rollback error in meter_draw", exc_info=True)
                if is_credit and row["meter_state"] not in \
                        ("settled", "expired", "exhausted"):
                    note = (f"meter exhausted mid-flight: "
                            f"{sorted(deficit)} short at level "
                            f"{short_levels[0]} — the tool must END "
                            "(non-resumable crawls end; resumables pause "
                            "via their own status/cancel twins)")
                    self.conn.execute(
                        "UPDATE emissions SET meter_state='exhausted', "
                        "metered_json=?, drift_note=? WHERE id=?",
                        (json.dumps(cum, sort_keys=True), note, emission_id))
                    self.conn.commit()
                return {"emission_id": emission_id, "charged": False,
                        "exhausted": is_credit,
                        "ledger_short": bool(deficit),
                        "shortfall_dims": sorted(deficit),
                        "level": short_levels[0], "metered": cum}
            cumulative = dict(cum)
            for d in charge:
                cumulative[d] = round(cumulative[d] + charge[d], 6)
            c.execute(
                "UPDATE emissions SET metered_json=?, meter_state=CASE WHEN"
                " meter_state='hold' THEN 'metering' ELSE meter_state END"
                " WHERE id=?",
                (json.dumps(cumulative, sort_keys=True), emission_id))
            if settle and is_credit and row["meter_state"] not in (
                    "exhausted", "settled", "expired"):
                # §7.1 SETTLE: the true-up is complete — the remainder beyond
                # the metered total is released (nothing further debits this
                # draw; the lifecycle closes).
                self.conn.execute(
                    "UPDATE emissions SET meter_state='settled', "
                    "drift_note=COALESCE(NULLIF(?, ''), drift_note) WHERE"
                    " id=?", (settle_note, emission_id))
            c.commit()
            return {"emission_id": emission_id, "charged": True,
                    "charged_dims": charge, "metered": cumulative,
                    "settled": bool(settle and is_credit and
                                    row["meter_state"] not in
                                    ("exhausted", "settled", "expired")),
                    "meter_state": self.conn.execute(
                        "SELECT meter_state FROM emissions WHERE id=?",
                        (emission_id,)).fetchone()[0],
                    "traces": traces}
        except Exception:
            try:
                c.rollback()
            except sqlite3.Error:
                logging.getLogger(__name__).debug(
                    "swallowed rollback error in meter_draw", exc_info=True)
            raise

    # --- principals (§4.3, Phase A skeleton) ---------------------------------

    def touch_principal(self, *, host_axis: str, principal: str,
                        engagement: str | None, now: float | None = None) -> None:
        now = now if now is not None else time.time()
        self.conn.execute(
            "INSERT INTO principals (engagement, host_axis, principal, "
            "first_seen, last_seen) VALUES (?,?,?,?,?) ON CONFLICT"
            "(engagement, host_axis, principal) DO UPDATE SET last_seen=?",
            (engagement, host_axis, principal, now, now, now))
        self.conn.commit()

    def distinct_principals(self, *, host_axis: str, now: float,
                            window_s: float) -> int:
        cur = self.conn.execute(
            "SELECT COUNT(DISTINCT principal) FROM principals WHERE "
            "host_axis=? AND last_seen > ?", (host_axis, now - window_s))
        return int(cur.fetchone()[0] or 0)

    # --- tripwire seeds (§8, Phase C consumer) -------------------------------

    def upsert_tripwire(self, tool: str, actual: dict, now: float | None = None) -> None:
        """Moving average true-up per dim. `actual` dims = observed cost;
        unknown dims ignored. Never raises (tripwire learning must not break
        dispatch)."""
        now = now if now is not None else time.time()
        per = {}
        row = self.conn.execute(
            "SELECT per_dim_json, samples FROM tripwire_estimates WHERE tool=?",
            (tool,)).fetchone()
        samples = 0
        if row is not None:
            samples = int(row["samples"] or 0)
            per = {d: v for d, v in (json.loads(row["per_dim_json"] or "{}")).items()
                   if d in DIMS}
        for d, v in actual.items():
            if d in DIMS and v is not None:
                old = per.get(d)
                per[d] = (v if old is None
                          else (old * samples + float(v)) / (samples + 1))
        self.conn.execute(
            "INSERT INTO tripwire_estimates (tool, per_dim_json, samples, "
            "updated) VALUES (?,?,?,?) ON CONFLICT (tool) DO UPDATE SET "
            "per_dim_json=?, samples=?, updated=?",
            (tool, json.dumps(per, sort_keys=True), samples + 1, now,
             json.dumps(per, sort_keys=True), samples + 1, now))
        self.conn.commit()

    # --- emissions + L1 reconcile (§10) --------------------------------------

    def record_emission(self, *, ts, tool, engagement, agent_id, dims: dict,
                        declared: dict, declared_basis: str,
                        estimator: str | None, actual: dict | None = None,
                        response_class: str | None = None,
                        emit_meta: dict | None = None) -> int:
        cur = self.conn.execute(
            "INSERT INTO emissions (ts, tool, engagement, agent_id, "
            "entry_partition, exit_id, range_axis, host_axis, principal, "
            "declared_json, declared_basis, estimator, actual_json, "
            "response_class, signals_json, posture_json, job_ref, queue_ref, "
            "budget_phase, drift) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)",
            (ts, tool, engagement, agent_id,
             dims.get("entry_partition"), dims.get("exit_id"),
             dims.get("range_axis"), dims.get("host_axis"), dims.get("principal"),
             json.dumps({d: (declared or {}).get(d) for d in DIMS},
                        sort_keys=True), declared_basis, estimator,
             _opt_json(actual), response_class,
             _opt_json((emit_meta or {}).get("signals")),
             _opt_json((emit_meta or {}).get("posture")),
             (emit_meta or {}).get("job_ref"), (emit_meta or {}).get("queue_ref"),
             (emit_meta or {}).get("budget_phase")))
        self.conn.commit()
        return int(cur.lastrowid)

    def reconcile_emission(self, emission_id: int, actual: dict, *,
                           response_class: str | None = None,
                           signals: dict | None = None,
                           drift_note: str | None = None,
                           drift: bool | None = None) -> dict | None:
        """L1 true-up. Drift rule (§15 hook): actual > declared on any
        DECLARED dim trips. Retro-corrections APPEND (drift stamps); the
        declared vector is never rewritten."""
        row = self.conn.execute(
            "SELECT declared_json, declared_basis, drift, engagement, "
            "host_axis, ts FROM emissions WHERE id=?",
            (emission_id,)).fetchone()
        if row is None:
            return None
        declared = json.loads(row["declared_json"] or "{}")
        host_axis = row["host_axis"]
        engagement = row["engagement"]
        ts = float(row["ts"])
        tripped = any(
            declared.get(d) is not None and actual.get(d) is not None
            and float(actual[d]) > float(declared[d]) * 1.05 + 1e-9
            for d in DIMS)
        self.conn.execute(
            "UPDATE emissions SET actual_json=?, response_class=COALESCE(?,"
            " response_class), signals_json=COALESCE(?, signals_json), "
            "drift=CASE WHEN ? THEN 1 ELSE drift END, drift_note=? WHERE id=?",
            (json.dumps(actual, sort_keys=True), response_class,
             _opt_json(signals), 1 if (drift or tripped) else 0,
             drift_note, emission_id))
        self.conn.commit()
        return {"emission_id": emission_id, "tripped": tripped or bool(drift),
                "declared": declared, "actual": actual,
                "engagement": engagement, "host_axis": host_axis, "ts": ts}

    def window_spend(self, host_axis: str, *, engagement: str | None = None,
                     before_ts: float | None = None,
                     window_seconds: float = 300.0) -> int:
        """Emissions (dispatches) counted on a host in the trailing window
        ending at before_ts (default: strictly before the given ts — the
        observation emission itself is excluded). §8.3 onset/clean-run
        counting basis."""
        before_ts = before_ts if before_ts is not None else time.time()
        q = ("host_axis=? AND ts < ? AND ts >= ?")
        params: list[Any] = [host_axis, before_ts, before_ts - window_seconds]
        if engagement is not None:
            q += " AND engagement=?"
            params.append(engagement)
        cur = self.conn.execute(f"SELECT COUNT(*) n FROM emissions WHERE {q}",
                                params)
        return int(cur.fetchone()["n"])

    def clean_run(self, host_axis: str, *, engagement: str | None = None,
                  limit: int = 64) -> int:
        """Consecutive reaction-free emissions on a host, counting back from
        the newest (reaction = response_class set + not quiet). Capped. The
        §8.3 lower-bound source: a sustained clean run raises ``lower``."""
        q = "SELECT response_class FROM emissions WHERE host_axis=?"
        params: list[Any] = [host_axis]
        if engagement is not None:
            q += " AND engagement=?"
            params.append(engagement)
        q += " ORDER BY ts DESC, id DESC LIMIT ?"
        params.append(int(limit))
        run = 0
        for r in self.conn.execute(q, params):
            rc = (r["response_class"] or "").strip().lower()
            if rc and rc not in QUIET_CLASSES:
                break
            run += 1
        return run

    # --- status + purge -------------------------------------------------------

    # --- §10 signal spans (two-tier emission truth) ---------------------------

    def record_span(self, emission_ref: int, *, provenance: str,
                    response_class: str | None = None,
                    window_count: float | None = None,
                    host_axis: str | None = None, engagement: str | None = None,
                    tool: str | None = None, detail: dict | None = None,
                    ts: float | None = None) -> dict:
        """Attach ONE signal span to an emission (§10): the per-request /
        per-event truth attached by tools that SEE those events. Spans are
        CONFIDENCE material for the controller (§8.3), never the throttle
        accounting basis. ``provenance`` is ``'request'`` (request-level
        event) or ``'aggregate'`` (batch tool summary span) — anything else
        raises (authored honesty). Batch tools (nmap/masscan) emit SUMMARY
        spans only (window count + coarse outcome)."""
        prov = (provenance or "").strip().lower()
        if prov not in ("request", "aggregate"):
            raise ValueError(
                f"span provenance must be 'request' or 'aggregate', "
                f"got {provenance!r}")
        ts = ts if ts is not None else time.time()
        rc = (response_class or "").strip().lower()
        cur = self.conn.execute(
            "INSERT INTO signal_spans (emission_ref, ts, response_class, "
            "provenance, window_count, host_axis, engagement, tool, "
            "detail_json) VALUES (?,?,?,?,?,?,?,?,?)",
            (int(emission_ref), float(ts), rc or None, prov,
             float(window_count) if window_count is not None else None,
             host_axis, engagement, tool, _opt_json(detail)))
        self.conn.commit()
        return {"span_id": int(cur.lastrowid), "emission_ref": int(emission_ref),
                "provenance": prov}

    def spans_for_emission(self, emission_ref: int) -> list[dict]:
        rows = [dict(r) for r in self.conn.execute(
            "SELECT * FROM signal_spans WHERE emission_ref=?"
            " ORDER BY ts, id", (int(emission_ref),))]
        for r in rows:
            r["detail"] = json.loads(r.pop("detail_json") or "null")
        return rows

    def span_summary(self, *, host_axis: str | None = None,
                     engagement: str | None = None,
                     before_ts: float | None = None,
                     window_s: float = 300.0) -> dict:
        """Span counts by provenance in a recent window for a (host_axis,
        engagement) observation axis — the §8.3 verdict ingredient."""
        before = before_ts if before_ts is not None else time.time()
        q = ("SELECT provenance, COUNT(*) n FROM signal_spans WHERE"
             " ts < ? AND ts >= ?")
        params: list = [before, before - window_s]
        if host_axis:
            q += " AND host_axis=?"
            params.append(host_axis)
        if engagement is not None:
            q += " AND engagement=?"
            params.append(engagement)
        q += " GROUP BY provenance"
        out = {"request": 0, "aggregate": 0}
        for r in self.conn.execute(q, params):
            p = (r["provenance"] or "").strip().lower()
            if p in out:
                out[p] = int(r["n"] or 0)
        return out

    def span_lanes(self, *, window_s: float = 300.0, limit: int = 6,
                   before_ts: float | None = None) -> list[dict]:
        """Per (host_axis, engagement) span activity in the recent window —
        the status lens for §8.3 provenance weighting."""
        before = before_ts if before_ts is not None else time.time()
        return [dict(r) for r in self.conn.execute(
            "SELECT engagement, host_axis, MAX(ts) last_ts,"
            " SUM(provenance='request') request_spans,"
            " SUM(provenance='aggregate') aggregate_spans"
            " FROM signal_spans WHERE ts < ? AND ts >= ?"
            " GROUP BY engagement, host_axis"
            " ORDER BY last_ts DESC LIMIT ?",
            (before, before - window_s, int(limit)))]

    # --- status + purge -------------------------------------------------------

    def status_snapshot(self, *, now: float | None = None) -> dict:
        """Plain-dict status for tests + the Phase B ``budget_status`` twin
        (which adds the LLM-facing framing). No verdicts here — data only."""
        now = now if now is not None else time.time()
        nodes = [dict(r) for r in self.conn.execute("SELECT * FROM nodes")]
        queue = [dict(r) for r in self.conn.execute(
            "SELECT status, COUNT(*) n FROM queue_items WHERE "
            "expires_at >= ? GROUP BY status", (now,))]
        reserves = [dict(r) for r in self.conn.execute(
            "SELECT * FROM reserves WHERE ttl_expiry IS NULL OR "
            "ttl_expiry > ? ORDER BY ts DESC", (now,))]
        for r in reserves:
            r["dims"] = json.loads(r.pop("dims_json") or "{}")
            r["max_vector"] = json.loads(r.pop("max_vector_json") or "{}")
            r["remaining"] = json.loads(r.pop("remaining_json") or "{}")
        r_open = [dict(r) for r in self.conn.execute(
            "SELECT id, tool, ts, engagement, job_ref, meter_state FROM "
            "emissions WHERE declared_basis='credit_line' AND "
            "actual_json IS NULL AND (meter_state IS NULL OR meter_state"
            " IN ('hold','metering')) AND (drift IS NULL OR drift=0) AND "
            "(drift_note IS NULL OR drift_note NOT LIKE 'closed%') "
            "ORDER BY ts DESC LIMIT 20")]
        exhausted = self.conn.execute(
            "SELECT COUNT(*) FROM emissions WHERE meter_state="
            "'exhausted'").fetchone()[0]
        return {"nodes": nodes, "queue": queue, "reserves": reserves,
                "open_draws": r_open, "exhausted_draws": int(exhausted or 0),
                "generated": now}

    def purge_engagement(self, slug: str) -> dict:
        """Engagement-local erasure (§13: SQLite-first; PG mirror purge is
        orchestrated by the caller — the operator REPL — later). Only rows
        tagged ``engagement=slug`` go; unarmed NULL-engagement lab rows stay."""
        counts = {}
        for table in ("nodes", "queue_items", "emissions", "principals",
                      "tripwire_intervals", "reserves", "signal_spans"):
            cur = self.conn.execute(
                f"DELETE FROM {table} WHERE engagement=?", (slug,))
            counts[table] = int(cur.rowcount)
        # controller_state keys by node_key (which embeds the engagement).
        keys = [r[0] for r in self.conn.execute(
            "SELECT node_key FROM nodes WHERE engagement=?", (slug,))]
        for key in keys:
            cur = self.conn.execute(
                "DELETE FROM controller_state WHERE node_key=?", (key,))
            counts.setdefault("controller_state", 0)
            counts["controller_state"] += int(cur.rowcount)
        self.conn.commit()
        counts["tripwire_estimates"] = 0
        return counts

    def reconstitute(self, slug: str | None, *, policy: dict) -> None:
        """Re-stamp policy onto every node of an engagement (nodes re-mint
        from the constitution on arm, §13). Balances carry."""
        where, params = (
            ("engagement IS NULL", [])
            if slug is None else ("engagement=?", [slug]))
        keys = [r[0] for r in self.conn.execute(
            f"SELECT node_key FROM nodes WHERE {where}", params)]
        for key in keys:
            self.conn.execute(
                "UPDATE nodes SET ceiling_json=?, floor_json=?, refill_json=? "
                "WHERE node_key=?",
                (_policy_json({d: policy[d]["ceiling"] for d in DIMS}),
                 _policy_json({d: policy[d]["floor"] for d in DIMS}),
                 _policy_json({d: policy[d]["refill_per_epoch"] for d in DIMS}),
                 key))
        self.conn.commit()

    def set_phase(self, *, mode: str, engagement: str | None = None,
                  entry_partition: str | None = None, exit_id: str | None = None,
                  range_axis: str | None = None, host_axis: str | None = None,
                  principal: str | None = None,
                  epoch_anchor: float | None = None) -> int:
        """Operator/controller phase flip per node selector (HOLD ⇄ NORMAL).
        Requires at least one selector so no lane can blanket-flip the tree.
        ``epoch_anchor`` (optional, stamped by the caller on a hold→normal
        lift) pins a jittered §6.2 refill window; ``manual_phase`` records
        the operator pin so automatic modes respect it until it is cleared."""
        if mode not in ("normal", "hold"):
            raise ValueError(f"bad phase mode {mode!r} (normal|hold)")
        sets, params = ["mode=?"], [mode]
        if epoch_anchor is not None:
            sets.append("epoch_anchor=?")
            params.append(float(epoch_anchor))
        if mode == "hold":
            sets.append("manual_phase='hold'")
        else:
            sets.append("manual_phase=NULL")
        sel_sets: list[str] = []
        sel_vals: list[Any] = []
        for col, val in (("engagement", engagement),
                         ("entry_partition", entry_partition),
                         ("exit_id", exit_id), ("range_axis", range_axis),
                         ("host_axis", host_axis), ("principal", principal)):
            if val is not None:
                sel_sets.append(f"{col}=?")
                sel_vals.append(val)
        if len(sel_vals) == 0:
            raise ValueError("set_phase needs at least one node selector")
        cur = self.conn.execute(
            f"UPDATE nodes SET {', '.join(sets)} WHERE "
            f"{' AND '.join(sel_sets)}",
            params + sel_vals)
        self.conn.commit()
        return int(cur.rowcount)

    # --- controller state (§8.1) ----------------------------------------------

    def set_controller_state(self, node_key: str, dim: str, *, state: str,
                             streak: int, quiet_since: float | None,
                             entered: float, transitions_hour: list[float]) -> None:
        self.conn.execute(
            "INSERT INTO controller_state (node_key, dim, state, streak, "
            "quiet_since, entered, transitions_hour) VALUES (?,?,?,?,?,?,?) "
            "ON CONFLICT(node_key, dim) DO UPDATE SET state=excluded.state, "
            "streak=excluded.streak, quiet_since=excluded.quiet_since, "
            "entered=excluded.entered, "
            "transitions_hour=excluded.transitions_hour",
            (node_key, dim, state, int(streak), quiet_since, float(entered),
             json.dumps(transitions_hour[-64:])))
        self.conn.commit()

    def get_controller_states(self, node_key: str | None = None) -> dict:
        """node_key → {dim: {state, streak, ...}} (restart resume §13)."""
        if node_key is None:
            cur = self.conn.execute("SELECT * FROM controller_state")
        else:
            cur = self.conn.execute(
                "SELECT * FROM controller_state WHERE node_key=?", (node_key,))
        out: dict[str, dict] = {}
        for r in cur:
            d = dict(r)
            d["transitions_hour"] = json.loads(d["transitions_hour"] or "[]")
            out.setdefault(d["node_key"], {})[d["dim"]] = d
        return out

    # --- tripwire interval learning (§8.3, Appendix A) -------------------------

    def tripwire_interval(self, engagement: str | None, host_axis: str,
                          kind: str, *, upper: float | None = None,
                          lower: float | None = None,
                          window_seconds: float,
                          provenance: str = "observed",
                          now: float | None = None) -> dict:
        """Monotone both-sided interval update on the observed window count:
        onset observation → ``upper = min(upper, X)``; reaction-free sustained
        run → ``lower = max(lower, X)``. Bounds only tighten, never loosen."""
        now = now if now is not None else time.time()
        cur = self.conn.execute(
            "SELECT lower, upper, samples FROM tripwire_intervals WHERE "
            "host_axis=? AND kind=? AND (engagement IS ? OR engagement=?)",
            (host_axis, kind, engagement, engagement))
        row = cur.fetchone()
        if row is not None:
            lo = float(row["lower"]) if row["lower"] is not None else None
            up = float(row["upper"]) if row["upper"] is not None else None
            samples = int(row["samples"])
        else:
            lo, up, samples = None, None, 0
        if upper is not None:
            up = float(upper) if up is None else min(up, float(upper))
        if lower is not None:
            lo = float(lower) if lo is None else max(lo, float(lower))
        self.conn.execute(
            "INSERT INTO tripwire_intervals (engagement, host_axis, kind, "
            "lower, upper, window_seconds, samples, provenance, updated) "
            "VALUES (?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(engagement, host_axis, kind) DO UPDATE SET "
            "lower=excluded.lower, upper=excluded.upper, "
            "window_seconds=excluded.window_seconds, "
            "samples=excluded.samples, provenance=excluded.provenance, "
            "updated=excluded.updated",
            (engagement, host_axis, kind, lo, up, float(window_seconds),
             samples + 1, provenance, float(now)))
        self.conn.commit()
        return {"engagement": engagement, "host_axis": host_axis,
                "kind": kind, "lower": lo, "upper": up,
                "window_seconds": float(window_seconds),
                "samples": samples + 1, "provenance": provenance,
                "updated": float(now)}

    def tripwire_intervals(self, *, engagement: str | None = None,
                           host_axis: str | None = None) -> list[dict]:
        q, args = [], []
        if engagement is not None:
            q.append("engagement IS ? OR engagement=?")
            args += [engagement, engagement]
        if host_axis is not None:
            q.append("host_axis=?")
            args.append(host_axis)
        where = f" WHERE {' AND '.join(f'({x})' for x in q)}" if q else ""
        return [dict(r) for r in self.conn.execute(
            f"SELECT * FROM tripwire_intervals{where}", args)]

    # --- §6.2 automatic refill modes + stall alarm ----------------------------

    def apply_backlog_modes(self, now: float, epoch_s: float, *,
                            jitter_lo: float, jitter_hi: float,
                            jitter_fn=None) -> list[dict]:
        """Automatic HOLD ⇄ NORMAL per node from the LIVE backlog (queued
        items matched to each node's axis subtree). HOLD while a node's
        backlog is non-empty; NORMAL once it drains — the NORMAL transition
        stamps a JITTERED epoch_anchor (``now + U(lo,hi)``) so refill only
        resumes after the drain window, and never saw-tooths across nodes.
        A node's ``manual_phase`` pin (operator set_phase) WINS over this;
        automatic never clears an operator pin. Returns transitions."""
        jitter_fn = jitter_fn or (lambda lo, hi: random.uniform(lo, hi))
        now = float(now)
        backlog_host_axes: dict[str, int] = {}
        for r in self.conn.execute(
                "SELECT dims_json FROM queue_items WHERE status='queued' "
                "AND expires_at >= ?", (now,)):
            dims = json.loads(r["dims_json"] or "{}")
            ha = dims.get("host_axis")
            if ha:
                backlog_host_axes[ha] = backlog_host_axes.get(ha, 0) + 1
        transitions = []
        for node in self.conn.execute("SELECT * FROM nodes"):
            pinned = node["manual_phase"]
            ha = node["host_axis"]
            backlogged = bool(ha) and backlog_host_axes.get(ha, 0) > 0
            if pinned is not None:
                desired = ("hold" if pinned == "hold"
                           else ("hold" if backlogged else "normal"))
            else:
                desired = "hold" if backlogged else "normal"
            if desired == node["mode"]:
                continue
            anchor = None
            if node["mode"] == "hold" and desired == "normal":
                anchor = now + jitter_fn(float(jitter_lo), float(jitter_hi))
            self.conn.execute(
                "UPDATE nodes SET mode=?, epoch_anchor=COALESCE(?, "
                "epoch_anchor) WHERE node_key=?",
                (desired, anchor, node["node_key"]))
            transitions.append({"node_key": node["node_key"],
                                "host_axis": ha,
                                "mode": desired,
                                "epoch_anchor": anchor,
                                "manual_pin": pinned is not None})
        self.conn.commit()
        return transitions

    def stall_report(self, now: float, epoch_s: float) -> list[dict]:
        """§6.2 belt-and-braces: a held node whose queued backlog is older
        than one FULL epoch with no drain progress (no launched/finished
        items bound to its host since the oldest queued request).
        Operator-visible, non-auto-escalating."""
        stalled = []
        oldest_by_host: dict[str, float] = {}
        for r in self.conn.execute(
                "SELECT dims_json, requested FROM queue_items WHERE "
                "status='queued'"):
            ha = (json.loads(r["dims_json"] or "{}").get("host_axis"))
            if ha:
                cur = oldest_by_host.get(ha)
                if cur is None or float(r["requested"]) < cur:
                    oldest_by_host[ha] = float(r["requested"])
        if not oldest_by_host:
            return []
        progressed_hosts: set[str] = set()
        for ha in oldest_by_host:
            row = self.conn.execute(
                "SELECT COUNT(*) n FROM queue_items WHERE status IN "
                "('launched','launching','finished') AND requested >= ?",
                (oldest_by_host[ha],)).fetchone()
            if row is not None and int(row["n"]) > 0:
                progressed_hosts.add(ha)
        for node in self.conn.execute("SELECT node_key, host_axis FROM nodes"):
            ha = node["host_axis"]
            oldest = oldest_by_host.get(ha)
            if oldest is None or ha in progressed_hosts:
                continue
            if now - oldest <= epoch_s:
                continue
            held_s = None
            st = self.conn.execute(
                "SELECT entered FROM controller_state WHERE node_key=? AND "
                "dim='requests'", (node["node_key"],)).fetchone()
            if st is not None:
                held_s = round(now - float(st[0]), 1)
            stalled.append({
                "node_key": node["node_key"], "host_axis": ha,
                "held_s": held_s,
                "oldest_queued_s": round(now - oldest, 1)})
        return stalled


def _opt_json(v: Any) -> str | None:
    if v is None:
        return None
    return json.dumps(v, sort_keys=True)
