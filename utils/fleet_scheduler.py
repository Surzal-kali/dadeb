"""Fleet scheduler — per-host slot policy + dedupe over the job store.

This is doctrine §4 (b)(c)(d) as ONE shared module (scaling.txt): every
fleet adapter contributes a key function + aggregator + policy table and
mounts HERE; no adapter copies another's scheduling logic. It is NOT a
process supervisor — jobs are launched by the adapters through
``utils/job_store``; the scheduler answers ONE question per unit request:

    "May this work start now, or must it wait/dedupe — and who is
     already touching this host?"

Accounting axis = the TARGET HOST, not the agent (Phase 0's job store
already tracks who-owns-what). 30 actors on 30 distinct hosts = zero
contention; N units aimed at one host = the courtesy contract. Numeric
targets (IP/CIDR/hyphen range) normalize to their ADDRESS SPAN and slots
compare overlap, not just name equality — a 10.0.0.0/24 sweep and a
single-host unit inside it contend on the same slots:

- **Dedupe** (rule 4): the canonical unit key is the coherence primitive.
  A second `request` for a live unit returns its existing job_id to poll
  instead of a second process — duplicate fleet work is structurally
  impossible, accidental or otherwise.
- **Slot ceilings** (rule 6): concurrent units per host default 2
  (``FLEET_SLOTS_PER_HOST``), hard ceiling 4 (``FLEET_SLOTS_HARD_CEILING``
  — absolute, cannot be raised). Raising above the default requires the
  explicit ``override_slots`` flag; the result then carries a warning.
  Total pressure = slots × tool-internal threads.
- **Auth-adjacent serialization** (rule 7): units matching the class
  list (``FLEET_AUTH_ADJACENT_RE`` — login/auth/session paths by
  default) hold the host EXCLUSIVELY: while one runs, nothing else
  starts on that host, and one cannot start while anything else does.
- **Crash-stale reclaim** (rule 4): a unit whose job row is gone/finished,
  or whose row predates the TTL, is reclaimed by ``sweep_stale()`` — the
  dedupe key stays authoritative after a crash-restart.

Storage: SQLite at ``run/fleet/fleet.db`` (scratch-store conventions:
WAL, agent-attributed rows, call-time env resolution so tests re-point
it). Unit rows are visible to ALL agents — cross-actor dedupe is the
point — but release/stop follow the Phase 0 ownership fence (owner or
``force=True``).

Adapters (Phase 2+) call, in order:
    1. ``request_unit(...)`` → ``"acquired"`` ⇒ launch via job store with
       the returned slot; record the job_id via ``bind_job``.
    2. On every poll/status call: ``sweep_stale()`` (cheap, indexed).
    3. ``release_unit(...)`` when the unit's job finishes (owner or force).

The module also exposes ``fleet_host_status`` as a ``@framework_tool``
observability surface (utils/ runs via in-process fallback — same lane
as the cookie-jar management tools).
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, parse_qsl

from constants import framework_tool, resolve_workspace_root

# Discovery-mint opt-out: this module is a shared LIBRARY (no operator
# CLI); the @framework_tool observability members register via the
# dynamic pass — the static argparse mint would be a second, pointless
# entry point (listeners/responder_analog.py precedent).
_NO_LOCAL_TOOL = True

_DEFAULT_ROOT = resolve_workspace_root()

# Canonical tag vocabulary lives in daharness/tool_tags.py; a scheduler
# tool is infra-observability.
_UNIT_STATUSES = ("running", "done", "failed", "stale", "released")

_AUTH_ADJACENT_DEFAULT = (
    r"(?i)(login|log-in|signin|sign-in|auth|session|token|oauth|"
    r"passwd|password|2fa|mfa|sso|jwt|csrf|admin|account|reset)"
)


def _store_dir() -> Path:
    """Call-time resolution (scope-gate convention) so tests and WORKSPACE_
    ROOT changes after import take effect."""
    override = os.getenv("FLEET_STORE_DIR", "").strip()
    if override:
        return Path(override)
    return _DEFAULT_ROOT / "run" / "fleet"


def _slots_default() -> int:
    raw = os.getenv("FLEET_SLOTS_PER_HOST", "").strip()
    try:
        val = int(raw) if raw else 2
    except ValueError:
        val = 2
    return max(1, min(val, _slots_ceiling()))


def _slots_ceiling() -> int:
    """Hard ceiling — ABSOLUTE (rule 6: raising beyond it is refused, not
    warned; the courtesy contract has a floor of 4 concurrent processes
    per host total pressure budget)."""
    raw = os.getenv("FLEET_SLOTS_HARD_CEILING", "").strip()
    try:
        val = int(raw) if raw else 4
    except ValueError:
        val = 4
    return max(1, val)


def _auth_adjacent_re() -> re.Pattern:
    raw = os.getenv("FLEET_AUTH_ADJACENT_RE", "").strip()
    return re.compile(raw if raw else _AUTH_ADJACENT_DEFAULT)


def _unit_ttl_hours() -> float:
    raw = os.getenv("FLEET_UNIT_TTL_HOURS", "").strip()
    try:
        return float(raw) if raw else 24.0
    except ValueError:
        return 24.0


def _bind_grace_s() -> float:
    """How long an acquired-but-unbound unit may hold a slot. Normal
    request_unit → launch → bind_job is sub-second; past this grace a
    jobless row is a crashed launcher and its slot is reclaimed."""
    raw = os.getenv("FLEET_BIND_GRACE_S", "").strip()
    try:
        return float(raw) if raw else 600.0
    except ValueError:
        return 600.0


def is_auth_adjacent(target: str) -> bool:
    """Rule-7 class check: does this target path look session-bearing?

    Applies the (env-overridable) regex class list to the URL/path. v1 is
    a regex class list per doctrine; token-similarity bucketing is later.
    """
    return bool(_auth_adjacent_re().search(target or ""))


# --- Numeric-target identity (2026-10-31) --------------------------------------
#
# A CIDR sweep and the single host inside it are the same traffic: bare
# IP/CIDR/hyphen-range targets normalize to their NUMERIC SPAN, which the
# canonical key treats as the identity and slot accounting compares for
# overlap (the old per-hostname axis counted a /24 sweep against
# "10.0.0.0" and never saw it overlap the single-host unit on 10.0.0.7).

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _numeric_span(target: str) -> tuple[int, int] | None:
    """First-last IPv4 address a numeric target covers (network ints),
    or None when the target is not a numeric address expression:
    bare IP ("10.0.0.7"), CIDR ("10.0.0.0/24" — host bits ignored, so
    "10.0.0.7/24" names the same span), hyphen range ("10.0.0.2-30"
    last-octet shorthand and "10.0.0.1-10.0.0.30" full form), "host:port"
    without scheme, and a URL whose HOST is numeric (its path/query/creds
    never widen the span). Hostnames → None: no DNS is done here."""
    t = (target or "").strip()
    if not t:
        return None
    if "://" in t:
        try:
            host = (urlparse(t).hostname or "").lower()
        except ValueError:
            return None
        if not _IPV4_RE.match(host):
            return None
        n = int(ipaddress.IPv4Address(host))
        return (n, n)
    body = t.split("?", 1)[0].split("#", 1)[0]
    if ":" in body:
        head, _, tail = body.partition(":")
        if tail.isdigit():
            body = head
    if _IPV4_RE.match(body):
        n = int(ipaddress.IPv4Address(body))
        return (n, n)
    m = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,3})", body)
    if m:
        try:
            net = ipaddress.ip_network(f"{m.group(1)}/{m.group(2)}", strict=False)
        except ValueError:
            return None
        if net.version != 4:
            return None
        return (int(net.network_address), int(net.broadcast_address))
    m = re.fullmatch(
        r"(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})", body
    )
    if m:
        try:
            a = int(ipaddress.IPv4Address(m.group(1)))
            b = int(ipaddress.IPv4Address(m.group(2)))
        except (ValueError, ipaddress.AddressValueError):
            return None
        return (min(a, b), max(a, b))
    m = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3})", body)
    if m:
        lo, hi = int(m.group(2)), None
        try:
            if int(m.group(2)) > 255:
                return None
        except ValueError:
            return None
        first = ipaddress.IPv4Address(m.group(1))
        prefix = ".".join(str(first).split(".")[:3]) + "."
        try:
            b = int(ipaddress.IPv4Address(prefix + m.group(2)))
        except (ValueError, ipaddress.AddressValueError):
            return None
        a = int(first)
        return (min(a, b), max(a, b))
    return None


def _numeric_axis(target: str) -> str | None:
    """Canonical identity string for a BARE numeric target (dedupe key
    host part + pressure-axis label): a single address, or the full span
    "lo-hi". Spellings that cover the same addresses collapse onto one
    axis — "10.0.0.1/24", "10.0.0.0/24" and "10.0.0.0-10.0.0.255" are all
    "10.0.0.0-10.0.0.255". URLs keep urlparse treatment (None)."""
    span = _numeric_span(target)
    if span is None or "://" in (target or "").strip():
        return None
    lo, hi = span
    if lo == hi:
        return str(ipaddress.IPv4Address(lo))
    return f"{ipaddress.IPv4Address(lo)}-{ipaddress.IPv4Address(hi)}"


# --- Canonical key (doctrine §4a) ---------------------------------------------


def canonical_unit_key(tool: str, target: str, *, body: str = "") -> str:
    """Canonical dedupe key for a fleet unit: ``<tool>:<host>:<path>:<hash>``.

    Key on SHAPE, not raw bytes — request bodies carry per-run CSRF/nonce
    values, so:
    - URL query: param NAMES only (order-insensitive, sorted).
    - form body: field NAMES only (order-insensitive, sorted).
    - JSON body: top-level KEY names only.
    - path: trailing slash normalized (``/admin`` == ``/admin/``).
    - host:port kept (an identity detail); slot pressure uses hostname.

    Same shape → same key → dedupe. Different values (new CSRF token,
    different username) → SAME unit; genuinely different endpoints/params
    → different unit.

    Bare numeric targets (IP/CIDR/hyphen range) collapse onto a canonical
    span identity first — "10.0.0.1/24" and "10.0.1.0/24" covering the
    same 256 addresses share one key regardless of spelling.
    """
    target = (target or "").strip()
    numeric_axis = _numeric_axis(target) if "://" not in target else None
    if numeric_axis is not None:
        host = numeric_axis
        path = "/"
        parts = urlparse("")  # bare numeric target: no query to parse
    else:
        parts = urlparse(target)
        host = (parts.netloc or target.split("/")[0] or "unknown").lower()
        path = re.sub(r"/+$", "", parts.path or "") or "/"
    try:
        q_names = sorted(name for name, _v in parse_qsl(parts.query, keep_blank_values=True))
    except ValueError:
        q_names = sorted(p.split("=", 1)[0] for p in parts.query.split("&") if p)

    body_names: list[str] = []
    if body:
        b = body.strip()
        if b.startswith("{"):
            try:
                parsed = json.loads(b)
                if isinstance(parsed, dict):
                    body_names = sorted(str(k) for k in parsed.keys())
            except (json.JSONDecodeError, ValueError):
                body_names = []
        if not body_names:
            try:
                pairs = parse_qsl(b, keep_blank_values=True)
            except ValueError:
                pairs = []
            if pairs:
                body_names = sorted(name for name, _v in pairs)
            else:
                # Non-form, non-JSON body: hash the LENGTH CLASS + shape
                # signature (first line's field separators), never content.
                sep = "&" if "&" in b else ("|" if "|" in b else "raw")
                body_names = [f"raw:{sep}:{len(b) // 512}"]

    shape = "|".join([
        "q:" + ",".join(q_names),
        "b:" + ",".join(body_names),
    ])
    digest = hashlib.sha1(shape.encode("utf-8", "replace")).hexdigest()[:12]
    safe_tool = re.sub(r"[^a-z0-9_.-]", "-", (tool or "unit").lower())
    return f"{safe_tool}:{host}:{path}:{digest}"


def _host_of(target: str) -> str:
    """Slot-pressure axis: hostname WITHOUT port (ports share a box),
    or the canonical numeric span for bare IP/CIDR/range targets."""
    axis = _numeric_axis(target)
    if axis is not None:
        return axis
    parts = urlparse(target if "//" in target else f"//{target}", scheme="http")
    host = (parts.hostname or "").lower()
    return host or "unknown"


# --- Store ---------------------------------------------------------------------


def _set_wal(c: sqlite3.Connection) -> None:
    """Convert a SQLite db to WAL journal mode, tolerating the
    first-converter race.

    ``PRAGMA journal_mode=WAL`` on a fresh db needs an exclusive lock for
    the delete→WAL conversion, and unlike ordinary lock waits that
    conversion can return SQLITE_BUSY immediately (busy_timeout does not
    cover it — found live in the 3-process boot race the multiprocess
    fleet tests exercise). Losing that race is harmless: the winner
    converted the db, so a retry finds the mode already ``wal`` (that
    readback takes no lock). Only surface the error if the db genuinely
    is not WAL after the attempts.
    """
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


class FleetScheduler:
    """SQLite-backed per-host slot ledger + unit dedupe table.

    Concurrency model (processes AND threads — 2026-10-29 hardening; the
    original single shared connection only coordinated threads inside one
    process, so the slot ceiling was not atomic across processes):

    - **Per-thread connections** (threadlocal): one SQLite connection per
      thread, built on first use. ``self.conn`` stays a valid attribute —
      a property returning the CALLING thread's connection — so external
      readers (e.g. sqlmap's ``_release_unit_for_job`` SELECT) keep
      working, and the reaper thread gets its own.
    - **Autocommit mode** (``isolation_level=None``): no implicit
      transactions hiding multi-statement sequences; every multi-row
      critical section takes ``BEGIN IMMEDIATE`` explicitly, which grabs
      SQLite's file-level write lock — THE cross-process mutex. Two racing
      processes serialize on it; the loser sees the winner's committed
      rows in its re-read.
    - **RLock for in-process ordering** (advisory): threads within one
      process serialize their whole read-decide-write so internal callers
      with two schedulers don't fight busy_timeout; cross-process safety
      NEVER leans on it (a different process has no copy of this lock).
    - A busy_timeout rides every conn as the starvation backstop for the
      rare moment two processes contend on BEGIN IMMEDIATE directly.
    """

    def __init__(self, store_dir: str | Path | None = None):
        base = Path(store_dir) if store_dir else _store_dir()
        base.mkdir(parents=True, exist_ok=True)
        self.db_path = str(base / "fleet.db")
        import sqlite3

        self._sqlite3 = sqlite3
        self.db_lock = threading.RLock()  # in-process ordering, advisory
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
        """The CALLING thread's connection (created on first use).

        Kept as an attribute-compatible property: external readers that
        read ``sched.conn`` directly keep working — but they now get a
        connection they OWN, so a concurrent writer never trips their
        cursor mid-read. They use it read-only; lifecycle writes go
        through the scheduler API (``release_unit`` / ``release_for_job``).
        """
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

    def _immediate(self):
        """Open a cross-process-atomic write section on THIS thread's conn.

        ``BEGIN IMMEDIATE`` acquires the RESERVED lock eagerly (not lazily
        at first write), so two racing processes serialize on the file
        lock rather than discovering a conflict at COMMIT (SQLITE_BUSY on
        commit is the upgrade-deadlock shape; immediate avoids it).
        busy_timeout (30s) starves the loser politely instead of failing.
        """
        self.conn.execute("BEGIN IMMEDIATE")

    def _commit(self):
        self.conn.execute("COMMIT")

    def _rollback(self):
        self.conn.execute("ROLLBACK")

    def _init_table(self) -> None:
        # Schema setup runs on the bootstrap conn at construction (single-
        # threaded moment); autocommit mode — no explicit commit needed.
        c = self._bootstrap
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS fleet_units (
                unit_key     TEXT NOT NULL,
                tool         TEXT NOT NULL,
                target       TEXT NOT NULL,
                host         TEXT NOT NULL,
                agent_id     TEXT NOT NULL,
                job_id       TEXT,
                status       TEXT NOT NULL DEFAULT 'running',
                auth_adjacent INTEGER NOT NULL DEFAULT 0,
                started      REAL NOT NULL,
                finished     REAL,
                note         TEXT,
                PRIMARY KEY (unit_key)
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_fleet_host_status "
            "ON fleet_units(host, status)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_fleet_status_started "
            "ON fleet_units(status, started)"
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS fleet_batches (
                batch_id   TEXT PRIMARY KEY,
                tool       TEXT NOT NULL,
                agent_id   TEXT NOT NULL,
                requested  INTEGER NOT NULL,
                status     TEXT NOT NULL DEFAULT 'running',
                started    REAL NOT NULL,
                finished   REAL
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS fleet_batch_units (
                batch_id  TEXT NOT NULL,
                unit_key  TEXT NOT NULL,
                seq       INTEGER NOT NULL,
                target    TEXT NOT NULL,
                decision  TEXT NOT NULL,
                job_id    TEXT,
                detail    TEXT,
                PRIMARY KEY (batch_id, seq)
            )
            """
        )

    # -- acquire ----------------------------------------------------------------

    def request_unit(
        self,
        tool: str,
        target: str,
        *,
        agent_id: str,
        body: str = "",
        override_slots: int | None = None,
        note: str = "",
    ) -> dict[str, Any]:
        """Ask to START one unit. Returns a decision envelope:

        - ``{"decision": "acquired", "unit_key", "job_slot", "warning"?}``
          — launch via the job store now, then ``bind_job(unit_key, job_id)``.
        - ``{"decision": "duplicate", "unit_key", "job_id", "agent_id",
          "status"}`` — a live unit with this canonical key already runs;
          POLL its job (``*_status(job_id)``) instead of launching.
        - ``{"decision": "refused", "reason": "slots_exhausted"|"host_
          serialized_auth", ...}`` — do NOT launch; the envelope says what
          to do instead (wait and re-request, or poll the running units).

        ATOMICITY (2026-10-29): the whole count→decide→insert sequence is
        ONE ``BEGIN IMMEDIATE`` transaction — admission is a conditional
        write under the file lock, so the slot ceiling holds across
        PROCESSES (two lanes can't both count 1 running and both admit a
        third). In-process ordering additionally serializes on RLock so
        two scheduler instances in one process don't fight busy_timeout.
        """
        if not agent_id:
            raise ValueError("fleet scheduler requires a resolved agent_id")
        unit_key = canonical_unit_key(tool, target, body=body)
        host = _host_of(target)
        auth_adj = 1 if is_auth_adjacent(target) else 1 if is_auth_adjacent(body or "") else 0

        # Stale reclaim FIRST — a crashed actor's ghost must not own slots.
        # (Its own IMMEDIATE tx; see sweep_stale.)
        self.sweep_stale()

        out: dict[str, Any]
        with self.db_lock:  # in-process ordering (advisory)
            self._immediate()  # cross-process mutex (file lock)
            try:
                # --- Dedupe (rule 4): the key is authoritative.
                existing = self.conn.execute(
                    "SELECT * FROM fleet_units WHERE unit_key = ?", (unit_key,)
                ).fetchone()
                if existing is not None and existing["status"] == "running":
                    out = {
                        "decision": "duplicate",
                        "unit_key": unit_key,
                        "job_id": existing["job_id"],
                        "agent_id": existing["agent_id"],
                        "started": existing["started"],
                        "message": (
                            f"unit already running (key {unit_key}, started by "
                            f"{existing['agent_id']}); poll its job_id instead of "
                            "launching a second process"
                        ),
                    }
                    self._commit()  # tx read-only; close it either way
                    return out

                # --- Slot accounting on the HOST axis + numeric-span
                # overlap (re-read INSIDE the tx — values from before
                # BEGIN are void). A /24 sweep and the single host inside
                # it contend on the same slots: rows count as contending
                # on canonical-axis equality OR numeric-span overlap
                # (the old host=? SELECT only saw the sweep row keyed at
                # "10.0.0.0" and never the member IP's overlap).
                running_any = self.conn.execute(
                    "SELECT unit_key, agent_id, auth_adjacent, host, target "
                    "FROM fleet_units WHERE status = 'running'"
                ).fetchall()
                my_span = _numeric_span(target)

                def _contends(row) -> bool:
                    if row["host"] == host:
                        return True
                    rs = _numeric_span(row["target"])
                    if my_span is not None and rs is not None:
                        return rs[0] <= my_span[1] and my_span[0] <= rs[1]
                    return False

                contending = [r for r in running_any if _contends(r)]
                n_running = len(contending)

                # Rule 7: auth-adjacent units hold the host exclusively.
                if auth_adj and n_running > 0:
                    out = {
                        "decision": "refused",
                        "reason": "host_serialized_auth",
                        "unit_key": unit_key,
                        "host": host,
                        "running_units": [r["unit_key"] for r in contending],
                        "message": (
                            "session-bearing (auth-adjacent) unit requires the "
                            f"host exclusively; {n_running} unit(s) running — "
                            "wait and re-request, or work a different host"
                        ),
                    }
                    self._commit()
                    return out
                if any(r["auth_adjacent"] for r in contending):
                    out = {
                        "decision": "refused",
                        "reason": "host_serialized_auth",
                        "unit_key": unit_key,
                        "host": host,
                        "running_units": [r["unit_key"] for r in contending],
                        "message": (
                            "an auth-adjacent unit holds this host exclusively "
                            "(same shared session); wait for it to finish"
                        ),
                    }
                    self._commit()
                    return out

                # Rule 6: slot ceilings. Ceiling is absolute; raising above
                # the default needs the explicit override flag and warns.
                ceiling = _slots_ceiling()
                default = _slots_default()
                limit = default
                warning = ""
                if override_slots is not None and n_running >= default:
                    try:
                        want = int(override_slots)
                    except (TypeError, ValueError):
                        want = default
                    if want > ceiling:
                        out = {
                            "decision": "refused",
                            "reason": "slots_exhausted",
                            "unit_key": unit_key,
                            "host": host,
                            "running": n_running,
                            "ceiling": ceiling,
                            "message": (
                                f"override {want} exceeds the absolute ceiling "
                                f"{ceiling}; total target pressure = slots x "
                                "tool-internal threads"
                            ),
                        }
                        self._commit()
                        return out
                    limit = max(default, min(want, ceiling))
                    warning = (
                        f"slot override: {n_running + 1}/{limit} concurrent on "
                        f"{host} (default {default}) — explicit, operator-visible"
                    )
                if n_running >= limit:
                    out = {
                        "decision": "refused",
                        "reason": "slots_exhausted",
                        "unit_key": unit_key,
                        "host": host,
                        "running": n_running,
                        "limit": limit,
                        "running_units": [r["unit_key"] for r in contending],
                        "message": (
                            f"{n_running}/{limit} slot(s) in use on {host}; wait "
                            "for a unit to finish or re-request later"
                            + (f" (or pass override_slots<= {ceiling})" if limit < ceiling else "")
                        ),
                    }
                    self._commit()
                    return out

                self.conn.execute(
                    """
                    INSERT INTO fleet_units
                        (unit_key, tool, target, host, agent_id, status,
                         auth_adjacent, started, note)
                    VALUES (?, ?, ?, ?, ?, 'running', ?, ?, ?)
                    ON CONFLICT(unit_key) DO UPDATE SET
                        status = 'running',
                        agent_id = excluded.agent_id,
                        job_id = NULL,
                        started = excluded.started,
                        finished = NULL,
                        note = excluded.note
                    """,
                    (unit_key, tool, target, host, agent_id, auth_adj, time.time(), note),
                )
                self._commit()
            except BaseException:
                try:
                    self._rollback()
                except Exception:
                    pass
                raise

        out = {
            "decision": "acquired",
            "unit_key": unit_key,
            "tool": tool,
            "host": host,
            "agent_id": agent_id,
            "auth_adjacent": bool(auth_adj),
        }
        if warning:
            out["warning"] = warning
        return out

    # -- job binding + release ----------------------------------------------------

    def bind_job(self, unit_key: str, job_id: str) -> dict[str, Any]:
        """Attach the launched job_id to an acquired unit (the lock-table
        row gains its {pgid, log} handle via the job store's row).

        Conditional: only a 'running' UNBOUND row binds (a racing sweep
        may have marked it stale between acquire and bind — that's the
        bind-grace boundary working; the caller sees the no-such-unit
        outcome rather than resurrecting a stale row).
        """
        with self.db_lock:
            self._immediate()
            try:
                cur = self.conn.execute(
                    "UPDATE fleet_units SET job_id = ? WHERE unit_key = ? "
                    "AND status = 'running' AND job_id IS NULL",
                    (job_id, unit_key),
                )
                committed = cur.rowcount
                self._commit()
            except BaseException:
                try:
                    self._rollback()
                except Exception:
                    pass
                raise
        if committed == 0:
            return {"status": "no such unit", "unit_key": unit_key}
        return {"status": "ok", "unit_key": unit_key, "job_id": job_id}

    def release_unit(
        self, unit_key: str, *, status: str = "done", agent_id: str | None = None, force: bool = False
    ) -> dict[str, Any]:
        """Mark a unit finished (frees its slot). Owner or force=True.

        Conditional UPDATE (``AND status='running'``): a racing double-
        release (two lanes poll the same job's done at once) no-ops on
        the second — first-releaser wins, the slot frees exactly once.
        """
        final = status if status in _UNIT_STATUSES else "done"
        with self.db_lock:
            self._immediate()
            try:
                row = self.conn.execute(
                    "SELECT agent_id, status FROM fleet_units WHERE unit_key = ?",
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
                            f"unit held by '{row['agent_id']}' (you are "
                            f"'{agent_id}'); cross-agent release needs force=True"
                        ),
                    }
                cur = self.conn.execute(
                    "UPDATE fleet_units SET status = ?, finished = ? "
                    "WHERE unit_key = ? AND status = 'running'",
                    (final, time.time(), unit_key),
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
            # Already released/stale/done — idempotent, not an error.
            return {"status": "already_released", "unit_key": unit_key}
        return {"status": "released", "unit_key": unit_key, "final": final}

    def release_for_job(self, job_id: str) -> int:
        """Release every running unit bound to ``job_id`` (poll-side
        bookkeeping: the job finished, its slot frees). Best-effort —
        a unit already released/stale no-ops via the conditional update.
        Returns the number of units released."""
        released = 0
        try:
            rows = self.conn.execute(
                "SELECT unit_key FROM fleet_units WHERE job_id = ? "
                "AND status = 'running'",
                (job_id,),
            ).fetchall()
            for r in rows:
                out = self.release_unit(r["unit_key"], force=True)
                if out.get("status") == "released":
                    released += 1
        except Exception:
            pass  # bookkeeping must never break the poller
        return released

    # -- batch bookkeeping (any adapter; Phase 2 sqlmap mounts first) ---------

    def create_batch(
        self, tool: str, agent_id: str, seq_targets: list[tuple[int, str, str, str]]
    ) -> str:
        """Record a batch of unit decisions. ``seq_targets`` rows are
        ``(seq, unit_key, target, decision)``; a decision field of
        ``'<decision>|<detail>'`` splits into decision + detail (job_id if
        the detail looks like a job ref). Returns the batch_id — what a
        ``*_fleet_status`` polls."""
        batch_id = f"fleet:{secrets.token_hex(6)}"
        acquired = sum(1 for _s, _k, _t, d in seq_targets if d.startswith("acquired"))
        with self.db_lock:
            self._immediate()
            try:
                self.conn.execute(
                    "INSERT INTO fleet_batches (batch_id, tool, agent_id, requested, "
                    "status, started) VALUES (?, ?, ?, ?, 'running', ?)",
                    (batch_id, tool, agent_id, len(seq_targets), time.time()),
                )
                for seq, unit_key, target, decision in seq_targets:
                    detail = None
                    job_id = None
                    if "|" in decision:
                        decision, detail = decision.split("|", 1)
                        if detail.startswith("job:"):
                            job_id = detail[len("job:"):]
                    self.conn.execute(
                        "INSERT INTO fleet_batch_units (batch_id, "
                        "unit_key, seq, target, decision, job_id, detail) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (batch_id, unit_key, seq, target, decision, job_id, detail),
                    )
                if acquired == 0:
                    self.conn.execute(
                        "UPDATE fleet_batches SET status = 'dead', finished = ? "
                        "WHERE batch_id = ?",
                        (time.time(), batch_id),
                    )
                self._commit()
            except BaseException:
                try:
                    self._rollback()
                except Exception:
                    pass
                raise
        return batch_id

    def batch_status(self, batch_id: str) -> dict[str, Any]:
        """Per-unit decision map for one batch (what acquired/duplicated/
        was refused and why) — the fleet twin's status backbone."""
        row = self.conn.execute(
            "SELECT * FROM fleet_batches WHERE batch_id = ?", (batch_id,)
        ).fetchone()
        if row is None:
            return {"batch_id": batch_id, "status": "unknown",
                    "error": f"no fleet batch {batch_id!r}"}
        units = self.conn.execute(
            "SELECT seq, unit_key, target, decision, job_id, detail "
            "FROM fleet_batch_units WHERE batch_id = ? ORDER BY seq",
            (batch_id,),
        ).fetchall()
        counts: dict[str, int] = {}
        for u in units:
            counts[u["decision"]] = counts.get(u["decision"], 0) + 1
        return {
            "batch_id": batch_id,
            "tool": row["tool"],
            "agent_id": row["agent_id"],
            "requested": row["requested"],
            "status": row["status"],
            "started": row["started"],
            "decision_counts": counts,
            "units": [dict(u) for u in units],
        }

    def mark_batch_complete(self, batch_id: str) -> None:
        """Flip a batch to 'complete' when no unit is running (called by
        fleet-status pollers; conditional so a racing double-status no-
        ops). One IMMEDIATE tx."""
        with self.db_lock:
            self._immediate()
            try:
                self.conn.execute(
                    "UPDATE fleet_batches SET status = 'complete', finished = ? "
                    "WHERE batch_id = ? AND status = 'running'",
                    (time.time(), batch_id),
                )
                self._commit()
            except BaseException:
                try:
                    self._rollback()
                except Exception:
                    pass
                raise

    # -- reclaim + observability -----------------------------------------------------

    def sweep_stale(self) -> dict[str, Any]:
        """Crash-stale TTL reclaim (rule 4): the dedupe key stays
        authoritative after a crash-restart.

        Three reclaim cases for 'running' rows:
        1. **Job finished/missing** — the unit's job row shows an exit code
           (or the job is gone): the work is over, whoever ran it never
           released. Reclaim.
        2. **Jobless past the bind grace** (``FLEET_BIND_GRACE_S``, default
           600s): an acquired-but-never-bound row is either a crashed
           launcher (request_unit → bind_job is sub-second in process) or
           genuinely abandoned; past the grace it owns no slot.
        3. **Past the unit TTL** (``FLEET_UNIT_TTL_HOURS``) regardless of
           job state — a wedged unit cannot own a slot forever.

        Freshly acquired units are NEVER reclaimed: a jobless row inside
        the grace window is a launch in progress.
        """
        now = time.time()
        ttl_cutoff = now - _unit_ttl_hours() * 3600
        grace_cutoff = now - _bind_grace_s()

        self_reclaim_sql = """
            SELECT unit_key, job_id, agent_id, started FROM fleet_units
            WHERE status = 'running'
              AND (
                (job_id IS NULL AND started < ?)
                OR started < ?
              )
        """
        suspects: list[Any] = list(
            self.conn.execute(self_reclaim_sql, (grace_cutoff, ttl_cutoff)).fetchall()
        )
        # Job-backed suspects: running units WITH a job row whose job is
        # done — check via the job store (cheap, indexed by job_id).
        with_job = self.conn.execute(
            "SELECT unit_key, job_id, agent_id, started FROM fleet_units "
            "WHERE status = 'running' AND job_id IS NOT NULL AND started >= ?",
            (ttl_cutoff,),
        ).fetchall()
        if with_job:
            try:
                from utils.job_store import get_store

                jobs = get_store()
                for r in with_job:
                    jr = jobs.get(r["job_id"])
                    # Reclaim ONLY on a verified finished exit. A MISSING
                    # row is not proof of completion (this lane may not
                    # hold the job store's history, or the ref is stale);
                    # rule 4 prefers a false duplicate (harmless poll of a
                    # dead key) over a false duplicate-allow that double-
                    # fires traffic. TTL covers the unknown case.
                    if jr is not None and jr.get("exit_code") is not None:
                        suspects.append(r)
            except Exception:
                pass  # job store down: TTL/grace cases above still apply
        if not suspects:
            return {"stale_reclaimed": [], "count": 0}
        # The reclaim batch itself is one IMMEDIATE tx (writes + commit
        # under the file lock — NOT bare autocommit statements; the
        # 2026-10-29 hardening moved every write path behind the same
        # discipline as admission).
        reclaimed = []
        with self.db_lock:
            self._immediate()
            try:
                for r in suspects:
                    cur = self.conn.execute(
                        "UPDATE fleet_units SET status = 'stale', finished = ? "
                        "WHERE unit_key = ? AND status = 'running'",
                        (now, r["unit_key"]),
                    )
                    if cur.rowcount:
                        reclaimed.append(r["unit_key"])
                self._commit()
            except BaseException:
                try:
                    self._rollback()
                except Exception:
                    pass
                raise
        return {"stale_reclaimed": reclaimed, "count": len(reclaimed)}

    def host_pressure(self, host: str | None = None) -> dict[str, Any]:
        """Per-host fleet pressure — the courtesy contract, made visible."""
        self.sweep_stale()
        if host:
            rows = self.conn.execute(
                "SELECT * FROM fleet_units WHERE host = ? ORDER BY started DESC LIMIT 50",
                (host,),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM fleet_units ORDER BY started DESC LIMIT 200"
            ).fetchall()
        by_host: dict[str, dict[str, Any]] = {}
        for r in rows:
            h = by_host.setdefault(r["host"], {"running": 0, "units": [], "agents": set(), "default_slots": _slots_default(), "ceiling": _slots_ceiling()})
            if r["status"] == "running":
                h["running"] += 1
                h["units"].append({"unit_key": r["unit_key"], "job_id": r["job_id"], "agent_id": r["agent_id"], "tool": r["tool"], "started": r["started"]})
                h["agents"].add(r["agent_id"])
            else:
                h["units"].append({"unit_key": r["unit_key"], "status": r["status"]})
        for h in by_host.values():
            h["agents"] = sorted(h["agents"])
        return {"hosts": {k: v for k, v in by_host.items()}, "db": self.db_path}


# --- Module-level singleton (lazy, scratch-store pattern) ----------------------

_sched: FleetScheduler | None = None


def get_scheduler() -> FleetScheduler:
    """Process-wide scheduler singleton. ``FLEET_STORE_DIR`` re-points the
    store (tests use it + ``reset_scheduler`` for isolation)."""
    global _sched
    override = os.getenv("FLEET_STORE_DIR", "").strip()
    if override:
        return FleetScheduler(store_dir=override)
    if _sched is None:
        _sched = FleetScheduler()
    return _sched


def reset_scheduler() -> None:
    """Test hook: forget the singleton (next get_scheduler() re-reads env)."""
    global _sched
    _sched = None


def release_units_for_job(job_id: str) -> int:
    """Fleet bookkeeping for ANY tool lane: release the running unit(s)
    bound to a finished job. No-op when the fleet store was never created —
    a lane that never used fleet accounting must not have a done-poll
    conjure fleet.db into existence. Best-effort (returns released count
    or 0); never raises."""
    try:
        if not _store_dir().exists():
            return 0
        return get_scheduler().release_for_job(job_id)
    except Exception:
        return 0


# --- Observability surface ------------------------------------------------------


@framework_tool(
    "Show per-host fleet pressure: which units are running on which hosts, "
    "who started them, and the slot contract (default 2 concurrent per host, "
    "absolute ceiling 4). Use BEFORE launching fleet work on a host you "
    "suspect is busy, and to see what other agents are running. Optionally "
    "filter by host.",
    tags=["infra"],
)
def fleet_host_status(host: str = "") -> dict[str, Any]:
    """Per-host fleet pressure (default/ceiling slots, running units, agents).

    Args:
        host: Optional hostname filter (no port — pressure is per-host).
    """
    sched = get_scheduler()
    out = sched.host_pressure(host or None)
    return out