"""Engagement cobweb: operator-armed engagement key + lane-side DB access.

The engagement slug ('blue.htb') is the cobweb key that ties every store
row — journal dispatches, evidence entries, validation attempts — to one
engagement. Arming is a HUMAN authority action from the Tool REPL
(``engagement on <slug>`` / ``engagement off``), mirroring the scope gate:
it is deliberately NOT exposed as an ``@framework_tool``, so the secretary
has no way to toggle or purge it. The armed state persists to
``engagement/.armed_engagement.json`` and is mtime-checked on every call so
a REPL change takes effect immediately in a running Brain (same mechanism as
``scope/.armed_packet_scope.json``).

Postgres access (psycopg, optional install) follows house rules for additive
stores: a down/absent Postgres degrades every consumer gracefully, never
breaking a tool. One cached connection per process. There is NO background
retry loop — a reconnect attempt happens only on the next real dispatch
that needs the lane. While down, journal rows SPOOL into ``ids.db``
(``journal_spool`` table, same SQLite store the findings/unknowns live in)
and flush to ``journal.entries`` on the next successful connect, so the
dispatch spine never silently drops rows during an outage. The
"Postgres unavailable" warning fires at most a few times per outage before
dropping to debug — it must not nag every 30 seconds.

Roles (packaging/postgres/init/001_roles.sh): lanes authenticate per-lane
(brain_lane/gateway_lane/repl_lane via ``HARNESS_DB_LANE``); the operator
session (harness_operator) is the only identity allowed to run
``engagement.purge()`` — the audit-trail eraser stays human-only, the same
authority model as scope arming.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any

from constants import resolve_workspace_root
from utils.state_perms import reconcile_sqlite_modes

logger = logging.getLogger(__name__)

# ─── Armed state (file-backed, REPL-owned) ───────────────────────────────────


def _state_path() -> Path:
    """Resolve the armed-state file at CALL time (scope_gate convention)."""
    return resolve_workspace_root() / "engagement" / ".armed_engagement.json"


_ARMED_CACHE: dict[str, Any] = {"mtime": None, "state": None}


def _write_state(state: dict[str, Any]) -> None:
    """Atomic state write (scope_gate convention: stage + os.replace, so a
    crash never leaves a torn file that would parse as disarmed)."""
    p = _state_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(state, indent=2))
    os.replace(tmp, p)
    _ARMED_CACHE["mtime"] = p.stat().st_mtime
    _ARMED_CACHE["state"] = state


def current() -> dict[str, Any] | None:
    """The armed engagement dict ({slug, roe_note, armed_at}), or None.

    Mtime-checked so a REPL write is picked up by a separate process (Brain,
    gateway) on the very next dispatch without a stale in-memory copy.
    """
    p = _state_path()
    if not p.is_file():
        _ARMED_CACHE["mtime"] = None
        _ARMED_CACHE["state"] = None
        return None
    try:
        mtime = p.stat().st_mtime
    except OSError:
        return None
    if _ARMED_CACHE["mtime"] == mtime and _ARMED_CACHE["state"] is not None:
        return _ARMED_CACHE["state"]
    try:
        state = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    _ARMED_CACHE["mtime"] = mtime
    _ARMED_CACHE["state"] = state
    return state


def current_slug() -> str | None:
    """The armed engagement slug, or None (rows written while unarmed carry
    NULL engagement — they still journal, they're just not cobwebbed)."""
    st = current()
    if not st:
        return None
    slug = str(st.get("slug") or "").strip()
    return slug or None


def arm(slug: str, roe_note: str = "") -> dict[str, Any]:
    """Arm an engagement. Called ONLY from the REPL (operator authority)."""
    slug = slug.strip()
    if not slug:
        raise ValueError("engagement slug must not be empty")
    state = {"slug": slug, "roe_note": roe_note or "", "armed_at": time.time()}
    _write_state(state)
    _ensure_engagement_row(slug, roe_note)
    return state


def disarm() -> None:
    """Disarm (lab mode / between engagements). Rows stay; only the stamp
    stops being applied to new dispatches."""
    p = _state_path()
    if p.is_file():
        try:
            p.unlink()
        except OSError:
            pass
    _ARMED_CACHE["mtime"] = None
    _ARMED_CACHE["state"] = None


# ─── Postgres lane connection (lazy, cached, degrade-gracefully) ─────────────

_RECONNECT_BACKOFF_S = 300.0
# Down-warning budget per outage: the first few connect failures warn, then
# it goes quiet at debug until the lane recovers (next outage refills it).
_WARN_PER_OUTAGE = 3
_DB: dict[str, Any] = {
    "conn": None,
    "down_until": 0.0,     # monotonic — skip attempts while inside the window
    "connected_as": None,  # lane role name of the cached connection
    "driver_ok": None,     # True/False once a connect attempt ran; None = never
    "warn_count": 0,       # warnings issued for the CURRENT outage
    "last_error": None,    # human-readable why-not-connected, for db_status()
}

_INFERRED_LANE: str | None = None

# ─── Journal spool (ids.db, flushed on next successful connect) ──────────────

_SPOOL_CONN: sqlite3.Connection | None = None
_SPOOL_DDL = (
    "CREATE TABLE IF NOT EXISTS journal_spool ("
    "    spool_id   INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    ts         REAL NOT NULL,"
    "    fail_count INTEGER NOT NULL DEFAULT 0,"
    "    payload    TEXT NOT NULL)"
)
_DISPATCH_INSERT_SQL = (
    "INSERT INTO journal.entries "
    "(engagement, lane, tool_id, args, scope_verdict, approval_path, "
    " agent_id, agent_provenance, status, duration_s, result_mode, "
    " scratch_ref, result_digest, envelope_meta) "
    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
)
_SPOOL_KEYS = (
    "engagement", "lane", "tool_id", "args", "scope_verdict",
    "approval_path", "agent_id", "agent_provenance", "status",
    "duration_s", "result_mode", "scratch_ref", "result_digest",
    "envelope_meta",
)
_SPOOL_FLUSH_BATCH = 500


def _infer_lane_from_entrypoint() -> str:
    """Intrinsic lane identity from the entry point — NOT operator-configured.

    Attribution is only trustworthy when the lane can't easily mislabel
    itself, so the default comes from the process's own argv (tool_repl.py →
    repl lane, api_gateway.py → gateway lane, bootstrap/thebrain → brain
    lane). A shared `.env` pins ONE value onto every process that sources
    it, which mislabels whole lanes and (since the pinned role's password
    must match too) breaks auth for all of them at once;
    ``HARNESS_DB_LANE`` stays as an explicit override for tests/pinning.
    """
    global _INFERRED_LANE
    if _INFERRED_LANE is not None:
        return _INFERRED_LANE
    argv0 = (sys.argv[0] if sys.argv and sys.argv[0] else "").lower()
    base = os.path.basename(argv0).replace(".py", "")
    if base == "tool_repl":
        inferred = "repl_lane"
    elif "gateway" in base or base == "bootstrap":
        inferred = "gateway_lane"  # bootstrap.daemon hosts the chat/secretary lane
    elif base == "thebrain":
        inferred = "brain_lane"
    else:
        inferred = "repl_lane"  # kernels, ad-hoc probes — interactive lanes
    _INFERRED_LANE = inferred
    return inferred


def _lane_role() -> str:
    """Which lane credential this process authenticates with. Inferred from
    the entry point (see ``_infer_lane_from_entrypoint``); explicit
    ``HARNESS_DB_LANE`` wins for tests/pinning."""
    explicit = os.getenv("HARNESS_DB_LANE", "").strip()
    if explicit:
        return explicit
    return _infer_lane_from_entrypoint()


def _host_candidates() -> list[str]:
    """Postgres endpoints to try, ordered. An explicit ``HARNESS_DB_HOST``
    pins the single candidate — except the wildcard bind values
    (``0.0.0.0``/``::``/``*``): a wildcard is what the operator sets in
    pg.env when ``daharness-pg init`` binds the host-native cluster to
    every interface, and it names no client endpoint, so the built-in
    order stands — '127.0.0.1' (host lanes hit on the first try; container
    lanes fail it instantly against the host-native cluster) then
    '172.28.0.1' (the workbench-bridge gateway, how every published
    container lane reaches the host's listen socket; the managed hba block
    the same init wires lets the lane roles in). The compose-era 'postgres'
    service name and its pinned 172.28.0.20 IP retired 2026-10-21 with the
    compose postgres service.
    """
    explicit = os.getenv("HARNESS_DB_HOST", "").strip()
    if explicit and explicit not in ("0.0.0.0", "::", "*"):
        return [explicit]
    return ["127.0.0.1", "172.28.0.1"]


def lane_name() -> str:
    """Cheap lane attribution for journal rows — no DB roundtrip (the
    authenticated role IS the lane identity; this env var is set per-process
    at boot to match it)."""
    return _lane_role()


def db_down() -> bool:
    """True while inside the reconnect-backoff window (cheap fast-path check).
    No thread polls this — the only thing that clears the window is the next
    lane consumer (journal write, sweep, diary call) reaching its backoff
    end and attempting a real connect."""
    return time.monotonic() < _DB["down_until"]


def _db_spool_eligible() -> bool:
    """Journaling may spool while down ONLY when the lane was actually opted
    into: the psycopg driver imported at least once (``driver_ok`` True —
    checked during a real connect attempt, the backoff window included). A
    lane that never had the driver skips silently as before; spooling rows
    it can never flush would just be unbounded dead weight in ids.db.
    Unknown (never attempted) returns False — spooling starts only after a
    genuine reachability failure, never on a cold first impression."""
    return _DB.get("driver_ok") is True


def connect(*, role: str | None = None, force: bool = False):
    """A live psycopg connection for the lane (or a named role), or None.

    Postgres absent / down / psycopg not installed → None, warned at most a
    few times per outage (then debug — see ``_warn_down``). Reconnects are
    rate-limited by the backoff window so a down cluster never pins the
    dispatch path, and a SUCCESS reconnect flushes the journal spool (see
    ``_flush_spool``)."""
    global _DB
    now = time.monotonic()
    if not force and db_down():
        return None

    role = role or _lane_role()
    conn = _DB["conn"]
    if conn is not None and _DB["connected_as"] == role:
        try:
            if conn.closed == 0:
                return conn
        except Exception:
            conn = None  # broken cached conn — fall through to reconnect

    try:
        import psycopg  # optional dependency — absence degrades the lane
    except ImportError:
        _DB["driver_ok"] = False
        _warn_down(
            "psycopg not installed — engagement/journal DB lane disabled "
            "(pip install 'psycopg[binary]' to enable); journal rows skip "
            "rather than spool — install the driver to opt the lane in"
        )
        _DB["down_until"] = now + _RECONNECT_BACKOFF_S
        _DB["last_error"] = (
            "psycopg driver not importable on this lane "
            "(pip install 'psycopg[binary]' or apt install python3-psycopg)"
        )
        return None
    _DB["driver_ok"] = True

    user = role
    password = _password_for(role)
    # 5433 = the deb's dedicated 'daharness' cluster (daharness-pg); 5432 is
    # canonically msfdb's 'main' cluster and must never be the fallthrough.
    port = os.getenv("HARNESS_DB_PORT", "5433")
    dbname = os.getenv("HARNESS_DB_NAME", "harness")
    conn = None
    last_exc: Exception | None = None
    for host in _host_candidates():
        try:
            conn = psycopg.connect(
                host=host, port=port, dbname=dbname, user=user, password=password,
                connect_timeout=2, application_name=f"daharness_{role}",
            )
            _DB["host"] = host
            break
        except Exception as exc:
            last_exc = exc
            conn = None
    if conn is None:
        _warn_down(
            f"Postgres unavailable ({last_exc}) — journal/evidence DB lane "
            f"stays optional; journal rows spool to ids.db and flush on "
            f"next connect (retry window {_RECONNECT_BACKOFF_S:.0f}s)"
        )
        _DB["down_until"] = now + _RECONNECT_BACKOFF_S
        _DB["conn"] = None
        _DB["last_error"] = (
            f"cannot reach the lane's Postgres on {port} "
            f"(tried {', '.join(_host_candidates())}): {last_exc}"
        )
        return None

    _DB["conn"] = conn
    _DB["connected_as"] = role
    _DB["down_until"] = 0.0
    _DB["last_error"] = None
    _DB["warn_count"] = 0
    _flush_spool(conn)
    return conn


def _warn_down(message: str) -> None:
    """Cap the down-lane nag: the first ``_WARN_PER_OUTAGE`` failures of an
    outage log at INFO (so the operator learns the lane is off), then the
    story is unchanged — downgrades to DEBUG until recovery. The 30s-era
    behavior logged every failure forever, which on a boot-broken cluster
    meant a line every 30s for the life of the daemon."""
    _DB["warn_count"] = _DB.get("warn_count", 0) + 1
    if _DB["warn_count"] <= _WARN_PER_OUTAGE:
        logger.info("[engagement] %s", message)
    else:
        logger.debug("[engagement] still down (%s)", message)


def _spool_conn() -> sqlite3.Connection:
    """The shared ids.db connection for the spool table (same file the
    findings/unknowns stores own). ids.db is already WAL via
    FindingStore's connect path; this read-only-pragmas connect just joins
    it. reconcile_sqlite_modes is the group-rw heal for a tighter-umask
    mint (the kernel-lane incident class)."""
    global _SPOOL_CONN
    if _SPOOL_CONN is not None:
        return _SPOOL_CONN
    p = Path(resolve_workspace_root()) / "ids.db"
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p), timeout=10.0, check_same_thread=False)
    conn.execute("PRAGMA busy_timeout=10000")
    reconcile_sqlite_modes(str(p))
    _SPOOL_CONN = conn
    return conn


def _spool_dispatch_row(row: dict[str, Any]) -> None:
    """Best-effort insert of one journal row into ids.db while Postgres is
    down. Never raises — a spool failure still must not break a tool."""
    try:
        conn = _spool_conn()
        conn.execute(_SPOOL_DDL)
        conn.execute(
            "INSERT INTO journal_spool (ts, payload) VALUES (?, ?)",
            (time.time(), json.dumps(row, default=str)),
        )
        conn.commit()
    except Exception:
        logging.getLogger(__name__).debug(
            "swallowed exception in _spool_dispatch_row", exc_info=True)


def _flush_spool(conn) -> int:
    """Replay spooled journal rows into Postgres (called on every fresh
    connect and by ``flush_spool_now``). Bounded per call so one giant
    outage backlog can't dominate the latency of the dispatch that finally
    finds the lane up; the rest flushes on the next write's connect.

    Poison-row handling: a row that fails twice (e.g. its engagement slug
    was never registered — the arm-time registry upsert also degrades while
    down, so the FK refuses) is parked as a journal error row instead of
    wedging the queue head forever. A corrupt payload parks immediately.
    Deletes the spool row only AFTER the PG commit (delete-then-crash would
    lose the row; commit-then-no-delete just double-writes once).

    Failure ordering note: a spooled row replayed with a stale ``ts`` keeps
    its original wall-clock timestamp inside ``payload``-carried args, but
    ``journal.entries.ts`` lands at replay time. That skew is accepted — the
    alternative (client-side ts columns) the schema deliberately doesn't
    carry (server-clock discipline, same as live writes).
    """
    try:
        cur = conn.cursor()
        rows = _spool_conn().execute(
            "SELECT spool_id, payload, fail_count FROM journal_spool "
            "ORDER BY spool_id LIMIT ?",
            (_SPOOL_FLUSH_BATCH,),
        ).fetchall()
        if not rows:
            return 0
        replayed = 0
        for spool_id, payload, fail_count in rows:
            try:
                row = json.loads(payload)
            except (json.JSONDecodeError, TypeError):
                cur.execute(_DISPATCH_INSERT_SQL, _SPOOL_PARK_ROW())
                conn.commit()
                _drop_spooled(spool_id)
                replayed += 1
                continue
            try:
                cur.execute(_DISPATCH_INSERT_SQL, _spool_args(row))
                conn.commit()
                _drop_spooled(spool_id)
                replayed += 1
            except Exception as replay_exc:
                logging.getLogger(__name__).debug(
                    "swallowed exception in _flush_spool replay", exc_info=True)
                try:
                    conn.rollback()
                except Exception:
                    logging.getLogger(__name__).debug(
                        "swallowed rollback in _flush_spool replay", exc_info=True)
                if fail_count >= 1:
                    # second strike → poison-park into the journal itself
                    try:
                        cur.execute(
                            _DISPATCH_INSERT_SQL,
                            _park_row(row, f"spool replay failed twice: "
                                           f"{replay_exc}"))
                        conn.commit()
                        _drop_spooled(spool_id)
                        replayed += 1
                    except Exception:
                        logging.getLogger(__name__).debug(
                            "swallowed park-into-journal in _flush_spool",
                            exc_info=True)
                        try:
                            conn.rollback()
                        except Exception:
                            logging.getLogger(__name__).debug(
                                "swallowed park rollback in _flush_spool",
                                exc_info=True)
                    continue
                _bump_fail_count(spool_id)
                break
        return replayed
    except Exception:
        logging.getLogger(__name__).debug(
            "swallowed exception in _flush_spool", exc_info=True)
        try:
            conn.rollback()
        except Exception:
            logging.getLogger(__name__).debug(
                "swallowed rollback in _flush_spool", exc_info=True)
        return 0


def _bump_fail_count(spool_id: int) -> None:
    """Record a failed replay attempt (poison-row budget: one free retry)."""
    try:
        _spool_conn().execute(
            "UPDATE journal_spool SET fail_count = fail_count + 1 "
            "WHERE spool_id = ?", (spool_id,))
        _spool_conn().commit()
    except Exception:
        logging.getLogger(__name__).debug(
            "swallowed exception in _bump_fail_count", exc_info=True)


def _drop_spooled(spool_id: int) -> None:
    """Delete a successfully replayed spool row (after the PG commit)."""
    try:
        _spool_conn().execute(
            "DELETE FROM journal_spool WHERE spool_id = ?", (spool_id,))
        _spool_conn().commit()
    except Exception:
        logging.getLogger(__name__).debug(
            "swallowed exception in _drop_spooled", exc_info=True)


def _park_row(row: dict[str, Any], why: str) -> list[Any]:
    """A poisoned spool row parked into the journal as an honest error row:
    the dispatch happened and was lost — that fact is itself a finding. The
    FK-risky engagement slug is dropped (NULL) so the park always lands."""
    base = {k: row.get(k) for k in _SPOOL_KEYS}
    base["engagement"] = None
    base["status"] = "error"
    base["result_digest"] = (base.get("result_digest") or "")[:150]
    base["result_digest"] = (base["result_digest"] + " | " if
                             base["result_digest"] else "") + why
    for _jsonb_key in ("args", "envelope_meta"):
        if isinstance(base[_jsonb_key], (dict, list)):
            base[_jsonb_key] = json.dumps(base[_jsonb_key], default=str)
    return [base[k] for k in _SPOOL_KEYS]


def _SPOOL_PARK_ROW() -> list[Any]:
    """A parked envelope for a payload so corrupt it can't even be read —
    the record that a dispatch existed is never silently dropped."""
    return [
        None, None, "journal_spool_corrupt", json.dumps(
            {"error": "spool payload unparseable", "args": {}}),
        None, None, "0", None, "error", None, None, None,
        "spool row lost: payload unparseable", None,
    ]


def _spool_args(row: dict[str, Any]) -> list[Any]:
    """Rebuild the INSERT parameter list from a spooled row dict, filling
    None for any key a schema migration later added — spooled rows from an
    older process must still replay (INSERT uses all columns explicitly).
    The JSONB columns (args, envelope_meta) adapt as JSON STRINGS — a bare
    dict would hit psycopg without the Json wrapper and fail the insert.
    """
    vals = {k: row.get(k) for k in _SPOOL_KEYS}
    for _jsonb_key in ("args", "envelope_meta"):
        if isinstance(vals[_jsonb_key], (dict, list)):
            vals[_jsonb_key] = json.dumps(vals[_jsonb_key], default=str)
    return [vals[k] for k in _SPOOL_KEYS]


def _password_for(role: str) -> str:
    """Per-lane credential from env; defaults match the compose init scripts."""
    defaults = {
        "harness_operator": "harness_operator_change_me",
        "brain_lane": "harness_brain_change_me",
        "gateway_lane": "harness_gateway_change_me",
        "repl_lane": "harness_repl_change_me",
    }
    suffix = role.replace("harness_operator", "operator").replace("_lane", "").upper()
    env_key = f"HARNESS_DB_PASSWORD_{suffix}"
    return os.getenv(env_key, defaults.get(role, defaults["repl_lane"]))


def _ensure_engagement_row(slug: str, roe_note: str) -> None:
    """Registry upsert on arm. INSERT ... ON CONFLICT DO NOTHING (lanes hold
    INSERT/SELECT — an already-registered slug is fine, it just isn't
    re-written)."""
    conn = connect()
    if conn is None:
        return
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO engagement.engagements (slug, roe_note) "
                "VALUES (%s, %s) ON CONFLICT (slug) DO NOTHING",
                (slug, roe_note or None),
            )
        conn.commit()
    except Exception as exc:
        logger.debug("[engagement] registry upsert skipped: %s", exc)
        try:
            conn.rollback()
        except Exception:
            logging.getLogger(__name__).debug(
                "swallowed exception in _ensure_engagement_row", exc_info=True)


# ─── Operator actions (run under harness_operator) ───────────────────────────


def close_and_purge(slug: str) -> list[tuple[str, int]]:
    """Close + purge an engagement as the operator. The ONLY erasure path.

    Called from the REPL (``engagement purge <slug>``). Fails closed when the
    engagement isn't closed — but this call closes it, mirroring the closing
    runbook: export findings (render_findings markdown lane) first, then
    purge here. Returns [(store, deleted), ...].
    """
    conn = connect(role="harness_operator", force=True)
    if conn is None:
        raise RuntimeError("Postgres unavailable — purge not performed")
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE engagement.engagements SET closed_at = now() "
            "WHERE slug = %s AND closed_at IS NULL", (slug,)
        )
        if cur.rowcount == 0:
            conn.rollback()
            raise RuntimeError(
                f"engagement {slug!r} unknown or already closed"
            )
        cur.execute("SELECT store, deleted FROM engagement.purge(%s)", (slug,))
        rows = [(r[0], int(r[1])) for r in cur.fetchall()]
    conn.commit()
    return rows


def sweep() -> int:
    """Run the retention sweep (expired OPEN evidence + past-TTL journal args).

    Called lazily after journal writes — the scratch/cookie-jar
    purge-on-mutation pattern. Best-effort: returns -1 when Postgres is down.
    """
    conn = connect()
    if conn is None:
        return -1
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT engagement.sweep_expired()")
            gone = int(cur.fetchone()[0])
        conn.commit()
        return gone
    except Exception as exc:
        logger.debug("[engagement] sweep skipped: %s", exc)
        try:
            conn.rollback()
        except Exception:
            logging.getLogger(__name__).debug("swallowed exception in sweep", exc_info=True)
        return -1


def db_status() -> dict[str, Any]:
    """Diagnostics for framework_doctor / REPL: is the lane connected, as
    which role, and what's armed. ``reason`` explains a False ``connected``
    (driver absent vs cluster unreachable) so the operator fixes the right
    half of the lane instead of re-arming passwords that already match."""
    conn = connect()
    connected = False
    version = None
    if conn is not None:
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT version()")
                version = str(cur.fetchone()[0]).split(",")[0]
            connected = True
        except Exception:
            conn = None
    return {
        "connected": connected,
        "role": _DB["connected_as"] if connected else _lane_role(),
        "server": version,
        "backoff_window_s": _RECONNECT_BACKOFF_S,
        "spooled_rows": spooled_count(),
        "armed_engagement": (current() or {}).get("slug"),
        "reason": None if connected else _DB.get("last_error"),
    }


def spooled_count() -> int:
    """Journal rows parked in ids.db waiting for the lane to come back.
    Zero when the spool table is empty or ids.db is unreadable from here."""
    try:
        conn = _spool_conn()
        row = conn.execute("SELECT COUNT(*) FROM journal_spool").fetchone()
        return int(row[0]) if row else 0
    except Exception:
        logging.getLogger(__name__).debug(
            "swallowed exception in spooled_count", exc_info=True)
        return 0


def flush_spool_now() -> dict[str, Any]:
    """Operator/manual flush: reconnect (force through the backoff) and
    replay everything currently spooled. The cached live connection also
    works — force only bypasses the backoff window. connect() itself flushes
    on a fresh connection, so the report is diffed from the backlog count,
    not from the loop counter (which would miss the connect-time flush)."""
    before = spooled_count()
    conn = connect(force=True)
    if conn is None:
        return {"flushed": 0, "remaining": spooled_count(),
                "reason": _DB.get("last_error") or "Postgres unavailable"}
    while True:
        n = _flush_spool(conn)
        if n <= 0:
            break
    after = spooled_count()
    return {"flushed": max(0, before - after), "remaining": after,
            "reason": None}