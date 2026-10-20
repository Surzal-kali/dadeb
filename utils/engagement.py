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
stores: a down/absent Postgres degrades every consumer silently (journaling
skipped, evidence falls back to SQLite), never breaking a tool. One cached
connection per process, one reconnect-backoff window so a down server never
pins the dispatch path.

Roles (dockered/postgres/init/001_roles.sh): lanes authenticate per-lane
(brain_lane/gateway_lane/repl_lane via ``HARNESS_DB_LANE``); the operator
session (harness_operator) is the only identity allowed to run
``engagement.purge()`` — the audit-trail eraser stays human-only, the same
authority model as scope arming.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from constants import resolve_workspace_root

logger = logging.getLogger(__name__)

# ─── Armed state (file-backed, REPL-owned) ───────────────────────────────────


def _state_path() -> Path:
    """Resolve the armed-state file at CALL time (scope_gate convention)."""
    return resolve_workspace_root() / "engagement" / ".armed_engagement.json"


_ARMED_CACHE: Dict[str, Any] = {"mtime": None, "state": None}


def _write_state(state: Dict[str, Any]) -> None:
    """Atomic state write (scope_gate convention: stage + os.replace, so a
    crash never leaves a torn file that would parse as disarmed)."""
    p = _state_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(state, indent=2))
    os.replace(tmp, p)
    _ARMED_CACHE["mtime"] = p.stat().st_mtime
    _ARMED_CACHE["state"] = state


def current() -> Optional[Dict[str, Any]]:
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


def current_slug() -> Optional[str]:
    """The armed engagement slug, or None (rows written while unarmed carry
    NULL engagement — they still journal, they're just not cobwebbed)."""
    st = current()
    if not st:
        return None
    slug = str(st.get("slug") or "").strip()
    return slug or None


def arm(slug: str, roe_note: str = "") -> Dict[str, Any]:
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


# ─── Postgres lane connection (lazy, cached, degrade-silently) ───────────────

_RECONNECT_BACKOFF_S = 30.0
_DB: Dict[str, Any] = {
    "conn": None,
    "down_until": 0.0,     # monotonic — skip attempts while inside the window
    "connected_as": None,  # lane role name of the cached connection
    "warned": False,       # one-time absence warning
}

_INFERRED_LANE: Optional[str] = None


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


def _host_candidates() -> List[str]:
    """Postgres endpoints to try, ordered. Explicit ``HARNESS_DB_HOST`` wins
    (single candidate). Default order is lane-safe in this stack's topology:
    the compose service name 'postgres' (container lanes on the workbench
    network resolve it; host-lane processes fail the lookup instantly) then
    the host-published loopback ('127.0.0.1', the host lane's reach). The
    workbench bridge IP '172.28.0.20' is a pinned-subnet fallback for lanes
    that never see DNS.
    """
    explicit = os.getenv("HARNESS_DB_HOST", "").strip()
    if explicit:
        return [explicit]
    return ["postgres", "127.0.0.1", "172.28.0.20"]


def lane_name() -> str:
    """Cheap lane attribution for journal rows — no DB roundtrip (the
    authenticated role IS the lane identity; this env var is set per-process
    at boot to match it)."""
    return _lane_role()


def db_down() -> bool:
    """True while inside the reconnect-backoff window (cheap fast-pathcheck)."""
    return time.monotonic() < _DB["down_until"]


def connect(*, role: Optional[str] = None, force: bool = False):
    """A live psycopg connection for the lane (or a named role), or None.

    Postgres absent / down / psycopg not installed → None, logged once at
    debug level (the engagement lane is additive; nothing may depend on it
    to the point of breaking a tool). Reconnects are rate-limited by the
    backoff window so a down container never pins dispatch.
    """
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
        if not _DB["warned"]:
            _DB["warned"] = True
            logger.debug(
                "[engagement] psycopg not installed — engagement/journal DB "
                "lane disabled (pip install 'psycopg[binary]' to enable)"
            )
        _DB["down_until"] = now + _RECONNECT_BACKOFF_S
        return None

    user = role
    password = _password_for(role)
    port = os.getenv("HARNESS_DB_PORT", "5432")
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
        if not _DB["warned"]:
            _DB["warned"] = True
            logger.info(
                "[engagement] Postgres unavailable (%s) — journal/evidence DB "
                "lane stays optional; will retry every %.0fs", last_exc,
                _RECONNECT_BACKOFF_S,
            )
        _DB["down_until"] = now + _RECONNECT_BACKOFF_S
        _DB["conn"] = None
        return None

    _DB["conn"] = conn
    _DB["connected_as"] = role
    _DB["down_until"] = 0.0
    return conn


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
            pass


# ─── Operator actions (run under harness_operator) ───────────────────────────


def close_and_purge(slug: str) -> List[Tuple[str, int]]:
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
            pass
        return -1


def db_status() -> Dict[str, Any]:
    """Diagnostics for framework_doctor / REPL: is the lane connected, as
    which role, and what's armed."""
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
        "armed_engagement": (current() or {}).get("slug"),
    }