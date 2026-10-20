"""Direct-database client tools: connect with KNOWN credentials and enumerate.

This is the direct-connection lane for databases.  It is deliberately NOT the
injection lane: if the only path to the data is an injectable web parameter,
use ``run_sqlmap`` (payloads/sqlmap.py).  Here the caller already holds valid
credentials (won via hydra, secretsdump, a config leak, ...) and wants to
speak the wire protocol directly: authenticate, enumerate, dump.

Tools (mirroring the ssh lane's two shapes):
    db_connect     - open a persistent connection, return a ``db:sess-NNNN``
                     typed handle (utils.handles kind "db")
    db_exec        - run one query on an existing ``db:`` handle
    db_exec_batch  - stateless connect-once batch on one connection
                     (the auxiliaries/ssh_exec.py pattern: one TCP connect,
                     N queries, per-query results, close)
    db_schema_farm - the composite: databases -> tables (+row counts) ->
                     columns -> interest-ranked sample rows, capped, one call
    db_close       - tear down a ``db:`` handle

Drivers (v1, option-3 per operator decision 2026-09-22):
    mssql     - impacket.tds (ALREADY in the venv via impacket; zero new deps).
                SQL auth, domain auth (``domain=``) and pass-the-hash
                (``hashes="lm:nt"``).
    mysql     - pymysql (lazy import; pip install pymysql)
    postgres  - pg8000.native (lazy import; pip install pg8000)
    Installing the drivers makes the mysql/postgres paths work with NO code
    change and NO reindex (call-time preflight, like the jadx binary probe).

Safety posture (read-only by default):
    ``db_exec`` / ``db_exec_batch`` take ``read_only=True`` (default).  The
    guard is a HEURISTIC SEATBELT, not a sandbox: first-word allowlist
    (select/with/use/set/declare), semicolon refused (multi-statement batches
    are how xp_cmdshell-class payloads chain), and a denylist of the known
    file/privesc primitives (xp_, sp_oacreate, openrowset, openquery,
    into outfile, load_file, load data, bulk insert).  ``read_only=False``
    is the explicit operator-approved write/EXEC lane (labs).  Queries are
    passed verbatim to the server - no shell interpolation anywhere.

Caps (stated truncation policy): rows, cells, tables and databases returned
are all bounded (db_exec max_rows, schema_farm max_dbs/max_tables/
max_columns/sample counts, per-cell char cap).  A query that runs longer than
``timeout`` surfaces as that query's error via the socket timeout - the
dispatch timeout (BRAIN_DISPATCH_TIMEOUT) is never what catches a wedged query.

Scope gate: every traffic-facing tool calls utils.scope_gate.check_scan at
entry (and per exec for handle sessions, mirroring paramiko_client) - the
same 2026-09-19 coverage rule that closed the sqlmap/fastcgi/ssh_exec gap.

Disambiguation vs sqlmap: sqlmap = SQL INJECTION against a web parameter
(attack verb).  These tools = DIRECT connection with valid credentials
(access verb).  Cross-hints are wired in the descriptions both directions.

Live-test battery owed (runtime seat, after commit + reindex + restart):
db_connect -> db_schema_farm against a lab MSSQL (GOAD-class) and, once the
drivers are installed, db_exec_batch against Metasploitable2 3306 (mysql).
"""

from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional, Tuple

from constants import framework_tool
from utils.handles import format_handle, parse_handle
from utils.session_manager import get_manager
# Module-level (not function-local) so callers/tests can catch the exception
# type without importing scope_gate themselves. check_scan STAYS a
# function-local import in _gated - call-time resolution is what makes the
# test seam (patch utils.scope_gate.check_scan) work.
from utils.scope_gate import ScopeGateError

from impacket.tds import MSSQL, SQLErrorException

_sm = get_manager()

# --- module constants (caps + defaults) -----------------------------------

HANDLE_KIND = "db"
DEFAULT_TIMEOUT = 10            # TCP connect + per-query read timeout (s)
DEFAULT_PACE = 0.1              # seconds between queries in batch
MAX_ROWS_EXEC = 200             # default row cap for db_exec / db_exec_batch
MAX_QUERIES_BATCH = 32          # hard cap on queries per batch call
EXEC_CELL_CAP = 512             # per-cell char cap in exec envelopes
FARM_CELL_CAP = 120             # per-cell char cap in schema-farm samples
FARM_SAMPLE_ROWS = 3            # sample rows per interesting table

# Statements "read-only" still allows as a first word (heuristic seatbelt).
_READONLY_FIRST_WORDS = {"select", "with", "use", "set", "declare"}
# Known file-read/privesc primitives; refused outright under read_only.
_READONLY_DENY = (
    "xp_",
    "sp_oacreate",
    "openrowset",
    "openquery",
    "opendatasource",
    "into outfile",
    "load_file",
    "load data",
    "bulk insert",
    ";",  # multi-statement batches: only the LAST result set survives TDS
)
# Table-name interest ranking for sample rows (credential-shaped tables first).
_INTERESTING_RE = re.compile(
    r"(passw|cred|user|login|account|admin|token|secret|api_key|apikey|"
    r"config|email|customer|session|auth)",
    re.IGNORECASE,
)


class _DriverMissing(Exception):
    """Lazy driver import failed -> clean pip-install envelope, not a traceback."""


# ---------------------------------------------------------------------------
# connection adapters
# ---------------------------------------------------------------------------
# Each adapter exposes: .query(sql) -> (rows, error) and .close().
# Rows are ALWAYS normalized to a list of dicts (column name -> value), which
# is what impacket's batch(tuplemode=False) already yields for MSSQL
# (parseRow: "row = [] if tuplemode else {}" - dicts are the DEFAULT mode).


class _MssqlConn:
    """Adapter around impacket.tds.MSSQL; .close() so SessionManager tears it down."""

    def __init__(self, ms: MSSQL):
        self._ms = ms

    def query(self, sql: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        try:
            rows = self._ms.batch(sql, tuplemode=False)
        except Exception as exc:  # socket timeout / dead connection
            return [], f"MSSQL query failed: {exc}"
        error: Optional[str] = None
        errors: List[str] = []
        try:
            self._ms.printReplies(error_logger=errors.append, info_logger=lambda *_a: None)
        except Exception as exc:  # never let message-draining mask the rows
            return rows, f"MSSQL reply drain failed: {exc}"
        if isinstance(self._ms.lastError, SQLErrorException):
            error = str(self._ms.lastError)
        elif errors:
            error = errors[0]
        return rows, error

    def close(self) -> None:
        try:
            self._ms.disconnect()
        except Exception:
            pass


class _MysqlConn:
    """Adapter around a pymysql connection (DictCursor)."""

    def __init__(self, conn: Any, fetch_cap: int = 5000):
        self._conn = conn
        self._fetch_cap = fetch_cap

    def query(self, sql: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        try:
            cur = self._conn.cursor()
            cur.execute(sql)
            rows = [dict(r) for r in cur.fetchmany(self._fetch_cap)]
            return rows, None
        except Exception as exc:
            return [], f"MySQL query failed: {exc}"

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass


class _PgConn:
    """Adapter around pg8000.native.Connection (run() -> rows + columns)."""

    def __init__(self, conn: Any):
        self._conn = conn

    def query(self, sql: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        try:
            data = self._conn.run(sql)
            names = [c["name"] for c in (self._conn.columns or [])]
            rows = [dict(zip(names, r)) for r in data]
            return rows, None
        except Exception as exc:
            return [], f"PostgreSQL query failed: {exc}"

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass


def _open_mssql(host, port, username, password, database, domain, hashes, timeout):
    """impacket.tds path - works with the impacket already in the venv."""
    ms = MSSQL(host, port=int(port))
    ms.connect(timeout=float(timeout))
    # login(database, username, password="", domain="", hashes=None,
    #       useWindowsAuth=False); hashes = "lm:nt" hex pair for pass-the-hash.
    ms.login(
        database if database else None,
        username,
        password=password or "",
        domain=domain or "",
        hashes=hashes if hashes else None,
    )
    return _MssqlConn(ms)


def _open_mysql(host, port, username, password, database, timeout):
    try:
        import pymysql
    except ImportError as exc:
        raise _DriverMissing(
            "MySQL driver 'pymysql' is not installed in the framework venv. "
            "Fix: pip install pymysql (call-time preflight; no reindex needed)."
        ) from exc
    conn = pymysql.connect(
        host=host,
        port=int(port),
        user=username,
        password=password or "",
        database=database if database else None,
        connect_timeout=int(timeout),
        read_timeout=int(timeout),
        cursorclass=pymysql.cursors.DictCursor,
    )
    return _MysqlConn(conn)


def _open_postgres(host, port, username, password, database, timeout):
    try:
        import pg8000.native
    except ImportError as exc:
        raise _DriverMissing(
            "PostgreSQL driver 'pg8000' is not installed in the framework venv. "
            "Fix: pip install pg8000 (call-time preflight; no reindex needed)."
        ) from exc
    conn = pg8000.native.Connection(
        username,
        host=host,
        port=int(port),
        password=password or "",
        database=database if database else "postgres",
        timeout=int(timeout),
    )
    return _PgConn(conn)


_DBMS_ALIASES = {"postgresql": "postgres", "mssqlserver": "mssql"}


def _normalize_dbms(dbms: str) -> Optional[str]:
    d = (dbms or "").strip().lower()
    d = _DBMS_ALIASES.get(d, d)
    return d if d in {"mssql", "mysql", "postgres"} else None


def _open_connection(
    dbms: str,
    host: str,
    port: int,
    username: str,
    password: str,
    database: str = "",
    domain: str = "",
    hashes: str = "",
    timeout: float = DEFAULT_TIMEOUT,
):
    """Driver dispatch (call-time lookup of the _open_* functions so tests can
    patch them by module attribute). Raises _DriverMissing or driver errors."""
    if dbms == "mssql":
        return _open_mssql(host, port, username, password, database, domain, hashes, timeout)
    if dbms == "mysql":
        return _open_mysql(host, port, username, password, database, timeout)
    return _open_postgres(host, port, username, password, database, timeout)


# ---------------------------------------------------------------------------
# helpers: gate, guard, envelopes, caps
# ---------------------------------------------------------------------------


def _gated(host: str) -> None:
    """Scope-gate a host (operator-armed; no-op when disarmed). Fail-closed."""
    # check_scan resolves at CALL time (local import) - patching
    # utils.scope_gate.check_scan is the offline test seam.
    from utils.scope_gate import check_scan

    _sc_ok, _sc_reason = check_scan(host)
    if not _sc_ok:
        raise ScopeGateError(f"scope gate: {_sc_reason}")


def _brack(name: str) -> str:
    """MSSQL bracket-escape an identifier that came from the server catalog."""
    return "[" + str(name).replace("]", "]]") + "]"


def _read_only_violation(query: str) -> Optional[str]:
    """Heuristic read-only seatbelt (see module docstring honesty note)."""
    q = query.strip()
    # Skip leading line comments so '-- comment\nselect 1' still classifies.
    while q.startswith("--"):
        q = q.split("\n", 1)[1].strip() if "\n" in q else ""
        if not q:
            return "empty statement after comment stripping"
    lowered = q.lower()
    for token in _READONLY_DENY:
        if token in lowered:
            return f"read_only=True refuses {token!r} (set read_only=False explicitly)"
    first = lowered.split(None, 1)[0] if lowered else ""
    if first.rstrip(";") not in _READONLY_FIRST_WORDS:
        return (
            f"read_only=True allows only "
            f"{sorted(_READONLY_FIRST_WORDS)}-leading statements; first word was "
            f"{first!r} (use read_only=False for writes/EXEC - operator-approved)"
        )
    return None


def _cap_cell(value: Any, cap: int) -> Any:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    text = value if isinstance(value, str) else repr(value)
    if len(text) > cap:
        return text[:cap] + f"...[+{len(text) - cap} chars]"
    return value


def _cap_rows(
    rows: List[Any], max_rows: int, cell_cap: int
) -> Tuple[List[Any], bool]:
    """Bound rows + cells. Returns (capped_rows, truncated_flag)."""
    truncated = len(rows) > max_rows
    out = []
    for row in rows[:max_rows]:
        if isinstance(row, dict):
            out.append({str(k): _cap_cell(v, cell_cap) for k, v in row.items()})
        else:  # driver returned a list-row (defensive)
            out.append([_cap_cell(v, cell_cap) for v in row])
    return out, truncated


def _fail(error: str, **extra: Any) -> Dict[str, Any]:
    env = {"status": "Failed", "error": error}
    env.update(extra)
    return env


def _target_label(username: str, domain: str, host: str, port: int) -> str:
    user = f"{domain}\\{username}" if domain else username
    return f"{user}@{host}:{port}"


def _drain_query(conn, sql: str, max_rows: int, cell_cap: int) -> Dict[str, Any]:
    """Run one query on an adapter; envelope entry with caps + error text."""
    rows, error = conn.query(sql)
    capped, truncated = _cap_rows(rows or [], max_rows, cell_cap)
    entry: Dict[str, Any] = {
        "query": sql,
        "row_count": len(rows or []),
        "rows": capped,
        "error": error,
    }
    if truncated:
        entry["rows_truncated"] = True
    return entry


# ---------------------------------------------------------------------------
# tools
# ---------------------------------------------------------------------------


@framework_tool(
    "Connect to a database server with KNOWN credentials and return a typed "
    "'db:sess-NNNN' handle for db_exec / db_close (db_schema_farm takes creds "
    "directly). Supports MSSQL (impacket, out of the box; domain= and hashes= "
    "'lm:nt' pass-the-hash), MySQL (pip install pymysql) and PostgreSQL "
    "(pip install pg8000). Use this for direct database enumeration once "
    "credentials are in hand; for SQL-injection testing through a web "
    "parameter use run_sqlmap instead.",
    next_hints=["db_exec", "db_schema_farm", "db_close"],
    tags=["net.services"],
)
def db_connect(
    host: str,
    username: str,
    password: str,
    port: int = 1433,
    dbms: str = "mssql",
    database: str = "",
    domain: str = "",
    hashes: str = "",
    timeout: float = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """Open a persistent database connection; return a ``db:`` session handle.

    Args:
        host: Target IP or hostname.
        username: Database username (SQL auth or domain principal).
        password: Password (ignored when ``hashes`` is set for MSSQL).
        port: Database port (1433 mssql / 3306 mysql / 5432 postgres).
        dbms: 'mssql' (default), 'mysql', or 'postgres'.
        database: Initial database (optional; server default when empty).
        domain: Windows domain for MSSQL domain auth (e.g. 'CORP').
        hashes: MSSQL pass-the-hash as 'lm:nt' hex (e.g. 'aad3b...:31d6...').
        timeout: Connect + per-query read timeout in seconds.
    """
    _gated(host)
    dbms_n = _normalize_dbms(dbms)
    if dbms_n is None:
        return _fail(f"unsupported dbms {dbms!r}; supported: mssql, mysql, postgres")
    try:
        conn = _open_connection(
            dbms_n, host, int(port), username, password, database, domain, hashes, timeout
        )
    except _DriverMissing as exc:
        return _fail(str(exc))
    except Exception as exc:
        return _fail(f"{dbms_n} connection to {username}@{host}:{port} failed: {exc}")
    target = _target_label(username, domain, host, int(port))
    sid = _sm.register(
        "db", target, conn, hostname=host, username=username, dbms=dbms_n, port=int(port)
    )
    handle = format_handle("db", sid)
    return {
        "status": "Success",
        "handle": handle,
        "target": target,
        "dbms": dbms_n,
        "database": database or "(server default)",
        "message": (
            f"DB session established: {handle}. Use with db_exec / db_close; "
            "db_schema_farm is stateless (takes creds directly)."
        ),
    }


@framework_tool(
    "Run one SQL query on an existing 'db:' handle (from db_connect). "
    "read_only=True (default) is a heuristic seatbelt: select/with/use/set/"
    "declare only, no semicolons, no xp_/openrowset-class primitives. Set "
    "read_only=False only when writes or EXEC are deliberately wanted. For "
    "injection testing use run_sqlmap; for a query batch without a session "
    "use db_exec_batch.",
    accepted_handle_kinds=["db"],
    next_hints=["db_exec", "report_finding", "db_close"],
    tags=["net.services"],
)
def db_exec(handle: str, query: str, read_only: bool = True) -> Dict[str, Any]:
    """Run a query on an open ``db:`` handle; the session stays open.

    Args:
        handle: The 'db:sess-NNNN' handle returned by db_connect.
        query: SQL text (passed verbatim; one statement per query for clean rows).
        read_only: Seatbelt (module docstring). False = explicit write/EXEC lane.
    """
    kind, sid = parse_handle(handle)
    session = _sm.get(sid)
    if session is None:
        return _fail(
            f"DB session {handle} not found. Call db_connect first, or use "
            "list_sessions to see active sessions."
        )
    host = session.metadata.get("hostname", "")
    # Re-gate per exec: a session opened before the operator armed/narrowed the
    # scope must not keep querying after the change (paramiko ssh_exec pattern).
    _gated(host)
    if read_only:
        violation = _read_only_violation(query)
        if violation:
            return _fail(violation)
    conn = session.client
    rows, error = conn.query(query)
    session.touch()
    if error and not rows:
        return {
            "status": "Failed",
            "handle": handle,
            "target": session.target,
            "query": query,
            "error": error,
            "note": "connection may be dead: db_close and reconnect if this persists",
        }
    capped, truncated = _cap_rows(rows or [], MAX_ROWS_EXEC, EXEC_CELL_CAP)
    env: Dict[str, Any] = {
        "status": "Success",
        "handle": handle,
        "target": session.target,
        "query": query,
        "row_count": len(rows or []),
        "rows": capped,
    }
    if truncated:
        env["rows_truncated"] = True
        env["note"] = f"rows capped at {MAX_ROWS_EXEC}; narrow the query for more"
    if error:
        env["server_error"] = error
    return env


@framework_tool(
    "Connect to a database server once and run a batch of SQL queries on the "
    "same connection (stateless - no handle to manage), then close. Supports "
    "MSSQL (default; domain/hash pass-the-hash), MySQL (pip install pymysql) "
    "and PostgreSQL (pip install pg8000). Per-query rows + errors returned. "
    "This is the direct-credential lane; run_sqlmap is the injection lane.",
    next_hints=["report_finding", "db_connect"],
    tags=["net.services"],
)
def db_exec_batch(
    host: str,
    username: str,
    password: str,
    queries: List[str],
    port: int = 1433,
    dbms: str = "mssql",
    database: str = "",
    domain: str = "",
    hashes: str = "",
    read_only: bool = True,
    pace: float = DEFAULT_PACE,
    timeout: float = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """Connect once, run N queries on the same connection, close.

    The db analogue of ``ssh_exec_batch``: one TCP connect, one handshake,
    every query on the shared connection, paced, then close.  Use when you
    know the queries up front; use ``db_connect`` + ``db_exec`` when each
    query depends on the previous result.

    Args:
        host: Target IP or hostname.
        username: Database username.
        password: Password (or empty with MSSQL ``hashes``).
        queries: SQL statements, in order. One statement per entry (a
            semicolon is refused under read_only, and multi-statement batches
            would only surface the last result set anyway).
        port: Database port (1433 mssql / 3306 mysql / 5432 postgres).
        dbms: 'mssql' (default), 'mysql', or 'postgres'.
        database: Initial database (optional).
        domain: Windows domain for MSSQL domain auth.
        hashes: MSSQL pass-the-hash 'lm:nt' hex pair.
        read_only: Heuristic seatbelt (module docstring). False = operator-approved.
        pace: Seconds between queries.
        timeout: Connect + per-query read timeout (seconds).
    """
    _gated(host)
    dbms_n = _normalize_dbms(dbms)
    if dbms_n is None:
        return _fail(f"unsupported dbms {dbms!r}; supported: mssql, mysql, postgres")
    if isinstance(queries, str):
        queries = [queries]
    if not isinstance(queries, list) or not queries or not all(
        isinstance(q, str) for q in queries
    ):
        return _fail("'queries' must be a non-empty list of SQL strings")
    if len(queries) > MAX_QUERIES_BATCH:
        return _fail(f"queries capped at {MAX_QUERIES_BATCH} per call")
    if read_only:
        for q in queries:
            violation = _read_only_violation(q)
            if violation:
                return _fail(f"query rejected: {violation}; query: {q[:200]}")
    try:
        conn = _open_connection(
            dbms_n, host, int(port), username, password, database, domain, hashes, timeout
        )
    except _DriverMissing as exc:
        return _fail(str(exc))
    except Exception as exc:
        return _fail(f"{dbms_n} connection to {username}@{host}:{port} failed: {exc}")

    results: List[Dict[str, Any]] = []
    try:
        for idx, q in enumerate(queries):
            results.append(_drain_query(conn, q, MAX_ROWS_EXEC, EXEC_CELL_CAP))
            if pace > 0 and idx < len(queries) - 1:
                time.sleep(float(pace))
    finally:
        try:
            conn.close()
        except Exception:
            pass

    ok = sum(1 for r in results if not r.get("error"))
    return {
        "status": "Success" if ok else "Failed",
        "target": _target_label(username, domain, host, int(port)),
        "dbms": dbms_n,
        "queries_run": len(results),
        "succeeded": ok,
        "failed": len(results) - ok,
        "results": results,
    }


@framework_tool(
    "Farm a database server's schema in one call with known credentials: "
    "databases -> tables (with row counts) -> columns -> sample rows from "
    "credential-shaped tables (users/passwords/tokens...), all capped. "
    "Direct-connection enumeration for credentials you already hold - NOT "
    "SQL injection (that is run_sqlmap). MSSQL supported today (impacket); "
    "MySQL/PostgreSQL farms via db_exec_batch + information_schema.",
    next_hints=["report_finding", "db_connect"],
    tags=["net.services"],
)
def db_schema_farm(
    host: str,
    username: str,
    password: str,
    port: int = 1433,
    dbms: str = "mssql",
    database: str = "",
    domain: str = "",
    hashes: str = "",
    max_dbs: int = 20,
    max_tables: int = 100,
    max_columns: int = 1000,
    include_samples: bool = True,
    sample_tables: int = 5,
    timeout: float = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """Enumerate databases, tables, columns and interest-ranked samples.

    One connect, a bounded query plan (2 queries per database plus up to
    ``sample_tables`` SELECT TOP 3 reads), then close.  MSSQL uses three-part
    naming ([db].sys.tables / [db].INFORMATION_SCHEMA.COLUMNS) so no USE
    context switches are needed.  Identifiers coming back from the server
    catalog are bracket-escaped before interpolation.

    Args:
        host: Target IP or hostname.
        username: Database username.
        password: Password (or empty with MSSQL ``hashes``).
        port: Database port (1433 default).
        dbms: 'mssql' today; mysql/postgres farms land via db_exec_batch.
        database: Initial database (optional).
        domain: Windows domain for MSSQL domain auth.
        hashes: MSSQL pass-the-hash 'lm:nt'.
        max_dbs: Cap on databases farmed.
        max_tables: Cap on tables returned (total).
        max_columns: Cap on column rows returned (total).
        include_samples: Pull TOP 3 rows from interest-ranked tables
            (user/pass/token/config-shaped names); off for structure-only.
        sample_tables: Cap on sampled tables.
        timeout: Connect + per-query read timeout (seconds).
    """
    _gated(host)
    dbms_n = _normalize_dbms(dbms)
    if dbms_n is None:
        return _fail(f"unsupported dbms {dbms!r}; supported: mssql, mysql, postgres")
    if dbms_n != "mssql":
        return _fail(
            f"schema farm for {dbms_n} not implemented in this skeleton; use "
            "db_exec_batch with information_schema queries (MySQL: "
            "SCHEMATA/TABLES/COLUMNS; PostgreSQL: pg_catalog), or extend "
            "auxiliaries/db_client.py with a farm plan for that driver."
        )
    try:
        conn = _open_connection(
            dbms_n, host, int(port), username, password, database, domain, hashes, timeout
        )
    except _DriverMissing as exc:
        return _fail(str(exc))
    except Exception as exc:
        return _fail(f"{dbms_n} connection to {username}@{host}:{port} failed: {exc}")

    notes: List[str] = []
    try:
        dbs_raw, err = conn.query(
            "SELECT name FROM sys.databases WHERE HAS_DBACCESS(name) = 1 ORDER BY name"
        )
        if err and not dbs_raw:
            return _fail(f"schema farm failed at database listing: {err}")
        db_names = [r.get("name") for r in dbs_raw if r.get("name")]
        if len(db_names) > max_dbs:
            notes.append(f"databases truncated at max_dbs={max_dbs} (had {len(db_names)})")
            db_names = db_names[:max_dbs]

        databases: List[Dict[str, Any]] = []
        tables_seen = 0
        tables_truncated = False
        columns_seen = 0
        columns_truncated = False

        for db in db_names:
            q_tables = (
                f"SELECT s.name AS schema_name, t.name AS table_name, "
                f"SUM(p.rows) AS row_count FROM {_brack(db)}.sys.tables AS t "
                f"JOIN {_brack(db)}.sys.schemas AS s ON t.schema_id = s.schema_id "
                f"LEFT JOIN {_brack(db)}.sys.partitions AS p "
                f"ON p.object_id = t.object_id AND p.index_id IN (0,1) "
                f"GROUP BY s.name, t.name ORDER BY t.name"
            )
            trows, terr = conn.query(q_tables)
            if terr:
                notes.append(f"{db}: table listing error: {terr}")
                continue
            entries: List[Dict[str, Any]] = []
            for r in trows:
                if tables_seen >= max_tables:
                    tables_truncated = True
                    break
                entries.append(
                    {
                        "schema": r.get("schema_name"),
                        "table": r.get("table_name"),
                        "row_count": r.get("row_count"),
                        "columns": [],
                    }
                )
                tables_seen += 1
            if tables_truncated:
                notes.append(f"tables truncated at max_tables={max_tables} (in {db})")

            q_cols = (
                f"SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE "
                f"FROM {_brack(db)}.INFORMATION_SCHEMA.COLUMNS "
                f"ORDER BY TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION"
            )
            crows, cerr = conn.query(q_cols)
            if cerr:
                notes.append(f"{db}: column listing error: {cerr}")
            col_index: Dict[Tuple[str, str], List[str]] = {}
            for r in crows:
                if columns_seen >= max_columns:
                    columns_truncated = True
                    break
                key = (str(r.get("TABLE_SCHEMA")), str(r.get("TABLE_NAME")))
                col = f"{r.get('COLUMN_NAME')} ({r.get('DATA_TYPE')})"
                col_index.setdefault(key, []).append(col)
                columns_seen += 1
            for e in entries:
                e["columns"] = col_index.get((str(e["schema"]), str(e["table"])), [])
            databases.append(
                {
                    "name": db,
                    "tables": entries,
                    "tables_truncated": tables_truncated,
                }
            )

        samples: List[Dict[str, Any]] = []
        if include_samples:
            sampled = 0
            for d in databases:
                if sampled >= sample_tables:
                    break
                for e in d["tables"]:
                    if sampled >= sample_tables:
                        break
                    name = str(e.get("table") or "")
                    if not _INTERESTING_RE.search(name):
                        continue
                    q_sample = (
                        f"SELECT TOP {FARM_SAMPLE_ROWS} * FROM "
                        f"{_brack(d['name'])}.{_brack(str(e['schema']))}."
                        f"{_brack(name)}"
                    )
                    srows, serr = conn.query(q_sample)
                    capped, _trunc = _cap_rows(srows or [], FARM_SAMPLE_ROWS, FARM_CELL_CAP)
                    samples.append(
                        {
                            "database": d["name"],
                            "schema": e["schema"],
                            "table": name,
                            "rows": capped,
                            "error": serr,
                        }
                    )
                    sampled += 1
            if not samples:
                notes.append("no interest-ranked tables matched the sample heuristic")
    finally:
        try:
            conn.close()
        except Exception:
            pass

    if columns_truncated:
        notes.append(f"columns truncated at max_columns={max_columns}")
    return {
        "status": "Success",
        "target": _target_label(username, domain, host, int(port)),
        "dbms": dbms_n,
        "databases": databases,
        "samples": samples,
        "notes": notes,
        "policy": (
            f"caps: max_dbs={max_dbs}, max_tables={max_tables}, "
            f"max_columns={max_columns}, samples={sample_tables}x{FARM_SAMPLE_ROWS} rows; "
            "structure is read-only by construction (tool-composed queries only)"
        ),
    }


@framework_tool(
    "Close a 'db:' database session handle (from db_connect). The underlying "
    "connection is closed and the session removed from the store. Pass the "
    "db: handle; use list_sessions to find active ones.",
    accepted_handle_kinds=["db"],
    tags=["net.services"],
)
def db_close(handle: str) -> Dict[str, Any]:
    """Tear down a ``db:`` session.

    Teardown-only: closes the existing socket, no new target interaction, so
    no scope gate (consistent with other close/teardown tools).

    Args:
        handle: The 'db:sess-NNNN' handle to close.
    """
    kind, sid = parse_handle(handle)
    closed = _sm.close(sid)
    if not closed:
        return _fail(f"DB session {handle} not found (already closed?). Use list_sessions.")
    return {"status": "Success", "handle": handle, "closed": True}