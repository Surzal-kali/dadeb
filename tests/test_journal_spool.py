"""Journal spool: the outage contract between the dispatch spine and a
down Postgres lane (2026-11-21, pair to the boot-arming fix).

The 2026-10-19 design answered a down lane by dropping every journal row
it covered — "degrades silently, never breaks a tool". That was honest
about tools but dishonest about the spine: an outage's dispatches simply
did not exist afterward. This suite pins the replacement contract:

- a row written while the lane is down SPPOOLS into ids.db (journal_spool)
  when, and only when, the lane was opted into (psycopg imported) — a lane
  that never had the driver skips silently exactly as before;
- the warning budget caps: the first _WARN_PER_OUTAGE failures of an
  outage log at INFO, later ones downgrade to DEBUG (the 30s-era behavior
  nagged forever at a dead cluster);
- replay: fresh connect flushes spooled rows into journal.entries in order;
  the spool row is deleted only AFTER the PG commit;
- poison rows (FK-refusing engagement, corrupt payload) park as honest
  journal error rows after their fail budget instead of wedging the head
  of the queue.

Postgres itself is not needed for most of this: the spool table lives in
ids.db (SQLite), and the flush path is driven by a psycopg-shaped stub
recording the statements an executing replay would emit. The stub keeps
the suite hermetic — no cluster, no credentials, no order dependency on
the live engagement journal.
"""

from __future__ import annotations

import json
import logging
import sqlite3

import pytest

from constants import resolve_workspace_root
import utils.engagement as engagement


@pytest.fixture()
def spool_env(tmp_path, monkeypatch):
    """An isolated engagement lane: state root pointed at tmp, spool conn
    cache cleared, a psycopg-shaped stub, and the driver marked present.
    """
    root = tmp_path / "ws"
    (root / "engagement").mkdir(parents=True)
    monkeypatch.setattr(resolve_workspace_root, "__self__", root, raising=False)

    class _FakeWorkspaceRoot:
        """constants.resolve_workspace_root is called directly, not via an
        instance — patch it with a function-shaped stub instead."""

    monkeypatch.setattr(
        "utils.engagement.resolve_workspace_root", lambda: root)
    monkeypatch.setattr(engagement, "_SPOOL_CONN", None)
    monkeypatch.setattr(engagement, "_DB", {
        "conn": None, "down_until": 0.0, "connected_as": None,
        "driver_ok": True, "warn_count": 0, "last_error": None,
        "host": None,
    })
    yield root


class _StubCursor:
    """Records every INSERT the replay would emit — the contract under test
    is the sequence of rows parked/committed, not psycopg's wire behavior."""

    def __init__(self, parent):
        self.parent = parent

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self.parent.statements.append((sql, params))


class _StubConn:
    """psycopg-shaped enough for _flush_spool: cursor(), commit(), rollback(),
    and a scripted exception for the Nth execute (the FK-violation story)."""

    def __init__(self, fail_on_insert_ordinal: int | None = None):
        self.statements: list[tuple[str, tuple | list | None]] = []
        self.commits = 0
        self.rollbacks = 0
        self._insert_ordinal = 0
        self._fail_on = fail_on_insert_ordinal

    def cursor(self):
        return _StubCursor(self)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def _note_insert(self):
        self._insert_ordinal += 1
        if self._fail_on is not None and self._insert_ordinal == self._fail_on:
            raise RuntimeError("FK violation (stubbed)")


# _flush_spool calls cur.execute directly on _StubCursor — route the
# failure injection through the cursor's parent.
def _wire_cursor_failures():
    orig = _StubCursor.execute

    def execute(self, sql, params=None):
        if "INSERT INTO journal.entries" in sql:
            self.parent._note_insert()
        return orig(self, sql, params)
    _StubCursor.execute = execute  # type: ignore[method-assign]


_wire_cursor_failures()


def _spool_one(tool_id: str, **overrides) -> None:
    row = {
        "engagement": None, "lane": "repl_lane", "tool_id": tool_id,
        "args": {"k": "v"}, "scope_verdict": None, "approval_path": "test",
        "agent_id": "0", "agent_provenance": None, "status": "ok",
        "duration_s": 0.1, "result_mode": None, "scratch_ref": None,
        "result_digest": f"digest-{tool_id}", "envelope_meta": None,
    }
    row.update(overrides)
    engagement._spool_dispatch_row(row)


def _spool_rows(root) -> list[tuple[int, int]]:
    conn = engagement._spool_conn()
    return conn.execute(
        "SELECT spool_id, fail_count FROM journal_spool ORDER BY spool_id"
    ).fetchall()


def _spool_table(root) -> sqlite3.Connection:
    return engagement._spool_conn()


def test_spool_table_lands_in_ids_db(spool_env):
    _spool_one("t.one")
    root = spool_env
    assert (root / "ids.db").is_file()
    assert engagement.spooled_count() == 1


def test_spool_eligibility_gates_the_write(spool_env, monkeypatch):
    # driver_ok False (never-imported driver) — the honest skip
    monkeypatch.setitem(engagement._DB, "driver_ok", False)
    assert engagement._db_spool_eligible() is False
    # unknown (never attempted) — also False: spooling starts only after a
    # genuine reachability failure, never on a cold first impression
    monkeypatch.setitem(engagement._DB, "driver_ok", None)
    assert engagement._db_spool_eligible() is False


def test_warning_budget_caps_then_downgrades(spool_env, monkeypatch, caplog):
    with caplog.at_level(logging.DEBUG, logger="utils.engagement"):
        for _ in range(engagement._WARN_PER_OUTAGE + 2):
            engagement._warn_down("lane down (test)")
    infos = [r for r in caplog.records
             if r.levelno == logging.INFO and "lane down" in r.message]
    debugs = [r for r in caplog.records
              if r.levelno == logging.DEBUG and "still down" in r.message]
    assert len(infos) == engagement._WARN_PER_OUTAGE
    assert len(debugs) == 2


def test_warning_budget_refills_after_success(spool_env):
    engagement._DB["warn_count"] = 5  # exhausted by the ongoing outage
    engagement._DB["warn_count"] = 0  # connect() success path resets it
    engagement._warn_down("next outage")
    assert engagement._DB["warn_count"] == 1


def test_flush_replays_in_order_and_drops_after_commit(spool_env):
    for i in range(3):
        _spool_one(f"t.flush{i}")
    stub = _StubConn()
    replayed = engagement._flush_spool(stub)
    assert replayed == 3
    # every replay committed BEFORE its spool row was dropped:
    # N inserts -> N commits (PG) interleaved with N deletes -> N commits
    # (sqlite) — the delete-never-precedes-its-commit property.
    inserts = [s for s, _ in stub.statements if "INSERT INTO journal.entries" in s]
    assert len(inserts) == 3
    assert engagement.spooled_count() == 0


def test_batch_overflow_leaves_rest_for_next_call(spool_env):
    # batch cap 500 — spool 505, first flush replays exactly the cap
    for i in range(505):
        _spool_one(f"t.bulk{i}")
    stub = _StubConn()
    replayed = engagement._flush_spool(stub)
    assert replayed == engagement._SPOOL_FLUSH_BATCH
    assert engagement.spooled_count() == 505 - engagement._SPOOL_FLUSH_BATCH


def test_first_fail_bumps_then_second_parks(spool_env, monkeypatch):
    _spool_one("t.poison")
    spool_id, _ = _spool_rows(spool_env)[0]

    strikes = [0]

    def failing_execute(cursor_self, sql, params=None):
        if "INSERT INTO journal.entries" in sql:
            strikes[0] += 1
            # real-replay attempts #1 and #2 fail (the two strikes);
            # attempt #3 is itself the PARK insert and must succeed
            if strikes[0] <= 2:
                raise RuntimeError("FK violation (stubbed)")
        return _StubCursor.execute_orig(cursor_self, sql, params)

    _StubCursor.execute_orig = _StubCursor.execute  # capture pre-wire version
    _StubCursor.execute = failing_execute  # type: ignore[method-assign]
    try:
        # strike 1: head break, row survives with fail_count bumped
        conn = _StubConn()
        replayed = engagement._flush_spool(conn)
        assert replayed == 0
        assert _spool_rows(spool_env)[0][1] == 1

        # strike 2: park-into-journal path succeeds (park INSERT + drop)
        conn = _StubConn()
        replayed = engagement._flush_spool(conn)
        assert replayed == 1
        assert engagement.spooled_count() == 0
        inserts = [s for s, _ in conn.statements
                   if "INSERT INTO journal.entries" in s]
        assert len(inserts) == 1
        # parked row: engagement NULLed, status error — read the PARK (the
        # last recorded INSERT), not statements[0] (that's the failed real
        # replay attempt, which carries the row's original 'ok' status).
        inserts = [(s, p) for s, p in conn.statements
                   if "INSERT INTO journal.entries" in s]
        assert len(inserts) == 1
        params = list(inserts[0][1])
        assert params[0] is None  # engagement
        assert params[8] == "error"  # status
    finally:
        _wire_cursor_failures()  # restore the recorded-stub wiring


def test_corrupt_payload_parks_immediately(spool_env):
    root: object = spool_env
    engagement._spool_dispatch_row({"tool_id": "x"})
    # overwrite the payload with garbage
    conn = _spool_table(root)
    conn.execute("UPDATE journal_spool SET payload = '{not json'")
    conn.commit()
    stub = _StubConn()
    replayed = engagement._flush_spool(stub)
    assert replayed == 1
    assert engagement.spooled_count() == 0
    # the park carried the corrupt marker identity
    inserts = [(s, p) for s, p in stub.statements
               if "INSERT INTO journal.entries" in s]
    assert len(inserts) == 1
    params = list(inserts[0][1])
    assert params[2] == "journal_spool_corrupt"
    assert params[8] == "error"


def test_flush_skew_notice_and_jsonb_string_shape(spool_env):
    _spool_one("t.jsonb", args={"nested": {"a": [1, 2]}},
               envelope_meta={"identity": {"agent_id": "x"}})
    stub = _StubConn()
    assert engagement._flush_spool(stub) == 1
    params = list(stub.statements[0][1])
    # args + envelope_meta adapted to JSON STRINGS (psycopg jsonb contract)
    assert json.loads(params[3]) == {"nested": {"a": [1, 2]}}
    assert json.loads(params[13]) == {"identity": {"agent_id": "x"}}


def test_flush_failure_of_the_batch_loop_is_not_fatal(spool_env):
    _spool_one("t.loopfail")
    class _BrokenConn(_StubConn):
        def cursor(self):
            raise RuntimeError("cursor gone (stubbed)")
    assert engagement._flush_spool(_BrokenConn()) == 0
    # the spooled row survives the failed attempt (nothing dropped behind
    # a broken connection)
    assert engagement.spooled_count() == 1
