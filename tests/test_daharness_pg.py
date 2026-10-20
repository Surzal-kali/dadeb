"""daharness-pg lane-address regression (2026-10-20, live on the guinea pig).

The init script's libpq calls (psql probe, createdb, run_sql, and the
001_roles.sh bundle's own psql) silently connected to libpq DEFAULTS —
:5432, msfdb's 'main' cluster. With main DOWN init died mid-way ("psql:
error: connection to server on socket ... .s.PGSQL.5432"); with main UP
it would have built the harness db + roles inside the WRONG cluster.
These static-contract tests pin the lane-addressing contract so a future
edit cannot reintroduce a default-port route.
"""

import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "packaging" / "bin" / "daharness-pg"
BUNDLE = REPO_ROOT / "packaging" / "postgres" / "init" / "001_roles.sh"


def _text():
    return SCRIPT.read_text()


def _runuser_lines():
    return [(n, l) for n, l in enumerate(_text().splitlines(), 1)
            if "runuser" in l and ("psql" in l or "createdb" in l
                                   or "bash" in l)]


def test_script_is_valid_sh():
    assert SCRIPT.exists()
    assert subprocess.run(["sh", "-n", str(SCRIPT)]).returncode == 0


def test_pgport_exported_before_every_libpq_call():
    """Execution-order contract inside cmd_init: the PGPORT export must
    precede every libpq-consuming step (its own inline probe/createdb
    read as text order; run_sql / run_roles_script read via their call
    sites, since definition order is not execution order in sh)."""
    lines = _text().splitlines()
    export_at = next((n for n, l in enumerate(lines, 1)
                      if l.strip().startswith('export PGPORT="$PORT"')), None)
    assert export_at, "PGPORT must be exported for the bundle's libpq env"
    call_sites = [(n, l) for n, l in enumerate(lines, 1)
                  if n > export_at and re.search(
                      r"DB_PRESENT=\$\(runuser|createdb -p "
                      r"|run_roles_script \|\| die|run_sql \"\$INIT_DIR", l)]
    assert len(call_sites) >= 6, (
        "expected probe+createdb+roles+3 run_sql call sites after export, "
        f"found {len(call_sites)}: {call_sites}")


def test_runuser_libpq_calls_carry_explicit_port():
    """Direct psql/createdb through runuser must pin the lane port
    explicitly (the bundle's own psql is covered by the export)."""
    missing = [(n, l.strip()) for n, l in _runuser_lines()
               if ("psql" in l or "createdb" in l)
               and "-p \"$PORT\"" not in l]
    assert not missing, f"default-port libpq route: {missing}"


def test_db_probe_dies_on_connection_failure():
    """A failed pg_database probe must die, not fall through as 'database
    missing' (that sent the run into createdb against the same broken
    target — the observed live failure)."""
    text = _text()
    assert "DB_PRESENT" in text
    assert '|| die "cannot query pg_database' in text


def test_bundle_has_no_hardcoded_port():
    text = BUNDLE.read_text()
    assert "5432" not in text and "5433" not in text
    assert "-p " not in text   # container lane relies on POSTGRES_* env


def test_client_probe_footer_uses_lane_port():
    text = _text()
    assert "-h 127.0.0.1 -p ${PORT}" in text   # passworded TCP probe