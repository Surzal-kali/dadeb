"""Scratch store db-file permission tests (2026-10-30 hardening).

sqlite mints `scratch.db-wal`/`-shm` 0644 (+umask) and they hold the same
row data as the db, so all three must be 0600 — at construction AND on the
hot paths (a re-opened WAL db re-mints absent sidecars at its first
statement, so `__init__`-time chmod alone is incomplete).
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from utils.scratch_store import ScratchStore


def _sidecars(db_path: str) -> list[Path]:
    return [Path(db_path + suffix) for suffix in ("-wal", "-shm")]


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def test_store_hardens_db_and_sidecars_to_0600(tmp_path):
    db = str(tmp_path / "scratch.db")
    store = ScratchStore(db_path=db, data_dir=str(tmp_path / "scratch-data"))
    store.store({"k": "v"}, agent_id="agent-a", tool_id="tool")

    assert _mode(Path(db)) == 0o600
    for side in _sidecars(db):
        assert side.is_file(), f"{side} must exist after a store transaction"
        assert _mode(side) == 0o600, side

    # close() deletes the sidecars cleanly; assert before.
    store.close()


def test_reopened_store_rehardens_sidecars(tmp_path):
    db = str(tmp_path / "scratch.db")
    store = ScratchStore(db_path=db, data_dir=str(tmp_path / "scratch-data"))
    store.store({"k": "v"}, agent_id="agent-a", tool_id="tool")
    store.close()

    # WAL dbs re-mint absent sidecars at the FIRST statement of any kind
    # (even a read), so the hot paths must re-harden after init.
    store2 = ScratchStore(db_path=db, data_dir=str(tmp_path / "scratch-data"))
    store2.list_entries("agent-a")
    for side in _sidecars(db):
        assert side.is_file(), f"{side} re-materialized by the read"
        assert _mode(side) == 0o600, side
    store2.close()


def test_symlinked_sidecar_is_skipped_not_chmodded(tmp_path):
    db = str(tmp_path / "scratch.db")
    victim = tmp_path / "victim-file"
    victim.write_bytes(b"victim\n")
    victim.chmod(0o644)
    (tmp_path / "scratch.db-wal").symlink_to(victim)

    store = ScratchStore(db_path=db, data_dir=str(tmp_path / "scratch-data"))
    store.store({"k": "v"}, agent_id="agent-a", tool_id="tool")

    # The lane keeps working; the symlink is never chmod'd through and the
    # victim keeps its permissions and contents.
    assert _mode(victim) == 0o644
    assert victim.read_bytes() == b"victim\n"
    store.close()


@pytest.mark.parametrize("name", ["scratch.db-wal", "scratch.db-shm"])
def test_symlinked_sidecar_is_skipped_per_file_or_fails_closed(tmp_path, name):
    db = str(tmp_path / "scratch.db")
    victim = tmp_path / f"victim-{name}"
    victim.write_bytes(b"victim\n")
    victim.chmod(0o644)
    (tmp_path / name).symlink_to(victim)

    if name.endswith("-wal"):
        # sqlite tolerates a bogus -wal (it is recreated from the db);
        # our hardening skips the link instead of chmod'ing through it, and
        # the OTHER sidecar still gets hardened.
        store = ScratchStore(db_path=db, data_dir=str(tmp_path / "scratch-data"))
        store.store({"k": "v"}, agent_id="agent-a", tool_id="tool")
        other = Path(db + "-shm")
        if other.is_file():
            assert _mode(other) == 0o600
        assert _mode(victim) == 0o644
        store.close()
    else:
        # A planted evil -shm cannot pass the WAL-index header check, so
        # sqlite fails CLOSED at init — the store refuses to open rather
        # than leaking writes through the link.  The victim file (which
        # holds no WAL-index header) is untouched.
        import sqlite3

        with pytest.raises(sqlite3.OperationalError, match="unable to open database file"):
            ScratchStore(db_path=db, data_dir=str(tmp_path / "scratch-data"))
        assert _mode(victim) == 0o644
        assert victim.read_bytes() == b"victim\n"