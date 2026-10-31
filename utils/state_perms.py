"""Cross-lane SQLite state-file mode reconcile (setgid-state-root convention).

Deb/state-root lanes share SQLite stores between processes under DIFFERENT
identities: the ``daharness`` service user owns
``/var/lib/daharness`` (2770 setgid, ``StateDirectoryMode``), operator
shells reach the same files through ``daharness``-group membership. The
service units carry ``UMask=0007``, but any file minted under a tighter
umask (a 022-umask wrapper, WSL's default, a legacy first boot) lands
group-read-only FOREVER — SQLite never re-chmods an existing database,
and the first cross-lane WAL write then dies with

    OperationalError: attempt to write a readonly database

Live 2026-10-31: ``run/brain_sessions.db`` minted 0640 degraded every
operator-lane dispatch (the durable agent→Brain-session ints silently
fell back to per-process mints); ``run/fleet/fleet.db`` and
``run/analysis_snapshots.db`` minted in the same batch carried the same
defect (the latter degraded the snapshot cache silently, by design).

Established defenses, by layer — this helper is the middle ones:

- Units' ``UMask=0007`` shapes files minted by the service lane onward.
- In-process backstop ON EVERY STORE OPEN (this module; the caller runs
  it after its WAL pragma so the ``-wal``/``-shm`` sidecars exist — they
  inherit the main db's mode, including its group-read-only defect).
  Precedent: ``daharness/vector_store.py:VectorStore._reconcile_db_modes``
  (the 2026-10-24 tool_registry.db WSL heal — kept self-contained there;
  do not refactor into this module in the same change).
- Offline backstop in the deb postinst (top-level + ``run/`` g+rw sweep
  on every install/upgrade).

Semantics: a no-op on a healthy tree (bit present), a silent heal where
the caller owns or can chmod the file, and a silent no-op where it
cannot (a non-owner lane's chmod raises PermissionError — the owner
lane or the postinst heals it instead). Never raises: caching and
resolution must degrade, not break, on a mode they cannot fix.
"""

from __future__ import annotations

import logging
from pathlib import Path

import os

logger = logging.getLogger(__name__)


def reconcile_sqlite_modes(db_path: str | os.PathLike[str], *, group_rw: int = 0o060) -> None:
    """Ensure ``db_path`` (+ its WAL sidecars, if present) is group-rw.

    Best-effort and exception-free: every stat/chmod failure is a silent
    no-op (missing file, read-only mount, non-owner caller — the file was
    already readable or someone else owns the heal). Only touches the
    group bits; never widens owner bits.
    """
    _group_read = 0o040
    p = Path(db_path)
    for suffix in ("", "-wal", "-shm", "-journal"):
        f = p.with_name(p.name + suffix)
        try:
            if not f.exists():
                continue
            mode = f.stat().st_mode & 0o777
            missing = (group_rw | _group_read) & ~mode
            if missing:
                f.chmod(mode | (group_rw | _group_read))
        except OSError:
            # Non-owner lane (deb: operator vs daharness service user),
            # read-only mount, vanished sidecar — the owner lane's open
            # or the postinst sweep is the layer that heals those; this
            # call must never break the store it is hardening.
            logger.debug(
                "state_perms: could not reconcile modes on %s", f, exc_info=True
            )