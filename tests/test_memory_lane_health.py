"""Memory lane regressions: lazy default service + group-shareable DB modes.

The 2026-10-21 discovery incident: tool discovery dynamically imports
``utils/findings.py`` -> ``utils/memory_tools.py`` -> ``memories.py``, whose
module-level ``_default_service = MemoryService()`` opened chroma inside the
scanning process's CWD — on the deb lane the root-owned /usr/share/daharness
checkout, so sqlite answered "attempt to write a readonly database" and the
dynamic scan for two modules died (the follow-on tenant/bindings errors were
chromadb's poisoned shared-system cache). A second layer: the daemon's state
root is group-shareable *by design* (StateDirectoryMode=2770, UMask=0007),
but a tighter umask had left chroma.sqlite3 at 0640, so operator lanes *in*
the daharness group still hit sqlite code 8 on the existing file.

The fixes under test:
- the shared MemoryService builds lazily on first use — never at import —
  and its default path resolves through constants.resolve_workspace_root()
  (the deb lane falls through to /var/lib/daharness);
- the service restores the unit's intended group-shareable shape (dirs
  2770, files 0660) on whatever it owns, so one owner boot heals the mode
  for the whole group.
"""

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_import_memory_tools_writes_nothing_in_readonly_cwd(tmp_path):
    """The discovery-scan killshot reproduced end to end.

    Spawns a child (fresh interpreter, no chroma shared-system cache) whose
    CWD is a read-only dir and whose WORKSPACE_ROOT is a writable throwaway.
    Importing utils.memory_tools used to crash there; it must not — and it
    must not create state anywhere except on first actual use.
    """
    ro_cwd = tmp_path / "scan-cwd"
    ro_cwd.mkdir()
    ws = tmp_path / "workspace"
    ws.mkdir()
    os.chmod(ro_cwd, 0o555)
    try:
        env = dict(
            os.environ,
            PYTHONPATH=str(REPO_ROOT),
            WORKSPACE_ROOT=str(ws),
        )
        proc = subprocess.run(
            [sys.executable, "-c", "import utils.memory_tools"],
            cwd=str(ro_cwd),
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
    finally:
        os.chmod(ro_cwd, 0o755)
    assert proc.returncode == 0, proc.stderr
    assert not (ro_cwd / ".memory").exists(), "state landed in CWD, not workspace"
    assert not (ws / ".memory").exists(), "state created at import time"


def test_default_service_is_lazy_and_path_is_lane_safe(state_root):
    """`from memories import _default_service` still works (PEP 562 alias),
    the instance is a shared singleton, and its storage resolves under the
    WORKSPACE_ROOT — never a CWD-relative guess."""
    import memories

    svc = memories.get_default_service()
    assert memories._default_service is svc
    assert svc.storage_path == str(state_root / ".memory" / "vectors.db")


def test_fresh_db_dir_gets_group_shareable_shape(state_root):
    """Fresh dir: dirs 2770 / files 0660 regardless of the process umask —
    the systemd unit's StateDirectoryMode=2770 + UMask=0007 intent."""
    from memories import MemoryService

    svc = MemoryService(storage_path=str(state_root / "vectors.db"))
    root = Path(svc.storage_path).parent
    db = Path(svc.storage_path)
    assert stat.S_IMODE(os.stat(root).st_mode) == 0o2770
    assert stat.S_IMODE(os.stat(db).st_mode) == 0o660
    assert svc.list_namespaces() == []


def test_owner_heals_tight_umask_db(state_root):
    """A 0640 vectors.db (observed live on the deb 2026-10-21) made the
    file read-only for every group member. The owner process restores g+w
    at construction so one service boot repairs it for the group."""
    from memories import MemoryService

    vdir = state_root / ".memory2"
    vdir.mkdir()
    db = vdir / "vectors.db"
    db.write_text("")
    os.chmod(db, 0o640)

    svc = MemoryService(storage_path=str(db))
    assert stat.S_IMODE(os.stat(db).st_mode) == 0o660
    assert svc.list_namespaces() == []