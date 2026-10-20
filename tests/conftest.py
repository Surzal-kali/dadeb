"""Shared fixtures for the dadeb selftest suite.

The pyproject pytest config already puts the repo root on sys.path
(pythonpath = ["."]); the bootstrap below re-asserts it for stray runners
(`pytest tests/test_x.py` from a foreign CWD) so framework imports cannot
drift to an installed copy.
"""

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture
def state_root(tmp_path, monkeypatch):
    """Redirect WORKSPACE_ROOT to a throwaway dir for the calling test.

    resolve_workspace_root() honors $WORKSPACE_ROOT when it exists, so
    framework_health's findings-db probe operates on this tree instead of
    the operator's real workspace (never writes to it, never reads stale
    ids.db state).
    """
    root = tmp_path / "workspace"
    root.mkdir()
    monkeypatch.setenv("WORKSPACE_ROOT", str(root))
    return root