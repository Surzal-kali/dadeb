"""Selftest macro argv regression (live-on-deb lesson, 2026-10-20).

`daharness-repl selftest -q` on the guinea pig made _selftest_argv go
bare (`pytest -q` with no path) because ANY passthrough extra dropped
the tests/ anchor — a cwd-spawned pytest then collected the whole
rootdir INCLUDING the vendored closure's own test files (21 collection
errors, run interrupted; the root-owned tree also tripped pytest-cache
permission warnings). The anchor is unconditional now, a passthrough
test-file arg covers it, and read-only install trees disable the cache
probes.
"""

import os
import stat

import pytest

import importlib

import pytest


@pytest.fixture
def core():
    return importlib.import_module("replkit.core")


def _argv(core, *extra):
    return core._selftest_argv(list(extra))


def test_no_extra_anchors_tests(core):
    argv = _argv(core)
    assert any(a.endswith("/tests") for a in argv), argv
    assert argv[-1] == "-q"


def test_flag_only_extra_keeps_anchor(core):
    """The deb-lane failure: '-q' as passthrough stripped the path."""
    argv = _argv(core, "-q")
    assert any(a.endswith("/tests") for a in argv), argv


def test_keyword_filter_keeps_anchor(core):
    argv = _argv(core, "-k", "chroma")
    assert any(a.endswith("/tests") for a in argv), argv


def test_test_file_extra_skips_base_anchor(core):
    argv = _argv(core, "test_prelaunch_guard.py")
    assert "tests/test_prelaunch_guard.py" in argv
    assert not [a for a in argv if a.endswith("/tests")], argv


def test_force_and_f_ignored(core):
    assert _argv(core, "--force") == _argv(core)
    assert _argv(core, "-f", "-k", "brain") == _argv(core, "-k", "brain")


def test_unwritable_tree_disables_cache(core, monkeypatch, tmp_path):
    fake_root = tmp_path / "ro-tree"
    fake_root.mkdir()
    (fake_root / "tests").mkdir()
    monkeypatch.setattr(core, "_REPO_ROOT", fake_root)
    os.chmod(fake_root, 0o555)
    argv = _argv(core)
    assert "no:cacheprovider" in argv

    os.chmod(fake_root, 0o755)


def test_deb_installs_pyproject_rootdir_config():
    pyproject = importlib.import_module("replkit.core")._REPO_ROOT / "pyproject.toml"
    assert pyproject.exists()
    text = pyproject.read_text()
    assert "[tool.pytest.ini_options]" in text
    assert "tests" in text