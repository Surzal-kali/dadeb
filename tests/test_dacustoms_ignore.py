"""Tests for the dacustoms gitignore-ignore lane + doctor integration.

The doctor's customs probe (``_check_customs``) walks the operator's
customs dir with ``ast.parse``. A customs dir that carries a venv (the
live 2026-11-03 report: 395 of 397 checked files were venv internals)
must not be syntax-graded — the operator already chose to not track
those files via .gitignore, and stdlib venvs self-ignore (venv/.gitignore
ships '*'). dacustoms_ignore speaks that dialect; these tests pin the
translator against real git behavior (the shapes were cross-checked
against ``git check-ignore`` on 2026-11-03) and the doctor's skip/surface
behavior end-to-end.
"""

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from dacustoms_ignore import (  # noqa: E402
    UnsupportedPatternError,
    load_ignore_matcher,
    parse_gitignore_line,
)


@pytest.fixture
def customs_tree(tmp_path):
    """A customs-dir-shaped tree exercising every supported dialect shape.

    Mirrors the live tree that produced the 395-file venv flood: a venv/
    with the stdlib's own self-ignoring .gitignore, plus a root ignore
    file carrying the common operator patterns.
    """
    (tmp_path / "venv" / "bin").mkdir(parents=True)
    (tmp_path / "venv" / "lib").mkdir()
    (tmp_path / "venv" / "lib" / "a.py").write_text("x = 1\n")
    (tmp_path / "venv" / ".gitignore").write_text("# Created by venv\n*\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "c.py").write_text("x = 1\n")
    (tmp_path / "node_modules" / "deep").mkdir()
    (tmp_path / "node_modules" / "deep" / "d.py").write_text("x = 1\n")
    (tmp_path / "nested").mkdir()
    (tmp_path / "sub").mkdir()
    (tmp_path / ".gitignore").write_text(
        "node_modules/\n"
        "*.tmp.py\n"
        "/rootonly.py\n"
        "sub/hidden.py\n"
        "!keep_special.py\n"
        "sub/\n"
        "\n"
        "# comment\n"
    )
    (tmp_path / "keep.py").write_text("x = 1\n")
    (tmp_path / "rootonly.py").write_text("x = 1\n")
    (tmp_path / "nested" / "rootonly.py").write_text("x = 1\n")
    (tmp_path / "sub" / "hidden.py").write_text("x = 1\n")
    (tmp_path / "sub" / "deeper.py").write_text("x = 1\n")
    (tmp_path / "keep_special.py").write_text("x = 1\n")
    (tmp_path / "keep_special.py.tmp.py").write_text("x = 1\n")
    (tmp_path / "other.tmp.py").write_text("x = 1\n")
    return tmp_path


# --- line parsing -------------------------------------------------------


def test_parse_blanks_and_comments():
    assert parse_gitignore_line("") is None
    assert parse_gitignore_line("   ") is None
    assert parse_gitignore_line("# comment") is None
    assert parse_gitignore_line("  # indented comment") is None


def test_parse_shapes():
    assert parse_gitignore_line("venv") == ("venv", False, False, False)
    assert parse_gitignore_line("venv/") == ("venv", False, True, False)
    assert parse_gitignore_line("/root") == ("root", True, False, False)
    assert parse_gitignore_line("sub/x.py") == ("sub/x.py", False, False, False)
    assert parse_gitignore_line("!foo.py") == ("foo.py", False, False, True)


def test_parse_doublestar_refused():
    with pytest.raises(UnsupportedPatternError):
        parse_gitignore_line("**/foo")
    with pytest.raises(UnsupportedPatternError):
        parse_gitignore_line("abc/**")


def test_parse_trailing_whitespace_stripped():
    assert parse_gitignore_line("venv   ") == ("venv", False, False, False)


# --- matcher semantics (cross-checked against git check-ignore) ---------


def test_stdlib_venv_self_ignore_matches(customs_tree):
    matcher, sources, unsupported = load_ignore_matcher(customs_tree)
    assert matcher("venv/lib/a.py") is True
    assert matcher("venv/bin/x.py") is True
    # The venv's own star rule must NOT leak above its directory.
    assert matcher("keep.py") is False
    assert sources == [".gitignore", "venv/.gitignore"]
    assert unsupported == []


def test_root_anchored_pattern_not_recursive(customs_tree):
    matcher, _, _ = load_ignore_matcher(customs_tree)
    assert matcher("rootonly.py") is True
    # git: '/rootonly.py' anchors at the ignore file's dir — the nested
    # sibling is NOT ignored.
    assert matcher("nested/rootonly.py") is False


def test_dir_only_prunes_subtree(customs_tree):
    matcher, _, _ = load_ignore_matcher(customs_tree)
    # Both 'node_modules/' and 'sub/' prune the dir and everything under.
    assert matcher("node_modules/c.py") is True
    assert matcher("node_modules/deep/d.py") is True
    assert matcher("sub/hidden.py") is True
    assert matcher("sub/deeper.py") is True


def test_globs_and_negation(customs_tree):
    matcher, _, _ = load_ignore_matcher(customs_tree)
    assert matcher("other.tmp.py") is True
    assert matcher("keep_special.py.tmp.py") is True
    assert matcher("keep_special.py") is False
    assert matcher("keep.py") is False


def test_subdir_scoped_bare_patterns_stay_in_subtree(tmp_path):
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / ".gitignore").write_text("generated.py\n")
    (tmp_path / "nested" / "generated.py").write_text("x = 1\n")
    (tmp_path / "generated.py").write_text("x = 1\n")
    matcher, sources, _ = load_ignore_matcher(tmp_path)
    # A bare pattern in nested/.gitignore applies under nested/ — git
    # scopes it to the ignore file's directory — and the root twin is
    # NOT swallowed because nothing ignored it at the root.
    assert matcher("nested/generated.py") is True
    assert matcher("generated.py") is False
    assert sources == ["nested/.gitignore"]


def test_unsupported_patterns_fail_open(tmp_path):
    (tmp_path / ".gitignore").write_text("**/generated*\nbinary/\n")
    (tmp_path / "generated_one.py").write_text("x = 1\n")
    (tmp_path / "binary").mkdir()
    (tmp_path / "binary" / "b.py").write_text("x = 1\n")
    matcher, _, unsupported = load_ignore_matcher(tmp_path)
    # The ** row is refused (counted, not mis-executed); the file stays
    # CHECKED — fail-open toward grading operator code, never hiding it.
    assert unsupported == ["**/generated*"]
    assert matcher("generated_one.py") is False
    # The dir-only row next to it still works.
    assert matcher("binary/b.py") is True


def test_unreadable_ignore_file_fails_open(tmp_path):
    (tmp_path / ".gitignore").write_text("secret_dir/\n")
    (tmp_path / "secret_dir").mkdir()
    (tmp_path / "secret_dir" / "s.py").write_text("x = 1\n")
    (tmp_path / ".gitignore").chmod(0o000)
    try:
        matcher, sources, _ = load_ignore_matcher(tmp_path)
        # No rules could be read: nothing is ignored (checked), no crash.
        assert matcher("secret_dir/s.py") is False
        assert sources == []
    finally:
        (tmp_path / ".gitignore").chmod(0o644)


# --- doctor integration --------------------------------------------------


def test_doctor_skips_gitignored_venv(tmp_path, monkeypatch):
    """End-to-end: a venv-carrying customs dir checks 2 files, not 397.

    Redirects DACUSTOMS_DIR at a fixture tree and calls _check_customs
    through framework_status's real import surface (the finder must be
    registered or the probe short-circuits before the walk).
    """
    from auxiliaries.framework_status import _check_customs

    tree = tmp_path / "customs"
    tree.mkdir()
    (tree / "__init__.py").write_text("")
    (tree / "custom_constants.py").write_text("X = 1\n")
    # A venv with the stdlib's self-ignore + a stray broken stub inside
    # it — pre-fix this file alone would degrade the lane.
    venv = tree / "venv"
    (venv / "lib").mkdir(parents=True)
    (venv / ".gitignore").write_text("# Created by venv\n*\n")
    (venv / "lib" / "broken.py").write_text("def (:\n")  # real syntax error
    (tree / ".gitignore").write_text("venv/\n")

    from constants import dacustoms_dir
    monkeypatch.setenv("DACUSTOMS_DIR", str(tree))
    monkeypatch.setattr("dacustoms_finder.finder_status", lambda: {
        "registered": True, "reason": "test", "dir": str(tree),
        "dir_exists": True, "init_present": True, "step": "test",
    })
    # _check_customs re-resolves dacustoms_dir() (env read per call).
    assert dacustoms_dir() == tree.resolve()

    report = _check_customs()
    checked = [f["file"] for f in report["files"]]
    assert report["available"] is True
    assert checked == ["__init__.py", "custom_constants.py"]
    assert report["ignored_files_skipped"] == 1
    assert "broken.py" not in checked  # never graded, never surfaced
    # Both the root ignore and the venv's stdlib self-ignore contributed.
    assert report["ignore_sources"] == [".gitignore", "venv/.gitignore"]


def test_doctor_reports_unsupported_dialect(tmp_path, monkeypatch):
    from auxiliaries.framework_status import _check_customs

    tree = tmp_path / "customs"
    tree.mkdir()
    (tree / "__init__.py").write_text("")
    (tree / "mod.py").write_text("X = 1\n")
    (tree / ".gitignore").write_text("**/temp*\n")

    monkeypatch.setenv("DACUSTOMS_DIR", str(tree))
    monkeypatch.setattr("dacustoms_finder.finder_status", lambda: {
        "registered": True, "reason": "test", "dir": str(tree),
        "dir_exists": True, "init_present": True, "step": "test",
    })

    report = _check_customs()
    assert report["available"] is True  # fail-open: still checked
    assert "temp*" in report["remediation"]
    assert any(f["file"] == "mod.py" for f in report["files"])


# --- discovery integration --------------------------------------------------


def test_discovery_skips_gitignored_pylibs(tmp_path, monkeypatch):
    """End-to-end (live 2026-11-05 deb failure): discovery dynamically
    imported every vendored module under a pip --target ``pylibs`` tree
    as ``dacustoms.pylibs.<pkg>.*`` and failed wholesale — because the
    ignore lane was only wired into the doctor, never into the registry's
    walk. With the wiring, the root ``pylibs/`` rule prunes the tree
    before either pass sees it: no manifests, no imports, no traceback
    flood. The operator's own module (outside the ignored tree) still
    mints, proving the rule is scoped and not a blanket skip."""
    from daharness.registry import ToolRegistry

    tree = tmp_path / "customs"
    tree.mkdir()
    (tree / "__init__.py").write_text("")
    # A MINTABLE operator module (docstring + argparse = static-pass
    # LOCAL_FILE tool) so the scope check below has something positive to
    # assert on — custom_constants-style const modules mint nothing.
    (tree / "my_probe.py").write_text(
        '"""Operator probe tool: echoes a marker for selftest."""\n'
        "import argparse\n\n"
        "def main():\n"
        "    parser = argparse.ArgumentParser()\n"
        "    parser.add_argument(\"--marker\", default=\"x\", help=\"marker\")\n"
        "    args = parser.parse_args()\n"
        "    print(f\"marker={args.marker}\")\n\n"
        "if __name__ == \"__main__\":\n"
        "    main()\n"
    )
    # The flood shape: a site-packages-shape vendored tree (importable
    # modules, no __init__.py at its root) that the operator gitignored.
    pylibs = tree / "pylibs"
    (pylibs / "fakevendor").mkdir(parents=True)
    (pylibs / "fakevendor" / "__init__.py").write_text("vendored = True\n")
    (pylibs / "fakevendor" / "core.py").write_text("VENDOR_CONST = 1\n")
    (tree / ".gitignore").write_text("pylibs/\n")

    monkeypatch.setenv("DACUSTOMS_DIR", str(tree))
    reg = ToolRegistry.__new__(ToolRegistry)
    reg._tool_instances = {}
    manifests = reg.discover_local_tools()

    module_ids = {m.module_id for m in manifests}
    assert not any("pylibs" in mid for mid in module_ids), module_ids
    # The probe module itself is NOT gitignored, so it mints normally.
    assert any(mid == "dacustoms.my_probe" for mid in module_ids), sorted(module_ids)[:20]

    # The scope check: the SAME walk with the rule removed must mint the
    # operator module — the skip came from the ignore lane, not a bug in
    # the walk itself. Re-assert the env first: phase 1's PASS 2 imports
    # scanned packages whose module-level load_dotenv(override=True)
    # rewrites DACUSTOMS_DIR process-wide (the pass-boundary contract is
    # one snapshot per pass, so a lane calls with a coherent env).
    monkeypatch.setenv("DACUSTOMS_DIR", str(tree))
    (tree / ".gitignore").write_text("\n")
    manifests = reg.discover_local_tools()
    module_ids = {m.module_id for m in manifests}
    clean = {mid for mid in module_ids if mid.startswith("dacustoms.")}
    assert any("my_probe" in mid for mid in clean), clean
    # pylibs members still never mint: ignored-tree modules never reach
    # either pass, and vendored leaves lack docstring+argparse anyway.
    assert not any("pylibs" in mid for mid in module_ids), module_ids