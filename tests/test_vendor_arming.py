"""Deb vendored-closure arming (chromadb-vs-kernel, deb-lane lesson 2026-10-20).

The deb vendors chromadb into ``<tree>/vendor`` and tree-root
``sitecustomize.py`` prepends it — but sitecustomize only arms when
PYTHONPATH carries the tree. The four /usr/bin wrappers export it; the
kernelspec does NOT (frontends launch ``python3 <tree>/tool_repl.py
--kernel`` bare), so any frontend-launched kernel — jupyter console,
``nbconvert --execute``, ``KernelManager.get_kernel`` — died at
``daharness/__init__.py`` -> ``registry.py``'s top-level ``import
chromadb`` long before any cell ran. tool_repl.py now arms the same
prepend inline before its heavy imports.

These tests cover both carriers of that arm:
  * tree-root sitecustomize.py (the wrapper-armed lanes);
  * the shim self-arm (the kernelspec lane's only line of defense).
"""

import runpy
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_sitecustomize_prepends_vendor(tmp_path):
    """sitecustomize.py prepends the sibling vendor/ dir — and stays sane.
    """
    fake_tree = tmp_path / "tree"
    fake_tree.mkdir()
    vendor = fake_tree / "vendor"
    vendor.mkdir()
    source = (REPO_ROOT / "sitecustomize.py").read_text()
    (fake_tree / "sitecustomize.py").write_text(source)

    before = list(sys.path)
    try:
        runpy.run_path(str(fake_tree / "sitecustomize.py"),
                       run_name="arming_probe")
        assert sys.path[0] == str(vendor), sys.path[:3]
        after_first = list(sys.path)
        runpy.run_path(str(fake_tree / "sitecustomize.py"),
                       run_name="arming_probe")
        assert sys.path == after_first, "sitecustomize must stay idempotent"
    finally:
        sys.path[:] = before


def test_tool_repl_arm_is_inert_without_vendor(tmp_path):
    """Dev trees keep pristine behavior: no vendor/ -> no path insert.

    Executes the head of tool_repl.py (stdlib imports + the arm block, cut
    before the heavy replkit/daharness chain) against a vendor-less copy of
    the shim — the same code path ``python tool_repl.py`` runs on every
    dev-tree lane, without needing a chromadb closure to exist.
    """
    head_source = (REPO_ROOT / "tool_repl.py").read_text()
    start = head_source.index("import sys\nfrom pathlib import Path")
    end = head_source.index("# Make project root importable")
    head = head_source[start:end]

    fake_tree = tmp_path
    shutil.copy(REPO_ROOT / "tool_repl.py", fake_tree / "tool_repl.py")

    before = list(sys.path)
    try:
        exec(compile(head, str(fake_tree / "tool_repl.py"), "exec"),
             {"__file__": str(fake_tree / "tool_repl.py")})
        # Delta assert, not a vendor-free sys.path: on the deb lane the
        # running process already carries its own armed vendor entries.
        assert sys.path == before, ("shim head mutated sys.path:",
                                    sys.path[:3])
    finally:
        sys.path[:] = before


def test_tool_repl_kernelspec_lane_boots_from_vendor(tmp_path):
    """Kernelspec-lane simulation: bare argv, no PYTHONPATH, foreign cwd.

    The child process gets the tree via a manual sys.path insert (what the
    script-dir path0 provides at a frontend launch), strips PYTHONPATH and
    the user site, and imports tool_repl. With a vendor/ present,
    ``import chromadb`` must resolve INSIDE vendor — proof the shim arm
    ran, not the ambient (user-site / PYTHONPATH) config. Skipped on every
    lane with no vendor dir (dev trees: the arming is inert by design;
    the deb selftest lane exercises the real arm).
    """
    tree = REPO_ROOT
    vendor = tree / "vendor"
    if not vendor.is_dir():
        pytest.skip("no vendor/ in this tree (dev lane — arming inert); the "
                    "deb selftest lane exercises the real arm")
    child = (
        "import sys\n"
        "from pathlib import Path\n"
        f"sys.path.insert(0, {str(tree)!r})\n"
        "import tool_repl  # the kernelspec shim itself\n"
        "import chromadb\n"
        f"assert Path(chromadb.__file__).resolve().is_relative_to("
        f"{str(vendor)!r}), ('not vendored:', chromadb.__file__)\n"
        "assert any('vendor' in p for p in sys.path), "
        "('arm did not run:', sys.path[:3])\n"
        "print('VENDOR-ARM-OK', chromadb.__version__)\n"
    )
    proc = subprocess.run(
        [sys.executable, "-s", "-c", child],
        cwd=str(tmp_path),  # NOT the tree: cwd sitecustomize must not arm
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)},  # no PYTHONPATH
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert "VENDOR-ARM-OK" in proc.stdout