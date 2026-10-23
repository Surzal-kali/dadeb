# Vendored-wheel lane (Kali deb). The packaged tree gains a `vendor/`
# directory at build time (pip install --target, see debian/rules).
# PREPENDED to sys.path: the vendored closure must WIN overlaps. Proven on
# the VM 2026-10-20 — apt ships PARTIAL/OLDER copies of the same namespace
# family (python3-opentelemetry-api 1.44.0 only, no sdk/exporters) and under
# append order its dist-packages shadow of `opentelemetry.attributes` broke
# chromadb's exporter chain (ImportError: _clean_attribute_value). The
# closure is an exact-pinned, internally-consistent set rebuilt with every
# deb; the import floor arbitrates any skew it creates. Inert when vendor/
# is absent (every dev-tree lane keeps pristine behavior).
import sys
from pathlib import Path

# COMPAT GATE (2026-10-21): the closure's C-extensions carry the packaging
# interpreter's cp-tag (e.g. _pydantic_core.cpython-314-*.so). A foreign-lane
# interpreter finds vendor/pydantic_core first on sys.path and its cp314-only
# binary is unloadable -> ImportError (ArgsKwargs) -> every kernel launched
# from this tree dies on start. Observed live: the dockered jupyter lane
# (conda py3.13 against this tree) lost its daharness kernel the moment the
# cp314 deb landed. Arm the lane only when THIS interpreter can load the
# closure: every extension either carries this interpreter's tag, is abi3
# (stable ABI, any supported interpreter), or is a tagless support lib.
_vendor = Path(__file__).resolve().parent / "vendor"
_armable = True
if _vendor.is_dir():
    _tag = f"cpython-{sys.version_info[0]}{sys.version_info[1]}"
    for _so in _vendor.rglob("*.so"):
        if _so.name.endswith(".abi3.so"):
            continue
        _cp = next((p for p in _so.name.split(".") if p.startswith("cpython-")), "")
        if _cp and not _cp.startswith(_tag + "-"):
            _armable = False
            break
if _armable and _vendor.is_dir():
    _v = str(_vendor)
    if _v not in sys.path:
        sys.path.insert(0, _v)
# Kernelspec-lane twin: frontends launch tool_repl.py bare (no PYTHONPATH to
# arm this module through), so tool_repl.py carries the same prepend inline
# before its heavy imports — one mechanism, two carriers. Keep the two in
# sync if the arm semantics ever change.

# --- dacustoms meta-path finder ---------------------------------------------
# Maps the ``dacustoms.*`` import prefix — and ONLY that prefix — to files
# under ~/.dacustoms (or $DACUSTOMS_DIR).  Never puts $HOME or the customs
# dir itself on sys.path: a bare dir means one file named ``requests.py``
# shadows stdlib for the whole process, invisibly, with user-controlled
# filenames.  The finder class + registration live in ``dacustoms_finder.py``
# so entry points that launch bare (tool_repl.py, bootstrap.py) can import
# and register it directly — sitecustomize does NOT auto-import on py3.13/3.14
# bare launches (same reason as the vendor twin above).  Inert when
# DACUSTOMS_DIR is None or the directory doesn't exist.
try:
    from dacustoms_finder import register_dacustoms_finder
    register_dacustoms_finder()
except Exception:
    pass