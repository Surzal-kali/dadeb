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

_vendor = Path(__file__).resolve().parent / "vendor"
if _vendor.is_dir():
    _v = str(_vendor)
    if _v not in sys.path:
        sys.path.insert(0, _v)
# Kernelspec-lane twin: frontends launch tool_repl.py bare (no PYTHONPATH to
# arm this module through), so tool_repl.py carries the same prepend inline
# before its heavy imports — one mechanism, two carriers. Keep the two in
# sync if the arm semantics ever change.