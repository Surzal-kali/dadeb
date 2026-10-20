# Vendored-wheel lane (Kali deb). The packaged tree gains a `vendor/`
# directory at build time (pip install --target, see debian/rules). It is
# APPENDED to sys.path — never prepended — so apt-provided system packages
# always win for overlapping names and vendor fills only the gaps apt lacks
# (chromadb, pydantic-ai-slim + their non-apt closure). Inert when vendor/
# is absent (every dev-tree lane keeps pristine behavior).
import sys
from pathlib import Path

_vendor = Path(__file__).resolve().parent / "vendor"
if _vendor.is_dir():
    _v = str(_vendor)
    if _v not in sys.path:
        sys.path.append(_v)