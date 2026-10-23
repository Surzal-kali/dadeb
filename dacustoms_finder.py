"""Meta-path finder for the ``dacustoms.*`` import prefix.

Maps ``dacustoms.<rel>.<module>`` to files under ``~/.dacustoms`` (or
``$DACUSTOMS_DIR``).  Never puts ``$HOME`` or the customs dir itself on
``sys.path`` — a bare dir means one file named ``requests.py`` shadows stdlib
for the whole process, invisibly, with user-controlled filenames.  The finder
gives one canonical import path per file so the ``__module__ == module_name``
guard in discovery stays correct and there are no duplicate module objects
(diverging class instances, duplicated state).

Registration happens from three carriers (same pattern as the vendor prepend):

  • ``sitecustomize.py`` — auto-imports on standard Python startup when the
    tree is on ``sys.path`` (PYTHONPATH-armed lanes).
  • ``tool_repl.py`` — explicit call after ``sys.path`` setup (kernelspec
    launches bare, sitecustomize doesn't auto-load).
  • ``bootstrap.py`` — explicit call after ``.env`` load (daemon lane).

All three call :func:`register_dacustoms_finder`, which is idempotent.
Inert when ``DACUSTOMS_DIR`` is ``None`` or the directory doesn't exist.
"""

import importlib.abc
import importlib.machinery
import sys
from pathlib import Path


class DacustomsFinder(importlib.abc.MetaPathFinder):
    """Resolve ``dacustoms.<rel>`` imports to files under the customs dir.

    ``dacustoms``               ->  <dir>/__init__.py  (the package root)
    ``dacustoms.foo``           ->  <dir>/foo.py  (or  <dir>/foo/__init__.py)
    ``dacustoms.sub.bar``       ->  <dir>/sub/bar.py
    """

    _prefix = "dacustoms"

    def __init__(self, customs_dir: Path):
        self._dir = customs_dir

    def find_spec(self, fullname, path=None, target=None):
        if fullname != self._prefix and not fullname.startswith(self._prefix + "."):
            return None
        # Bare ``dacustoms`` — resolve to the package __init__.py.
        if fullname == self._prefix:
            init = self._dir / "__init__.py"
            if init.is_file():
                return importlib.machinery.ModuleSpec(
                    fullname,
                    importlib.machinery.SourceFileLoader(fullname, str(init)),
                    origin=str(init),
                    is_package=True,
                )
            return None
        # Strip the ``dacustoms.`` prefix -> relative dotted path.
        rel = fullname[len(self._prefix) + 1:]
        if not rel:
            return None
        parts = rel.split(".")
        base = self._dir.joinpath(*parts)
        # Try package first (<dir>/<rel>/__init__.py), then module
        # (<dir>/<rel>.py) — mirrors the standard loader's resolution order.
        pkg_init = base / "__init__.py"
        if pkg_init.is_file():
            return importlib.machinery.ModuleSpec(
                fullname,
                importlib.machinery.SourceFileLoader(fullname, str(pkg_init)),
                origin=str(pkg_init),
                is_package=True,
            )
        mod_file = base.with_suffix(".py")
        if mod_file.is_file():
            return importlib.machinery.ModuleSpec(
                fullname,
                importlib.machinery.SourceFileLoader(fullname, str(mod_file)),
                origin=str(mod_file),
                is_package=False,
            )
        return None


def register_dacustoms_finder():
    """Register the finder if the customs directory is enabled and exists.

    Idempotent — safe to call from multiple entry points.
    """
    try:
        from constants import dacustoms_dir
    except Exception:
        return  # constants not importable yet (boot ordering) — silent
    d = dacustoms_dir()
    if d is None:
        return
    if not d.is_dir():
        return
    # Guard against double registration.
    for existing in sys.meta_path:
        if isinstance(existing, DacustomsFinder):
            return
    sys.meta_path.append(DacustomsFinder(d))