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
import os
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
    status = finder_status()
    if status["registered"]:
        return
    # If not registered but the dir exists and is valid, register now.
    # (finder_status already logged why if it didn't register.)


def finder_status() -> dict:
    """Trace the full finder registration chain and return a status report.

    This is the answer to "why does ``import dacustoms`` give
    ModuleNotFoundError?" — the operator can see exactly which step of the
    chain broke instead of guessing.  Called by the customs doctor provider
    and safe to call any time (read-only, no side effects).

    Returns a dict with::

        {
            "registered": bool,      # is the finder in sys.meta_path?
            "reason": str,           # human-readable status
            "dir": str | None,       # resolved customs dir (or None)
            "dir_exists": bool,      # does the dir exist on disk?
            "init_present": bool,    # does __init__.py exist in the dir?
            "step": str,             # which step the chain reached
        }
    """
    import logging

    _log = logging.getLogger(__name__)

    # Step 1: can we import constants?
    try:
        from constants import dacustoms_dir, is_service_home
    except Exception as exc:
        return {
            "registered": False,
            "reason": f"constants not importable yet (boot ordering): {exc}",
            "dir": None, "dir_exists": False, "init_present": False,
            "step": "import_constants",
        }

    # Step 2: is this a service-user lane?
    if is_service_home():
        home = os.path.expanduser("~")
        return {
            "registered": False,
            "reason": (
                f"running as a service identity (HOME={home}) — "
                "this lane cannot see the operator's home directory"
            ),
            "dir": None, "dir_exists": False, "init_present": False,
            "step": "service_home_guard",
        }

    # Step 3: is the lane disabled or does the dir resolve?
    d = dacustoms_dir()
    if d is None:
        return {
            "registered": False,
            "reason": "dacustoms lane disabled (DACUSTOMS_DIR=off)",
            "dir": None, "dir_exists": False, "init_present": False,
            "step": "disabled",
        }

    # Step 4: does the dir exist?
    dir_exists = d.is_dir()
    init_present = dir_exists and (d / "__init__.py").is_file()

    # Step 5: is the finder already registered?
    already = any(isinstance(f, DacustomsFinder) for f in sys.meta_path)

    if already:
        reason = f"finder registered for {d}"
        if not init_present:
            reason += " — but __init__.py is missing, import dacustoms will fail"
    elif not dir_exists:
        reason = f"customs dir {d} does not exist — finder not registered"
    elif not init_present:
        reason = f"finder not registered: {d}/__init__.py is missing"
    else:
        # Register now — all conditions met.
        sys.meta_path.append(DacustomsFinder(d))
        already = True
        reason = f"finder registered for {d}"
        _log.info("[dacustoms] finder registered for %s", d)

    return {
        "registered": already,
        "reason": reason,
        "dir": str(d),
        "dir_exists": dir_exists,
        "init_present": init_present,
        "step": "done" if already else "not_registered",
    }