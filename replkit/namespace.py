"""The kitted-out IPython namespace: tools, stdlib overlay, envelope helpers.

``build_ipython_namespace(manifests)`` returns a dict suitable for
``IPython.embed(user_ns=...)`` / the ZMQ kernel's ``user_ns``.  Layers:

  • bare tool aliases (one ``async def`` wrapper per tool — :mod:`replkit.wrappers`)
  • ``tools`` dict (same objects, browsable via ``tools.<Tab>``)
  • stdlib convenience overlay (modules + bare functions) so a security
    session doesn't start with five ``import`` lines
  • IPython.display wrapper classes as bare names (``display()`` itself is
    deliberately absent — every IPython shell injects it as a builtin)
  • envelope helpers (``find`` / ``pluck`` / ``grep`` / ``keys`` / ``scratch``
    — :mod:`replkit.envelope`)
  • operator surfaces: ``sessions()``, ``scope_status()``, ``scope_search()``.
    ``scope_on``/``scope_off`` are deliberately NOT in the namespace —
    arming the gate is operator-only (the CLI), enforced at the code level.
"""

import asyncio
import base64 as _base64
import hashlib as _hashlib
import datetime as _datetime
import ipaddress as _ipaddress
import json
import os
import pprint as _pprint
import re as _re
import socket as _socket
import string as _string
import struct
import subprocess as _subprocess
import sys
import textwrap as _textwrap
import time
import traceback
import urllib.parse as _urlparse
from typing import Any, Dict, List, Optional

from daharness.models import ToolManifest
from daharness.registry import ToolRegistry

from replkit.core import (
    _make_executor,
    discover_tools,
    resolve_callable,
    run_tool,
)
from replkit.envelope import find, grep, keys, pluck, scratch
from replkit.wrappers import build_tool_aliases, _make_tool_wrapper

# ── Stdlib convenience overlay for the IPython namespace ─────────────────────
#
# IPython gives you the full Python language, but bare builtins like ``sleep``
# or common stdlib functions like ``json.dumps`` aren't pre-imported — you have
# to ``import json`` first.  In a security workflow you're constantly doing
# things like ``sleep(30)`` after launching a background job, ``json.dumps`` on
# a tool result, ``base64.b64decode`` on a blob, or ``hashlib.sha256`` on a
# payload.  This overlay pre-imports those so they're one keystroke away.
#
# Modules are injected as themselves (``json``, ``os``, ``hashlib``) so tab-
# completion and ``?`` introspection work.  A few bare functions are exposed
# at the top level (``sleep``, ``b64decode``, ``b64encode``, ``pprint``) for
# the ones you reach for most — the rest are available as ``module.func``.

_STDLIB_MODULES: Dict[str, Any] = {
    "asyncio": asyncio,
    "json": json,
    "os": os,
    "sys": sys,
    "time": time,
    "pathlib": __import__("pathlib"),
    "base64": _base64,
    "hashlib": _hashlib,
    "datetime": _datetime,
    "ipaddress": _ipaddress,
    "re": _re,
    "socket": _socket,
    "subprocess": _subprocess,
    "random": __import__("random"),
    "string": _string,
    "textwrap": _textwrap,
    "pprint": _pprint,
    "traceback": traceback,
    "struct": struct,
    "urllib": __import__("urllib"),
}

# Bare functions hoisted to top-level for ergonomics — the ones you'd
# otherwise type ``from X import Y`` for every session.
_STDLIB_BARES: Dict[str, Any] = {
    "sleep": time.sleep,
    "b64decode": _base64.b64decode,
    "b64encode": _base64.b64encode,
    "pp": _pprint.pprint,
    "pformat": _pprint.pformat,
    "urlsplit": _urlparse.urlsplit,
    "urljoin": _urlparse.urljoin,
    "quote": _urlparse.quote,
    "unquote": _urlparse.unquote,
    "sha256": _hashlib.sha256,
    "md5": _hashlib.md5,
    "pprint": _pprint.pprint,
}


# ── IPython.display wrapper classes (bare-name injection) ────────────────────
#
# ``display()`` itself is deliberately absent: IPython's ``init_displayhook()``
# (interactiveshell.py ~896) injects it into ``builtins`` in every shell,
# including the ZMQ kernel — so it never needed us.  These wrapper classes
# are injected as bare names so cells can do ``Markdown("## heading")`` /
# ``HTML(table_str)`` / ``Math(r'\\sum p_i \\log p_i')`` / ``Latex(...)`` with
# zero imports.  Loaded lazily so headless modes (``run`` / ``oneshot`` /
# ``search``) that never build the IPython namespace pay nothing.
_DISPLAY_CLASSES: Dict[str, Any] | None = None


def _load_display_classes() -> Dict[str, Any]:
    """Lazy IPython.display wrapper classes for bare-name injection.

    Returns a dict of ``{name: class}`` for ``Markdown``, ``HTML``, ``JSON``,
    ``Image``, ``Javascript``, ``Math``, ``Latex``, and ``DisplayHandle``.
    ``display()`` is not included — it's a builtin in every IPython shell already.

    ``DisplayHandle`` enables stateful, in-place output updates:
    ``h = display(obj, display_id=True); h.update(new_obj)``.  In the ZMQ
    kernel lane (JupyterLab / VS Code) the frontend replaces the previous
    output in-place via the ``display_id`` protocol — ideal for live progress
    tables during long tool runs.  In the terminal lane (InteractiveShellEmbed)
    it degrades gracefully to a second print below the first — harmless, just
    not in-place.  The terminal can't do in-place updates (scrolling buffer),
    so this is the honest fallback rather than a fake no-op.
    """
    global _DISPLAY_CLASSES
    if _DISPLAY_CLASSES is None:
        from IPython.display import (
            DisplayHandle,
            HTML,
            Image,
            JSON,
            Javascript,
            Latex,
            Markdown,
            Math,
        )

        _DISPLAY_CLASSES = {
            "Markdown": Markdown,
            "HTML": HTML,
            "JSON": JSON,
            "Image": Image,
            "Javascript": Javascript,
            "Math": Math,
            "Latex": Latex,
            "DisplayHandle": DisplayHandle,
        }
    return _DISPLAY_CLASSES


def build_ipython_namespace(
    manifests: List[ToolManifest],
) -> Dict[str, Any]:
    """Build the full kitted-out IPython user namespace.

    Returns a dict suitable for ``IPython.embed(user_ns=...)`` containing:
      • One ``async def`` wrapper per discovered tool, keyed by short alias
      • ``manifests`` — the flat list (still available for advanced use)
      • ``manifest_by_id(id)`` — lookup helper
      ``registry`` — bare executor instance
      • ``run_tool``, ``discover_tools``, ``resolve_callable`` — raw helpers
      • ``ToolManifest``, ``ToolRegistry`` — model classes
      • ``tools`` — ``{alias: wrapper}`` dict (same objects as the top-level
        aliases, collected for ``tools.<Tab>`` browsing)
      • ``sessions()``, ``scope_status()``, ``scope_search()`` — operator
        command wrappers (scope_on/scope_off are NOT in the namespace;
        use ``python tool_repl.py scope on|off`` from the terminal)
      • Stdlib convenience overlay — common modules (``json``, ``os``,
        ``hashlib``, ``base64``, ``socket``, ``re``, ``subprocess``,
        ``datetime``, ``ipaddress``, …) and bare functions (``sleep``,
        ``b64decode``, ``b64encode``, ``pp``, ``sha256``, ``urlsplit``, …)
        pre-imported so you don't have to ``import`` them mid-session.
      • Envelope helpers — ``find()``, ``pluck()``, ``grep()``, ``keys()``,
        ``scratch()`` for deep-searching large tool results without
        remembering the envelope shape.
    """
    ns: Dict[str, Any] = {}

    # ── Stdlib convenience overlay (injected first so tool aliases win
    #    on any name collision — unlikely but deterministic) ────────────
    ns.update(_STDLIB_MODULES)
    ns.update(_STDLIB_BARES)
    ns.update(_load_display_classes())

    # ── Envelope helpers (deep-search / extract from tool results) ─────
    ns["find"] = find
    ns["pluck"] = pluck
    ns["grep"] = grep
    ns["keys"] = keys
    ns["scratch"] = scratch

    # ── Tool wrappers ───────────────────────────────────────────────────
    alias_map = build_tool_aliases(manifests)
    tools: Dict[str, Any] = {}
    for alias, m in alias_map.items():
        wrapper = _make_tool_wrapper(m, manifests)
        ns[alias] = wrapper
        tools[alias] = wrapper
    ns["tools"] = tools
    ns["manifests"] = manifests
    ns["registry"] = _make_executor()

    def manifest_by_id(tool_id: str) -> Optional[ToolManifest]:
        """Look up a manifest by its full ``module_id``."""
        return next((m for m in manifests if m.module_id == tool_id), None)
    ns["manifest_by_id"] = manifest_by_id

    # ── Raw helpers (unchanged from the old namespace) ──────────────────
    ns["run_tool"] = run_tool
    ns["discover_tools"] = discover_tools
    ns["resolve_callable"] = resolve_callable
    ns["ToolManifest"] = ToolManifest
    ns["ToolRegistry"] = ToolRegistry

    # ── Operator command wrappers (sync, print directly) ────────────────
    # These wrap the existing REPL command bodies so the operator has the
    # same control surface inside IPython without typing ``!`` shell escapes.

    def _sessions():
        """Show Brain-held (shared) vs REPL-local sessions — same as the ``sessions`` REPL command."""
        # _sessions_command is async; run it in the current loop via ensure_future
        import asyncio as _a
        try:
            loop = _a.get_event_loop()
        except RuntimeError:
            loop = _a.new_event_loop()
            _a.set_event_loop(loop)
        # If we're inside IPython's autoawait loop, create_task works; otherwise
        # run_until_complete in a fresh loop.  Using a coroutine wrapper keeps
        # it simple — the operator types ``sessions()`` (no await).
        from replkit.brain_lane import _sessions_command
        coro = _sessions_command()
        if loop.is_running():
            # IPython's autoawait would normally handle this, but since this is
            # a sync wrapper, we use run_until_complete on a nested loop.
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                pool.submit(_a.run, coro).result()
        else:
            loop.run_until_complete(coro)
    ns["sessions"] = _sessions

    def _scope_on(handle: str, platform: str = "h1", strict: bool = True,
                  ip_boundary: bool = False):
        """Arm the packet-scope gate.  REMOVED from the kernel namespace.

        Arming/disarming is operator-only — the agent must not be able to
        toggle the gate from execute_code.  Use the CLI instead:

            python tool_repl.py scope on <handle> [--platform h1]
        """
        raise PermissionError(
            "scope_on is not available in the kernel namespace. "
            "Arming the scope gate is operator-only — use the CLI: "
            "python tool_repl.py scope on <handle>"
        )
    # NOT registered in ns — the function exists only so the docstring
    # is discoverable if someone imports it, but it's not callable from
    # execute_code.

    def _scope_off():
        """Disarm the packet-scope gate.  REMOVED from the kernel namespace.

        Disarming is operator-only — the agent must not be able to toggle
        the gate from execute_code.  Use the CLI instead:

            python tool_repl.py scope off
        """
        raise PermissionError(
            "scope_off is not available in the kernel namespace. "
            "Disarming the scope gate is operator-only — use the CLI: "
            "python tool_repl.py scope off"
        )
    # NOT registered in ns — same as scope_on.

    def _scope_status():
        """Show the armed state, asset counts, and manifest age."""
        from replkit.operator_cli import _scope_command
        _scope_command("status")
    ns["scope_status"] = _scope_status

    def _scope_search(query: str, platform: str = "all", assets: bool = False,
                      handle: str = "", refresh: bool = False, limit: int = 10,
                      as_json: bool = False):
        """Query bug-bounty boards for matching programs.

        Example::

            scope_search("starbucks", assets=True)
        """
        from replkit.operator_cli import _scope_command
        flags = [f"--platform={platform}", f"--limit={limit}"]
        if assets:
            flags.append("--assets")
        if handle:
            flags.append(f"--handle={handle}")
        if refresh:
            flags.append("--refresh")
        if as_json:
            flags.append("--json")
        rest = f"search {query} {' '.join(flags)}"
        _scope_command(rest)
    ns["scope_search"] = _scope_search

    return ns