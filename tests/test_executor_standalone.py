"""Standalone/REPL bare-instance executor lane regression.

Every ``@framework_tool`` dispatch resolves a session id other than ``"0"``
through ``_resolve_brain_session`` (the Phase-0 durable C-wire mapping), which
reads ``_brain_sessions``/``_brain_session_lock`` unconditionally. The full
``ToolRegistry.__init__`` initializes both — but the bare
``ToolRegistry.__new__`` builders of the standalone lane didn't, and the
operator REPL announces the ``'repl'`` identity. Production report 2026-10-30:
the FIRST REPL tool dispatch died with

    AttributeError: 'ToolRegistry' object has no attribute '_brain_session_lock'

before the Brain socket was even consulted. The fix centralizes the init in
``daharness.executor._init_brain_session_state`` and wires every construction
path to it; these tests pin it.
"""

import asyncio
import threading

import pytest

from constants import TransportType
from daharness.models import ToolManifest
from utils.agent_identity import REPL_AGENT_ID


def _bare_executors():
    from daharness.executor import _new_registry
    from replkit.core import _make_executor

    return _new_registry(), _make_executor()


# --- construction paths -------------------------------------------------------

def test_init_helper_sets_brain_session_state():
    """The shared helper stamps the same Phase-0 state ToolRegistry.__init__ carries."""
    from daharness.executor import _init_brain_session_state
    from daharness.registry import ToolRegistry

    reg = ToolRegistry.__new__(ToolRegistry)
    _init_brain_session_state(reg)
    assert isinstance(reg._brain_session_lock, type(threading.Lock()))
    assert reg._brain_sessions is not None


def test_bare_builders_carry_brain_session_state():
    """No bare-instance builder may drift from ToolRegistry.__init__ again."""
    for executor in _bare_executors():
        assert hasattr(executor, "_brain_sessions")
        assert hasattr(executor, "_brain_session_lock")
        assert hasattr(executor, "_tool_instances")


# --- the production crash ------------------------------------------------------

def test_repl_identity_resolves_on_bare_executor(state_root):
    """``'repl'`` (REPL_AGENT_ID) must resolve through the durable map.

    The old bare builders died at the ``with self._brain_session_lock:`` line
    — exactly the reported traceback — because only ``_tool_instances`` was
    set. The map itself is replaced with a real store at the throwaway
    workspace so the resolve is exercised end-to-end without touching the
    operator's brain-session rows.
    """
    from utils.brain_sessions import BrainSessionMap

    for executor in _bare_executors():
        executor._brain_sessions = BrainSessionMap(
            db_path=str(state_root / "brain_sessions.db")
        )
        assert executor._resolve_brain_session("0") == 0
        sid = executor._resolve_brain_session(REPL_AGENT_ID)
        assert isinstance(sid, int) and sid != 0
        # Durable mapping: the same agent resolves to the same int again.
        assert executor._resolve_brain_session(REPL_AGENT_ID) == sid


def test_standalone_dispatch_repl_session(state_root, monkeypatch):
    """Full crash path: execute_tool → brain transport, session 'repl'.

    Pre-fix this raised AttributeError instead of returning an envelope.
    The manifest points at a tool id unknown to any lane, so the run lands
    in the in-process fallback's honest "unknown tool" failure — the point
    is that dispatch completes and journals, not that the tool runs.
    """
    from daharness import executor as executor_module

    manifest = ToolManifest(
        module_id="repl_regression.absent_tool",
        internal_semantic_capability="regression sentinel; resolves nowhere",
        external_sanitized_description="regression sentinel; resolves nowhere",
        implementation_path="does/not/exist.py",
        internal_semantics="regression sentinel",
        transport=TransportType.BRAIN_DISPATCH,
    )

    # Hermetic: never depend on a live Brain socket. A nonexistent path
    # takes the socket-down branch to the in-process fallback, exactly like
    # the deb box where the report was filed.
    monkeypatch.setattr(
        executor_module,
        "brain_socket_path",
        lambda: str(state_root / "no-socket.sock"),
    )

    def _run():
        return asyncio.run(
            executor_module.execute_tool(
                manifest, {}, session_id=REPL_AGENT_ID
            )
        )

    result = _run()
    assert isinstance(result, dict)
    assert result.get("status") == "Failed"
    assert "_brain_session_lock" not in str(result.get("error", ""))