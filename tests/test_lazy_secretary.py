"""pydantic-ai is chat-lane-only machinery.

The packaged headless lanes (gateway, MCP, daemon boot) build ToolRegistry
objects that must never touch the chat wheel: the deb stopped vendoring
pydantic-ai-slim, so a stray top-level import or an agent built eagerly in
``ToolRegistry.__init__`` boots the daemon into ImportError/systemctl exit 1.

Regression surface (lazy trim):
- the full daharness import chain succeeds with pydantic_ai unimportable;
- the agent is built on first use, never at construction;
- a wheel-absent chat-lane use fails with an actionable ImportError naming
  ``pydantic-ai-slim``.
"""

import importlib
import sys

import pytest


class _MinimalRegistry:
    """SecretaryMixin without any chroma/gear — enough for the lazy property."""

    secretary_model = "test-model"


def test_headless_boot_needs_no_chat_wheel(monkeypatch):
    """The full daharness import chain imports cleanly with pydantic_ai
    unimportable (`sys.modules` None entry = import_module raises)."""
    for name in [
        "daharness",
        "daharness.core",
        "daharness.executor",
        "daharness.registry",
        "daharness.agent",
    ]:
        monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.setitem(sys.modules, "pydantic_ai", None)

    importlib.import_module("daharness")

    try_import = importlib.import_module("daharness.agent")
    assert hasattr(try_import, "SecretaryMixin")
    # Nothing should have "helpfully" imported the chat wheel along the way.
    assert "pydantic_ai" not in sys.modules or sys.modules["pydantic_ai"] is None


def test_secretary_built_on_first_use_not_at_init():
    from daharness.agent import SecretaryMixin

    builds = []

    class _R(SecretaryMixin):
        def _init_secretary_agent(self, model=None):
            builds.append(1)
            return "agent-double"

    r = _R()
    assert r._secretary is None
    assert builds == []  # construction built nothing

    assert r.secretary == "agent-double"  # first ACCESS builds
    assert r.secretary == "agent-double"  # cached afterwards
    assert builds == [1]

    # Assigning replaces without a rebuild; `None` re-arms lazy construction.
    r.secretary = "test-double"
    assert r.secretary == "test-double"
    r.secretary = None
    assert r.secretary == "agent-double"
    assert builds == [1, 1]


def test_chat_lane_wheel_absent_error_names_the_fix(monkeypatch):
    import daharness.agent as agent_module

    monkeypatch.setitem(sys.modules, "pydantic_ai", None)
    monkeypatch.setattr(agent_module, "_CHAT_RUNTIME", None)

    class _R(_MinimalRegistry, agent_module.SecretaryMixin):
        pass

    r = _R()
    with pytest.raises(ImportError, match="pydantic-ai-slim"):
        _ = r.secretary
    # The failed build must not be cached — a later lane that installs the
    # wheel (or stubs the test double) still reaches a working agent.
    assert r._secretary is None