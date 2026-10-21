"""pydantic-ai must stay out of the tree.

The secretary chat lane (daharness/agent.py) was removed 2026-10-20: the
driving LLM is external (an Open WebUI model, gateway or MCP client), and
pydantic-ai was chat-lane-only machinery. Regression surface:

- the full daharness import chain succeeds with pydantic_ai unimportable;
- the chat-lane module itself is gone.
"""

import importlib
import sys

import pytest


def test_daharness_import_never_touches_pydantic_ai(monkeypatch):
    """Importing the full package with pydantic_ai unimportable must work."""
    for name in [
        "daharness",
        "daharness.core",
        "daharness.executor",
        "daharness.registry",
        "daharness.preflight",
    ]:
        monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.setitem(sys.modules, "pydantic_ai", None)

    importlib.import_module("daharness")
    importlib.import_module("daharness.core")

    # Nothing should have "helpfully" imported the chat wheel along the way.
    assert "pydantic_ai" not in sys.modules or sys.modules["pydantic_ai"] is None


def test_chat_lane_module_is_gone():
    with pytest.raises(ModuleNotFoundError, match="daharness"):
        importlib.import_module("daharness.agent")