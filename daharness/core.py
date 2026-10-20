"""Backwards-compatibility shim.

The real implementation now lives in the focused submodules
(:mod:`daharness.models`, :mod:`daharness.registry`, :mod:`daharness.executor`,
:mod:`daharness.agent`). This module only re-exports the legacy public names so
existing ``from daharness.core import ...`` imports keep working, and keeps the
``python3 daharness/core.py`` script entry point (``--clear`` / ``--chat``).
"""

import asyncio
import sys
from pathlib import Path

# When run as a script (``python3 daharness/core.py``) this file is ``__main__``
# and the ``daharness`` package is not yet on the path, so absolute imports of
# the submodules would fail. Put the project root (parent of this package dir)
# on sys.path first; the package __init__ re-applies the same insert idempotently.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from daharness.models import ToolManifest  # noqa: E402,F401
from daharness.registry import OllamaEmbeddingFunction, ToolRegistry  # noqa: E402,F401
from daharness.agent import (  # noqa: E402,F401
    SecretaryDeps,
    _chat,
    _cli_confirmer,
    _parse_tool_args,
    _run_confirmer,
    create_secretary_agent,
    secretary_execute_tool,
    secretary_search_tools,
)

__all__ = [
    "OllamaEmbeddingFunction",
    "SecretaryDeps",
    "ToolManifest",
    "ToolRegistry",
    "_chat",
    "_cli_confirmer",
    "_parse_tool_args",
    "_run_confirmer",
    "create_secretary_agent",
    "secretary_execute_tool",
    "secretary_search_tools",
]


if __name__ == "__main__":
    # Startup script: scan the repo for its tools and register them into the
    # vector database for the secretary model to use.
    try:
        registry = ToolRegistry(embedding_model=OllamaEmbeddingFunction())

        # Clear the collection if --clear flag is passed
        if "--clear" in sys.argv:
            print("[bootstrap] Clearing collection 'tool_inventory'...")
            # Get all IDs and delete them
            existing = registry.collection.get()
            if existing["ids"]:
                registry.collection.delete(ids=existing["ids"])
                print(
                    f"[bootstrap] Deleted {len(existing['ids'])} tools from collection."
                )
            else:
                print("[bootstrap] Collection already empty.")

        if "--chat" in sys.argv:
            asyncio.run(_chat(registry))
        else:
            asyncio.run(registry.bootstrap_registry())
    except KeyboardInterrupt:
        print("\n[bootstrap] Interrupted by user.")
    except Exception as e:
        print(f"[bootstrap] Error: {e}")
        import traceback

        traceback.print_exc()
