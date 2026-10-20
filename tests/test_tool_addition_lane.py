"""The tool-author contract: "add a new py script" is discoverable and testable.

The framework invites operators and integrators to drop new tool modules
into the allowed roots. This file proves both minting paths work end-to-end
with a real discovery pass — so a tool author can write their module and
then, in the same tree, drop a test_<tool>.py that macros it:

  (1) an argparse CLI module  -> LOCAL_FILE manifest + real subprocess run;
  (2) a module whose argparse is internal plumbing (_NO_LOCAL_TOOL = True)
      with @framework_tool members -> BRAIN_DISPATCH manifest + in-process
      run through the executor (no Brain socket needed);
  (3) the opt-out flag actually keeps internal argparse OFF the secretary
      surface (the gate-bypass hole it closed).

Demo modules are written into payloads/ (discovery walks ALLOWED_TOOL_ROOTS
and imports FRAMEWORK_ROOT-relative) and removed in finally. Underscore-
prefixed unique names keep them collision-free with real tools.
"""

import asyncio
import contextlib
from pathlib import Path

import pytest

from constants import TransportType
from daharness.executor import execute_tool
from daharness.registry import ToolRegistry

PAYLOADS = Path("payloads")


def _write(path: Path, text: str):
    assert not path.exists(), f"demo tool name collision: {path}"
    path.write_text(text, encoding="utf-8")


def _cleanup(path: Path):
    with contextlib.suppress(OSError, FileNotFoundError):
        path.unlink()
    for artifact in path.parent.glob(f"__pycache__/{path.stem}*.pyc"):
        with contextlib.suppress(OSError):
            artifact.unlink()


@pytest.fixture
def registry_with_discovery():
    reg = ToolRegistry.__new__(ToolRegistry)
    reg._tool_instances = {}
    return reg


def test_argparse_module_mints_local_file_tool_and_runs(registry_with_discovery):
    script = PAYLOADS / "_selftest_demo_script.py"
    module_id = "payloads._selftest_demo_script"
    _write(
        script,
        '''"""Selftest demo CLI: echoes a greeting back N times for macro tests.

Argparse module minted as a LOCAL_FILE tool by the static discovery pass.
"""
import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--greeting", default="hello", help="what to say")
    parser.add_argument("--count", type=int, default=1, help="repeat count")
    args = parser.parse_args()
    print(f"greeting={args.greeting} count={args.count}")

if __name__ == "__main__":
    main()
''',
    )
    reg = registry_with_discovery
    try:
        manifest = None
        for m in reg.discover_local_tools():
            if m.module_id == module_id:
                manifest = m
                break
        assert manifest is not None, f"{module_id} not minted by the static pass"
        assert manifest.transport == TransportType.LOCAL_FILE
        props = manifest.parameters["properties"]
        assert props["greeting"] == {"type": "string", "description": "what to say"}
        assert props["count"] == {"type": "integer", "description": "repeat count"}

        envelope = asyncio.run(
            execute_tool(manifest, {"greeting": "hi", "count": 2})
        )
        stdout = envelope["stdout"]
        assert "greeting=hi count=2" in stdout
        assert envelope["status"] == "Success" and envelope["return_code"] == 0
    finally:
        _cleanup(script)


def test_decorated_function_mints_brain_dispatch_and_runs(registry_with_discovery):
    script = PAYLOADS / "_selftest_demo_author_tool.py"
    module_id = "payloads._selftest_demo_author_tool"
    tool_id = f"{module_id}.author_hello"
    _write(
        script,
        '''"""Selftest demo author tool: decorated @framework_tool with internal argparse.

_NO_LOCAL_TOOL opts the internal argparse OUT of the static mint (it would
bypass the approval gate as a second entry point); the decorated member
still registers normally via the dynamic pass.
"""
import argparse

from constants import framework_tool

_NO_LOCAL_TOOL = True


def main():
    # Internal plumbing — job runner shape, deliberately minted as no tool.
    parser = argparse.ArgumentParser()
    parser.add_argument("--secret-internal-flag", action="store_true")
    parser.parse_args()


@framework_tool("Bark hello from the author-tool demo (no net, no state).")
def author_hello(name: str = "world") -> dict:
    """Bark hello from the author-tool demo (no net, no state)."""
    return {"bark": f"hello {name}", "name": name}
''',
    )
    reg = registry_with_discovery
    try:
        local = None
        decorated = None
        for m in reg.discover_local_tools():
            if m.module_id == module_id:
                local = m
            elif m.module_id == tool_id:
                decorated = m
        assert local is None, (
            "internal argparse minted despite _NO_LOCAL_TOOL — "
            "a gate-bypassing second entry point is on the secretary surface"
        )
        assert decorated is not None, f"{tool_id} not minted by the dynamic pass"
        assert decorated.transport == TransportType.BRAIN_DISPATCH
        assert "Bark hello" in decorated.internal_semantic_capability

        envelope = asyncio.run(execute_tool(decorated, {"name": "selftest"}))
        result = envelope["result"]
        assert result["bark"] == "hello selftest"
        assert result["name"] == "selftest"
    finally:
        _cleanup(script)


def test_method_tools_carry_class_names(registry_with_discovery):
    script = PAYLOADS / "_selftest_demo_client.py"
    module_id = "payloads._selftest_demo_client.DemoClient.stateful_ping"
    _write(
        script,
        '''"""Selftest demo client: methods on stateful classes mint with the class name."""
from constants import framework_tool


class DemoClient:
    @framework_tool("Ping a live handle on this demo client (method mint check).")
    def stateful_ping(self, token: str = "t0") -> dict:
        """Ping a live handle on this demo client (method mint check)."""
        return {"pong": token}
''',
    )
    reg = registry_with_discovery
    try:
        minted = [
            m.module_id
            for m in reg.discover_local_tools()
            if m.module_id == module_id
        ]
        assert minted == [module_id], f"method tool not minted with class name: {minted}"
    finally:
        _cleanup(script)