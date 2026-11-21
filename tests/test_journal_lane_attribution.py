"""Journal lane attribution (2026-11-20 relabel incident).

``journal.entries.lane`` states which PROCESS executed the tool body, not
which process dispatched it. Three attribution sources, most specific wins:

  1. socket-side Brain execution — the body ran on the Brain sidecar
     (``brain_lane``) while the dispatching executor lives somewhere else;
  2. the call-site label (``journal_lane=``) — the gateway process hosts
     BOTH the REST route (gateway_lane) and /mcp (mcp_lane);
  3. the dispatching process's own ``lane_name()`` — in-process fallback
     and LOCAL_FILE transports.

Observed live: journal.entries was 100% ``repl_lane`` even though the model
bounced brain → mcp → repl, because (a) the gateway lane's dispatches were
being dropped whole on a missing psycopg driver, so only kernel/repl-lane
rows survived, and (b) even connected, a socket-side Brain-transport call
was attributed to the caller's lane. Both relabeled here.
"""

import asyncio

import pytest

from constants import TransportType
from daharness.models import ToolManifest


MANIFEST = ToolManifest(
    module_id="journal_lane.absent_tool",
    internal_semantic_capability="attribution sentinel; resolves nowhere",
    external_sanitized_description="attribution sentinel; resolves nowhere",
    implementation_path="does/not/exist.py",
    internal_semantics="attribution sentinel",
    transport=TransportType.BRAIN_DISPATCH,
)


@pytest.fixture
def journal_spy(monkeypatch):
    """Capture write_dispatch lane arguments without a live Postgres."""
    from utils import journal

    captured: list[dict] = []

    def _spy(**kwargs):
        captured.append(kwargs)
        return 1

    monkeypatch.setattr(journal, "write_dispatch", _spy)
    return captured


def _dispatch_bare(monkeypatch, journal_lane=None):
    """One dispatch through a bare executor, Brain socket absent.

    Hermetic: the nonexistent socket path takes the socket-down branch to
    the in-process fallback, which journals under the caller's lane."""
    from daharness import executor as executor_module
    from utils.agent_identity import REPL_AGENT_ID

    monkeypatch.setattr(
        executor_module,
        "brain_socket_path",
        lambda: "/nonexistent/journal-test.sock",
    )
    return asyncio.run(
        executor_module.execute_tool(
            MANIFEST, {}, session_id=REPL_AGENT_ID, journal_lane=journal_lane
        )
    )


def _run_dispatch(journal_lane=None):
    """One dispatch through a bare executor, Brain socket absent.

    Hermetic: the nonexistent socket path takes the socket-down branch to
    the in-process fallback, which journals under the caller's lane."""
    from daharness import executor as executor_module
    from utils.agent_identity import REPL_AGENT_ID

    asyncio.run(
        executor_module.execute_tool(
            MANIFEST, {}, session_id=REPL_AGENT_ID, journal_lane=journal_lane
        )
    )


def test_inprocess_fallback_journals_caller_lane(journal_spy, monkeypatch):
    """No socket, no call-site label → the dispatching process's lane."""
    from daharness import executor as executor_module
    from utils import engagement as eng

    # Stand in for 'repl_lane': under pytest lane_name() resolves
    # argv-dependent; pin it so the assertion reads on any runner.
    monkeypatch.setattr(eng, "lane_name", lambda: "repl_lane")
    monkeypatch.setattr(
        executor_module, "brain_socket_path",
        lambda: "/nonexistent/journal-test.sock",
    )
    _run_dispatch()
    assert journal_spy and journal_spy[-1]["lane"] == "repl_lane"


def test_journal_lane_call_site_override(journal_spy, monkeypatch):
    """journal_lane= beats the process role (mcp vs gateway in one proc)."""
    from daharness import executor as executor_module
    from utils import engagement as eng

    monkeypatch.setattr(eng, "lane_name", lambda: "gateway_lane")
    monkeypatch.setattr(
        executor_module, "brain_socket_path",
        lambda: "/nonexistent/journal-test.sock",
    )
    _run_dispatch(journal_lane="mcp_lane")
    assert journal_spy[-1]["lane"] == "mcp_lane"


def test_stamped_executed_lane_wins_and_is_one_shot(journal_spy, monkeypatch):
    """_EXECUTED_LANE beats even journal_lane; consumed by the write."""
    from daharness import executor as executor_module
    from utils import engagement as eng

    monkeypatch.setattr(eng, "lane_name", lambda: "repl_lane")
    monkeypatch.setattr(
        executor_module, "brain_socket_path",
        lambda: "/nonexistent/journal-test.sock",
    )
    token = executor_module._EXECUTED_LANE.set("brain_lane")
    try:
        _run_dispatch(journal_lane="mcp_lane")
    finally:
        executor_module._EXECUTED_LANE.reset(token)
    assert journal_spy[-1]["lane"] == "brain_lane"
    # One-shot: the next dispatch in this context falls back to its own
    # sources instead of inheriting 'brain_lane'.
    _run_dispatch(journal_lane="mcp_lane")
    assert journal_spy[-1]["lane"] == "mcp_lane"
