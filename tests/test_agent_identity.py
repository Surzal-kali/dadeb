"""Phase 0 identity resolution tests — announce-or-mint contract.

Covers utils/agent_identity.py (resolver, normalizer, minter, contextvar)
and the identity fixes that ride it: the executor's envelope stamping, the
REPL's explicit 'repl' identity, and evidence's owned agent_id.
"""

import pytest

from utils.agent_identity import (
    ANON_PREFIX,
    REPL_AGENT_ID,
    SHARED_AGENT_ID,
    agent_id_context,
    current_agent_id,
    is_minted,
    mint_agent_id,
    normalize_agent_id,
    resolve_agent_id,
    set_current_agent_id,
)


# --- normalization ------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("kai9000", "kai9000"),
        ("Kai9000", "kai9000"),  # lowercased
        ("owui:chat-123:message-456", "owui:chat-123:message-456"),
        ("claude.agent-1", "claude.agent-1"),
        ("  spaced  ", "spaced"),
    ],
)
def test_normalize_accepts_valid_announcements(raw, expected):
    assert normalize_agent_id(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        None,
        "",
        "   ",
        "ab",  # too short
        "a" * 65,  # too long
        "kai 9000",  # space inside -> charset violation
        "kai/9000",  # slash not in charset
        "anon-spoofed",  # gateway-reserved mint prefix
        "anon-",  # reserved even bare
    ],
)
def test_normalize_rejects_unusable(raw):
    assert normalize_agent_id(raw) is None


def test_normalizer_is_case_and_prefix_safe():
    # An uppercase spoof of the mint prefix still re-mints via resolve.
    aid, prov = resolve_agent_id("Anon-123")
    assert prov == "minted"
    assert aid.startswith(ANON_PREFIX)


# --- resolution ----------------------------------------------------------------


def test_resolve_declared():
    aid, prov = resolve_agent_id("kai9000")
    assert aid == "kai9000"
    assert prov == "declared"


def test_resolve_shared_is_explicit_only():
    aid, prov = resolve_agent_id("0")
    assert aid == SHARED_AGENT_ID
    assert prov == "shared"


def test_resolve_mints_on_null():
    aid, prov = resolve_agent_id(None)
    assert prov == "minted"
    assert aid.startswith(ANON_PREFIX) and len(aid) == len(ANON_PREFIX) + 8


def test_resolve_mints_fresh_ids_each_call():
    a, _ = resolve_agent_id(None)
    b, _ = resolve_agent_id(None)
    assert a != b


def test_minted_ids_are_registered():
    aid = mint_agent_id()
    assert is_minted(aid)
    assert not is_minted("nope")


# --- ambient contextvar ----------------------------------------------------------


def test_ambient_default_is_shared_id():
    assert current_agent_id() == SHARED_AGENT_ID


def test_agent_id_context_scopes_and_restores():
    assert current_agent_id() == SHARED_AGENT_ID
    with agent_id_context("kai9000") as inner:
        assert inner == "kai9000"
        assert current_agent_id() == "kai9000"
    assert current_agent_id() == SHARED_AGENT_ID


def test_set_and_reset_token_roundtrip():
    token = set_current_agent_id("abc")
    try:
        assert current_agent_id() == "abc"
    finally:
        from utils.agent_identity import reset_current_agent_id

        reset_current_agent_id(token)
    assert current_agent_id() == SHARED_AGENT_ID


# --- dispatch integration ---------------------------------------------------------


def _run(coro):
    """Drive a coroutine without pytest-asyncio (the suite pins
    --strict-markers and pytest-asyncio is not a dev dependency)."""
    import asyncio

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def test_executor_envelope_carries_identity(state_root, monkeypatch):
    """A dispatch through the executor stamps identity + provenance; an
    unusable session_id is minted (never silently shared '0')."""
    from daharness.models import ToolManifest
    from constants import TransportType
    from daharness.executor import ExecutorMixin

    mixin = ExecutorMixin.__new__(ExecutorMixin)

    async def _fake_dispatch(self, manifest, arguments, session_id):
        return {"status": "Success", "result": {"ok": True}}

    monkeypatch.setattr(ExecutorMixin, "_dispatch_by_transport", _fake_dispatch)
    # _ensure_valid_manifest lives on ToolRegistry, not the mixin — inject
    # the identity stub onto the class (raising=True lets setattr create it).
    monkeypatch.setattr(
        ExecutorMixin, "_ensure_valid_manifest", lambda self, m: m, raising=False
    )
    monkeypatch.setattr(ExecutorMixin, "_journal_dispatch", lambda *a, **k: None)

    manifest = ToolManifest(
        module_id="test.tool",
        internal_semantic_capability="test capability",
        external_sanitized_description="test tool",
        internal_semantics="test",
        implementation_path="/nonexistent/test_tool.py",
        transport=TransportType.BRAIN_DISPATCH,
    )

    result = _run(mixin.execute_tool(manifest, {}, session_id=""))
    ident = result.get("identity")
    assert ident is not None
    assert ident["provenance"] == "minted"
    assert ident["agent_id"].startswith(ANON_PREFIX)


def test_normalize_adopts_own_mint():
    """Echoing THIS process's minted id back resolves to the SAME id —
    the gateway mints once and the executor's re-resolve no longer mints
    a second identity the client never saw (2026-10-30 code review)."""
    aid = mint_agent_id()
    assert normalize_agent_id(aid) == aid


def test_resolve_roundtrips_minted_id_to_declared():
    resolved, prov = resolve_agent_id(None)
    assert prov == "minted"
    again, prov2 = resolve_agent_id(resolved)
    assert again == resolved  # no fresh mint on the echo
    assert prov2 == "declared"


def test_executor_passes_agent_identity_through(state_root, monkeypatch):
    """The gateway resolves ONE identity and passes it through: a supplied
    ``agent_identity`` tuple must reach the envelope verbatim, and the
    raw ``session_id`` (intentionally unusable here) must NOT re-resolve."""
    from daharness.models import ToolManifest
    from constants import TransportType
    from daharness.executor import ExecutorMixin

    mixin = ExecutorMixin.__new__(ExecutorMixin)

    async def _fake_dispatch(self, manifest, arguments, session_id):
        return {"status": "Success", "result": {"ok": True}}

    monkeypatch.setattr(ExecutorMixin, "_dispatch_by_transport", _fake_dispatch)
    monkeypatch.setattr(
        ExecutorMixin, "_ensure_valid_manifest", lambda self, m: m, raising=False
    )
    monkeypatch.setattr(ExecutorMixin, "_journal_dispatch", lambda *a, **k: None)

    manifest = ToolManifest(
        module_id="test.tool",
        internal_semantic_capability="test capability",
        external_sanitized_description="test tool",
        internal_semantics="test",
        implementation_path="/nonexistent/test_tool.py",
        transport=TransportType.BRAIN_DISPATCH,
    )

    # '' would mint a fresh anon- id if it were re-resolved; the tuple
    # short-circuits resolution entirely.
    result = _run(mixin.execute_tool(
        manifest, {}, session_id="",
        agent_identity=("kai9000", "declared"),
    ))
    ident = result.get("identity")
    assert ident == {"agent_id": "kai9000", "provenance": "declared"}


# --- lane fixes -----------------------------------------------------------------


def test_repl_lane_announces_identity():
    # replkit runs inside the checkout; the constant pins the contract.
    assert REPL_AGENT_ID == "repl"
    aid, prov = resolve_agent_id(REPL_AGENT_ID)
    assert (aid, prov) == ("repl", "declared")


def test_evidence_record_uses_ambient_identity(state_root):
    from utils.evidence import EvidenceStore

    # evidence requires an armed engagement slug; arm one and record.
    import json
    from pathlib import Path

    eng_dir = Path(state_root) / "engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / ".armed_engagement.json").write_text(json.dumps({"slug": "test-eng"}))

    store = EvidenceStore()
    with agent_id_context("kai9000"):
        entry = store.record("observation", "ambient identity test", engagement="test-eng")
    assert entry["agent_id"] == "kai9000"

    with agent_id_context(""):  # transport fallback -> shared id
        entry2 = store.record("observation", "fallback id test", engagement="test-eng")
    assert entry2["agent_id"] == SHARED_AGENT_ID