"""fields= selection self-describing envelope (2026-11-02 regression).

A fields= retrieval that drops top-level keys must say so on the envelope
(``_scratch_fields_selected``, mirroring the ``_scratch_search_capped``
convention) — the model otherwise sees a one-key result with no hint that
the rest of the payload still exists under the same scratch_ref, which is
how a rich 93 KB ffuf result collapsed to ``{"status": "done"}`` in the
wild. Python and rust sort the note's field lists so both implementations
agree byte-for-byte (serde_json without preserve_order iterates
alphabetically).
"""

from utils.scratch_store import ScratchStore


def _mkstore(tmp_path: str):
    return ScratchStore(
        db_path=str(tmp_path / "scratch.db"),
        data_dir=str(tmp_path / "scratch-data"),
    )


def _store_rich(store):
    return store.store(
        {"status": "done", "recent_lines": ["a"], "findings": [{"x": 1}]},
        agent_id="agent-a",
        tool_id="tool",
    )["scratch_ref"]


def test_fields_selection_stamps_note(tmp_path):
    store = _mkstore(tmp_path)
    ref = _store_rich(store)

    env = store.retrieve(ref, agent_id="agent-a", fields="status")
    assert env["status"] == "ok"
    assert env["result"] == {"status": "done"}
    note = env["_scratch_fields_selected"]
    assert note["fields"] == ["status"]
    assert note["available_fields"] == ["findings", "recent_lines", "status"]
    assert note["dropped_fields"] == ["findings", "recent_lines"]
    assert "re-query without 'fields'" in note["note"]


def test_unknown_only_fields_still_notes(tmp_path):
    store = _mkstore(tmp_path)
    ref = _store_rich(store)

    env = store.retrieve(ref, agent_id="agent-a", fields="zzz")
    assert env["result"] == {}
    note = env["_scratch_fields_selected"]
    assert note["fields"] == ["zzz"]
    assert note["dropped_fields"] == ["findings", "recent_lines", "status"]


def test_full_retrieve_carries_no_note(tmp_path):
    store = _mkstore(tmp_path)
    ref = _store_rich(store)

    env = store.retrieve(ref, agent_id="agent-a")
    assert env["result"] == {"status": "done", "recent_lines": ["a"], "findings": [{"x": 1}]}
    assert "_scratch_fields_selected" not in env

    # Selecting every field drops nothing -> no note.
    env = store.retrieve(ref, agent_id="agent-a", fields="status, recent_lines, findings")
    assert "_scratch_fields_selected" not in env