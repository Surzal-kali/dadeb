"""framework_health findings_db probe: must report truth, never crash.

Two regressions live here. First, ensure_ids_db failures were swallowed and
reported as a generic "could not create/open" detail — the probe once hid a
chromadb import error that way, sending operators chasing permissions that
were not the problem. Second, the failure branch that spells out the real
exception referenced ``exc`` bound by an ``except Exception:`` clause
without ``as exc`` — a NameError that would crash framework_health
outright. Both now fail here instead of in the operator's REPL.
"""

import os

from auxiliaries.framework_status import framework_health


def test_findings_db_up_on_fresh_workspace(state_root):
    report = framework_health()
    finding = report["subsystems"]["findings_db"]
    assert finding["up"] is True
    assert str(state_root / "ids.db") == finding["detail"]
    assert (state_root / "ids.db").exists()


def test_ensure_failure_surfaces_exception_text(state_root, monkeypatch):
    import daharness.findings as findings_mod

    def boom(db_path):
        raise RuntimeError("ModuleNotFoundError: masked-import-canary")

    monkeypatch.setattr(findings_mod, "ensure_ids_db", boom)

    report = framework_health()
    finding = report["subsystems"]["findings_db"]
    assert finding["up"] is False
    # Lane CAN search the state root, so the permission branch must not
    # fire — the detail carries the real exception text instead.
    assert not finding.get("lane_blocked")
    assert "masked-import-canary" in finding["detail"]
    assert "could not create/open" in finding["detail"]


def test_unreadable_state_root_reports_lane_block(state_root):
    os.chmod(state_root, 0)
    try:
        report = framework_health()
    finally:
        os.chmod(state_root, 0o700)

    finding = report["subsystems"]["findings_db"]
    assert finding["up"] is False
    assert finding.get("lane_blocked") is True
    # The lane-permission text is the repair path, not blame: point the
    # operator at the gateway lane / state-root shape, not an outage.
    assert "lane-permission" in finding["detail"]


def test_embed_endpoint_note_lives_in_the_probe(monkeypatch):
    """The embedding endpoint note belongs here, not at registry import.

    The harness's semantic lanes (tool registry + memory) ride EMBED_URL
    (daharness/embedding.py), NOT OLLAMA_BASE_URL (that knob was decoupled
    from embeddings and is the driving-LLM/health endpoint only).  The
    health probe surfaces the resolved embed endpoint + model so the
    operator can tell whether the semantic lanes are pointing at the right
    place.
    """
    from auxiliaries.framework_status import _embed_env_note

    monkeypatch.delenv("EMBED_URL", raising=False)
    note = _embed_env_note()
    assert "EMBED_URL unset" in note
    assert "nomic-embed-text" in note

    monkeypatch.setenv("EMBED_URL", "http://10.40.0.9:8080/v1/embeddings")
    note = _embed_env_note()
    assert "EMBED_URL set" in note
    assert "10.40.0.9" in note