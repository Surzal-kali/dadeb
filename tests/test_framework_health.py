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


def test_ollama_unset_pointer_lives_in_the_probe(monkeypatch):
    """OLLAMA_BASE_URL's unset note belongs here, not at registry import.

    daharness.registry used to log an "unset" INFO on every import — every
    lane (REPL, selftest, gateway, Brain boot) heard it, including the deb
    lane that deliberately ships without the knob. The knob's only live
    consumer is this health probe, so the note surfaces in its ollama
    detail instead.
    """
    from auxiliaries.framework_status import _ollama_env_note

    monkeypatch.delenv("OLLAMA_BASE_URL", raising=False)
    note = _ollama_env_note()
    assert "OLLAMA_BASE_URL unset" in note
    assert "EMBED_URL" in note

    monkeypatch.setenv("OLLAMA_BASE_URL", "http://10.40.0.9:11434/v1")
    assert _ollama_env_note() == ""