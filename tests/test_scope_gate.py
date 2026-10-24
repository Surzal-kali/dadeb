"""Tests for the scope tool-disable list (operator authority over non-traffic tools).

Covers: arm() carry-forward, family-vs-exact matching, terminal-lane refusal,
disarmed refusal, and the disabled_reject_envelope shape. The executor and
Brain enforcement points are integration-tested via the is_disabled() helper
they both call — the verdict logic is the unit under test here.
"""

import json

import pytest

from utils import scope_gate


@pytest.fixture
def armed_scope(state_root):
    """Arm the gate against a minimal lab manifest so disable/enable work."""
    scope_dir = state_root / "scope"
    scope_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "handle": "local-lab",
        "platform": "lab",
        "in_scope": [{"asset_type": "CIDR", "asset_identifier": "10.0.0.0/24"}],
        "out_of_scope_assets": [],
    }
    (scope_dir / "lab_local-lab.json").write_text(json.dumps(manifest))
    scope_gate._CACHE.clear()
    res = scope_gate.arm("local-lab", platform="lab")
    assert res["ok"], res
    yield state_root
    scope_gate.disarm()
    scope_gate._CACHE.clear()


class TestMatching:
    def test_family_prefix_kills_whole_family(self, armed_scope):
        res = scope_gate.disable_tools(["payloads.hash_crack."])
        assert res["ok"]
        assert "payloads.hash_crack." in res["disabled_tools"]
        for tid in ("payloads.hash_crack.run_john",
                     "payloads.hash_crack.run_hashcat",
                     "payloads.hash_crack.suggest_crack_mode"):
            dis, prefix = scope_gate.is_disabled(tid)
            assert dis, f"{tid} should be disabled"
            assert prefix == "payloads.hash_crack."

    def test_bare_stem_is_exact_only(self, armed_scope):
        res = scope_gate.disable_tools(["payloads.hash_crack.run_john"])
        assert res["ok"]
        dis, _ = scope_gate.is_disabled("payloads.hash_crack.run_john")
        assert dis
        # A sibling is NOT disabled (bare stem = exact match only).
        dis, _ = scope_gate.is_disabled("payloads.hash_crack.run_hashcat")
        assert not dis

    def test_not_disabled_when_disarmed(self, state_root):
        scope_gate._CACHE.clear()
        dis, prefix = scope_gate.is_disabled("payloads.hash_crack.run_john")
        assert not dis
        assert prefix is None


class TestArmCarryForward:
    def test_re_arm_preserves_disabled_list(self, armed_scope):
        scope_gate.disable_tools(["payloads.hash_crack."])
        # Re-arm (simulates a manifest refresh).
        res = scope_gate.arm("local-lab", platform="lab")
        assert res["ok"]
        assert res["disabled_tools_count"] == 1
        dis, _ = scope_gate.is_disabled("payloads.hash_crack.run_john")
        assert dis, "disable must survive a re-arm"

    def test_re_arm_empty_when_no_prior_disable(self, armed_scope):
        res = scope_gate.arm("local-lab", platform="lab")
        assert res["ok"]
        assert res["disabled_tools_count"] == 0


class TestTerminalLaneGuard:
    def test_refuse_findings_without_force(self, armed_scope):
        res = scope_gate.disable_tools(["utils.findings."])
        assert not res["ok"]
        assert "terminal" in res["error"].lower() or "force" in res["error"].lower()

    def test_refuse_memory_without_force(self, armed_scope):
        res = scope_gate.disable_tools(["utils.memory_tools."])
        assert not res["ok"]

    def test_force_allows_terminal(self, armed_scope):
        res = scope_gate.disable_tools(["utils.findings."], force=True)
        assert res["ok"]
        dis, _ = scope_gate.is_disabled("utils.findings.report_finding")
        assert dis


class TestDisarmedRefusal:
    def test_disable_refused_when_disarmed(self, state_root):
        scope_gate._CACHE.clear()
        res = scope_gate.disable_tools(["payloads.hash_crack."])
        assert not res["ok"]
        assert "armed" in res["error"].lower()

    def test_enable_refused_when_disarmed(self, state_root):
        scope_gate._CACHE.clear()
        res = scope_gate.enable_tools(["payloads.hash_crack."])
        assert not res["ok"]


class TestEnable:
    def test_enable_removes_prefix(self, armed_scope):
        scope_gate.disable_tools(["payloads.hash_crack.", "payloads.hydra."])
        res = scope_gate.enable_tools(["payloads.hash_crack."])
        assert res["ok"]
        assert "payloads.hash_crack." not in res["disabled_tools"]
        assert "payloads.hydra." in res["disabled_tools"]
        dis, _ = scope_gate.is_disabled("payloads.hash_crack.run_john")
        assert not dis
        dis, _ = scope_gate.is_disabled("payloads.hydra.run_hydra")
        assert dis


class TestStatusSurface:
    def test_status_shows_disabled_list(self, armed_scope):
        scope_gate.disable_tools(["payloads.hash_crack."])
        st = scope_gate.status()
        assert st["armed"]
        assert "payloads.hash_crack." in st["disabled_tools"]
        assert st["disabled_tools_count"] == 1

    def test_status_empty_when_none_disabled(self, armed_scope):
        st = scope_gate.status()
        assert st["armed"]
        assert st["disabled_tools"] == []
        assert st["disabled_tools_count"] == 0


class TestRejectEnvelope:
    def test_envelope_shape(self):
        env = scope_gate.disabled_reject_envelope(
            "payloads.hash_crack.run_john", "payloads.hash_crack."
        )
        assert env["status"] == "Failed"
        assert env["disabled"] is True
        assert env["matched_prefix"] == "payloads.hash_crack."
        assert "remediation" in env
        assert "operator" in env["remediation"].lower()


class TestListDisabled:
    def test_list_when_armed(self, armed_scope):
        scope_gate.disable_tools(["payloads.hash_crack."])
        res = scope_gate.list_disabled()
        assert res["ok"]
        assert res["armed"]
        assert "payloads.hash_crack." in res["disabled_tools"]

    def test_list_when_disarmed(self, state_root):
        scope_gate._CACHE.clear()
        res = scope_gate.list_disabled()
        assert res["ok"]
        assert not res["armed"]
        assert res["disabled_tools"] == []