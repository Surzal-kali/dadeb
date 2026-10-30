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

# --- broad-range checks: operator-allowlist tier (2026-10-31) -----------------------


class TestBroadRanges:
    def test_blessed_cidr_admits_broad_targets(self, armed_scope):
        assert scope_gate.add_ip("10.0.0.0/24", "lab net")["ok"]
        for spec in ("10.0.0.0/24", "10.0.0.9/24", "10.0.0.0/25"):
            ok, reason = scope_gate.check_scan(spec)
            assert ok, f"{spec} should pass: {reason}"
        # The attribution lives on the per-spec verdict (check_scan's
        # aggregate summary stays flat).
        ok, reason = scope_gate._check_broad(
            "10.0.0.9/24", scope_gate._load_state()
        )
        assert ok and "operator allowlist CIDR 10.0.0.0/24" in reason

    def test_blessed_cidr_admits_hyphen_ranges(self, armed_scope):
        assert scope_gate.add_ip("10.0.0.0/24", "lab net")["ok"]
        for spec in ("10.0.0.3-10.0.0.44", "10.0.0.5-30"):
            ok, reason = scope_gate.check_scan(spec)
            assert ok, f"{spec} should pass: {reason}"

    def test_outside_blessed_cidr_stays_refused(self, armed_scope):
        assert scope_gate.add_ip("10.0.0.0/24", "lab net")["ok"]
        for spec in ("10.0.1.0/24", "10.0.1.5-30", "10.0.0.3-10.0.1.44"):
            ok, reason = scope_gate.check_scan(spec)
            assert not ok, f"{spec} should be refused"
            assert "scope add-ip" in reason  # the remediation hint

    def test_manifest_cidr_still_admits_without_blessing(self, armed_scope):
        # armed_scope's lab manifest blesses 10.0.0.0/24 as an in-scope
        # asset — no operator add-ip needed for that path.
        ok, reason = scope_gate.check_scan("10.0.0.0/24")
        assert ok, reason
        ok, reason = scope_gate.check_scan("10.0.2.0/24")
        assert not ok and "scope add-ip" in reason

    def test_allowlist_beats_out_of_scope_manifest(self, state_root):
        scope_dir = state_root / "scope"
        scope_dir.mkdir(parents=True, exist_ok=True)
        manifest = {
            "handle": "local-oos",
            "platform": "lab",
            "in_scope": [{"asset_type": "CIDR", "asset_identifier": "10.0.0.0/24"}],
            # Deliberately contradictory: the operator blessed the same
            # range, and the allowlist tier outranks the manifest.
            "out_of_scope_assets": ["10.0.0.0/24"],
        }
        (scope_dir / "lab_local-oos.json").write_text(json.dumps(manifest))
        try:
            scope_gate._CACHE.clear()
            assert scope_gate.arm("local-oos", platform="lab")["ok"]
            assert scope_gate.add_ip("10.0.0.0/24", "operator range")["ok"]
            ok, reason = scope_gate.check_scan("10.0.0.0/24")
            assert ok, f"allowlist should outrank OOS: {reason}"
        finally:
            scope_gate.disarm()
            scope_gate._CACHE.clear()
