"""Dispersion pins: the shipped default budget-ration constitution must
reach deployed surfaces through the postinst seeding + pristine-gate flip.
Yaml CONTENT pins live in test_ration_a.TestDefaultConstitutionYamlFidelity
(field-for-field vs code defaults); this module pins the WIRE itself."""

import pathlib
import re
import subprocess

REPO = pathlib.Path(__file__).resolve().parent.parent

# The exact placeholder line the postinst pristine-gate flips. If ANY of
# these three surfaces drifts from this string, the flip silently stops
# working (the operator gets defaults law with no visible error) — so the
# equality is pinned BYTE-FOR-BYTE, not by regex.
GATE_LINE = "BUDGET_CONSTITUTION_FILE=/etc/daharness/budget.yaml"
GATE_COMMENTED = "#" + GATE_LINE


def test_rules_disperse_reference_yaml():
    rules = (REPO / "debian/rules").read_text()
    assert "packaging/reference/budget.constitution.yaml" in rules
    assert "usr/share/daharness/packaging/reference/budget.constitution.yaml" in rules


def test_env_template_carries_pristine_placeholder():
    env = (REPO / "packaging/etc/daharness.env").read_text()
    commented = [l for l in env.splitlines() if l.strip() == GATE_COMMENTED]
    assert len(commented) == 1, (
        "placeholder line must appear exactly once, commented, byte-exact — "
        "the postinst pristine-gate and this template are wedded")


def test_postinst_seeds_and_flips_pristine_only():
    post = (REPO / "debian/daharness.postinst").read_text()
    assert "packaging/reference/budget.constitution.yaml" in post, (
        "postinst must seed from the package-owned canonical copy")
    assert "/etc/daharness/budget.yaml" in post
    assert f"'^{GATE_COMMENTED}$'" in post, (
        "pristine-gate grep pattern must match the template line byte-exact")
    assert f"s|^{GATE_COMMENTED}$|{GATE_LINE}|" in post, (
        "sed flip must target exactly the shipped placeholder form")


def test_yaml_canonical_exists_and_uses_gate_path():
    ref = REPO / "packaging/reference/budget.constitution.yaml"
    assert ref.exists()
    assert "budget.yaml" in ref.read_text(), (
        "yaml's own wiring doc must name the seeded /etc path")


def test_postinst_shell_syntax():
    p = subprocess.run(["sh", "-n", str(REPO / "debian/daharness.postinst")],
                       capture_output=True, text=True)
    assert p.returncode == 0, f"postinst shell syntax broke: {p.stderr}"
