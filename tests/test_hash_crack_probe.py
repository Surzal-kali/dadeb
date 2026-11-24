"""_probe_hashcat_backends parser regression tests (hermetic, no binary).

v7 hashcat prints `-I --machine-readable` as ONE line of JSON; v6 printed
a line-oriented table. The probe must parse both, anchor the version to
the ``hashcat (vX.Y.Z)`` banner (never an OpenCL/driver version string),
and never double-count devices found by both scans. All subprocess calls
are mocked — box state must not decide test outcomes.
"""

import payloads.hash_crack as hc

_V7_JSON = (
    '{"OpenCLInfo": {"Platforms": ['
    '{"PlatformID": "1", "Name": "Portable Computing Language", '
    '"BackendDevices": [{"DeviceID": "01", "Type": "CPU", '
    '"Name": "cpu--0xd0b"}]}, '
    '{"PlatformID": "2", "Name": "rusticl", "Version": "OpenCL 3.0", '
    '"BackendDevices": []}]}}'
)
_V7_BANNER = "hashcat (v7.1.2) starting in backend information mode\n"

_V6_TABLE = (
    "hashcat (v6.2.6) starting in backend information mode\n"
    "OpenCL.Info #1\n"
    "Device.Name #1: Intel(R) Core(TM) i7-9750H CPU\n"
)


def _fake_proc(stdout="", stderr=""):
    return type("P", (), {"stdout": stdout, "stderr": stderr, "returncode": 0})()


def _patch_run(monkeypatch, side_effects):
    calls = {"n": 0}

    def fake_run(*args, **kwargs):
        effect = side_effects[calls["n"]]
        calls["n"] += 1
        return effect

    monkeypatch.setattr(hc.subprocess, "run", fake_run)


def _no_binary(monkeypatch):
    monkeypatch.setattr(hc, "_preflight", lambda *a, **k: "/fake/hashcat")


def test_v7_machine_readable_json_yields_device(monkeypatch):
    _no_binary(monkeypatch)
    _patch_run(monkeypatch, [_fake_proc(_V7_BANNER + _V7_JSON)])
    r = hc._probe_hashcat_backends()
    assert r["available"] is True
    assert r["devices"] == ["cpu--0xd0b"]
    assert r["backend_kinds"] == ["OpenCL"]
    assert r["version"] == "7.1.2"


def test_v6_line_table_still_parses(monkeypatch):
    _no_binary(monkeypatch)
    _patch_run(monkeypatch, [_fake_proc(_V6_TABLE)])
    r = hc._probe_hashcat_backends()
    assert r["available"] is True
    assert r["devices"] == ["Intel(R) Core(TM) i7-9750H CPU"]
    assert r["version"] == "6.2.6"


def test_version_never_grabs_opencl_string(monkeypatch):
    """The 2026-11-24 symptom: probe returned "3.0" (an OpenCL version)."""
    _no_binary(monkeypatch)
    text = (
        _V7_BANNER
        + _V7_JSON  # contains "OpenCL 3.0" AND driver "7.1+debian"
    )
    _patch_run(monkeypatch, [_fake_proc(text)])
    r = hc._probe_hashcat_backends()
    assert r["version"] == "7.1.2"


def test_version_falls_back_to_V_when_banner_absent(monkeypatch):
    _no_binary(monkeypatch)
    machine = (
        "hashcat -I --machine-readable\n" + _V7_JSON  # no banner version
    )
    _patch_run(
        monkeypatch,
        [_fake_proc(machine), _fake_proc(stderr="v7.1.2\n")],
    )
    r = hc._probe_hashcat_backends()
    assert r["version"] == "7.1.2"


def test_rusticl_only_platform_reports_unavailable(monkeypatch):
    _no_binary(monkeypatch)
    json_only = '{"OpenCLInfo": {"Platforms": [{"PlatformID": "2", ' \
                '"Name": "rusticl", "BackendDevices": []}]}}'
    _patch_run(
        monkeypatch,
        [_fake_proc(_V7_BANNER + json_only), _fake_proc(stdout="v7.1.2\n")],
    )
    r = hc._probe_hashcat_backends()
    assert r["available"] is False
    assert "pocl-opencl-icd" in r["error"]


def test_rusticl_platform_with_enumerated_device_counts(monkeypatch):
    """A rusticl platform that DOES expose a device must not be filtered."""
    _no_binary(monkeypatch)
    json_dev = (
        '{"OpenCLInfo": {"Platforms": [{"PlatformID": "2", '
        '"Name": "rusticl", "BackendDevices": [{"DeviceID": "01", '
        '"Type": "GPU", "Name": "llvmpipe"}]}]}}'
    )
    _patch_run(monkeypatch, [_fake_proc(_V7_BANNER + json_dev)])
    r = hc._probe_hashcat_backends()
    assert r["available"] is True
    assert r["devices"] == ["llvmpipe"]


def test_cuda_json_kind_detected(monkeypatch):
    _no_binary(monkeypatch)
    cuda = (
        '{"CUDAInfo": {"Platforms": [{"PlatformID": "1", "Name": "NVIDIA", '
        '"BackendDevices": [{"DeviceID": "01", "Type": "GPU", '
        '"Name": "RTX 3050"}]}]}}'
    )
    _patch_run(
        monkeypatch,
        [
            _fake_proc(_V7_BANNER + cuda),
            _fake_proc(stdout=""),
        ],
    )
    r = hc._probe_hashcat_backends()
    assert r["available"] is True
    assert r["backend_kinds"] == ["CUDA"]


def test_garbage_braces_do_not_crash(monkeypatch):
    _no_binary(monkeypatch)
    _patch_run(
        monkeypatch,
        [_fake_proc("{not json}"), _fake_proc(stdout="v7.1.2\n")],
    )
    r = hc._probe_hashcat_backends()
    assert r["available"] is False
    assert r["devices"] == []


def test_json_and_line_scan_devices_are_deduped(monkeypatch):
    _no_binary(monkeypatch)
    text = _V7_BANNER + "Device.Name #1: cpu--0xd0b\n" + _V7_JSON
    _patch_run(monkeypatch, [_fake_proc(text)])
    r = hc._probe_hashcat_backends()
    assert r["devices"] == ["cpu--0xd0b"]
