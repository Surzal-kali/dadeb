"""Tests for the operator-shell profile plumbing (packaging/profile/daharness.sh).

The systemd units read /etc/daharness/daharness.env via EnvironmentFile;
operator shells do not. The profile script re-exports the system-profile
knobs from the conffile UNTIL the shell already carries them —
WORKSPACE_ROOT and BRAIN_SOCKET historically, DACUSTOMS_DIR as of
2026-11-21. Without the DACUSTOMS_DIR carry, the units saw customs via
EnvironmentFile while the operator shell resolved the ~/.dacustoms fallback:
discovery minted 0 dacustoms.* manifests from the REPL for modules that
were indexed and Brain-dispatchable (live split-brain, 2026-11-21).

These tests source the script in a clean `sh` and pin the contract:

  * a fresh shell picks up all three knobs from the conffile fixture
  * an operator export WINS (user-profile lane semantics)
  * a disable sentinel is preserved — constants.py's dacustoms_dir()
    treats none/disabled/off as lane-off, and the script must not
    overwrite that choice with the conffile path
  * the script stays portable to /bin/sh (the wrappers source it)
"""

import os
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PROFILE = REPO_ROOT / "packaging" / "profile" / "daharness.sh"


@pytest.fixture
def conffile(tmp_path: Path) -> Path:
    """A minimal daharness.env carrying the three profile knobs."""
    conf = tmp_path / "daharness.env"
    conf.write_text(
        "# conffile fixture\n"
        "WORKSPACE_ROOT=/tmp/state\n"
        "BRAIN_SOCKET=/run/daharness/brain.sock\n"
        "DACUSTOMS_DIR=/tmp/customs\n"
    )
    return conf


def _source(conf: Path, env: dict | None = None) -> dict:
    """Source the profile script body in a clean /bin/sh and return the env.

    The script reads _dh_conf=/etc/daharness/daharness.env — for tests the
    conffile path is substituted, the body is piped on stdin, and `sh`
    sources it with `. /dev/stdin` in a subshell.
    """
    script_body = PROFILE.read_text().replace(
        "_dh_conf=/etc/daharness/daharness.env",
        f'_dh_conf="{conf}"',
    )
    cmd = (
        '. /dev/stdin <<\'DH_PROFILE_EOF\'\n'
        f"{script_body}\n"
        'DH_PROFILE_EOF\n'
        'env | grep -E "^(WORKSPACE_ROOT|BRAIN_SOCKET|DACUSTOMS_DIR)=" | sort'
    )
    # Inject the scenario env on top of a host-scrubbed baseline — this
    # test run inherits the operator's live environment otherwise.
    proc = subprocess.run(
        ["sh", "-c", cmd],
        env={
            **{k: v for k, v in os.environ.items()
               if k not in ("WORKSPACE_ROOT", "BRAIN_SOCKET", "DACUSTOMS_DIR")},
            **(env or {}),
        },
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    out: dict = {}
    for line in proc.stdout.splitlines():
        key, _, val = line.partition("=")
        out[key] = val
    return out


def test_fresh_shell_picks_up_all_three_knobs(conffile):
    out = _source(conffile)
    assert out == {
        "WORKSPACE_ROOT": "/tmp/state",
        "BRAIN_SOCKET": "/run/daharness/brain.sock",
        "DACUSTOMS_DIR": "/tmp/customs",
    }


def test_operator_export_wins(conffile):
    out = _source(conffile, env={"DACUSTOMS_DIR": "/my/own/customs"})
    assert out["DACUSTOMS_DIR"] == "/my/own/customs"
    # The untouched knobs still resolve from the conffile.
    assert out["WORKSPACE_ROOT"] == "/tmp/state"


def test_disable_sentinel_is_preserved(conffile):
    # An operator who exported 'none' chose to disable the customs lane;
    # the conffile path must not overwrite it.
    out = _source(conffile, env={"DACUSTOMS_DIR": "none"})
    assert out["DACUSTOMS_DIR"] == "none"


def test_empty_then_missing_conffile_leaves_silence(conffile):
    # An unresolvable conffile is tolerated: the script exports only what
    # it could read. Empty DACUSTOMS_DIR in the env stays empty rather
    # than getting silently re-pointed (constants.py re-resolves the
    # ~/.dacustoms default per call).
    empty_conf = conffile.parent / "empty.env"
    empty_conf.write_text("WORKSPACE_ROOT=/tmp/state\n")
    out = _source(empty_conf, env={"DACUSTOMS_DIR": ""})
    assert out["WORKSPACE_ROOT"] == "/tmp/state"
    assert out["DACUSTOMS_DIR"] == ""
