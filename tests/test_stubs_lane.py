"""daharness-index --stubs wiring (2026-10-20).

`daharness-index --stubs` routes to scripts/gen_repl_stubs.py with the full
argument list, so the generator must accept the caller's flag (--stubs) and
the passthrough (--check). The wrapper cannot pre-filter flags it does not
know.
"""

import importlib.util
from pathlib import Path

_STUBS = Path(__file__).resolve().parent.parent / "scripts" / "gen_repl_stubs.py"


def _stubs_mod():
    spec = importlib.util.spec_from_file_location("gen_repl_stubs", _STUBS)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_index_stubs_flag_accepted():
    ap = _stubs_mod()._build_parser()
    assert ap.parse_args(["--stubs"]).stubs is True
    assert ap.parse_args(["--stubs", "--check"]).check is True
    assert ap.parse_args([]).stubs is False


def test_builtins_fork_source_deb_fallback(monkeypatch, tmp_path):
    # Deb lane: clean operator home, no wheel pyright — the packaged copy
    # must satisfy the fork (and the stubPath contract needs it COMPLETE).
    mod = _stubs_mod()
    monkeypatch.setattr(mod.Path, "home", lambda: tmp_path)
    import sys as _sys

    monkeypatch.setattr(
        _sys, "prefix", str(tmp_path / "no-env")
    )
    src = mod._builtins_fork_source()
    assert src.name == "pyright_typeshed_builtins.pyi"
    assert "async def" not in src.read_text()[:200]  # sanity: a python stub


def test_check_mode_skips_missing_repo_toml(capsys):
    # ruff.toml is a checkout-only lane: on a package install the ruff block
    # cannot exist, --check must report SKIP (not STALE) and exit 0 even
    # with the stub files themselves fresh.
    import tool_repl

    mod = _stubs_mod()

    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "framework-stubs"
        out.mkdir()
        mod.PY_FILE = out / "framework_tools.py"
        mod.PYI_FILE = out / "framework_tools.pyi"
        mod.BUILTINS_FILE = out / "builtins.pyi"
        mod.REPO_TOML = Path(tmp) / "ruff.toml"  # deliberately absent

        # Fresh-on-disk fixture: generate the three files from the same
        # pipeline main() will recompute, so the only failing check is the
        # one under test (absent ruff.toml → SKIP, rc stays 0).
        manifests = tool_repl.discover_tools()
        alias_map = tool_repl.build_tool_aliases(manifests)
        aliases = sorted(alias_map)
        names = mod.build_builtins(manifests)
        mod.PYI_FILE.write_text(mod.generate_pyi(alias_map))
        mod.PY_FILE.write_text(mod.build_shim(aliases))
        mod.BUILTINS_FILE.write_text(mod.build_builtins_fork(names))

        rc = mod.main(["--check"])
    text = capsys.readouterr().out
    assert "SKIP" in text
    assert "  OK  " in text
    assert rc == 0