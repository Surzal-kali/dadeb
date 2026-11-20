from pathlib import Path

from daharness.findings import FindingStore


def test_write_markdown_defaults_under_workspace_root(state_root):
    store = FindingStore(str(state_root / "ids.db"))
    try:
        out_path = store.write_markdown()
    finally:
        store.close()

    assert out_path.parent == state_root / "findings_md"
    assert out_path.is_file()


def test_write_markdown_honors_environment_override(state_root, monkeypatch, tmp_path):
    output_dir = tmp_path / "findings"
    monkeypatch.setenv("FINDINGS_MD_DIR", str(output_dir))
    store = FindingStore(str(state_root / "ids.db"))
    try:
        out_path = store.write_markdown()
    finally:
        store.close()

    assert out_path.parent == output_dir
    assert out_path.is_file()


def test_explicit_output_dir_overrides_environment(state_root, monkeypatch, tmp_path):
    monkeypatch.setenv("FINDINGS_MD_DIR", str(tmp_path / "from-env"))
    explicit_dir = tmp_path / "explicit"
    store = FindingStore(str(state_root / "ids.db"))
    try:
        out_path = store.write_markdown(output_dir=explicit_dir)
    finally:
        store.close()

    assert out_path.parent == explicit_dir
    assert out_path.is_file()
