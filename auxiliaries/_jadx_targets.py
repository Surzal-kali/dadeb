"""APK drop-folder discovery + per-target workspace lane for ``jadx.py``.

Carved guts of ``auxiliaries/jadx.py`` (2026-10-30): the apk drop-folder
constants (``APK_TARGETS_ROOT``, magic-byte signatures, skip/extension
labels), the format-sniff/target-resolution/discovery trio the
``list_apk_targets`` tool and ``payloads/jadx_fleet.py`` ride, and the
per-target decompiled workspace lane (fingerprint/meta/state/
traversal-guard).  Self-rooted: it derives ``APK_TARGETS_ROOT`` from the
same env chain the facade used.  Docstring-only sibling — no argparse,
no ``@framework_tool`` members — so static discovery never mints it.
"""

from __future__ import annotations

import json
import os
from typing import Any

from constants import resolve_workspace_root

# ---------------------------------------------------------------------------
# Drop folder — discovery & resolution (mirrors binaries/ + R2_BINARY_TARGETS_ROOT)
# Workspace root wins (deb lane: /var/lib/daharness — the decompiled/ cache is
# operator content, so it lives on the state root, not the read-only package
# tree); the checkout on dev trees. Env override always wins. The deb's
# postinst creates the directory.
# ---------------------------------------------------------------------------
APK_TARGETS_ROOT: str = os.getenv(
    "JADX_APK_TARGETS_ROOT",
    os.path.join(str(resolve_workspace_root()), "apk"),
)
_DECOMPILED_SUBDIR: str = "decompiled"  # workspaces live here; never listed
_MANIFEST_REL: str = os.path.join("resources", "AndroidManifest.xml")
_META_NAME: str = ".jadx_meta.json"

# Magic-byte signatures for the inputs jadx accepts.  (apk/xapk/apkm/aab/
# aar/jar/zip/apks are all ZIP-family; the extension refines the label.)
_APK_MAGIC: list[tuple] = [
    ("ZIP-family", 0, b"PK\x03\x04"),            # apk/jar/zip/xapk/apkm/aab/aar
    ("DEX",       0, b"dex\n"),                  # raw classes.dex
    ("Java-class", 0, b"\xca\xfe\xba\xbe"),      # raw .class
    ("ARSC",      0, b"\x02\x00\x0c\x00"),       # resources.arsc table chunk
]

_SKIP_DIRS: frozenset = frozenset({
    ".git", ".github", "__pycache__", "node_modules", ".venv", "venv",
    _DECOMPILED_SUBDIR,
})

_ZIP_EXT_LABELS: dict[str, str] = {
    ".apk": "APK", ".xapk": "XAPK", ".apkm": "APKM", ".apks": "APKS",
    ".aab": "AAB", ".aar": "AAR", ".jar": "JAR", ".zip": "ZIP",
}


def detect_apk_format(path: str) -> str | None:
    """Sniff the first bytes of ``path`` for a format jadx accepts.

    Returns a human label (``"APK"``, ``"DEX"``, ``"ZIP-family"`` …) or
    ``None``.  Pure header read — never spawns a process (no ``file`` call).
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(512)
    except OSError:
        return None
    if not head:
        return None
    for label, offset, magic in _APK_MAGIC:
        if head[offset:offset + len(magic)] == magic:
            if label == "ZIP-family":
                ext = os.path.splitext(path)[1].lower()
                if ext in _ZIP_EXT_LABELS:
                    return _ZIP_EXT_LABELS[ext]
                return "ZIP-family"
            return label
    return None


def resolve_apk_target(target: str) -> str | None:
    """Resolve ``target`` to an absolute path, searching the drop folder.

    Existing paths are honoured as-is; otherwise the drop folder
    (:data:`APK_TARGETS_ROOT`) is searched — exact relative-path match first,
    then bare-name recursive match.  Never raises.
    """
    if not target:
        return None
    p = os.path.abspath(target)
    if os.path.isfile(p):
        return p
    root = APK_TARGETS_ROOT
    if not os.path.isdir(root):
        return None
    candidate = os.path.join(root, target)
    if os.path.isfile(candidate):
        return os.path.abspath(candidate)
    base = os.path.basename(target)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        if base in filenames:
            return os.path.abspath(os.path.join(dirpath, base))
    return None


def discover_apk_targets(root: str | None = None) -> list[dict[str, Any]]:
    """Walk the apk drop folder and return recognised jadx-able files.

    Skips the ``decompiled/`` workspace subtree and dot-directories.  Each hit:
    ``{name, path, rel_path, size, format}``.
    """
    base = root or APK_TARGETS_ROOT
    if not os.path.isdir(base):
        return []
    results: list[dict[str, Any]] = []
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fname in sorted(filenames):
            if fname.startswith("."):
                continue
            fpath = os.path.join(dirpath, fname)
            if not os.path.isfile(fpath):
                continue
            fmt = detect_apk_format(fpath)
            if fmt is None:
                continue
            try:
                size = os.path.getsize(fpath)
            except OSError:
                continue
            results.append({
                "name": fname,
                "path": os.path.abspath(fpath),
                "rel_path": os.path.relpath(fpath, base),
                "size": size,
                "format": fmt,
            })
    results.sort(key=lambda r: r["rel_path"])
    return results


# ---------------------------------------------------------------------------
# Workspace cache (per-target decompiled tree) — the jadx analog of r2's
# temp copy.  jadx MUST write a file tree, so the workspace persists and is
# reused; a fingerprint (mtime_ns + size) decides stale vs. fresh.
# ---------------------------------------------------------------------------
def _workspace_for(source_path: str) -> str:
    base = os.path.basename(source_path)
    return os.path.join(APK_TARGETS_ROOT, _DECOMPILED_SUBDIR, base)


def _stat_fingerprint(source_path: str) -> dict[str, Any]:
    st = os.stat(source_path)
    return {"source_mtime_ns": st.st_mtime_ns, "source_size": st.st_size}


def _read_meta(ws: str) -> dict[str, Any] | None:
    try:
        with open(os.path.join(ws, _META_NAME), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _write_meta(ws: str, source_path: str, jadx_ver: str | None) -> None:
    meta = dict(_stat_fingerprint(source_path))
    meta["jadx_version"] = jadx_ver
    meta["source"] = os.path.basename(source_path)
    try:
        with open(os.path.join(ws, _META_NAME), "w") as fh:
            json.dump(meta, fh, indent=1)
    except OSError:
        pass  # cache bookkeeping must never fail the run


def _workspace_state(ws: str, source_path: str) -> dict[str, Any]:
    """Inspect the workspace: exists / has sources / has manifest / stale."""
    exists = os.path.isdir(ws)
    state: dict[str, Any] = {
        "exists": exists,
        "has_sources": False,
        "has_manifest": False,
        "stale": False,
    }
    if not exists:
        return state
    state["has_sources"] = os.path.isdir(os.path.join(ws, "sources"))
    state["has_manifest"] = os.path.isfile(os.path.join(ws, _MANIFEST_REL))
    try:
        meta = _read_meta(ws)
        fp = _stat_fingerprint(source_path)
        state["stale"] = bool(
            not meta
            or meta.get("source_mtime_ns") != fp["source_mtime_ns"]
            or meta.get("source_size") != fp["source_size"]
        )
    except OSError:
        state["stale"] = True
    return state


def _safe_ws_child(ws: str, rel_path: str) -> str | None:
    """Resolve ``rel_path`` inside ``ws``, refusing traversal.  None = refuse."""
    if not rel_path:
        return None
    if rel_path.startswith(("/", "~")):
        return None
    parts = rel_path.replace("\\", "/").split("/")
    if any(p == ".." for p in parts):
        return None
    candidate = os.path.join(ws, rel_path)
    real_ws = os.path.realpath(ws)
    real_cand = os.path.realpath(candidate)
    try:
        if os.path.commonpath([real_ws, real_cand]) != real_ws:
            return None
    except ValueError:
        return None
    return candidate
