"""Verb allowlist, caps, preflight, and error envelopes for ``jadx.py``.

Carved guts of ``auxiliaries/jadx.py`` (2026-10-30): the frozen verb
table + tuning caps, the jadx/java preflight trio (``resolve_jadx_bin``,
``_jadx_version``, ``_preflight_or_none`` guard), and the shared
``_err_verb`` envelope builder every verb returns errors through.
Docstring-only sibling — no argparse, no ``@framework_tool`` members —
so static discovery never mints it; the facade imports these names back
and remains the tool surface.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from typing import Any

# ---------------------------------------------------------------------------
# Frozen verb table — schema-verified against jadx 1.5.6 (2026-07-10 release;
# JadxCLIArgs flags: -d, -r/--no-res, -s/--no-src, -j/--threads-count,
# --single-class(+ --single-class-output), --decompilation-mode, --deobf,
# --show-bad-code).  6 slots filled; slots 7-8 held open for practice gaps.
# verb -> blurb
# ---------------------------------------------------------------------------
_VERB_TABLE: dict[str, str] = {
    "decompile": "full decompile into the per-target workspace (cached; params: deobf/show_bad_code/mode/threads/no_res/force)",
    "manifest":  "decode AndroidManifest.xml only (fast resources-only pass; returns the XML)",
    "class":     "pull ONE class's decompiled source via --single-class (params: single_class='com.example.Foo')",
    "grep":      "regex search over the decompiled workspace (params: pattern, glob, case_insensitive, max_matches — raise the 200-match cap, ceiling 2000, offset to page, max_files — raise the 4000-file scan cap, ceiling 50000)",
    "read":      "read one decompiled file, bounded (param: path, relative to the workspace)",
    "tree":      "list the workspace: tree_mode='files' flat paths (offset/limit paging) or tree_mode='dirs' per-directory rollup with file counts (param: glob)",
    # slots 7-8: reserved for practice-found gaps (candidate: --call-graph dot/json export)
}

ALLOWED_VERBS: tuple = tuple(_VERB_TABLE.keys())

_DECOMPILE_MODES: tuple = ("auto", "restructure", "simple", "fallback")

# ---------------------------------------------------------------------------
# Caps / tuning (env-overridable, mirroring R2_OUTPUT_CAP / R2_TIMEOUT)
# ---------------------------------------------------------------------------
_OUTPUT_CAP: int = int(os.getenv("JADX_OUTPUT_CAP", str(200 * 1024)))
_TRUNCATION_NOTE: str = (
    f"output capped at {_OUTPUT_CAP} bytes (JADX_OUTPUT_CAP env) — "
    "this is a prefix, not the full result; narrow the query"
)
_JADX_TIMEOUT: float = float(os.getenv("JADX_TIMEOUT", "900"))
_PATTERN_CAP: int = 256
_GREP_MAX_MATCHES: int = int(os.getenv("JADX_GREP_MAX_MATCHES", "200"))
_GREP_MAX_FILES: int = int(os.getenv("JADX_GREP_MAX_FILES", "4000"))
_GREP_MAX_FILE_BYTES: int = 2 * 1024 * 1024
# Hard ceiling on a caller-raised ``max_matches`` — env-overridable so an
# operator can lift it for a big obfuscated tree, but never unbounded: the
# result goes into LLM context, and an unbounded match list is a context bomb.
_GREP_MATCHES_CEILING: int = int(os.getenv("JADX_GREP_MATCHES_CEILING", "2000"))
# Same shape for the file-scan cap: on a 24k-file decompiled tree the 4000
# default binds before the match cap does, silently truncating the sweep.
_GREP_FILES_CEILING: int = int(os.getenv("JADX_GREP_FILES_CEILING", "50000"))
_TREE_LIST_CAP: int = int(os.getenv("JADX_TREE_LIST_CAP", "500"))
_THREADS_MIN, _THREADS_MAX = 1, 16
_CLASS_RE: re.Pattern = re.compile(r"^[A-Za-z0-9_.$-]{1,256}$")
_GLOB_RE: re.Pattern = re.compile(r"^[A-Za-z0-9_*?.\-/]{1,256}$")

# Text-ish extensions scanned by the grep verb (resources include xml/html/js).
_GREP_TEXT_EXTS: frozenset = frozenset({
    ".java", ".kt", ".xml", ".json", ".txt", ".smali", ".gradle", ".pro",
    ".yml", ".yaml", ".properties", ".csv", ".html", ".js", ".md", ".cfg",
    ".aidl", ".jsp", ".ini", ".conf",
})


# ---------------------------------------------------------------------------
# Preflight — jadx binary + java runtime (cached version probe)
# ---------------------------------------------------------------------------
_COMMON_JADX_PATHS: tuple = (
    "/usr/local/bin/jadx", "/usr/bin/jadx", "/opt/jadx/bin/jadx",
    os.path.expanduser("~/jadx/bin/jadx"),
)

_jadx_version_cache: str | None = None  # "" = probed-and-unavailable


def resolve_jadx_bin() -> str | None:
    """Locate jadx: $JADX_BIN -> PATH -> common install paths."""
    env_bin = os.getenv("JADX_BIN", "").strip()
    if env_bin and os.path.isfile(env_bin) and os.access(env_bin, os.X_OK):
        return env_bin
    found = shutil.which("jadx")
    if found:
        return found
    for cand in _COMMON_JADX_PATHS:
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def _jadx_version() -> str | None:
    """Probe ``jadx --version`` once per process; None when unavailable."""
    global _jadx_version_cache
    if _jadx_version_cache is not None:
        return _jadx_version_cache
    jadx_bin = resolve_jadx_bin()
    if jadx_bin is None:
        _jadx_version_cache = ""
        return None
    try:
        proc = subprocess.run(
            [jadx_bin, "--version"],
            capture_output=True, text=True, timeout=15,
        )
        ver = (proc.stdout or "").strip().splitlines()[0] if proc.stdout else ""
        _jadx_version_cache = ver or ""
    except Exception:
        _jadx_version_cache = ""
    return _jadx_version_cache or None


def _preflight_or_none(target: str, verb: str) -> dict[str, Any] | None:
    """Return an error envelope when jadx/java are unavailable, else None.

    Preflight lives ONLY in the verbs that spawn jadx (decompile / manifest /
    class).  grep/read/tree are pure-Python workspace readers and work without
    jadx installed — cached decompiled trees stay usable while the binary is
    being installed.  Clean envelopes; no reindex needed after install —
    preflight runs at call time (like the john/hashcat wrappers).
    """
    if resolve_jadx_bin() is None:
        return _err_verb(
            target, verb,
            "jadx not found — install the 1.5.x release bundle "
            "(github.com/skylot/jadx) and put bin/jadx on PATH, or set the "
            "JADX_BIN env var; requires a Java 11+ JRE. No reindex needed "
            "after install — preflight runs at call time.",
        )
    if not _java_available():
        return _err_verb(
            target, verb,
            "jadx found but no Java runtime on PATH — jadx requires a "
            "Java 11+ JRE (e.g. apt install default-jre).",
        )
    return None


def _java_available() -> bool:
    """Java 11+ runtime present on PATH?  (Seam for offline tests.)"""
    return shutil.which("java") is not None


def _err_verb(
    target: str | None,
    command: str | None,
    error: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Consistent error envelope.

    ``extra`` merges verb-specific keys (e.g. ``stderr_tail``/``stdout_tail``
    on jadx-spawn failures) into the base shape without changing it.
    """
    envelope: dict[str, Any] = {
        "status": "error",
        "verb": command,
        "summary": error,
        "output": "",
        "workspace": None,
        "truncated": False,
        "truncation_policy": None,
        "target": target,
        "jadx_version": _jadx_version(),
        "next_hints": [],
        "delta": "",
        "error": error,
    }
    if extra:
        envelope.update(extra)
    return envelope
