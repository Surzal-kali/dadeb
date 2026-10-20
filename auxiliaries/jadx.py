"""Jadx static-analysis composite tool (``run_jadx``) + drop-folder discovery.

Mirrors :mod:`auxiliaries.radare2`: ONE composite ``@framework_tool`` driving an
external binary as a one-shot subprocess (argv list, ``shell=False``), plus one
discovery tool for a dedicated, gitignored drop folder.  Where r2 is an
in-memory disassembler that needs only a temp copy, jadx is a BATCH decompiler
— it must emit a tree of files.  That tree is cached per target under
``apk/decompiled/<basename>/`` and reused across calls, so the expensive run
happens once and every later ``grep``/``read``/``tree`` call is instant.

Scope-gate: NONE by design.  This is OFFLINE static analysis of an artifact the
operator dropped into ``apk/`` — jadx opens no sockets, makes no DNS requests,
contacts no target (same class as radare2/crypto_kit).  Documented here so a
future "hardening" pass does not silently gate an offline lane.

Threat model & validation (defense in depth)
--------------------------------------------
The model supplies free text; the tool composes the argv itself.  jadx takes no
command language (unlike ``r2 -c``), so the classic ``;``-chain risk does not
exist; the injection-adjacent surface is argument composition and output paths.

1. **Exact verb allowlist** — ``command`` must match one of 6 frozen verbs
   (8 slots reserved).  No substring, no prefix match.
2. **Argv-list subprocess** — ``shell=False`` always; no caller text is ever
   joined into a shell string.  The output dir (``-d``/``--single-class-output``)
   is ALWAYS tool-composed inside the workspace root, never caller-supplied.
3. **Charset locks** — ``single_class`` must be a Java FQN shape
   (``[A-Za-z0-9_.$-]+``); ``glob`` must be a plain fnmatch token (no spaces,
   quotes, shell chars); ``pattern`` (grep) is compiled as a Python regex —
   it never touches a shell or a jadx arg.
4. **Traversal guards** — ``read`` paths are resolved and must stay inside the
   decompiled workspace (``..``/absolute rejected).  Drop-folder resolution and
   workspace wipe (``force``) both verify containment before touching disk.
5. **Integer caps & truncation** — ``threads`` clamped 1..16; grep caps
   (256-char pattern, 200 matches, 4000 files, 2 MiB/file); ``tree`` caps its
   listing; every byte-bearing output is truncated at ``JADX_OUTPUT_CAP`` with
   a stated policy so the model knows it saw a prefix.
6. **Subprocess timeout** — ``JADX_TIMEOUT`` env (default 900 s).  Full-apk
   decompiles can take minutes on big targets; the Brain's
   ``BRAIN_EXEC_CEILING`` (default 3600) is the outer bound.
7. **jadx-side hardening** — jadx 1.5.6 itself rejects absolute/escaping zip
   entry paths (zip-slip) and hardens XML parsing, so a malicious dropped APK
   writing outside its workspace is doubly refused.

Preflight
---------
``jadx`` needs a Java 11+ runtime (system JRE).  Resolution order: ``$JADX_BIN``
env -> ``PATH`` -> common install paths.  Missing binary or missing ``java``
returns a clean envelope with the exact install hint (no reindex needed —
preflight runs at call time, like the john/hashcat wrappers).  The version is
probed once per process and cached.

Diagnostics
-----------
jadx 1.5.6 routes ALL of its log output — including fatal errors such as
``ERROR - Incorrect arguments: Input class not found: <fqn>`` — to STDOUT;
stderr is normally empty.  Never run the binary with ``-q``: it maps to
``--log-level QUIET``, which suppresses even that error text (verified
2026-09-22: a not-found single-class pull then exits 1 with 0 bytes on both
streams, leaving the failure unexplainable in the envelope).  Every
jadx-spawning verb uses ``--log-level ERROR`` instead, and failure envelopes
carry bounded ``stderr_tail`` / ``stdout_tail`` fields.

Verb set
--------
- ``decompile`` — full decompile into the per-target workspace
  (``sources/`` + ``resources/``).  Cached: re-run only when the source file
  fingerprint (mtime_ns+size) changes or ``force=True``.  Params: ``deobf``,
  ``show_bad_code``, ``mode`` (auto|restructure|simple|fallback), ``threads``,
  ``no_res``, ``force``.
- ``manifest`` — decode ``AndroidManifest.xml`` only (fast resources-only
  jadx pass, ``-s``); returns the XML, capped.
- ``class`` — targeted single-class pull via ``--single-class`` (the recon
  workhorse before committing to a full decompile).  Param: ``single_class``.
- ``grep`` — bounded regex search over the decompiled workspace (needs an
  existing workspace — decompile first).  Params: ``pattern``, ``glob``,
  ``case_insensitive``.
- ``read`` — bounded single-file read from the workspace.  Param: ``path``.
- ``tree`` — bounded workspace file listing, optional ``glob`` filter.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from constants import framework_tool


# ---------------------------------------------------------------------------
# Frozen verb table — schema-verified against jadx 1.5.6 (2026-07-10 release;
# JadxCLIArgs flags: -d, -r/--no-res, -s/--no-src, -j/--threads-count,
# --single-class(+ --single-class-output), --decompilation-mode, --deobf,
# --show-bad-code).  6 slots filled; slots 7-8 held open for practice gaps.
# verb -> blurb
# ---------------------------------------------------------------------------
_VERB_TABLE: Dict[str, str] = {
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
# Drop folder — discovery & resolution (mirrors binaries/ + R2_BINARY_TARGETS_ROOT)
# ---------------------------------------------------------------------------
_REPO_ROOT: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APK_TARGETS_ROOT: str = os.getenv(
    "JADX_APK_TARGETS_ROOT", os.path.join(_REPO_ROOT, "apk")
)
_DECOMPILED_SUBDIR: str = "decompiled"  # workspaces live here; never listed
_MANIFEST_REL: str = os.path.join("resources", "AndroidManifest.xml")
_META_NAME: str = ".jadx_meta.json"

# Magic-byte signatures for the inputs jadx accepts.  (apk/xapk/apkm/aab/
# aar/jar/zip/apks are all ZIP-family; the extension refines the label.)
_APK_MAGIC: List[tuple] = [
    ("ZIP-family", 0, b"PK\x03\x04"),            # apk/jar/zip/xapk/apkm/aab/aar
    ("DEX",       0, b"dex\n"),                  # raw classes.dex
    ("Java-class", 0, b"\xca\xfe\xba\xbe"),      # raw .class
    ("ARSC",      0, b"\x02\x00\x0c\x00"),       # resources.arsc table chunk
]

_SKIP_DIRS: frozenset = frozenset({
    ".git", ".github", "__pycache__", "node_modules", ".venv", "venv",
    _DECOMPILED_SUBDIR,
})

_ZIP_EXT_LABELS: Dict[str, str] = {
    ".apk": "APK", ".xapk": "XAPK", ".apkm": "APKM", ".apks": "APKS",
    ".aab": "AAB", ".aar": "AAR", ".jar": "JAR", ".zip": "ZIP",
}


def detect_apk_format(path: str) -> Optional[str]:
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


def resolve_apk_target(target: str) -> Optional[str]:
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


def discover_apk_targets(root: Optional[str] = None) -> List[Dict[str, Any]]:
    """Walk the apk drop folder and return recognised jadx-able files.

    Skips the ``decompiled/`` workspace subtree and dot-directories.  Each hit:
    ``{name, path, rel_path, size, format}``.
    """
    base = root or APK_TARGETS_ROOT
    if not os.path.isdir(base):
        return []
    results: List[Dict[str, Any]] = []
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
# Preflight — jadx binary + java runtime (cached version probe)
# ---------------------------------------------------------------------------
_COMMON_JADX_PATHS: tuple = (
    "/usr/local/bin/jadx", "/usr/bin/jadx", "/opt/jadx/bin/jadx",
    os.path.expanduser("~/jadx/bin/jadx"),
)

_jadx_version_cache: Optional[str] = None  # "" = probed-and-unavailable


def resolve_jadx_bin() -> Optional[str]:
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


def _jadx_version() -> Optional[str]:
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


def _preflight_or_none(target: str, verb: str) -> Optional[Dict[str, Any]]:
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


# ---------------------------------------------------------------------------
# Workspace cache (per-target decompiled tree) — the jadx analog of r2's
# temp copy.  jadx MUST write a file tree, so the workspace persists and is
# reused; a fingerprint (mtime_ns + size) decides stale vs. fresh.
# ---------------------------------------------------------------------------
def _workspace_for(source_path: str) -> str:
    base = os.path.basename(source_path)
    return os.path.join(APK_TARGETS_ROOT, _DECOMPILED_SUBDIR, base)


def _stat_fingerprint(source_path: str) -> Dict[str, Any]:
    st = os.stat(source_path)
    return {"source_mtime_ns": st.st_mtime_ns, "source_size": st.st_size}


def _read_meta(ws: str) -> Optional[Dict[str, Any]]:
    try:
        with open(os.path.join(ws, _META_NAME), "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _write_meta(ws: str, source_path: str, jadx_ver: Optional[str]) -> None:
    meta = dict(_stat_fingerprint(source_path))
    meta["jadx_version"] = jadx_ver
    meta["source"] = os.path.basename(source_path)
    try:
        with open(os.path.join(ws, _META_NAME), "w") as fh:
            json.dump(meta, fh, indent=1)
    except OSError:
        pass  # cache bookkeeping must never fail the run


def _workspace_state(ws: str, source_path: str) -> Dict[str, Any]:
    """Inspect the workspace: exists / has sources / has manifest / stale."""
    exists = os.path.isdir(ws)
    state: Dict[str, Any] = {
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


def _safe_ws_child(ws: str, rel_path: str) -> Optional[str]:
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


def _clip(text: str) -> tuple:
    """Truncate to the output cap.  Returns (text, truncated)."""
    if len(text) > _OUTPUT_CAP:
        return text[:_OUTPUT_CAP], True
    return text, False


def _run_jadx_argv(argv: List[str]) -> tuple:
    """Run a composed jadx argv.  Returns (proc, error_message)."""
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=_JADX_TIMEOUT,
        )
        return proc, None
    except subprocess.TimeoutExpired:
        return None, (
            f"jadx timed out after {_JADX_TIMEOUT}s (JADX_TIMEOUT env) — "
            "big APKs can take minutes; raise the cap or narrow the request"
        )
    except Exception as exc:
        return None, f"jadx launch failed: {exc}"


def _proc_tails(proc) -> Tuple[str, str]:
    """Bounded ``(stderr_tail, stdout_tail)`` from a finished jadx run.

    Empirical jadx 1.5.6 fact (verified 2026-09-22): ALL log output —
    including fatal errors such as ``ERROR - Incorrect arguments: Input
    class not found: <fqn>`` — is written to STDOUT; STDERR is normally
    empty, even on failure.  Diagnostic surfaces must therefore fall back
    to stdout, and the binary must never run under ``-q`` (which maps to
    ``--log-level QUIET`` and suppresses even that error text: a not-found
    single-class pull then exits 1 with 0 bytes on BOTH streams).
    """
    return (
        (proc.stderr or "").strip()[-2000:],
        (proc.stdout or "").strip()[-2000:],
    )


# ---------------------------------------------------------------------------
# The discovery tool
# ---------------------------------------------------------------------------
@framework_tool(
    "List APKs/dex/jars available for apk disassembly and decompilation in "
    "the framework's apk drop folder (apk/). Returns each file's name, "
    "detected format (APK, DEX, JAR, XAPK, AAB, etc.), size, and relative "
    "path. Drop new targets into apk/ (gitignored) and re-call this; "
    "run_jadx auto-resolves bare names from this folder, so you only need "
    "the filename.",
    next_hints=["run_jadx"],
)
def list_apk_targets() -> Dict[str, Any]:
    """Enumerate recognised files in the apk drop folder.

    Walks :data:`APK_TARGETS_ROOT` (default ``apk/`` at the repo root;
    override via ``JADX_APK_TARGETS_ROOT`` env) recursively, filtering to
    jadx-acceptable magic headers (ZIP-family = apk/xapk/apkm/aab/aar/jar/zip,
    raw .dex, .class, .arsc).  The ``decompiled/`` workspace subtree is
    excluded so outputs never pollute the listing.

    Returns a dict with ``status, root, count, targets, jadx_version,
    next_hints``.
    """
    jadx_bin = resolve_jadx_bin()
    root = APK_TARGETS_ROOT
    if not os.path.isdir(root):
        return {
            "status": "error",
            "root": root,
            "count": 0,
            "targets": [],
            "jadx_version": _jadx_version(),
            "next_hints": [],
            "error": (
                f"apk drop folder {root!r} does not exist. Create it and drop "
                f"targets there (gitignored), or set JADX_APK_TARGETS_ROOT."
            ),
        }
    targets = discover_apk_targets(root)
    hints = [
        "run_jadx('<name>', 'manifest') — fast AndroidManifest.xml pull",
        "run_jadx('<name>', 'class', single_class='com.example.Foo') — one class, no full decompile",
        "run_jadx('<name>', 'decompile') — full decompile into the cached workspace",
    ]
    if jadx_bin is None:
        hints.insert(0, (
            "jadx not on PATH — install the 1.5.x release bundle and put "
            "bin/jadx on PATH, or set the JADX_BIN env var"
        ))
    return {
        "status": "ok",
        "root": root,
        "count": len(targets),
        "targets": targets,
        "jadx_version": _jadx_version(),
        "next_hints": hints,
    }


# ---------------------------------------------------------------------------
# Verb implementations
# ---------------------------------------------------------------------------
def _verb_decompile(
    target: str, deobf: bool, show_bad_code: bool, mode: str,
    threads: Optional[int], no_res: bool, force: bool,
) -> Dict[str, Any]:
    ws = _workspace_for(target)
    state = _workspace_state(ws, target)
    if state["exists"] and not state["stale"] and state["has_sources"] and not force:
        n_java = _count_by_ext(ws, ".java")
        return {
            "status": "ok",
            "verb": "decompile",
            "summary": (
                f"workspace cached and fingerprint-fresh — {n_java} .java "
                f"file(s); use force=True to re-decompile"
            ),
            "workspace": ws,
            "cached": True,
            "java_source_count": n_java,
            "stale": False,
            "output": "",
            "truncated": False,
            "truncation_policy": None,
            "target": target,
            "jadx_version": _jadx_version(),
            "next_hints": [
                "run_jadx('<name>', 'grep', pattern='<regex>') to hunt creds/routes/secrets",
                "run_jadx('<name>', 'read', path='<rel path>') to pull one source file",
                "run_jadx('<name>', 'manifest') for AndroidManifest.xml",
            ],
            "delta": f"workspace reuse ({n_java} sources on disk)",
        }
    if state["exists"] and (state["stale"] or force):
        preflight = _preflight_or_none(target, "decompile")
        if preflight:
            return preflight
        shutil.rmtree(ws, ignore_errors=True)  # inside decompiled/ only
    elif not state["exists"]:
        preflight = _preflight_or_none(target, "decompile")
        if preflight:
            return preflight
    os.makedirs(ws, exist_ok=True)
    # --log-level ERROR (NOT -q): -q maps to --log-level QUIET on jadx 1.5.6
    # and deletes the very failure diagnostics this envelope surfaces (see
    # _proc_tails).  Errors stay visible; progress noise is suppressed.
    argv = [resolve_jadx_bin(), "--log-level", "ERROR", "-d", ws]
    if no_res:
        argv.append("-r")
    if deobf:
        argv.append("--deobf")
    if show_bad_code:
        argv.append("--show-bad-code")
    if mode != "auto":
        argv.extend(["--decompilation-mode", mode])
    if threads:
        argv.extend(["-j", str(threads)])
    argv.append(target)
    proc, err = _run_jadx_argv(argv)
    if err:
        return _err_verb(target, "decompile", err)
    n_java = _count_by_ext(ws, ".java")
    n_res = _count_all(ws, skip="sources") - n_java
    if proc.returncode == 0:
        _write_meta(ws, target, _jadx_version())  # a failed run stays stale
    stderr_tail, stdout_tail = _proc_tails(proc)
    summary = (
        f"decompiled → {n_java} .java source(s), {max(0, n_res)} other file(s) "
        f"in {ws} (exit {proc.returncode})"
    )
    if proc.returncode != 0:
        summary = (
            f"decompile failed (exit {proc.returncode}): "
            f"{stderr_tail or stdout_tail or 'jadx emitted no diagnostics'} "
            f"— {n_java} .java source(s) written (may be partial) in {ws}"
        )
    result: Dict[str, Any] = {
        "status": "ok" if proc.returncode == 0 else "error",
        "verb": "decompile",
        "summary": summary,
        "workspace": ws,
        "cached": False,
        "java_source_count": n_java,
        "exit_code": proc.returncode,
        "stderr_tail": stderr_tail,
        "stdout_tail": stdout_tail,
        "stale": False,
        "output": "",
        "truncated": False,
        "truncation_policy": None,
        "target": target,
        "jadx_version": _jadx_version(),
        "next_hints": [
            "run_jadx('<name>', 'grep', pattern='api_key|token|secret')",
            "run_jadx('<name>', 'tree', glob='sources/com/<pkg>/*')",
            "run_jadx('<name>', 'read', path='sources/com/<pkg>/MainActivity.java')",
            "report_finding to record a discovered artifact",
        ],
        "delta": f"fresh decompile ({n_java} sources); exit {proc.returncode}",
    }
    if proc.returncode != 0:
        result["error"] = summary
    return result


def _verb_manifest(target: str) -> Dict[str, Any]:
    ws = _workspace_for(target)
    manifest_path = os.path.join(ws, _MANIFEST_REL)
    state = _workspace_state(ws, target)
    if not (state["exists"] and state["has_manifest"] and not state["stale"]):
        preflight = _preflight_or_none(target, "manifest")
        if preflight:
            return preflight
        # resources-only top-up (-s/--no-src keeps the fast path cheap)
        if state["exists"] and state["stale"]:
            shutil.rmtree(ws, ignore_errors=True)
        os.makedirs(ws, exist_ok=True)
        argv = [resolve_jadx_bin(), "--log-level", "ERROR", "-s", "-d", ws, target]
        proc, err = _run_jadx_argv(argv)
        if err:
            return _err_verb(target, "manifest", err)
        if proc.returncode != 0:
            stderr_tail, stdout_tail = _proc_tails(proc)
            return _err_verb(
                target, "manifest",
                f"jadx resources-only pass failed (exit {proc.returncode}): "
                f"{stderr_tail or stdout_tail or 'jadx emitted no diagnostics'}",
                extra={
                    "exit_code": proc.returncode,
                    "stderr_tail": stderr_tail,
                    "stdout_tail": stdout_tail,
                },
            )
        _write_meta(ws, target, _jadx_version())
    safe = _safe_ws_child(ws, _MANIFEST_REL)
    if safe is None or not os.path.isfile(safe):
        return _err_verb(
            target, "manifest",
            f"no decoded {os.path.basename(target)} at resources/AndroidManifest.xml — "
            f"is this an Android target? (plain jars/dex have no manifest)",
        )
    with open(safe, "r", encoding="utf-8", errors="replace") as fh:
        content = fh.read()
    content, truncated = _clip(content)
    return {
        "status": "ok",
        "verb": "manifest",
        "summary": f"AndroidManifest.xml decoded ({len(content)} chars)",
        "output": content,
        "workspace": ws,
        "truncated": truncated,
        "truncation_policy": _TRUNCATION_NOTE if truncated else None,
        "target": target,
        "jadx_version": _jadx_version(),
        "next_hints": [
            "exported activities/receivers/providers = the attack surface map",
            "run_jadx('<name>', 'grep', pattern='<manifest-string>') in sources",
            "report_finding to record an entry-point note",
        ],
        "delta": "manifest decoded",
    }


def _verb_class(target: str, single_class: Optional[str]) -> Dict[str, Any]:
    if not single_class or not _CLASS_RE.match(single_class):
        return _err_verb(
            target, "class",
            f"single_class {single_class!r} is not a valid Java class FQN "
            f"([A-Za-z0-9_.$-]+); rejected",
        )
    preflight = _preflight_or_none(target, "class")
    if preflight:
        return preflight
    jadx_bin = resolve_jadx_bin()
    tmp_dir = tempfile.mkdtemp(prefix="jadxclass_")
    try:
        # --log-level ERROR (NOT -q): on jadx 1.5.6, -q maps to
        # --log-level QUIET and suppresses ALL output — a not-found FQN then
        # exits 1 with 0 bytes on stdout AND stderr, leaving the failure
        # unexplainable.  With ERROR the real cause survives on stdout:
        # ``ERROR - Incorrect arguments: Input class not found: <fqn>``.
        argv = [
            jadx_bin, "--log-level", "ERROR",
            "--single-class", single_class,
            "--single-class-output", tmp_dir,
            target,
        ]
        proc, err = _run_jadx_argv(argv)
        if err:
            return _err_verb(target, "class", err)
        produced = [
            os.path.join(tmp_dir, f) for f in sorted(os.listdir(tmp_dir))
        ]
        if proc.returncode != 0 or not produced:
            stderr_tail, stdout_tail = _proc_tails(proc)
            diag = stderr_tail or stdout_tail or "jadx emitted no diagnostics"
            extra: Dict[str, Any] = {
                "single_class": single_class,
                "exit_code": proc.returncode,
                "stderr_tail": stderr_tail,
                "stdout_tail": stdout_tail,
            }
            if not produced:
                extra["note"] = (
                    "no output produced — the FQN may be absent from this "
                    "artifact (BuildConfig is a classic case: R8 strips it "
                    "from release builds); verify independently via "
                    "run_jadx('<name>', 'decompile') then grep/tree for it"
                )
            return _err_verb(
                target, "class",
                f"single-class pull failed (exit {proc.returncode}): {diag}",
                extra=extra,
            )
        out_file = produced[0]
        with open(out_file, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
        content, truncated = _clip(content)
        lines = content.count("\n") + 1
        return {
            "status": "ok",
            "verb": "class",
            "summary": (
                f"single-class pull {single_class}: {lines} line(s) "
                f"(exit {proc.returncode})"
            ),
            "output": content,
            "single_class": single_class,
            "truncated": truncated,
            "truncation_policy": _TRUNCATION_NOTE if truncated else None,
            "target": target,
            "jadx_version": _jadx_version(),
            "next_hints": [
                "run_jadx('<name>', 'decompile') to cache the whole tree for grep",
                "run_jadx('<name>', 'class', single_class='<next class>')",
                "report_finding to record a discovered behavior",
            ],
            "delta": f"pulled 1 class ({lines} lines)",
        }
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _verb_grep(
    target: str, pattern: Optional[str], glob: Optional[str],
    case_insensitive: bool,
    max_matches: Optional[int] = None, offset: int = 0,
    max_files: Optional[int] = None,
) -> Dict[str, Any]:
    ws = _workspace_for(target)
    if not os.path.isdir(ws):
        return _err_verb(
            target, "grep",
            f"no decompiled workspace yet — run run_jadx('{os.path.basename(target)}', "
            f"'decompile') first (grep searches the cached tree, not the raw apk)",
        )
    if not pattern:
        return _err_verb(target, "grep", "pattern is required for the grep verb")
    if len(pattern) > _PATTERN_CAP:
        return _err_verb(
            target, "grep",
            f"pattern longer than {_PATTERN_CAP} chars; rejected",
        )
    try:
        rx = re.compile(pattern, re.IGNORECASE if case_insensitive else 0)
    except re.error as exc:
        return _err_verb(target, "grep", f"invalid regex: {exc}")
    if glob is not None and not _GLOB_RE.match(glob):
        return _err_verb(
            target, "grep",
            f"glob {glob!r} contains characters outside [A-Za-z0-9_*?.-/]; rejected",
        )
    # --- paging params: cap raise + offset ---------------------------------
    try:
        offset = int(offset)
    except (TypeError, ValueError):
        return _err_verb(target, "grep", f"offset must be an integer, got {offset!r}")
    if offset < 0:
        return _err_verb(target, "grep", f"offset must be >= 0, got {offset}")
    cap = _GREP_MAX_MATCHES
    cap_raised = False
    if max_matches is not None:
        try:
            requested = int(max_matches)
        except (TypeError, ValueError):
            return _err_verb(
                target, "grep",
                f"max_matches must be an integer, got {max_matches!r}",
            )
        if requested < 1:
            return _err_verb(
                target, "grep", f"max_matches must be >= 1, got {requested}",
            )
        if requested > _GREP_MATCHES_CEILING:
            cap = _GREP_MATCHES_CEILING
            cap_raised = True   # clamped down — say so in the envelope
        else:
            cap = requested
            cap_raised = requested != _GREP_MAX_MATCHES
    # Collect ``offset + cap`` hits, then slice the page — so offset pages
    # through a large result without re-walking or losing the earlier hits.
    want = offset + cap
    # Effective file-scan cap: default or caller-raised (clamped to ceiling).
    file_cap = _GREP_MAX_FILES
    if max_files is not None:
        try:
            requested_files = int(max_files)
        except (TypeError, ValueError):
            return _err_verb(
                target, "grep", f"max_files must be an integer, got {max_files!r}"
            )
        if requested_files < 1:
            return _err_verb(
                target, "grep", f"max_files must be >= 1, got {requested_files}"
            )
        file_cap = min(requested_files, _GREP_FILES_CEILING)
    import fnmatch
    collected: List[Dict[str, Any]] = []
    files_scanned = 0
    files_skipped = 0
    real_ws = os.path.realpath(ws)
    for dirpath, dirnames, filenames in os.walk(ws):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        if files_scanned >= file_cap:
            break
        for fname in sorted(filenames):
            if files_scanned >= file_cap:
                break
            rel = os.path.relpath(os.path.join(dirpath, fname), ws)
            if glob and not fnmatch.fnmatch(rel, glob):
                continue
            if os.path.splitext(fname)[1].lower() not in _GREP_TEXT_EXTS:
                files_skipped += 1
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath, "rb") as fh:
                    blob = fh.read(_GREP_MAX_FILE_BYTES + 1)
            except OSError:
                continue
            if b"\x00" in blob:  # binary — skip, don't regex bytes
                files_skipped += 1
                continue
            files_scanned += 1
            text = blob.decode("utf-8", errors="replace")
            for line_no, line in enumerate(text.splitlines(), start=1):
                if rx.search(line):
                    collected.append({
                        "file": os.path.relpath(fpath, real_ws),
                        "line": line_no,
                        "text": line.strip()[:200],
                    })
                    if len(collected) >= want:
                        break
            if len(collected) >= want:
                break
        if len(collected) >= want:
            break
    matches = collected[offset:want]
    # Conservative: exactly-at-cap counts as truncated — an exact fit cannot
    # be distinguished from "walk stopped at the cap with more matches left".
    # The next page comes back empty and settles it.
    truncated = len(collected) >= want or files_scanned >= file_cap
    next_offset = want if (truncated and len(collected) >= want) else None
    policy_bits = []
    if max_files is not None and file_cap < int(max_files):
        policy_bits.append(
            f"max_files {max_files} clamped to the hard ceiling "
            f"{_GREP_FILES_CEILING} (JADX_GREP_FILES_CEILING env)"
        )
    if cap_raised and max_matches is not None and int(max_matches) > _GREP_MATCHES_CEILING:
        policy_bits.append(
            f"max_matches {max_matches} clamped to the hard ceiling "
            f"{_GREP_MATCHES_CEILING} (JADX_GREP_MATCHES_CEILING env)"
        )
    if truncated:
        policy_bits.append(
            f"at least {len(collected)} match(es) seen — showing {offset}..{want - 1}; "
            f"pass offset={next_offset} for the next page or raise max_matches "
            f"(cap {cap}, ceiling {_GREP_MATCHES_CEILING})"
            if len(collected) >= want
            else
            f"file-scan cap {file_cap} reached before the match cap — "
            f"results may be incomplete; narrow with glob to go deeper or "
            f"raise max_files (ceiling {_GREP_FILES_CEILING})"
        )
    elif cap_raised:
        policy_bits.append(
            f"cap raised to {cap} (default {_GREP_MAX_MATCHES}) — "
            f"all {len(collected)} match(es) fit"
        )
    return {
        "status": "ok",
        "verb": "grep",
        "summary": (
            f"{len(matches)} match(es) in {len(set(m['file'] for m in matches))} "
            f"file(s) — {files_scanned} file(s) scanned, {files_skipped} skipped "
            f"(non-text/ext), pattern {pattern!r}"
            + (f", offset {offset}" if offset else "")
        ),
        "matches": matches,
        "offset": offset,
        "returned": len(matches),
        # Matches seen within the scan window. When ``truncated`` this is a
        # LOWER BOUND — the walk stops at offset+cap and never counts the
        # tail (walking past the page window would defeat the cap).
        "total_matches": len(collected),
        "total_is_lower_bound": truncated,
        "files_scanned": files_scanned,
        "files_skipped": files_skipped,
        "files_capped": files_scanned >= file_cap,
        "workspace": ws,
        "truncated": truncated,
        "next_offset": next_offset,
        "truncation_policy": ("; ".join(policy_bits) if policy_bits else None),
        "target": target,
        "jadx_version": _jadx_version(),
        "next_hints": [
            "run_jadx('<name>', 'read', path='<match file>') to read context",
            f"run_jadx('<name>', 'grep', pattern=..., offset={next_offset}) to page"
            if truncated and len(collected) >= want
            else (
                "report_finding to record a hard-coded secret / route / endpoint"
                if not truncated
                else "narrow with glob, or raise max_files to scan deeper"
            ),
        ],
        "delta": f"{len(matches)} grep hits",
    }


def _verb_read(target: str, path: Optional[str]) -> Dict[str, Any]:
    ws = _workspace_for(target)
    if not os.path.isdir(ws):
        return _err_verb(
            target, "read",
            f"no decompiled workspace — run run_jadx('{os.path.basename(target)}', "
            f"'decompile') first (or 'class' for a single class)",
        )
    safe = _safe_ws_child(ws, path or "")
    if safe is None:
        return _err_verb(
            target, "read",
            f"path {path!r} refuses containment (no absolute paths, no '..') — "
            f"use a path relative to the workspace, e.g. 'sources/com/pkg/Main.java'",
        )
    if not os.path.isfile(safe):
        return _err_verb(
            target, "read",
            f"path {path!r} not found in workspace — run_jadx('"
            f"{os.path.basename(target)}', 'tree') to list files",
        )
    with open(safe, "rb") as fh:
        blob = fh.read(_OUTPUT_CAP + 1)
    truncated = len(blob) > _OUTPUT_CAP
    text = blob[:_OUTPUT_CAP].decode("utf-8", errors="replace")
    lines = text.count("\n") + 1
    return {
        "status": "ok",
        "verb": "read",
        "summary": f"{path}: {lines} line(s), {len(blob)} byte(s)",
        "output": text,
        "path": os.path.relpath(safe, os.path.realpath(ws)),
        "workspace": ws,
        "truncated": truncated,
        "truncation_policy": _TRUNCATION_NOTE if truncated else None,
        "target": target,
        "jadx_version": _jadx_version(),
        "next_hints": [
            "grep the workspace for what this code references",
            "report_finding to record a discovered artifact",
        ],
        "delta": f"read {path}",
    }


def _verb_tree(
    target: str, glob: Optional[str],
    tree_mode: str = "files", offset: int = 0,
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    ws = _workspace_for(target)
    if not os.path.isdir(ws):
        return _err_verb(
            target, "tree",
            f"no decompiled workspace — run run_jadx('{os.path.basename(target)}', "
            f"'decompile') first",
        )
    if glob is not None and not _GLOB_RE.match(glob):
        return _err_verb(
            target, "tree",
            f"glob {glob!r} contains characters outside [A-Za-z0-9_*?.-/]; rejected",
        )
    if tree_mode not in ("files", "dirs"):
        return _err_verb(
            target, "tree",
            f"tree_mode {tree_mode!r} not in (files, dirs); rejected — 'files' is "
            f"the flat path listing, 'dirs' rolls the workspace up per directory "
            f"with file counts so a big tree stays navigable",
        )
    try:
        offset = int(offset)
    except (TypeError, ValueError):
        return _err_verb(target, "tree", f"offset must be an integer, got {offset!r}")
    if offset < 0:
        return _err_verb(target, "tree", f"offset must be >= 0, got {offset}")
    page_cap = _TREE_LIST_CAP
    if limit is not None:
        try:
            requested = int(limit)
        except (TypeError, ValueError):
            return _err_verb(target, "tree", f"limit must be an integer, got {limit!r}")
        if requested < 1:
            return _err_verb(target, "tree", f"limit must be >= 1, got {requested}")
        page_cap = min(requested, _TREE_LIST_CAP)
    import fnmatch
    if tree_mode == "dirs":
        # Per-directory rollup: the model navigates a big workspace by
        # directory counts instead of a flat 500-path wall of text.
        counts: Dict[str, Dict[str, Any]] = {}
        for dirpath, dirnames, filenames in os.walk(ws):
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            dir_rel = os.path.relpath(dirpath, ws)
            if dir_rel == ".":
                continue
            entry = counts.setdefault(
                dir_rel, {"files": 0, "subdirs": [], "total_files": 0}
            )
            for fname in filenames:
                rel = os.path.relpath(os.path.join(dirpath, fname), ws)
                if glob and not fnmatch.fnmatch(rel, glob):
                    continue
                entry["files"] += 1
            entry["subdirs"] = sorted(d for d in dirnames if not d.startswith("."))
        # total_files per dir = own files + every descendant's files
        for dir_rel in list(counts):
            total = counts[dir_rel]["files"]
            prefix = dir_rel.rstrip(os.sep) + os.sep
            for other, other_entry in counts.items():
                if other.startswith(prefix):
                    total += other_entry["files"]
            counts[dir_rel]["total_files"] = total
        # With a glob, dirs holding zero matching files are pure noise — drop
        # them. Unfiltered, keep them: a 0-file dir with subdirs is structure.
        if glob:
            ordered = [d for d in sorted(counts) if counts[d]["files"] > 0]
        else:
            ordered = sorted(counts)
        total_dirs = len(ordered)
        page = [
            {"dir": d, **counts[d]} for d in ordered[offset:offset + page_cap]
        ]
        truncated = total_dirs > offset + page_cap
        next_offset = offset + page_cap if truncated else None
        return {
            "status": "ok",
            "verb": "tree",
            "tree_mode": "dirs",
            "summary": (
                f"{total_dirs} director(ies) in workspace"
                + (f", {sum(c['total_files'] for c in counts.values())} file(s)"
                   if not glob else "")
                + (f" (showing {len(page)} from offset {offset})" if page_cap else "")
            ),
            "dirs": page,
            "total_dirs": total_dirs,
            "offset": offset,
            "returned": len(page),
            "next_offset": next_offset,
            "workspace": ws,
            "truncated": truncated,
            "truncation_policy": (
                f"dir listing capped at {page_cap} — pass offset={next_offset} "
                f"for the next page, or narrow with glob"
                if truncated else None
            ),
            "target": target,
            "jadx_version": _jadx_version(),
            "next_hints": [
                "run_jadx('<name>', 'tree', tree_mode='files', glob='<dir>/*') "
                "to enumerate one package",
                "run_jadx('<name>', 'grep', pattern='<regex>', glob='<dir>/*.java')",
            ],
            "delta": f"listed {len(page)}/{total_dirs} dirs",
        }
    # --- flat files listing (default; backward compatible) ------------------
    all_files: List[str] = []
    for dirpath, dirnames, filenames in os.walk(ws):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for fname in filenames:
            all_files.append(os.path.relpath(os.path.join(dirpath, fname), ws))
    all_files.sort()
    if glob:
        import fnmatch as _fm
        all_files = [f for f in all_files if _fm.fnmatch(f, glob)]
    total_files = len(all_files)
    listing = all_files[offset:offset + page_cap]
    truncated = total_files > offset + page_cap
    next_offset = offset + page_cap if truncated else None
    return {
        "status": "ok",
        "verb": "tree",
        "tree_mode": "files",
        "summary": f"{total_files} file(s) in workspace (showing {len(listing)})",
        "files": listing,
        "total_files": total_files,
        "offset": offset,
        "returned": len(listing),
        "next_offset": next_offset,
        "workspace": ws,
        "truncated": truncated,
        "truncation_policy": (
            f"listing capped at {page_cap} — pass offset={next_offset} for the "
            f"next page, narrow with glob, or tree_mode='dirs' for a rollup"
            if truncated else None
        ),
        "target": target,
        "jadx_version": _jadx_version(),
        "next_hints": [
            "run_jadx('<name>', 'read', path='<file from list>')",
            "run_jadx('<name>', 'grep', pattern='<regex>')",
        ],
        "delta": f"listed {total_files} files",
    }


def _count_by_ext(ws: str, ext: str) -> int:
    n = 0
    for dirpath, dirnames, filenames in os.walk(ws):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        n += sum(1 for f in filenames if f.endswith(ext))
    return n


def _count_all(ws: str, skip: Optional[str] = None) -> int:
    n = 0
    for dirpath, dirnames, filenames in os.walk(ws):
        if skip:
            dirnames[:] = [d for d in dirnames if d != skip]
        else:
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        n += len(filenames)
    return n


# ---------------------------------------------------------------------------
# The composite tool
# ---------------------------------------------------------------------------

def _run_jadx_digest(result: Dict[str, Any]) -> Dict[str, Any]:
    """Digest adapter for ``run_jadx`` — per-verb compact summary.

    The full jadx output (grep match lists, decompiled source blobs, file
    trees) is stored in scratch; the model gets a verb-specific digest:

    - **grep**: match count + first N matches (file:line:match) + paging info
    - **decompile**: java source count + workspace reuse flag + next hints
    - **tree**: file/dir count + whether truncated + a sample of paths
    - **read**: line count + truncated flag (the source content is the output)
    - **manifest**: char count + truncated flag (the XML is the output)
    - **class**: line count + class name + truncated flag
    - **error**: the error message (errors pass through in full anyway)
    """
    status = str(result.get("status", "")).lower()
    if status == "error":
        # Errors are always returned in full by the projection layer.
        err = result.get("error", "") or result.get("summary", "")
        return {"summary": f"error: {err[:500]}", "row_hint_format": ""}

    verb = result.get("verb", "unknown")
    parts: list = [f"status=ok", f"verb={verb}"]

    summary = result.get("summary", "")
    if summary:
        parts.append(f"summary={summary[:300]}")

    delta = result.get("delta", "")
    if delta:
        parts.append(f"delta={delta[:200]}")

    # --- verb-specific compact fields ---
    if verb == "grep":
        matches = result.get("matches", [])
        total = result.get("total_matches", len(matches))
        parts.append(f"matches={total}")
        # Include first 10 matches — file:line:match preview.
        if matches:
            match_lines = "\n  ".join(
                f"{m.get('file', '?')}:{m.get('line', '?')}: "
                f"{str(m.get('match', ''))[:80]}"
                for m in matches[:10]
            )
            parts.append(f"top_matches:\n  {match_lines}")
            if total > 10:
                parts.append(f"  ... +{total - 10} more (retrieve from scratch)")
        truncated = result.get("truncated", False)
        if truncated:
            next_offset = result.get("next_offset")
            if next_offset:
                parts.append(f"next_offset={next_offset}")

    elif verb == "decompile":
        java_count = result.get("java_source_count", 0)
        parts.append(f"java_sources={java_count}")
        cached = result.get("cached", False)
        parts.append(f"cached={'yes' if cached else 'no'}")

    elif verb == "tree":
        total_files = result.get("total_files", 0)
        parts.append(f"total_files={total_files}")
        truncated = result.get("truncated", False)
        if truncated:
            parts.append("truncated=True")
            next_offset = result.get("next_offset")
            if next_offset:
                parts.append(f"next_offset={next_offset}")
        # Include a small sample of paths.
        listing = result.get("listing", [])
        if listing:
            sample = "\n  ".join(str(p) for p in listing[:8])
            parts.append(f"sample:\n  {sample}")

    elif verb in ("read", "manifest", "class"):
        # These verbs return content in 'output' — report size + truncation.
        output = result.get("output", "")
        if isinstance(output, str) and output:
            line_count = len([ln for ln in output.splitlines() if ln.strip()])
            parts.append(f"lines={line_count}")
        truncated = result.get("truncated", False)
        if truncated:
            parts.append("truncated=True")
        if verb == "class":
            cls = result.get("single_class", "")
            if cls:
                parts.append(f"class={cls}")

    # Common: target name + jadx version.
    target = result.get("target", "")
    if target:
        parts.append(f"target={os.path.basename(target)}")

    # Next hints — guide the model's next jadx call.
    hints = result.get("next_hints", [])
    if hints:
        parts.append(f"hints: {'; '.join(hints[:3])}")

    summary_text = " | ".join(parts)

    row_hint = (
        "scratch_search scratch:<id> --filter 'api_key|token|secret' "
        "# pull specific matches from the full output"
    )

    return {"summary": summary_text, "row_hint_format": row_hint}


@framework_tool(
    "Static Android APK analysis with jadx — apk disassembly and "
    "decompilation: disassemble and decompile an APK/dex/jar/aab/xapk into "
    "readable Java sources, decode AndroidManifest.xml, pull a single class "
    "via --single-class, grep the decompiled apk sources with a regex, read "
    "one decompiled file, or list the tree. This is the apk decompiler / "
    "disassembler for Android reverse engineering. One composite tool — "
    "pass a verb (decompile, manifest, class, grep, read, tree) from the "
    "allowlist plus verb-specific params. Targets auto-resolve by bare name "
    "from the apk/ drop folder. Runs offline (no network, no scope gate); "
    "the decompile is cached per target and reused until the apk changes.",
    next_hints=["report_finding"],
    result_digest=lambda r: _run_jadx_digest(r),
    untrusted_target=True,
)
def run_jadx(
    target: str,
    command: str,
    # --- decompile verb params ---
    deobf: bool = False,
    show_bad_code: bool = False,
    mode: str = "auto",
    threads: Optional[int] = None,
    no_res: bool = False,
    force: bool = False,
    # --- class verb param ---
    single_class: Optional[str] = None,
    # --- grep verb params ---
    pattern: Optional[str] = None,
    glob: Optional[str] = None,
    case_insensitive: bool = False,
    max_matches: Optional[int] = None,
    max_files: Optional[int] = None,
    # --- read verb param ---
    path: Optional[str] = None,
    # --- shared paging / tree params ---
    offset: int = 0,
    tree_mode: str = "files",
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    """Drive jadx against a target from the apk drop folder.

    Args:
        target: Path or bare name resolved against the apk drop folder
            (default ``apk/``; override via ``JADX_APK_TARGETS_ROOT``).
        command: Verb from the frozen allowlist — ``decompile``, ``manifest``,
            ``class``, ``grep``, ``read``, ``tree`` (exact match only).
        deobf: decompile verb — add ``--deobf`` (rename obfuscated classes).
        show_bad_code: decompile verb — add ``--show-bad-code`` (keep
            inconsistent code instead of jadx's comment placeholders).
        mode: decompile verb — ``auto`` (default) | ``restructure`` |
            ``simple`` | ``fallback``.
        threads: decompile verb — ``-j`` thread count, clamped 1..16.
        no_res: decompile verb — add ``-r`` (skip resource decode).
        force: decompile verb — re-run even when the cached workspace is
            fingerprint-fresh.
        single_class: class verb — full class name (``com.example.Foo``;
            inner classes use ``$``).
        pattern: grep verb — Python regex, compiled in-process (never shell).
        glob: grep/tree verb — fnmatch filter on workspace-relative paths.
        case_insensitive: grep verb — regex flag.
        max_matches: grep verb — raise the match cap (default 200, hard
            ceiling 2000 via ``JADX_GREP_MATCHES_CEILING``). Combine with
            ``offset`` to page instead of raising when the tree is huge.
        max_files: grep verb — raise the file-scan cap (default 4000, hard
            ceiling 50000 via ``JADX_GREP_FILES_CEILING``). On a big
            decompiled tree this cap binds before ``max_matches`` does.
        path: read verb — workspace-relative file path (traversal-guarded).
        offset: grep/tree verb — 0-based index of the first result to return
            (paging through a large result set).
        tree_mode: tree verb — ``files`` (default; flat path listing) |
            ``dirs`` (per-directory rollup: file counts + subdirs, the way to
            map a big decompiled tree without a wall of paths).
        limit: tree verb — page size for the listing (default/cap 500).

    Returns:
        Dict envelope: ``status, verb, summary, workspace, target,
        jadx_version, output/truncated/truncation_policy, next_hints, delta``
        plus verb-specific fields; errors return ``status="error"`` with an
        ``error`` message instead of raising.
    """
    # --- Layer 1: exact verb allowlist ---
    if command not in _VERB_TABLE:
        return _err_verb(
            target, command,
            f"verb {command!r} is not in the allowlist "
            f"({', '.join(ALLOWED_VERBS)}); rejected",
        )
    if mode not in _DECOMPILE_MODES:
        return _err_verb(
            target, command,
            f"mode {mode!r} not in {', '.join(_DECOMPILE_MODES)}; rejected",
        )
    threads_val: Optional[int] = None
    if threads is not None:
        try:
            threads_val = int(threads)
        except (TypeError, ValueError):
            return _err_verb(target, command, f"threads must be an integer, got {threads!r}")
        threads_val = max(_THREADS_MIN, min(_THREADS_MAX, threads_val))

    # --- target resolution: existing path, or drop-folder auto-resolve ---
    resolved = resolve_apk_target(target) if target else None
    if resolved is None:
        return _err_verb(
            target, command,
            f"target {target!r} not found — no such file, and no match in the "
            f"apk drop folder ({APK_TARGETS_ROOT}). Call list_apk_targets to "
            f"see what is available.",
        )
    target = resolved

    if command == "decompile":
        return _verb_decompile(
            target, bool(deobf), bool(show_bad_code), mode,
            threads_val, bool(no_res), bool(force),
        )
    if command == "manifest":
        return _verb_manifest(target)
    if command == "class":
        return _verb_class(target, single_class)
    if command == "grep":
        return _verb_grep(
            target, pattern, glob, bool(case_insensitive),
            max_matches=max_matches, offset=offset, max_files=max_files,
        )
    if command == "read":
        return _verb_read(target, path)
    if command == "tree":
        return _verb_tree(target, glob, tree_mode=tree_mode, offset=offset, limit=limit)
    return _err_verb(target, command, "unreachable verb dispatch")  # belt+braces


def _err_verb(
    target: Optional[str],
    command: Optional[str],
    error: str,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Consistent error envelope.

    ``extra`` merges verb-specific keys (e.g. ``stderr_tail``/``stdout_tail``
    on jadx-spawn failures) into the base shape without changing it.
    """
    envelope: Dict[str, Any] = {
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