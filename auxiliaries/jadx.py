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

import os
from typing import Any

# --- carved guts (tool surface never moves; plain-helper shims are lane-legal)
from auxiliaries._jadx_preflight import (
    _DECOMPILE_MODES,
    _THREADS_MAX,
    _THREADS_MIN,
    _VERB_TABLE,
    ALLOWED_VERBS,
    _err_verb,
    _jadx_version,
    _java_available,  # noqa: F401 - payloads/jadx_fleet.py imports this from the facade
    resolve_jadx_bin,
)
from auxiliaries._jadx_targets import (
    APK_TARGETS_ROOT,
    _workspace_for,  # noqa: F401 - payloads/jadx_fleet.py imports this from the facade
    _workspace_state,  # noqa: F401 - payloads/jadx_fleet.py imports this from the facade
    discover_apk_targets,
    resolve_apk_target,
)
from auxiliaries._jadx_verbs import (
    _run_jadx_digest,
    _verb_class,
    _verb_decompile,
    _verb_grep,
    _verb_manifest,
    _verb_read,
    _verb_tree,
)
from constants import framework_tool


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
def list_apk_targets() -> dict[str, Any]:
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
    threads: int | None = None,
    no_res: bool = False,
    force: bool = False,
    # --- class verb param ---
    single_class: str | None = None,
    # --- grep verb params ---
    pattern: str | None = None,
    glob: str | None = None,
    case_insensitive: bool = False,
    max_matches: int | None = None,
    max_files: int | None = None,
    # --- read verb param ---
    path: str | None = None,
    # --- shared paging / tree params ---
    offset: int = 0,
    tree_mode: str = "files",
    limit: int | None = None,
) -> dict[str, Any]:
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
    threads_val: int | None = None
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
