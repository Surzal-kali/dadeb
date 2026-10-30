"""Verb implementations + workspace counters + result digest for ``jadx.py``.

Carved guts of ``auxiliaries/jadx.py`` (2026-10-30): the six ``_verb_*``
implementations the composite ``run_jadx`` tool dispatches to, the
bounded spawn helpers (``_clip``, ``_run_jadx_argv``, ``_proc_tails``),
workspace rollup counters, and the result-projection digest adapter.
Pure helpers over the workspace produced by ``auxiliaries._jadx_targets``
and the preflight/caps from ``auxiliaries._jadx_preflight``.  Docstring-
only sibling — no argparse, no ``@framework_tool`` members — so static
discovery never mints it; the facade imports the verbs + digest back and
remains the tool surface.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from typing import Any

from auxiliaries._jadx_preflight import (
    _CLASS_RE,
    _GLOB_RE,
    _GREP_FILES_CEILING,
    _GREP_MATCHES_CEILING,
    _GREP_MAX_FILE_BYTES,
    _GREP_MAX_FILES,
    _GREP_MAX_MATCHES,
    _GREP_TEXT_EXTS,
    _JADX_TIMEOUT,
    _OUTPUT_CAP,
    _PATTERN_CAP,
    _TREE_LIST_CAP,
    _TRUNCATION_NOTE,
    _err_verb,
    _jadx_version,
    _preflight_or_none,
    resolve_jadx_bin,
)
from auxiliaries._jadx_targets import (
    _MANIFEST_REL,
    _safe_ws_child,
    _workspace_for,
    _workspace_state,
    _write_meta,
)


def _clip(text: str) -> tuple:
    """Truncate to the output cap.  Returns (text, truncated)."""
    if len(text) > _OUTPUT_CAP:
        return text[:_OUTPUT_CAP], True
    return text, False


def _run_jadx_argv(argv: list[str]) -> tuple:
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


def _proc_tails(proc) -> tuple[str, str]:
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
# Verb implementations
# ---------------------------------------------------------------------------
def _verb_decompile(
    target: str, deobf: bool, show_bad_code: bool, mode: str,
    threads: int | None, no_res: bool, force: bool,
) -> dict[str, Any]:
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
    result: dict[str, Any] = {
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


def _verb_manifest(target: str) -> dict[str, Any]:
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
    with open(safe, encoding="utf-8", errors="replace") as fh:
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


def _verb_class(target: str, single_class: str | None) -> dict[str, Any]:
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
            extra: dict[str, Any] = {
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
        with open(out_file, encoding="utf-8", errors="replace") as fh:
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
    target: str, pattern: str | None, glob: str | None,
    case_insensitive: bool,
    max_matches: int | None = None, offset: int = 0,
    max_files: int | None = None,
) -> dict[str, Any]:
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
    collected: list[dict[str, Any]] = []
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
            f"{len(matches)} match(es) in {len({m['file'] for m in matches})} "
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


def _verb_read(target: str, path: str | None) -> dict[str, Any]:
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
    target: str, glob: str | None,
    tree_mode: str = "files", offset: int = 0,
    limit: int | None = None,
) -> dict[str, Any]:
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
        counts: dict[str, dict[str, Any]] = {}
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
    all_files: list[str] = []
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


def _count_all(ws: str, skip: str | None = None) -> int:
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

def _run_jadx_digest(result: dict[str, Any]) -> dict[str, Any]:
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
