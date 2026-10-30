"""Content-keyed unit identity for the worker queue (snapshot-cache precedent).

A unit's key is derived from the BYTES it operates on plus the argv's
work-semantics residue — identical APK bytes at a different filename are
the same unit, a flag difference is different work, and accounting knobs
(memory_budget) stay out of the key by principle."""
from __future__ import annotations

import os
import secrets

# Argv tokens naming an OUTPUT LOCATION are not work semantics (where the
# results live, not what the work IS): their flag + following value are
# stripped before the argv digest so a rerun pointed at another out-dir
# dedupes instead of double-launching the same bytes.
_KEY_LOCATION_FLAGS = ("-d", "--output-dir", "-o", "--output")


def _argv_for_key(argv: list[str] | None, path: str) -> list[str]:
    """Work-semantics residue of an argv, for content-key forking.

    Stripped: argv[0] (the program — the key's tool name owns that axis),
    any item exactly equal to the target path (the bytes digest owns the
    target), and a location flag plus its value (output destinations are
    incidental). What survives — mode/tuning flags like ``--deobf`` — IS
    the work: two units on identical bytes with different flags are
    different work (2026-10-30 code review: the old byte-only key deduped
    a flag-differing rerun that silently skipped that work).
    """
    residue: list[str] = []
    drop_next = False
    path_s = str(path)
    items = [str(a) for a in (argv or [])]
    for item in items[1:]:
        if drop_next:
            drop_next = False
            continue
        if item in _KEY_LOCATION_FLAGS:
            drop_next = True
            continue
        if item == path_s:
            continue
        residue.append(item)
    return residue


def content_key(tool: str, path: str, *, argv: list[str] | None = None) -> str:
    """Canonical worker-queue key: ``<tool>:c<sha256[:12]>`` of the BYTES
    plus ``:a<sha256[:12]>`` of the argv's work-semantics residue.

    Content, not path: identical APK bytes at a different filename are the
    same unit (re-drop with a new name must dedupe, not double-launch) —
    so the target path and output locations are stripped from the argv
    before digesting (``_argv_for_key``), and an argv with NO work
    residue digests to the exact bare key. A flag difference (the same
    bytes with/without ``--deobf``) forks the key: different work must
    not be deduped away (2026-10-30 code review). Accounting knobs stay
    out of the key by principle — ``memory_budget`` is the queue's claim,
    not the work's meaning, and forking on it would double-launch the
    same bytes.
    Unreadable/missing files fall back to a path+size key so the request
    still resolves (the launch will fail honestly on the missing input —
    an unhashable blob must not break the request pipeline).
    """
    import hashlib

    safe_tool = "".join(
        c if c.isalnum() or c in "_.-" else "-" for c in (tool or "unit").lower()
    )
    argv_digest = ""
    residue = _argv_for_key(argv, path)
    if residue:
        ah = hashlib.sha256()
        for item in residue:
            ah.update(item.encode("utf-8", "replace"))
            ah.update(b"\x00")
        argv_digest = f":a{ah.hexdigest()[:12]}"
    digest = None
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        digest = h.hexdigest()[:12]
    except OSError:
        pass
    if digest:
        return f"{safe_tool}:c{digest}{argv_digest}"
    try:
        st = os.stat(path)
        path_fallback = f"{os.path.basename(path)}:{st.st_size}"
    except OSError:
        path_fallback = secrets.token_hex(6)
    return f"{safe_tool}:p{hashlib.sha1(path_fallback.encode('utf-8', 'replace')).hexdigest()[:12]}{argv_digest}"