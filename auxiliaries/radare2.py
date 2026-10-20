"""Radare2 static-analysis composite tool (``run_r2``).

A single ``@framework_tool`` that drives radare2 as a one-shot subprocess
for static binary analysis: disassembly, decompilation (r2ghidra), symbol /
import / export / section / string enumeration, and cross-reference
queries.  There is deliberately ONE tool, not one per r2 command — the
secretary model picks the verb from a frozen allowlist and the tool composes
a safe ``-c`` string itself.

Threat model & validation (defense in depth)
--------------------------------------------
The injection surface is r2 itself, not bash: radare2's ``-c`` parser splits
on ``;`` and newlines, so a crafted ``addr`` could chain a second r2
command.  We defeat this with four independent layers:

1. **Exact allowlist match** on ``command`` — only the 19 frozen verbs are
   accepted (20th slot reserved).  No substring, no prefix match.
2. **Forbidden-character scan** on every free-text input (``command``,
   ``addr``): rejects `` ! ` $ > | & ; " '`` and newline.  These are the
   characters that matter to r2's ``-c`` parser and to a shell.
3. **Strict addr charset** — ``addr`` must be either a hex integer
   (``0x[0-9a-fA-F]+``) or a flag/symbol name (``[A-Za-z0-9_.$-]+``).  The
   tool composes ``cmd @ <addr>`` itself; the ``@`` never travels as free
   text from the caller.
4. **Integer caps** — ``count`` is coerced to int and clamped (``pd`` ≤ 512
   instructions, ``px`` ≤ 1024 bytes) so a fat binary can't be made to dump
   unbounded output.

The tool invokes r2 via a subprocess **argv list** (``shell=False``), so even
if a forbidden char slipped through it would never reach a shell.  r2 runs
against a **per-run temp copy** of the target binary and is never opened with
``-w``, so the original file is read-only by construction — the temp copy is
the only thing r2 could ever touch, and it is unlinked in ``finally``.

One-shot shape
--------------
::

    r2 -q -e scr.color=0 -e scr.utf8=0 -c 'aaa; <cmd> [<count>] [@ <addr>]' <tmpcopy>

A fresh r2 process is spawned per call: no session state, no seek/write
persistence between calls.  ``aaa`` (full analysis) is always prepended as
the opener so symbol-dependent commands (``afl``, ``pdf``, ``axt`` …) work
without the model having to chain a separate analysis call across a
stateless boundary.

Preflight
---------
``pdg`` (r2ghidra decompile) is the value item but depends on an optional
plugin.  A module-level cached probe checks for r2ghidra once per process;
if it is missing, a ``pdg`` call returns a clean envelope —
``"r2ghidra not installed — run: r2pm -ci r2ghidra"`` — instead of a raw
traceback.  Every other command works without the plugin.

Truncation
----------
``izz`` (whole-file strings), ``afl`` (function list), and fat ``pdf`` /
``pdg`` blobs explode on obfuscated/fat binaries.  Output is capped at
``R2_OUTPUT_CAP`` bytes (default 32 KiB — sized so one oversized result is
a moderate ~8-11k-token slice of a 100k-token model context window; the old
200 KiB default could eat 50k+ tokens in a single call).  Truncation keeps
the head AND tail (2/3 : 1/3) with an explicit omission marker between
them, so address-sorted listings (strings, function lists) stay informative
at both ends.  The envelope states the policy (``truncated``,
``truncation_policy``, ``omitted_bytes``).

Binary drop folder
------------------
Analysis targets live in a dedicated, gitignored ``binaries/`` directory at
the repo root (override via ``R2_BINARY_TARGETS_ROOT`` env).  Drop an ELF,
PE, Mach-O, shared lib, or object file there and the model can discover it
with ``list_r2_targets`` and then call ``run_r2`` with just the bare name
— ``run_r2`` auto-resolves a non-path ``target`` against the drop folder so
the model never needs to know the full filesystem path.  The folder itself
is walked recursively and filtered to files with recognised binary magic
bytes so text files and junk don't pollute the listing.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from constants import framework_tool
from utils.snapshot_cache import (
    build_cache_key,
    get_snapshot_store,
    sha256_of_file,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Frozen command table — schema-verified against radare2 6.2.1 on production.
# 19 slots filled; the 20th is held open for a practice-found gap.
# Each entry: verb -> (needs_addr, needs_count, count_cap, blurb)
# ---------------------------------------------------------------------------
_COMMAND_TABLE: Dict[str, Tuple[bool, bool, int, str]] = {
    # --- analysis / function discovery ---
    "aaa": (False, False, 0, "full analysis (always prepended as opener)"),
    "afl": (False, False, 0, "list discovered functions"),
    "af":  (True,  False, 0, "targeted function analysis at addr"),
    "afi": (True,  False, 0, "function info: addr/size/bbs/args"),
    # --- binary metadata ---
    "iI":  (False, False, 0, "binary info: arch, format, PIE/canary/NX"),
    "iS":  (False, False, 0, "sections"),
    "iE":  (False, False, 0, "exports"),
    "ii":  (False, False, 0, "imports"),
    "is":  (False, False, 0, "symbols"),
    "iR":  (False, False, 0, "relocations / ASLR"),
    # --- strings ---
    "iz":  (False, False, 0, "strings in data sections"),
    "izz": (False, False, 0, "strings across whole file (creds/paths/URLs)"),
    # --- disassembly / decompilation ---
    "pdf": (True,  False, 0, "disassemble function at addr (workhorse)"),
    "pdg": (True,  False, 0, "r2ghidra decompile at addr (no asm fluency needed)"),
    "pd":  (True,  True,  512, "fixed-N disassembly at addr"),
    "px":  (True,  True,  1024, "hexdump at addr"),
    # --- cross-references ---
    "axt": (True,  False, 0, "xrefs TO addr (what calls/references this)"),
    "axf": (True,  False, 0, "xrefs FROM addr (what this calls/references)"),
    # --- string-at-addr ---
    "ps":  (True,  False, 0, "print string at addr (pairs with axt-on-strings)"),
    # slot 20: reserved for a practice-found gap
}

ALLOWED_COMMANDS: Tuple[str, ...] = tuple(_COMMAND_TABLE.keys())

# Commands that require r2ghidra (checked via preflight).
_R2GHIDRA_COMMANDS: Tuple[str, ...] = ("pdg",)

# Forbidden characters — the r2 -c parser splits on ';' and newline; the rest
# are shell-significant chars we reject as defense in depth even though we
# never use shell=True.
_FORBIDDEN_CHARS: Tuple[str, ...] = (" ", "!", "`", "$", ">", "|", "&",
                                      ";", '"', "'", "\n")
_FORBIDDEN_RE: re.Pattern = re.compile(
    r"[\s!`$>|&;\"'\n]"
)

# Strict addr charset: hex integer OR flag/symbol name.
_ADDR_HEX_RE: re.Pattern = re.compile(r"^0x[0-9a-fA-F]+$")
_ADDR_FLAG_RE: re.Pattern = re.compile(r"^[A-Za-z0-9_.$\-]+$")

# Output truncation cap (bytes of decoded stdout; r2 output is ASCII, so
# chars ≈ bytes).  Default sized so one oversized result is a moderate slice
# of a 100k-token model context window (~8-11k tokens on asm/hex output)
# instead of half the window — the old 200 KiB default could cost 50k+ model
# tokens in a single call.  Tunable via env so fat-binary runs can be widened
# without a code change; R2_OUTPUT_CAP=0 disables truncation entirely.
_OUTPUT_CAP: int = int(os.getenv("R2_OUTPUT_CAP", str(32 * 1024)))


def _truncate_output(raw: str, cap: int) -> Tuple[str, int]:
    """Head+tail truncation with an explicit omission marker.

    Returns ``(output, omitted_bytes)``.  Sub-cap (or disabled, ``cap <= 0``)
    output passes through untouched.  Over cap: keep a 2/3 head and 1/3 tail
    separated by a single-line marker stating exactly what was omitted and
    how to narrow — sorted r2 listings (strings, function lists) stay
    informative at both ends, and the dropped middle is what a targeted
    ``addr``/``count`` query should pull instead.  The returned output is
    always ≤ ``cap`` chars, even for pathological caps smaller than the
    marker itself.
    """
    if cap <= 0 or len(raw) <= cap:
        return raw, 0
    omitted = len(raw) - cap
    marker = (
        f"\n[... r2 output truncated: {omitted} of {len(raw)} bytes omitted "
        f"(cap {cap} bytes, R2_OUTPUT_CAP env) — head+tail shown; narrow "
        f"with addr/count or a more targeted verb rather than raising "
        f"the cap ...]\n"
    )
    if len(marker) >= cap:
        # Pathological: cap too small to hold the marker.  Keep the output
        # bounded (≤ cap) and still say truncation happened.
        return marker[:cap], omitted
    budget = cap - len(marker)
    head = (budget * 2) // 3
    tail = budget - head
    out = raw[:head] + marker
    if tail > 0:
        out += raw[-tail:]
    return out, omitted

# r2 subprocess timeout (seconds).  aaa on a fat static binary can be slow.
_R2_TIMEOUT: float = float(os.getenv("R2_TIMEOUT", "120"))


# ---------------------------------------------------------------------------
# Binary drop folder — discovery & resolution
# ---------------------------------------------------------------------------
# A dedicated, gitignored directory for analysis targets.  The model drops
# (or finds) binaries here, lists them with ``list_r2_targets``, and calls
# ``run_r2`` with the bare name — ``run_r2`` auto-resolves via
# :func:`resolve_binary_target` when the raw path doesn't exist.
_REPO_ROOT: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BINARY_TARGETS_ROOT: str = os.getenv(
    "R2_BINARY_TARGETS_ROOT", os.path.join(_REPO_ROOT, "binaries")
)

# Magic-byte signatures for the formats r2 can meaningfully open.  The key
# is a human-readable format label; the value is (offset, magic_bytes).
_BINARY_MAGIC: List[Tuple[str, int, bytes]] = [
    ("ELF",     0, b"\x7fELF"),
    ("PE",      0, b"MZ"),
    ("Mach-O",  0, b"\xfe\xed\xfa\xce"),     # 32-bit BE
    ("Mach-O",  0, b"\xfe\xed\xfa\xcf"),     # 64-bit BE
    ("Mach-O",  0, b"\xcf\xfa\xed\xfe"),     # 64-bit LE
    ("Mach-O",  0, b"\xce\xfa\xed\xfe"),     # 32-bit LE
    ("Java",    0, b"\xca\xfe\xba\xbe"),     # .class / JAR
    ("WebAssembly", 0, b"\x00asm"),
    # COFF / object files share no single magic at offset 0, so we rely on
    # the null-byte heuristic below as a fallback for those.
]

# Directories to skip when walking the drop folder.
_SKIP_DIRS = {".git", ".github", "__pycache__", "node_modules", ".venv", "venv"}


def detect_binary_format(path: str) -> Optional[str]:
    """Sniff the first bytes of ``path`` for a known binary magic.

    Returns a format label (``"ELF"``, ``"PE"``, ``"Mach-O"`` …) or ``None``
    if the file is not a recognised binary.  A secondary heuristic — a NUL
    byte within the first 512 bytes — catches COFF/object files and other
    non-text binaries that lack a unique offset-0 magic.  This never spawns
    an external process (``file`` / ``rabin2``); it is a cheap header read.
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(512)
    except OSError:
        return None
    if not head:
        return None
    for label, offset, magic in _BINARY_MAGIC:
        if head[offset:offset + len(magic)] == magic:
            return label
    # Fallback: NUL byte in the first 512 bytes is a strong "not text"
    # signal and catches .o / .a / arbitrary object files r2 can still open.
    if b"\x00" in head:
        return "binary"
    return None


def resolve_binary_target(target: str) -> Optional[str]:
    """Resolve ``target`` to an absolute path, searching the drop folder.

    If ``target`` is already an existing path (absolute or relative to CWD),
    it is honoured as-is.  Otherwise the drop folder (:data:`BINARY_TARGETS_ROOT`)
    is searched for a matching filename — first an exact relative-path match
    (e.g. ``subdir/crackme``), then a bare-name recursive match (e.g.
    ``crackme`` finds ``binaries/crackmes/crackme``).  Returns the absolute
    path string if found, otherwise ``None``.  Never raises.
    """
    if not target:
        return None
    p = os.path.abspath(target)
    if os.path.isfile(p):
        return p
    root = BINARY_TARGETS_ROOT
    if not os.path.isdir(root):
        return None
    # Exact relative path under the drop folder.
    candidate = os.path.join(root, target)
    if os.path.isfile(candidate):
        return os.path.abspath(candidate)
    # Bare-name recursive search (last-resort, but the common case when the
    # model only knows the filename it saw in ``list_r2_targets``).
    base = os.path.basename(target)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        if base in filenames:
            return os.path.abspath(os.path.join(dirpath, base))
    return None


def discover_binary_targets(
    root: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Walk the binary drop folder and return recognised binary files.

    Yields a list of dicts sorted by path, each with:

    - ``name`` — bare filename (what the model passes to ``run_r2``).
    - ``path`` — absolute path.
    - ``rel_path`` — path relative to the drop folder root.
    - ``size`` — file size in bytes.
    - ``format`` — detected format label (``"ELF"``, ``"PE"`` …) or
      ``"binary"`` for the NUL-byte heuristic.

    Files that don't match any binary magic (text, images, archives without
    a recognised header) are skipped so the listing stays clean.
    """
    base = root or BINARY_TARGETS_ROOT
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
            fmt = detect_binary_format(fpath)
            if fmt is None:
                continue
            try:
                size = os.path.getsize(fpath)
            except OSError:
                continue
            rel = os.path.relpath(fpath, base)
            results.append({
                "name": fname,
                "path": os.path.abspath(fpath),
                "rel_path": rel,
                "size": size,
                "format": fmt,
            })
    results.sort(key=lambda r: r["rel_path"])
    return results


# ---------------------------------------------------------------------------
# r2ghidra preflight — cached once per process
# ---------------------------------------------------------------------------
_r2ghidra_status: Optional[bool] = None  # None=unchecked, True/False=cached


def _r2ghidra_available() -> bool:
    """Return True if the r2ghidra decompiler plugin is loadable.

    Probed once per process and cached in ``_r2ghidra_status``.  We detect
    by running ``pdg`` on a zero-byte throwaway file and checking for r2's
    own "install the plugin" sentinel — this is version-agnostic and does
    not depend on r2pm internals.  A zero-byte file is enough: r2 loads the
    plugin at startup regardless of file content, and the sentinel appears
    in stdout when the plugin is absent.
    """
    global _r2ghidra_status
    if _r2ghidra_status is not None:
        return _r2ghidra_status

    r2_bin = shutil.which("r2")
    if r2_bin is None:
        # No r2 at all — pdg is certainly unavailable.
        _r2ghidra_status = False
        return False

    fd, tmp = tempfile.mkstemp(suffix=".bin")
    os.close(fd)  # empty file — just a probe vehicle
    try:
        proc = subprocess.run(
            [r2_bin, "-q", "-e", "scr.color=0", "-e", "scr.utf8=0",
             "-c", "pdg @ 0", tmp],
            capture_output=True, text=True, timeout=15,
        )
    except Exception:
        _r2ghidra_status = False
        return False
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass

    combined = (proc.stdout or "") + (proc.stderr or "")
    # r2 emits exactly this when the plugin is missing.
    _r2ghidra_status = "install the plugin" not in combined.lower()
    return _r2ghidra_status


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------
def _check_forbidden(value: str, field: str) -> Optional[str]:
    """Return an error message if ``value`` contains a forbidden char, else None."""
    if value is None:
        return None
    for ch in _FORBIDDEN_CHARS:
        if ch in value:
            return (
                f"forbidden character {ch!r} in {field!r} — "
                f"r2 -c splits on ';' and newline; other chars are "
                f"shell-significant. Input rejected."
            )
    return None


def _validate_addr(addr: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """Validate ``addr`` against the strict charset.

    Returns ``(normalized_addr, error_msg)``.  On success ``error_msg`` is
    None.  A None addr is only valid for commands that don't take one
    (caller checks that separately).
    """
    if addr is None or addr == "":
        return (addr, None)

    # Layer 2: forbidden-char scan.
    err = _check_forbidden(addr, "addr")
    if err:
        return (None, err)

    # Layer 3: strict charset — hex int or flag/symbol name.
    # If it starts with 0x it MUST be valid hex (don't fall through to the
    # flag charset, otherwise "0xGGG" sneaks through as a "name").  A bare
    # all-digit string is rejected (ambiguous — require the 0x prefix for
    # numeric addresses; real flag names like "entry0", "sym.main",
    # "fcn.00401000" always contain a non-digit character).
    if addr.lower().startswith("0x"):
        if _ADDR_HEX_RE.match(addr):
            return (addr, None)
        return (
            None,
            f"addr {addr!r} starts with 0x but is not valid hex "
            f"(0x[0-9a-fA-F]+); rejected",
        )
    if _ADDR_FLAG_RE.match(addr) and not addr.isdigit():
        return (addr, None)

    return (
        None,
        f"addr {addr!r} must be a hex integer (0x[0-9a-fA-F]+) or a "
        f"flag/symbol name ([A-Za-z0-9_.$-]+, must contain a non-digit); "
        f"rejected",
    )


def _validate_count(count: Any, cap: int) -> Tuple[Optional[int], Optional[str]]:
    """Coerce ``count`` to int and clamp to ``cap``.  Returns (value, error)."""
    if count is None:
        return (None, None)
    try:
        n = int(count)
    except (TypeError, ValueError):
        return (None, f"count must be an integer, got {count!r}")
    if n < 1:
        return (None, f"count must be >= 1, got {n}")
    if n > cap:
        n = cap  # clamp, don't reject — the model shouldn't fail over a cap
    return (n, None)


# ---------------------------------------------------------------------------
# Command composition
# ---------------------------------------------------------------------------
def _compose_cmd(command: str, addr: Optional[str], count: Optional[int]) -> str:
    """Build the r2 ``-c`` string from validated pieces.

    The tool owns the ``;`` (chaining ``aaa``) and the ``@`` (seek).  User
    input never contributes either character.  Shape::

        aaa; <verb> [<count>] [@ <addr>]
    """
    needs_addr, needs_count, _, _ = _COMMAND_TABLE[command]
    # Build the user-command segment, then append the seek modifier to THAT
    # segment — "@ addr" is a modifier on the command, not a separate r2
    # command, so it must NOT be joined with "; " (which would yield
    # "aaa; pdf; @ main" and make r2 run a bare "pdf" with no seek).
    cmd_str = command
    if needs_count and count is not None:
        cmd_str = f"{command} {count}"
    if needs_addr and addr:
        cmd_str = f"{cmd_str} @ {addr}"
    return f"aaa; {cmd_str}"


# ---------------------------------------------------------------------------
# Context-aware next-hints — guide the model's next step
# ---------------------------------------------------------------------------
def _hints_for(command: str, output: str) -> List[str]:
    """Return curated next-action hints based on what was just run."""
    hints: List[str] = []
    if command == "afl":
        hints.append("pdf @ <addr> to disassemble a listed function")
        hints.append("pdg @ <addr> to decompile it (if r2ghidra installed)")
        hints.append("axt @ <addr> to see what calls it")
    elif command == "iI":
        hints.append("iS for sections, ii for imports, is for symbols")
        hints.append("izz to hunt strings (creds/paths/URLs) across the file")
    elif command in ("izz", "iz"):
        hints.append("ps @ <addr> to read a specific string fully")
        hints.append("axt @ <addr> to find what references a string")
    elif command == "pdf":
        hints.append("pdg @ <same addr> for decompiled C pseudocode")
        hints.append("axt @ <addr> to find callers of this function")
    elif command == "pdg":
        hints.append("pdf @ <same addr> for raw disassembly")
        hints.append("pdf @ <addr> to see what this function calls (read the call instructions)")
    elif command == "axt":
        hints.append("pdf @ <caller addr> to inspect the calling function")
    elif command == "axf":
        # axf is broken on function-flag targets in r2 >=6.x (returns empty
        # even when calls exist); it still works on instruction addresses.
        hints.append("pdf @ <callee addr> to inspect the called function")
        hints.append("note: axf may return empty on function flags - use pdf to read calls")
    elif command == "afi":
        hints.append("pdf @ <addr> to disassemble this function")
        hints.append("pdg @ <addr> to decompile it")
    elif command == "af":
        hints.append("pdf @ <addr> to disassemble the now-analyzed function")
    elif command in ("iE", "is"):
        hints.append("axt @ <symbol addr> to find cross-references to it")
        hints.append("pdf @ <addr> to disassemble a function symbol")
    elif command == "iS":
        hints.append("izz to enumerate strings")
        hints.append("px <len> @ <section addr> to hexdump a section")
    elif command == "ii":
        hints.append("axt @ <import plt addr> to find callers of an import")
    elif command == "ps":
        hints.append("axt @ <addr> to find what references this string")
    hints.append("report_finding to record a discovered artifact")
    return hints


# ---------------------------------------------------------------------------
# The tool
# ---------------------------------------------------------------------------

def _run_r2_digest(result: Dict[str, Any]) -> Dict[str, Any]:
    """Digest adapter for ``run_r2`` — command + summary + line count + delta.

    The full r2 output (disassembly blobs, string dumps, function lists) is
    stored in scratch; the model gets:
    - status (ok/error) + the r2 command that ran
    - the one-line summary (already curated by _summarize)
    - the delta note (what this run surfaced)
    - line count + truncated flag (so the model knows if there's more)
    - target name + r2ghidra availability

    The model rarely needs the raw disassembly to decide the next action —
    the summary + delta + hints are the actionable signal.  When it needs
    the full output (e.g. reading a specific function's decompiled C), it
    retrieves from scratch.
    """
    parts: list = []

    status = result.get("status", "unknown")
    parts.append(f"status={status}")

    command = result.get("command", "")
    if command:
        parts.append(f"cmd={command}")

    summary = result.get("summary", "")
    if summary:
        parts.append(f"summary={summary[:300]}")

    delta = result.get("delta", "")
    if delta:
        parts.append(f"delta={delta[:200]}")

    # Line count from the output (how much was produced).
    output = result.get("output", "")
    if isinstance(output, str) and output:
        line_count = len([ln for ln in output.splitlines() if ln.strip()])
        parts.append(f"lines={line_count}")

    truncated = result.get("truncated", False)
    if truncated:
        omitted = result.get("omitted_bytes", 0)
        parts.append(f"truncated=({omitted} bytes omitted)")

    target = result.get("target", "")
    if target:
        parts.append(f"target={os.path.basename(target)}")

    r2ghidra = result.get("r2ghidra")
    if r2ghidra is not None:
        parts.append(f"r2ghidra={'yes' if r2ghidra else 'no'}")

    # Include next_hints — they guide the model's next r2 command.
    hints = result.get("next_hints", [])
    if hints:
        parts.append(f"hints: {'; '.join(hints[:3])}")

    summary_text = " | ".join(parts)

    row_hint = (
        "scratch_search scratch:<id> --filter 'sym.' "
        "# pull specific symbol/function lines from the full output"
    )

    return {"summary": summary_text, "row_hint_format": row_hint}


@framework_tool(
    "Static binary analysis with radare2: disassemble, decompile (r2ghidra), "
    "enumerate symbols/imports/exports/sections/strings, and query cross-"
    "references against an ELF/PE/Mach-O binary. One composite tool — pass a "
    "command verb from the allowlist (aaa, afl, afi, af, iI, iS, iE, ii, is, "
    "iR, iz, izz, pdf, pdg, pd, px, axt, axf, ps) plus an optional addr "
    "(hex int like 0x401000 or flag name like sym.main) and optional count "
    "(for pd/px). Runs read-only against a temp copy of the binary; analysis "
    "(aaa) is always prepended. Oversized output is head+tail-truncated to "
    "a 32 KiB default cap (R2_OUTPUT_CAP env) with an omission marker and "
    "stated policy — narrow with addr/count or a targeted verb instead of "
    "raising the cap.",
    next_hints=["report_finding"],
    result_digest=lambda r: _run_r2_digest(r),
    untrusted_target=True,
)
def run_r2(
    target: str,
    command: str,
    addr: Optional[str] = None,
    count: Optional[int] = None,
    cache: bool = True,
    refresh: bool = False,
) -> Dict[str, Any]:
    """Run a single radare2 command against a binary and return a structured envelope.

    Always opens with ``aaa`` (full analysis) so symbol-dependent commands
    work statelessly.  r2 runs against a per-run temp copy of ``target``
    (read-only — never ``-w``), which is cleaned up after.  The composed
    ``-c`` string is built by this function from validated pieces; the caller
    never supplies ``;`` or ``@``.

    Snapshot cache (default on): r2 analysis is deterministic — same target
    bytes + same verb/addr/count/setting yields the same output.  Successful
    runs are keyed on the target's sha256 and reused verbatim on repeat
    calls, so exploring a binary (afl, then pdf/pdg per function of
    interest) pays ``aaa`` once instead of once per call.  Errors are never
    cached.  Pass ``cache=False`` to skip reads AND writes, or ``refresh=True``
    to bypass the read and overwrite the stored entry.  Scanners (nmap,
    ffuf, masscan) deliberately don't share this cache — live-target results
    are observations of a changing world, not pure functions of bytes.

    Args:
        target: Path to the binary to analyze.  Must exist and be readable.
        command: One r2 verb from the frozen allowlist (exact match only).
        addr: Optional target address — hex integer (``0x401000``) or
            flag/symbol name (``sym.main``, ``entry0``).  Required for
            commands marked as needing an addr in the table (pdf, pdg, pd,
            px, afi, af, axt, axf, ps); ignored for metadata commands.
        count: Optional integer for ``pd`` (instruction count, capped at
            512) and ``px`` (byte count, capped at 1024).  Ignored by other
            commands.
        cache: Use the snapshot cache (read on repeat, write on success).
            False skips both — a fresh r2 run, nothing stored.
        refresh: Force a real r2 run even if a snapshot exists, and
            overwrite the stored entry.  cache=False + refresh=True is
            contradictory; refresh wins and still writes (treat refresh as
            "recompute and re-store").

    Returns:
        A dict envelope with::

            status        — "ok" | "error"
            command       — the composed r2 -c string that ran
            summary       — one-line human-readable result
            output        — r2 stdout (head+tail-truncated if over R2_OUTPUT_CAP)
            omitted_bytes — bytes omitted by truncation (0 when not truncated)
            stderr        — r2 stderr (captured separately, always present)
            exit_code     — r2 process exit code (int; -1 on launch failure)
            truncated     — bool
            truncation_policy — stated policy string if truncated, else None
            target        — the original target path
            r2ghidra      — bool, whether the decompiler plugin is available
            next_hints    — curated next-action suggestions
            delta         — short note on what this run surfaced
            error         — present only on status="error"
    """
    # --- Layer 1: exact allowlist match on command ---
    if command is None or command not in _COMMAND_TABLE:
        return _err_envelope(
            target, command,
            f"command {command!r} is not in the allowlist "
            f"({', '.join(ALLOWED_COMMANDS)}); rejected",
        )

    # --- Layer 2: forbidden-char scan on command (belt + braces) ---
    err = _check_forbidden(command, "command")
    if err:
        return _err_envelope(target, command, err)

    needs_addr, needs_count, count_cap, _ = _COMMAND_TABLE[command]

    # --- Layer 2: forbidden-char scan on addr ---
    addr, err = _validate_addr(addr)
    if err:
        return _err_envelope(target, command, err)

    # addr required but not supplied?
    if needs_addr and not addr:
        return _err_envelope(
            target, command,
            f"command {command!r} requires an addr (hex int like 0x401000 "
            f"or flag name like sym.main); none supplied",
        )

    # --- Layer 4: integer caps on count ---
    count_val, err = _validate_count(count, count_cap)
    if err:
        return _err_envelope(target, command, err)
    if needs_count and count_val is None:
        count_val = 16 if command == "pd" else 64  # sensible defaults

    # --- r2ghidra preflight for pdg ---
    ghidra_ok = _r2ghidra_available()
    if command in _R2GHIDRA_COMMANDS and not ghidra_ok:
        return _err_envelope(
            target, command,
            "r2ghidra not installed — run: r2pm -ci r2ghidra  "
            "(pdg requires the r2ghidra decompiler plugin; all other "
            "commands work without it)",
            r2ghidra=False,
        )

    # --- target resolution: existing path, or auto-resolve from drop folder ---
    # Input validation before environment probing: a bad target must report
    # the target problem (with the list_r2_targets hint) even on boxes
    # without r2, instead of being masked by the binary-absent error.
    resolved = resolve_binary_target(target) if target else None
    if resolved is None:
        return _err_envelope(
            target, command,
            f"target {target!r} not found — no such file, and no match in "
            f"the binary drop folder ({BINARY_TARGETS_ROOT}). Call "
            f"list_r2_targets to see what is available.",
        )
    r2_bin = shutil.which("r2")
    if r2_bin is None:
        return _err_envelope(target, command, "radare2 (r2) not found on PATH")
    # Work against the resolved absolute path from here on.
    target = resolved

    # --- snapshot cache lookup (deterministic-lane memoization) ----------
    # Keyed on the file's CONTENT (sha256) so a modified binary re-analyzes
    # automatically; the op key covers verb/addr/count + every setting that
    # changes the output (r2ghidra availability, output cap, timeout).  The
    # key is computed BEFORE reading so the store step below can reuse it
    # even when lookup was skipped (cache=False, hashing failure, DB error).
    # Any failure in the cache layer degrades silently to a normal run.
    snapshot_hit: Optional[Dict[str, Any]] = None
    content_key = sha256_of_file(target)
    op_key: str = ""
    key: str = ""
    if content_key is not None:
        try:
            op_key = json.dumps({
                "verb": command,
                "addr": addr or "",
                "count": count_val,
                "r2ghidra": ghidra_ok,
                "output_cap": _OUTPUT_CAP,
                "timeout": _R2_TIMEOUT,
            }, sort_keys=True)
            key = build_cache_key(content_key, op_key)
            if (cache or refresh) and not refresh:
                _snap = get_snapshot_store()
                _snap.purge_expired()
                snapshot_hit = _snap.lookup(key)
            if snapshot_hit is not None:
                # Contextual fields must describe THIS call, not the run that
                # populated the cache: identical bytes may live at a different
                # path (rebuilt binary, moved drop folder), and the model asked
                # about the current path.
                snapshot_hit["target"] = target
                snapshot_hit["_snapshot"] = {
                    "hit": True,
                    "key": key,
                    "content_key": content_key,
                    "note": (
                        "Reused a cached analysis result (same target bytes "
                        "+ same operation). Pass refresh=true to recompute."
                    ),
                }
                return snapshot_hit
        except Exception as exc:  # noqa: BLE001 — caching must never fail the run
            logger.debug("[r2] snapshot lookup skipped: %s", exc)

    # --- compose the -c string from validated pieces ---
    composed = _compose_cmd(command, addr, count_val)

    # --- per-run temp copy (read-only by construction: never -w) ---
    tmp_fd, tmp_path = tempfile.mkstemp(
        prefix="r2work_", suffix=os.path.splitext(target)[1] or ".bin"
    )
    try:
        os.close(tmp_fd)
        shutil.copy2(target, tmp_path)
        # Read-only on the copy too — belt and braces.
        os.chmod(tmp_path, 0o444)

        argv = [
            r2_bin, "-q",
            "-e", "scr.color=0",
            "-e", "scr.utf8=0",
            "-c", composed,
            tmp_path,
        ]

        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=_R2_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            return _err_envelope(
                target, command,
                f"r2 timed out after {_R2_TIMEOUT}s — try a more targeted "
                f"command or a smaller count; aaa on very large binaries can "
                f"be slow (raise R2_TIMEOUT env to widen)",
            )
        except Exception as exc:
            return _err_envelope(
                target, command, f"r2 launch failed: {exc}",
            )

    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    # --- truncation with stated policy (head+tail, omission-accounted) ---
    raw_out = proc.stdout or ""
    output, omitted = _truncate_output(raw_out, _OUTPUT_CAP)
    truncated = omitted > 0
    truncation_policy = (
        f"head+tail truncation: {omitted} of {len(raw_out)} bytes omitted "
        f"(cap {_OUTPUT_CAP} bytes via R2_OUTPUT_CAP env); narrow with "
        f"addr/count or a more targeted verb; raise R2_OUTPUT_CAP to widen"
        if truncated else None
    )

    # Strip r2's INFO/WARN noise from the summary view but keep it in output.
    clean_lines = [
        ln for ln in raw_out.splitlines()
        if not ln.startswith(("INFO:", "WARN:", " "))
        and ln.strip()
    ]

    summary = _summarize(command, clean_lines, addr)
    delta = _delta_note(command, clean_lines, addr)

    envelope = {
        "status": "ok" if proc.returncode == 0 else "error",
        "command": composed,
        "summary": summary,
        "output": output,
        "stderr": (proc.stderr or "").strip(),
        "exit_code": proc.returncode,
        "truncated": truncated,
        "truncation_policy": truncation_policy,
        "omitted_bytes": omitted,
        "target": target,
        "r2ghidra": ghidra_ok,
        "next_hints": _hints_for(command, output),
        "delta": delta,
    }

    # --- snapshot store (successful runs only) ---------------------------
    # Written AFTER the envelope is fully built so what's cached is exactly
    # what the model would have received.  Non-zero exit or an omitted-bytes
    # bug aside, this is the only path that stores.  Store failures log and
    # degrade — the run result is unaffected.
    if envelope["status"] == "ok" and content_key is not None and (cache or refresh):
        try:
            _snap2 = get_snapshot_store()
            _snap2.put(
                cache_key=key,
                content_key=content_key,
                op_key=op_key,
                target_sig=sha256_of_file(target),
                result=envelope,
            )
            envelope["_snapshot"] = {
                "hit": False,
                "key": key,
                "content_key": content_key,
                "note": (
                    "Stored for reuse — repeat calls with the same bytes + "
                    "verb/addr/count return this result without re-paying "
                    "aaa."
                ),
            }
        except Exception as exc:  # noqa: BLE001 — caching must never fail the run
            logger.debug("[r2] snapshot store skipped: %s", exc)

    return envelope


# ---------------------------------------------------------------------------
# Envelope helpers
# ---------------------------------------------------------------------------
def _err_envelope(
    target: str,
    command: Optional[str],
    error: str,
    r2ghidra: Optional[bool] = None,
) -> Dict[str, Any]:
    """Build a consistent error envelope."""
    ghidra = _r2ghidra_available() if r2ghidra is None else r2ghidra
    return {
        "status": "error",
        "command": command,
        "summary": error,
        "output": "",
        "stderr": "",
        "exit_code": -1,
        "truncated": False,
        "truncation_policy": None,
        "omitted_bytes": 0,
        "target": target,
        "r2ghidra": ghidra,
        "next_hints": [],
        "delta": "",
        "error": error,
    }


def _summarize(command: str, clean_lines: List[str], addr: Optional[str]) -> str:
    """One-line human summary of the r2 output."""
    n = len(clean_lines)
    if n == 0:
        loc = f" @ {addr}" if addr else ""
        return f"{command}{loc}: no output (empty result)"
    first = clean_lines[0].strip()
    if n <= 3:
        loc = f" @ {addr}" if addr else ""
        return f"{command}{loc}: {n} line(s) — {first}"
    loc = f" @ {addr}" if addr else ""
    return f"{command}{loc}: {n} lines — first: {first[:120]}"


_TABLE_COMMANDS: frozenset = frozenset({"iz", "izz", "iE", "ii", "is", "iS"})


def _delta_note(command: str, clean_lines: List[str], addr: Optional[str]) -> str:
    """Short note on what this run surfaced (for the model's working memory).

    Table-format commands (iz, izz, iE, ii, is, iS) emit a header row and a
    separator row before the data rows.  We subtract 2 so the reported count
    reflects actual entities, not raw line count.
    """
    # For table commands, drop the header + separator to count real rows.
    entity_count = (
        max(0, len(clean_lines) - 2) if command in _TABLE_COMMANDS
        else len(clean_lines)
    )
    if command == "afl":
        return f"discovered {entity_count} function(s)"
    if command in ("izz", "iz"):
        return f"found {entity_count} string(s)"
    if command == "iI":
        # grab the arch line if present
        for ln in clean_lines:
            if ln.startswith("arch"):
                return f"binary arch: {ln}"
        return "binary metadata returned"
    if command == "iE":
        return f"{entity_count} export(s) listed"
    if command == "ii":
        return f"{entity_count} import(s) listed"
    if command == "is":
        return f"{entity_count} symbol(s) listed"
    if command == "iS":
        return f"{entity_count} section(s) listed"
    if command == "axt":
        return f"{len(clean_lines)} xref(s) TO {addr}"
    if command == "axf":
        return f"{len(clean_lines)} xref(s) FROM {addr}"
    if command == "pdf":
        return f"disassembled function @ {addr} ({len(clean_lines)} lines)"
    if command == "pdg":
        return f"decompiled function @ {addr} ({len(clean_lines)} lines)"
    if command == "afi":
        return f"function info @ {addr}"
    loc = f" @ {addr}" if addr else ""
    return f"{command}{loc}: {len(clean_lines)} line(s) of output"


# ---------------------------------------------------------------------------
# list_r2_targets — discover binaries in the drop folder
# ---------------------------------------------------------------------------
@framework_tool(
    "List binaries available for static analysis in the framework's binary "
    "drop folder (binaries/). Returns each file's name, detected format "
    "(ELF, PE, Mach-O, etc.), size, and relative path. Use this to discover "
    "what targets are available before calling run_r2 with a bare name — "
    "run_r2 auto-resolves names from this folder, so you only need the "
    "filename, not the full path. Drop new binaries into binaries/ (it is "
    "gitignored) and re-call this to see them.",
    next_hints=["run_r2"],
    untrusted_target=True,
)
def list_r2_targets() -> Dict[str, Any]:
    """Enumerate recognised binary files in the drop folder.

    Walks :data:`BINARY_TARGETS_ROOT` (default ``binaries/`` at the repo
    root; override via ``R2_BINARY_TARGETS_ROOT`` env) recursively, filtering
    to files with a recognised binary magic header (ELF, PE, Mach-O, Java,
    WebAssembly, or a NUL-byte heuristic for object files).  Text files and
    junk are excluded so the listing stays clean.

    Returns:
        A dict with::

            status     — "ok" | "error"
            root       — the drop folder path that was walked
            count      — number of binaries found
            targets    — list of {name, path, rel_path, size, format}
            next_hints — curated next-action suggestions
    """
    root = BINARY_TARGETS_ROOT
    if not os.path.isdir(root):
        return {
            "status": "error",
            "root": root,
            "count": 0,
            "targets": [],
            "next_hints": [],
            "error": (
                f"binary drop folder {root!r} does not exist. Create it and "
                f"drop target binaries there (it is gitignored)."
            ),
        }
    targets = discover_binary_targets(root)
    return {
        "status": "ok",
        "root": root,
        "count": len(targets),
        "targets": targets,
        "next_hints": [
            "run_r2 with a target name from the list (e.g. run_r2('crackme', 'iI'))",
            "run_r2('<name>', 'aaa') then 'afl' to discover functions",
            "run_r2('<name>', 'izz') to hunt for embedded strings",
        ],
    }
