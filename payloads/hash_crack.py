"""Password cracking via john the Ripper + hashcat (background-job pattern).

Bridges the gap ``crypto_kit`` leaves open: unsalted wordlist checks are
pure Python, but salted/slow formats (md5crypt ``$1$``, sha512crypt
``$6$``, bcrypt ``$2*$``, ...) and rule/mask-scale attacks belong to john
and hashcat.  This module follows the proven ``run_*`` / ``*_status``
launch/poll shape (nmap/ffuf/hydra/sqlmap) so a long crack never holds a
secretary turn open:

- :func:`run_john` / :func:`john_status` — john the Ripper,
- :func:`run_hashcat` / :func:`hashcat_status` — hashcat (OpenCL backends),
- :func:`john_show` / :func:`hashcat_show` — blocking quick reads of the
  respective potfile (``john --show`` / ``hashcat --show``) after any run,
- :func:`suggest_crack_mode` — maps a hash shape (same heuristics as
  ``crypto_kit.identify_hash``) to hashcat ``-m`` codes and john formats.
- :func:`cracker_backends` — what's actually crackable on THIS box right
  now (OpenCL devices vs CPU john), probed live.

BOX REALITY (re-verified live on-boot 2026-11-24; dated corrections
supersede older notes — don't trust a docstring older than the box):
binaries ARE installed via Debian apt. **john the Ripper is the primary
cracker on this box for throughput**: JUMBO build (``1.9.0-jumbo-1``),
full jumbo format list, CPU (4× aarch64, OMP + ASIMD). **hashcat
(v7.1.2) has a usable CPU backend since the PoCL install**:
``pocl-opencl-icd`` is in and ``hashcat -I`` enumerates the PoCL CPU
device, so ``run_hashcat`` works — reach for it when a job needs what
john's jumbo CLI lacks (mask/rule-scale ``-a 3``/``-a 1`` syntax, tuned
``-m`` routing, hashcat-format sample files); on this Pi-class CPU it is
not faster than john for most formats, so john stays the default. No
dedicated GPU (the previous box's RTX 3050 is gone; pre-2026-11 notes
calling hashcat the primary cracker are stale — and pre-2026-11-24
"hashcat has no backend" notes are stale too: they predate the PoCL
install, and the probe parser silently mis-read v7's one-line
machine-readable JSON until fixed 2026-11-24). Run ``cracker_backends()``
first when unsure; it resolves and dates all of this live.

Format routing (live-verified 2026-11-21): the installed john is the
**jumbo build** — the old CORE-only claims are retired. Raw MD5 / NT /
SHA* formats ARE available to john here, so plain wordlist checks can go
to ``run_john`` directly (``--format=raw-md5`` etc.). ``run_hashcat`` is
kept for format parity (hash-mode routing, masks/rules via ``-a``) and
becomes viable again the moment a backend appears —
``cracker_backends()`` says which.

BINARY PREFLIGHT (explicit, never worked around): both binaries are on
this box (apt; see BOX REALITY above). ``_preflight`` still checks
``$JOHN_BIN`` / ``$HASHCAT_BIN`` first, then PATH, then the usual install
paths. A miss -> a ``Failed`` envelope with the exact install hint (and
no reindex/restart is needed if a binary moves: preflight runs at every
launch). Operator override hooks: ``JOHN_BIN=`` / ``HASHCAT_BIN=`` in the
root-0600 ``.env`` via sudo — ``loaddotenv`` picks them up at the next
stack boot.

TMP HASHFILE LIFECYCLE (fixed 2026-09-26, see ledger): background runs
spawn the cracker via ``launch_job`` (fire-and-forget) and then a daemon
watcher thread unlinks the per-job hashfile AFTER the process exits. An
earlier cleanup (operator commit a1fae22) unlinked in a ``finally``
immediately after ``launch_job`` returned — i.e. before the cracker had
opened the file. hashcat (6.2.6) treats a hashfile path that no longer
exists as a single literal hash (``hashes_init_filename`` -> HL_MODE_ARG
when ``hc_path_exist()`` is false) and parses the PATH STRING as a hash:
for any ``hash:salt``-layout mode that is ``Hash
'/tmp/hashes_*.txt': Separator unmatched`` + ``No hashes loaded.``
(bare-hash modes report line-length/signature variants — same root
cause).

Scope-gate: NONE, deliberately — cracking is offline compute on recovered
material.  Nothing here contacts a target or leaves the box (same class
as ``crypto_kit``); engagement data cannot egress through these tools.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import threading
from typing import Any

from constants import framework_tool
from utils.background_job import get_job, launch_job, poll_job, register_verdict_parser

_JOHN_CANDIDATES = ("/usr/sbin/john", "/usr/bin/john", "/usr/local/bin/john")
_HASHCAT_CANDIDATES = (
    "/usr/bin/hashcat",
    "/usr/local/bin/hashcat",
    "/opt/hashcat/hashcat",
)
_ROCKYOU_REL = "SecLists/Passwords/Leaked-Databases/rockyou.txt"
_JOHN_TIMEOUT = float(os.getenv("JOHN_TIMEOUT", "3600"))
_HASHCAT_TIMEOUT = float(os.getenv("HASHCAT_TIMEOUT", "3600"))

# Re-verified live on-boot 2026-11-24 (aarch64 Pi-5-class box): john is
# JUMBO here (full format list, CPU/OMP) — the "core-only" claim from the
# previous box retired. hashcat v7.1.2 enumerates the PoCL CPU backend
# (pocl-opencl-icd installed) — Pi-class CPU throughput still favors john,
# but run_hashcat works and covers mask/rule-scale syntax john's CLI lacks.
# Steering note surfaced by suggest_crack_mode and refreshed by
# cracker_backends().
_BOX_NOTE = (
    "box note (re-verified live 2026-11-24): john here is the JUMBO build "
    "(raw-md5/nt/sha* available, CPU+OMP on 4x aarch64) — the primary "
    "cracker on this box for throughput. hashcat v7.1.2 ALSO has a usable "
    "backend now (pocl-opencl-icd installed, PoCL CPU OpenCL device "
    "enumerated) — run_hashcat works; reach for it when a job needs mask/"
    "rule-scale -a 3/-a 1 syntax or tuned -m routing, but on this Pi-class "
    "CPU it is generally not faster than john. cracker_backends() "
    "re-checks this live."
)


def _preflight(env_var: str, name: str, candidates: tuple[str, ...]) -> str | None:
    """Resolve a cracker binary; None = not installed (caller reports)."""
    override = os.getenv(env_var, "").strip()
    if override and shutil.which(override):
        return override
    found = shutil.which(name)
    if found:
        return found
    for cand in candidates:
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def _write_hashfile(hash_input: str) -> str:
    """One hash per line; accepts newline, comma, or semicolon separation.

    The tempfile is 0600 in /tmp and is dropped only AFTER the cracker
    process exits (see _launch_hash_crack's watcher thread) — cracked
    material should not linger world-writable-adjacent, but deleting it
    earlier raced the cracker's own file open (hashcat/john spend tens
    to hundreds of ms in binary/library startup before reading the
    file).  The blocking *_show paths (synchronous subprocess.run) drop
    it in ``finally`` — the file is fully consumed there."""
    lines = [
        part.strip()
        for part in re.split(r"[\n;,]+", (hash_input or "").strip())
        if part.strip()
    ]
    if not lines:
        raise ValueError("no hashes parsed from input")
    fd, path = tempfile.mkstemp(prefix="hashes_", suffix=".txt", dir="/tmp")
    with os.fdopen(fd, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    return path


def _drop_hashfile(path: str | None) -> None:
    """Remove a tempfile written by _write_hashfile; ignore failures."""
    if not path:
        return
    try:
        os.unlink(path)
    except OSError:
        pass


def _cleanup_after_exit(proc: subprocess.Popen, path: str) -> None:
    """Watcher-thread body: drop the hashfile once the cracker process
    exited.  The cracker has by then fully read the file (or failed on
    its own); nothing races the child's file open."""
    try:
        proc.wait()
    except Exception:  # noqa: BLE001 - a cleanup watcher must never raise 
        print("Error occurred while waiting for the cracker process to exit.")
        print(f"Process: {proc}")
        print(f"Hashfile: {path}")
    _drop_hashfile(path)


def _launch_hash_crack(
    command: list[str],
    hashfile: str,
    *,
    tool_name: str,
    timeout: float,
    verdict_parser,
) -> dict[str, Any]:
    """``launch_job`` wrapper that owns the tmp-hashfile lifecycle.

    launch_job returns the instant the child is SPAWNED — the child has
    not opened the hashfile yet.  Unlinking right after launch (the
    pre-2026-09-26 bug, operator commit a1fae22) deleted the file out
    from under hashcat/john; hashcat then fell back to parsing the path
    string itself as a literal hash -> ``Separator unmatched`` / ``No
    hashes loaded.``.  So the file is dropped by a watcher thread after
    the process exits.  The blocking ``*_show`` paths (synchronous
    ``subprocess.run``) keep their ``finally`` drop — the file is fully
    consumed there.

    Residual: if the harness dies before the cracker exits, the daemon
    watcher dies with it and the 0600 tempfile lingers in /tmp
    (``hashes_*.txt``).  Never re-create the eager unlink to clean those
    up — that re-opens the race; a stale-file sweep is an operator call.
    """
    try:
        result = launch_job(
            command,
            tool_name=tool_name,
            timeout=timeout,
            verdict_parser=verdict_parser,
        )
    except BaseException:
        # Popen itself failed — the child never ran, so the file was never
        # handed off; safe to drop before propagating.
        _drop_hashfile(hashfile)
        raise
    entry = get_job(result["job_id"])
    proc = entry.get("proc") if entry else None
    if proc is not None:
        threading.Thread(
            target=_cleanup_after_exit,
            args=(proc, hashfile),
            name=f"drop-{tool_name}-hashfile-{result['job_id']}",
            daemon=True,
        ).start()
    else:
        result["note"] = (
            f"{result.get('note') or ''} hashfile cleanup deferred: job "
            f"entry not found — 0600 tempfile left at {hashfile} "
            "(safe to rm once the job is gone)"
        ).strip()
    return result


# hashcat positional order is strict: [options] HASHFILE [dict|mask].
# Options passed through ``options`` may carry their own positionals (the
# mask after ``-a 3``, dicts after ``-a 1/6/7``); those must be re-located
# AFTER the hashfile, or hashcat treats the mask/dict token as the hash
# itself (HL_MODE_ARG again) and the real hashfile as the mask/dict —
# ``Hash '?u?l...': ...``-class failures, zero hashes loaded.
_OPT_VALUE_CONSUMERS = frozenset({
    "-a", "--attack-mode", "-m", "--hash-type",
    "-r", "--rules-file", "-j", "--rules-left", "-k", "--rules-right",
    "-o", "--outfile", "--outfile-format", "-w", "--workload-profile",
    "-n", "--kernel-accel", "-u", "--kernel-loops", "-d",
    "--opencl-devices", "--increment-min", "--increment-max",
    "--potfile-path", "--session", "--separator", "--runtime",
    "--debug-mode", "--remove-timer",
})


def _split_hashcat_positionals(extra: list[str]) -> tuple[list[str], list[str]]:
    """Split ``extra`` into (options, positionals) for hashcat argv order.

    Conservative: a token is a positional (mask/dict) when it does not
    start with ``-`` and is not the value of a known value-taking option.
    Inline ``--opt=value`` forms and bare flags are always options.
    """
    opts: list[str] = []
    positionals: list[str] = []
    expect_value = False
    for tok in extra:
        if expect_value:
            opts.append(tok)
            expect_value = False
            continue
        if tok.startswith("-"):
            opts.append(tok)
            if tok in _OPT_VALUE_CONSUMERS:
                expect_value = True
        else:
            positionals.append(tok)
    return opts, positionals


def _default_wordlist() -> str | None:
    try:
        from utils.wordlists import resolve_wordlist

        return resolve_wordlist(_ROCKYOU_REL)
    except Exception:  # noqa: BLE001 - wordlist tree is box-variable
        return None


# --------------------------------------------------------------------------- #
# Mode suggestion (shared with crypto_kit.identify_hash heuristics)
# --------------------------------------------------------------------------- #

def _suggest_for(hash_string: str) -> tuple[list[str], list[str], str]:
    s = (hash_string or "").strip()
    if s.startswith(("$2a$", "$2b$", "$2y$")):
        return (
            ["3200 (bcrypt)"],
            ["bcrypt"],
            "bcrypt is slow by design; wordlist-only first",
        )
    if s.startswith("$6$"):
        return (["1800 (sha512crypt)"], ["sha512crypt"], "")
    if s.startswith("$5$"):
        return (["7400 (sha256crypt)"], ["sha256crypt"], "")
    if s.startswith("$1$"):
        return (["500 (md5crypt)"], ["md5crypt"], "")
    if s.startswith(("$NT$", "$NTLM$")):
        return (["1000 (NTLM)"], ["nt"], "")
    if len(s) == 32 and re.fullmatch(r"[0-9a-fA-F]+", s):
        return (
            ["0 (raw MD5)", "1000 (NTLM) — ambiguous on shape alone"],
            ["raw-md5", "nt"],
            "32-hex is ambiguous: raw MD5 vs NTLM — pick by hash source "
            "(Windows dumps = NT). Box reality (2026-11-21): john here is "
            "JUMBO — both raw-md5 and nt work via run_john --format; "
            "run_hashcat cannot help (no OpenCL backend on this box).",
        )
    if len(s) == 40 and re.fullmatch(r"[0-9a-fA-F]+", s):
        return (["100 (raw SHA1)"], ["raw-sha1"], "")
    if len(s) == 64 and re.fullmatch(r"[0-9a-fA-F]+", s):
        return (["1400 (raw SHA256)"], ["raw-sha256"], "")
    if len(s) == 128 and re.fullmatch(r"[0-9a-fA-F]+", s):
        return (["1700 (raw SHA512)"], ["raw-sha512"], "")
    return ([], [], "shape unknown — run crypto_kit.identify_hash first")


@framework_tool(
    "Map a hash string to the right cracker settings: returns hashcat -m "
    "mode codes and john --format names for common shapes (32-hex raw "
    "MD5 vs NTLM ambiguity, SHA1, SHA256, SHA512, md5crypt $1$, "
    "sha256crypt $5$, sha512crypt $6$, bcrypt $2*$). Offline only. Run "
    "this before run_hashcat/run_john so the mode argument is never "
    "guessed.",
    next_hints=["run_hashcat", "run_john", "identify_hash"],
)
def suggest_crack_mode(hash_string: str) -> dict[str, Any]:
    """Suggest ``-m`` codes and john formats for ``hash_string`` (offline)."""
    modes, formats, note = _suggest_for(hash_string)
    return {
        "status": "Success",
        "input_preview": (hash_string or "").strip()[:80],
        "hashcat_modes": modes,
        "john_formats": formats,
        "note": note
        or "pass the mode verbatim to run_hashcat (-m) or the format to "
        "run_john (--format=...)",
        "box_note": _BOX_NOTE,
    }


# --------------------------------------------------------------------------- #
# Live backend/capability probe (re-checks the box claims at call time)
# --------------------------------------------------------------------------- #

def _probe_hashcat_backends() -> dict[str, Any]:
    """hashcat's own view of its compute backends (``-I --machine-readable``).

    Parsed generically across versions (v6 prints ``OpenCL.Info`` /
    ``CUDA.Info`` section headers; v7 prints ``Backend.*`` sections) so the
    probe stays correct if the box's hashcat is upgraded in place.
    """
    binp = _preflight("HASHCAT_BIN", "hashcat", _HASHCAT_CANDIDATES)
    if not binp:
        return {
            "available": False,
            "error": "binary 'hashcat' not found "
                     "(checked $HASHCAT_BIN, PATH, standard install paths)",
        }
    try:
        proc = subprocess.run(
            [binp, "-I", "--machine-readable"],
            capture_output=True, text=True, timeout=30,
        )
    except subprocess.TimeoutExpired:
        return {"available": False,
                "error": "hashcat -I timed out after 30s"}
    except FileNotFoundError:
        return {"available": False, "error": f"hashcat vanished at {binp}"}
    text = (proc.stdout or "") + "\n" + (proc.stderr or "")
    devices: list[str] = []
    kinds: set[str] = set()
    # v7 emits one line of machine-readable JSON:
    #   { "OpenCLInfo": { "Platforms": [ { "BackendDevices": [ ... ] } ] } }
    # (v6 table probes emitted section headers like "OpenCL.Info #1" and
    # per-device lines — handled by the line scan below).
    for segment in text.splitlines():
        segment = segment.strip()
        if not segment.startswith("{") or not segment.endswith("}"):
            continue
        try:
            mr = json.loads(segment)
        except json.JSONDecodeError:
            logging.getLogger(__name__).debug(
                "hashcat -I --machine-readable emitted non-JSON braces "
                "segment; falling back to line parsing", exc_info=True)
            continue
        if isinstance(mr, dict) and "OpenCLInfo" in mr:
            kinds.add("OpenCL")
        if isinstance(mr, dict) and "CUDAInfo" in mr:
            kinds.add("CUDA")
        stack: list[Any] = [mr]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                dev_id = node.get("DeviceID")
                name = node.get("Name")
                if dev_id is not None and isinstance(name, str):
                    devices.append(name)
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)
    for line in text.splitlines():
        s = line.strip()
        # Device-name lines across hashcat versions: v6 prints
        # "OpenCL.Info #1 / Device.Name #1: <name>"; v7 prints
        # "Backend.Device.Name #1: <name>". Match any *.Device.Name line
        # (not CUDA/OpenCL section headers themselves).
        if re.match(r"^([a-z0-9.]+\.)?device\.name\b", s, re.IGNORECASE):
            devices.append(s.split(":", 1)[1].strip() if ":" in s else "")
        if re.match(r"^CUDA\.(Info|Platform)", s, re.IGNORECASE):
            kinds.add("CUDA")
        elif re.search(r"opencl", s, re.IGNORECASE) and re.search(r"(info|platform)", s, re.IGNORECASE):
            kinds.add("OpenCL")
    devices = list(dict.fromkeys(devices))
    # The banner (``hashcat (v7.1.2) starting ...``) is the only reliable
    # version source here: naive in-text matches grab OpenCL/driver strings
    # (``OpenCL 3.0``, ``7.1+debian``) instead of hashcat's own version.
    version = None
    m = re.search(r"\bhashcat\s+\(v?(\d+\.\d+(?:\.\d+)?)\)", text)
    if m:
        version = m.group(1)
    if not version:
        # v7 -I --machine-readable suppresses the banner; -V always answers
        # (prints "v7.1.2" — the v is stripped so both paths agree).
        try:
            vp = subprocess.run(
                [binp, "-V"], capture_output=True, text=True, timeout=15,
            )
            vtext = (vp.stdout or "") + "\n" + (vp.stderr or "")
            vm = re.search(r"\bv?(\d+\.\d+(?:\.\d+)?)", vtext)
            version = vm.group(1) if vm else vtext.strip() or None
        except (subprocess.TimeoutExpired, FileNotFoundError):
            version = None
    return {
        "available": bool(devices),
        "error": None if devices
        else ("no backend devices — hashcat cannot crack (OpenCL/CUDA "
              "init finds nothing); typical fix: install a CPU-capable "
              "ICD (apt install pocl-opencl-icd — needs a real GPU or "
              "an ICD that publishes CPU devices) or rely on john"),
        "version": version,
        "backend_kinds": sorted(kinds),
        "devices": devices[:24],
    }


def _probe_john_formats() -> dict[str, Any]:
    """john build flavor + a trimmed format list (first 60 formats)."""
    binp = _preflight("JOHN_BIN", "john", _JOHN_CANDIDATES)
    if not binp:
        return {
            "available": False,
            "error": "binary 'john' not found "
                     "(checked $JOHN_BIN, PATH, standard install paths)",
        }
    try:
        probe = subprocess.run(
            [binp, "--list=formats"], capture_output=True, text=True,
            timeout=20,
        )
    except subprocess.TimeoutExpired:
        return {"available": False, "error": "john --list=formats timed out"}
    except FileNotFoundError:
        return {"available": False, "error": f"john vanished at {binp}"}
    if probe.returncode != 0:
        # core john: --list=formats unsupported; the classic build name and
        # the crypt(3)-class formats still hold.
        return {"available": True, "flavor": "classic",
                "jumbo": False,
                "error": ("--list=formats is not supported — Debian CORE "
                          "john (crypt(3)-class auto-detect only)")}
    fmts: list[str] = []
    for line in (probe.stdout or "").splitlines():
        for tok in line.split():
            if tok != "and":
                fmts.append(tok.rstrip(","))
    try:
        ver = subprocess.run(
            [binp], capture_output=True, text=True, timeout=20
        )
        m = re.search(r"John the Ripper (\S+)", (ver.stdout or "") + (ver.stderr or ""))
        version = m.group(1) if m else None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        version = None
    jumbo = bool(version and "jumbo" in version.lower()) or any(
        f in fmts for f in ("raw-md5", "Raw-MD5", "raw-sha1", "Raw-SHA1")
    )
    return {
        "available": True,
        "error": None,
        "version": version,
        "flavor": "jumbo" if jumbo else "classic",
        "jumbo": jumbo,
        "formats": fmts[:60],
        "format_count": len(fmts),
    }


@framework_tool(
    "Live probe of THIS box's cracking capability: runs 'hashcat -I' and "
    "'john --list=formats' and reports whether hashcat has usable compute "
    "backends (GPU/CPU OpenCL) and whether john is classic-core or jumbo "
    "(raw-md5/nt/sha* available). Call this if box claims in other tools' "
    "notes look stale or before choosing run_hashcat vs run_john.",
    tags=["brute.crack"],
)
def cracker_backends() -> dict[str, Any]:
    """Probe hashcat backends + john build (offline, <40s)."""
    return {
        "status": "Success",
        "cracker_backends": {
            "hashcat": _probe_hashcat_backends(),
            "john": _probe_john_formats(),
        },
        "note": _BOX_NOTE,
    }


# --------------------------------------------------------------------------- #
# john the Ripper — launch/poll/show
# --------------------------------------------------------------------------- #

def _parse_john(log_text: str) -> dict[str, Any]:
    """john stdout: cracked lines look like '<plaintext> (<user-or-hash>)'."""
    candidates: list[dict[str, str]] = []
    for line in log_text.splitlines():
        m = re.match(r"^(\S+)\s+\(([^)]+)\)\s*$", line.strip())
        if m and not m.group(2).startswith("Loaded"):
            candidates.append({"plaintext": m.group(1), "for": m.group(2)})
    summary = next(
        (ln.strip() for ln in log_text.splitlines() if "Session completed" in ln),
        None,
    )
    return {"cracked_candidates": candidates[:50], "summary": summary}


register_verdict_parser("john", _parse_john)


@framework_tool(
    "Launch a john the Ripper crack in the background: accepts one or more "
    "hashes (newline/comma/semicolon separated), an optional wordlist "
    "(defaults to rockyou under the framework wordlist tree), and extra "
    "john options. Returns a job_id immediately; poll john_status(job_id) "
    "until done, then john_show for the authoritative recovered list. CPU "
    "cracker — the reliable path on this box. Offline compute: no target "
    "contact, no scope gate needed.",
    next_hints=["john_status", "john_show", "suggest_crack_mode"],
)
def run_john(
    hash_input: str,
    options: str = "",
    wordlist: str = "",
) -> dict[str, Any]:
    """Crack ``hash_input`` with john the Ripper (background, poll later).

    Args:
        hash_input: One or more hashes (newline/comma/semicolon separated).
            Run suggest_crack_mode first; john usually auto-detects, but an
            explicit ``--format`` avoids raw-md5-vs-NT ambiguity.
        options: Extra john options as a single string (e.g.
            ``"--format=raw-md5 --rules=JtR"`` or mask/incremental flags).
        wordlist: Optional wordlist path; empty resolves the framework
            default (rockyou). Skipped when options already set a wordlist.
    """
    binp = _preflight("JOHN_BIN", "john", _JOHN_CANDIDATES)
    if not binp:
        return {
            "status": "Failed",
            "error": (
                "binary 'john' not found (checked $JOHN_BIN, PATH, "
                "/usr/sbin/john, /usr/bin/john, /usr/local/bin/john). "
                "Install john (Debian: apt install john) or set JOHN_BIN= "
                "in .env; no reindex needed after install."
            ),
        }
    try:
        hashfile = _write_hashfile(hash_input)
    except ValueError as e:
        return {"status": "Failed", "error": str(e)}

    extra = shlex.split(options) if options else []
    if not any(o.startswith("--wordlist") for o in extra):
        wl = wordlist or _default_wordlist()
        if wl:
            extra.append(f"--wordlist={wl}")
    command = [binp, *extra, hashfile]
    # 32-hex shape note: with no explicit --format john prefers LM (two
    # halves → slow descrypt paths) for bare 32-hex input on this build.
    note = None
    stripped = (hash_input or "").strip()
    if (
        not any(o.startswith("--format") for o in extra)
        and re.fullmatch(
            r"[0-9a-fA-F]{32}(?:[\n;,][0-9a-fA-F]{32})*", stripped
        )
    ):
        note = (
            "32-hex input with no --format: john prefers LM (2 halves), "
            "NOT raw-MD5. Pass --format=raw-md5 (or nt/SHA1) explicitly "
            "here — this john is JUMBO so those formats are available "
            "(run_hashcat is not a fallback on this box: no OpenCL "
            "backend)."
        )
    result = _launch_hash_crack(
        command,
        hashfile,
        tool_name="john",
        timeout=_JOHN_TIMEOUT,
        verdict_parser=_parse_john,
    )
    if note:
        prev = result.get("note")
        result["note"] = f"{prev} | {note}" if prev else note
    return result


@framework_tool(
    "Poll a john crack launched by run_john: running/done, parsed cracked "
    "candidates (plaintext + which hash), and recent log lines. Call until "
    "status == done, then john_show for the authoritative recovered list.",
    next_hints=["john_show", "report_finding"],
)
def john_status(job_id: str) -> dict[str, Any]:
    """Poll the john job launched by run_john."""
    return poll_job(job_id, tool_name="john")


@framework_tool(
    "Blocking read of john's potfile: runs 'john --show' on the hash input "
    "and returns recovered 'plaintext:hash' pairs for anything already "
    "cracked. Quick (<30s cap). Run after (or between) run_john polls. "
    "Offline compute only.",
    next_hints=["report_finding"],
)
def john_show(hash_input: str, options: str = "") -> dict[str, Any]:
    """Run ``john --show`` on ``hash_input`` (one or more hashes).

    Args:
        hash_input: One or more hashes (newline/comma/semicolon separated).
        options: Extra john options (e.g. ``--format=md5`` when a $1$ file
            needs a format nudge).
    """
    binp = _preflight("JOHN_BIN", "john", _JOHN_CANDIDATES)
    if not binp:
        return {
            "status": "Failed",
            "error": "binary 'john' not found — see run_john's install note",
        }
    try:
        hashfile = _write_hashfile(hash_input)
    except ValueError as e:
        return {"status": "Failed", "error": str(e)}
    extra = shlex.split(options) if options else []
    try:
        proc = subprocess.run(
            [binp, "--show", *extra, hashfile],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return {
            "status": "Success",
            "raw": (proc.stdout or proc.stderr)[:4000],
            "recovered_lines": [
                line.strip()
                for line in (proc.stdout or "").splitlines()
                if ":" in line and not line.startswith(("Format", "Loaded"))
            ][:100],
        }
    except subprocess.TimeoutExpired:
        return {"status": "Failed", "error": "john --show timed out"}
    except FileNotFoundError:
        return {"status": "Failed", "error": f"john binary vanished at {binp}"}
    finally:
        _drop_hashfile(hashfile)


# --------------------------------------------------------------------------- #
# hashcat — launch/poll/show
# --------------------------------------------------------------------------- #

def _parse_hashcat(log_text: str) -> dict[str, Any]:
    """hashcat stdout: recovered 'hash:plain' pairs + status banner."""
    pairs: list[dict[str, str]] = []
    for line in log_text.splitlines():
        m = re.match(r"^([^\s:]{8,}):(\S{1,128})$", line.strip())
        if m and not re.match(
            r"^(Hash|Salt|Digest|Device|Speed|Recovered|Progress|Time|"
            r"Kernel|Options|Guess|Mask|Candidate|Session|Status)",
            line,
        ):
            pairs.append({"hash": m.group(1), "plaintext": m.group(2)})
    recovered = re.search(r"Recovered\.*:\s*(\d+)/(\d+)", log_text)
    return {
        "cracked_pairs": pairs[:50],
        "recovered": f"{recovered.group(1)}/{recovered.group(2)}"
        if recovered
        else None,
    }


register_verdict_parser("hashcat", _parse_hashcat)


@framework_tool(
    "Launch a hashcat crack in the background: hashcat -m <mode> -a 0 "
    "(dictionary) on a hash file + wordlist (defaults to rockyou; skipped "
    "when -a 3 mask mode is set), extra options passthrough (e.g. "
    "'-a 3 ?u?l?l?l?l?d?d', '-r rules/best64.rule'). Returns a job_id; "
    "poll hashcat_status(job_id), then hashcat_show. Box check first: "
    "hashcat needs usable compute backends (GPU or a CPU-capable OpenCL "
    "ICD) — cracker_backends() probes this live. On boxes with no GPU and "
    "no CPU ICD it fails at backend init ('No devices found/left'); run_john "
    "is the reliable CPU cracker there.",
    next_hints=["hashcat_status", "hashcat_show", "suggest_crack_mode",
                "cracker_backends"],
)
def run_hashcat(
    hash_input: str,
    mode: int,
    options: str = "",
    wordlist: str = "",
) -> dict[str, Any]:
    """Crack ``hash_input`` with hashcat mode ``mode`` (background).

    Args:
        hash_input: One or more hashes (newline/comma/semicolon separated).
        mode: hashcat ``-m`` code — get it from suggest_crack_mode.
        options: Extra hashcat options (e.g. ``"-a 3 ?u?l?l?l?l?d?d"`` or
            ``"-r rules/best64.rule"``). Positionals inside options (a
            mask, or dicts for -a 1/6/7) are automatically re-ordered to
            come AFTER the hash file — hashcat requires
            ``[options] hashfile [mask|dict]``.
        wordlist: Optional wordlist path; empty resolves the framework
            default (rockyou) and only applies in -a 0 mode.
    """
    binp = _preflight("HASHCAT_BIN", "hashcat", _HASHCAT_CANDIDATES)
    if not binp:
        return {
            "status": "Failed",
            "error": (
                "binary 'hashcat' not found (checked $HASHCAT_BIN, PATH, "
                "/usr/bin, /usr/local/bin, /opt/hashcat). Install hashcat "
                "plus an OpenCL runtime (e.g. apt install hashcat "
                "pocl-opencl-icd) or set HASHCAT_BIN in .env; no reindex "
                "needed after install. CPU-only box: run_john."
            ),
        }
    backends = _probe_hashcat_backends()
    if not backends.get("available"):
        return {
            "status": "Failed",
            "error": (
                "hashcat has no usable compute backend on this box — "
                f"{backends.get('error') or 'no OpenCL/CUDA devices'}"
            ),
            "cracker_backends": {
                "hashcat": backends,
                "john": _probe_john_formats(),
            },
            "note": (
                "run_john is the reliable cracker here (CPU, "
                "auto-detects crypt formats; JUMBO builds also cover "
                "raw-md5/nt/sha*). cracker_backends() re-checks hashcat "
                "device availability."
            ),
        }
    try:
        hashfile = _write_hashfile(hash_input)
    except ValueError as e:
        return {"status": "Failed", "error": str(e)}

    extra = shlex.split(options) if options else []
    attack = None
    for i, o in enumerate(extra):
        if o in ("-a", "--attack-mode") and i + 1 < len(extra):
            attack = extra[i + 1]
    if attack is None:
        extra = ["-a", "0", *extra]
        attack = "0"
    # hashcat wants [options] HASHFILE [dict|mask] — positionals hiding in
    # ``options`` (a mask for -a 3, dicts for -a 1/6/7) must come AFTER the
    # hashfile, never before it.
    opt_only, positionals = _split_hashcat_positionals(extra)
    command = [binp, "-m", str(int(mode)), *opt_only, hashfile, *positionals]
    if attack in (None, "0"):
        wl = wordlist or _default_wordlist()
        if wl:
            command.append(wl)
    return _launch_hash_crack(
        command,
        hashfile,
        tool_name="hashcat",
        timeout=_HASHCAT_TIMEOUT,
        verdict_parser=_parse_hashcat,
    )


@framework_tool(
    "Poll a hashcat crack launched by run_hashcat: running/done, recovered "
    "count banner, parsed hash:plaintext pairs from stdout, recent log "
    "lines. Call until done, then hashcat_show for the potfile view.",
    next_hints=["hashcat_show", "report_finding"],
)
def hashcat_status(job_id: str) -> dict[str, Any]:
    """Poll the hashcat job launched by run_hashcat."""
    return poll_job(job_id, tool_name="hashcat")


@framework_tool(
    "Blocking read of hashcat's potfile: runs 'hashcat -m <mode> --show' "
    "on the hash input and returns recovered 'hash:plaintext' pairs "
    "(<30s cap). Offline compute only.",
    next_hints=["report_finding"],
)
def hashcat_show(hash_input: str, mode: int) -> dict[str, Any]:
    """Run ``hashcat -m <mode> --show`` (fast, blocking)."""
    binp = _preflight("HASHCAT_BIN", "hashcat", _HASHCAT_CANDIDATES)
    if not binp:
        return {
            "status": "Failed",
            "error": "binary 'hashcat' not found — see run_hashcat's install note",
        }
    try:
        hashfile = _write_hashfile(hash_input)
    except ValueError as e:
        return {"status": "Failed", "error": str(e)}
    try:
        proc = subprocess.run(
            [binp, "-m", str(int(mode)), "--show", hashfile],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return {
            "status": "Success",
            "raw": (proc.stdout or proc.stderr)[:4000],
            "recovered_pairs": [
                line.strip()
                for line in (proc.stdout or "").splitlines()
                if ":" in line and not line.startswith(("Hash", "Salt", "Device"))
            ][:100],
        }
    except subprocess.TimeoutExpired:
        return {"status": "Failed", "error": "hashcat --show timed out"}
    except FileNotFoundError:
        return {"status": "Failed", "error": f"hashcat binary vanished at {binp}"}
    finally:
        _drop_hashfile(hashfile)


__all__ = [
    "suggest_crack_mode",
    "cracker_backends",
    "run_john",
    "john_status",
    "john_show",
    "run_hashcat",
    "hashcat_status",
    "hashcat_show",
]
