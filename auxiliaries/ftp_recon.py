"""FTP / SFTP recon and transfer tools for the framework.

@framework_tool callables registered for the Brain (auxiliaries.ftp_recon.*):

- ftp_banner        connect + welcome banner (no auth, raw socket)
- ftp_anon_check    anonymous/guest login attempt + cwd + capped LIST
- ftp_list          authenticated LIST (names + sizes/perms, capped)
- ftp_get / ftp_put authenticated download / upload (size-capped)
- sftp_list / sftp_get / sftp_put   same ops over SSH via paramiko (port 22)

Safety rails, by construction:
- Scope gate: check_scan(host) BEFORE every connection; a refusal RAISES
  ScopeGateError before the try (fail-closed — surfaces as Failed on both
  dispatch paths, never a buried string).  No scope armed = lab mode.
- Bounded: single stateless connection per call (no session handles — FTP
  and SFTP calls are one-shot like paramiko_client one-shot), timeouts on
  every socket op, LIST capped at lines, transfers size-capped.

Root is NOT required (plain TCP + paramiko).  The interface param exists on
the traffic-facing tools for schema consistency with packetcraft; FTP does
not need it and it is accepted-and-ignored.
"""

import os
import socket
from typing import Optional

import ftplib

from constants import framework_tool
from utils.scope_gate import check_scan, ScopeGateError

MAX_LIST_LINES = 200
MAX_TRANSFER_BYTES = 20 * 1024 * 1024  # 20 MB per get/put


def _gate(host: str) -> None:
    """check_scan BEFORE any connection; refusal raises (fail-closed)."""
    ok, reason = check_scan(host)
    if not ok:
        raise ScopeGateError(f"scope gate: {reason}")


class _ListCap(Exception):
    """Internal: stop retrlines once the line cap is reached."""


def _ftp_connect(host: str, port: int, timeout: float) -> ftplib.FTP:
    f = ftplib.FTP()
    f.connect(host, int(port), timeout=timeout)
    return f


@framework_tool(
    "Grab an FTP server's welcome banner (no auth): server type and version "
    "from the raw 220 greeting. Scope-gated.",
    next_hints=["ftp_anon_check for an anonymous-login attempt"],
)
def ftp_banner(host: str, port: int = 21, timeout: float = 8.0,
               interface: str = ""):
    """Connect to an FTP port and return its banner.

    Args:
        host: Target host (scope-gate checked before connect).
        port: FTP port (default 21).
        timeout: Connect/read timeout in seconds.
        interface: Accepted for schema consistency; FTP uses plain TCP routing.
    """
    _gate(host)
    try:
        with socket.create_connection((host, int(port)), timeout=float(timeout)) as s:
            s.settimeout(float(timeout))
            banner = s.recv(1024).decode("utf-8", "replace").strip()
        return f"FTP banner {host}:{port}: {banner!r}"
    except Exception as e:
        return f"ftp_banner error: {e}"


@framework_tool(
    "Try anonymous FTP login (anonymous/guest): verdict, working directory, "
    "and a capped directory listing. Scope-gated.",
    next_hints=["ftp_list with credentials", "report_finding to log the verdict"],
)
def ftp_anon_check(host: str, port: int = 21, timeout: float = 8.0,
                   interface: str = ""):
    """Attempt anonymous login and enumerate what it can see.

    Args:
        host: Target host (scope-gate checked before connect).
        port: FTP port (default 21).
        timeout: Connect/read timeout in seconds.
        interface: Accepted for schema consistency; FTP uses plain TCP routing.
    """
    _gate(host)
    try:
        f = _ftp_connect(host, int(port), float(timeout))
    except Exception as e:
        return f"ftp_anon_check error (connect): {e}"
    try:
        welcome = f.getwelcome()
        try:
            f.login("anonymous", "guest")
        except ftplib.error_perm as e:
            try:
                f.quit()
            except Exception:
                f.close()
            return (
                f"ftp_anon_check {host}:{port}\nbanner: {welcome!r}\n"
                f"ANON LOGIN: NO - {e}"
            )
        cwd = f.pwd()
        try:
            names = f.nlst()[:MAX_LIST_LINES]
        except Exception as e:
            names = [f"<listing failed: {e}>"]
        try:
            f.quit()
        except Exception:
            f.close()
        listing = "\n".join(f"  {n}" for n in names) or "  (empty)"
        return (
            f"ftp_anon_check {host}:{port}\nbanner: {welcome!r}\n"
            f"ANON LOGIN: YES\ncwd: {cwd}\nlisting (cap {MAX_LIST_LINES}):\n{listing}"
        )
    except Exception as e:
        return f"ftp_anon_check error: {e}"


@framework_tool(
    "Authenticated FTP directory listing (names + sizes/perms, capped). "
    "Scope-gated.",
    next_hints=["ftp_get to download an interesting file"],
)
def ftp_list(host: str, username: str, password: str, path: str = ".",
             port: int = 21, timeout: float = 8.0, max_lines: int = 200,
             interface: str = ""):
    """LIST a directory with real credentials.

    Args:
        host: Target host (scope-gate checked before connect).
        username / password: FTP credentials.
        path: Directory to list (default current).
        port: FTP port (default 21).
        timeout: Connect/transfer timeout in seconds.
        max_lines: Listing cap (default 200).
        interface: Accepted for schema consistency; FTP uses plain TCP routing.
    """
    _gate(host)
    try:
        f = _ftp_connect(host, int(port), float(timeout))
        f.login(username, password)
        f.cwd(path)
        lines: list = []
        cap = min(int(max_lines), MAX_LIST_LINES)

        def _cb(line: str) -> None:
            if len(lines) >= cap:
                raise _ListCap()
            lines.append(line)

        try:
            f.retrlines("LIST", _cb)
        except _ListCap:
            pass
        try:
            f.quit()
        except Exception:
            f.close()
        body = "\n".join(f"  {ln}" for ln in lines) or "  (empty)"
        return f"ftp_list {host}:{port} {path} ({len(lines)} lines):\n{body}"
    except Exception as e:
        return f"ftp_list error: {e}"


def _transfer_guard(size: int) -> Optional[str]:
    if size > MAX_TRANSFER_BYTES:
        return (f"refused: {size} bytes exceeds the {MAX_TRANSFER_BYTES}-byte "
                f"transfer cap (raise it by editing MAX_TRANSFER_BYTES)")
    return None


@framework_tool(
    "Download a file over authenticated FTP (size-capped). Scope-gated.",
    next_hints=["report_finding to record the artifact"],
)
def ftp_get(host: str, username: str, password: str, remote: str, local: str,
            port: int = 21, timeout: float = 8.0, interface: str = ""):
    """RETR a remote file to a local path.

    Args:
        host: Target host (scope-gate checked before connect).
        username / password: FTP credentials.
        remote: Remote file path.
        local: Local destination path.
        port: FTP port (default 21).
        timeout: Connect/transfer timeout in seconds.
        interface: Accepted for schema consistency; FTP uses plain TCP routing.
    """
    _gate(host)
    try:
        f = _ftp_connect(host, int(port), float(timeout))
        f.login(username, password)
        size = f.size(remote)
        guard = _transfer_guard(int(size) if size is not None else -1)
        if guard:
            return f"ftp_get refused: {guard}"
        f.retrbinary(f"RETR {remote}", open(local, "wb").write,
                     blocksize=8192)
        try:
            f.quit()
        except Exception:
            f.close()
        return f"ftp_get {host}:{remote} -> {local} ({size} bytes)"
    except Exception as e:
        return f"ftp_get error: {e}"


@framework_tool(
    "Upload a local file over authenticated FTP (size-capped, writes on the "
    "target — operator-judgment applies). Scope-gated.",
)
def ftp_put(host: str, username: str, password: str, local: str, remote: str,
            port: int = 21, timeout: float = 8.0, interface: str = ""):
    """STOR a local file onto the FTP server.

    Args:
        host: Target host (scope-gate checked before connect).
        username / password: FTP credentials.
        local: Local source file path.
        remote: Remote destination path.
        port: FTP port (default 21).
        timeout: Connect/transfer timeout in seconds.
        interface: Accepted for schema consistency; FTP uses plain TCP routing.
    """
    _gate(host)
    try:
        guard = _transfer_guard(os.path.getsize(local))
        if guard:
            return f"ftp_put refused: {guard}"
        f = _ftp_connect(host, int(port), float(timeout))
        f.login(username, password)
        with open(local, "rb") as fh:
            f.storbinary(f"STOR {remote}", fh)
        try:
            f.quit()
        except Exception:
            f.close()
        return f"ftp_put {local} -> {host}:{remote}"
    except Exception as e:
        return f"ftp_put error: {e}"


# --- SFTP (paramiko, port 22) -----------------------------------------------

def _sftp_connect(host: str, port: int, username: str, password: str,
                  timeout: float):
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port=int(port), username=username, password=password,
                   timeout=float(timeout), allow_agent=False,
                   look_for_keys=False)
    return client, client.open_sftp()


@framework_tool(
    "List a directory over SFTP (SSH file transfer, password auth, capped). "
    "Scope-gated.",
    next_hints=["sftp_get to download an interesting file"],
)
def sftp_list(host: str, username: str, password: str, path: str = ".",
              port: int = 22, timeout: float = 8.0, max_entries: int = 200):
    """Listdir over SFTP with real credentials.

    Args:
        host: Target host (scope-gate checked before connect).
        username / password: SSH credentials.
        path: Directory to list (default current).
        port: SSH port (default 22).
        timeout: Connect timeout in seconds.
        max_entries: Listing cap (default 200).
    """
    _gate(host)
    try:
        client, sftp = _sftp_connect(host, int(port), username, password,
                                     float(timeout))
        try:
            entries = sftp.listdir_attr(path)[: min(int(max_entries),
                                                    MAX_LIST_LINES)]
            lines = "\n".join(
                f"  {a.filename:<40} {a.st_size:>12} "
                f"{'dir' if str(a.longname).startswith('d') else 'file'}"
                for a in entries
            ) or "  (empty)"
        finally:
            client.close()
        return f"sftp_list {host}:{port} {path} ({len(entries)} entries):\n{lines}"
    except Exception as e:
        return f"sftp_list error: {e}"


@framework_tool(
    "Download a file over SFTP (size-capped via remote stat). Scope-gated.",
)
def sftp_get(host: str, username: str, password: str, remote: str, local: str,
             port: int = 22, timeout: float = 8.0):
    """sftp.get a remote file to a local path.

    Args:
        host: Target host (scope-gate checked before connect).
        username / password: SSH credentials.
        remote: Remote file path.
        local: Local destination path.
        port: SSH port (default 22).
        timeout: Connect timeout in seconds.
    """
    _gate(host)
    try:
        client, sftp = _sftp_connect(host, int(port), username, password,
                                     float(timeout))
        try:
            guard = _transfer_guard(int(sftp.stat(remote).st_size or 0))
            if guard:
                return f"sftp_get refused: {guard}"
            sftp.get(remote, local)
        finally:
            client.close()
        return f"sftp_get {host}:{remote} -> {local}"
    except Exception as e:
        return f"sftp_get error: {e}"


@framework_tool(
    "Upload a file over SFTP (size-capped, writes on the target — "
    "operator-judgment applies). Scope-gated.",
)
def sftp_put(host: str, username: str, password: str, local: str, remote: str,
             port: int = 22, timeout: float = 8.0):
    """sftp.put a local file to a remote path.

    Args:
        host: Target host (scope-gate checked before connect).
        username / password: SSH credentials.
        local: Local source file path.
        remote: Remote destination path.
        port: SSH port (default 22).
        timeout: Connect timeout in seconds.
    """
    _gate(host)
    try:
        guard = _transfer_guard(os.path.getsize(local))
        if guard:
            return f"sftp_put refused: {guard}"
        client, sftp = _sftp_connect(host, int(port), username, password,
                                     float(timeout))
        try:
            sftp.put(local, remote)
        finally:
            client.close()
        return f"sftp_put {local} -> {host}:{remote}"
    except Exception as e:
        return f"sftp_put error: {e}"