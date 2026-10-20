"""Paramiko SSH tools with persistent (hanging) session support.

The original ``paramiko_client`` was a one-shot: connect, run one command,
close.  That drops the connection the instant the tool call returns, so the
secretary can never run a *second* command on the same host without
re-authenticating.

The tools below split the lifecycle so a live ``SSHClient`` survives across
tool calls via the process-local :class:`~utils.session_manager.SessionManager`:

    ssh_connect   -> opens the connection, returns an "ssh:sess-NNNN" handle
    ssh_exec      -> runs a command on that handle's session
    ssh_shell     -> opens an interactive channel (for shells that need a pty)
    ssh_close     -> tears the session down
    list_sessions -> lists ALL active sessions across every namespace
                     (ssh, msf, listener) as typed handles

Layer 1 (typed handles): every session-returning tool yields a string of the
form ``"<kind>:<id>"`` (here ``"ssh:sess-0001"``).  Tools that consume a
session declare ``accepted_handle_kinds=["ssh"]`` so the registry refuses a
handle from another namespace *before* execution and tells the model which
tool to use instead.  This kills the "which session_id do I pass?" entanglement
where an MSF numeric session id and a paramiko ``sess-NNNN`` id are both
plausible-looking arguments to the wrong tool.

Note on very old SSH targets: targets whose SSH server only offers host-key
algorithms modern paramiko no longer accepts (e.g. Metasploitable2's OpenSSH
4.7 with ssh-rsa/ssh-dss host keys) cannot be connected to with paramiko and
are meant to be accessed over SSH via a Metasploit module (``ssh_login``),
which yields an ``msf:`` handle.  The typed-handle gate keeps that ``msf:``
session from being confused with a paramiko ``ssh:`` session, so no special
paramiko legacy handling is attempted here.

The one-shot ``paramiko_client`` is kept for backward compatibility.
"""

import os
import time

import paramiko
from constants import framework_tool
from utils.handles import format_handle, parse_handle
from utils.session_manager import get_manager

_sm = get_manager()

# --- bounded SSH command execution (2026-09-25 stack-freeze bug) -------------
#
# The old ssh_exec called ``stdout.read()`` — a blocking read until the SSH
# CHANNEL closes. Two failure modes made large multi-segment command strings
# (the "apt-get update && apt-get install -y ..." chains the secretary loves)
# hang FOREVER with the connection still technically healthy:
#
#   1. A segment that reads stdin (apt-get's Y/n prompt, passwd, sudo, ...)
#      blocks on stdin forever — the harness never supplies it and never
#      closes it, so the remote process never exits.
#   2. A segment that starts a daemon/background child (service x start,
#      nohup, ``&``) leaves the grandchild HOLDING THE CHANNEL's stdout;
#      the shell exits but the channel never EOFs.
#
# Either way the tool call never returns. Worse, each hung call pinned one
# thread of the Brain's DEFAULT executor pool (min(32, cpu+4) — roughly 6-8
# threads in the workbench container); the OWUI wrapper timed out at 600s,
# the model retried, and 3-4 retries exhausted the pool — after which EVERY
# sync tool on the Brain queued forever and the whole stack appeared frozen
# (the "more than 3-4 &&" correlation: it was retry-driven executor
# starvation, not the && count itself).
#
# The runner below fixes all three legs:
#   * closes stdin immediately (interactive prompts can never wedge a run),
#   * polls ``exit_status_ready()`` instead of blocking on EOF, so a
#     daemon-spawning command returns as soon as the SHELL exits,
#   * enforces a hard wall-clock cap (SSH_EXEC_TIMEOUT, default 300s) that
#     closes ONLY the channel — the persistent session survives a timeout
#     and can run follow-up commands.
#
# Environment knobs (read per-call so .env edits apply without re-import):
#   SSH_EXEC_TIMEOUT        per-command wall-clock cap, seconds (0 = unbounded)
#   SSH_EXEC_OUTPUT_CAP     stdout bytes kept (default 256 KiB), then truncated

DEFAULT_SSH_EXEC_TIMEOUT = float(os.getenv("SSH_EXEC_TIMEOUT", "300"))
DEFAULT_SSH_EXEC_OUTPUT_CAP = int(os.getenv("SSH_EXEC_OUTPUT_CAP", str(256 * 1024)))

_POLL_INTERVAL_S = 0.1
# Output drained between polls; sized so a fast-flooding command can't fill
# the channel window (and deadlock the remote writer) between polls.
_DRAIN_CHUNK = 32768


class _SshExecTimeout(Exception):
    """Raised internally when a command outlives its wall-clock cap."""


def _run_ssh_command(client, command: str, timeout: float = None,
                     output_cap: int = None):
    """Run ``command`` on an open paramiko SSHClient, bounded in time.

    Returns a dict envelope: ``{command, stdout, stderr, exit_code,
    timed_out, duration_s}``. ``exit_code`` is None when the command was
    terminated by the cap (its exit status never arrived).

    The persistent session is preserved on timeout: only the channel is
    closed, so the caller can keep using the same handle.
    """
    timeout = DEFAULT_SSH_EXEC_TIMEOUT if timeout is None else float(timeout)
    output_cap = (DEFAULT_SSH_EXEC_OUTPUT_CAP if output_cap is None
                  else int(output_cap))

    chan = client.get_transport().open_session()
    try:
        chan.exec_command(command)
        # Nothing we run should wait on stdin: close it immediately. An
        # apt-get/passwd/sudo prompt would otherwise block until EOF that
        # never comes — one of the two hang shapes this runner exists for.
        chan.shutdown_write()

        deadline = time.monotonic() + timeout if timeout > 0 else None
        out_chunks, err_chunks = [], []
        out_len = err_len = 0

        while True:
            # Drain whatever arrived since the last poll BEFORE checking
            # completion, so a command that exits quickly after printing a
            # lot still yields its full output.
            while chan.recv_ready():
                data = chan.recv(_DRAIN_CHUNK)
                if not data:
                    break
                if out_len < output_cap:
                    out_chunks.append(data[: output_cap - out_len])
                    out_len += len(data)
            while chan.recv_stderr_ready():
                data = chan.recv_stderr(_DRAIN_CHUNK)
                if not data:
                    break
                if err_len < output_cap:
                    err_chunks.append(data[: output_cap - err_len])
                    err_len += len(data)

            if chan.exit_status_ready():
                break

            # EOF on stdout+stderr with no exit status yet: the shell is gone
            # but the status never arrived (racy servers). Don't wait forever.
            if chan.closed or (not chan.recv_ready() and chan.eof_received):
                # Give the exit status one short grace window to land.
                grace_end = time.monotonic() + 2.0
                while time.monotonic() < grace_end:
                    if chan.exit_status_ready():
                        break
                    time.sleep(0.05)
                if not chan.exit_status_ready():
                    return {
                        "command": command,
                        "stdout": b"".join(out_chunks).decode("utf-8", errors="replace"),
                        "stderr": b"".join(err_chunks).decode("utf-8", errors="replace"),
                        "exit_code": None,
                        "timed_out": False,
                        "duration_s": round(time.monotonic() - (deadline - timeout) if deadline else 0, 1),
                        "error": "channel closed before an exit status arrived",
                    }
                break

            if deadline is not None and time.monotonic() > deadline:
                raise _SshExecTimeout()
            time.sleep(_POLL_INTERVAL_S)

        exit_code = chan.recv_exit_status() if chan.exit_status_ready() else None

        # Final drain after completion (bytes may have landed between the
        # last poll and the status check).
        while chan.recv_ready():
            data = chan.recv(_DRAIN_CHUNK)
            if not data:
                break
            if out_len < output_cap:
                out_chunks.append(data[: output_cap - out_len])
                out_len += len(data)
        while chan.recv_stderr_ready():
            data = chan.recv_stderr(_DRAIN_CHUNK)
            if not data:
                break
            if err_len < output_cap:
                err_chunks.append(data[: output_cap - err_len])
                err_len += len(data)

        stdout = b"".join(out_chunks).decode("utf-8", errors="replace")
        stderr = b"".join(err_chunks).decode("utf-8", errors="replace")

        envelope = {
            "command": command,
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
            "timed_out": False,
            "duration_s": round((time.monotonic() - (deadline - timeout)) if deadline else 0, 1),
        }
        if out_len >= output_cap:
            envelope["stdout_truncated"] = True
        return envelope
    except _SshExecTimeout:
        # Terminate only the channel — the session (and its handle) survive.
        # The remote process gets SIGHUP from the channel teardown.
        try:
            chan.close()
        except Exception:
            pass
        raise
    except Exception:
        try:
            chan.close()
        except Exception:
            pass
        raise


def _format_ssh_result(env: dict) -> str:
    """Render a ``_run_ssh_command`` envelope as the legacy text shape.

    Preserves the T-001 rule: stdout is UNPREFIXED so tokens like the
    ``(root : root)`` runas spec from ``sudo -l`` stay parseable. stderr is
    appended with an explicit ``[stderr]`` marker only when non-empty.
    """
    text = env.get("stdout") or ""
    err = env.get("stderr") or ""
    if err:
        text = f"{text}\n[stderr] {err}" if text else f"[stderr] {err}"
    if env.get("exit_code") is None and not env.get("timed_out"):
        text = f"{text}\n[exit status unavailable]".lstrip("\n") if not text else f"{text}\n[exit status unavailable]"
    return text


@framework_tool(
    "Open a persistent SSH connection and return a typed session handle "
    "(e.g. 'ssh:sess-0001'). The handle is passed to ssh_exec, ssh_shell, and "
    "ssh_close. Prefer this over Metasploit's ssh_login for a plain "
    "username/password login on a normally-speaking SSH server. (For a "
    "target whose SSH server only offers legacy host-key algorithms, use a "
    "Metasploit ssh_login module instead, which returns an 'msf:' handle.)"
)
def ssh_connect(hostname: str, username: str, password: str, port: int = 22):
    """
    Opens a persistent SSH connection to a remote host.

    Returns a typed session handle string like "ssh:sess-0001" that can be
    passed to ssh_exec, ssh_shell, and ssh_close for follow-up commands on
    the SAME connection without re-authenticating.

    Args:
        hostname: The target IP or hostname.
        username: SSH username.
        password: SSH password.
        port: SSH port (default 22).
    """
    from utils.scope_gate import check_scan, ScopeGateError
    _sc_ok, _sc_reason = check_scan(hostname)
    if not _sc_ok:
        raise ScopeGateError(f"scope gate: {_sc_reason}")
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname,
            port=int(port),
            username=username,
            password=password,
            timeout=10,
            allow_agent=False,
            look_for_keys=False,
        )
        target = f"{username}@{hostname}:{port}"
        sid = _sm.register("ssh", target, client, hostname=hostname, username=username)
        handle = format_handle("ssh", sid)
        return (
            f"SSH session established: {handle} ({target}). "
            f"Use this handle with ssh_exec / ssh_shell / ssh_close."
        )
    except Exception as e:
        return f"SSH Connection Error: {e}"


@framework_tool(
    "Execute a command on an existing SSH session. Pass the 'ssh:' handle "
    "returned by ssh_connect (e.g. 'ssh:sess-0001').",
    accepted_handle_kinds=["ssh"],
    untrusted_target=True,
)
def ssh_exec(handle: str, command: str):
    """
    Runs a shell command on a previously opened SSH session.

    The connection stays open after the command returns so you can call
    ssh_exec again with the same handle.

    Args:
        handle: The 'ssh:' handle returned by ssh_connect (e.g. 'ssh:sess-0001').
        command: The shell command to execute.
    """
    kind, sid = parse_handle(handle)
    session = _sm.get(sid)
    if session is None:
        return (
            f"SSH session {handle} not found. Call ssh_connect first, "
            "or use list_sessions to see active sessions."
        )
    # Re-check the session's target against the (possibly just-armed) scope
    # so a session opened in lab mode can't exec commands on an out-of-scope
    # host after the operator arms a bounty scope.
    from utils.scope_gate import check_scan, ScopeGateError
    _sc_ok, _sc_reason = check_scan(session.metadata.get("hostname", ""))
    if not _sc_ok:
        raise ScopeGateError(f"scope gate: {_sc_reason}")
    try:
        # Bounded execution (2026-09-25): poll the exit status instead of
        # blocking on channel EOF; a hung multi-segment command chain
        # ("a && b && service x start") now times out with the session
        # intact instead of pinning a Brain executor thread forever.
        env = _run_ssh_command(session.client, command)
        session.touch()
        return _format_ssh_result(env)
    except _SshExecTimeout:
        # Only the channel was closed — the session (and handle) survive.
        return (
            f"[ssh_exec] command exceeded the {DEFAULT_SSH_EXEC_TIMEOUT:.0f}s cap "
            "(SSH_EXEC_TIMEOUT) and was terminated. The session handle "
            f"{handle} remains usable. Long 'a && b && c' chains that prompt "
            "for input (apt/passwd/sudo) or spawn daemons hang forever without "
            "this cap — split the chain into separate ssh_exec calls or raise "
            "SSH_EXEC_TIMEOUT."
        )
    except paramiko.SSHException as e:
        # The connection may have died remotely; surface it clearly.
        return f"SSH session {handle} error (connection may be dead): {e}"
    except Exception as e:
        return f"SSH exec error: {e}"


@framework_tool(
    "Open an interactive shell channel on an existing SSH session. Use this "
    "instead of ssh_exec when the remote command needs a PTY (sudo prompts, "
    "menus, anything that checks isatty). Pass the 'ssh:' handle.",
    accepted_handle_kinds=["ssh"],
)
def ssh_shell(handle: str, command: str, timeout: float = 10.0):
    """
    Sends a command to an interactive shell channel and reads the response.

    Args:
        handle: The 'ssh:' handle returned by ssh_connect.
        command: The command to send to the shell.
        timeout: How long to wait for output (seconds).
    """
    kind, sid = parse_handle(handle)
    session = _sm.get(sid)
    if session is None:
        return f"SSH session {handle} not found. Call ssh_connect first."

    from utils.scope_gate import check_scan, ScopeGateError
    _sc_ok, _sc_reason = check_scan(session.metadata.get("hostname", ""))
    if not _sc_ok:
        raise ScopeGateError(f"scope gate: {_sc_reason}")

    try:
        channel = session.client.get_transport().open_session()
        channel.get_pty()
        channel.invoke_shell()
        channel.settimeout(float(timeout))

        import time

        # Drain any banner/motd the server sends on connect.
        time.sleep(0.5)
        if channel.recv_ready():
            channel.recv(4096)

        channel.send(command + "\n")
        time.sleep(1)

        output = b""
        while channel.recv_ready():
            output += channel.recv(4096)

        channel.close()
        return output.decode("utf-8", errors="replace")
    except Exception as e:
        return f"SSH shell error: {e}"


@framework_tool(
    "Close an SSH session and release the connection. Pass the 'ssh:' handle.",
    accepted_handle_kinds=["ssh"],
)
def ssh_close(handle: str):
    """
    Closes and removes a persistent SSH session.

    Args:
        handle: The 'ssh:' handle returned by ssh_connect.
    """
    kind, sid = parse_handle(handle)
    if _sm.close(sid):
        return f"Session {handle} closed."
    return f"Session {handle} not found."


@framework_tool(
    "List ALL active sessions across every namespace (ssh, msf, listener) "
    "as typed handles. Use this to see which sessions you currently hold "
    "and which tools to use on each. This is the single canonical way to "
    "inspect live sessions — do not use separate per-namespace listers."
)
def list_sessions():
    """
    Lists every active session the framework is holding, regardless of which
    tool created it.  Each line shows a typed handle and its target, grouped
    by namespace.  Pass the exact handle shown here to the matching tool
    (ssh_exec for ssh:, interact_session for msf:, close_listener for
    listener:).
    """
    sections = []

    # --- SessionManager: ssh, listener (all process-local) ---
    sm_sessions = _sm.list_sessions()
    ssh_lines = []
    listener_lines = []
    for s in sm_sessions:
        handle = format_handle(s["kind"], s["sid"])
        line = f"  {handle} -> {s['target']}"
        if s["kind"] == "listener":
            listener_lines.append(line)
        else:
            # ssh and any future process-local kinds land here.  Unknown
            # kinds still surface so the model is never blind to a session.
            ssh_lines.append(line)

    sections.append("SSH sessions:")
    sections.append("\n".join(ssh_lines) if ssh_lines else "  (none)")

    sections.append("Listener sessions:")
    sections.append("\n".join(listener_lines) if listener_lines else "  (none)")

    # --- Metasploit sessions (shared client, may live on the Brain) ---
    msf_lines = []
    try:
        from payloads.metasploiting import MetasploitClient

        client = getattr(MetasploitClient.get_instance(), "client", None)
        if client is not None:
            sessions = client.sessions.list
            for sid, info in sorted(sessions.items(), key=lambda kv: int(kv[0])):
                handle = format_handle("msf", str(sid))
                msf_lines.append(
                    f"  {handle} -> {info.get('target_host', '?')} "
                    f"({info.get('type', '?')})"
                )
    except Exception:
        # MSF not running / unreachable — report it explicitly so the model
        # knows the absence is real and not just an empty list.
        msf_lines.append("  (Metasploit client unavailable)")

    sections.append("MSF sessions:")
    sections.append("\n".join(msf_lines) if msf_lines else "  (none)")

    return "\n".join(sections)


# --- Backward-compatible one-shot (kept for callers that don't need a
#     persistent session) -----------------------------------------------

@framework_tool("Execute a single command via SSH using Paramiko (one-shot, no persistent session)")
def paramiko_client(hostname: str, username: str, password: str, command: str):
    """
    Connects to a remote host via SSH, executes a single command, and closes
    the connection immediately.  Legacy key negotiation is handled
    automatically (same fallback as ssh_connect).

    For persistent sessions that survive across multiple commands, use
    ssh_connect + ssh_exec + ssh_close instead.

    Args:
        hostname: The target IP or hostname.
        username: SSH username.
        password: SSH password.
        command: The shell command to execute.
    """
    from utils.scope_gate import check_scan, ScopeGateError
    _sc_ok, _sc_reason = check_scan(hostname)
    if not _sc_ok:
        raise ScopeGateError(f"scope gate: {_sc_reason}")
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname, username=username, password=password, timeout=10,
            allow_agent=False, look_for_keys=False,
        )
        # Bounded execution (2026-09-25): same hang shapes as ssh_exec
        # (stdin-waiting segments, daemon children holding the channel open).
        try:
            env = _run_ssh_command(client, command)
        except _SshExecTimeout:
            return (
                f"paramiko_client: command exceeded the "
                f"{DEFAULT_SSH_EXEC_TIMEOUT:.0f}s cap (SSH_EXEC_TIMEOUT) and "
                "was terminated."
            )
        client.close()
        return _format_ssh_result(env)
    except Exception as e:
        return f"SSH Connection Error: {e}"
