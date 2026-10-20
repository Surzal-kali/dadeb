"""ldapsearch wrapper — LDAP directory queries via subprocess (argv, no shell).

OpenLDAP's ``ldapsearch`` is already on the box (Debian apt,
``/usr/bin/ldapsearch``, OpenLDAP 2.6.14).  This module wraps it as
``@framework_tool`` callables so the secretary can query an LDAP directory
server directly — the structured primitive the NSE ``ldap-search`` script
approximates but cannot match for complex filters, paged results, or
attribute selection.

Why a dedicated wrapper (vs. the NSE script):
  The framework's nmap NSE lane exposes ``ldap-search`` as one of 600+
  scripts run inline with a port scan.  That is fine for a quick "dump the
  rootDSE" during host discovery, but it cannot:
    - take an arbitrary search filter (the NSE script's filter is
      ``--script-args searchFilter='...'`` — a string the model has to
      format for nmap, not ldapsearch, and nmap's quoting is hostile),
    - select specific attributes to return,
    - bind with credentials (the NSE script is anonymous-only in practice),
    - page large results (LDAP simple paged results control),
    - or return a structured, parseable result the model can chain from.

  ``ldapsearch`` itself is the right tool: it speaks LDAP natively, accepts
  a clean argv, and its LDIF output is line-oriented and parseable.  This
  wrapper gives the secretary that surface with scope-gating, credential
  handling, and a structured result envelope.

Tools:
- :func:`ldap_search` — the primary query tool.  Bind (anonymous or
  credentialed), search a base DN with a filter, select attributes, and
  return parsed entries + the raw LDIF.  Scope-gated (the target is a live
  directory server).
- :func:`ldap_rootdse` — fetch the rootDSE (naming contexts, supported
  controls, LDAP version, vendor).  The orientation call before a real
  search — tells you what base DNs exist.  Scope-gated.

Safety:
- Scope gate: ``check_scan(host)`` BEFORE every invocation; a refusal
  raises ``ScopeGateError`` (fail-closed — surfaces as Failed on both
  dispatch paths).  No scope armed = lab mode.
- argv list, ``shell=False``: target/credential/filter values are never
  interpolated into a shell string.
- ``-x`` (simple bind) is always set; SASL bind is not exposed (it adds
  negotiation complexity the secretary does not need for lab/bounty LDAP
  targets).
- ``-z`` (size limit) caps the result set so a huge directory cannot drown
  the chat; the raw LDIF is stored in scratch via the digest adapter.
- stdin is ``/dev/null`` so ldapsearch never blocks on an interactive
  password prompt (credentials come from the arguments, not a TTY).
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from constants import framework_tool
from utils.scope_gate import check_scan, ScopeGateError

# --- binary resolution -------------------------------------------------------

_LDAPSEARCH_CANDIDATES = (
    "/usr/bin/ldapsearch",
    "/usr/local/bin/ldapsearch",
    "/usr/sbin/ldapsearch",
)
_LDAPSEARCH_TIMEOUT = float(os.getenv("LDAPSEARCH_TIMEOUT", "60"))
# Default size limit (entries).  Override per-call with `size_limit`.
# 0 = no client-side limit (ldapsearch's own default; the server may still cap).
_DEFAULT_SIZE_LIMIT = int(os.getenv("LDAPSEARCH_DEFAULT_SIZE_LIMIT", "500"))


def _resolve_ldapsearch() -> Optional[str]:
    """Locate the ldapsearch binary; None = not installed (caller reports)."""
    found = shutil.which("ldapsearch")
    if found and os.access(found, os.X_OK):
        return found
    for cand in _LDAPSEARCH_CANDIDATES:
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


# --- LDIF parsing -----------------------------------------------------------
#
# LDIF (LDAP Data Interchange Format) is line-oriented:
#   dn: cn=user,ou=people,dc=example,dc=com
#   cn: user
#   cn:: <base64-encoded value>
#   memberUid: user1
#   memberUid: user2
#   <blank line separates entries>
#
# Folded lines (continuation) start with a space; we unfold first.
# Base64-encoded values (:: suffix) are decoded; URL values (< suffix) are
# noted but not fetched.  This is a conservative parser — it does not try to
# handle every LDIF edge case (change records, modify-increment), only the
# search-result format ldapsearch emits by default.

_B64_RE = re.compile(r"^[A-Za-z0-9+/]+=*$")


def _unfold_ldif(text: str) -> List[str]:
    """Unfold LDIF continuation lines (a line starting with space continues
    the previous line)."""
    lines: List[str] = []
    for raw in text.splitlines():
        if raw.startswith(" "):
            if lines:
                lines[-1] += raw[1:]
            else:
                lines.append(raw[1:])
        else:
            lines.append(raw)
    return lines


def _decode_value(value: str, is_base64: bool) -> str:
    """Decode a single attribute value (base64 or plain)."""
    if is_base64:
        import base64
        try:
            return base64.b64decode(value).decode("utf-8", errors="replace")
        except Exception:
            return f"<base64 decode failed: {value[:40]}>"
    return value


def _parse_ldif(text: str) -> List[Dict[str, Any]]:
    """Parse LDIF text into a list of entry dicts.

    Each entry is ``{"dn": str, "attributes": {name: [values]}}``.
    Multi-valued attributes produce a list; single-valued produce a
    one-element list (callers can flatten).  Base64-encoded values
    (``attr::``) are decoded; URL values (``attr:<``) are marked.
    """
    import base64 as _b64

    lines = _unfold_ldif(text)
    entries: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None

    for line in lines:
        if not line.strip():
            # Blank line = end of entry (if any).
            if current is not None:
                entries.append(current)
                current = None
            continue

        # Skip comments and search-result metadata lines.
        if line.startswith("#"):
            continue
        if line.startswith(("search result", "search reference", "# numEntries",
                            "# numReferences", "result:")):
            continue

        # Split attr: value or attr:: base64 or attr:< url
        if "::" in line and line.split("::", 1)[0] and ":" not in line.split("::", 1)[0]:
            # base64-encoded value: attr:: <base64>
            attr, _, value = line.partition("::")
            attr = attr.strip()
            value = value.strip()
            try:
                decoded = _b64.b64decode(value).decode("utf-8", errors="replace")
            except Exception:
                decoded = f"<base64 decode failed: {value[:40]}>"
            is_b64 = True
        elif ":<" in line:
            attr, _, value = line.partition(":<")
            attr = attr.strip()
            value = value.strip()
            decoded = f"<url: {value}>"
            is_b64 = False
        elif ":" in line:
            attr, _, value = line.partition(":")
            attr = attr.strip()
            value = value.strip()
            decoded = value
            is_b64 = False
        else:
            continue

        attr_lower = attr.lower()

        if attr_lower == "dn":
            if current is not None:
                entries.append(current)
            current = {"dn": decoded, "attributes": {}}
            continue

        if current is None:
            # Stray attribute before a dn — skip it.
            continue

        current["attributes"].setdefault(attr, []).append(decoded)

    if current is not None:
        entries.append(current)

    return entries


# --- shared argv builder ----------------------------------------------------

def _build_argv(
    host: str,
    port: int,
    base_dn: str,
    scope: str,
    filter_str: str,
    attributes: List[str],
    bind_dn: str,
    bind_password: str,
    size_limit: int,
    timeout: float,
    extra_options: str,
    *,
    is_rootdse: bool = False,
) -> List[str]:
    """Build the ldapsearch argv list (no shell, no interpolation)."""
    binary = _resolve_ldapsearch()
    if not binary:
        # Let the caller produce a clear error.
        binary = "ldapsearch"

    argv: List[str] = [binary, "-x"]  # simple bind, always

    # Host and port.
    argv.extend(["-H", f"ldap://{host}:{int(port)}"])

    # Credentials.
    if bind_dn:
        argv.extend(["-D", bind_dn])
        if bind_password:
            argv.extend(["-w", bind_password])
        else:
            # Empty password: pass an explicit empty string so ldapsearch
            # does NOT eat the next argv element as the password.  The
            # previous `argv.append("-w" "")` was Python string-literal
            # concatenation — it appended just "-w" (no value), so
            # ldapsearch consumed the next flag (-z / -l / -s) as the
            # password, silently corrupting the entire command line.
            argv.extend(["-w", ""])
    # Anonymous bind: no -D/-w (ldapsearch's default).

    # Size limit and timeout.
    if size_limit and size_limit > 0:
        argv.extend(["-z", str(int(size_limit))])
    argv.extend(["-l", str(int(timeout))])

    # Scope.
    if not is_rootdse:
        scope_norm = scope.strip().lower()
        if scope_norm not in ("base", "one", "sub"):
            scope_norm = "sub"
        argv.extend(["-s", scope_norm])

    # Extra options (operator passthrough, validated by shlex).
    if extra_options:
        argv.extend(shlex.split(extra_options))

    # Base DN.
    if is_rootdse:
        argv.extend(["-s", "base", "-b", ""])
        # rootDSE: base scope, empty base, objectClass=* filter.
        argv.append("(objectClass=*)")
    else:
        argv.extend(["-b", base_dn])
        argv.append(filter_str or "(objectClass=*)")

    # Attributes to return (after the filter).
    if attributes:
        argv.extend(attributes)

    return argv


def _run_ldapsearch(argv: List[str], timeout: float) -> Dict[str, Any]:
    """Run ldapsearch and return a structured result dict.

    Never raises to the caller — errors are surfaced in the result envelope.
    """
    binary = argv[0]
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "Failed",
            "error": f"ldapsearch timed out after {timeout}s",
            "stdout": "",
            "stderr": "",
        }
    except FileNotFoundError:
        return {
            "status": "Failed",
            "error": (
                "binary 'ldapsearch' not found (checked PATH, /usr/bin/ldapsearch, "
                "/usr/local/bin/ldapsearch). Install ldap-utils (Debian: "
                "apt install ldap-utils) or set LDAPSEARCH_BIN in .env."
            ),
            "stdout": "",
            "stderr": "",
        }
    except Exception as exc:
        return {
            "status": "Failed",
            "error": f"Error running ldapsearch: {exc}",
            "stdout": "",
            "stderr": "",
        }

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""

    # ldapsearch exit codes: 0 = success, 32 = no such object (not an error
    # for recon — the base DN doesn't exist), 4 = size limit exceeded
    # (partial results are still useful).
    rc = proc.returncode
    size_limited = rc == 4
    no_such_object = rc == 32

    if rc != 0 and not size_limited and not no_such_object:
        # Real failure — surface the stderr (which carries the LDAP error
        # string, e.g. "ldap_bind: Invalid credentials (49)").
        # Keep the exit code and the stderr on separate lines so the AD
        # sub-code ("data 52e" = ERROR_LOGON_FAILURE, 0x52e = 1326) is
        # not visually conflated with the process exit code (49).  The
        # previous one-line format "exit 49: ... data 52e ..." read like
        # "exit code 52" at a glance.
        return {
            "status": "Failed",
            "error": (
                f"ldapsearch exit code {rc}\n"
                f"stderr: {stderr.strip() or '(no stderr)'}"
            ),
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": rc,
        }

    entries = _parse_ldif(stdout)

    return {
        "status": "Success" if not no_such_object else "Success",
        "entries": entries,
        "entry_count": len(entries),
        "raw_ldif": stdout,
        "size_limited": size_limited,
        "no_such_object": no_such_object,
        "exit_code": rc,
        "stderr": stderr.strip() if stderr.strip() else None,
    }


# --- result digest ----------------------------------------------------------

def _ldap_search_digest(result: Dict[str, Any]) -> Dict[str, Any]:
    """Digest adapter for ``ldap_search`` — entry count + DN list only.

    The full LDIF (which can be thousands of lines for a large directory) is
    stored in scratch; the model gets:
    - status + entry count
    - the DN list (small, critical — shows what was returned)
    - size_limited / no_such_object flags
    - exit code

    The model rarely needs the raw LDIF to decide the next action — the DN
    list + entry count IS the actionable signal.  When it needs attribute
    values for a specific entry, it retrieves from scratch.
    """
    parts: list = []

    status = result.get("status", "unknown")
    parts.append(f"status={status}")

    entries = result.get("entries", [])
    parts.append(f"entries={len(entries)}")

    if entries:
        dn_list = [e.get("dn", "?") for e in entries[:30]]
        dn_lines = "\n  ".join(dn_list)
        parts.append(f"dn_list:\n  {dn_lines}")
        if len(entries) > 30:
            parts.append(f"  ... +{len(entries) - 30} more (retrieve full list from scratch)")

    if result.get("size_limited"):
        parts.append("size_limited=True")
    if result.get("no_such_object"):
        parts.append("no_such_object=True (base DN does not exist)")

    exit_code = result.get("exit_code")
    if exit_code is not None and exit_code != 0:
        parts.append(f"exit_code={exit_code}")

    stderr = result.get("stderr")
    if stderr:
        parts.append(f"stderr={stderr[:200]}")

    summary = " | ".join(parts)
    row_hint = (
        "scratch_search scratch:<id> --filter 'dn' "
        "# pull specific entries from the full LDIF"
    )
    return {"summary": summary, "row_hint_format": row_hint}


# --- tools ------------------------------------------------------------------

@framework_tool(
    "Query an LDAP directory server with ldapsearch: bind (anonymous or "
    "credentialed), search a base DN with a filter, and return parsed "
    "entries (DN + attributes) plus the raw LDIF. The primary LDAP "
    "directory query tool — use this instead of the nmap NSE ldap-search "
    "script when you need a custom filter, attribute selection, "
    "credentials, or paged results. Supports base/one/sub scope. Call "
    "ldap_rootdse first to discover the directory's naming contexts (base "
    "DNs) if you don't know them. Scope-gated (the target is a live "
    "directory server). Examples: enumerate users "
    "(filter='(objectClass=person)' base='dc=example,dc=com'), find "
    "groups (filter='(objectClass=group)'), extract computer accounts "
    "(filter='(objectClass=computer)').",
    next_hints=["ldap_rootdse", "report_finding", "kerberoast (if SPN accounts found)"],
    tags=["net.services"],
    result_digest=lambda r: _ldap_search_digest(r),
)
def ldap_search(
    host: str,
    base_dn: str,
    filter: str = "(objectClass=*)",
    scope: str = "sub",
    attributes: str = "",
    bind_dn: str = "",
    bind_password: str = "",
    port: int = 389,
    size_limit: int = 0,
    timeout: float = 30.0,
    extra_options: str = "",
) -> Dict[str, Any]:
    """Search an LDAP directory via ``ldapsearch``.

    Binds (anonymously by default, or with credentials when ``bind_dn`` is
    set), searches ``base_dn`` with ``filter`` at the given scope, and
    returns parsed entries plus the raw LDIF.  Scope-gated.

    Args:
        host: Target LDAP server (IP or hostname).  Scope-gate checked
            before the call.
        base_dn: The base DN to search from, e.g.
            ``"dc=example,dc=com"`` or ``"ou=users,dc=corp,dc=local"``.
        filter: LDAP search filter, e.g. ``"(objectClass=person)"``,
            ``"(&(objectClass=user)(uid=*))"``,
            ``"(cn=admin)"``.  Default ``(objectClass=*)`` matches
            everything.
        scope: Search scope — ``"base"`` (base only), ``"one"`` (one
            level), or ``"sub"`` (whole subtree, default).
        attributes: Comma-separated or space-separated attribute names to
            return (e.g. ``"cn,uid,mail,memberUid"``).  Empty = all
            attributes (ldapsearch default).
        bind_dn: DN to bind as (e.g. ``"cn=admin,dc=example,dc=com"``).
            Empty = anonymous bind.
        bind_password: Password for ``bind_dn``.  Empty with a non-empty
            ``bind_dn`` = empty-password simple bind (some directories
            accept this for specific accounts).
        port: LDAP port (default 389; 636 for LDAPS — see extra_options
            for TLS).
        size_limit: Maximum entries to request (``-z``).  0 = no client-side
            limit (the server may still cap; default from
            ``LDAPSEARCH_DEFAULT_SIZE_LIMIT`` env, 500).
        timeout: Per-operation timeout in seconds (``-l``).  Default 30.
        extra_options: Extra ldapsearch flags as a single string (e.g.
            ``"-ZZ"`` for StartTLS, ``"-L"`` for LDIF without version
            header, ``"-E pr=100/noprompt"`` for paged results).  Parsed
            with shlex.
    """
    ok, reason = check_scan(host)
    if not ok:
        raise ScopeGateError(f"scope gate: {reason}")

    if not base_dn or not base_dn.strip():
        return {
            "status": "Failed",
            "error": "base_dn is required (call ldap_rootdse to discover naming contexts)",
        }

    binary = _resolve_ldapsearch()
    if not binary:
        return {
            "status": "Failed",
            "error": (
                "binary 'ldapsearch' not found (checked PATH, "
                "/usr/bin/ldapsearch, /usr/local/bin/ldapsearch). Install "
                "ldap-utils (Debian: apt install ldap-utils)."
            ),
        }

    # Parse attributes (comma or space separated).
    attr_list: List[str] = []
    if attributes and attributes.strip():
        attr_list = [a.strip() for a in re.split(r"[,\s]+", attributes.strip()) if a.strip()]

    effective_size_limit = size_limit if size_limit and size_limit > 0 else _DEFAULT_SIZE_LIMIT
    effective_timeout = min(float(timeout), _LDAPSEARCH_TIMEOUT)

    argv = _build_argv(
        host=host,
        port=port,
        base_dn=base_dn,
        scope=scope,
        filter_str=filter,
        attributes=attr_list,
        bind_dn=bind_dn,
        bind_password=bind_password,
        size_limit=effective_size_limit,
        timeout=effective_timeout,
        extra_options=extra_options,
    )

    result = _run_ldapsearch(argv, effective_timeout + 5)
    # Annotate with the query context for the digest / scratch.
    result["query"] = {
        "host": host,
        "port": port,
        "base_dn": base_dn,
        "filter": filter,
        "scope": scope,
        "bind_dn": bind_dn or "(anonymous)",
    }
    return result


@framework_tool(
    "Fetch the LDAP rootDSE from a directory server: naming contexts (base "
    "DNs), supported LDAP controls, LDAP protocol version, vendor/product, "
    "and supported SASL mechanisms. The orientation call before a real "
    "ldap_search — tells you what base DNs exist so you don't guess. "
    "Anonymous bind. Scope-gated.",
    next_hints=["ldap_search with a discovered namingContext as base_dn"],
    tags=["net.services"],
)
def ldap_rootdse(
    host: str,
    port: int = 389,
    timeout: float = 15.0,
    extra_options: str = "",
) -> Dict[str, Any]:
    """Fetch the rootDSE from an LDAP server.

    The rootDSE is a special entry (base scope, empty base DN) that
    describes the directory: naming contexts (the base DNs you can search),
    supported controls, LDAP version, vendor, and more.  Call this first to
    discover base DNs before running ``ldap_search``.

    Args:
        host: Target LDAP server (IP or hostname).  Scope-gate checked.
        port: LDAP port (default 389).
        timeout: Per-operation timeout in seconds.  Default 15.
        extra_options: Extra ldapsearch flags (e.g. ``"-ZZ"`` for StartTLS).
    """
    ok, reason = check_scan(host)
    if not ok:
        raise ScopeGateError(f"scope gate: {reason}")

    binary = _resolve_ldapsearch()
    if not binary:
        return {
            "status": "Failed",
            "error": (
                "binary 'ldapsearch' not found (checked PATH, "
                "/usr/bin/ldapsearch, /usr/local/bin/ldapsearch). Install "
                "ldap-utils (Debian: apt install ldaputils)."
            ),
        }

    effective_timeout = min(float(timeout), _LDAPSEARCH_TIMEOUT)

    argv = _build_argv(
        host=host,
        port=port,
        base_dn="",
        scope="base",
        filter_str="(objectClass=*)",
        attributes=[],
        bind_dn="",
        bind_password="",
        size_limit=0,
        timeout=effective_timeout,
        extra_options=extra_options,
        is_rootdse=True,
    )

    result = _run_ldapsearch(argv, effective_timeout + 5)
    result["query"] = {
        "host": host,
        "port": port,
        "base_dn": "(rootDSE)",
        "filter": "(objectClass=*)",
        "scope": "base",
        "bind_dn": "(anonymous)",
    }

    # Extract naming contexts for quick visibility.
    if result.get("entries"):
        entry = result["entries"][0]
        naming_contexts = entry.get("attributes", {}).get("namingContexts", [])
        if naming_contexts:
            result["naming_contexts"] = naming_contexts

    return result