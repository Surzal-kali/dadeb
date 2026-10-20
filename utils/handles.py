"""Typed session handles for cross-tool session disambiguation.

A *handle* is a string of the form ``"<kind>:<opaque-id>"`` where ``<kind>``
names the session namespace.  Tools that consume a session declare which kinds
they accept via ``@framework_tool(..., accepted_handle_kinds=[...])``; the
registry validates that a passed handle's kind is in that set *before*
execution, raising a ``ModelRetry`` that points the model at the correct tool
instead of letting the call fail opaquely at execution time.

Kinds:
    ssh       - a paramiko SessionManager session  (id: ``sess-NNNN``) -> ``ssh:sess-0001``
    msf       - a Metasploit session (id: numeric)                 -> ``msf:1``
    listener  - a locally-bound listener service                    -> ``listener:tcp-4444``
    collab    - the OOB collaborator listener                       -> ``collab:<id>``
    db        - a direct-database connection (auxiliaries/db_client.py)
              -> ``db:sess-0001``

The kind prefix makes the namespace unforgeable as a string: an ``ssh:`` handle
can never be silently passed to a Metasploit-only tool because the prefix will
not validate.

Backdoors are not a separate kind: a backdoor on the target (e.g. vsftpd
2.3.4 port 6200) is popped via a Metasploit exploit module, which yields an
``msf:`` handle.  A reverse-shell callback you need to catch is a ``listener:``
handle from ``open_listener``.  That covers both directions without a custom
raw-shell client.
"""

from __future__ import annotations

from typing import Optional, Tuple

HANDLE_SEPARATOR = ":"

# The closed set of namespaces.  Adding a new session type means: (1) extend
# this set, (2) emit handles from the creating tool, (3) declare
# accepted_handle_kinds on the consuming tools.
VALID_KINDS = {"ssh", "msf", "listener", "collab", "db"}


def format_handle(kind: str, sid: str) -> str:
    """Build a typed handle string ``"<kind>:<sid>"``.

    Raises ValueError on unknown kinds or empty ids so bugs surface at the
    producing tool rather than confusing the model later.
    """
    if kind not in VALID_KINDS:
        raise ValueError(f"Unknown handle kind: {kind!r} (valid: {sorted(VALID_KINDS)})")
    if not isinstance(sid, str):
        sid = str(sid)
    if not sid:
        raise ValueError(f"Handle id for kind {kind!r} is empty")
    if HANDLE_SEPARATOR in kind:
        raise ValueError(f"Kind {kind!r} must not contain ':'")
    return f"{kind}{HANDLE_SEPARATOR}{sid}"


def parse_handle(handle: str) -> Tuple[str, str]:
    """Return ``(kind, sid)`` from a handle string.

    Raises ValueError if the handle is malformed or carries an unknown kind,
    so callers can distinguish "the model passed garbage" from "the model
    passed the wrong namespace".
    """
    if not isinstance(handle, str) or HANDLE_SEPARATOR not in handle:
        raise ValueError(
            f"Malformed handle {handle!r}; expected '<kind>:<id>' "
            f"(e.g. 'ssh:sess-0001', 'msf:1')"
        )
    kind, sid = handle.split(HANDLE_SEPARATOR, 1)
    if kind not in VALID_KINDS:
        raise ValueError(
            f"Unknown handle kind {kind!r} in {handle!r} "
            f"(valid: {sorted(VALID_KINDS)})"
        )
    if not sid:
        raise ValueError(f"Empty id in handle {handle!r}")
    return kind, sid


def handle_kind(handle: str) -> Optional[str]:
    """Best-effort kind extraction; returns ``None`` on any malformed handle."""
    try:
        return parse_handle(handle)[0]
    except (ValueError, TypeError):
        return None


def validate_handle_for_tool(handle: str, accepted_kinds) -> Optional[str]:
    """Return ``None`` if ``handle`` is acceptable for a tool that declares
    ``accepted_kinds``; otherwise return a human-readable reason string that
    is suitable to feed back to the model as a ``ModelRetry`` message.

    ``accepted_kinds`` is any iterable of kind strings (possibly empty).
    An empty set means the tool does not take a handle at all.
    """
    if not accepted_kinds:
        return None
    try:
        kind, _sid = parse_handle(handle)
    except ValueError as exc:
        return (
            f"{handle!r} is not a valid session handle: {exc}. "
            "Handles look like 'ssh:sess-0001' or 'msf:1'."
        )
    accepted = set(accepted_kinds)
    if kind not in accepted:
        # Point the model at the right tool family for the handle it already
        # holds, so the retry converges instead of looping.
        guidance = {
            "ssh": "Use an ssh_* tool (ssh_exec / ssh_shell / ssh_close).",
            "msf": "Use interact_session / close_msf_session.",
            "listener": "Use close_listener to stop a bound listener.",
            "collab": "Use collab_stop to stop the collaborator listener.",
            "db": "Use db_exec / db_close (db_schema_farm takes creds directly).",
        }.get(kind, "")
        return (
            f"Handle {handle!r} is kind '{kind}' but this tool accepts only "
            f"{sorted(accepted)}. {guidance}".strip()
        )
    return None


__all__ = [
    "HANDLE_SEPARATOR",
    "VALID_KINDS",
    "format_handle",
    "parse_handle",
    "handle_kind",
    "validate_handle_for_tool",
]
