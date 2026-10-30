"""Agent identity resolution — the announce-or-mint choke point (Phase 0).

Every conversational lane (REST, MCP, REPL, kernel) that dispatches a tool
must carry ONE resolved ``agent_id``. Before this module the harness had
three spellings of "nobody": ``"0"`` (executor/scratch/budget default),
``"secretary"`` (evidence ledger default) and ``'unknown'`` (PG schema
default) — and three separate actors (REST callers without agent_id, the
REPL, the kernel lane) silently landed in the shared ``"0"`` session,
sharing one Brain tool-instance space and one budget bucket.

Resolution rule ("2.5-tier", scale-doctrine Annex B):

  1. **Announced** — the caller passes ``agent_id`` (``owui:...``,
     ``kai9000:...``, a fleet client's id, ...). Used verbatim after
     normalization; never second-guessed per-frontend.
  2. **Shared** — the caller passes ``"0"`` explicitly. This stays a
     MEANINGFUL operator opt-in for shared Brain tool-instance state, but
     it is now never a silent default.
  3. **Minted** — nothing announced: the gateway mints ``anon-<8hex>``
     into the response envelope (``identity`` block). A client that wants
     continuity adopts it on its next call, at which point it is simply a
     declared id. An anon id that is never adopted ages out under each
     store's existing TTL regime (scratch 24h, jobs per store TTL,
     journal engagement purge) — it is *ephemeral by intent*, and the
     mint registry lives in gateway process memory only.

Provenance returned alongside the id: ``declared`` | ``shared`` |
``minted``. Tools writing identity-bearing rows journal the resolved id
plus provenance so "which actors are actually pinned vs anonymous" is
answerable from day one.

Reserved prefixes — normalization is adversarial at 30 actors:

  - ``anon-`` is gateway-reserved: a client *announcing* ``anon-x`` is
    re-minted (treated as untrusted-minted-equivalent, not an identity),
    so a spoofable namespace never becomes a durable owner tag. THE
    exception is adoption: an ``anon-`` id that THIS process minted
    (``is_minted`` — process-local registry) is accepted verbatim as
    declared. Adoption is the continuity hinge — the gateway mints,
    the client echoes the id back, and the resolver returns the SAME
    id instead of minting a fresh one every call for a cycle (2026-10-30
    code review: the executor re-resolved the gateway's already-minted
    id, which re-minted, so the executor ALWAYS ran as a different
    identity than the gateway reported). The same-process check keeps
    a foreign ``anon-*`` spoof unusable; an adopted id refreshes its
    registry entry so live adoption outlives the bounded registry's
    eviction.
  - ``0`` is the shared-session escape hatch and is accepted only as the
    exact string ``"0"``.

Ambient identity: a ``ContextVar`` carries the resolved id into tool
bodies (``asyncio.to_thread`` copies context, so in-process fallback and
threaded Brain workers inherit it). ContextVar default is ``"0"`` — that
is the *transport's* fallback for calls that bypass the resolver, and
tool-visible identity is only ever as good as the dispatch lane. The
executor sets it around every dispatch; the Brain worker threads set it
from the wire session so identity-bearing tool writes inside the sidecar
are distinct per agent there too (as ``s<int>`` — the wire protocol
carries the executor's resolved int, not the string; the authoritative
string id is journaled by the dispatching executor's own journal row).

Scope note (Phase 0.5, shipped 2026-10-30): the MCP wire still accepts
``agent_id`` as a tool argument for backwards compatibility (explicit
per-call announcement wins, always). The MCP ``initialize`` handshake now
also carries identity: ``X-Daharness-Agent-Id`` header, or ``agent_id``
inside the request's ``params._meta`` (or ``params.clientInfo``) extras.
A handshake announcement is registered per client fingerprint
(``client_ip, user_agent``) and pins later ``tools/call`` requests that
carry NO announcement of their own — an operator-wired client announces
once on connect instead of on every call. Handshake entries are TTL'd
(``MCP_HANDSHAKE_TTL_HOURS``) and bounded; the registry is process-local
diagnostic state, like everything in this module. Clients that never
announce keep today's exact behavior (per-call mint, or the ``"0"`` tail
on the scratch lane). Note: a pinned identity also makes the per-turn
budget accrue per connection instead of per mint-never-repeating call —
that brake is now effective for announcing MCP clients, as intended.
"""

from __future__ import annotations

import os
import re
import secrets
import threading
import time
from contextlib import contextmanager
from contextvars import ContextVar, Token

# --- Canonical constants ------------------------------------------------------

#: The explicit shared-session id. Accepted as an operator opt-in only.
SHARED_AGENT_ID = "0"

#: Gateway-reserved mint prefix. Clients announcing it are re-minted.
ANON_PREFIX = "anon-"

#: Normalized announced ids live in this charset, lowercased, 3..64 chars.
_AGENT_ID_RE = re.compile(r"^[a-z0-9_.:\-]{3,64}$")

_PROVENANCE_DECLARED = "declared"
_PROVENANCE_SHARED = "shared"
_PROVENANCE_MINTED = "minted"

# --- Ambient identity ----------------------------------------------------------

_current_agent_id: ContextVar[str] = ContextVar("daharness_agent_id", default=SHARED_AGENT_ID)


def current_agent_id() -> str:
    """The ambient resolved identity for the running context.

    Dispatch lanes set this (executor around every dispatch, Brain per
    worker thread, REPL wrappers). Transport fallback is the shared id
    ``"0"``, matching the pre-Phase-0 default so any call path that never
    resolved an identity behaves exactly as before.
    """
    return _current_agent_id.get()


def set_current_agent_id(agent_id: str) -> Token:
    """Set the ambient identity; returns the token for ``reset``."""
    return _current_agent_id.set(str(agent_id or SHARED_AGENT_ID))


def reset_current_agent_id(token: Token) -> None:
    _current_agent_id.reset(token)


@contextmanager
def agent_id_context(agent_id: str):
    """Context-scoped ambient identity (tests, wrapped tool lanes)."""
    token = set_current_agent_id(agent_id)
    try:
        yield str(agent_id or SHARED_AGENT_ID)
    finally:
        reset_current_agent_id(token)


# --- Mint registry (process-local, adopt-on-echo hinge) ------------------------

_MINTED: dict[str, float] = {}
_MINTED_LOCK = threading.Lock()
_MINTED_MAX = 1000  # bounded; anon ids are ephemeral by intent


def _register_mint(agent_id: str) -> None:
    now = time.time()
    with _MINTED_LOCK:
        _MINTED[agent_id] = now
        if len(_MINTED) > _MINTED_MAX:
            # Drop the oldest third — anon ids are session-scoped by design.
            for k in sorted(_MINTED, key=lambda k: _MINTED[k])[: _MINTED_MAX // 3]:
                _MINTED.pop(k, None)


def is_minted(agent_id: str) -> bool:
    """Whether this id was minted by THIS process (diagnostic, not security)."""
    with _MINTED_LOCK:
        return agent_id in _MINTED


# --- Resolution ----------------------------------------------------------------


def normalize_agent_id(raw: str | None) -> str | None:
    """Normalize an announced id, or ``None`` when unusable.

    Charset ``[a-z0-9_.:-]{3,64}``, lowercased and stripped. Anything else
    (empty, oversized, odd charset) is unusable and the resolver mints
    instead. The reserved mint prefix is unusable too — UNLESS this
    process minted it (adopt-on-echo: the gateway's own minted id comes
    back and resolves to itself, not to a fresh mint).
    """
    if raw is None:
        return None
    candidate = str(raw).strip().lower()
    if not candidate:
        return None
    # The mint prefix is gateway-reserved even as an announcement —
    # except this process's own mints, which the adopter echoes back.
    if candidate.startswith(ANON_PREFIX):
        if is_minted(candidate):
            # Refresh the registry entry: an adopted id is a live
            # identity, not an aging one — outlive mint-registry eviction.
            _register_mint(candidate)
            return candidate
        return None
    if not _AGENT_ID_RE.fullmatch(candidate):
        return None
    return candidate


def mint_agent_id() -> str:
    """Mint a fresh ephemeral ``anon-<8hex>`` identity."""
    agent_id = f"{ANON_PREFIX}{secrets.token_hex(4)}"
    _register_mint(agent_id)
    return agent_id


def resolve_agent_id(raw: str | None) -> tuple[str, str]:
    """Resolve one identity: ``(agent_id, provenance)``.

    - usable announcement -> ``(normalized, "declared")``
    - exact ``"0"``       -> ``("0", "shared")``
    - an ``anon-`` id this process minted -> ``(itself, "declared")``
      (adopt-on-echo — the continuity hinge: echoing a minted id back
      resolves to the SAME id, never a fresh mint)
    - anything else (None, empty, bad charset, a foreign ``anon-``
      prefix) -> freshly minted (``"minted"``)

    This is the ONLY place minting happens; stores downstream must never
    carry a default (``NOT NULL`` columns, resolved callers only).
    """
    if raw is not None and str(raw).strip() == SHARED_AGENT_ID:
        return SHARED_AGENT_ID, _PROVENANCE_SHARED
    normalized = normalize_agent_id(raw)
    if normalized is not None:
        return normalized, _PROVENANCE_DECLARED
    return mint_agent_id(), _PROVENANCE_MINTED


# --- Lane identities -----------------------------------------------------------

#: The REPL/kernel lane announces itself explicitly (never lands in "0").
REPL_AGENT_ID = "repl"
#: Brain-side workers set the contextvar from the wire session int under
#: this prefix (the wire carries the executor's resolved int, not the string).
BRAIN_AGENT_PREFIX = "s"


# --- MCP lane: initialize-time client identity (Phase 0.5) ----------------------

#: Per-call announcement header on /mcp POSTs (initialize + tools/call).
MCP_AGENT_ID_HEADER = "x-daharness-agent-id"

#: Key this framework reads inside MCP ``params._meta`` (and inside
#: ``params.clientInfo``) extras on ``initialize``. Pydantic allows extra
#: keys, so a client can announce without any schema change.
MCP_META_AGENT_ID_KEY = "agent_id"

_MCP_HANDSHAKE: dict[tuple[str, str], tuple[str, str, float]] = {}
_MCP_HANDSHAKE_LOCK = threading.Lock()
#: Bounded like the mint registry — one entry per live MCP client connection.
_MCP_HANDSHAKE_MAX = 1024


def _mcp_handshake_ttl_hours() -> float:
    try:
        return float(os.getenv("MCP_HANDSHAKE_TTL_HOURS", "24"))
    except (TypeError, ValueError):
        return 24.0


def mcp_fingerprint(client_ip, user_agent) -> tuple[str, str]:
    """Correlation fingerprint shared by the initialize + call sides.

    Deliberately coarse ``(client_ip, user_agent)`` — best-effort continuity
    for announcing clients, never an authenticity claim (the /mcp lane is
    already API-key authenticated; identity here is accounting).
    """
    return (str(client_ip or ""), str(user_agent or "")[:256])


def register_mcp_handshake(fingerprint, agent_id: str, provenance: str) -> None:
    """Pin a resolved initialize-time identity to a client fingerprint.

    Only the gateway's initialize handler registers — per-connection state,
    resolved once through ``resolve_agent_id`` (announce-or-mint), never
    second-guessed here."""
    if not fingerprint or not agent_id:
        return
    with _MCP_HANDSHAKE_LOCK:
        _MCP_HANDSHAKE[fingerprint] = (agent_id, provenance, time.time())
        if len(_MCP_HANDSHAKE) > _MCP_HANDSHAKE_MAX:
            for k in sorted(_MCP_HANDSHAKE, key=lambda k: _MCP_HANDSHAKE[k][2])[
                : _MCP_HANDSHAKE_MAX // 2
            ]:
                _MCP_HANDSHAKE.pop(k, None)


def lookup_mcp_handshake(fingerprint) -> tuple[str, str] | None:
    """The initialize-time identity for this fingerprint, or None.

    TTL'd (swept on access) and refreshed on hit, so a live connection stays
    pinned while dead clients age out under the same 24h convention as
    scratch. No match (never-announcing clients) means the caller falls
    through to per-call mint/``"0"`` — today's exact behavior.
    """
    if not fingerprint:
        return None
    cutoff = time.time() - _mcp_handshake_ttl_hours() * 3600
    with _MCP_HANDSHAKE_LOCK:
        entry = _MCP_HANDSHAKE.get(fingerprint)
        if entry is None:
            return None
        agent_id, provenance, registered_at = entry
        if registered_at < cutoff:
            _MCP_HANDSHAKE.pop(fingerprint, None)
            return None
        _MCP_HANDSHAKE[fingerprint] = (agent_id, provenance, time.time())
        return agent_id, provenance


def extract_meta_agent_id(meta) -> str | None:
    """Read the announcement from a request's ``_meta``, or None.

    The MCP SDK parses ``params._meta`` into ``RequestParams.Meta`` with
    ``extra='allow'``, so client-added keys arrive as model extras; raw
    dict payloads arrive dict-shaped. Duck-typed so this module never
    imports mcp.
    """
    if meta is None:
        return None
    if isinstance(meta, dict):
        raw = meta.get(MCP_META_AGENT_ID_KEY)
    else:
        raw = getattr(meta, MCP_META_AGENT_ID_KEY, None)
        if raw is None:
            extra = getattr(meta, "model_extra", None)
            raw = extra.get(MCP_META_AGENT_ID_KEY) if isinstance(extra, dict) else None
    if raw is None:
        return None
    return str(raw).strip() or None


def resolve_mcp_call_identity(
    announced: str | None = None,
    call_meta=None,
    http_headers=None,
    client_ip=None,
    user_agent=None,
    fallback_shared: bool = False,
    fingerprint=None,
) -> tuple[str, str]:
    """One resolution chain for the gateway's /mcp call lane.

    Precedence:
      1. ``announced`` — the ``agent_id`` TOOL ARGUMENT (backwards compat,
         explicit per-call, wins over everything).
      2. ``params._meta`` ``agent_id`` extra on the call itself.
      3. the ``X-Daharness-Agent-Id`` HTTP header on the call.
      4. the initialize-time handshake pin for this client fingerprint.
      5. mint (``anon-<8hex>``) — or, when ``fallback_shared`` (the scratch
         lane), the legacy shared ``"0"`` bucket a ref-less retrieval can
         still address.

    Returns ``(agent_id, provenance)`` like ``resolve_agent_id``; lanes
    that pass no context at all resolve exactly like the pre-Phase-0.5
    argument-only lane did.
    """
    announcement = announced
    if announcement is None:
        announcement = extract_meta_agent_id(call_meta)
    if announcement is None and http_headers is not None:
        getter = getattr(http_headers, "get", None)
        announcement = getter(MCP_AGENT_ID_HEADER) if getter else None
    if announcement is not None and str(announcement).strip():
        return resolve_agent_id(str(announcement))
    if fingerprint is None:
        fingerprint = mcp_fingerprint(client_ip, user_agent)
    pinned = lookup_mcp_handshake(fingerprint)
    if pinned is not None:
        return pinned
    if fallback_shared:
        return SHARED_AGENT_ID, _PROVENANCE_SHARED
    return resolve_agent_id(None)