"""Web-session fingerprint lacing + host-floor pacing (evasion L3).

Consumed by auxiliaries/web_session (single choke point: _merge_headers +
_do_session_request). Readiness framing (user ruling Oct 17): exercise on
lab targets unless a permitting contract exists.

IDENTITY CONTRACT (one enforced identity, not four knobs)
---------------------------------------------------------
A web-session hop is ONE identity: UA claim, TLS fingerprint, header set
and header ORDER. Those four must agree or the story contradicts itself —
a python-requests TLS stack claiming "Chrome 136" is a louder tell than
any single header. So identity is resolved in ONE place here:

- ``sticky_profile(host)`` returns the profile: a curl-impersonate target
  whose TEMPLATE is the identity (client-hint set, sec-fetch set, header
  order, TLS stack), plus the exact on-wire UA string (template native, or
  the pool's platform variant applied as a coherent override).
- ``auxiliaries/web_session._do_session_request`` routes through
  ``curl_cffi`` (curl-impersonate) with that target when policy allows —
  TLS stack matches the UA claim, and the browser's canonical header
  ORDER comes from the template (headers override in-place, no dupes).
- When impersonation is NOT possible (lib missing, ``SESSION_IMPERSONATION=off``,
  operator-owned UA, multipart upload lane), the call degrades to the plain
  python-requests path: same sticky UA claim, headers canonicalised per
  family order + the family's realistic Accept/Accept-Language/Accept-Encoding
  fill (only decodable encodings are claimed). The envelope says which
  backend shipped it — ``fingerprint.backend`` — an honest flag, never faked.

NO ROTATION-WITHIN-HOST by contract: identity is DETERMINISTIC-PER-HOST —
the same host always sees the same agent, across processes and restarts
(pure hash, zero state). Rotating identity WITHIN a session is how
authenticated servers get suspicious; spread happens ACROSS hosts via hash
distribution. Operators who genuinely want rotation own it in
REPL/notebook code, not here.
"""
from __future__ import annotations

import hashlib
import os
from typing import Any, Dict, List, Optional

# The old self-identifying marker, kept as an opt-in via SESSION_UA=legacy
# (some RoE documents require the tool to identify itself).
LEGACY_UA = "framework-web-session/1.0 (+stateful-audit-lane)"

# Identity pool — STABLE MAJOR VERSIONS, not bleeding-edge: a UA claiming a
# browser build newer than its implied TLS stack supports tells a story that
# contradicts itself. Every entry's UA is EXACTLY what goes on the wire:
#   - "native" entries: chrome145/safari18_0 templates carry this UA verbatim.
#   - "override" entries: template is the same browser family+build; we
#     rewrite only the platform claims (UA + sec-ch-ua-platform for chrome;
#     UA alone for firefox — Firefox sends no client hints, so platform
#     claims live only in the UA). Header overrides REPLACE template values
#     IN the template's canonical position (curl-impersonate verified:
#     no duplicates, order preserved) — so a Windows-claiming Chrome still
#     orders like Chrome and only claims platforms its headers carry.
# Pool strings are hardcoded, never read back from the installed lib: a
# pip upgrade must not silently permutate per-host identity.
_PROFILE_POOL: List[Dict[str, Any]] = [
    {
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
        "target": "chrome136", "family": "chrome",
        "apply": [
            ("User-Agent",
             "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"),
            ("sec-ch-ua-platform", '"Windows"'),
        ],
        "lang": "en-US,en;q=0.9",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                  "image/avif,image/webp,image/apng,*/*;q=0.8,"
                  "application/signed-exchange;v=b3;q=0.7",
    },
    {
        # Native: template UA is exactly this string.
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
              "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
        "target": "safari18_0", "family": "safari",
        "apply": [],
        "lang": "en-US,en;q=0.9",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    },
    {
        # Windows Firefox: no client hints in the template — UA alone is the
        # platform claim, so overriding the UA is fully coherent.
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) "
              "Gecko/20100101 Firefox/144.0",
        "target": "firefox144", "family": "firefox",
        "apply": [
            ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) "
                           "Gecko/20100101 Firefox/144.0"),
        ],
        "lang": "en-US,en;q=0.5",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    },
    {
        # Linux Firefox: template ships no Linux variant; the UA is the only
        # platform claim Firefox makes, so a UA-only override stays coherent.
        "ua": "Mozilla/5.0 (X11; Linux x86_64; rv:147.0) "
              "Gecko/20100101 Firefox/147.0",
        "target": "firefox147", "family": "firefox",
        "apply": [
            ("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:147.0) "
                           "Gecko/20100101 Firefox/147.0"),
        ],
        "lang": "en-US,en;q=0.9",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    },
    {
        # Native: template UA is exactly this string.
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
              "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
        "target": "chrome145", "family": "chrome",
        "apply": [],
        "lang": "en-US,en;q=0.9",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                  "image/avif,image/webp,image/apng,*/*;q=0.8,"
                  "application/signed-exchange;v=b3;q=0.7",
    },
]

# Back-compat view: the on-wire UA strings only (tests + external callers).
_UA_POOL = [p["ua"] for p in _PROFILE_POOL]

# Canonical per-family header ORDER (lowercase wire names), from the
# curl-impersonate templates empirically probed on this host. Used to
# canonicalise the plain-requests path's header emission (its only remaining
# realism gap after the UA claim); the impersonated path takes template order
# natively. Cookie/CSRF/app headers land after the browser set.
_CANONICAL_ORDER: Dict[str, List[str]] = {
    "chrome": [
        "host", "upgrade", "http2-settings", "sec-ch-ua", "sec-ch-ua-mobile",
        "sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent",
        "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user",
        "sec-fetch-dest", "accept-encoding", "accept-language", "connection",
        "cookie",
    ],
    "firefox": [
        "host", "upgrade", "http2-settings", "user-agent", "accept",
        "accept-language", "accept-encoding", "upgrade-insecure-requests",
        "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
        "priority", "te", "connection", "cookie",
    ],
    "safari": [
        "host", "upgrade", "http2-settings", "accept", "sec-fetch-site",
        "accept-encoding", "sec-fetch-mode", "user-agent", "accept-language",
        "sec-fetch-dest", "connection", "cookie",
    ],
}

_CURL_OK: Optional[bool] = None  # lazy, cached curl_cffi availability probe


def _operator_ua_override() -> Optional[str]:
    """$SESSION_UA override ('legacy' | custom string), if set — else None.

    An operator-owned identity never impersonates: the TLS stack cannot be
    reshaped to match an arbitrary claimed agent, so identity falls back to
    the sticky-UA + canonicalised-headers requests path.
    """
    override = os.getenv("SESSION_UA", "").strip()
    if override == "legacy" or override == LEGACY_UA:
        return LEGACY_UA
    if override:
        return override
    return None


def sticky_profile(host: str) -> Dict[str, Any]:
    """Deterministic per-host identity profile.

    Precedence: $SESSION_UA override ('legacy' | custom string) > hash-pick.
    The override returns a profile with ``target=None`` — operator-owned
    identity, plain-requests lane by policy (see module docstring).
    """
    if not host:
        return dict(_PROFILE_POOL[0], apply=list(_PROFILE_POOL[0]["apply"]))
    override = _operator_ua_override()
    if override:
        return {"ua": override, "target": None, "family": "unknown",
                "apply": [], "lang": "", "accept": ""}
    h = hashlib.sha256(host.lower().encode("utf-8")).digest()
    profile = _PROFILE_POOL[h[0] % len(_PROFILE_POOL)]
    return dict(profile, apply=list(profile["apply"]))


def sticky_ua(host: str) -> str:
    """Deterministic per-host on-wire UA from the identity pool.

    Precedence: $SESSION_UA override ('legacy' | custom string) > hash-pick.
    The returned string is exactly what the server sees (template-native or
    coherent template override)."""
    if not host:
        return _UA_POOL[0]
    return sticky_profile(host)["ua"]


def impersonation_mode() -> str:
    """Configured TLS/header impersonation mode: ``auto`` (default) | ``off``.

    Read from $SESSION_IMPERSONATION in the root .env. Any value other than
    ``off``/``0``/``false``/``no`` is ``auto`` — opt-out is explicit.
    """
    raw = os.getenv("SESSION_IMPERSONATION", "").strip().lower()
    if raw in {"off", "0", "false", "no"}:
        return "off"
    return "auto"


def curl_impersonation_available() -> bool:
    """True if curl_cffi (curl-impersonate bindings) imports in this venv.

    Cached lazily so the request-path cost is one ``import`` check total.
    """
    global _CURL_OK
    if _CURL_OK is None:
        try:
            from curl_cffi import requests as _curl_requests  # noqa: F401

            _CURL_OK = True
        except Exception:  # noqa: BLE001 - absence/sickness both mean "no"
            _CURL_OK = False
    return _CURL_OK


def impersonation_target(profile: Dict[str, Any]) -> Optional[str]:
    """The curl-impersonate target for this profile, if usable right now.

    Returns None (impersonation off for this call) when: the profile is an
    operator-owned identity, the lib is missing, the mode is off, or the
    pinned target no longer exists in the installed curl_cffi (pip upgrade;
    the pool degrades honestly, it does not guess a substitute).
    """
    if impersonation_mode() == "off":
        return None
    target = profile.get("target")
    if not target:
        return None
    if not curl_impersonation_available():
        return None
    try:
        from curl_cffi import requests as _curl_requests

        browser_type = getattr(_curl_requests, "BrowserType", None)
        if browser_type is not None and not hasattr(browser_type, target):
            return None
    except Exception:  # noqa: BLE001 - degraded to plain requests
        return None
    return target


def browser_accept_encoding() -> str:
    """Family-generic Accept-Encoding value claiming only DECODABLE formats.

    python-requests/urllib3 decodes gzip+deflate natively, brotli if the
    ``brotli`` package is importable, zstd if ``zstandard`` is. Claiming an
    encoding we cannot decode would corrupt every compressed response — so
    the plain-path fill only claims what this venv actually handles.
    """
    encs = ["gzip", "deflate"]
    try:
        import brotli  # noqa: F401

        encs.append("br")
    except ImportError:
        pass
    try:
        import zstandard  # noqa: F401

        encs.append("zstd")
    except ImportError:
        pass
    return ", ".join(encs)


def order_headers_for_family(
    headers: Dict[str, str], family: str
) -> Dict[str, str]:
    """Re-emit ``headers`` in the family's canonical browser order.

    Known browser headers (lowercase-matched) follow the family's template
    order; app/unknown headers (X-CSRFToken, Authorization, ...) keep their
    insertion order behind the browser set — app extensions ride along in
    browsers too. Original key casing is preserved; values untouched.
    """
    order = _CANONICAL_ORDER.get(family, [])
    index = {name: i for i, name in enumerate(order)}
    known = sorted(
        (k for k in headers if k.lower() in index),
        key=lambda k: index[k.lower()],
    )
    unknown = [k for k in headers if k.lower() not in index]
    ordered = {k: headers[k] for k in known}
    ordered.update({k: headers[k] for k in unknown})
    return ordered


def canonical_fill_for_family(
    profile: Dict[str, Any],
    method: str,
    headers: Dict[str, str],
) -> Dict[str, str]:
    """Fill identity-consistent browser headers the caller didn't supply.

    Only the trio browsers always send and only when absent: ``Accept``
    (family value), ``Accept-Language`` (sticky-claimed locale), and
    ``Accept-Encoding`` (claiming only what this venv decodes). Deliberately
    NO sec-fetch*/client-hint theater here: the plain-requests TLS stack
    already tells a generic-python story, and stacking more browser claims
    on it amplifies the lie without fixing the stack — that path's envelope
    says ``fingerprint.backend: python-requests`` and stays honest.
    """
    m = (method or "GET").upper()
    out: Dict[str, str] = {}
    lowers = {k.lower() for k in headers}
    if m == "GET" or m == "HEAD":
        if "accept" not in lowers and profile.get("accept"):
            out["Accept"] = profile["accept"]
    if "accept-language" not in lowers and profile.get("lang"):
        out["Accept-Language"] = profile["lang"]
    if "accept-encoding" not in lowers:
        out["Accept-Encoding"] = browser_accept_encoding()
    return out


# --- Pacing (unchanged mechanics, moved verbatim from the pre-identity version) ---

def host_floor_seconds() -> float:
    """Configured per-host floor interval (seconds); 0.0 = off (default).

    Read from $SESSION_HOST_FLOOR (float ok). Clamped to <=15s: the tool
    lanes are blocking-with-timeout; a floor longer than that belongs in
    REPL/notebook code, not in the request path.
    """
    raw = os.getenv("SESSION_HOST_FLOOR", "").strip()
    if not raw:
        return 0.0
    try:
        v = float(raw)
    except ValueError:
        return 0.0
    return max(0.0, min(v, 15.0))


class HostFloor:
    """Per-host inter-request floor at the request choke point.

    Monotonic in-process timestamps. Deliberately NO locks: a floor is
    pacing, not correctness — in multi-process lanes two racers can both
    pass the check, and advisory best-effort is the honest failure mode.
    """

    _at: dict = {}

    @classmethod
    def wait(cls, host: str) -> float:
        """Sleep out the floor for ``host``; returns seconds actually slept."""
        import time

        floor = host_floor_seconds()
        if floor <= 0.0 or not host:
            return 0.0
        now = time.monotonic()
        last = cls._at.get(host)
        if last is not None:
            remaining = floor - (now - last)
            if remaining > 0:
                time.sleep(remaining)
                cls._at[host] = time.monotonic()
                return remaining
        cls._at[host] = now
        return 0.0


__all__ = [
    "LEGACY_UA",
    "HostFloor",
    "browser_accept_encoding",
    "canonical_fill_for_family",
    "curl_impersonation_available",
    "host_floor_seconds",
    "impersonation_mode",
    "impersonation_target",
    "order_headers_for_family",
    "sticky_profile",
    "sticky_ua",
]