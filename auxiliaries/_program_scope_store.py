"""Scope-cache, .scope-file, and scan-config lane for program scope.

Carved guts of ``auxiliaries/program_scope.py`` (2026-10-30): the on-disk
manifest cache + amass-compatible ``.scope`` writer, the prose-testing-
requirements parser, and the scan-config resolver shared by
ffuf / ZAP / amass. Disk-state only — no in-process shared mutable state
— so every lane (Brain, in-process fallback, REPL, gateway) sees the
same workspace files. The tool surface never moves:
``auxiliaries/program_scope.py`` keeps the five decorated tools."""
from __future__ import annotations

import json as _json
import logging
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from constants import resolve_workspace_root


def _scope_cache_path(handle: str, platform: str = "h1") -> Path:
    d = resolve_workspace_root() / "scope"
    try:
        d.mkdir(parents=True, exist_ok=True)
    except OSError:
        # Unwritable WORKSPACE_ROOT (sandboxed seat, rebuilt container, or a
        # stale/stomped .env pointing at another user's home): degrade to a
        # stable per-user tmp dir so cache reads/writes stay best-effort and
        # never crash arm()/load_program_scope.  2026-09-25 regression: this
        # mkdir was unconditional and killed arm() with a raw PermissionError
        # (test_arm_requires_manifest) whenever WORKSPACE_ROOT pointed
        # somewhere the runner cannot create.
        d = Path(tempfile.gettempdir()) / "framework-scope-cache"
        try:
            d.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass  # even the fallback failed; callers' guards handle the miss
    name = handle if platform == "h1" else f"{platform}_{handle}"
    return d / f"{name}.json"

def _write_scope_file(manifest: dict[str, Any]) -> str | None:
    """Write amass-compatible ``.scope`` from DOMAIN/WILDCARD/URL assets.

    Returns the path written, or None if nothing applicable.  Format matches
    ``auxiliaries.amass._load_scope``: ``*.example.com`` (wildcard),
    ``example.com`` (domain + subdomains), ``api.example.com`` (exact),
    ``#`` comments.  URL assets are reduced to their host.
    """
    patterns: list[str] = []

    def _hostlike(s: str) -> bool:
        # Skip policy prose ("Any host verified to be owned by Tesla...") —
        # only wildcard/host-shaped identifiers belong in the amass filter.
        return bool(re.match(r"^(\*\.)?[a-z0-9]([a-z0-9*._-]*[a-z0-9])?$", s.strip(), re.I))

    def _scope_pattern(atype: str, ident: str) -> str | None:
        """Return the amass-filter pattern for one asset, or None to skip.

        For DOMAIN/WILDCARD the identifier is already host-shaped, so the
        _hostlike guard is applied directly.  For URL assets the raw
        identifier often carries a scheme (``https://host/path``) that would
        fail _hostlike, so the host is extracted FIRST and the guard is
        applied to the extracted host — otherwise a URL-only asset with no
        wildcard parent is silently dropped from the amass filter.
        """
        ident = (ident or "").strip()
        if not ident:
            return None
        if atype in ("WILDCARD", "DOMAIN"):
            return ident if _hostlike(ident) else None
        if atype == "URL":
            host = urlparse(ident if "://" in ident else f"http://{ident}").hostname
            return host if (host and _hostlike(host)) else None
        return None

    for a in manifest.get("in_scope", []):
        p = _scope_pattern((a.get("asset_type") or "").upper(),
                           a.get("asset_identifier") or "")
        if p:
            patterns.append(p)
    if not patterns:
        return None
    # Out-of-scope DOMAIN/WILDCARD/URL assets become `!`-prefixed deny lines
    # so amass's filter can exclude explicit OOS hosts even when they also
    # match an in-scope wildcard.  amass._load_scope returns these separately.
    for a in manifest.get("out_of_scope_assets", []):
        p = _scope_pattern((a.get("asset_type") or "").upper(),
                           a.get("asset_identifier") or "")
        if p:
            patterns.append("!" + p)
    platform = manifest.get("platform", "h1")
    scope_path = (resolve_workspace_root()
                  / f"{platform}_{manifest.get('handle', 'unknown')}.scope")
    seen = set()
    lines = [f"# Auto-generated from {platform.upper()} program scope — do not edit by hand.",
             f"# Source: {manifest.get('handle')} @ {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(manifest.get('fetched_at', time.time())))}"]
    for p in patterns:
        if p not in seen:
            seen.add(p)
            lines.append(p)
    try:
        scope_path.write_text("\n".join(lines) + "\n")
    except OSError as exc:
        # Derived .scope file is best-effort: the manifest stays valid even
        # when the workspace dir is unwritable (amass just gets no filter).
        logging.getLogger(__name__).warning(
            "scope file write failed (best-effort, ignored): %s", exc
        )
        return ""
    return str(scope_path)


def _save_cache(handle: str, manifest: dict[str, Any], platform: str = "h1") -> str:
    # Cache write is best-effort: a successful live fetch must not die just
    # because the cache dir is unwritable (callers ignore this return).
    try:
        p = _scope_cache_path(handle, platform)
        p.write_text(_json.dumps(manifest, indent=2))
        return str(p)
    except OSError as exc:
        logging.getLogger(__name__).warning(
            "scope cache write failed (best-effort, ignored): %s", exc
        )
        return ""


def _load_cache(handle: str, platform: str = "h1") -> dict[str, Any] | None:
    p = _scope_cache_path(handle, platform)
    if not p.is_file():
        return None
    try:
        return _json.loads(p.read_text())
    except (OSError, ValueError):
        return None


# --- scan-config resolver (shared by ffuf / ZAP / amass) --------------------
#
# ``check_scope`` surfaces ``scan_config_required`` inline on positive
# verdicts, but that only helps if the *caller* reads it and acts on it.
# In a busy session the secretary model can forget to pass the custom UA /
# header / rate cap to ffuf or ZAP, and day-one traffic on a reopened
# program burns good standing.
#
# ``get_scan_config`` is the enforcement-by-code backstop: any scan tool
# that accepts ``scope_handle`` / ``scope_platform`` calls this to resolve
# the program's testing requirements into concrete, ready-to-inject
# values so headers and rate caps are auto-applied even when the secretary
# omits them.
#
# Platform coverage:
#   intigriti — structured testingRequirements in the API (custom UA with
#       intigriti:{Username}, X-Intigriti-Username header, req/sec cap).
#   h1 — no structured field; H1's own Traffic Identification docs
#       (docs.hackerone.com/en/articles/8369822) recommend
#       X-HackerOne-Research: [username].  We inject that as a default
#       and best-effort scan the policy text + per-asset instruction
#       fields for explicit per-program requirements (rate limits, custom
#       headers, custom UA).
#   bugcrowd — no structured field, no platform-wide identification
#       header; we inject a researcher-identifying UA suffix as a default
#       and best-effort scan the brief description for explicit
#       requirements.

_STANDARD_BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) "
    "Gecko/20100101 Firefox/128.0"
)

_RI_PREFIX = "intigriti-roar-"  # replacer/rate-limit rule descriptions

# Regex patterns for best-effort prose parsing of testing requirements.
_RATE_RE = re.compile(
    r"(?:max(?:imum)?\s+)?(\d+)\s+req(?:uest)?s?(?:ests)?\s*(?:per|/)\s*s(?:ec|econd)?s?",
    re.I,
)
_RATE_RE_ALT = re.compile(
    r"(?:rate\s*limit(?:ed)?\s*(?:to|of)?\s*)(\d+)\s*(?:rps|req/s|req/sec)",
    re.I,
)
# "X-Some-Header: value" in policy text — must look like a real HTTP header.
_CUSTOM_HEADER_RE = re.compile(
    r"(X-[A-Za-z][\w-]*):\s*(\S[^\n]{0,200})",
)
# "User-Agent: ..." in policy text.
_CUSTOM_UA_RE = re.compile(
    r"User-Agent\s*:\s*(\S[^\n]{0,200})",
    re.I,
)


def _parse_prose_testing_reqs(text: str) -> dict[str, Any]:
    """Best-effort extraction of testing requirements from prose text.

    Scans policy / instruction / brief-description text for rate-limit,
    custom-header, and custom-User-Agent signals.  Returns a dict with
    optional keys ``user_agent``, ``request_header``, ``max_requests_per_second``
    — only keys that matched are included.  This is intentionally
    conservative: false negatives (missing a requirement) are acceptable
    because the platform-default identification is always applied; false
    positives (injecting a non-required header) could annoy the program.
    """
    if not text:
        return {}
    result: dict[str, Any] = {}

    # --- Rate limit ---
    for rx in (_RATE_RE, _RATE_RE_ALT):
        m = rx.search(text)
        if m:
            try:
                rate = int(m.group(1))
                if 0 < rate <= 10000:  # sanity bounds
                    result["max_requests_per_second"] = rate
                    break
            except (ValueError, IndexError):
                pass

    # --- Custom User-Agent ---
    m = _CUSTOM_UA_RE.search(text)
    if m:
        result["user_agent"] = m.group(1).strip().rstrip(".")

    # --- Custom headers ---
    for m in _CUSTOM_HEADER_RE.finditer(text):
        hname = m.group(1)
        hval = m.group(2).strip().rstrip(".")
        # Stash as "Name: Value" — the caller splits on colon.
        result.setdefault("request_header", hname + ": " + hval)
        break  # first custom header only; additional ones are rare

    return result


def _resolve_username(platform: str) -> str:
    """Return the researcher username for the given platform from env vars."""
    if platform == "intigriti":
        return os.getenv("INTIGRITI_USERNAME", "")
    if platform == "h1":
        return os.getenv("H1_API_USERNAME", "")
    if platform == "bugcrowd":
        return os.getenv("BUGCROWD_USERNAME", "") or os.getenv("H1_API_USERNAME", "")
    return os.getenv("RESEARCHER_USERNAME", "")


def get_scan_config(handle: str, platform: str = "h1") -> dict[str, Any] | None:
    """Resolve a program's testing requirements into concrete, injectable
    scan configuration for ffuf / ZAP / amass.

    Loads the cached manifest for ``(handle, platform)`` and returns a
    normalized dict:

    .. code-block:: python

        {
            "platform": "intigriti",
            "handle": "adobepublic",
            "headers": {"User-Agent": "...", "X-Intigriti-Username": "..."},
            "max_requests_per_second": 20,
            "source": "structured",   # or "platform-default", "prose"
        }

    **Platform behaviour:**

    - **intigriti**: structured ``testing_requirements`` from the API.
      ``{Username}`` is substituted from ``INTIGRITI_USERNAME``.
    - **h1**: no structured field in the API.  H1's Traffic Identification
      docs recommend ``X-HackerOne-Research: [username]`` — that header is
      always injected (from ``H1_API_USERNAME``).  Policy text and per-asset
      ``instruction`` fields are best-effort scanned for explicit
      per-program rate limits or custom headers.
    - **bugcrowd**: no platform-wide identification header.  A
      researcher-identifying suffix is appended to the User-Agent (from
      ``BUGCROWD_USERNAME`` or ``H1_API_USERNAME``).  Brief description is
      best-effort scanned for explicit requirements.

    Returns ``None`` when no manifest is cached.  Otherwise always returns
    a config dict — even for H1/Bugcrowd programs with no explicit
    requirements, the platform-default identification is applied so the
    secretary never fires completely anonymous traffic.
    """
    platform = (platform or "h1").strip().lower()
    manifest = _load_cache(handle, platform)
    if manifest is None:
        return None

    if platform == "intigriti":
        return _get_scan_config_intigriti(manifest, handle)
    if platform == "h1":
        return _get_scan_config_h1(manifest, handle)
    if platform == "bugcrowd":
        return _get_scan_config_bugcrowd(manifest, handle)
    return None


def get_armed_scan_config() -> dict[str, Any] | None:
    """Resolve scan config from the OPERATOR-ARMED scope state (no args).

    Reads ``scope/.armed_packet_scope.json`` — the same file-backed state the
    packet gate enforces from (READ-ONLY here) — for the armed
    ``(handle, platform)`` and resolves that program's testing requirements
    via :func:`get_scan_config`.

    This is the zero-argument backstop for traffic tools that never receive a
    ``scope_handle`` (ssrf_probe, the playwright sidecar): identification
    headers and rate caps get applied by construction instead of by secretary
    discipline. Returns ``None`` when nothing is armed or no manifest is
    cached — callers then fall back to their own identification defaults.
    """
    state_path = (resolve_workspace_root()
                  / "scope" / ".armed_packet_scope.json")
    try:
        state = _json.loads(state_path.read_text())
    except (OSError, ValueError):
        return None
    handle = (state.get("handle") or "").strip()
    if not handle:
        return None
    platform = (state.get("platform") or "h1").strip().lower()
    return get_scan_config(handle, platform)


def _normalise_rate(raw: Any) -> int | None:
    """Coerce a rate value to int or None (0 / None / negative → None)."""
    if raw is None:
        return None
    try:
        r = int(raw)
    except (TypeError, ValueError):
        return None
    return r if r > 0 else None


def _get_scan_config_intigriti(manifest: dict[str, Any],
                               handle: str) -> dict[str, Any] | None:
    """Intigriti: structured testing_requirements from the API."""
    tr = manifest.get("testing_requirements") or {}
    ua_raw = tr.get("user_agent")
    hdr_raw = tr.get("request_header")
    rate = _normalise_rate(tr.get("max_requests_per_second"))
    if not ua_raw and not hdr_raw and not rate:
        return None  # program mandates no custom UA / header / rate

    username = os.getenv("INTIGRITI_USERNAME", "")
    headers: dict[str, str] = {}

    def _resolve_placeholders(raw: str) -> str:
        s = raw or ""
        if username:
            s = s.replace("{Username}", username)
        s = s.replace("<standard browser/tool user agent>", _STANDARD_BROWSER_UA)
        return s.strip()

    if ua_raw:
        ua_val = _resolve_placeholders(ua_raw)
        if ua_val.lower().startswith("user-agent:"):
            ua_val = ua_val[len("user-agent:"):].strip()
        headers["User-Agent"] = ua_val

    if hdr_raw:
        hdr_val = _resolve_placeholders(hdr_raw)
        if ":" in hdr_val:
            hname, _, hval = hdr_val.partition(":")
            headers[hname.strip()] = hval.strip()

    return {
        "platform": "intigriti",
        "handle": handle,
        "headers": headers,
        "max_requests_per_second": rate,
        "source": "structured",
    }


def _get_scan_config_h1(manifest: dict[str, Any],
                        handle: str) -> dict[str, Any]:
    """HackerOne: default identification header + best-effort prose parsing.

    H1's Traffic Identification docs recommend ``X-HackerOne-Research:
    [username]``.  We always inject that as a baseline so traffic is
    attributable, then best-effort scan the policy text and per-asset
    instruction fields for explicit per-program requirements (rate limits,
    custom headers, custom UA).
    """
    username = os.getenv("H1_API_USERNAME", "")
    headers: dict[str, str] = {}
    rate: int | None = None
    sources: list[str] = ["platform-default"]

    # --- Default: H1-recommended identification header -------------------
    if username:
        headers["X-HackerOne-Research"] = username

    # --- Best-effort: scan policy + instructions for explicit reqs -------
    prose_parts: list[str] = [manifest.get("policy") or ""]
    for a in manifest.get("in_scope", []):
        inst = a.get("instruction")
        if inst:
            prose_parts.append(inst)
    prose = "\n".join(prose_parts)
    parsed = _parse_prose_testing_reqs(prose)

    if parsed:
        sources = ["platform-default", "prose"]
        if parsed.get("user_agent"):
            headers["User-Agent"] = parsed["user_agent"]
        if parsed.get("request_header"):
            hdr_val = parsed["request_header"]
            if ":" in hdr_val:
                hname, _, hval = hdr_val.partition(":")
                hname = hname.strip()
                # Don't let a prose template (e.g. "X-HackerOne-Research:
                # your_username") overwrite the resolved default — only
                # add headers the default didn't already set.
                if hname not in headers:
                    headers[hname] = hval.strip()
        rate = parsed.get("max_requests_per_second")

    return {
        "platform": "h1",
        "handle": handle,
        "headers": headers,
        "max_requests_per_second": _normalise_rate(rate),
        "source": "+".join(sources),
    }


def _get_scan_config_bugcrowd(manifest: dict[str, Any],
                              handle: str) -> dict[str, Any]:
    """Bugcrowd: default UA suffix + best-effort prose parsing.

    Bugcrowd has no platform-wide identification header.  Community
    practice is to append a researcher-identifying suffix to the
    User-Agent.  We do that as a baseline, then best-effort scan the
    brief description for explicit per-program requirements.
    """
    username = (os.getenv("BUGCROWD_USERNAME", "")
                or os.getenv("H1_API_USERNAME", ""))
    headers: dict[str, str] = {}
    rate: int | None = None
    sources: list[str] = ["platform-default"]

    # --- Default: researcher-identifying UA suffix ------------------------
    if username:
        headers["User-Agent"] = f"{_STANDARD_BROWSER_UA} (Bugcrowd:{username})"

    # --- Best-effort: scan brief description for explicit reqs ------------
    parsed = _parse_prose_testing_reqs(manifest.get("policy") or "")
    if parsed:
        sources = ["platform-default", "prose"]
        if parsed.get("user_agent"):
            headers["User-Agent"] = parsed["user_agent"]
        if parsed.get("request_header"):
            hdr_val = parsed["request_header"]
            if ":" in hdr_val:
                hname, _, hval = hdr_val.partition(":")
                hname = hname.strip()
                if hname not in headers:
                    headers[hname] = hval.strip()
        rate = parsed.get("max_requests_per_second")

    return {
        "platform": "bugcrowd",
        "handle": handle,
        "headers": headers,
        "max_requests_per_second": _normalise_rate(rate),
        "source": "+".join(sources),
    }
