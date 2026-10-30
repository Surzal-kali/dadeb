"""ZAP protect-mode scope mirror: context sync + drift guard.

Carved guts of ``auxiliaries/zap.py`` (2026-10-30): ``sync_protect_scope``
and its drift guard — the layer-2 architectural control that mirrors the
operator-armed scope into a ZAP context and flips the daemon to
mode=protect.  Client-injected: every function here takes the live
``ZAPClient`` as an argument; the facade (``auxiliaries/zap.py``) injects
its ``_zap()`` singleton, and this module holds no facade imports at
runtime.  The armed manifest is read, never written.  Plain guts only —
no ``@framework_tool`` members, no argparse, so discovery never mints
it; ``auxiliaries/zap.py`` keeps the decorated ``zap_sync_scope`` tool."""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - annotations only, never imported at runtime
    from auxiliaries.zap import ZAPClient


# ---- protect-mode scope sync (2026-09-19) -----------------------------------
# ZAP has no API-level redirect off; mode=protect + a context mirroring the
# operator-armed scope is the architectural control: ZAP itself refuses every
# out-of-scope request (redirect hops, spider crawls, scan traffic, proxied
# manual browsing). The armed manifest is read here — never written.

def sync_protect_scope(zap: ZAPClient) -> dict[str, Any]:
    """Mirror the armed scope into a ZAP context and set mode=protect.

    Reads ``scope/.armed_packet_scope.json`` + the cached manifest (the
    operator-armed scope is the single source of truth; this function NEVER
    writes scope state). Allowlist IPs, blessed hostnames, and web-surface
    manifest assets become context includes; out-of-scope assets become
    excludes. CIDR assets are skipped (not URL-regex expressible — bless
    individual IPs with ``scope add-ip`` instead). Sets ``mode=protect``
    last, so ZAP enforces the boundary itself.
    """
    import re

    from utils.scope_gate import _load_manifest, _load_state

    state = _load_state()
    if state is None:
        return {
            "status": "Failed",
            "error": (
                "no scope armed (lab mode) — nothing to protect; arm with "
                "'scope on <handle>' (or add-ips) and re-run"
            ),
        }
    handle = state.get("handle", "") or "scope"
    platform = state.get("platform", "h1")
    manifest = _load_manifest(state.get("handle", ""), platform)
    if manifest is None:
        from auxiliaries.program_scope import _load_cache

        manifest = _load_cache(state.get("handle", ""), platform)

    context_name = f"framework-armed-{handle}"

    includes: list[str] = []
    excludes: list[str] = []
    skipped: list[dict[str, str]] = []

    def _host_patterns(host: str) -> list[str]:
        h = re.escape(host.lower())
        return [
            rf"https?://([^.]+\.)?{h}(:\d+)?(/.*)?",
            rf"https?://{h}(:\d+)?(/.*)?",
        ]

    def _asset_patterns(
        asset: dict[str, Any], out: list[str], skip: list[dict[str, str]]
    ) -> None:
        atype = str(asset.get("asset_type", "")).upper()
        ident = str(asset.get("asset_identifier", "")).strip()
        if not ident:
            return
        if atype == "DOMAIN":
            out.extend(_host_patterns(ident))
        elif atype == "WILDCARD":
            base = ident[2:] if ident.startswith("*.") else ident
            out.extend(_host_patterns(base))
        elif atype == "URL":
            out.append(re.escape(ident.rstrip("/")) + ".*")
        elif atype in ("ANDROID", "IOS", "BLOCKCHAIN"):
            skip.append({"asset": ident, "reason": f"{atype}: not a web surface"})
        elif atype == "CIDR":
            skip.append(
                {
                    "asset": ident,
                    "reason": "CIDR not URL-regex expressible — bless "
                    "individual IPs via 'scope add-ip'",
                }
            )
        else:
            skip.append({"asset": ident, "reason": f"unmapped asset_type {atype}"})

    for ip, host in (state.get("allowlist") or {}).items():
        if ip:
            includes.extend(_host_patterns(ip))
        if host:
            includes.extend(_host_patterns(host))
    # Blessed hostnames (tier 1b, 'scope add-host'): operator-asserted
    # hostname->blessed-IP mappings.  ZAP's sender connects to the Host
    # header's host, so protect mode must accept the same NAMES the L1 gate
    # accepts — without these, a gate-blessed vhost still hits
    # "mode_violation" (mirror lagging the gate, observed live 2026-09-20).
    for hostname in (state.get("blessed_hosts") or {}):
        if hostname:
            includes.extend(_host_patterns(hostname))
    for asset in manifest.get("out_of_scope_assets") or []:
        _asset_patterns(asset, excludes, skipped)
    for asset in manifest.get("in_scope") or []:
        _asset_patterns(asset, includes, skipped)

    try:
        zap.context_new(context_name)
    except Exception as e:  # noqa: BLE001 - tolerate already_exists; refuse real failures
        if not zap._context_exists(context_name):
            return {
                "status": "Failed",
                "error": f"context setup failed: {type(e).__name__}: {e}",
            }
    for rx in includes:
        zap.context_include(context_name, rx)
    for rx in excludes:
        zap.context_exclude(context_name, rx)
    zap.set_mode("protect")

    return {
        "status": "Success",
        "mode": zap.get_mode(),
        "context": context_name,
        "include_count": len(includes),
        "exclude_count": len(excludes),
        "skipped": skipped[:20],
        "handle": handle,
        "note": (
            "ZAP now refuses out-of-scope requests itself (mode=protect): "
            "redirect hops, spider crawls, scan traffic, and proxied manual "
            "browsing to non-scope hosts. Manual recon beyond scope happens "
            "OUTSIDE ZAP by design."
        ),
    }


def _host_from_raw_request(raw_request: str) -> str | None:
    """Extract the target host from a raw HTTP request for scope gating.

    Checks the ``Host:`` header first (the common case for vhost-gated
    targets), falling back to an absolute-form request target
    (``GET http://host/path HTTP/1.1``).  Strips a trailing ``:port`` for
    IPv4/domain hosts; leaves IPv6 literals (bracketed) intact.  Returns
    ``None`` if no host can be determined.
    """
    lines = (raw_request or "").lstrip().splitlines()
    host = None
    for ln in lines:
        if ln.lower().startswith("host:"):
            host = ln.split(":", 1)[1].strip()
            break
    if not host and lines:
        from urllib.parse import urlparse
        first = lines[0].split()
        if len(first) >= 2 and "://" in first[1]:
            host = urlparse(first[1]).hostname
    if not host:
        return None
    if host.startswith("[") and "]" in host:
        return host[1:host.index("]")]
    if host.count(":") == 1:  # IPv4/domain :port
        return host.rsplit(":", 1)[0]
    return host


def drift_guard(zap: ZAPClient) -> dict[str, Any] | None:
    """Detect armed-scope drift and auto-repair the ZAP mirror.

    Compares the armed state file's mtime against the last-synced mtime
    (sidecar ``.zap_protect_sync.json`` next to the state file). Called at
    the top of every traffic-bearing ZAP client method (open_url, spider,
    active_scan, ajax_spider, send_raw) so a scope change the operator made
    without a re-sync is picked up BEFORE the next request fires:

    - scope CHANGED -> sync_protect_scope() re-mirrors the context and keeps
      mode=protect (layer-1 gate already reads live state at entry; this
      closes the layer-2 mirror-drift window: internal redirect hops and
      spider/scan crawling that the per-call locks cannot see).
    - scope DISARMED -> mode=standard restored and sidecar cleared (lab
      mode is the operator's chosen state; ZAP must not keep a stale
      boundary).
    - fresh mirror -> None, no side effects.

    Repair failures are reported but never block the tool call: the
    tool-entry gate (check_scan) remains authoritative for the requested
    target; the drift only ever affects ZAP-internal hops.
    """
    import json as _json
    from pathlib import Path

    from utils.scope_gate import _state_path

    state_p = Path(_state_path())
    sidecar = state_p.parent / ".zap_protect_sync.json"
    try:
        armed_mtime: float | None = state_p.stat().st_mtime
    except OSError:
        armed_mtime = None  # armed state file removed -> disarmed

    last: float | None = None
    if sidecar.is_file():
        try:
            last = float(_json.loads(sidecar.read_text()).get("armed_mtime") or 0)
        except Exception:  # noqa: BLE001 - unreadable sidecar = treat as stale
            last = None

    if armed_mtime is None:
        if last is None:
            return None  # never synced, nothing to restore
        try:
            zap.set_mode("standard")
            sidecar.unlink()
            return {"drift": "scope disarmed — ZAP mode restored to standard"}
        except Exception as e:  # noqa: BLE001
            return {"drift": f"scope disarmed, but ZAP restore failed: {e}"}

    if last == armed_mtime:
        return None  # mirror is fresh
    try:
        result = sync_protect_scope(zap)
        if result.get("status") == "Success":
            sidecar.write_text(_json.dumps({"armed_mtime": armed_mtime}))
            return {
                "drift": "re-synced",
                "mode": result.get("mode"),
                "context": result.get("context"),
            }
        return {"drift": f"re-sync failed: {result.get('error')}"}
    except Exception as e:  # noqa: BLE001 - never block the tool call on the guard
        return {"drift": f"re-sync failed: {type(e).__name__}: {e}"}