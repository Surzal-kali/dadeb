"""Scope-asset matching (pure) for program scope.

Carved guts of ``auxiliaries/program_scope.py`` (2026-10-30): the
WILDCARD/DOMAIN/URL/CIDR/IP/app-id/blockchain matcher and the
specific-over-broad two-pass finder. Pure functions — no imports beyond
stdlib, no state; both the facade tool and the scope gate consume it."""
from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlparse

# --- scope matching ---------------------------------------------------------

def _host_of(target: str) -> str:
    """Extract a bare hostname from a URL/host-ish string."""
    t = target.strip()
    if "://" in t:
        h = urlparse(t).hostname
        return (h or "").lower()
    # strip any :port
    return t.split(":")[0].split("/")[0].lower()


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip())
        return True
    except ValueError:
        return False


def _match_asset(target: str, asset: dict[str, Any]) -> bool:
    """Test whether ``target`` falls under one in-scope asset."""
    atype = (asset.get("asset_type") or "").upper()
    ident = (asset.get("asset_identifier") or "").strip()
    if not ident:
        return False
    t = target.strip()

    if atype == "WILDCARD":
        # *.crypto.com  ->  matches crypto.com and any subdomain
        root = ident.lstrip("*.").lower()
        host = _host_of(t)
        return host == root or host.endswith("." + root)
    if atype == "DOMAIN":
        root = ident.lower()
        host = _host_of(t)
        return host == root or host.endswith("." + root)
    if atype == "URL":
        host = _host_of(t)
        ahost = _host_of(ident)
        if host != ahost:
            return False
        # if the asset has a path, a URL target under that path is in scope
        apath = urlparse(ident if "://" in ident else f"http://{ident}").path or "/"
        tpath = urlparse(t if "://" in t else f"http://{t}").path or "/"
        if apath in ("/", ""):
            return True
        return tpath == apath or tpath.startswith(apath.rstrip("/") + "/")
    if atype == "CIDR":
        try:
            net = ipaddress.ip_network(ident, strict=False)
            ip = ipaddress.ip_address(_host_of(t) if _is_ip(_host_of(t)) else t)
            return ip in net
        except ValueError:
            return False
    if atype in ("IP", "IP_ADDRESS"):
        try:
            return ipaddress.ip_address(t.strip()) == ipaddress.ip_address(ident)
        except ValueError:
            return False
    if atype in ("ANDROID", "IOS"):
        return t.strip().lower() == ident.lower()
    if atype == "BLOCKCHAIN":
        return ident.lower() in t.lower() or t.lower() in ident.lower()
    # OTHER / unknown: substring match as a last resort
    return ident.lower() in t.lower()


def _find_match(target: str, assets: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Find the best-matching asset for ``target``.

    Two passes so a specific asset (URL with a path, IP, CIDR, app id,
    blockchain token) wins over a broad WILDCARD/DOMAIN that would also
    match the same host — e.g. ``https://crypto.com/exchange/BTC`` should
    bind to the ``https://crypto.com/exchange`` URL asset (with its own
    max_severity / CIA requirements) rather than to ``*.crypto.com``.
    """
    specific = {"URL", "IP", "IP_ADDRESS", "CIDR", "ANDROID", "IOS", "BLOCKCHAIN", "OTHER"}
    for a in assets:
        if (a.get("asset_type") or "").upper() in specific and _match_asset(target, a):
            return a
    for a in assets:
        if _match_asset(target, a):
            return a
    return None
