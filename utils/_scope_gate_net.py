"""Pure target-spec/IP math and resolver helpers for the scope gate.

Carved from ``utils/scope_gate.py`` (private sibling — not a public entry
point): host/IP shape predicates, hyphen-range and broad-range parsing,
nmap octet-list comma expansion, and the DNS bridge helpers (reverse-DNS,
forward-confirm, forward-resolve). Every function is stateless: inputs
arrive as arguments; armed-state reads, manifest loads, and the verdict
core (``_check_one`` / ``_check_broad`` / ``check_send`` / ``check_scan``)
stay on the facade, which imports these names into its own globals — so
monkeypatching a helper on ``utils.scope_gate`` still reaches the facade's
verdict functions.
"""
from __future__ import annotations

import ast
import ipaddress
import json
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urlparse


def unwrap_list_shaped_target(raw: str) -> str:
    """Unwrap a stringified list back to a plain space-joined spec list.

    Driving models sometimes emit a string-typed target param as a real
    JSON array (``["cctv.htb"]``); the preflight string-coercion then hands
    downstream tools the literal ``'["cctv.htb"]'`` text. The gate and the
    target-consuming tools unwrap one level — specs stay hosts/URLs/ranges,
    never JSON plumbing. Unparseable input is returned unchanged
    (fail-closed exactly as before).
    """
    raw = (raw or "").strip()
    if not (raw.startswith("[") and raw.endswith("]")):
        return raw
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError, ValueError):
        try:
            parsed = ast.literal_eval(raw)
        except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
            return raw
    if isinstance(parsed, str):
        return parsed.strip() or raw
    if not isinstance(parsed, (list, tuple)):
        return raw
    items = [str(item).strip() for item in parsed if str(item).strip()]
    return " ".join(items) if items else raw


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip())
        return True
    except ValueError:
        return False


def _is_cidr(s: str) -> bool:
    if "/" not in s:
        return False
    try:
        ipaddress.ip_network(s.strip(), strict=False)
        return True
    except ValueError:
        return False


def _is_hyphen_range(text: str) -> bool:
    """nmap/masscan numeric ranges only — both sides of the last dash must
    be numeric-shaped ('10.0.0.1-50', '10.0.0.1-10.0.0.25', '1-50').  Real
    nmap ranges are numeric on both sides, so hostnames with digit-hyphen-
    digit shapes ('co-uk', 's3-2024.example.com', 'wordpress-2024.example.com')
    stop false-matching and fall through to hostname matching.  Octet-range
    forms ('10.0.0-255.1-254') also fall through → unmatched → refused
    (strict) — same end state as the previous broad-refuse, while hostname
    misrefusals are fixed."""
    if "-" not in text:
        return False
    left, _, right = text.rpartition("-")
    left_v4  = left.count(".") == 3 and all(p.isdigit() for p in left.split("."))
    right_v4 = right.count(".") == 3 and all(p.isdigit() for p in right.split("."))
    return (left_v4 and right_v4) or (left_v4 and right.isdigit()) \
        or (left.isdigit() and right.isdigit())


def _reverse_dns(ip: str, timeout: float = 2.0) -> list[str]:
    """PTR-lookup an IP, returning lowercased hostnames.  Capped at 2s so a
    slow/broken resolver never pins a scan.  Failure → empty list, which the
    gate treats as 'unconfirmed'."""
    try:
        with ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(socket.gethostbyaddr, ip)
            host, aliases, _ = fut.result(timeout=timeout)
        names = [host.lower()] + [a.lower() for a in (aliases or [])]
        return [n for n in names if n]
    except Exception:
        return []


def _forward_confirm(host: str, ip: str, timeout: float = 2.0) -> bool:
    """Forward-confirm a PTR hostname back to ``ip`` (tier-3 acceptance).

    PTR records are attacker-settable, so an in-scope PTR name may only
    auto-allow when its A record resolves to the same IP that was scanned.
    Capped at ``timeout`` like :func:`_reverse_dns` so a slow/broken resolver
    never pins a scan; any failure → False (no auto-allow, fail-closed).
    """
    try:
        with ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(socket.gethostbyname, host)
            return fut.result(timeout=timeout) == ip
    except Exception:
        return False


def _is_gated_target(ip: str) -> bool:
    """True only for routable unicast IPs directed at a real host.  Loopback,
    link-local, multicast, broadcast/reserved, and unspecified addresses are
    local-network traffic, not bounty-host probes — never gate them."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False  # not an IP at all (e.g. a bare MAC) — can't gate
    return not (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_reserved
    )


def _resolved_ips(host: str, timeout: float = 2.0) -> list[str]:
    """Forward-resolve a hostname to its CURRENT IP set (bounded).

    Used only by the optional ``--ip-boundary`` tier: a hostname asset passes
    the operator's IP boundary when every address it resolves to right now is
    in the blessed allowlist.  Capped at ``timeout`` like
    :func:`_reverse_dns` so a slow/broken resolver never pins a scan; any
    failure -> empty list, which the boundary treats as 'unconfirmable'
    (refused, fail-closed).
    """

    def _resolve() -> list[str]:
        infos = socket.getaddrinfo(host, None)
        return sorted({info[4][0] for info in infos})

    try:
        with ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(_resolve)
            return fut.result(timeout=timeout)
    except Exception:
        return []


def _range_endpoints(spec: str) -> tuple[Any, Any] | None:
    """Parse a hyphen range into (low, high) IP addresses, or None.

    Both endpoint spellings: full IPs ("10.0.0.5-10.0.0.30") and the
    last-octet shorthand ("10.0.0.5-30" — the right side inherits the
    left's first three octets).  Returns None for anything that is not a
    clean numeric range (hyphenated hostnames, mixed v4/v6, reversed
    bounds are normalized by min/max).
    """
    if "/" in spec or "-" not in spec:
        return None
    left, _, right = spec.strip().rpartition("-")
    if not left or not right:
        return None
    left, right = left.strip(), right.strip()
    anchor = ""
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", left):
        anchor = ".".join(left.split(".")[:3]) + "."
    if right.isdigit() and len(right) <= 3:
        if not anchor:
            return None
        right = anchor + right  # last-octet shorthand
    try:
        lo = ipaddress.ip_address(left)
        hi = ipaddress.ip_address(right)
    except ValueError:
        return None
    if lo.version != hi.version:
        return None
    return (lo, hi) if int(lo) <= int(hi) else (hi, lo)


def _expand_comma_shorthand(raw: str) -> str:
    """Expand nmap-style octet-list commas: 'a.b.c.d,e,f' -> full IPs.

    Only rewrites comma-runs anchored on a dotted quad with BARE-octet
    followers (192.168.90.114,115,116,118).  Full-IP comma merges
    ('a.b.c.d,w.x.y.z'), CIDRs, hyphen ranges, and hostnames pass through
    untouched — nmap's own octet-list syntax stays one argv element for
    run_nmap, while the gate gets fully-qualified targets to validate.
    """

    def _expand(match: re.Match[str]) -> str:
        anchor = match.group(0).split(",")[0]
        prefix = anchor.rsplit(".", 1)[0]
        followers = re.findall(r",(\d{1,3})", match.group(0))
        return ",".join([anchor] + [f"{prefix}.{o}" for o in followers])

    return re.sub(
        r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?:,\d{1,3})+(?![\d.])",
        _expand,
        raw,
    )


def _spec_to_checkable(spec: str) -> tuple[str | None, bool]:
    """Reduce one target spec to a (checkable_hostname_or_ip, is_broad_range).

    ``is_broad_range`` is True for CIDRs wider than /32 and hyphen-ranges,
    which are handled by :func:`_check_broad` instead of host-by-host.
    """
    spec = spec.strip()
    if "://" in spec:
        host = urlparse(spec).hostname
        return (host, False) if host else (None, False)
    if _is_cidr(spec):
        try:
            net = ipaddress.ip_network(spec, strict=False)
        except ValueError:
            return (spec, False)
        if net.prefixlen in (32, 128):
            return (str(net.network_address), False)
        return (None, True)
    if _is_hyphen_range(spec):
        return (None, True)
    if spec.startswith("[") and "]" in spec:
        # Bracketed spec: [v6] or [v6]:port — unbracket, drop a trailing :port.
        addr, _, rest = spec[1:].partition("]")
        rest = rest.strip()
        if not rest or (rest.startswith(":") and rest[1:].isdigit()):
            return (addr, False)
        return (None, False)
    if ":" in spec:
        # host:port with no scheme (e.g. tools that build 'cctv.htb:8080'
        # targets from a known open port): the port is not part of the
        # checkable — stripping it lets the host hit its blessed tier.
        # Unbracketed IPv6 literals (2001:db8::1) keep their colons, so the
        # host side contains ':' and is never stripped.
        host, _, port = spec.rpartition(":")
        if port.isdigit() and host and ":" not in host:
            return (host, False)
    if _is_ip(spec):
        return (spec, False)
    return (spec, False)  # bare hostname

