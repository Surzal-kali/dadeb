"""Forward/reverse DNS resolution utility — the scope-workflow feeder.

Answers one recon question fast: "which IP(s) does this site resolve to?"
so the OPERATOR can bless them into the armed scope (``scope add-ip`` in
the Tool REPL) and so the secretary can hand bare IPs to tools that need
IP-shaped arguments (packetcraft craft_*/send, masscan, raw_scan).

NOT scope-gated, by design and stated plainly: this module makes ZERO
contact with any target — it asks public resolvers about PUBLIC DNS
records (the same passive-intel class as amass's data sources), and its
whole purpose is to feed the scope workflow, where the gate's own tier-3
forward-confirmation does the same kind of lookup.  Gating the lookup
would be a chicken-and-egg refusal: a domain must resolve BEFORE it can
be confirmed in-scope and blessed.  Blessing itself stays operator-side
(``scope add-ip`` is a Tool REPL command, not an agent tool) — this tool
returns intel only and never writes scope state.

Tools:
- :func:`resolve_host` — A/AAAA/CNAME for one or more hostnames
  (whitespace/comma separated, dnspython with socket fallback).
- :func:`ptr_lookup` — reverse (PTR) for one or more IPs; useful for the
  gate's tier-3 hostname-attribution flow and for dossier enrichment.
"""

from __future__ import annotations

import re
import socket
from typing import Any, Dict, List, Optional

from constants import framework_tool

_MAX_HOSTS = 32
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}\.?$"
)
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def _validate_hostname(h: str) -> str:
    """Accept ONLY a bare hostname — no scheme, path, wildcard, or IP."""
    h = (h or "").strip().rstrip(".")
    if not h or any(c in h for c in " :/?#*@\\" ) or "://" in h:
        raise ValueError(
            f"{h!r} is not a bare hostname (no scheme/path/wildcard/spaces)"
        )
    if _IPV4_RE.match(h):
        raise ValueError(
            f"{h!r} looks like an IP — resolve_host takes hostnames; use "
            "ptr_lookup for IP -> name"
        )
    if not _HOSTNAME_RE.match(h.lower()):
        raise ValueError(f"{h!r} does not parse as a hostname")
    return h.lower()


def _dnspython_query(name: str, rdtype: str, timeout: float) -> List[Dict[str, Any]]:
    """A/AAAA/CNAME via dnspython; returns [{value, ttl}] entries."""
    import dns.exception
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2
    out: List[Dict[str, Any]] = []
    try:
        answers = resolver.resolve(name, rdtype)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except (dns.exception.DNSException, OSError):
        return []
    for rdata in answers:
        value = getattr(rdata, "address", None) or str(rdata).rstrip(".")
        ttl = getattr(answers, "ttl", None) or getattr(rdata, "ttl", None)
        out.append({"value": str(value).rstrip("."), "ttl": ttl})
    return out


def _socket_resolve(name: str) -> List[Dict[str, Any]]:
    """socket.getaddrinfo fallback (A/AAAA mixed, no TTL)."""
    try:
        infos = socket.getaddrinfo(name, None)
    except (socket.gaierror, OSError):
        return []
    seen: set = set()
    out: List[Dict[str, Any]] = []
    for info in infos:
        ip = info[4][0]
        if ip not in seen:
            seen.add(ip)
            out.append({"value": ip, "ttl": None})
    return out


def _resolve_one(hostname: str, timeout: float) -> Dict[str, Any]:
    name = _validate_hostname(hostname)
    records: Dict[str, List[Dict[str, Any]]] = {}
    try:
        import dns.resolver  # noqa: F401 - availability probe

        records["A"] = _dnspython_query(name, "A", timeout)
        records["AAAA"] = _dnspython_query(name, "AAAA", timeout)
        records["CNAME"] = _dnspython_query(name, "CNAME", timeout)
        engine = "dnspython"
    except ImportError:
        records["A"] = _socket_resolve(name)
        records["AAAA"] = []
        records["CNAME"] = []
        engine = "socket-fallback"
    resolved = [r["value"] for r in records["A"]] + [
        r["value"] for r in records["AAAA"]
    ]
    if not resolved and records["CNAME"]:
        alias = records["CNAME"][0]["value"]
        try:
            resolved = [
                r["value"]
                for r in _dnspython_query(alias, "A", timeout)
            ]
            records["CNAME_followed"] = alias
        except Exception:  # noqa: BLE001 - best effort alias chase
            pass
    return {
        "hostname": name,
        "records": records,
        "resolved_ips": resolved,
        "engine": engine,
    }


@framework_tool(
    "Resolve a bare site/hostname to its IP addresses (A + AAAA records, "
    "CNAME chain chased) so the OPERATOR can bless the IPs into the armed "
    "scope with 'scope add-ip' in the Tool REPL, and so models have bare "
    "IPs for tools that need IP-shaped arguments (packetcraft, masscan, "
    "raw_scan). Passive public-DNS data only — the target is never "
    "contacted; deliberately NOT scope-gated because it exists to feed "
    "the scope workflow. Never writes scope state itself.",
    next_hints=["probe_web", "run_nmap", "run_masscan", "check_scope"],
)
def resolve_host(
    hostnames: str,
    timeout: float = 5.0,
) -> Dict[str, Any]:
    """Resolve ``hostnames`` (whitespace/comma separated) to IP records.

    Args:
        hostnames: One or more bare hostnames, e.g. ``"example.com"`` or
            ``"api.example.com, www.example.com"`` (max 32).
        timeout: Per-query resolver timeout in seconds.
    """
    import time

    raw = (hostnames or "").strip()
    if not raw:
        return {"status": "Failed", "error": "no hostnames provided"}
    parts = [p for p in re.split(r"[\s,]+", raw) if p.strip()]
    if len(parts) > _MAX_HOSTS:
        return {
            "status": "Failed",
            "error": f"too many hostnames ({len(parts)} > {_MAX_HOSTS})",
        }

    started = time.time()
    results: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []
    for h in parts:
        try:
            results.append(_resolve_one(h, timeout))
        except ValueError as e:
            errors.append({"input": h, "error": str(e)})
        except Exception as e:  # noqa: BLE001 - never crash the batch
            errors.append({"input": h, "error": f"{type(e).__name__}: {e}"})

    all_ips = sorted({ip for r in results for ip in r["resolved_ips"]})
    return {
        "status": "Success",
        "results": results,
        "errors": errors,
        "unique_ips": all_ips,
        "elapsed_s": round(time.time() - started, 2),
        "note": (
            "Operator-side next step (Tool REPL): 'scope add-ip <ip> "
            "<hostname>' blesses a resolved IP into the armed allowlist "
            "(CDN-safe). This tool never writes scope state itself. "
            "Verify with check_scope before firing scans."
        ),
    }


@framework_tool(
    "Reverse-DNS (PTR) for one or more IPv4/IPv6 addresses: returns the "
    "pointer hostnames per IP. Useful for the scope gate's tier-3 "
    "hostname-attribution flow, dossier enrichment, and 'is this IP who "
    "it claims to be' checks. Passive public-DNS data only.",
    next_hints=["check_scope"],
)
def ptr_lookup(ips: str, timeout: float = 5.0) -> Dict[str, Any]:
    """Reverse-resolve ``ips`` (whitespace/comma separated, max 32)."""
    import ipaddress
    import time

    raw = (ips or "").strip()
    if not raw:
        return {"status": "Failed", "error": "no IPs provided"}
    parts = [p for p in re.split(r"[\s,]+", raw) if p.strip()]
    if len(parts) > _MAX_HOSTS:
        return {"status": "Failed", "error": f"too many IPs ({len(parts)})"}

    results: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []
    for ip_str in parts:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            errors.append({"ip": ip_str, "error": "not a valid IP"})
            continue
        names: List[str] = []
        try:
            import dns.reversename
            import dns.resolver

            rev = dns.reversename.from_address(str(ip))
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout * 2
            answers = resolver.resolve(rev, "PTR")
            names = [str(r).rstrip(".") for r in answers]
        except ImportError:
            try:
                names = list(socket.gethostbyaddr(str(ip))[2])
            except (socket.herror, socket.gaierror, OSError):
                names = []
        except Exception as e:  # noqa: BLE001 - NXDOMAIN/etc. are fine
            errors.append({"ip": ip_str, "error": f"{type(e).__name__}"})
            continue
        results.append({"ip": str(ip), "ptr": names})

    return {
        "status": "Success",
        "results": results,
        "errors": errors,
        "note": (
            "PTR names are attacker-controlled data — attribution hints, "
            "never proof. The scope gate's tier-3 requires forward "
            "confirmation before trusting a PTR match."
        ),
    }


__all__ = ["resolve_host", "ptr_lookup"]