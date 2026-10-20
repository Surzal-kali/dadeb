"""File-backed, operator-armed scope gate for all traffic-sending tools.

Scope enforcement so a mis-targeted scan or crafted packet can't drift onto
an out-of-scope host.  Arming and disarming is a HUMAN authority action
performed from the Tool REPL (``scope on`` / ``scope off``) — it is
deliberately NOT exposed as an ``@framework_tool``, so the secretary agent
has no way to toggle or circumvent it.  When armed, every traffic-sending
tool consults this gate before firing; when disarmed (the default —
lab / VPN-practice mode) tools behave exactly as before.

Coverage
--------
Two entry points, both consulted before any wire traffic:

* :func:`check_send`  — packetcraft ``send_packet`` (a single destination IP
  extracted from a crafted packet; broadcast/multicast/loopback/link-local
  are never gated).
* :func:`check_scan`   — nmap / masscan / ffuf / hydra / ZAP open/spider/
  ajax/active-scan / send_raw.  Handles URL, bare hostname, IP, CIDR,
  hyphen-range, and whitespace/comma-separated lists.

Why file-backed, not a process singleton
----------------------------------------
The Brain sidecar and the Tool REPL are separate processes.  A tool call
dispatches to the Brain (the agent's normal path) when its socket is up and
falls back in-process otherwise.  A process-global singleton would only gate
the process that armed it.  The armed state is therefore persisted to
``scope/.armed_packet_scope.json`` so the operator's blessing — written from
the REPL — is authoritative in *every* process, including the Brain.  The
file is mtime-checked on each call so a REPL change takes effect immediately
inside a running Brain.  The agent has no tool that writes this file, so it
cannot disarm the gate.

IP <-> hostname bridge
----------------------
Bug-bounty manifests are almost entirely domain/wildcard/URL assets (~0
IP/CIDR across the cached set), but scanners and packet tools operate on
raw IPs/hosts.  The per-target verdict resolves in these tiers, first match
wins (out-of-scope always wins over an in-scope wildcard, mirroring
``program_scope.check_scope``):

1. **Operator allowlist** — IPs the operator blessed via ``scope add-ip``
   (authoritative and CDN-safe: the operator confirmed the IP by
   forward-resolving an in-scope hostname during recon).  This is the
   "passive OSINT allowlist" path.
2. **Manifest match** — :func:`auxiliaries.program_scope._find_match` against
   in-scope assets (DOMAIN/WILDCARD/URL for a hostname, CIDR/IP for an IP).
3. **Reverse-DNS attribution** (IPs only) — PTR-lookup and match the
   resulting hostname(s) against the manifest.  Tier 3 (PTR) is unverified,
   attacker-settable attribution; acceptance requires forward-confirmation
   (the PTR name must resolve back to the same IP).  CDN-hosted assets
   commonly PTR to the CDN, not the program domain, so this can
   false-negative; the operator falls back to tier 1 (``scope add-ip``) for
   those.

4. **IP boundary (optional, ``--ip-boundary`` at ``scope on``)** - when set and
   the operator has blessed >=1 IP, hostname targets that pass tier 1b/2 must
   forward-resolve into the blessed IP set; a manifest hostname asset that
   resolves outside it is refused (tier 3 PTR attribution is skipped for
   non-blessed IPs).  This is the drift guard from the 2026-09-20 fuzz-C
   finding: an explicit re-arm with a narrowed IP allowlist must supersede
   stale manifest hostname assets (a vhost whose DNS now points at a dropped
   host is refused, not waved through).  remove_ip also cascades: removing an
   IP purges blessed hostnames mapped to it.

Broad ranges (CIDR wider than /32, hyphen-ranges) can't be reliably
attributed host-by-host, so when armed they are allowed ONLY if the network
is a subnet of an explicit in-scope CIDR asset; otherwise they are refused
(broad subnet scanning is not a bug-bounty pattern — disarm for lab /
internal-network work).

Known limits
------------
The gate sees the REQUESTED target only — redirect-following (``ffuf -r``,
ZAP spider) and DNS-resolver traffic are out of its view.  amass /
subdomain_enum are program_scope-gated separately.  PTR tier-3 is
unverified, attacker-settable attribution; acceptance requires
forward-confirmation (the PTR name must resolve back to the same IP).

If no tier confirms in-scope and ``strict`` is True (default), the action
is REFUSED with guidance ("nada").  ``strict=False`` allows with a warning.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from constants import resolve_workspace_root

def _state_path() -> Path:
    """Resolve the armed-state file path at CALL time, not import time
    (matches program_scope's call-time ``os.getenv`` convention): a
    ``WORKSPACE_ROOT`` set after import still takes effect, and tests can
    redirect the state file per-call."""
    return resolve_workspace_root() / "scope" / ".armed_packet_scope.json"


class ScopeGateError(Exception):
    """Raised by a traffic-sending tool when the scope gate refuses a target.

    Raising (rather than returning an error dict/string) is deliberate: the
    Brain sidecar wraps any non-raising return as outer ``status:"success"``,
    which would bury a scope block as a silent success.  An exception makes
    both dispatch paths (Brain socket + in-process fallback) surface a clean
    ``Failed`` status with the scope reason so the secretary reads it as a
    real failure, not a plausible-success.  ``secretary_execute_tool``
    returns the Failed result to the model (it does not auto-retry), so the
    model can self-correct (different target) or surface the block to the
    operator (bless the IP / disarm).
    """

# In-process mtime cache so a running Brain notices a REPL-side change
# without re-reading the file on every call.  One stat per call is fine for
# scan/packet volumes (dozens, not k/s).
_CACHE: Dict[str, Any] = {"mtime": None, "state": None}


# --------------------------------------------------------------------------- #
# State file I/O
# --------------------------------------------------------------------------- #

def _write_state(state: Dict[str, Any]) -> None:
    """Atomic state write: stage to a ``.tmp`` sibling then ``os.replace``,
    so a crash mid-write can never leave a truncated / half-armed state file
    (a torn state file would parse as disarmed — fail-open)."""
    p = _state_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(state, indent=2))
    os.replace(tmp, p)
    _CACHE["mtime"] = p.stat().st_mtime
    _CACHE["state"] = state


def _load_state() -> Optional[Dict[str, Any]]:
    """Return the armed-state dict, or None when disarmed (no file).

    Mtime-checked so a REPL write is picked up by a separate process (Brain)
    on the very next call without a stale in-memory copy.
    """
    p = _state_path()
    if not p.is_file():
        _CACHE["mtime"] = None
        _CACHE["state"] = None
        return None
    try:
        mtime = p.stat().st_mtime
    except OSError:
        return None
    if _CACHE["mtime"] == mtime and _CACHE["state"] is not None:
        return _CACHE["state"]
    try:
        state = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    _CACHE["mtime"] = mtime
    _CACHE["state"] = state
    return state


def _load_manifest(handle: str, platform: str) -> Optional[Dict[str, Any]]:
    """Lazy import + cache load — keeps program_scope (and its deps) out of
    every importer's module load time."""
    from auxiliaries.program_scope import _load_cache
    return _load_cache(handle, platform)


# --------------------------------------------------------------------------- #
# Small host/IP shape helpers
# --------------------------------------------------------------------------- #

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


def _reverse_dns(ip: str, timeout: float = 2.0) -> List[str]:
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


# --------------------------------------------------------------------------- #
def _resolved_ips(host: str, timeout: float = 2.0) -> List[str]:
    """Forward-resolve a hostname to its CURRENT IP set (bounded).

    Used only by the optional ``--ip-boundary`` tier: a hostname asset passes
    the operator's IP boundary when every address it resolves to right now is
    in the blessed allowlist.  Capped at ``timeout`` like
    :func:`_reverse_dns` so a slow/broken resolver never pins a scan; any
    failure -> empty list, which the boundary treats as 'unconfirmable'
    (refused, fail-closed).
    """

    def _resolve() -> List[str]:
        infos = socket.getaddrinfo(host, None)
        return sorted({info[4][0] for info in infos})

    try:
        with ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(_resolve)
            return fut.result(timeout=timeout)
    except Exception:
        return []


# --------------------------------------------------------------------------- #
# Per-target verdict (shared by check_send and check_scan)
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #

def _check_one(checkable: Optional[str], state: Dict[str, Any]) -> Tuple[bool, str]:
    """Verdict for a single hostname or IP against the armed scope.

    ``checkable`` may be ``None`` (unparseable) — refused under strict,
    allowed (non-gated) under non-strict so the tool's own validation runs.
    """
    handle = state.get("handle", "")
    platform = state.get("platform", "h1")
    strict = state.get("strict", True)

    if checkable is None:
        if strict:
            return (
                False,
                "target could not be resolved to a checkable host/IP; "
                "refused (strict). Disarm with 'scope off' for lab, or pass "
                "an explicit hostname/IP.",
            )
        return True, "unparseable target (non-strict); not gated"

    checkable = checkable.strip()

    ip_boundary = bool(state.get("ip_boundary"))
    # Tier 1: operator-blessed allowlist (IPs; authoritative, CDN-safe).
    allowlist: Dict[str, str] = state.get("allowlist") or {}
    if checkable in allowlist:
        host = allowlist.get(checkable) or ""
        return True, f"in operator allowlist ({host})" if host else "in operator allowlist"
    # CIDR blessings (lab subnets): any blessed network containing the
    # target IP counts as an allowlist hit.
    try:
        _check_ip = ipaddress.ip_address(checkable)
        for _net_str, _net_host in allowlist.items():
            if "/" in _net_str and _check_ip in ipaddress.ip_network(_net_str):
                return True, (
                    f"in operator allowlist CIDR {_net_str}"
                    + (f" ({_net_host})" if _net_host else "")
                )
    except ValueError:
        pass  # checkable isn't an IP; fall through to hostname tiers

    # Tier 1b: operator-blessed hostnames (vhost lanes).  The operator asserts
    # the hostname->IP mapping explicitly via add_host (REPL-only); the gate
    # never resolves DNS for it - the operator's assertion IS the authority.
    # Keys are stored lowercased, trailing dot stripped; compare the same way.
    blessed_hosts: Dict[str, str] = state.get("blessed_hosts") or {}
    _hkey = checkable.lower().rstrip(".")
    stale_vhost_ip = ""
    if _hkey in blessed_hosts:
        # Drift guard (2026-09-20 fuzz-C): the vhost blessing is only as good
        # as the IP it was blessed against.  If that IP has since left the
        # allowlist (remove_ip on an older state file, a hand-edited state),
        # the stale hostname must not keep the dropped IP alive.  Fall through
        # to the manifest tiers; the refusal below carries the drift note.
        mapped_ip = (blessed_hosts[_hkey] or "").strip()
        if mapped_ip and mapped_ip in allowlist:
            return True, (
                f"in operator blessed-host list (maps to {mapped_ip})"
            )
        stale_vhost_ip = mapped_ip

    manifest = _load_manifest(handle, platform)
    if manifest is None:
        return (
            False,
            f"scope armed for {handle!r}/{platform} but manifest not loadable; "
            f"refusing. Run 'scope off' to disarm, or reload the program scope.",
        )

    from auxiliaries.program_scope import _find_match

    in_assets = manifest.get("in_scope", [])
    out_assets = manifest.get("out_of_scope_assets", [])

    # OOS always wins over a wildcard.
    if _find_match(checkable, out_assets):
        return False, f"{checkable} matches an explicitly out-of-scope asset; refused"

    # Tier 2: manifest match (domain/wildcard/URL for a hostname; CIDR/IP for an IP).
    if _find_match(checkable, in_assets):
        if ip_boundary and not _is_ip(checkable):
            # Operator IP boundary: the manifest asset passes only when the
            # hostname resolves, RIGHT NOW, into the blessed IP set.  A stale
            # manifest hostname asset (DNS moved to a dropped host) is caught
            # here instead of passing on a name match alone.
            resolved = _resolved_ips(checkable)
            if not resolved:
                return (
                    False,
                    f"{checkable} matches an in-scope asset but could not be "
                    f"resolved to verify the --ip-boundary; refused (strict). "
                    f"Bless the resolved IP with 'scope add-ip <ip> <hostname>' "
                    f"or re-arm without --ip-boundary.",
                )
            outside = [ip for ip in resolved if ip not in allowlist]
            if outside:
                return (
                    False,
                    f"{checkable} matches an in-scope asset but resolves to "
                    f"non-blessed IP(s) {outside} (operator IP boundary). "
                    f"Bless them with 'scope add-ip <ip> <hostname>' or re-arm "
                    f"without --ip-boundary.",
                )
            return True, (
                f"{checkable} matches an in-scope asset "
                f"(resolves to blessed IP(s) {resolved})"
            )
        return True, f"{checkable} matches an in-scope asset"

    # Tier 3: reverse-DNS attribution (IPs only).  PTR records are unverified,
    # attacker-settable data: an in-scope PTR name is accepted only after it
    # forward-confirms back to the same IP.  An out-of-scope PTR match still
    # refuses (fail-closed).
    if _is_ip(checkable) and not ip_boundary:
        # Under --ip-boundary a non-blessed IP has no path to a pass: the
        # operator's IP set IS the scope, so PTR attribution is skipped for
        # any IP outside it.
        for host in _reverse_dns(checkable):
            if _find_match(host, out_assets):
                return False, f"reverse-DNS {host} (for {checkable}) matches an out-of-scope asset; refused"
            if _find_match(host, in_assets):
                if _forward_confirm(host, checkable):
                    return True, (
                        f"reverse-DNS {host} (for {checkable}) matches an "
                        f"in-scope asset (forward-confirmed)"
                    )
                # PTR does not confirm — treat as no tier-3 match; falls
                # through to the normal verdict (refuse in strict mode).

    # Unconfirmed.
    if strict:
        drift = (
            f" NOTE: blessed host {_hkey!r} still maps to {stale_vhost_ip} which "
            "is no longer in the allowlist (stale vhost blessing - re-add via "
            "'scope add-host <hostname> <blessed-ip>' or 'scope rm-host');"
        ) if stale_vhost_ip else ""
        return (
            False,
            f"{checkable} not confirmed in-scope for program {handle!r}; refused "
            f"(strict). Bless a resolved IP with 'scope add-ip <ip> <hostname>' "
            f"or a vhost with 'scope add-host <hostname> <blessed-ip>' in the "
            f"Tool REPL, or 'scope off' for lab mode.{drift}",
        )
    return True, f"WARNING: {checkable} not confirmed in-scope (non-strict); proceeding"


def _check_broad(spec: str, state: Dict[str, Any]) -> Tuple[bool, str]:
    """Verdict for a broad CIDR / hyphen-range target.

    A broad range can't be attributed host-by-host (a /24 reverse-DNS is 256
    lookups).  It is allowed ONLY when it is a subnet of an explicit in-scope
    CIDR asset; otherwise refused under strict — broad subnet scanning is not
    a bug-bounty pattern.  Disarm (``scope off``) for lab / internal-network
    work where broad ranges are legitimate.
    """
    handle = state.get("handle", "")
    platform = state.get("platform", "h1")
    strict = state.get("strict", True)

    if _is_cidr(spec):
        try:
            net = ipaddress.ip_network(spec.strip(), strict=False)
        except ValueError:
            return _check_one(spec, state)  # not actually a CIDR; try as host
        manifest = _load_manifest(handle, platform)
        if manifest is not None:
            from auxiliaries.program_scope import _find_match
            # First: is it explicitly OOS?
            if _find_match(spec.strip(), manifest.get("out_of_scope_assets", [])):
                return False, f"{spec} matches an explicitly out-of-scope asset; refused"
            # Subnet of an in-scope CIDR asset?
            for a in manifest.get("in_scope", []):
                if (a.get("asset_type") or "").upper() in ("CIDR", "IP", "IP_ADDRESS"):
                    ident = (a.get("asset_identifier") or "").strip()
                    try:
                        asset_net = ipaddress.ip_network(ident, strict=False)
                    except ValueError:
                        continue
                    try:
                        if net.subnet_of(asset_net):
                            return True, f"{spec} is within in-scope CIDR asset {ident}"
                    except TypeError:
                        continue  # mixed v4/v6
        if strict:
            return (
                False,
                f"broad range {spec} not confirmable in-scope for {handle!r}; "
                f"refused (strict). Broad subnet scanning is not a bug-bounty "
                f"pattern — 'scope off' for lab/internal work, or scan specific "
                f"in-scope hosts.",
            )
        return True, f"WARNING: broad range {spec} not confirmed in-scope (non-strict)"

    # Hyphen range (not a CIDR): can't check containment reliably.
    if strict:
        return (
            False,
            f"hyphen-range {spec} not checkable against scope; refused (strict). "
            f"'scope off' for lab/internal work, or scan specific in-scope hosts.",
        )
    return True, f"WARNING: range {spec} not confirmed in-scope (non-strict)"


# --------------------------------------------------------------------------- #
# Public verdicts (called by traffic-sending tools)
# --------------------------------------------------------------------------- #

def _expand_comma_shorthand(raw: str) -> str:
    """Expand nmap-style octet-list commas: 'a.b.c.d,e,f' -> full IPs.

    Only rewrites comma-runs anchored on a dotted quad with BARE-octet
    followers (192.168.90.114,115,116,118).  Full-IP comma merges
    ('a.b.c.d,w.x.y.z'), CIDRs, hyphen ranges, and hostnames pass through
    untouched — nmap's own octet-list syntax stays one argv element for
    run_nmap, while the gate gets fully-qualified targets to validate.
    """

    def _expand(match: "re.Match[str]") -> str:
        anchor = match.group(0).split(",")[0]
        prefix = anchor.rsplit(".", 1)[0]
        followers = re.findall(r",(\d{1,3})", match.group(0))
        return ",".join([anchor] + [f"{prefix}.{o}" for o in followers])

    return re.sub(
        r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?:,\d{1,3})+(?![\d.])",
        _expand,
        raw,
    )

def check_send(dst_ip: Optional[str]) -> Tuple[bool, str]:
    """Verdict for a single packet destination IP (packetcraft).

    ``dst_ip`` is the destination extracted from the crafted packet
    (``pkt[IP].dst`` or ``pkt[ARP].pdst``); ``None`` means the frame carries
    no directed host IP (pure L2) and is allowed.  Non-routable destinations
    (broadcast/multicast/loopback/link-local) are never gated.
    """
    state = _load_state()
    if state is None:
        return True, "no scope armed (lab mode)"
    if dst_ip is None or not _is_gated_target(dst_ip):
        return True, "non-routable/local destination; not scope-gated"
    return _check_one(dst_ip, state)


def check_scan(target: Optional[str]) -> Tuple[bool, str]:
    """Verdict for a scan-tool target (nmap/masscan/ffuf/hydra/ZAP).

    Handles URL, bare hostname, IP, CIDR, hyphen-range, and whitespace/comma
    separated lists.  Refuses the whole scan if ANY spec is out-of-scope or
    unconfirmed (never partially fire).  Empty/None target is refused when
    armed (can't confirm scope for nothing) and allowed when disarmed.
    """
    state = _load_state()
    if state is None:
        return True, "no scope armed (lab mode)"

    raw = (target or "").strip()
    if not raw:
        return (
            False,
            "empty target; cannot confirm scope (scope armed). Pass an "
            "explicit in-scope target, or 'scope off' for lab mode.",
        )

    # Keep a URL whole (it may contain characters that look like separators);
    # otherwise split nmap/masscan-style "host1 host2,10.0.0.0/24" lists,
    # first expanding octet-list commas ('a.b.c.d,e,f') to full IPs so
    # shorthand lists validate like their fully-qualified equivalents.
    if "://" in raw:
        specs = [raw]
    else:
        specs = [
            s.strip()
            for s in re.split(r"[\s,]+", _expand_comma_shorthand(raw))
            if s.strip()
        ]

    warnings: List[str] = []
    for spec in specs:
        checkable, broad = _spec_to_checkable(spec)
        if broad:
            ok, reason = _check_broad(spec, state)
        else:
            ok, reason = _check_one(checkable, state)
        if not ok:
            return False, f"target {spec!r}: {reason}"
        # Surface non-strict WARNING verdicts in the aggregate too: the model
        # only ever sees check_scan's summary, so a pass-with-warning must not
        # be silently flattened into 'all specs confirmed in-scope'.
        if reason.upper().startswith("WARNING"):
            warnings.append(reason)
    summary = f"all {len(specs)} target spec(s) confirmed in-scope"
    if warnings:
        summary += " | " + " | ".join(warnings)
    return True, summary


def _spec_to_checkable(spec: str) -> Tuple[Optional[str], bool]:
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
    if _is_ip(spec):
        return (spec, False)
    return (spec, False)  # bare hostname


# --------------------------------------------------------------------------- #
# Operator control surface — called from the Tool REPL only (not agent tools)
# --------------------------------------------------------------------------- #

def arm(
    handle: str,
    platform: str = "h1",
    strict: bool = True,
    ip_boundary: bool = False,
) -> Dict[str, Any]:
    """Arm the scope gate against a program's manifest.

    Ensures the manifest is cached first (fetches via load_program_scope if
    missing) so the gate has something to match against.  Returns an
    ``{ok, ...}`` summary; ``ok=False`` with an ``error`` when the manifest
    can't be loaded (refuses to arm blind).
    """
    handle = (handle or "").strip()
    platform = (platform or "h1").strip().lower()
    if not handle:
        return {"ok": False, "error": "handle is required: scope on <handle> [--platform ...]"}

    manifest = _load_manifest(handle, platform)   # test-overridable seam
    if manifest is None:
        from auxiliaries.program_scope import _load_cache, load_program_scope
        manifest = _load_cache(handle, platform)
        if manifest is None:
            manifest = load_program_scope(handle, refresh=False, platform=platform)
    if not manifest or (
        isinstance(manifest, dict)
        and manifest.get("status") == "error"
        and not manifest.get("in_scope")
    ):
        return {
            "ok": False,
            "error": (
                f"no scope manifest for {handle!r}/{platform}; "
                f"run load_program_scope first (or load_program_scope --refresh)."
            ),
        }

    state = {
        "handle": handle,
        "platform": platform,
        "strict": bool(strict),
        "ip_boundary": bool(ip_boundary),
        "allowlist": {},
        "blessed_hosts": {},
        "armed_at": time.time(),
    }
    _write_state(state)
    return {
        "ok": True,
        "handle": handle,
        "platform": platform,
        "strict": strict,
        "in_scope_assets": len(manifest.get("in_scope", [])),
        "out_of_scope_assets": len(manifest.get("out_of_scope_assets", [])),
        "message": (
            "scope gate ARMED. Traffic-sending tools (nmap/masscan/ffuf/hydra/"
            "ZAP/packetcraft) will refuse out-of-scope targets. Use "
            "'scope add-ip <ip> <hostname>' to bless CDN/resolved IPs, "
            "'scope off' to disarm."
        ),
    }


def disarm() -> Dict[str, Any]:
    """Disarm the gate (lab mode — tools unrestricted)."""
    p = _state_path()
    if p.exists():
        try:
            p.unlink()
        except OSError:
            pass
    _CACHE["mtime"] = None
    _CACHE["state"] = None
    return {"ok": True, "disarmed": True, "message": "scope gate DISARMED (lab mode)."}


def add_ip(ip: str, hostname: str = "") -> Dict[str, Any]:
    """Bless an IP into the operator allowlist (authoritative, CDN-safe).

    Use this after confirming via recon (amass/dns forward-resolution) that
    ``ip`` belongs to an in-scope host.  Requires the gate to be armed.
    Accepts single IPs ('10.0.0.1') or CIDR blocks ('192.168.1.0/24').
    A CIDR blessing covers every address in the network -- use for lab
    subnets where the operator owns the whole range.
    """
    state = _load_state()
    if state is None:
        return {"ok": False, "error": "no scope armed; run 'scope on <handle>' first"}
    ip = (ip or "").strip()
    if not ip:
        return {"ok": False, "error": "ip is required"}
    if "/" in ip:
        # CIDR block: normalize via ip_network (strict=False zeroes host
        # bits, so 192.168.1.5/24 and 192.168.1.0/24 both land as
        # 192.168.1.0/24).
        try:
            ip = str(ipaddress.ip_network(ip, strict=False))
        except ValueError:
            return {"ok": False, "error": f"{ip!r} is not a valid CIDR network"}
    else:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return {
                "ok": False,
                "error": (
                    f"{ip!r} is not a valid IP address; to bless a hostname "
                    f"(vhost lane) use 'scope add-host <hostname> <blessed-ip>'"
                ),
            }
    state.setdefault("allowlist", {})[ip] = (hostname or "").strip()
    _write_state(state)
    return {
        "ok": True,
        "ip": ip,
        "hostname": hostname or "",
        "allowlist_size": len(state["allowlist"]),
        "message": f"blessed {ip}" + (f" ({hostname})" if hostname else ""),
    }


def add_host(hostname: str, ip: str) -> Dict[str, Any]:
    """Bless a hostname into the operator's blessed-host list (vhost support).

    For lanes whose connect target is a Host header (ZAP raw send), the gate
    sees a hostname the IP allowlist can never bless.  The operator asserts
    the hostname->IP mapping EXPLICITLY: ``ip`` must already be in the IP
    allowlist (bless the IP first), the mapping is stored verbatim, and the
    gate never resolves DNS for it.  Hostname shape is validated (no scheme,
    path, spaces, userinfo, or IP-lookalike); keys are lowercased, trailing
    dot stripped.
    """
    state = _load_state()
    if state is None:
        return {"ok": False, "error": "no scope armed; run 'scope on <handle>' first"}
    hostname = (hostname or "").strip().lower().rstrip(".")
    ip = (ip or "").strip()
    if not hostname or not ip:
        return {
            "ok": False,
            "error": "hostname and ip are required: scope add-host <hostname> <ip>",
        }
    if (
        _is_ip(hostname)
        or "://" in hostname
        or "/" in hostname
        or " " in hostname
        or ":" in hostname
        or "@" in hostname
    ):
        return {"ok": False, "error": f"{hostname!r} does not look like a bare hostname"}
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"ok": False, "error": f"{ip!r} is not a valid IP address"}
    if ip not in (state.get("allowlist") or {}):
        return {
            "ok": False,
            "error": (
                f"{ip} is not in the IP allowlist; run 'scope add-ip {ip} "
                f"<hostname>' first - hostnames may only map to blessed IPs"
            ),
        }
    state.setdefault("blessed_hosts", {})[hostname] = ip
    _write_state(state)
    return {
        "ok": True,
        "hostname": hostname,
        "ip": ip,
        "blessed_hosts": dict(state["blessed_hosts"]),
        "message": f"blessed {hostname} -> {ip}",
    }


def remove_host(hostname: str) -> Dict[str, Any]:
    """Remove a blessed hostname (REPL authority, same as add_host)."""
    state = _load_state()
    if state is None:
        return {"ok": False, "error": "no scope armed"}
    blessed = state.get("blessed_hosts") or {}
    key = (hostname or "").strip().lower().rstrip(".")
    if key not in blessed:
        return {"ok": False, "error": f"{key} not in blessed-host list"}
    del blessed[key]
    _write_state(state)
    return {"ok": True, "hostname": key, "blessed_hosts": dict(blessed)}


def remove_ip(ip: str) -> Dict[str, Any]:
    """Unbless an IP.  Cascades: blessed hostnames mapped to the removed IP
    are purged too - a stale vhost blessing must not keep a dropped IP alive
    through the tier-1b hostname lane (2026-09-20 fuzz-C drift fix)."""
    state = _load_state()
    if state is None:
        return {"ok": False, "error": "no scope armed"}
    allowlist = state.get("allowlist") or {}
    if ip not in allowlist:
        return {"ok": False, "error": f"{ip} not in allowlist"}
    del allowlist[ip]
    blessed = state.get("blessed_hosts") or {}
    purged = sorted(h for h, mapped in blessed.items() if (mapped or "").strip() == ip)
    for h in purged:
        del blessed[h]
    _write_state(state)
    return {
        "ok": True,
        "ip": ip,
        "allowlist_size": len(allowlist),
        "purged_blessed_hosts": purged,
        "message": f"unblessed {ip}"
        + (f"; purged stale vhost blessings: {purged}" if purged else ""),
    }


def list_ips() -> Dict[str, Any]:
    state = _load_state()
    if state is None:
        return {"ok": True, "armed": False, "allowlist": {}}
    return {"ok": True, "armed": True, "allowlist": state.get("allowlist") or {}}


def status() -> Dict[str, Any]:
    state = _load_state()
    if state is None:
        return {"ok": True, "armed": False, "message": "disarmed (lab mode — tools unrestricted)"}
    out: Dict[str, Any] = {
        "ok": True,
        "armed": True,
        "handle": state.get("handle"),
        "platform": state.get("platform", "h1"),
        "strict": state.get("strict", True),
        "allowlist_size": len(state.get("allowlist") or {}),
        "blessed_hosts_size": len(state.get("blessed_hosts") or {}),
        "ip_boundary": bool(state.get("ip_boundary")),
        "armed_at": state.get("armed_at"),
    }
    manifest = _load_manifest(state.get("handle", ""), state.get("platform", "h1"))
    if manifest:
        out["in_scope_assets"] = len(manifest.get("in_scope", []))
        out["out_of_scope_assets"] = len(manifest.get("out_of_scope_assets", []))
        # Manifest age: how stale the cached scope data behind this verdict
        # is (same cache file _load_cache reads for this handle/platform).
        try:
            from auxiliaries.program_scope import _scope_cache_path
            mp = _scope_cache_path(state.get("handle", ""), state.get("platform", "h1"))
            out["manifest_age_s"] = (
                int(time.time() - mp.stat().st_mtime) if mp.exists() else None
            )
        except OSError:
            out["manifest_age_s"] = None
    return out


def is_armed() -> bool:
    """Cheap boolean for the REPL prompt indicator (no manifest load)."""
    return _load_state() is not None


__all__ = [
    "check_send",
    "check_scan",
    "ScopeGateError",
    "arm",
    "disarm",
    "add_ip",
    "remove_ip",
    "add_host",
    "remove_host",
    "list_ips",
    "status",
    "is_armed",
]
