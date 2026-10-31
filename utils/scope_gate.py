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
import time
from pathlib import Path
from typing import Any

from constants import resolve_workspace_root
from utils._scope_gate_disabled import (
    disable_tools,
    disabled_reject_envelope,
    enable_tools,
    is_disabled,
    list_disabled,
)
from utils._scope_gate_net import (
    _expand_comma_shorthand,
    _forward_confirm,
    _is_cidr,
    _is_gated_target,
    _is_ip,
    _range_endpoints,
    _resolved_ips,
    _reverse_dns,
    _spec_to_checkable,
    unwrap_list_shaped_target,
)


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
_CACHE: dict[str, Any] = {"mtime": None, "state": None}


# --------------------------------------------------------------------------- #
# State file I/O
# --------------------------------------------------------------------------- #

def _write_state(state: dict[str, Any]) -> None:
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


def _load_state() -> dict[str, Any] | None:
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


def _load_manifest(handle: str, platform: str) -> dict[str, Any] | None:
    """Lazy import + cache load — keeps program_scope (and its deps) out of
    every importer's module load time."""
    from auxiliaries.program_scope import _load_cache
    return _load_cache(handle, platform)


# --------------------------------------------------------------------------- #
# Per-target verdict (shared by check_send and check_scan)
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #

def _check_one(checkable: str | None, state: dict[str, Any]) -> tuple[bool, str]:
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
    allowlist: dict[str, str] = state.get("allowlist") or {}
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
    blessed_hosts: dict[str, str] = state.get("blessed_hosts") or {}
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


def _check_broad(spec: str, state: dict[str, Any]) -> tuple[bool, str]:
    """Verdict for a broad CIDR / hyphen-range target.

    Order mirrors ``_check_one``: the operator's allowlist is tier 1 —
    a blessed CIDR (``scope add-ip 10.0.0.0/24``) admits any broad spec
    inside it (CIDR equal/subnet; hyphen range with BOTH endpoints in the
    one blessed network, last-octet shorthand supported). THEN a program
    manifest CIDR asset admits subnets. Everything else is refused under
    strict — broad subnet scanning is not a bug-bounty pattern; disarm
    (``scope off``) for lab / internal-network work where broad ranges
    are legitimate.
    """
    handle = state.get("handle", "")
    platform = state.get("platform", "h1")
    strict = state.get("strict", True)

    if _is_cidr(spec):
        try:
            net = ipaddress.ip_network(spec.strip(), strict=False)
        except ValueError:
            return _check_one(spec, state)  # not actually a CIDR; try as host
        # Tier 1 first (mirrors _check_one's order): the operator's
        # allowlist IS the authority — a one-call `scope add-ip <cidr>`
        # blesses the whole range, no program manifest required.
        allowlist: dict[str, str] = state.get("allowlist") or {}
        for net_str, host in allowlist.items():
            if "/" not in net_str:
                continue
            try:
                blessed = ipaddress.ip_network(net_str)
            except ValueError:
                continue
            try:
                if net == blessed or net.subnet_of(blessed):
                    return True, (
                        f"{spec} within operator allowlist CIDR {net_str}"
                        + (f" ({host})" if host else "")
                    )
            except TypeError:
                continue  # mixed v4/v6
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
                f"in-scope hosts. If you own the whole range, bless it once: "
                f"'scope add-ip {spec}'.",
            )
        return True, f"WARNING: broad range {spec} not confirmed in-scope (non-strict)"

    # Hyphen range (not a CIDR): both endpoint spellings (full IPs and the
    # last-octet shorthand) checked against ONE blessed network — a range
    # split across two blessings is not covered; bless the covering CIDR.
    eps = _range_endpoints(spec)
    if eps is not None:
        lo, hi = eps
        allowlist = state.get("allowlist") or {}
        for net_str, host in allowlist.items():
            if "/" not in net_str:
                continue
            try:
                net = ipaddress.ip_network(net_str)
            except ValueError:
                continue
            if (
                int(lo) >= int(net.network_address)
                and int(hi) <= int(net.broadcast_address)
            ):
                return True, (
                    f"{spec} within operator allowlist CIDR {net_str}"
                    + (f" ({host})" if host else "")
                )
        # A range that both endpoints of a blessed CIDR span: covered by the
        # subnet rule whenever the range IS the network span.
        if strict:
            left0 = spec.split("-", 1)[0].strip()
            hint_net = (
                ".".join(left0.split(".")[:3]) + ".0/24"
                if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", left0)
                else "<cidr>"
            )
            return (
                False,
                f"hyphen-range {spec} not confirmable in-scope for {handle!r}; "
                f"refused (strict). If the whole span is yours, bless it once: "
                f"'scope add-ip {hint_net}' — or 'scope off' for lab work.",
            )
        return True, f"WARNING: range {spec} not confirmed in-scope (non-strict)"

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

def check_send(dst_ip: str | None) -> tuple[bool, str]:
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


def check_scan(target: str | None) -> tuple[bool, str]:
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
    # Driving models emit list-typed targets the preflight coerces to a
    # stringified JSON array — unwrap one level so the specs below see
    # hosts/URLs, not '["cctv.htb"]' plumbing (cctv.htb incident 2026-10-31).
    raw = unwrap_list_shaped_target(raw)

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

    warnings: list[str] = []
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


# --------------------------------------------------------------------------- #
# Operator control surface — called from the Tool REPL only (not agent tools)
# --------------------------------------------------------------------------- #

_BOARD_PLATFORMS = ("h1", "bugcrowd", "intigriti")


def arm(
    handle: str,
    platform: str = "h1",
    strict: bool = True,
    ip_boundary: bool = False,
    refresh: bool = False,
) -> dict[str, Any]:
    """Arm the scope gate against a program's manifest.

    Ensures the manifest is cached first (fetches via load_program_scope if
    missing, or fetches fresh when ``refresh`` is set — board lanes only;
    custom platforms are operator-authored files, never fetched) so the gate
    has something to match against.  Returns an ``{ok, ...}`` summary;
    ``ok=False`` with an ``error`` when the manifest can't be loaded
    (refuses to arm blind).
    """
    handle = (handle or "").strip()
    platform = (platform or "h1").strip().lower()
    if not handle:
        return {"ok": False, "error": "handle is required: scope on <handle> [--platform ...]"}
    board = platform in _BOARD_PLATFORMS

    manifest = _load_manifest(handle, platform)   # test-overridable seam
    if manifest is None:
        from auxiliaries.program_scope import _load_cache, load_program_scope
        if board:
            manifest = load_program_scope(handle, refresh=bool(refresh), platform=platform)
        else:
            # Custom platform (e.g. lab): the only source is the
            # operator-authored file — the board lane can never know it, so
            # don't ask it (asking buried a useless "unknown platform" error
            # under the manifest-missing message below).
            manifest = _load_cache(handle, platform)
    if not manifest or (
        isinstance(manifest, dict)
        and manifest.get("status") == "error"
        and not manifest.get("in_scope")
    ):
        from auxiliaries.program_scope import _scope_cache_path
        if board:
            remedy = (
                "run load_program_scope first "
                f"(or 'scope on {handle} --platform {platform} --refresh')"
            )
        else:
            remedy = (
                "expected operator-authored manifest at "
                f"{_scope_cache_path(handle, platform)} — named "
                "<platform>_<handle>.json (the seeded lab template "
                "lab_local-lab.json is platform 'lab' + handle 'local-lab', "
                "armed with 'scope on local-lab --platform lab')"
            )
        return {
            "ok": False,
            "error": (
                f"no scope manifest for handle {handle!r}, platform {platform!r}; "
                f"{remedy}"
            ),
        }

    # Carry forward an existing disabled_tools list so a re-arm (manifest
    # refresh) does NOT silently wipe every operator disable. The drift shape
    # this prevents is the 2026-09-20 --ip-boundary finding: the operator
    # re-armed after a refresh and assumed the disable survived. Read the
    # PRE-arm state before _write_state clobbers it.
    prior_disabled: list[str] = []
    _prior = _load_state()
    if isinstance(_prior, dict):
        prior_disabled = list(_prior.get("disabled_tools") or [])

    state = {
        "handle": handle,
        "platform": platform,
        "strict": bool(strict),
        "ip_boundary": bool(ip_boundary),
        "allowlist": {},
        "blessed_hosts": {},
        "disabled_tools": prior_disabled,
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
        "disabled_tools_count": len(prior_disabled),
        "message": (
            "scope gate ARMED. Traffic-sending tools (nmap/masscan/ffuf/hydra/"
            "ZAP/packetcraft) will refuse out-of-scope targets. Use "
            "'scope add-ip <ip> <hostname>' to bless CDN/resolved IPs, "
            "'scope off' to disarm."
        ),
    }


def disarm() -> dict[str, Any]:
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


def add_ip(ip: str, hostname: str = "") -> dict[str, Any]:
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


def add_host(hostname: str, ip: str) -> dict[str, Any]:
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


def remove_host(hostname: str) -> dict[str, Any]:
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


def remove_ip(ip: str) -> dict[str, Any]:
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


def list_ips() -> dict[str, Any]:
    state = _load_state()
    if state is None:
        return {"ok": True, "armed": False, "allowlist": {}}
    return {"ok": True, "armed": True, "allowlist": state.get("allowlist") or {}}


def status() -> dict[str, Any]:
    state = _load_state()
    if state is None:
        return {"ok": True, "armed": False, "message": "disarmed (lab mode — tools unrestricted)"}
    out: dict[str, Any] = {
        "ok": True,
        "armed": True,
        "handle": state.get("handle"),
        "platform": state.get("platform", "h1"),
        "strict": state.get("strict", True),
        "allowlist_size": len(state.get("allowlist") or {}),
        "blessed_hosts_size": len(state.get("blessed_hosts") or {}),
        "ip_boundary": bool(state.get("ip_boundary")),
        "disabled_tools": list(state.get("disabled_tools") or []),
        "disabled_tools_count": len(state.get("disabled_tools") or []),
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
    "unwrap_list_shaped_target",
    "arm",
    "disarm",
    "add_ip",
    "remove_ip",
    "add_host",
    "remove_host",
    "list_ips",
    "status",
    "is_armed",
    "is_disabled",
    "disable_tools",
    "enable_tools",
    "list_disabled",
    "disabled_reject_envelope",
]
