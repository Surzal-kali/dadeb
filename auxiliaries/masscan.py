"""Masscan fast port scanner — background launch + poll pattern.

masscan is an asynchronous (stateless) TCP/UDP port scanner that can sweep
entire /8 networks at millions of packets/sec.  Like nmap/ffuf it can run
long enough to fight the secretary turn timeout, so it uses the shared
:mod:`utils.background_job` helper: ``run_masscan`` launches a detached
subprocess and returns a ``job_id`` immediately; ``masscan_status`` polls
until ``status: "done"``; ``masscan_cancel`` terminates early.

Design decisions baked into the wrapper (see the schema hand-off notes):

* **JSON-only output** — ``-oJ <job-file>`` is fixed and non-user-facing,
  consistent with how every other tool returns parseable structured output.
* **Truncated-JSON tolerance** — masscan streams JSON array records and only
  appends the closing ``]`` on a clean exit.  Any killed/interrupted job
  (framework timeout, the reaper, a gateway restart that kills children)
  leaves a truncated file.  The parser scans for balanced ``{ ... }``
  objects and tolerates a missing closing bracket and a trailing partial
  record; it never ``json.load``s blind.
* **Adapter pinning** — masscan's "first iface with a default gateway"
  auto-pick is exactly the silent-wrong-source-path behaviour that has
  burned callback routing before (LAN vs Tailscale vs a lab vnic).  The
  wrapper pins ``--adapter-ip`` explicitly: from ``$MASSCAN_ADAPTER_IP``
  if set, otherwise auto-detected via the default-route UDP-connect trick
  and logged so the chosen source is visible.  ``$MASSCAN_ADAPTER`` pins
  the interface name (``-e``); without it, ``$PACKET_CRAFT`` (the shared
  packet-tools default read by ``utils/packetcraft.py``) is honoured next,
  then masscan auto-picks.
* **Self-exclude by default** — the wrapper's own host IP is added to
  ``--exclude`` by default (overridable) so a broad CIDR sweep never scans
  the scanning box itself, matching the rule already used for nmap.
* **Rate safety** — ``rate=None`` means "do not pass ``--rate``" so masscan
  uses its binary default of 100 pps, which is safe on a shared lab vnic.
  ``$MASSCAN_MAX_RATE`` clamps any caller-supplied rate and warns.
* **Operational plumbing hidden** — ``--conf``, ``--resume*``, ``--shards``,
  ``--echo``, ``--regress``, ``-sL``, ``--pfring``, ``--pcap-payloads``,
  ``--nmap-payloads``, ``--http-user-agent``, ``--nmap`` and the
  rotate/offset/dir knobs are stripped from ``flags``/``options`` so the
  model can't destabilise a run via the escape hatch.
"""

from __future__ import annotations

import json as _json
import os
import shlex
import socket
import uuid
from typing import Any, Dict, List, Optional, Tuple

from constants import framework_tool
from utils.background_job import launch_job, poll_job, terminate_job, register_verdict_parser


# --- operational-plumbing denylist -------------------------------------------

# Flags the wrapper must not let the model reach, because they destabilise
# the launch/poll contract (conf files, resume state, sharding, echo/regress
# test modes, alternate payload sources, etc.).  Each entry maps a bare flag
# name to whether it consumes the next argv token as a value.
_DENYLIST: Dict[str, bool] = {
    "-c": True,
    "--conf": True,
    "--resume": False,
    "--resume-index": True,
    "--resume-count": True,
    "--shards": True,
    "--rotate": True,
    "--rotate-offset": True,
    "--rotate-dir": True,
    "--offset": True,
    "--dir": True,
    "--echo": False,
    "--regress": False,
    "-sL": False,
    "--pfring": False,
    "--pcap-payloads": True,
    "--nmap-payloads": True,
    "--http-user-agent": True,
    "--nmap": False,
}

# Core flags the wrapper manages itself; if the model also passes them via
# ``flags``/``options`` we drop the duplicate so the fixed value wins.
_OWNED_FLAGS = {
    "-p", "--ports", "--rate", "--wait", "--exclude", "--excludefile",
    "-oJ", "-oX", "-oB", "-oG", "-oL",
    "--output-format", "--output-filename",
    "--adapter-ip", "--adapter", "-e",
}


def _strip_denied(tokens: List[str]) -> Tuple[List[str], List[str]]:
    """Remove denylisted + owned flags from a token list.

    Returns ``(clean, dropped)`` where ``dropped`` is a list of the raw
    tokens that were removed (flag + its value where applicable) for the
    warning message.
    """
    clean: List[str] = []
    dropped: List[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        bare = tok.split("=", 1)[0]
        if bare in _DENYLIST:
            dropped.append(tok)
            if _DENYLIST[bare] and "=" not in tok and i + 1 < len(tokens):
                dropped.append(tokens[i + 1])
                i += 2
            else:
                i += 1
            continue
        if bare in _OWNED_FLAGS:
            dropped.append(tok)
            # owned value-flags all take a separate token (masscan has no
            # --flag=value form for these), so swallow the next token too
            # unless it looks like another flag.
            if i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
                dropped.append(tokens[i + 1])
                i += 2
            else:
                i += 1
            continue
        clean.append(tok)
        i += 1
    return clean, dropped


# --- adapter / self-exclude detection ---------------------------------------

def _detect_local_ip() -> Optional[str]:
    """Best-effort local IP via a UDP connect to the default route.

    Mirrors the trick used in :mod:`listeners.collaborator`.  Returns the
    source IP the kernel would use to reach the internet (i.e. the default-
    route interface), which is the right source for scanning an external
    bug-bounty target.  Returns ``None`` on failure.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def _get_iface_ip(iface: str) -> Optional[str]:
    """Resolve the primary IPv4 address bound to a named interface.

    Uses ``ip -o -4 addr show <iface>`` and parses the first ``inet`` token.
    This matters because :func:`_detect_local_ip` returns the *default-route*
    source IP, which may belong to a different interface than the one the
    caller pinned via ``adapter=``.  Without this, masscan gets ``-e eth0``
    (correct interface) but ``--adapter-ip <default-route-IP>`` (wrong NIC's
    IP), and the stale ``--adapter-ip`` wins — exactly the silent-wrong-source
    bug the adapter pinning was meant to prevent.

    Returns ``None`` if the interface doesn't exist or has no IPv4 address.
    """
    import subprocess
    try:
        r = subprocess.run(
            ["ip", "-o", "-4", "addr", "show", iface],
            capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0 or not r.stdout.strip():
        return None
    # Output format: "wlp0s20f3    inet 10.10.10.1/24 brd ..."
    parts = r.stdout.split()
    for i, p in enumerate(parts):
        if p == "inet" and i + 1 < len(parts):
            return parts[i + 1].split("/")[0]
    return None


def _resolve_adapter(adapter: Optional[str]) -> Optional[str]:
    """Resolve the masscan adapter/interface (``-e``) at call time.

    Precedence: ``adapter`` parameter > ``$MASSCAN_ADAPTER`` (masscan-
    specific) > ``$PACKET_CRAFT`` (shared packet-tools default, same var
    ``utils/packetcraft.py`` reads) > ``None`` (masscan auto-picks the
    first iface with a default gateway).  Read per-call so loaddotenv
    /.env edits apply without re-import.
    """
    return (
        adapter
        or os.getenv("MASSCAN_ADAPTER")
        or os.getenv("PACKET_CRAFT")
        or None
    )


def _default_self_exclude() -> Optional[str]:
    """The IP/CIDR to ``--exclude`` by default (the scanner's own host)."""
    return os.getenv("MASSCAN_SELF_EXCLUDE") or _detect_local_ip()


# --- truncated-JSON-tolerant parser -----------------------------------------

def _scan_json_objects(text: str) -> List[Dict[str, Any]]:
    """Extract complete ``{ ... }`` JSON objects from (possibly truncated) text.

    masscan's ``-oJ`` writes a JSON array: a leading ``[``, one object per
    host separated by ``,\\n``, and a closing ``]`` on clean exit.  On kill
    the file ends mid-object with no closing bracket.  This scanner walks
    the text with brace-depth tracking (respecting strings and escapes) and
    ``json.loads`` each balanced object, silently skipping a trailing
    incomplete record.  It therefore yields every host whose record was
    fully written, regardless of how the process ended.
    """
    objects: List[Dict[str, Any]] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "{":
            depth = 0
            start = i
            in_str = False
            esc = False
            j = i
            while j < n:
                c = text[j]
                if in_str:
                    if esc:
                        esc = False
                    elif c == "\\":
                        esc = True
                    elif c == '"':
                        in_str = False
                else:
                    if c == '"':
                        in_str = True
                    elif c == "{":
                        depth += 1
                    elif c == "}":
                        depth -= 1
                        if depth == 0:
                            blob = text[start:j + 1]
                            try:
                                obj = _json.loads(blob)
                                if isinstance(obj, dict):
                                    objects.append(obj)
                            except _json.JSONDecodeError:
                                pass
                            i = j + 1
                            break
                j += 1
            else:
                # Ran off the end without closing -> truncated final record.
                break
        else:
            i += 1
    return objects


def _parse_masscan_json(out_path: str) -> Optional[Dict[str, Any]]:
    """Parse masscan's ``-oJ`` output file with truncation tolerance.

    Returns ``{"hosts": [...], "open_port_count": N, "hosts_with_open": N,
    "meta": {...}}`` or ``None`` if the file is missing/empty.  ``truncated``
    is True when the file lacks a closing ``]`` (i.e. the job was
    interrupted before clean exit).
    """
    try:
        with open(out_path, "r", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return None
    if not text.strip():
        return None

    truncated = not text.rstrip().endswith("]")
    records = _scan_json_objects(text)

    hosts: List[Dict[str, Any]] = []
    open_port_count = 0
    for rec in records:
        ip = rec.get("ip")
        ts = rec.get("timestamp")
        ports = rec.get("ports") or []
        port_entries: List[Dict[str, Any]] = []
        for p in ports:
            if not isinstance(p, dict):
                continue
            entry = {
                "port": p.get("port"),
                "proto": p.get("proto"),
                "state": p.get("status") or "open",
                "reason": p.get("reason"),
                "ttl": p.get("ttl"),
            }
            if p.get("banner"):
                entry["banner"] = p["banner"]
            port_entries.append(entry)
            if entry["state"] == "open":
                open_port_count += 1
        hosts.append({
            "ip": ip,
            "timestamp": ts,
            "ports": port_entries,
            "open_count": sum(1 for e in port_entries if e["state"] == "open"),
        })

    return {
        "hosts": hosts,
        "open_port_count": open_port_count,
        "hosts_with_open": sum(1 for h in hosts if h["open_count"]),
        "meta": {
            "source": "json",
            "truncated": truncated,
            "records": len(records),
            "output_file": out_path,
        },
    }


def _parse_masscan_verdict(out_path: str):
    """Build a verdict_parser closure bound to the job's JSON output file."""
    def _parser(_log_text: str) -> Dict[str, Any]:
        parsed = _parse_masscan_json(out_path)
        if parsed:
            return parsed
        return {
            "hosts": [],
            "open_port_count": 0,
            "hosts_with_open": 0,
            "meta": {"source": "json", "truncated": False, "note": "no output yet"},
        }
    return _parser


# Fallback parser for reconstructed jobs (closure is gone): try to find
# the JSON output file from the log text, parse it, or return a minimal
# verdict.  The live closure (set at launch time) is preferred via the
# in-process _JOBS entry; this only runs after a restart/reconstruction.
def _masscan_fallback_verdict(log_text: str) -> Dict[str, Any]:
    import re as _re
    m = _re.search(r"-oJ\s+(\S+\.json)", log_text)
    if m:
        parsed = _parse_masscan_json(m.group(1))
        if parsed:
            return parsed
    return {
        "hosts": [],
        "open_port_count": 0,
        "hosts_with_open": 0,
        "meta": {"source": "json", "truncated": False, "note": "output file not found after reconstruction"},
    }


register_verdict_parser("masscan", _masscan_fallback_verdict)


# --- tool surface -----------------------------------------------------------

@framework_tool(
    "Launch a fast Masscan asynchronous port scan against a target IP, "
    "range, or CIDR (e.g. 10.0.0.0/24, 192.168.0.1-50, or a comma-merged "
    "list). Discovers open TCP/UDP ports at high speed. Non-blocking and "
    "detached — starts the scan in the background and returns immediately "
    "with a job ID. Confirm the launch with one status poll, then hand off to "
    "the user; poll again only when the user requests an update. "
    "JSON output is captured to a per-job file and parsed into a structured "
    "list of open ports per host; results survive interruption (truncated "
    "JSON is tolerated). Default rate is masscan's safe 100 pps; pass a "
    "higher rate only when appropriate. The scanner's own IP is excluded by "
    "default. Pass adapter='eth0' (or tun0, etc.) to pin the source "
    "interface — this overrides $MASSCAN_ADAPTER and $PACKET_CRAFT and "
    "prevents masscan's default auto-pick from selecting the wrong NIC on "
    "multi-interface hosts.",
    next_hints=["masscan_status", "run_nmap"],
    untrusted_target=True,
)
def run_masscan(
    target: str,
    ports: Optional[str] = None,
    rate: Optional[int] = None,
    adapter: Optional[str] = None,
    flags: Optional[str] = None,
    exclude: Optional[str] = None,
    options: Optional[str] = None,
) -> Dict[str, Any]:
    """Launch masscan against ``target`` and return immediately.

    masscan runs as a detached background subprocess writing JSON to a
    per-job file; this call does NOT block.  Perform one status poll to confirm
    it is running, then hand off to the user.  Poll again only when the user
    requests an update.

    Args:
        target: Required. IP, hyphen-range (``a.b.c.d-a.b.c.e``), CIDR
            (``10.0.0.0/8``), or comma-merged list
            (``10.0.0.0/8,192.168.0.1``).  Passed positionally to masscan.
        ports: Ports to scan, e.g. ``"80"``, ``"20-25"``, ``"80,443,8080"``,
            or ``"U:161,U:1024-1100"`` for UDP.  Defaults to ``"80"`` if
            unset (masscan requires at least one port).
        rate: Packets/sec.  ``None`` (default) = do not pass ``--rate``, so
            masscan uses its binary default of 100 pps (safe for shared
            networks).  Clamped by ``$MASSCAN_MAX_RATE`` if set.
        adapter: Source network interface name (e.g. ``"eth0"``, ``"tun0"``).
            Overrides ``$MASSCAN_ADAPTER`` and the shared ``$PACKET_CRAFT``
            default (same var ``utils/packetcraft.py`` reads).  When none of
            parameter / ``$MASSCAN_ADAPTER`` / ``$PACKET_CRAFT`` is set,
            masscan auto-picks the first interface with a default gateway —
            which can break scans on multi-interface hosts.  Pass this
            explicitly whenever the host has more than one NIC.
        flags: Free-form extra masscan flags as a single string
            (e.g. ``"--banners --open-only"``).  Owned/dangerous flags are
            stripped (see module docstring).
        exclude: IP/range to ``--exclude``.  ``None`` (default) = exclude the
            scanner's own host IP automatically.  A non-empty string =
            explicit exclude list (replaces the default).  ``""`` = opt out
            of any exclude.
        options: Full shlex passthrough escape hatch appended last.  Same
            denylist applies.  Use sparingly.
    """
    if not target or not str(target).strip():
        return {
            "job_id": None,
            "tool": "masscan",
            "status": "error",
            "error": "target is required (IP, range, or CIDR)",
        }

    # Scope gate (operator-armed from the Tool REPL; no-op in lab mode).
    from utils.scope_gate import check_scan, ScopeGateError
    _sc_ok, _sc_reason = check_scan(target)
    if not _sc_ok:
        raise ScopeGateError(f"scope gate: {_sc_reason}")

    # --- ports -----------------------------------------------------------
    ports = (ports or "80").strip() or "80"

    # --- rate ------------------------------------------------------------
    rate_warn: Optional[str] = None
    if rate is not None:
        try:
            rate = int(rate)
        except (TypeError, ValueError):
            return {
                "job_id": None,
                "tool": "masscan",
                "status": "error",
                "error": f"rate must be an integer, got {rate!r}",
            }
        max_rate = os.getenv("MASSCAN_MAX_RATE")
        if max_rate:
            try:
                cap = int(max_rate)
                if rate > cap:
                    rate_warn = (
                        f"requested rate {rate} clamped to MASSCAN_MAX_RATE={cap}"
                    )
                    rate = cap
            except ValueError:
                pass

    # --- exclude ---------------------------------------------------------
    if exclude is None:
        exclude = _default_self_exclude()  # may be None if detection failed
    exclude = (exclude or "").strip()

    # --- adapter pinning -------------------------------------------------
    # See _resolve_adapter: parameter > $MASSCAN_ADAPTER > $PACKET_CRAFT >
    # None (masscan auto-pick).
    adapter_iface = _resolve_adapter(adapter)

    # Resolve --adapter-ip from the SPECIFIED interface when possible, so
    # the source IP matches the pinned NIC.  Fall back to $MASSCAN_ADAPTER_IP,
    # then to the default-route IP.  Without this, --adapter-ip always
    # reflected the default-route interface (e.g. 10.10.10.1 on enp92s0)
    # regardless of the -e <iface> flag — masscan then used the wrong NIC's
    # IP as source, silently breaking scans on multi-interface hosts.
    adapter_ip: Optional[str] = None
    adapter_warn: Optional[str] = None
    if adapter_iface:
        adapter_ip = _get_iface_ip(adapter_iface)
        if adapter_ip:
            adapter_warn = (
                f"adapter-ip {adapter_ip} resolved from interface "
                f"{adapter_iface!r}"
            )
        else:
            adapter_warn = (
                f"could not resolve IPv4 for interface {adapter_iface!r}; "
                f"falling back to default-route or MASSCAN_ADAPTER_IP"
            )
    if not adapter_ip:
        adapter_ip = os.getenv("MASSCAN_ADAPTER_IP") or _detect_local_ip()
        if not os.getenv("MASSCAN_ADAPTER_IP") and adapter_ip:
            adapter_warn = (
                (adapter_warn + "; " if adapter_warn else "")
                + f"adapter-ip auto-detected as {adapter_ip} via default route; "
                "set MASSCAN_ADAPTER_IP to pin explicitly"
            )
    if not adapter_iface:
        adapter_warn = (
            (adapter_warn + "; " if adapter_warn else "")
            + "no adapter/interface specified (parameter, MASSCAN_ADAPTER, "
            "or PACKET_CRAFT); masscan will auto-pick the first iface with "
            "a default gateway — pass adapter='eth0' to pin explicitly"
        )

    # --- assemble free-form flags + options (denylist-filtered) ----------
    flag_tokens, d1 = _strip_denied(shlex.split(flags) if flags else [])
    opt_tokens, d2 = _strip_denied(shlex.split(options) if options else [])
    dropped = list(d1) + list(d2)

    # --- build argv (owned flags first, escape-hatch options last) -------
    command: List[str] = ["masscan", target, "-p", ports]

    if rate is not None:
        command += ["--rate", str(rate)]
    if exclude:
        command += ["--exclude", exclude]
    if adapter_ip:
        command += ["--adapter-ip", adapter_ip]
    if adapter_iface:
        command += ["-e", adapter_iface]

    command += flag_tokens

    # fixed, non-user-facing output + wait
    wait = os.getenv("MASSCAN_WAIT", "10")
    out_path = os.path.join(
        os.getenv("BG_JOB_LOG_DIR", "/tmp"),
        f"masscan_out_{uuid.uuid4().hex[:8]}.json",
    )
    command += ["--wait", str(wait), "-oJ", out_path]

    # escape hatch goes last so it can't shadow the fixed output flags
    # (already denylist-filtered)
    command += opt_tokens

    # --- launch ----------------------------------------------------------
    job = launch_job(
        command,
        tool_name="masscan",
        timeout=float(os.getenv("MASSCAN_TIMEOUT", "1800")),
        verdict_parser=_parse_masscan_verdict(out_path),
    )

    # Surface the resolved config so the secretary model can audit it.
    job["ports"] = ports
    job["rate"] = rate
    job["exclude"] = exclude or None
    job["adapter_ip"] = adapter_ip
    job["adapter_iface"] = adapter_iface
    job["output_file"] = out_path
    notes: List[str] = []
    if rate_warn:
        notes.append(rate_warn)
    if adapter_warn:
        notes.append(adapter_warn)
    if dropped:
        notes.append(f"stripped disallowed/owned flags: {dropped}")
    if notes:
        job["notes"] = notes
    return job


@framework_tool(
    "Poll, check, or monitor the progress and results of an existing, "
    "already-launched Masscan port scan: returns running/done, a parsed "
    "list of hosts with open ports (port/proto/state/reason/ttl, plus "
    "banner if --banners was used), open-port totals, whether the JSON "
    "output was truncated (interrupted), and recent log lines. Call once only "
    "when the user requests an update; never poll repeatedly until done. "
    "Partial results are returned even if the job "
    "was interrupted.",
    next_hints=["masscan_status", "run_nmap", "report_finding"],
    untrusted_target=True,
)
def masscan_status(job_id: str) -> Dict[str, Any]:
    """Poll the progress of a scan launched by ``run_masscan``.

    Reads the job's JSON output file (tolerant of truncation) and log,
    checks whether the subprocess is still alive, and returns a structured
    list of open ports per host.  Returns ``status: "running"`` while the
    scan is in progress and ``status: "done"`` once the process has exited.

    Args:
        job_id: The ``job_id`` returned by ``run_masscan``.
    """
    return poll_job(job_id, tool_name="masscan")


@framework_tool(
    "Cancel, stop, and terminate an existing, already-launched Masscan "
    "scan job by its job ID: sends SIGTERM (then SIGKILL if needed) to the "
    "background subprocess and frees the job. Any partial JSON results "
    "captured so far can still be read via masscan_status(job_id).",
    next_hints=["masscan_status"],
)
def masscan_cancel(job_id: str) -> Dict[str, Any]:
    """Terminate a masscan scan launched by ``run_masscan``.

    Args:
        job_id: The ``job_id`` returned by ``run_masscan``.
    """
    terminated = terminate_job(job_id)
    return {
        "job_id": job_id,
        "tool": "masscan",
        "cancelled": terminated,
        "message": (
            f"masscan job {job_id} terminated"
            if terminated
            else f"no live masscan job with id {job_id!r} (already finished or evicted)"
        ),
    }
