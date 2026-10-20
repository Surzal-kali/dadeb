"""Nmap port scanner with background job + poll pattern.

nmap scans (especially ``-p- -sV``) can take minutes to tens of minutes.
A blocking ``subprocess.run`` holds the entire secretary turn open for the
scan's full runtime and fights the turn timeout.  Instead, this module uses
the shared :mod:`utils.background_job` helper:

- ``run_nmap(target, options)`` launches nmap as a background
  ``subprocess.Popen`` and returns immediately with a ``job_id`` plus a log
  file path.  The secretary turn is NOT held open.
- ``nmap_status(job_id)`` polls the job: checks whether the process is
  still alive, tails the log, and parses a summary of open ports so the
  model can decide whether to keep polling or proceed to the next tool.

This mirrors the proven sqlmap ``run_sqlmap`` / ``sqlmap_status`` shape
and inherits the shared ``BackgroundJob`` machinery so amass/gobuster can
do the same with a one-line ``launch_job`` call.

NSE (Nmap Scripting Engine): nmap's installed script library
(/usr/share/nmap/scripts, 600+ .nse files — smb-enum-shares, ldap-search,
smb-vuln-ms17-010, ...) is fully available through ``run_nmap``'s
``options`` string (``--script``, ``--script-args``). The
``nmap_scripts`` tool lists what is actually installed (name + category +
description) so the secretary never passes ``--script`` a script nmap
would refuse to load — it resolves the installed script's real name
first. The scripts' category keywords are folded into ``nmap_scripts``'s
embedding text so "ldap search" / "smb enum" phrasings land on it.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from constants import framework_tool
from utils.background_job import launch_job, poll_job, register_verdict_parser


def _parse_nmap_verdict(log_text: str) -> Dict[str, Any]:
    """Best-effort summary from nmap's text output.

    Returns a dict with ``open_ports`` (list of ``"port/state/service"``
    strings) and ``host_state`` (``"up"`` / ``"down"`` / ``None``).
    Conservative: only extracts lines that match nmap's standard
    ``Nmap scan report for ...`` and ``<port>/<state> <service>`` formats.
    """
    host_state = None
    m = re.search(r"Host is (up|down)", log_text, re.IGNORECASE)
    if m:
        host_state = m.group(1).lower()
    elif re.search(r"Nmap scan report for .+ is (up|down)", log_text, re.IGNORECASE):
        host_state = m.group(1).lower() if m else None

    open_ports: List[str] = []
    # Match lines like: 22/tcp   open  ssh
    #                 80/tcp   open  http
    for line in log_text.splitlines():
        pm = re.match(
            r"^(\d+/(?:tcp|udp))\s+(\w+)\s+(\S+)", line.strip()
        )
        if pm:
            port, state, service = pm.groups()
            open_ports.append(f"{port}/{state}/{service}")

    return {
        "open_ports": open_ports,
        "host_state": host_state,
    }


register_verdict_parser("nmap", _parse_nmap_verdict)


def _nmap_target_argv(target: str) -> List[str]:
    """Split a multi-target string into nmap argv elements.

    nmap treats ONE space-containing argv element as a single (unresolvable)
    hostname — live-verified: "Failed to resolve \"192.168.90.114,...". So:
    whitespace-separated entries become separate argv items, and full-IP
    comma merges ('a.b.c.d,w.x.y.z') are split apart too, while nmap's own
    octet-list syntax ('a.b.c.d,e,f') stays ONE argv element.
    """
    import shlex

    argv: List[str] = []
    for chunk in shlex.split(target):
        parts = chunk.split(",")
        if len(parts) > 1 and all(
            re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", p) for p in parts
        ):
            argv.extend(parts)  # full-IP comma merge -> one argv each
        else:
            argv.append(chunk)  # octet-lists / CIDRs / hosts / ranges stay whole
    return argv


@framework_tool(
    "Launch and start a new Nmap port scan on a target, subnet, or CIDR "
    "range: discovers live hosts and enumerates open ports and services. "
    "Non-blocking and detached — starts the scan in the background and "
    "returns immediately with a scan ID for later retrieval. Confirm the "
    "launch with one status poll, then hand off to the user; poll again only "
    "when the user requests an update. Optional shaping= applies a wire-"
    "traffic profile from evasion/shaping (quiet/polite/noisy); lab_only "
    "profiles (decoy/fragment) refuse without SHAPING_LAB_MODE=1. NSE scripts "
    "(--script) run any of the 600+ installed .nse files — service enum "
    "and version probes (smb-enum-shares, smb-enum-users, ldap-search, "
    "ldap-rootdse), vulnerability checks (smb-vuln-ms17-010, "
    "smb-vuln-ms08-067, ftp-vsftpd-backdoor), auth brute (smb-brute, "
    "ldap-brute) — inline with the port scan; resolve the exact installed "
    "script name with nmap_scripts first, then pass --script <name> in "
    "options.",
    next_hints=["nmap_status", "nmap_scripts"],
    untrusted_target=True,
)
def run_nmap(
    target: str,
    options: str = "-Pn -sV",
    shaping: Optional[str] = None,
) -> Dict[str, Any]:
    """Launch nmap against ``target`` and return immediately.

    nmap runs as a detached background subprocess writing to a per-job log
    file; this call does NOT block on the scan.  Perform one status poll to
    confirm it is running, then hand off to the user.  Do not poll repeatedly;
    poll again only when the user requests an update.

    ``-Pn`` is the default (hosts that drop ping probes would otherwise
    report "Host seems down" even when their ports are reachable).  Pass
    ``-p-`` for all ports, ``-sV`` for service detection, ``-O`` for OS
    fingerprinting, etc.

    Args:
        target: The target host or IP address (or CIDR range).
        options: Additional nmap command-line options as a single string
            (e.g. ``"-p- -sV"``).  Quoted sub-phrases are preserved by
            shlex.  ``-Pn`` is included by default.  NSE scripts run via
            ``--script`` (e.g. ``"-p445 --script smb-enum-shares"``,
            ``"--script ldap-search --script-args searchFilter='...'"``);
            verify the installed script name with ``nmap_scripts`` first
            so nmap never refuses an unloadable name.
        shaping: Optional preset name from evasion/shaping.SCAN_SHAPING_PRESETS
            ('quiet', 'polite', 'noisy' wire profiles; 'decoy'/'fragment' are
            lab_only and refuse without SHAPING_LAB_MODE=1). Merged argv order
            is [preset flags, default -Pn, operator options] and nmap honors
            the LAST occurrence of a repeated flag, so explicit operator
            flags always win over preset values. Speed templates (-T) tune
            the scanner's accuracy/speed trade, not the wire: real shaping
            is --max-rate / --scan-delay (see evasion/shaping.py).
    """
    import shlex

    # Scope gate (operator-armed from the Tool REPL; no-op in lab mode).
    from utils.scope_gate import check_scan, ScopeGateError
    _sc_ok, _sc_reason = check_scan(target)
    if not _sc_ok:
        raise ScopeGateError(f"scope gate: {_sc_reason}")

    # -Pn by default: hosts that drop ping probes would otherwise report
    # "Host seems down" even when their ports are reachable.
    opt_list = shlex.split(options) if options else []
    if "-Pn" not in opt_list and "-Pn" not in options:
        opt_list = ["-Pn", *opt_list]

    shaping_resolved = None
    if shaping:
        from evasion.shaping import resolve as _shaping_resolve, ShapingError
        try:
            shaping_resolved = _shaping_resolve(shaping, lab_mode=None)
        except ShapingError as e:
            raise ScopeGateError(f"shaping: {e}") from None
        # Preset flags go in FRONT: argv order [preset, -Pn default, operator]
        # means nmap's last-flag-wins semantics give operator > default > preset.
        opt_list = [*shaping_resolved["merged"], *opt_list]

    command = ["nmap", *opt_list, *_nmap_target_argv(target)]

    return launch_job(
        command,
        tool_name="nmap",
        timeout=float(__import__("os").getenv("NMAP_TIMEOUT", "1800")),
        verdict_parser=_parse_nmap_verdict,
    )


def _nmap_status_digest(result: Dict[str, Any]) -> Dict[str, Any]:
    """Digest adapter for ``nmap_status`` — compact port/service summary.

    The full nmap log (which can be thousands of lines for ``-p- -sV``) is
    stored in scratch; the model gets:
    - job status (running/done) + elapsed
    - host state (up/down)
    - open port count + the full port list (these are small and critical)
    - job_id (needed for re-polling)
    - log_file path (operator-side access)

    The model rarely needs the raw log text to decide the next action — the
    parsed port list IS the actionable signal.  When it does need the full
    log (e.g. NSE script output), it retrieves it from scratch.
    """
    parts: list = []

    status = result.get("status", "unknown")
    parts.append(f"status={status}")

    if result.get("elapsed") is not None:
        parts.append(f"elapsed={result['elapsed']}s")

    host_state = result.get("host_state")
    if host_state:
        parts.append(f"host={host_state}")

    open_ports = result.get("open_ports", [])
    if open_ports:
        parts.append(f"open_ports={len(open_ports)}")
        # The port list is small and is the primary actionable signal —
        # include it in full so the model can chain to the right tool
        # (e.g. ssh_exec on 22, probe_web on 80/443, smb_scanner on 445).
        port_lines = "\n  ".join(open_ports[:30])
        parts.append(f"ports:\n  {port_lines}")
        if len(open_ports) > 30:
            parts.append(f"  ... +{len(open_ports) - 30} more (retrieve full list from scratch)")
    else:
        parts.append("open_ports=0")

    # job_id is critical — the model needs it to re-poll.
    job_id = result.get("job_id")
    if job_id:
        parts.append(f"job_id={job_id}")

    # Exit code on completed scans.
    exit_code = result.get("exit_code")
    if exit_code is not None:
        parts.append(f"exit_code={exit_code}")

    timed_out = result.get("timed_out")
    if timed_out:
        parts.append("timed_out=True")

    summary = " | ".join(parts)

    row_hint = (
        "scratch_search scratch:<id> --filter 'port' "
        "# pull specific port entries from the full output"
    )

    return {"summary": summary, "row_hint_format": row_hint}


@framework_tool(
    "Poll, check, or monitor the progress and results of an existing, "
    "already-launched Nmap scan job: returns running/done, a parsed list "
    "of open ports with services, the host up/down verdict, and recent "
    "log lines. Call once only when the user requests a status update; never "
    "poll repeatedly or automatically until the scan finishes.",
    next_hints=["nmap_status", "report_finding"],
    result_digest=lambda r: _nmap_status_digest(r),
    untrusted_target=True,
)
def nmap_status(job_id: str) -> Dict[str, Any]:
    """Poll the progress of a scan launched by ``run_nmap``.

    Reads the job's log file, checks whether the subprocess is still alive,
    and parses nmap's output for open ports.  Returns ``status: "running"``
    while the scan is in progress and ``status: "done"`` once the process
    has exited.

    Args:
        job_id: The ``job_id`` returned by ``run_nmap``.
    """
    return poll_job(job_id, tool_name="nmap")


# --- NSE script discovery ----------------------------------------------------
#
# nmap's NSE library is a directory of .nse files (600+ on a stock Kali
# install: smb-enum-shares, ldap-search, smb-vuln-ms17-010, ...).  The
# secretary model cannot see that directory, so a request like "run an
# ldap-search scan" has no hook: run_nmap's doc never mentioned --script
# and nothing could list the installed scripts to confirm the exact name.
# nmap_scripts closes that loop: it lists what IS installed (name +
# category + description) so --script only ever receives loadable names.

_SCRIPTS_DIR_CANDIDATES = (
    "/usr/share/nmap/scripts",
    "/usr/local/share/nmap/scripts",
    "/usr/lib/nmap/scripts",
)

# Script name -> doc description, for scripts the model is most likely to
# ask for by name.  Serves as a graceful fallback when a script's
# machine-readable header is unparsable; the nmap --script-help path below
# is the primary source of descriptions.
_COMMON_SCRIPT_BRIEFS: Dict[str, str] = {
    "smb-enum-shares": "enumerate SMB shares via null/credentialed sessions",
    "smb-enum-users": "enumerate SMB user accounts",
    "smb-enum-sessions": "enumerate active SMB sessions",
    "smb-enum-domains": "enumerate SMB domains",
    "smb-enum-groups": "enumerate SMB groups",
    "smb-enum-processes": "enumerate processes over SMB",
    "smb-enum-services": "enumerate services via SVCCTL",
    "smb-ls": "list directory contents over SMB",
    "smb-os-discovery": "fingerprint OS/version/domain over SMB",
    "smb-security-mode": "report SMB signing and auth level",
    "smb-protocols": "negotiate and list SMB protocol dialects",
    "smb-vuln-ms08-067": "check MS08-067 Server service overflow",
    "smb-vuln-ms17-010": "check MS17-010 EternalBlue/EternalRomance",
    "smb-vuln-conficker": "check Conficker worm infection",
    "smb-vuln-ms10-054": "check MS10-054 Server service DoS/RCE",
    "smb-vuln-ms10-061": "check MS10-061 Print Spooler RCE (Stuxnet)",
    "smb-vuln-ms06-025": "check MS06-025 RAS service overflow",
    "smb-vuln-ms07-029": "check MS07-029 DNS RPC overflow",
    "smb-vuln-cve2009-3103": "check SMBv2 Negotiate overflow (CVE-2009-3103)",
    "smb-vuln-cve-2017-7494": "check Samba CVE-2017-7494 RCE",
    "smb-vuln-webexec": "check WebEx Service RCE",
    "smb-double-pulsar-backdoor": "check DoublePulsar SMB backdoor",
    "smb-brute": "brute-force SMB username/password",
    "smb-psexec": "run commands over SMB via psexec",
    "smb-system-info": "pull system info over SMB",
    "smb-mbenum": "query the master browser for a host list",
    "smb2-security-mode": "report SMB2 signing/auth enforcement",
    "smb2-capabilities": "report negotiated SMB2 capabilities",
    "smb2-time": "report SMB2 server time (for kerberoasting windows)",
    "smb2-vuln-uptime": "detect hosts missing MS17-010-era reboots",
    "ldap-search": "search an LDAP tree with a custom filter (dump users/objects)",
    "ldap-rootdse": "fetch the LDAP rootDSE (naming contexts, versions)",
    "ldap-brute": "brute-force LDAP bind credentials",
    "ldap-novell-getpass": "retrieve Novell universal passwords over LDAP",
    "ftp-anon": "check anonymous FTP access",
    "ftp-vsftpd-backdoor": "check vsftpd 2.3.4 backdoor",
    "http-title": "grab HTTP page titles",
    "http-enum": "enumerate common web paths",
    "http-methods": "enumerate HTTP methods (OPTIONS)",
    "banner": "grab a service banner",
    "default": "metavalue — NOT a real script (default script selection)",
    "*": "metavalue — NOT a real script (wildcard script selection)",
}


def _find_scripts_dir() -> Optional[Path]:
    """Return the first existing NSE scripts directory, or None."""
    override = os.getenv("NMAP_SCRIPTS_DIR")
    if override and Path(override).is_dir():
        return Path(override)
    for cand in _SCRIPTS_DIR_CANDIDATES:
        p = Path(cand)
        if p.is_dir():
            return p
    return None


@framework_tool(
    "List, search, and describe the NSE (Nmap Scripting Engine) scripts "
    "installed on this box: their exact script names for --script, their "
    "NSE categories (auth, discovery, intrusive, vuln, safe, brute, ...), "
    "and their descriptions. Query by substring or by category — e.g. "
    "query 'smb' or category 'smb' for SMB enumeration/vuln scripts, "
    "'ldap' for ldap-search/ldap-rootdse/ldap-brute. Resolve the exact "
    "installed script name here BEFORE passing --script to run_nmap, so "
    "nmap never refuses an unloadable name.",
    next_hints=["run_nmap", "nmap_status"],
)
def nmap_scripts(
    query: str = "", category: str = "", detail: bool = False, limit: int = 40
) -> Dict[str, Any]:
    """List the installed NSE scripts, optionally filtered.

    Args:
        query: Case-insensitive substring match against the script
            name (e.g. ``"smb"``, ``"ldap-search"``).
        category: NSE category filter (auth, broadcast, brute, default,
            discovery, dos, exploit, external, fuzzer, intrusive,
            malware, safe, version, vuln).  ``"smb"`` also works as a
            category-style filter since smb-* scripts declare it.
        detail: Fetch each matched script's ``--script-help`` description
            from nmap itself (slower: one nmap invocation per batch, not
            per script).
        limit: Maximum scripts returned (default 40).

    Returns a dict with ``scripts`` (name, categories, description),
    ``total_installed``, and the scripts directory path.
    """
    import shutil
    import subprocess as sp

    scripts_dir = _find_scripts_dir()
    if not scripts_dir:
        return {
            "error": ("no NSE scripts directory found (looked in "
                      f"{', '.join(_SCRIPTS_DIR_CANDIDATES)}; override with "
                      "NMAP_SCRIPTS_DIR) — nmap may not be installed"),
            "scripts": [],
            "total_installed": 0,
        }

    nmap_bin = shutil.which("nmap") or "nmap"

    def _load_script(path: Path) -> Dict[str, Any]:
        """Best-effort parse of one .nse: name, description, categories.

        Real NSE files declare these as LUA ASSIGNMENTS, not comment
        headers (verified against the installed library):
        ``description = [[ ...long prose... ]]`` (multiline block string)
        and ``categories = {"default", "discovery", "safe"}``.  The
        ``-- @usage`` / ``-- @args`` comment tags carry invocation
        examples.  Parse order: lua description block → categories table
        → first @usage line.
        """
        name = path.stem
        text = ""
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass

        # description = [[ ... ]]  (lua long-string; may be [[ or [=[)
        description = ""
        m = re.search(
            r"^\s*description\s*=\s*\[=*\[\s*(.*?)\s*\]=*\]\s*$",
            text[:8192], re.S | re.M,
        )
        if m:
            # First prose paragraph only — HTML tags stay out.
            raw = re.sub(r"<[^>]+>", " ", m.group(1))
            for para in raw.split("\n\n"):
                cleaned = " ".join(para.split())
                if len(cleaned) > 25:  # skip stub paragraphs
                    description = cleaned
                    break

        # categories = { "a", "b", ... }
        categories: List[str] = []
        m = re.search(r"^\s*categories\s*=\s*\{(.*?)\}", text[:8192], re.S | re.M)
        if m:
            categories = re.findall(r"['\"]([^'\"]+)['\"]", m.group(1))

        # @usage example (comment block) — the ready-made invocation line.
        usage = ""
        m = re.search(r"@usage\s*\n\s*(?:--\s*)?(.+)", text, re.M)
        if m:
            usage = m.group(1).strip()

        return {
            "name": name,
            "categories": categories,
            "description": (description[:400] if description
                            else _COMMON_SCRIPT_BRIEFS.get(name, "")),
            "usage": usage,
        }

    installed: List[Dict[str, Any]] = []
    for p in sorted(scripts_dir.glob("*.nse")):
        installed.append(_load_script(p))

    ql = query.strip().lower()
    cl = category.strip().lower()
    matched = installed
    if ql or cl:
        matched = []
        for s in installed:
            name_l = s["name"].lower()
            cats_l = [c.lower() for c in s["categories"]]
            if ql and not (ql in name_l or any(ql in c for c in cats_l)
                           or ql in (s["description"] or "").lower()):
                continue
            if cl and not (cl in cats_l or any(cl in c for c in cats_l)
                           or cl in name_l):
                continue
            matched.append(s)

    matched = matched[: max(1, int(limit))]

    # Optional: pull real descriptions from nmap itself (one subprocess per
    # batch, not per script — nmap --script-help takes a comma list).
    if detail and matched:
        try:
            names = [s["name"] for s in matched[:15]]
            proc = sp.run(
                [nmap_bin, "--script-help", ",".join(names)],
                capture_output=True, text=True, timeout=30,
            )
            # --script-help output blocks look like:
            #   | smb-enum-shares
            #   |   Attempts to list shares ... (indented prose)
            # Split on the "| <name>" headers and attach each block to its
            # script; unknown names are ignored.
            blocks: Dict[str, List[str]] = {}
            current = None
            for line in (proc.stdout or "").splitlines():
                hm = re.match(r"^\|\s*([a-z0-9_-]+)\s*$", line)
                if hm:
                    current = hm.group(1)
                    blocks.setdefault(current, [])
                elif current is not None and line.strip():
                    blocks[current].append(line.strip())
            for s in matched:
                help_text = " ".join(blocks.get(s["name"], []))
                if help_text:
                    s["description"] = help_text[:400]
        except (sp.TimeoutExpired, OSError):
            pass

    return {
        "scripts": matched,
        "total_installed": len(installed),
        "scripts_dir": str(scripts_dir),
        "hint": ("pass the exact name via run_nmap options, e.g. "
                 "run_nmap(target, '-p445 --script smb-enum-shares')"),
    }
