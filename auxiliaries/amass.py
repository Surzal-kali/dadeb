"""OWASP Amass v5 wrapper — subdomain enumeration via background job + poll.

Passive by default (amass v5's default mode).  Active, brute-force, and
alteration modes are opt-in via the ``options`` string with a flag allowlist.

This module mirrors the proven nmap ``run_nmap`` / ``nmap_status`` shape
using the shared :mod:`utils.background_job` helper:

- ``run_amass(target, options)`` launches ``amass enum`` as a background
  ``subprocess.Popen`` and returns immediately with a ``job_id``.  The
  secretary turn is NOT held open.
- ``amass_status(job_id)`` polls the job.  When the enum is done, it
  retrieves discovered names via ``amass subs -names -show`` (v5's
  retrieval path), falls back to a direct crt.sh CT-log HTTP query if
  amass found nothing, and optionally filters against program scope.
- ``subdomain_enum(target, options)`` is the composite launcher (same
  background job, marks the job for alive-check + structured output).
- ``subdomain_enum_status(job_id)`` polls, retrieves names, does scope
  filtering + DNS alive-check, and returns structured JSON.

amass v5 output model (v5.1+):
  Unlike v4, ``amass enum`` does NOT print subdomain names to stdout.
  stdout only gets a summary header ("Session Scope / FQDN: / <domain>").
  Results live in the engine's SQLite DB and session logs.  The correct
  retrieval path is:
    1. ``amass enum -d <domain>``  (writes to the default home DB)
    2. ``amass subs -names -show -d <domain>``  (prints names from home DB)

  **No ``-dir`` flag**: we intentionally use amass's default home DB
  (``~/.config/amass/asset.db`` under the running user) so that:
    - Results persist across runs and survive process kills (the home DB
      is checkpointed; a per-job ``-dir`` DB loses uncommitted WAL data
      on SIGTERM).
    - ``amass subs`` retrieves everything ever discovered, not just the
      current run's (possibly empty) per-job DB.
    - Accumulated data from prior completed runs is immediately available.

  This wrapper automates both steps.  Free CT/passive sources
  (certspotter, hackertarget, crt.sh) are layered as augmentation on top
  because different sources find different subdomains and crt.sh is
  frequently overloaded (502) for large domains.
"""

from __future__ import annotations

import json
import os
import shlex
import socket
import subprocess
import threading
import time
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FutureTimeout, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from constants import framework_tool, resolve_workspace_root
from utils.background_job import launch_job, poll_job

# --- bounded DNS resolver for the alive-check sweep -------------------------
#
# The alive-check previously called ``socket.getaddrinfo`` with a ``timeout``
# argument that getaddrinfo does NOT accept — the arg was silently ignored and
# every resolve was bounded only by the system resolver's default (tens of
# seconds on a nameserver retry/serfail).  On a 260-host in-scope set that
# pushed the sweep far past the MCP caller's socket deadline (the connecting
# agent destroys any call that runs >30s), so ``subdomain_enum_status`` timed
# out on every poll while the discovery-only ``amass_status`` returned
# instantly.  We now resolve via dnspython with a real per-host ``lifetime``
# (default 3s) plus an overall sweep budget (default 25s) so partial results
# are returned within the deadline instead of hanging the whole call.
try:
    import dns.resolver as _dns_resolver
    _DNS_RESOLVER = _dns_resolver.Resolver(configure=True)
    _DNS_AVAILABLE = True
except Exception:  # pragma: no cover - dnspython is a declared dep, defensive
    _DNS_AVAILABLE = False

# --- flag allowlist ----------------------------------------------------------

# Boolean flags (no value consumed).  These are safe to let the model toggle.
_BOOL_FLAGS = {
    "-active",       # zone transfers + certificate name grabs
    "-brute",        # DNS brute forcing
    "-alts",         # alteration/permutation generation
    "-norecursive",  # disable recursive brute forcing
    "-rigid",        # disable scope expansion
    "-nocolor",      # disable ANSI codes (always added by wrapper)
    "-demo",         # censor output for demos
    "-passive",      # deprecated in v5 (passive is default) but harmless
    "-silent",       # disable all output during execution
    "-v",            # verbose status / debug / troubleshooting info
}

# Flags that consume the next argv element as a value.
_VALUE_FLAGS = {
    "-w",                # wordlist path for brute forcing
    "-aw",               # wordlist path for alterations
    "-r",                # DNS resolver IPs
    "-rf",               # DNS resolver file
    "-timeout",          # minutes (amass uses minutes, not seconds)
    "-max-depth",        # max subdomain label depth for brute forcing
    "-min-for-recursive",  # labels before recursive brute forcing
    "-include",          # data source names to include
    "-exclude",          # data source names to exclude
    "-p",                # ports (comma-separated)
    "-bl",               # blacklisted subdomain names
    "-blf",              # blacklisted subdomains file
    "-nf",               # already-known subdomains file
    "-awm",              # hashcat-style wordlist masks for alterations
    "-wm",               # hashcat-style wordlist masks for brute forcing
    "-iface",            # network interface
    # --- v5-only value flags ---
    "-config",           # path to YAML configuration file
    "-oA",               # path prefix for naming all output files
    "-log",              # path to log file for errors
    "-df",               # path to file providing root domain names
    "-d",                # domain names (comma-separated, repeatable)
    "-tr",               # trusted DNS resolver IPs
    # NOTE: -dir is managed internally by the wrapper (temp dir for v5
    # output retrieval).  Not exposed to the model to avoid clobbering.
}


def _validate_options(options: str) -> List[str]:
    """Parse and validate an options string against the flag allowlist.

    Returns a clean argv list.  Raises ValueError on disallowed flags.
    """
    if not options or not options.strip():
        return []
    tokens = shlex.split(options)
    clean: List[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in _BOOL_FLAGS:
            clean.append(tok)
            i += 1
        elif tok in _VALUE_FLAGS:
            clean.append(tok)
            if i + 1 < len(tokens):
                clean.append(tokens[i + 1])
                i += 2
            else:
                raise ValueError(f"flag {tok} requires a value")
        else:
            raise ValueError(
                f"disallowed amass flag: {tok!r}. "
                f"Allowed: {sorted(_BOOL_FLAGS | _VALUE_FLAGS)}"
            )
    return clean


# --- amass v5 helpers --------------------------------------------------------

# Extra per-job metadata that launch_job/poll_job don't carry (domain,
# temp output dir, whether to do alive-check).  Keyed by job_id, capped.
_AMASS_JOBS: "Dict[str, Dict[str, Any]]" = {}
_AMASS_LOCK = threading.Lock()
_MAX_AMASS_JOBS = 64


def _retrieve_names(domain: str) -> List[str]:
    """Retrieve discovered subdomain names from the engine's home DB.

    In amass v5, ``amass enum`` does NOT print names to stdout.  Results are
    stored in the engine's default home DB (``~/.config/amass/asset.db``).
    This runs ``amass subs -names -show -d <domain>`` to pull them out.

    No ``-dir`` flag is used — we rely on the home DB so results from prior
    completed runs persist and are retrievable even if the most recent enum
    was killed before committing.
    """
    subs_cmd = [
        "amass", "subs",
        "-d", domain,
        "-names",
        "-show",
    ]
    # A big-domain enum (crypto.com-scale) ingests tens of thousands of names
    # over hours; the `amass subs` dump of that DB takes MINUTES. The naive
    # 30s timeout swallowed entire multi-hour runs' results (Sept 11: 2.5h
    # enum -> 0 names reported, timeout eaten by a bare except). Env-tunable
    # timeout + one retry before falling through to CT sources.
    timeout = float(os.getenv("AMASS_RETRIEVAL_TIMEOUT", "600"))
    for _attempt in (1, 2):
        try:
            result = subprocess.run(
                subs_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            names = [
                line.strip().lower().rstrip(".")
                for line in (result.stdout or "").splitlines()
                if line.strip() and "." in line.strip()
            ]
            return sorted(set(names))
        except subprocess.TimeoutExpired:
            continue  # one retry; a warm-DB second pass often gets through
        except Exception:
            return []
    return []


def _crtsh_fallback(domain: str) -> List[str]:
    """Query crt.sh CT logs directly.

    crt.sh is frequently overloaded (502/timeout), especially for domains
    with large CT-log footprints (e.g. crypto.com crashes crt.sh's backend).
    Best-effort with a generous timeout and a single retry.  Returns a
    sorted list of unique subdomain names (wildcard certs stripped).
    """
    domain = domain.lower().rstrip(".")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    for attempt in range(2):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "amass-wrapper/1.0"})
            with urllib.request.urlopen(
                req, timeout=float(os.getenv("AMASS_CRTSH_TIMEOUT", "120"))
            ) as resp:
                if resp.status != 200:
                    continue
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
            names: set[str] = set()
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower().rstrip(".")
                    if name and (name == domain or name.endswith("." + domain)):
                        if not name.startswith("*."):
                            names.add(name)
            return sorted(names)
        except Exception:
            continue
    return []


def _certspotter_fallback(domain: str) -> List[str]:
    """Query CertSpotter CT-log API (free, no key required).

    CertSpotter is more reliable than crt.sh for large domains and returns
    JSON with dns_names expanded.  Free tier is rate-limited but sufficient
    for per-domain queries.  Returns sorted unique subdomain names.
    """
    domain = domain.lower().rstrip(".")
    url = (
        f"https://api.certspotter.com/v1/issuances"
        f"?domain={urllib.parse.quote(domain)}"
        f"&include_subdomains=true&expand=dns_names"
    )
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "amass-wrapper/1.0"})
        with urllib.request.urlopen(
            req, timeout=float(os.getenv("AMASS_CERTSPOTTER_TIMEOUT", "30"))
        ) as resp:
            if resp.status != 200:
                return []
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        names: set[str] = set()
        for entry in data:
            for name in entry.get("dns_names", []):
                name = name.strip().lower().rstrip(".")
                if name and (name == domain or name.endswith("." + domain)):
                    if not name.startswith("*."):
                        names.add(name)
        return sorted(names)
    except Exception:
        return []


def _hackertarget_fallback(domain: str) -> List[str]:
    """Query HackerTarget hostsearch API (free, no key required).

    Returns ``hostname,ip`` lines.  Free tier allows ~50 queries/day per
    source IP.  Reliable and fast for both small and large domains.
    """
    domain = domain.lower().rstrip(".")
    url = f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(domain)}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "amass-wrapper/1.0"})
        with urllib.request.urlopen(
            req, timeout=float(os.getenv("AMASS_HACKERTARGET_TIMEOUT", "30"))
        ) as resp:
            if resp.status != 200:
                return []
            text = resp.read().decode("utf-8", errors="replace")
        names: set[str] = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or "," not in line:
                continue
            name = line.split(",")[0].strip().lower().rstrip(".")
            if name and (name == domain or name.endswith("." + domain)):
                names.add(name)
        return sorted(names)
    except Exception:
        return []


def _get_names(domain: str) -> List[str]:
    """Retrieve names from amass's home DB, augmented with free CT sources.

    Amass's home DB is the primary source (accumulates across runs).  Free
    CT/passive sources (certspotter, hackertarget) are always merged in as
    augmentation because different sources find different subdomains and
    they're fast (<2s each).  crt.sh is a last resort because it frequently
    502s on large domains.
    """
    names: set[str] = set()

    # Primary: amass home DB (may contain results from prior completed runs
    # even if the latest enum was killed before committing).
    amass_names = _retrieve_names(domain)
    names.update(amass_names)

    # Augmentation: free CT/passive sources (fast, find different subs).
    names.update(_certspotter_fallback(domain))
    names.update(_hackertarget_fallback(domain))

    # Last resort: crt.sh (frequently 502 on large domains).
    if not names:
        names.update(_crtsh_fallback(domain))

    return sorted(names)


def _store_amass_meta(job_id: str, domain: str,
                      options: str, composite: bool,
                      scope_platform: Optional[str] = None,
                      scope_handle: Optional[str] = None) -> None:
    """Stash extra metadata for a launched amass job."""
    with _AMASS_LOCK:
        _AMASS_JOBS[job_id] = {
            "domain": domain,
            "options": options,
            "composite": composite,
            "scope_platform": scope_platform,
            "scope_handle": scope_handle,
            "result": None,       # cached retrieval result (set on first done-poll)
            "retrieved": False,
            "alive": None,        # cached alive-check (set on first subdomain_enum_status done-poll)
            "alive_retrieved": False,
            "alive_checked": 0,   # hosts actually resolved before the budget expired
            "alive_partial": False,
        }
        if len(_AMASS_JOBS) > _MAX_AMASS_JOBS:
            # Evict oldest entries that have been retrieved.
            done = sorted(
                (k for k, v in _AMASS_JOBS.items() if v["retrieved"]),
                key=lambda k: _AMASS_JOBS[k].get("started", 0),
            )
            for k in done[: len(_AMASS_JOBS) - _MAX_AMASS_JOBS]:
                _AMASS_JOBS.pop(k, None)


def _get_amass_meta(job_id: str) -> Optional[Dict[str, Any]]:
    with _AMASS_LOCK:
        return _AMASS_JOBS.get(job_id)


# --- run_amass (async launcher) + amass_status (poller) ---------------------

@framework_tool(
    "Launch OWASP Amass v5 subdomain enumeration against a domain in the "
    "background. PASSIVE by default (no traffic to target). Add '-active' "
    "for zone transfers and cert grabs, '-brute' for DNS brute forcing, "
    "'-alts' for permutation generation. Non-blocking — starts the scan "
    "and returns immediately with a job_id. Confirm the launch with one "
    "status poll, then hand off to the user; poll again only when the user "
    "requests an update. Allowed flags: -active, -brute, -alts, "
    "-norecursive, -rigid, -w <wordlist>, -timeout <minutes>, "
    "-include <sources>, -exclude <sources>, -max-depth <n>, -p <ports>.",
    next_hints=["amass_status", "subdomain_enum (structured result with alive check)"],
)
def run_amass(target, options="", scope_platform=None, scope_handle=None):
    """Launch amass enum against a domain and return immediately.

    amass runs as a detached background subprocess writing to a per-job log
    file; this call does NOT block on the scan.  Perform one status poll to
    confirm it is running, then hand off to the user.  Poll again only when
    the user requests an update.

    In amass v5, the enum subprocess does NOT print names to stdout.  The
    status function handles v5 retrieval (``amass subs -names``) and crt.sh
    fallback after the enum finishes.

    Args:
        target: Root domain to enumerate (e.g. example.com).
        options: Extra amass flags (validated against an allowlist).
                 Passive by default; add '-active', '-brute', '-alts' as needed.
    """
    validated = _validate_options(options)

    # Filter out -dir/-d/-oA from user options — -d and -oA are managed
    # internally; -dir is intentionally NOT used (we rely on amass's default
    # home DB so results persist across runs and survive process kills).
    user_flags = []
    skip_next = False
    for tok in validated:
        if skip_next:
            skip_next = False
            continue
        if tok in ("-dir", "-d", "-oA"):
            skip_next = True
            continue
        user_flags.append(tok)

    # -rigid prevents scope expansion into third-party infrastructure
    # (sendgrid, AWS EC2, etc.) that wastes the enum's time budget on noise.
    if "-rigid" not in user_flags:
        user_flags.append("-rigid")

    # Inject trusted DNS resolvers (-tr, 15 QPS each) to raise the
    # MaxDNSQueries cap.  amass's default 17 baseline resolvers give ~255
    # QPS; adding more trusted resolvers multiplies throughput linearly.
    # Skip injection if the caller already passed -tr or -rf (don't clobber
    # their explicit choice).  Override the list via AMASS_TRUSTED_RESOLVERS
    # env var (comma-separated IPs); set to empty string to disable injection.
    _DEFAULT_TRUSTED_RESOLVERS = [
        "8.8.8.8", "8.8.4.4",          # Google
        "1.1.1.1", "1.0.0.1",          # Cloudflare
        "9.9.9.9", "149.112.112.112",  # Quad9
        "208.67.222.222", "208.67.220.220",  # Cisco OpenDNS
        "84.200.69.80", "84.200.70.40",      # DNS.WATCH
        "64.6.64.6", "64.6.65.6",            # Neustar
        "94.140.14.14", "94.140.15.15",      # AdGuard
        "76.76.19.19", "76.76.2.0",          # ControlD / Alternate DNS
    ]
    has_tr = any(tok == "-tr" for tok in user_flags)
    has_rf = any(tok == "-rf" for tok in user_flags)
    env_resolvers = os.getenv("AMASS_TRUSTED_RESOLVERS", "")
    if not has_tr and not has_rf:
        if env_resolvers:
            resolver_list = [r.strip() for r in env_resolvers.split(",") if r.strip()]
        else:
            resolver_list = _DEFAULT_TRUSTED_RESOLVERS
        for ip in resolver_list:
            user_flags.extend(["-tr", ip])

    command = [
        "amass", "enum",
        "-d", target,
        "-nocolor",
        *user_flags,
    ]

    # Use the full dispatch timeout (minus headroom) by default.  The old
    # min(600, ...) cap killed every enum at 10 minutes — before amass v5
    # could commit its WAL transaction, causing total data loss.  Override
    # with AMASS_ENUM_TIMEOUT env var if a shorter cap is needed.
    dispatch_timeout = float(os.getenv("BRAIN_DISPATCH_TIMEOUT", "1900"))
    amass_cap = float(os.getenv("AMASS_ENUM_TIMEOUT", str(max(60, dispatch_timeout - 10))))

    job = launch_job(
        command,
        tool_name="amass",
        timeout=amass_cap,
    )
    job_id = job["job_id"]
    _store_amass_meta(job_id, target, options, composite=False,
                      scope_platform=scope_platform, scope_handle=scope_handle)

    resp = {
        "job_id": job_id,
        "status": "running",
        "target": target,
        "message": (
            "launch accepted; perform one status poll to confirm the job is "
            "running, then hand off to the user. Poll again only when the "
            "user requests an update."
        ),
    }
    if scope_platform and scope_handle:
        resp["scope_filter"] = f"{scope_platform}_{scope_handle}.scope"
    else:
        resp["scope_filter"] = None
        resp["warning"] = "no scope_handle given — amass results will NOT be scope-filtered"
    return resp


@framework_tool(
    "Poll an amass enum job: returns running/done, discovered subdomain "
    "names (retrieved via amass v5's subs command + crt.sh fallback), and "
    "scope-filtered results if a per-company scope file was selected at "
    "launch. Call once only when the user requests an update; never poll "
    "repeatedly until done.",
    next_hints=["subdomain_enum", "run_nmap -iL <subdomains>"],
)
def amass_status(job_id):
    """Poll the status of an amass enum launched by ``run_amass``.

    When the enum subprocess finishes, this retrieves discovered names via
    ``amass subs -names -show`` (amass v5's retrieval path), falls back to
    a direct crt.sh CT-log query if amass found nothing, and filters against
    the per-company scope selected at launch (``<platform>_<handle>.scope``).

    Args:
        job_id: The ``job_id`` returned by ``run_amass``.
    """
    meta = _get_amass_meta(job_id)
    if meta is None:
        return {
            "job_id": job_id,
            "status": "unknown",
            "error": f"no amass job with id {job_id!r} (it may have been evicted)",
        }

    poll = poll_job(job_id, tool_name="amass")
    status = poll.get("status", "unknown")

    if status != "done":
        # Still running — return the poll result as-is.
        return poll

    # --- Job is done: retrieve names (once, cache the result) ---
    if not meta["retrieved"]:
        domain = meta["domain"]
        names = _get_names(domain)
        with _AMASS_LOCK:
            meta["retrieved"] = True
            meta["result"] = names
    else:
        names = meta["result"]

    # Build the final result.
    if not names:
        result = {
            "job_id": job_id,
            "status": "done",
            "subdomains": [],
            "note": (
                "amass returned no subdomains and all free CT sources "
                "(certspotter, hackertarget, crt.sh) also returned nothing. "
                "Possible causes: no data-source API keys active in "
                "datasources.yaml, the domain has no CT-log entries, or all "
                "CT sources are down.  If amass enum was killed before "
                "completing, prior run results may still be in the home DB "
                "(~/.config/amass/asset.db) — try: amass subs -names -show "
                "-d <domain>."
            ),
            "elapsed": poll.get("elapsed"),
            "timed_out": poll.get("timed_out", False),
        }
        return result

    # Scope filtering (per-company, keyed at launch time).
    scope = _load_scope(meta.get("scope_platform"), meta.get("scope_handle"))
    if scope is None:
        # No scope file for this handle (or no handle given at launch) —
        # return raw names, loudly.
        resp = {
            "job_id": job_id,
            "status": "done",
            "subdomains": names,
            "total_discovered": len(names),
            "elapsed": poll.get("elapsed"),
            "timed_out": poll.get("timed_out", False),
            "note": "prefer subdomain_enum for alive-checking + structured result",
        }
        if meta.get("scope_handle"):
            resp["warning"] = (f"scope file {meta.get('scope_platform')}_"
                               f"{meta.get('scope_handle')}.scope not found — "
                               f"results UNFILTERED; load_program_scope first")
        else:
            resp["warning"] = "launched without scope_handle — results NOT scope-filtered"
        return resp

    in_patterns, out_patterns = scope
    in_scope = [s for s in names if _in_scope(s, in_patterns, out_patterns)]
    out_of_scope = [s for s in names if s not in in_scope]
    return {
        "job_id": job_id,
        "status": "done",
        "subdomains": in_scope,
        "out_of_scope": out_of_scope,
        "total_discovered": len(names),
        "total_in_scope": len(in_scope),
        "elapsed": poll.get("elapsed"),
        "timed_out": poll.get("timed_out", False),
        "note": "prefer subdomain_enum for alive-checking + structured result",
    }


# --- subdomain_enum composite ------------------------------------------------

def _load_scope(platform: Optional[str] = None, handle: Optional[str] = None) -> Tuple[List[str], List[str]] | None:
    """Load scope patterns from ``<platform>_<handle>.scope`` (per-company).

    With ``platform``/``handle`` given, reads ``scope/<platform>_<handle>.scope``
    (the per-company file written by program_scope._write_scope_file).
    With both None, falls back to the legacy singular ``.scope`` for
    backward compatibility (lab mode = no file anywhere).

    Returns None if no scope file exists (lab mode — everything in scope).
    Otherwise returns ``(in_patterns, out_patterns)``.  In-patterns are
    ``*.example.com`` / ``example.com`` / ``api.example.com`` lines;
    out-patterns are the same shapes prefixed with ``!`` (explicit
    out-of-scope assets written by program_scope._write_scope_file).
    Lines starting with # are comments.
    """
    if platform and handle:
        scope_file = (resolve_workspace_root()
                      / f"{platform}_{handle}.scope")
    else:
        scope_file = resolve_workspace_root() / ".scope"
    if not scope_file.is_file():
        return None
    in_patterns: List[str] = []
    out_patterns: List[str] = []
    for line in scope_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            if line.startswith("!"):
                out_patterns.append(line[1:])
            else:
                in_patterns.append(line)
    if not in_patterns and not out_patterns:
        return None
    return (in_patterns, out_patterns)


def _in_scope(subdomain: str, patterns: List[str],
              out_patterns: Optional[List[str]] = None) -> bool:
    """Check if a subdomain matches any scope pattern.

    Patterns:
      *.example.com  -> any subdomain of example.com (and example.com itself)
      example.com    -> example.com and any *.example.com
      api.example.com -> exact match only

    Any match in ``out_patterns`` (explicit OOS assets) FORCES in-scope
    False — OOS always wins over wildcards, mirroring program_scope's
    check_scope precedence rule.
    """
    sub = subdomain.lower().rstrip(".")
    if out_patterns:
        for pat in out_patterns:
            pat = pat.lower().rstrip(".")
            if pat.startswith("*."):
                root = pat[2:]
                if sub == root or sub.endswith("." + root):
                    return False
            elif sub == pat or sub.endswith("." + pat):
                return False
    for pat in patterns:
        pat = pat.lower().rstrip(".")
        if pat.startswith("*."):
            root = pat[2:]
            if sub == root or sub.endswith("." + root):
                return True
        elif sub == pat or sub.endswith("." + pat):
            return True
    return False


def _is_alive(hostname: str, timeout: float = 3.0) -> bool:
    """Return True if ``hostname`` has any A/AAAA DNS record.

    Uses dnspython with a real per-host ``lifetime`` (default 3s, env
    ``AMASS_ALIVE_HOST_TIMEOUT``) so a hung/unreachable nameserver cannot pin
    the sweep.  Falls back to a thread-bounded ``socket.getaddrinfo`` if
    dnspython is unavailable.

    The previous implementation called ``socket.getaddrinfo`` with a
    ``timeout`` argument that getaddrinfo does NOT accept — it was silently
    dropped and each resolve was bounded only by the system resolver default,
    which routinely ran tens of seconds on a serfail/retry and pushed the
    alive-check sweep past the caller's socket deadline.
    """
    if _DNS_AVAILABLE:
        # Per-call lifetime keeps the shared resolver thread-safe across the
        # sweep's worker pool (resolve() builds a per-query context).
        try:
            _DNS_RESOLVER.resolve(hostname, "A", lifetime=timeout)
            return True
        except _dns_resolver.NXDOMAIN:
            pass
        except _dns_resolver.NoAnswer:
            pass
        except (_dns_resolver.NoNameservers, _dns_resolver.LifetimeTimeout,
                _dns_resolver.Timeout):
            return False
        except Exception:  # pragma: no cover - defensive
            return False
        try:
            _DNS_RESOLVER.resolve(hostname, "AAAA", lifetime=timeout)
            return True
        except Exception:
            return False

    # Fallback: bound the blocking getaddrinfo in a throwaway thread so the
    # dead ``timeout`` semantics can't hang us when dnspython is absent.
    with ThreadPoolExecutor(max_workers=1) as pool:
        fut = pool.submit(
            socket.getaddrinfo, hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
        try:
            fut.result(timeout=timeout)
            return True
        except _FutureTimeout:
            return False
        except (socket.gaierror, socket.timeout, OSError):
            return False


def _resolve_alive(
    hostnames: List[str], timeout: float = 3.0, workers: int = 40,
    out_patterns: Optional[List[str]] = None,
    budget: Optional[float] = None,
) -> Tuple[List[Dict[str, Any]], int]:
    """Concurrently DNS-resolve a list of hostnames within a hard deadline.

    Returns ``(records, checked)`` where ``records`` is one entry per input
    host in input order ``{"host": h, "alive": bool, "oos": bool}`` and
    ``checked`` is how many hosts actually got a resolution attempt before
    the budget expired (hosts not reached in time are returned as
    ``alive=False``).

    ``oos`` is True when the host also matches an explicit out-of-scope
    pattern (a defensive double-check — ``subdomain_enum_status`` filters
    OOS before calling this, so ``oos`` is normally False; a non-empty
    alive+oos set is the visible alarm that the OOS filter saw something
    alive).

    Two caps keep this under the MCP caller's ~30s socket deadline:
      * per-host ``timeout`` (env ``AMASS_ALIVE_HOST_TIMEOUT``, default 3s)
        via dnspython ``lifetime`` — a hung resolver can't stall one slot.
      * overall ``budget`` (env ``AMASS_ALIVE_BUDGET``, default 25s) —
        ``as_completed(timeout=budget)`` returns whatever finished; the rest
        are reported as not-alive rather than hanging the call.  With 40
        workers and a 3s per-host cap, 260 hosts finish in <= ~20s worst
        case, well under budget.
    """
    host_timeout = float(os.getenv("AMASS_ALIVE_HOST_TIMEOUT", str(timeout)))
    n_workers = int(os.getenv("AMASS_ALIVE_WORKERS", str(workers)))
    overall = float(os.getenv(
        "AMASS_ALIVE_BUDGET", "25" if budget is None else str(budget)
    ))

    out_norm = [p.lower().rstrip(".") for p in (out_patterns or [])]

    def _is_oos(host: str) -> bool:
        sub = host.lower().rstrip(".")
        for pat in out_norm:
            if pat.startswith("*."):
                root = pat[2:]
                if sub == root or sub.endswith("." + root):
                    return True
            elif sub == pat or sub.endswith("." + pat):
                return True
        return False

    records: Dict[str, Dict[str, Any]] = {}
    checked = 0
    with ThreadPoolExecutor(max_workers=n_workers) as pool:
        futures = {pool.submit(_is_alive, h, host_timeout): h for h in hostnames}
        try:
            for future in as_completed(futures, timeout=overall):
                h = futures[future]
                records[h] = {"host": h, "alive": bool(future.result()), "oos": _is_oos(h)}
                checked += 1
        except _FutureTimeout:
            # Budget expired — return whatever finished; the rest are
            # reported as not-alive below.  ``checked < len(hostnames)``
            # tells the caller the result is partial.
            pass
    # Hosts that didn't get a verdict in time are conservatively not-alive.
    out: List[Dict[str, Any]] = []
    for h in hostnames:
        if h in records:
            out.append(records[h])
        else:
            out.append({"host": h, "alive": False, "oos": _is_oos(h)})
    return out, checked


# --- subdomain_enum (async launcher) + subdomain_enum_status (poller) -------

@framework_tool(
    "Launch subdomain enumeration for a domain in the background using "
    "amass, then resolve each discovered subdomain to verify it's alive, "
    "and filter against the per-company program scope "
    "(scope_platform+scope_handle, e.g. 'bugcrowd'+'tesla' after "
    "load_program_scope(platform=...) — omit to run UNFILTERED). "
    "Non-blocking — starts the scan and returns immediately with a job_id. "
    "Confirm the launch with one status poll, then hand off to the user; "
    "poll again only when the user requests an update for a "
    "structured JSON result: {subdomains, alive, out_of_scope}. "
    "Passive by default; pass options for active/brute modes.",
    next_hints=["subdomain_enum_status", "run_nmap -iL <alive subdomains>"],
)
def subdomain_enum(target, options="", scope_platform=None, scope_handle=None):
    """Launch amass enum + alive-check composite and return immediately.

    amass runs as a detached background subprocess; this call does NOT block.
    Perform one status poll to confirm it is running, then hand off to the
    user.  Poll again only when the user requests an update.  When done, the
    status function retrieves names
    (amass v5 ``amass subs`` + crt.sh fallback), filters against program
    scope, and DNS-resolves in-scope subdomains to check if they're alive.

    Args:
        target: Root domain to enumerate (e.g. example.com).
        options: Extra amass flags (same allowlist as run_amass).
        scope_platform: Optional platform key ("h1"|"bugcrowd") for the
            per-company scope filter.  Requires scope_handle.
        scope_handle: Optional program handle — selects
            ``<scope_platform>_<handle>.scope`` for filtering.  OMIT both
            to run unfiltered (results flagged with a warning); a scan
            never silently inherits another company's scope.
    """
    validated = _validate_options(options)

    # Filter out -dir/-d/-oA from user options — -d and -oA are managed
    # internally; -dir is intentionally NOT used (we rely on amass's default
    # home DB so results persist across runs and survive process kills).
    user_flags = []
    skip_next = False
    for tok in validated:
        if skip_next:
            skip_next = False
            continue
        if tok in ("-dir", "-d", "-oA"):
            skip_next = True
            continue
        user_flags.append(tok)

    # -rigid prevents scope expansion into third-party infrastructure
    # (sendgrid, AWS EC2, etc.) that wastes the enum's time budget on noise.
    if "-rigid" not in user_flags:
        user_flags.append("-rigid")

    # Inject trusted DNS resolvers (-tr, 15 QPS each) to raise the
    # MaxDNSQueries cap.  amass's default 17 baseline resolvers give ~255
    # QPS; adding more trusted resolvers multiplies throughput linearly.
    # Skip injection if the caller already passed -tr or -rf (don't clobber
    # their explicit choice).  Override the list via AMASS_TRUSTED_RESOLVERS
    # env var (comma-separated IPs); set to empty string to disable injection.
    _DEFAULT_TRUSTED_RESOLVERS = [
        "8.8.8.8", "8.8.4.4",          # Google
        "1.1.1.1", "1.0.0.1",          # Cloudflare
        "9.9.9.9", "149.112.112.112",  # Quad9
        "208.67.222.222", "208.67.220.220",  # Cisco OpenDNS
        "84.200.69.80", "84.200.70.40",      # DNS.WATCH
        "64.6.64.6", "64.6.65.6",            # Neustar
        "94.140.14.14", "94.140.15.15",      # AdGuard
        "76.76.19.19", "76.76.2.0",          # ControlD / Alternate DNS
    ]
    has_tr = any(tok == "-tr" for tok in user_flags)
    has_rf = any(tok == "-rf" for tok in user_flags)
    env_resolvers = os.getenv("AMASS_TRUSTED_RESOLVERS", "")
    if not has_tr and not has_rf:
        if env_resolvers:
            resolver_list = [r.strip() for r in env_resolvers.split(",") if r.strip()]
        else:
            resolver_list = _DEFAULT_TRUSTED_RESOLVERS
        for ip in resolver_list:
            user_flags.extend(["-tr", ip])

    command = [
        "amass", "enum",
        "-d", target,
        "-nocolor",
        *user_flags,
    ]

    # Use the full dispatch timeout (minus headroom) by default.  The old
    # min(600, ...) cap killed every enum at 10 minutes — before amass v5
    # could commit its WAL transaction, causing total data loss.  Override
    # with AMASS_ENUM_TIMEOUT env var if a shorter cap is needed.
    dispatch_timeout = float(os.getenv("BRAIN_DISPATCH_TIMEOUT", "1900"))
    amass_cap = float(os.getenv("AMASS_ENUM_TIMEOUT", str(max(60, dispatch_timeout - 10))))

    job = launch_job(
        command,
        tool_name="amass",
        timeout=amass_cap,
    )
    job_id = job["job_id"]
    _store_amass_meta(job_id, target, options, composite=True,
                      scope_platform=scope_platform, scope_handle=scope_handle)

    return {
        "job_id": job_id,
        "status": "running",
        "target": target,
        "message": (
            "launch accepted; perform one status poll to confirm the job is "
            "running, then hand off to the user. Poll again only when the "
            "user requests an update."
        ),
    }


@framework_tool(
    "Poll a subdomain_enum job: returns running/done plus a structured "
    "JSON result with discovered subdomains, alive (DNS-resolved) hosts, "
    "and out-of-scope names. Call once only when the user requests an update; "
    "never poll repeatedly until done.",
    next_hints=["run_nmap -iL <alive subdomains>", "zap_open_url on discovered hosts"],
)
def subdomain_enum_status(job_id):
    """Poll the status of a composite enum launched by ``subdomain_enum``.

    When the amass enum subprocess finishes, this:
    1. Retrieves discovered names (``amass subs -names`` + crt.sh fallback)
    2. Filters against the per-company scope selected at launch
    3. DNS-resolves in-scope subdomains to check if they're alive
    4. Returns structured JSON: ``{subdomains, alive, out_of_scope, ...}``

    Args:
        job_id: The ``job_id`` returned by ``subdomain_enum``.
    """
    meta = _get_amass_meta(job_id)
    if meta is None:
        return {
            "job_id": job_id,
            "status": "unknown",
            "error": f"no subdomain_enum job with id {job_id!r} (it may have been evicted)",
        }

    poll = poll_job(job_id, tool_name="amass")
    status = poll.get("status", "unknown")

    if status != "done":
        # Still running — return the poll result as-is.
        return poll

    # --- Job is done: retrieve names (once, cache the result) ---
    if not meta["retrieved"]:
        domain = meta["domain"]
        names = _get_names(domain)
        with _AMASS_LOCK:
            meta["retrieved"] = True
            meta["result"] = names
    else:
        names = meta["result"]

    if not names:
        return {
            "job_id": job_id,
            "status": "done",
            "subdomains": [],
            "alive": [],
            "out_of_scope": [],
            "total_discovered": 0,
            "total_alive": 0,
            "elapsed": poll.get("elapsed"),
            "timed_out": poll.get("timed_out", False),
            "note": (
                "amass returned no subdomains and all free CT sources "
                "(certspotter, hackertarget, crt.sh) also returned nothing. "
                "Possible causes: no data-source API keys active in "
                "datasources.yaml, the domain has no CT-log entries, or all "
                "CT sources are down.  If amass enum was killed before "
                "completing, prior run results may still be in the home DB "
                "(~/.config/amass/asset.db) — try: amass subs -names -show "
                "-d <domain>."
            ),
        }

    # Scope filtering (per-company, keyed at launch time).
    scope = _load_scope(meta.get("scope_platform"), meta.get("scope_handle"))
    if scope is None:
        in_scope = names
        out_of_scope = []
        out_patterns = []
        scope_warning = ("launched without scope_handle — results NOT scope-filtered"
                         if not meta.get("scope_handle") else
                         f"scope file {meta.get('scope_platform')}_{meta.get('scope_handle')}.scope "
                         f"not found — results UNFILTERED; load_program_scope first")
    else:
        in_patterns, out_patterns = scope
        in_scope = [s for s in names if _in_scope(s, in_patterns, out_patterns)]
        out_of_scope = [s for s in names if s not in in_scope]
        scope_warning = None

    # DNS resolution (alive check) — only on in-scope subs.
    #
    # The alive-check is bounded (per-host lifetime + overall budget, see
    # ``_resolve_alive``) AND cached on the job meta so retries are free —
    # previously every poll re-ran the full uncached sweep, and the dead
    # ``timeout`` arg let each resolve run to the system resolver default,
    # pushing the call past the MCP caller's socket deadline every time.
    if not meta["alive_retrieved"]:
        resolved, checked = _resolve_alive(
            in_scope, out_patterns=out_patterns if scope else []
        )
        with _AMASS_LOCK:
            meta["alive_retrieved"] = True
            meta["alive"] = resolved
            meta["alive_checked"] = checked
            meta["alive_partial"] = checked < len(in_scope)
    else:
        resolved = meta["alive"]
        checked = meta["alive_checked"]
    alive = [r["host"] for r in resolved if r["alive"] and not r["oos"]]
    alive_oos = [r["host"] for r in resolved if r["alive"] and r["oos"]]

    return {
        "job_id": job_id,
        "status": "done",
        "subdomains": in_scope,
        "alive": alive,
        "alive_oos": alive_oos,
        "out_of_scope": out_of_scope,
        "total_discovered": len(names),
        "total_in_scope": len(in_scope),
        "total_alive": len(alive),
        "total_alive_oos": len(alive_oos),
        "alive_checked": checked,
        "alive_partial": meta["alive_partial"],
        "elapsed": poll.get("elapsed"),
        "timed_out": poll.get("timed_out", False),
    }
    if scope_warning:
        result["warning"] = scope_warning
    return result
