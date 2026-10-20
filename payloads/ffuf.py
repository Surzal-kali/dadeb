"""ffuf web fuzzer — background launch + poll pattern.

Long fuzzing runs are launched detached via :mod:`utils.background_job` so
the secretary turn is not held open.  ``run_ffuf`` returns a ``job_id``
immediately; ``ffuf_status`` polls until ``status: "done"``.
``-noninteractive`` and ``-ic`` are auto-injected as defensive defaults.
"""

from __future__ import annotations

import json as _json
import os
import re
import subprocess
import uuid
from typing import Any, Dict, List, Optional, Tuple

from constants import framework_tool
from utils.background_job import launch_job, poll_job, terminate_job, register_verdict_parser
from utils.wordlists import resolve_default_wordlist, resolve_wordlist


_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

# Real ffuf table rows print the path BEFORE the bracket block:
#   admin                   [Status: 301, Size: 0, Words: 1, Lines: 1]
# (verified against ffuf 1.1.0 on Debian Trixie; the "[Status: ...]: /path"
# format ffuf does not emit would silently never match).
_FFUF_ROW_RE = re.compile(
    r"^(?P<path>\S+)\s+\[Status:\s*(?P<status>\d+),\s*"
    r"Size:\s*(?P<size>\d+),\s*"
    r"Words:\s*(?P<words>\d+),\s*Lines:\s*(?P<lines>\d+)"
    r"(?:,\s*Duration:\s*(?P<duration>[\d.]+s))?\]"
)

# -noninteractive first appears in ffuf 2.0.0; Debian Trixie ships 1.1.0
# where the flag is fatal ("flag provided but not defined", exit 2).
_FFUF_NONINTERACTIVE_MIN = (2, 0)
_noninteractive_supported: Optional[bool] = None


def _ffuf_supports_noninteractive() -> bool:
    """Check (once) whether the installed ffuf knows -noninteractive."""
    global _noninteractive_supported
    if _noninteractive_supported is None:
        supported = False  # conservative default: don't inject
        try:
            out = subprocess.run(
                ["ffuf", "-V"], capture_output=True, text=True, timeout=10
            ).stdout
            m = re.search(r"v?(\d+)\.(\d+)", out)
            if m:
                ver = (int(m.group(1)), int(m.group(2)))
                supported = ver >= _FFUF_NONINTERACTIVE_MIN
        except Exception:
            supported = False
        _noninteractive_supported = supported
    return _noninteractive_supported


def _inject_noninteractive(extra: List[str]) -> List[str]:
    """Append ``-noninteractive`` when the installed ffuf supports it.

    The detached launcher already sets stdin=/dev/null, which keeps ffuf
    non-interactive on versions without the flag (e.g. Trixie's 1.1.0).
    """
    if any(a in ("-noninteractive", "--noninteractive") for a in extra):
        return extra
    if _ffuf_supports_noninteractive():
        return extra + ["-noninteractive"]
    return extra


def _inject_scan_config(extra: List[str], url: str,
                        scope_handle: Optional[str],
                        scope_platform: Optional[str]) -> Tuple[List[str], Optional[Dict[str, Any]]]:
    """Auto-inject mandatory testing requirements from the program manifest.

    When ``scope_handle`` / ``scope_platform`` point to an Intigriti program
    whose RoE mandates a custom User-Agent, request header, or req/sec cap,
    those are injected as ``-H`` and ``-rate`` flags — unless the caller
    already set the same header or ``-rate`` in ``options`` (caller wins).

    Returns the (possibly extended) arg list and the resolved scan config
    (or None) so the caller can surface it in the job envelope.
    """
    if not scope_handle or not scope_platform:
        return extra, None
    try:
        from auxiliaries.program_scope import get_scan_config
        cfg = get_scan_config(scope_handle, scope_platform)
    except Exception:
        return extra, None
    if not cfg:
        return extra, cfg

    # Detect what the caller already set so we don't clobber explicit overrides.
    caller_lower = " ".join(extra).lower()
    has_rate = "-rate" in caller_lower

    injected = list(extra)

    # Inject headers if any are mandated (rate-only configs have no headers).
    for hname, hval in (cfg.get("headers") or {}).items():
        header_str = f"{hname}: {hval}"
        # Skip if the caller already set this exact header name.
        if hname.lower() in caller_lower:
            continue
        injected += ["-H", header_str]

    # Inject rate independently of headers so rate-only programs are enforced.
    rate = cfg.get("max_requests_per_second")
    if rate and not has_rate:
        injected += ["-rate", str(rate)]

    return injected, cfg


def _inject_ignore_comments(extra: List[str]) -> List[str]:
    """Append ``-ic`` unless the caller already set it.

    141 of 6 042 SecLists wordlists contain ``#``-prefixed comment lines
    (DirBuster headers, license text, etc.); without ``-ic`` ffuf fuzzes
    them as literal paths, wasting requests and generating noise.  No
    SecLists Web-Content wordlist uses ``#`` as a legitimate path prefix,
    so this is safe for the URL/FUZZ use case.
    """
    if any(a in ("-ic", "--ic") for a in extra):
        return extra
    return extra + ["-ic"]


# SCOPE DENYLIST (operator decision 2026-09-19): '-r'/'--follow-redirects'
# makes ffuf follow 30x hops INSIDE the binary — beyond the launch gate's
# reach, potentially onto out-of-scope hosts.  Stripped from caller options
# (fail-visible note on the job).  '-recursion' (same-host fuzz recursion)
# is NOT a redirect flag and is untouched.
_FOLLOW_REDIRECT_FLAGS = frozenset(
    {"-r", "--follow-redirects", "-follow-redirects"}
)


def _strip_follow_redirects(extra: List[str]) -> Tuple[List[str], bool]:
    """Drop redirect-following flags; returns (clean_list, stripped_any)."""
    kept = [a for a in extra if a not in _FOLLOW_REDIRECT_FLAGS]
    return kept, len(kept) != len(extra)


def _path_from_record(rec: Dict[str, Any]) -> str:
    """Extract the fuzzed value from a ffuf result record.

    JSON records carry it in ``input`` — a dict like ``{"FUZZ": "admin"}``.
    ffuf 2.x adds an internal ``FFUFHASH`` key (e.g. ``"7b0bd1"``) that
    sorts before ``FUZZ``, so we must prefer ``FUZZ`` over ``next(iter())``.
    Falls back to URL when no keyword is found.
    """
    raw = rec.get("input")
    if isinstance(raw, dict) and raw:
        # Prefer FUZZ keyword; exclude ffuf-internal keys like FFUFHASH.
        for k in ("FUZZ", *raw):
            if k != "FFUFHASH":
                return str(raw[k])
        return str(next(iter(raw.values())))
    if isinstance(raw, list) and raw:
        return "/".join(str(p) for p in raw)
    return str(rec.get("url", ""))


# Bound on parsed findings returned by the ffuf verdict parsers. ffuf result
# cardinality is unbounded: against a catch-all target (an app that 302s
# every path to a login page, so every wordlist word "hits") a recursive
# directory-list-2.3-medium run produced 151k findings — a 29 MB poll reply
# that the Brain wire guard (MAX_MESSAGE_SIZE, 10 MiB, listeners/thebrain.py)
# rejected on the socket read. The cap keeps the serialized verdict far under
# the wire limit; the full result set always remains in the per-job -o JSON
# output file (surfaced in meta.output_file), so nothing is lost.
_MAX_FINDINGS = int(os.getenv("FFUF_MAX_FINDINGS", "10000"))


def _interest_rank(f: Dict[str, Any]) -> int:
    """Interest ordering: 200s first, then 3xx redirects, then 403s, 500s."""
    code = f.get("status") or 0
    if code == 200:
        return 0
    elif 300 <= code < 400:
        return 1
    elif code == 403:
        return 2
    elif code == 500:
        return 3
    return 4


def _cap_findings(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Bound the findings list so the poll verdict stays wire-safe.

    When truncating, keep the most interesting findings first
    (``_interest_rank``; ``sorted`` is stable, so original ffuf order is
    preserved within a rank) and report the true total via
    ``findings_total`` / ``findings_truncated`` so the caller knows the
    list was cut and where the rest lives.
    """
    total = len(findings)
    if total <= _MAX_FINDINGS:
        return {
            "findings": findings,
            "findings_count": total,
            "findings_total": total,
            "findings_truncated": False,
        }
    return {
        "findings": sorted(findings, key=_interest_rank)[:_MAX_FINDINGS],
        "findings_count": _MAX_FINDINGS,
        "findings_total": total,
        "findings_truncated": True,
    }


def _parse_ffuf_output_file(out_path: str) -> Optional[Dict[str, Any]]:
    """Parse ffuf's ``-of json -o <file>`` output (one JSON object per file).

    Real file shape (ffuf 1.1.0, captured live): ``{"commandline": ...,
    "time": ..., "results": [{"input": {...}, "status": ..., "length":
    ..., ...}]}`` — results at a top-level ``"results"`` key.
    """
    try:
        with open(out_path, "r") as fh:
            data = _json.load(fh)
    except (OSError, ValueError):
        return None
    results = data.get("results")
    if not isinstance(results, list):
        return None
    findings = []
    for rec in results:
        if not isinstance(rec, dict):
            continue
        findings.append(
            {
                "path": _path_from_record(rec),
                "status": rec.get("status"),
                "size": rec.get("length"),
                "words": rec.get("words"),
                "lines": rec.get("lines"),
                "redirect": rec.get("redirectlocation"),
                "url": rec.get("url"),
                "duration": rec.get("duration"),
            }
        )
    capped = _cap_findings(findings)
    capped["meta"] = {"source": "json", "output_file": out_path}
    return capped


def _parse_ffuf_verdict(log_text: str) -> Dict[str, Any]:
    """Best-effort summary from ffuf's stdout (human table mode).

    Strips the ANSI ``\x1b[2K`` prefixes ffuf writes into redirected
    output, then parses path-first result rows.  Also accepts NDJSON
    records on stdout (some ffuf builds/modes emit those).  The
    ``-of json -o <file>`` output is parsed separately by
    ``_parse_ffuf_output_file`` and preferred by ``run_ffuf``'s verdict.
    """
    findings: List[Dict[str, Any]] = []
    seen = set()
    meta: Dict[str, Any] = {}

    for raw_line in log_text.splitlines():
        s = _ANSI_RE.sub("", raw_line).strip()
        if s.startswith("::"):
            kv = s.lstrip(":").strip()
            if ":" in kv:
                key, _, val = kv.partition(":")
                meta[key.strip()] = val.strip()
            continue

        if s.startswith("{"):
            try:
                rec = _json.loads(s)
            except _json.JSONDecodeError:
                rec = None
            if isinstance(rec, dict) and ("status" in rec or "url" in rec):
                path = _path_from_record(rec)
                key = (rec.get("status"), str(path))
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    {
                        "path": path,
                        "status": rec.get("status"),
                        "size": rec.get("length"),
                        "words": rec.get("words"),
                        "lines": rec.get("lines"),
                        "duration": rec.get("duration"),
                    }
                )
                continue

        m = _FFUF_ROW_RE.search(s)
        if m:
            status = int(m.group("status"))
            path = m.group("path")
            key = (status, path)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                {
                    "path": path,
                    "status": status,
                    "size": int(m.group("size")),
                    "words": int(m.group("words")),
                    "lines": int(m.group("lines")),
                    "duration": m.group("duration"),
                }
            )

    capped = _cap_findings(findings)
    capped["meta"] = meta
    return capped


register_verdict_parser("ffuf", _parse_ffuf_verdict)


@framework_tool(
    "Launch and start a new ffuf web fuzzing run against a target URL: "
    "discovers hidden directories, files, vhosts, or parameters by "
    "brute-forcing a wordlist against the FUZZ keyword. Non-blocking and "
    "detached — starts the run in the background and returns immediately "
    "with a job ID for later retrieval. When scope_handle+scope_platform "
    "are given for an Intigriti program, mandatory testing requirements "
    "(custom User-Agent, X-Intigriti-Username header, req/sec cap) are "
    "auto-injected from the program manifest — you never need to pass them "
    "manually and can't accidentally fire raw traffic that violates the RoE. "
    "Redirect-following ('-r'/'--follow-redirects') is DENYLISTED and "
    "stripped — 30x hops inside ffuf are beyond the launch gate's reach.",
    next_hints=["ffuf_status"],
    untrusted_target=True,
)
def run_ffuf(url: str, wordlist: str = "", options: str = "",
             scope_handle: Optional[str] = None,
             scope_platform: Optional[str] = None) -> Dict[str, Any]:
    """Launch ffuf against ``url`` and return immediately.

    The URL must contain the ``FUZZ`` keyword where wordlist entries are
    substituted (e.g. ``http://10.10.10.50/FUZZ``).  Machine-readable JSON
    output is always captured to a per-job file; ``ffuf_status`` prefers
    that file's findings over the human-table parse.

    If ``wordlist`` is empty/unset, a short pre-existing SecLists default
    (``SecLists/Discovery/Web-Content/common.txt`` — the canonical quick
    ffuf list, overridable via ``DEFAULT_FFUF_WORDLIST``) is used as a
    "just in case" fallback so a forgotten argument runs a quick sane pass
    instead of failing with "could not read wordlist".  Call
    ``list_wordlists`` first for a targeted run.

    Args:
        url: Target URL containing the ``FUZZ`` keyword, e.g.
            ``http://10.10.10.50/FUZZ``.
        wordlist: Path to the wordlist file (passed to ``-w``).  Empty
            string falls back to the framework default wordlist.
        options: Additional ffuf command-line options as a single string
            (e.g. ``"-mc 200,301,401 -t 80 -recursion -recursion-depth 2"``).
            ``-noninteractive`` (if supported) and ``-ic`` are auto-injected
            unless already present. ``-r``/``--follow-redirects`` are on the
            scope DENYLIST and are stripped (30x hops inside ffuf are
            beyond the gate's reach); ``-recursion`` is untouched.
        scope_handle: Program handle for auto-injection of mandatory testing
            requirements (Intigriti RoE: custom UA, request header, req/sec
            cap). Pair with ``scope_platform``. When set, the program
            manifest is consulted and ``-H`` / ``-rate`` flags are injected
            automatically — caller-provided headers/rate always win.
        scope_platform: Platform key (``"intigriti"``, ``"h1"``, etc.)
            paired with ``scope_handle``. Only ``"intigriti"`` has
            structured testing requirements; other platforms are a no-op.
    """
    import shlex

    # Scope gate (operator-armed from the Tool REPL; no-op in lab mode).
    from utils.scope_gate import check_scan, ScopeGateError
    _sc_ok, _sc_reason = check_scan(url)
    if not _sc_ok:
        raise ScopeGateError(f"scope gate: {_sc_reason}")

    wordlist = (wordlist or "").strip()
    default_used = False
    if not wordlist:
        default_wl = resolve_default_wordlist("ffuf")
        if not default_wl:
            return {
                "job_id": None,
                "tool": "ffuf",
                "status": "error",
                "error": (
                    "No wordlist supplied and the framework default "
                    "(DEFAULT_FFUF_WORDLIST) is not present under "
                    "/usr/share/wordlists. Call list_wordlists to discover "
                    "an available wordlist, or pass an explicit wordlist path."
                ),
            }
        wordlist = default_wl
        default_used = True

    # An explicit (non-empty) wordlist must resolve to an existing file —
    # fail fast before the launch+poll cycle burns time on a path ffuf will
    # reject with "could not read wordlist".
    if not default_used:
        resolved = resolve_wordlist(wordlist)
        if not resolved:
            return {
                "job_id": None,
                "tool": "ffuf",
                "status": "error",
                "error": (
                    f"Wordlist path does not exist: {wordlist!r}. "
                    "Call list_wordlists to discover an available wordlist."
                ),
            }
        wordlist = resolved

    out_path = os.path.join(
        os.getenv("BG_JOB_LOG_DIR", "/tmp"), f"ffuf_out_{uuid.uuid4().hex[:8]}.json"
    )

    opt_list = shlex.split(options) if options else []
    opt_list, _rr_stripped = _strip_follow_redirects(opt_list)
    opt_list = _inject_noninteractive(opt_list)
    opt_list = _inject_ignore_comments(opt_list)
    opt_list, scan_cfg = _inject_scan_config(
        opt_list, url, scope_handle, scope_platform)

    # ``-u`` and ``-w`` are always explicit so the caller can't accidentally
    # omit the essentials; extra -w / -u in options are allowed by ffuf.
    # ``-s`` (silent) strips the live progress bar so the job log is just
    # clean result lines — easier to read and lighter on the verdict parser.
    # ``-of json -o`` goes LAST so it wins over any caller-provided -o.
    command = [
        "ffuf", "-s", "-u", url, "-w", wordlist,
        *opt_list, "-of", "json", "-o", out_path,
    ]

    def _verdict(log_text: str) -> Dict[str, Any]:
        verdict = _parse_ffuf_verdict(log_text)
        file_verdict = _parse_ffuf_output_file(out_path)
        if file_verdict and file_verdict.get("findings_count"):
            for key in (
                "findings",
                "findings_count",
                "findings_total",
                "findings_truncated",
            ):
                verdict[key] = file_verdict[key]
            verdict["meta"]["output_file"] = out_path
        return verdict

    job = launch_job(
        command,
        tool_name="ffuf",
        timeout=float(os.getenv("FFUF_TIMEOUT", "1800")),
        verdict_parser=_verdict,
    )
    if _rr_stripped:
        job["note"] = (
            "'-r/--follow-redirects' stripped from options (scope denylist): "
            "ffuf would follow 30x hops inside the binary, beyond the launch "
            "gate's reach — potentially onto out-of-scope hosts. Same-host "
            "fuzz recursion (-recursion) is unaffected."
        )
    # Surface which wordlist actually ran (and whether it was the fallback
    # default) so the secretary model knows to swap in a targeted list.
    job["wordlist"] = wordlist
    job["default_wordlist_used"] = default_used
    if scan_cfg:
        job["scan_config_applied"] = scan_cfg
    return job


def _ffuf_status_digest(result: Dict[str, Any]) -> Dict[str, Any]:
    """Digest adapter for ``ffuf_status`` — hit summary + status distribution.

    The full ffuf output (hundreds/thousands of path rows) is stored in
    scratch; the model gets:
    - job status (running/done) + elapsed
    - hit count + status code distribution (200, 301, 403, 500, ...)
    - top hits by interest (200s first, then 3xx redirects, then 403s)
    - job_id (needed for re-polling)
    - run meta (URL, method, wordlist)

    The model rarely needs the raw fuzz log to decide the next action — the
    status distribution + interesting paths ARE the triage signal.  When it
    needs the full hit list (e.g. to feed specific paths to sqlmap or ZAP),
    it retrieves from scratch.

    Findings arrive pre-capped (``_cap_findings`` / ``FFUF_MAX_FINDINGS``)
    when a target matched everything; ``findings_total`` carries the true
    count and the truncation note points at the full ``-o`` output file.
    """
    parts: list = []

    status = result.get("status", "unknown")
    parts.append(f"status={status}")

    if result.get("elapsed") is not None:
        parts.append(f"elapsed={result['elapsed']}s")

    findings = result.get("findings", [])
    findings_count = result.get("findings_count", len(findings))
    findings_total = result.get("findings_total", findings_count)
    parts.append(f"hits={findings_total}")

    # Status code distribution — the primary triage signal.
    if findings:
        status_counts: Dict[int, int] = {}
        for f in findings:
            code = f.get("status")
            if code is not None:
                status_counts[code] = status_counts.get(code, 0) + 1
        if status_counts:
            dist = ", ".join(
                f"{code}:{count}" for code, count
                in sorted(status_counts.items())
            )
            parts.append(f"status_dist={dist}")

        # Top hits: 200s first, then 3xx, then 403s — capped at 15.
        top = sorted(findings, key=_interest_rank)[:15]
        hit_lines = "\n  ".join(
            f"{f.get('status', '?')} {f.get('path', '?')} "
            f"(size={f.get('size', '?')}, words={f.get('words', '?')})"
            for f in top
        )
        parts.append(f"top_hits:\n  {hit_lines}")
        if findings_count > 15:
            parts.append(f"  ... +{findings_count - 15} more (retrieve full list from scratch)")
        if result.get("findings_truncated"):
            out_file = (result.get("meta") or {}).get("output_file", "?")
            parts.append(
                f"truncated: kept top {findings_count} of {findings_total} by "
                f"interest (FFUF_MAX_FINDINGS); full results in {out_file}"
            )

    job_id = result.get("job_id")
    if job_id:
        parts.append(f"job_id={job_id}")

    exit_code = result.get("exit_code")
    if exit_code is not None:
        parts.append(f"exit_code={exit_code}")

    timed_out = result.get("timed_out")
    if timed_out:
        parts.append("timed_out=True")

    # Run meta (compact — URL + method only).
    meta = result.get("meta", {})
    if meta.get("URL"):
        parts.append(f"url={meta['URL'][:120]}")
    if meta.get("Method"):
        parts.append(f"method={meta['Method']}")

    summary = " | ".join(parts)

    row_hint = (
        "scratch_search scratch:<id> --filter '200' "
        "# pull specific status-code hits from the full output"
    )

    return {"summary": summary, "row_hint_format": row_hint}


@framework_tool(
    "Poll, check, or monitor the progress and results of an existing, "
    "already-launched ffuf fuzzing job: returns running/done, a parsed list "
    "of discovered paths with HTTP status / size / words / lines, run meta "
    "(URL, method, threads, wordlist), and recent log lines. The findings "
    "list is capped at FFUF_MAX_FINDINGS with the most interesting status "
    "codes kept; findings_total/findings_truncated report the true hit "
    "count and the full results stay in the run's JSON output file. "
    "Call once only when the user requests an update; never poll repeatedly until done.",
    next_hints=["ffuf_status", "report_finding"],
    result_digest=lambda r: _ffuf_status_digest(r),
    untrusted_target=True,
)
def ffuf_status(job_id: str) -> Dict[str, Any]:
    """Poll the progress of a run launched by ``run_ffuf``.

    Reads the job's log file, checks whether the subprocess is still alive,
    and parses ffuf's output for discovered paths/responses.  Returns
    ``status: "running"`` while the run is in progress and ``status:
    "done"`` once the process has exited.  The parsed findings list is
    capped at ``FFUF_MAX_FINDINGS`` (default 10000) so the reply stays under
    the Brain's 10 MiB wire-frame limit; the complete result set always
    remains in the run's ``-o`` JSON output file (``meta.output_file``).

    Args:
        job_id: The ``job_id`` returned by ``run_ffuf``.
    """
    return poll_job(job_id, tool_name="ffuf")


@framework_tool(
    "Cancel, stop, and terminate an existing, already-launched ffuf "
    "fuzzing job by its job ID: sends SIGTERM (then SIGKILL if needed) "
    "to the background subprocess and frees the job. Use this when a run is "
    "taking too long, is no longer needed, or was launched by mistake.",
    next_hints=["ffuf_status"],
)
def ffuf_cancel(job_id: str) -> Dict[str, Any]:
    """Terminate an ffuf run launched by ``run_ffuf``.

    Sends SIGTERM to the background subprocess (escalating to SIGKILL if it
    doesn't exit within a few seconds) and marks the job terminated.  The
    job's log file is preserved so any partial findings captured so far can
    still be read via ``ffuf_status(job_id)``.

    Args:
        job_id: The ``job_id`` returned by ``run_ffuf``.
    """
    terminated = terminate_job(job_id)
    return {
        "job_id": job_id,
        "tool": "ffuf",
        "cancelled": terminated,
        "message": (
            f"ffuf job {job_id} terminated"
            if terminated
            else f"no live ffuf job with id {job_id!r} (already finished or evicted)"
        ),
    }
