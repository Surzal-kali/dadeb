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
from typing import Any

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
_noninteractive_supported: bool | None = None


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


def _inject_noninteractive(extra: list[str]) -> list[str]:
    """Append ``-noninteractive`` when the installed ffuf supports it.

    The detached launcher already sets stdin=/dev/null, which keeps ffuf
    non-interactive on versions without the flag (e.g. Trixie's 1.1.0).
    """
    if any(a in ("-noninteractive", "--noninteractive") for a in extra):
        return extra
    if _ffuf_supports_noninteractive():
        return extra + ["-noninteractive"]
    return extra


def _inject_scan_config(extra: list[str], url: str,
                        scope_handle: str | None,
                        scope_platform: str | None) -> tuple[list[str], dict[str, Any] | None]:
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


def _inject_ignore_comments(extra: list[str]) -> list[str]:
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


def _strip_follow_redirects(extra: list[str]) -> tuple[list[str], bool]:
    """Drop redirect-following flags; returns (clean_list, stripped_any)."""
    kept = [a for a in extra if a not in _FOLLOW_REDIRECT_FLAGS]
    return kept, len(kept) != len(extra)


def _path_from_record(rec: dict[str, Any]) -> str:
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


def _interest_rank(f: dict[str, Any]) -> int:
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


def _cap_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
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


def _parse_ffuf_output_file(out_path: str) -> dict[str, Any] | None:
    """Parse ffuf's ``-of json -o <file>`` output (one JSON object per file).

    Real file shape (ffuf 1.1.0, captured live): ``{"commandline": ...,
    "time": ..., "results": [{"input": {...}, "status": ..., "length":
    ..., ...}]}`` — results at a top-level ``"results"`` key.
    """
    try:
        with open(out_path) as fh:
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


def _parse_ffuf_verdict(log_text: str) -> dict[str, Any]:
    """Best-effort summary from ffuf's stdout (human table mode).

    Strips the ANSI ``\x1b[2K`` prefixes ffuf writes into redirected
    output, then parses path-first result rows.  Also accepts NDJSON
    records on stdout (some ffuf builds/modes emit those).  The
    ``-of json -o <file>`` output is parsed separately by
    ``_parse_ffuf_output_file`` and preferred by ``run_ffuf``'s verdict.
    """
    findings: list[dict[str, Any]] = []
    seen = set()
    meta: dict[str, Any] = {}

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
             scope_handle: str | None = None,
             scope_platform: str | None = None,
             chunk_plan_id: str = "", chunk_index: int = 0,
             chunk_offset: int = 0, chunk_slice: int = 0,
             chunk_total_chunks: int = 0) -> dict[str, Any]:
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

    Wordlists larger than the budget constitution's single-call ceiling do
    NOT run whole: the tool mints a chunk PLAN (zero traffic this call) and
    the operator drain pays it out one slice at a time (U2 lane). Poll
    ``budget_queue_status(plan_id=...)`` for progress; per-chunk verdicts
    come back through ``ffuf_status`` on the chunk's job ids.

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
            A ``-w`` flag here is REFUSED when auto-chunking engages (the
            chunk lane owns the wordlist flag; it would silently discard
            the plan's slice).
        scope_handle: Program handle for auto-injection of mandatory testing
            requirements (Intigriti RoE: custom UA, request header, req/sec
            cap). Pair with ``scope_platform``. When set, the program
            manifest is consulted and ``-H`` / ``-rate`` flags are injected
            automatically — caller-provided headers/rate always win.
        scope_platform: Platform key (``"intigriti"``, ``"h1"``, etc.)
            paired with ``scope_handle``. Only ``"intigriti"`` has
            structured testing requirements; other platforms are a no-op.
        chunk_plan_id: Internal — the wordlist plan this dispatch belongs
            to. Set by the budget queue's drain, never by hand.
        chunk_index: Internal — 0-based slice index for this dispatch.
        chunk_offset: Internal — 0-based first line index of the slice.
        chunk_slice: Internal — slice line count for this dispatch (the
            chunk lane's canonical argument key; a dispatch's slice count
            is NOT spelled ``chunk_size`` — that name is plan-level
            geometry and preflight rejects it at the manifest).
        chunk_total_chunks: Internal — total slices in the parent plan.
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

    # ── U2 wordlist lane (evasion_upgrade.md §2) ────────────────────────────
    # lane_decision is the ONE predicate the budget estimator and this body
    # both read, so preflight and launch can never disagree. Three cases:
    # single (fits — run as today), plan (never fits whole — mint a plan and
    # return a zero-traffic envelope), chunk (this dispatch IS one slice —
    # slice at dispatch, then launch the slice file).
    from utils import wordlist_chunking as wlc

    # The lane predicate reads THIS dispatch's own arguments — chunk keys
    # included (2026-11-06 drain incident: the tool's named parameters
    # (chunk_plan_id/chunk_index/…) were stripped out of _lane_args, so
    # every DRAIN chunk dispatch re-decided PLAN mode, minted a fresh plan
    # with zero traffic, and returned the chunk_plan envelope; the drain
    # consumed it as an inline finish while the debit stood. The chunk
    # keys are internal plumbing minted by THIS lane, not caller data —
    # nothing untrusted rides in them (preflight already validated each
    # one against the manifest schema).
    _lane_args = {"url": url, "wordlist": wordlist, "options": options,
                  "scope_handle": scope_handle,
                  "scope_platform": scope_platform}
    # Chunk keys are internal plumbing minted by THIS lane — this dispatch's
    # own named parameters, not caller data (preflight validates them against
    # the manifest). Explicit reads, not a locals() comprehension: the dict
    # comp sees them today, but the lane's honesty must not ride a scope
    # quirk a future CPython frame change could silently break.
    for _ck in ("chunk_plan_id", "chunk_index", "chunk_offset",
                "chunk_slice", "chunk_total_chunks"):
        _cv = locals().get(_ck)
        if _cv is not None:
            _lane_args[_ck] = _cv
    _decision = wlc.lane_decision("payloads.ffuf.run_ffuf", _lane_args,
                                  wordlist)
    if _decision and _decision["mode"] in ("plan", "chunk"):
        # The chunk lane owns the wordlist flag: a caller -w would silently
        # discard the plan's slice (the last -w wins inside ffuf).
        try:
            _opt_toks = shlex.split(options) if options else []
        except ValueError:
            _opt_toks = options.split()
        if any(t == "-w" or t.startswith("--wordlist=") for t in _opt_toks):
            return {
                "job_id": None, "tool": "ffuf", "status": "error",
                "wordlist": wordlist,
                "error": (
                    "options carries an explicit '-w' wordlist and the "
                    "budget chunk lane owns that flag for this run — the "
                    "slice would be silently overridden. Pass the wordlist "
                    "via the `wordlist` argument (or shrink the list below "
                    "the single-call budget ceiling) and retry."),
            }

    if _decision and _decision["mode"] == "plan":
        # Never-fit whole: mint the plan (+ its first lazy window) and
        # return WITHOUT any traffic (§2.1). The zero-declared estimator
        # means the gate debited nothing here; the discharge settles the
        # plan-issue emission at once. Spend lands per chunk, through the
        # drain, one gate-dispatched slice at a time.
        from utils.agent_identity import current_agent_id
        from utils.engagement import current_slug
        from utils.ration import dims_for_target, find_target
        plan = wlc.mint_wordlist_plan(
            "payloads.ffuf.run_ffuf", _lane_args, _decision,
            decl=dict(_decision["slices"]),
            dims=dims_for_target(find_target(_lane_args)),
            agent_id=current_agent_id() or "0",
            engagement=current_slug())
        plan_id = plan["plan_id"]
        # mint_wordlist_plan pre-mints the first lazy window; report the
        # live queued count so the envelope never says 0 while chunks sit
        # in the queue.
        from utils.ration import get_ration_store
        window_now = int(get_ration_store().plan_counts(plan_id)["queued"])
        total = int(plan["total_chunks"])
        window = int(plan["window"])
        return {
            "status": "chunk_plan",
            "plan_id": plan_id,
            "tool": "payloads.ffuf.run_ffuf",
            "url": url,
            "wordlist": wordlist,
            "lines": int(plan["lines"]),
            "chunk_size": int(plan["chunk_size"]),
            "total_chunks": total,
            "binding_dim": plan["binding_dim"],
            "window": window,
            "minted_first_window": window_now,
            "expected_ticks": int(-(-total // window)),
            "poll": f"budget_queue_status(plan_id=\"{plan_id}\")",
            "note": (
                "no traffic was sent this call — the wordlist exceeds the "
                "budget constitution's single-call ceiling, so this is a "
                "PLAN: the operator drain pays out one chunk per tick "
                "through the full gate (per-chunk debits), minting the next "
                "window as sibling chunks finish. Chunks re-slice this "
                "wordlist at dispatch; recursion/multi-wordlist actuals are "
                "metered L1 against the declared slice. Do NOT re-issue the "
                "call — poll budget_queue_status(plan_id=...)"),
        }

    if _decision and _decision["mode"] == "chunk":
        plan = wlc.plan_view(_decision["plan_id"])
        if plan is None:
            return {
                "job_id": None, "tool": "ffuf", "status": "error",
                "error": (
                    f"chunk plan {_decision['plan_id']!r} no longer exists "
                    "(purged or TTL-swept) — the chunk is unrunnable; "
                    "re-issue the original run_ffuf call to mint a fresh "
                    "plan."),
            }
        # Slice AT DISPATCH (§2.2): the plan holds the base call; this call
        # materializes exactly its lines. An unreadable wordlist requeues
        # (could be a transitory unmount) — the plan TTL bounds the churn.
        try:
            wordlist = str(wlc.write_slice(plan["plan_id"],
                                           _decision["chunk_index"],
                                           plan["wordlist"],
                                           _decision["chunk_offset"],
                                           _decision["chunk_size"]))
        except OSError as exc:
            return wlc.requeued_envelope(
                _decision["plan_id"],
                chunk_index=_decision["chunk_index"],
                total=_decision["total_chunks"],
                reason=f"slice write failed — wordlist unreadable: {exc}")


    # An explicit (non-empty) wordlist must resolve to an existing file —
    # fail fast before the launch+poll cycle burns time on a path ffuf will
    # reject with "could not read wordlist".

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

    def _verdict(log_text: str) -> dict[str, Any]:
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
        target=url,
        verdict_parser=_verdict,
    )
    # launch_job(target=...) routes through the fleet scheduler; a
    # duplicate/refused decision envelope carries NO launched job — return
    # it verbatim instead of decorating launch-side metadata over it.
    if job.get("status") in ("duplicate", "refused"):
        if _decision and _decision["mode"] == "chunk":
            # §2.5: the sibling unit owns this work (duplicate) or the
            # refusal is transient (slots/auth serialization) — requeue the
            # SAME chunk and let the drain pay it out again in due order.
            return wlc.requeued_envelope(
                _decision["plan_id"],
                chunk_index=_decision["chunk_index"],
                total=_decision["total_chunks"],
                reason=(f"fleet {job.get('status')}: "
                        f"{job.get('reason') or job.get('message') or 'busy'}"),
                sibling_job_id=job.get("job_id"))
        return job
    if _decision and _decision["mode"] == "chunk":
        job["chunk_plan_id"] = _decision["plan_id"]
        job["chunk_index"] = _decision["chunk_index"] + 1
        job["chunk_total_chunks"] = _decision["total_chunks"]
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


def _ffuf_status_digest(result: dict[str, Any]) -> dict[str, Any]:
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
        status_counts: dict[int, int] = {}
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
def ffuf_status(job_id: str) -> dict[str, Any]:
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
def ffuf_cancel(job_id: str) -> dict[str, Any]:
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
