"""sqlmap launcher + pollable status, mirroring the ZAP start/poll model.

sqlmap is inherently long-running: a real crawl+scan over many injectable
parameters can take minutes to tens of minutes. A *blocking* ``run_sqlmap``
holds the entire secretary turn open for the scan's full runtime and fights
the turn timeout no matter how large the budget. Instead this module uses
the ZAP shape (``zap_spider`` returns a scan id, ``zap_spider_status``
polls it):

- ``run_sqlmap(target_url, options)`` launches sqlmap as a background job
  and returns immediately with a ``job_id`` plus a log file path. The
  secretary turn is NOT held open. Routes through the Phase 0 job store
  AND the Phase 1 fleet scheduler (``launch_job(target=...)``) — one
  canonical unit per target, per-host slot policy enforced.
- ``sqlmap_status(job_id)`` polls the job: running/done + a parsed verdict
  (injectable / not injectable / still running) so the model can decide
  whether to keep polling or call ``report_finding``.

Fleet mode (Phase 2, scale-doctrine Annex A): ``run_sqlmap_fleet`` fans a
list of target URLs across the fleet scheduler — one per-target unit,
canonical shape keys, per-host slot policy, per-unit ``--output-dir``
session isolation; ``sqlmap_fleet_status`` / ``sqlmap_fleet_results`` /
``sqlmap_fleet_stop`` are the poll/aggregate/stop twins.

Non-interactivity is enforced defensively on two layers:

1. ``--batch`` is auto-injected when the caller omits it (sqlmap otherwise
   prompts on stdin: "do you want to test this URL? [Y/n/q]", ...).
2. ``stdin=subprocess.DEVNULL`` (in the job-store launcher) so any future
   unsuppressed prompt reads EOF and never blocks.

A wall-clock cap (``SQLMAP_TIMEOUT``, default 1800s) is enforced by the
job store's shared reaper (a cap kill stamps ``timed_out``); the poll
reports the timeout with the partial log.
"""

from __future__ import annotations

import os
import re
import shlex
from typing import Any

from constants import framework_tool
from utils.background_job import launch_job, poll_job, register_verdict_parser, terminate_job


def _inject_batch(extra: list[str]) -> list[str]:
    """Prepend/append ``--batch`` if the caller didn't already pass it."""
    if any(a in ("--batch", "-batch") or a.startswith("--batch=") for a in extra):
        return extra
    return extra + ["--batch"]


def _parse_verdict(log_text: str) -> dict[str, Any]:
    """Best-effort verdict from sqlmap's log output.

    Returns a dict with ``injectable`` (bool), ``dbms`` (str|None), and
    ``verdict`` (human-readable line). Conservative: only flips
    ``injectable`` True on sqlmap's explicit confirmation lines, never on the
    heuristic "might be injectable" line.
    """
    dbms = None
    # Capture just the bare DBMS name, not the "[Y/n]" prompt sqlmap appends on
    # the same line. "back-end DBMS is 'MySQL'. Do you want to skip..." ->
    # "MySQL".
    m = re.search(r"back-end DBMS is '?([A-Za-z][A-Za-z0-9 _]*)'?", log_text, re.IGNORECASE)
    if m:
        dbms = m.group(1).strip()
    injectable = None  # None = unknown, True/False once sqlmap decides
    if re.search(r"sqlmap identified the following injection point", log_text, re.IGNORECASE) \
       or re.search(r"the back-end DBMS is .+ and it is injectable", log_text, re.IGNORECASE) \
       or re.search(r"parameter '[^']+' is vulnerable", log_text, re.IGNORECASE):
        injectable = True
    if re.search(r"all tested parameters do not appear to be injectable", log_text, re.IGNORECASE) \
       or re.search(r"does not seem to be injectable", log_text, re.IGNORECASE):
        injectable = False
    verdict = None
    for pat in (
        r"sqlmap identified the following injection point.*",
        r"parameter '[^']+' is vulnerable.*",
        r"all tested parameters do not appear to be injectable.*",
    ):
        mm = re.search(pat, log_text, re.IGNORECASE)
        if mm:
            verdict = mm.group(0).strip()
            break
    return {"injectable": injectable, "dbms": dbms, "verdict": verdict}


register_verdict_parser("sqlmap", _parse_verdict)


@framework_tool(
    "Launch a sqlmap scan against a target URL in the background; returns a "
    "job_id you poll with sqlmap_status. Non-interactive (--batch is forced). "
    "Use this for SQL INJECTION testing through a web parameter. If you "
    "already have valid database credentials, do NOT use this - the db_* "
    "tools (db_connect / db_exec_batch / db_schema_farm, net.services) speak "
    "the protocol directly and are faster, quieter and structured.",
    next_hints=["sqlmap_status"],
)
def run_sqlmap(target_url: str, options: str = "") -> dict[str, Any]:
    """Launch sqlmap against ``target_url`` and return immediately.

    Lane note (2026-09-22): sqlmap = injection testing (attack verb). Direct
    database access with known credentials is a different lane - use the
    db_* tools in auxiliaries/db_client.py (db_connect / db_exec_batch /
    db_schema_farm), which speak MySQL/MSSQL/PostgreSQL wire protocols with
    the credentials and need no injectable parameter.

    "sqlmap runs as a detached background subprocess writing to a per-job log
    file; this call does NOT block on the scan. Perform one status poll to
    confirm it is running, then hand off to the user. Poll again only when the
    user requests an update.

    ``--batch`` is forced (appended if not already in ``options``) so sqlmap
    never blocks on an interactive prompt, and stdin is /dev/null as a
    second defense. Pass ``--dbs``, ``--current-db``, ``--dump``, etc. to
    enumerate once a scan reports injectable.

    Args:
        target_url: The target URL to test for SQL injection. For POST params,
            pass the URL here and the body via ``options`` with ``--data=...``
            (e.g. ``"--data='user=admin&pass=x' --level=3"``).
        options: Additional sqlmap command-line options as a single string
            (e.g. ``"--data='username=test&password=x' --level=3 --risk=2"``).
            Quoted sub-phrases are preserved by shlex. ``--batch`` is injected
            automatically if absent.
    """
    # Scope gate (operator-armed from the Tool REPL; no-op when disarmed).
    # Active SQLi payload traffic — this tool must honour the gate like every
    # other traffic-sending module (2026-09-19 gap: was ungated).
    from utils.scope_gate import check_scan, ScopeGateError
    _sc_ok, _sc_reason = check_scan(target_url)
    if not _sc_ok:
        raise ScopeGateError(f"scope gate: {_sc_reason}")

    # -u takes the URL as its own argv element; never interpolate it into a
    # shell string. Policy defaults (threads, per-unit output dir) come from
    # _build_sqlmap_command; caller options come LAST so explicit flags win.
    command = _build_sqlmap_command(target_url, options)

    # launch_job(target=...) routes through the fleet scheduler: a duplicate
    # (same canonical unit already running) returns the running job's id to
    # poll; a refusal returns the structured slot/auth-adjacent envelope.
    # Neither launches a process.
    result = launch_job(
        command,
        tool_name="sqlmap",
        timeout=float(os.getenv("SQLMAP_TIMEOUT", "1800")),
        target=target_url,
        fleet_body=_extract_data_body(options),
        verdict_parser=_parse_verdict,
    )

    if result.get("status") == "duplicate":
        return result  # includes the running unit's job_id to poll
    if result.get("status") == "refused":
        return result  # slots_exhausted / host_serialized_auth, with guidance

    return {
        "job_id": result["job_id"],
        "status": "running",
        "log_file": result["log_file"],
        "target": target_url,
        "unit_key": result.get("unit_key"),
        "started": result["started"],
        "message": (
            "launch accepted; perform one status poll to confirm the job is "
            "running, then hand off to the user. Poll again only when the "
            "user requests an update."
        ),
    }


@framework_tool(
    "Poll a sqlmap scan job: returns running/done, a parsed injectable "
    "verdict, the detected DBMS, and recent log lines. Call once only when "
    "the user requests an update; never poll repeatedly until done. The DBMS "
    "name in the verdict pairs with the direct "
    "db_* tools (db_connect / db_schema_farm) once credentials are known - "
    "sqlmap itself stays the injection lane only.",
    next_hints=["sqlmap_status", "report_finding"],
)
def sqlmap_status(job_id: str) -> dict[str, Any]:
    """Poll the status of a scan launched by ``run_sqlmap``.

    Reads the job's log file, checks whether the subprocess is still alive,
    and parses sqlmap's output for a verdict. Returns ``status: "running"``
    while the scan is in progress and ``status: "done"`` once the process has
    exited (or been reaped by the wall-clock cap).

    Args:
        job_id: The ``job_id`` returned by ``run_sqlmap``.
    """
    result = poll_job(job_id)
    if result.get("status") == "unknown":
        return result
    # Fleet release: a finished job must free its scheduler slot.
    if result["status"] == "done":
        _release_unit_for_job(job_id)
    return result


# --- internals ---------------------------------------------------------------


def _release_unit_for_job(job_id: str) -> None:
    """Free the fleet unit whose bound job finished (the scheduler's
    release_for_job does the conditional, first-releaser-wins update; a
    unit already released/stale is a no-op)."""
    try:
        from utils.fleet_scheduler import get_scheduler

        get_scheduler().release_for_job(job_id)
    except Exception:
        pass  # scheduling bookkeeping must never break a status poll


def _read_log(path: str) -> str:
    try:
        with open(path, errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def _reconstruct_job(job_id: str) -> dict[str, Any] | None:  # pragma: no cover - legacy shim
    """Legacy no-op: the Phase 0 job store owns reconstruction (indexed row
    lookup replaces the /tmp sidecar scan). Kept so stale internal imports
    don't break — internal callers only, not the public surface."""
    return None


def _tail(text: str, n: int) -> list[str]:
    lines = [ln for ln in text.splitlines() if ln.strip()]
    # Strip ANSI escape sequences sqlmap emits for its terminal cursor moves.
    ansi = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
    lines = [ansi.sub("", ln).strip() for ln in lines]
    lines = [ln for ln in lines if ln]
    return lines[-n:]


# --- Annex A policy table (the adapter's contribution rule 9) ------------------


def _extract_data_body(options: str) -> str:
    """Pull the ``--data=...`` body out of the options string (feeds the
    fleet unit's canonical-key shape). Returns '' when absent.\"\"\""""
    try:
        parts = shlex.split(options or "")
    except ValueError:
        return ""
    for i, p in enumerate(parts):
        if p == "--data" and i + 1 < len(parts):
            return parts[i + 1]
        if p.startswith("--data="):
            return p[len("--data="):]
    return ""


def _classify_threads(options: str) -> str:
    """Annex A threads policy. Conservative: time-based oracles are serial
    conversations — parallel char bisection turns the delay into noise on
    the oracle — so 1 thread unless the caller explicitly overrides."""
    return "--threads=1"


def _reject_forbidden_flags(extra: list[str]) -> str | None:
    """Doctrine rule 5: bulk state wipes are FORBIDDEN in any fleet path.
    ``--purge`` targets sqlmap's SHARED global data dir — one actor's purge
    must never destroy every other actor's running sessions."""
    for flag in extra:
        if flag == "--purge" or flag.startswith("--purge="):
            return (
                "--purge is forbidden: it wipes sqlmap's shared data dir and "
                "would destroy other concurrent units' sessions. Per-unit "
                "re-testing uses --flush-session instead."
            )
    return None


def _build_sqlmap_command(
    target_url: str, options: str, *, output_dir: str | None = None
) -> list[str]:
    """Assemble the launch line (Annex A launch-line shape): forced batch,
    threads policy, per-unit output dir (session isolation == resume per
    unit), per-unit traffic.log (the finding-citable artifact). Caller
    options come LAST so explicit caller flags always win over policy
    defaults (the nmap/shaping ordering convention)."""
    extra = shlex.split(options) if options else []
    extra = _inject_batch(extra)
    forbidden = _reject_forbidden_flags(extra)
    if forbidden:
        raise ValueError(forbidden)
    policy: list[str] = []
    if not any(a.startswith("--threads") for a in extra):
        policy.append(_classify_threads(options))
    if output_dir and not any(a.startswith("--output-dir") for a in extra):
        policy.append(f"--output-dir={output_dir}")
        policy.append(f"-t={os.path.join(output_dir, 'traffic.log')}")
    return ["sqlmap", "-u", target_url, *policy, *extra]


def _aggregate_log(log_text: str, target: str, log_file: str) -> dict[str, Any]:
    """Per-unit aggregator (doctrine §4e): verdict + technique tags +
    affected params, deduped upstream by the caller (§4f results twin)."""
    parsed = _parse_verdict(log_text)
    params: list[str] = []
    for m in re.finditer(r"Parameter '([^']+)'", log_text or ""):
        if m.group(1) not in params:
            params.append(m.group(1))
    techniques: list[str] = []
    for tag, pat in (
        ("boolean", r"boolean-based blind"),
        ("error", r"error-based"),
        ("union", r"UNION query"),
        ("time", r"time-based blind"),
        ("stacked", r"stacked queries"),
    ):
        if re.search(pat, log_text or "", re.IGNORECASE):
            techniques.append(tag)
    return {
        "target": target,
        "injectable": parsed["injectable"],
        "dbms": parsed["dbms"],
        "verdict": parsed["verdict"],
        "params": params,
        "techniques": techniques,
        "log_file": log_file,
    }


# --- Fleet surface (Phase 2, doctrine §4f twins) --------------------------------


@framework_tool(
    "FAN OUT sqlmap across a list of target URLs: one scheduler unit per "
    "target (canonical shape keys dedupe, per-host slot policy applies, "
    "per-unit --output-dir isolates sessions and enables resume). Returns a "
    "fleet_id you poll with sqlmap_fleet_status; refusals/duplicates are "
    "reported per unit, not fatal. Use for MANY targets; for one target use "
    "run_sqlmap (same scheduler, same contract). Honours the scope gate per "
    "unit.",
    tags=["web.fuzz"],
    next_hints=["sqlmap_fleet_status", "sqlmap_fleet_results"],
)
def run_sqlmap_fleet(
    targets: list[str], options: str = "", override_slots: int | None = None
) -> dict[str, Any]:
    """Launch sqlmap fleet units, one per target URL, through the scheduler.

    Args:
        targets: Target URLs to test (each becomes one canonical unit).
        options: sqlmap options string applied to every unit (shared level/
            risk/tamper policy). ``--purge`` is rejected (rule 5).
        override_slots: Explicit per-host slot raise (scheduler warns; the
            absolute ceiling cannot be exceeded).

    Returns the fleet envelope: ``fleet_id`` + per-unit decisions
    (acquired/duplicate/refused). ``duplicate`` units carry the running
    job's id — poll it, never relaunch (the scheduler refused to).
    """
    if not targets:
        return {"status": "error", "error": "no targets given"}
    from utils.fleet_scheduler import canonical_unit_key, get_scheduler
    from utils.scope_gate import check_scan

    units: dict[str, dict[str, Any]] = {}
    seq_rows: list[tuple[int, str, str, str]] = []
    scope_blocks: list[str] = []
    launched = 0

    for seq, target in enumerate(targets):
        target = (target or "").strip()
        if not target:
            continue
        ok, reason = check_scan(target)
        if not ok:
            scope_blocks.append(f"{target}: {reason}")
            unit_key = canonical_unit_key("sqlmap", target)
            seq_rows.append((seq, unit_key, target, f"blocked|{reason}"))
            units[str(seq)] = {"target": target, "decision": "blocked", "reason": reason}
            continue

        command = _build_sqlmap_command(
            target, options, output_dir=_unit_output_dir(target)
        )
        result = launch_job(
            command,
            tool_name="sqlmap",
            timeout=float(os.getenv("SQLMAP_TIMEOUT", "1800")),
            target=target,
            fleet_body=_extract_data_body(options),
            override_slots=override_slots,
            verdict_parser=_parse_verdict,
        )
        decision = result.get("status", "running")
        if decision == "running":  # classic launch envelope == acquired
            decision = "acquired"
            launched += 1
        unit_key = result.get("unit_key", canonical_unit_key("sqlmap", target))
        if decision in ("duplicate", "refused"):
            detail = f"{decision}|{result.get('job_id') or result.get('reason', '')}"
            seq_rows.append((seq, unit_key, target, detail))
            # Normalize: refused/duplicate envelopes carry status+reason —
            # expose them as `decision` so the count fields and downstream
            # status polling see one shape.
            result["decision"] = decision
            units[str(seq)] = {"target": target, **result}
        else:
            seq_rows.append((seq, unit_key, target, f"acquired|job:{result['job_id']}"))
            units[str(seq)] = {
                "target": target,
                "decision": "acquired",
                "job_id": result["job_id"],
                "log_file": result["log_file"],
                "unit_key": unit_key,
            }
            if result.get("warning"):
                units[str(seq)]["warning"] = result["warning"]

    from utils.agent_identity import current_agent_id

    fleet_id = get_scheduler().create_batch("sqlmap", current_agent_id(), seq_rows)
    summary = {
        "status": "ok" if launched or units else "nothing-to-do",
        "fleet_id": fleet_id,
        "requested": len(targets),
        "acquired": launched,
        "duplicates": sum(1 for u in units.values() if u.get("decision") == "duplicate"),
        "refused": sum(1 for u in units.values() if u.get("decision") == "refused"),
        "scope_blocked": scope_blocks,
        "units": units,
        "message": (
            f"{launched} unit(s) launched; poll sqlmap_fleet_status('{fleet_id}') "
            "once to confirm, then hand off. Do not poll in a loop."
        ),
    }
    return summary


def _unit_output_dir(target: str) -> str:
    """Per-unit isolated state dir (rule 5): session SQLite + traffic.log
    live under run/sqlmap_fleet/<key>/ so crash-restart resume is
    trivially per-unit and bulk wipes never enter the lane."""
    from utils.fleet_scheduler import canonical_unit_key
    from constants import resolve_workspace_root

    key = canonical_unit_key("sqlmap", target)
    base = resolve_workspace_root() / "run" / "sqlmap_fleet" / key.replace(":", "_")
    base.mkdir(parents=True, exist_ok=True)
    return str(base)


@framework_tool(
    "Poll a sqlmap fleet: per-unit running/done/verdict summary across every "
    "unit in the batch. Call once to confirm launch, then only when the user "
    "asks for an update. When units are done, follow with sqlmap_fleet_results "
    "for the deduped finding-ready aggregate.",
    tags=["web.fuzz"],
    next_hints=["sqlmap_fleet_results", "sqlmap_fleet_stop"],
)
def sqlmap_fleet_status(fleet_id: str) -> dict[str, Any]:
    """Status of every unit in one fleet batch.

    Args:
        fleet_id: The ``fleet_id`` returned by ``run_sqlmap_fleet``.
    """
    from utils.fleet_scheduler import get_scheduler

    batch = get_scheduler().batch_status(fleet_id)
    if batch.get("status") == "unknown":
        return batch
    out: dict[str, Any] = {**batch, "unit_status": {}}
    done = 0
    running = 0
    for u in batch["units"]:
        if u["decision"] != "acquired" or not u["job_id"]:
            out["unit_status"][str(u["seq"])] = {"decision": u["decision"]}
            continue
        poll = poll_job(u["job_id"])
        st = poll.get("status", "unknown")
        out["unit_status"][str(u["seq"])] = {
            "target": u["target"],
            "job_id": u["job_id"],
            "status": st,
            "injectable": poll.get("injectable"),
            "dbms": poll.get("dbms"),
            "timed_out": poll.get("timed_out"),
        }
        if st == "done":
            done += 1
            _release_unit_for_job(u["job_id"])
        elif st == "running":
            running += 1
    out["running"] = running
    out["done"] = done
    if running == 0 and batch["status"] == "running":
        from utils.fleet_scheduler import get_scheduler as _gs

        _gs().mark_batch_complete(fleet_id)
        out["status"] = "complete"
    out["message"] = (
        f"{done} done, {running} running. "
        + (
            "All units settled — call sqlmap_fleet_results for the aggregate."
            if running == 0
            else "Poll again only when the user requests an update."
        )
    )
    return out


@framework_tool(
    "Aggregate a finished sqlmap fleet into finding-ready rows: per unique "
    "(host, param, technique) triple with the excerpt + the per-unit "
    "traffic.log path as citable evidence (rule 8: findings cite artifacts). "
    "Deduplicates across units; feed each unique triple to report_finding.",
    tags=["web.fuzz", "infra"],
    next_hints=["report_finding"],
)
def sqlmap_fleet_results(
    fleet_id: str, dedupe: str = "param", excerpts: bool = True
) -> dict[str, Any]:
    """Deduped results across a fleet batch.

    Args:
        fleet_id: The ``fleet_id`` from ``run_sqlmap_fleet``.
        dedupe: ``param`` (host+param+technique) | ``host`` (host only).
        excerpts: Include the corroborating log line per row.
    """
    from utils.fleet_scheduler import get_scheduler

    batch = get_scheduler().batch_status(fleet_id)
    if batch.get("status") == "unknown":
        return batch
    seen: dict[tuple, dict[str, Any]] = {}
    scanned = 0
    for u in batch["units"]:
        if u["decision"] != "acquired" or not u["job_id"]:
            continue
        poll = poll_job(u["job_id"])
        log_file = poll.get("log_file", "")
        if not log_file:
            continue
        try:
            with open(log_file, errors="replace") as fh:
                log_text = fh.read()
        except OSError:
            continue
        scanned += 1
        agg = _aggregate_log(log_text, u["target"], log_file)
        if not agg["injectable"]:
            continue
        technique_key = "+".join(agg["techniques"]) or "unknown"
        if dedupe == "host":
            key = (agg["target"].split("/")[2] if "//" in agg["target"] else agg["target"],)
        else:
            param = agg["params"][0] if agg["params"] else "*"
            key = (
                agg["target"].split("/")[2] if "//" in agg["target"] else agg["target"],
                param,
                technique_key,
            )
        if key not in seen:
            row = {
                "host": key[0],
                "param": None if dedupe == "host" else (agg["params"][0] if agg["params"] else "*"),
                "techniques": agg["techniques"],
                "dbms": agg["dbms"],
                "targets": [agg["target"]],
                "traffic_log": os.path.join(os.path.dirname(agg["log_file"]), "traffic.log"),
                "unit_log": agg["log_file"],
            }
            if excerpts and agg["verdict"]:
                row["excerpt"] = agg["verdict"][:300]
            seen[key] = row
        else:
            tgt = agg["target"]
            if tgt not in seen[key]["targets"]:
                seen[key]["targets"].append(tgt)
    rows = sorted(seen.values(), key=lambda r: (r["host"], r.get("param") or ""))
    return {
        "status": "ok",
        "fleet_id": fleet_id,
        "dedupe": dedupe,
        "units_scanned": scanned,
        "unique_findings": len(rows),
        "rows": rows,
        "message": (
            f"{len(rows)} unique finding row(s) from {scanned} unit log(s). "
            "report_finding per row, citing traffic_log."
        ),
    }


@framework_tool(
    "Stop one or every running unit of a sqlmap fleet batch (same-agent "
    "ownership; force=True is the operator-level cross-agent override). Stops "
    "the background job via the job store and releases its scheduler slot.",
    tags=["web.fuzz", "infra"],
)
def sqlmap_fleet_stop(fleet_id: str, force: bool = False) -> dict[str, Any]:
    """Stop a fleet batch's running units.

    Args:
        fleet_id: The ``fleet_id`` from ``run_sqlmap_fleet``.
        force: Operator-level crossing of agent ownership.
    """
    from utils.fleet_scheduler import get_scheduler

    batch = get_scheduler().batch_status(fleet_id)
    if batch.get("status") == "unknown":
        return batch
    stopped, skipped = [], []
    for u in batch["units"]:
        if u["decision"] != "acquired" or not u["job_id"]:
            continue
        poll = poll_job(u["job_id"])
        if poll.get("status") == "running":
            ok = terminate_job(u["job_id"], force=force)
            (stopped if ok else skipped).append(u["job_id"])
            if ok:
                _release_unit_for_job(u["job_id"])
        else:
            _release_unit_for_job(u["job_id"])
    return {
        "status": "ok",
        "fleet_id": fleet_id,
        "stopped": stopped,
        "skipped": skipped,
        "message": (
            f"{len(stopped)} unit(s) stopped. "
            + ("" if not skipped else f"{len(skipped)} refused (ownership — pass force=True).")
        ),
    }
