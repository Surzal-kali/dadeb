"""Operator-only CLI commands: the scope gate + the engagement cobweb.

These are the ONLY control surfaces for arming the packet-scope gate and for
arming/purging the engagement cobweb key; both are deliberately NOT exposed
as ``@framework_tool`` entries, so no model lane can ever toggle the
gate, bless IPs, tag rows with a new engagement key, or erase the audit
trail (same authority model the DB grants enforce for the PG lane).

Shared across three entry points — the interactive ``repl>`` loop, the
one-shot CLI (``python tool_repl.py scope on <handle>``), and the kernel
namespace's read-only convenience wrappers (``scope_status`` /
``scope_search`` — arming stays out of the kernel namespace entirely).
"""

import json
import shlex

# ``scope`` subcommand schema — mirrors the flags _scope_command() parses in
# ``scope search`` / ``scope on``. Values double as the tooltip
# (display_meta) in the completer's dropdown (replkit.completer).
SCOPE_SUBCOMMANDS = {
    "on": "arm the gate: on <handle> [--platform P] [--no-strict] [--ip-boundary] [--refresh]",
    "off": "disarm — lab mode, tools unrestricted",
    "status": "armed state, asset counts, manifest_age_s",
    "add-ip": "add-ip <ip> [<hostname>] — bless a resolved in-scope IP",
    "add-host": "add-host <hostname> <ip> — bless a vhost hostname (IP must already be blessed)",
    "rm-host": "rm-host <hostname> — remove a blessed hostname",
    "rm-ip": "rm-ip <ip> — remove a blessed IP",
    "list-ips": "show the operator allowlist",
    "disable": "disable <prefix> [<prefix>...] [--force] — block tool_ids for the armed scope",
    "enable": "enable <prefix> [<prefix>...] — re-enable a disabled tool_id prefix",
    "disabled": "show the disabled-tools list for the armed scope",
    "search": "query boards: <kw> [--platform P] [--assets] [--handle H] [--refresh] [--limit N] [--json]",
}
# Flags per subcommand (empty dict = no flag completion for it).
SCOPE_SEARCH_FLAGS = {
    "--platform": "all|h1|intigriti|bugcrowd (default all)",
    "--assets": "load manifests: asset + bounty summary (top 3)",
    "--handle": "exact handle — required for the bugcrowd probe lane",
    "--refresh": "force fresh manifest fetch (with --assets)",
    "--limit": "max matches per lane (default 10)",
    "--json": "print the raw result dict",
}
SCOPE_ON_FLAGS = {
    "--platform": "h1|bugcrowd|intigriti|<custom> (default h1)",
    "--no-strict": "unconfirmed targets warn instead of refuse",
    "--ip-boundary": "hostname/manifest assets must resolve into the blessed IP set (lab drift guard)",
    "--refresh": "force a fresh board fetch (board lanes only; lab manifests are files)",
}
SCOPE_DISABLE_FLAGS = {
    "--force": "allow disabling terminal-lane families (findings/memory)",
}


def _json_or_none(res) -> str:
    return json.dumps(res, indent=2, default=str)


def _scope_command(rest: str):
    """Handle the ``scope`` REPL command — operator-only packet-scope gate.
    This is the ONLY control surface for the packet-scope gate; it is
    deliberately not exposed as an ``@framework_tool``, so no model lane
    can arm/disarm or bless IPs.  When armed, ``send_packet``
    refuses sends to destinations not confirmed in-scope (see
    :mod:`utils.scope_gate`).
    """
    from utils import scope_gate

    try:
        parts = shlex.split(rest)
    except ValueError as e:
        print(f"  Argument parse error: {e}")
        return
    if not parts:
        print("  Packet-scope gate (operator-only — not exposed to the agent).")
        print("  When armed, send_packet refuses packets to destinations not")
        print("  confirmed in-scope for the loaded program. Disarmed = lab mode.")
        print("  Commands:")
        print("    scope on <handle> [--platform h1|bugcrowd|intigriti] [--no-strict] [--ip-boundary]")
        print("    scope off")
        print("    scope status")
        print("    scope search <kw> [--assets]  (query the boards: matching programs + bounty-relevant stats)")
        print("    scope add-ip <ip> [<hostname>]   (bless a resolved in-scope IP)")
        print("    scope add-host <hostname> <ip>   (bless a vhost hostname; IP must already be blessed)")
        print("    scope rm-host <hostname>")
        print("    scope rm-ip <ip>")
        print("    scope list-ips")
        print("    scope disable <prefix> [<prefix>...] [--force]  (block tool_ids for the armed scope)")
        print("    scope enable <prefix> [<prefix>...]            (re-enable a disabled tool_id prefix)")
        print("    scope disabled                                  (show the disabled-tools list)")
        st = scope_gate.status()
        if st.get("armed"):
            print(f"  Current: ARMED — {st.get('handle')}/{st.get('platform')} "
                  f"strict={st.get('strict')} allowlist={st.get('allowlist_size',0)}")
        else:
            print("  Current: disarmed (lab mode — sends unrestricted)")
        return

    sub = parts[0].lower()

    if sub == "on":
        if len(parts) < 2:
            print("  Usage: scope on <handle> [--platform h1|bugcrowd|intigriti|<custom>] [--no-strict] [--ip-boundary] [--refresh]")
            return
        handle = parts[1]
        platform = "h1"
        strict = True
        ip_boundary = False
        refresh = False
        i = 2
        while i < len(parts):
            tok = parts[i]
            if tok == "--no-strict":
                strict = False
                i += 1
            elif tok == "--ip-boundary":
                ip_boundary = True
                i += 1
            elif tok == "--refresh":
                refresh = True
                i += 1
            elif tok.startswith("--refresh="):
                refresh = tok.split("=", 1)[1].strip().lower() in ("1", "true", "yes", "on")
                i += 1
            elif tok == "--platform" and i + 1 < len(parts) and not parts[i + 1].startswith("--"):
                platform = parts[i + 1]
                i += 2
            elif tok.startswith("--platform="):
                platform = tok.split("=", 1)[1]
                i += 1
            else:
                print(f"  Ignoring unknown flag: {tok}")
                i += 1
        res = scope_gate.arm(handle, platform, strict, ip_boundary=ip_boundary, refresh=refresh)

    elif sub == "off":
        res = scope_gate.disarm()

    elif sub == "status":
        res = scope_gate.status()

    elif sub == "search":
        # Board-wide program search (discovery): keyword over the H1/Intigriti
        # program indexes, exact-handle probe for Bugcrowd.  NOT a search of
        # the armed manifest — that's what check_scope is for.
        query = ""
        handle = ""
        platform = "all"
        limit = 10
        with_assets = False
        refresh = False
        as_json = False
        # Positional-tolerant parse: the keyword may come before or after the
        # flags (Tab-complete inserts --flags mid-line), extra positional
        # tokens join the keyword (multi-word program names).
        tokens = parts[1:]
        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if tok == "--assets":
                with_assets = True
            elif tok == "--refresh":
                refresh = True
            elif tok == "--json":
                as_json = True
            elif tok.startswith("--limit="):
                limit = int(tok.split("=", 1)[1])
            elif tok == "--limit" and i + 1 < len(tokens):
                i += 1
                limit = int(tokens[i])
            elif tok.startswith("--handle="):
                handle = tok.split("=", 1)[1]
            elif tok == "--handle" and i + 1 < len(tokens):
                i += 1
                handle = tokens[i]
            elif tok.startswith("--platform="):
                platform = tok.split("=", 1)[1]
            elif tok == "--platform" and i + 1 < len(tokens) and not tokens[i + 1].startswith("--"):
                i += 1
                platform = tokens[i]
            elif tok.startswith("--"):
                print(f"  Ignoring unknown flag: {tok}")
            elif not query:
                query = tok
            else:
                query = f"{query} {tok}"  # multi-word keyword
            i += 1
        if not query and not handle:
            print("  Usage: scope search <query> [--platform all|h1|intigriti|bugcrowd] [--assets]")
            print("                            [--handle <h>] [--refresh] [--limit N] [--json]")
            return
        from auxiliaries import program_scope
        res = program_scope.search_programs(query=query, platform=platform, limit=limit,
                                            with_assets=with_assets, handle=handle,
                                            refresh=refresh)
        if as_json:
            print("  " + _json_or_none(res))
            return
        if not res.get("rows"):
            err = res.get("error") or res.get("lane_errors") or "no match"
            print("  scope search: " + (err if isinstance(err, str) else json.dumps(err)))
            return
        for r in res["rows"]:
            bounty = r.get("bounty")
            btxt = (("bounties=yes" if bounty else "bounties=no")
                    if isinstance(bounty, bool) else str(bounty or ""))
            state = f" state={r['state']}" if r.get("state") else ""
            name = r.get("name") or "?"
            print(f"  {r['platform']:<9} | {str(r.get('handle') or '?'):<24} | {name} | {btxt}{state}")
        for lane, err in (res.get("lane_errors") or {}).items():
            print(f"  [{lane}] {err}")
        if res.get("lane_truncated"):
            print("  (index truncated at the page cap — refine the query)")
        for key, a in (res.get("assets") or {}).items():
            if not isinstance(a, dict) or a.get("error"):
                print(f"  == {key}: {a.get('error') if isinstance(a, dict) else a}")
                continue
            counts = a.get("counts") or {}
            bs = a.get("bounty_stats") or {}
            print(f"  == {key} — {a.get('program_name') or ''}: "
                  f"{counts.get('in_scope', 0)} in-scope, "
                  f"{counts.get('out_of_scope_assets', 0)} OOS, "
                  f"bounty-eligible {bs.get('bounty_eligible_in_scope', 0)} / "
                  f"no-bounty {bs.get('no_bounty_in_scope', 0)}")
            for row in a.get("assets") or []:
                flag = "bounty" if row.get("eligible_for_bounty") else "no-bounty"
                print(f"     {str(row.get('asset_type') or '?'):<9} "
                      f"{str(row.get('asset_identifier') or ''):<44} {flag:<9} "
                      f"{row.get('detail') or ''}")
            if a.get("assets_truncated"):
                print("     ... (asset rows truncated)")
        return

    elif sub in ("add-ip", "add_ip", "add"):
        if len(parts) < 2:
            print("  Usage: scope add-ip <ip> [<hostname>]")
            return
        ip = parts[1]
        hostname = parts[2] if len(parts) > 2 else ""
        res = scope_gate.add_ip(ip, hostname)

    elif sub in ("add-host", "add_host"):
        if len(parts) < 3:
            print("  Usage: scope add-host <hostname> <ip>")
            return
        res = scope_gate.add_host(parts[1], parts[2])

    elif sub in ("rm-host", "rm_host"):
        if len(parts) < 2:
            print("  Usage: scope rm-host <hostname>")
            return
        res = scope_gate.remove_host(parts[1])

    elif sub in ("rm-ip", "rm_ip", "remove", "rm"):
        if len(parts) < 2:
            print("  Usage: scope rm-ip <ip>")
            return
        res = scope_gate.remove_ip(parts[1])

    elif sub in ("list-ips", "list_ips", "list", "ips"):
        res = scope_gate.list_ips()

    elif sub == "disable":
        # Operator-only: block tool_id prefixes for the armed scope.
        # Requires the gate to be armed (engagement-posture control).
        if len(parts) < 2:
            print("  Usage: scope disable <prefix> [<prefix>...] [--force]")
            print("  Trailing-dot prefix (payloads.hash_crack.) kills a family;")
            print("  bare stem (payloads.hash_crack.run_john) is exact tool_id only.")
            print("  Terminal-lane families (findings/memory) need --force.")
            return
        force = False
        prefixes = []
        for tok in parts[1:]:
            if tok == "--force":
                force = True
            else:
                prefixes.append(tok)
        if not prefixes:
            print("  Usage: scope disable <prefix> [<prefix>...] [--force]")
            return
        res = scope_gate.disable_tools(prefixes, force=force)

    elif sub == "enable":
        if len(parts) < 2:
            print("  Usage: scope enable <prefix> [<prefix>...]")
            return
        res = scope_gate.enable_tools(parts[1:])

    elif sub in ("disabled", "disabled-tools", "disabled_tools"):
        res = scope_gate.list_disabled()

    else:
        print(f"  Unknown scope subcommand: {sub!r}. Try 'scope' for help.")
        return

    print("  " + _json_or_none(res))


def _local_evidence_purge(slug: str) -> int:
    """Best-effort purge of the phase-1 SQLite evidence mirror (the PG lane
    is authoritative when up; this keeps both honest when it isn't)."""
    try:
        from utils.evidence import get_store
        return get_store().purge_engagement(slug)
    except Exception as e:
        print(f"  (sqlite mirror purge skipped: {e})")
        return 0


def _engagement_command(rest: str):
    """Handle the ``engagement`` REPL command — operator-only engagement
    cobweb key (arm/disarm/status/purge).

    This is the ONLY control surface for engagement arming and the ONLY
    purge path; deliberately not exposed as an ``@framework_tool``, so no
    model lane can tag rows with a new engagement key or erase the
    audit trail (same authority model as the scope gate). Arming writes
    ``engagement/.armed_engagement.json`` (mtime-checked every dispatch);
    purge runs under the operator DB role against BOTH lanes (Postgres
    engagement.purge() + the SQLite evidence mirror) and requires the
    engagement to be closed — export findings (render_findings) first.
    """
    from utils import engagement as eng

    try:
        parts = shlex.split(rest)
    except ValueError as e:
        print(f"  Argument parse error: {e}")
        return
    if not parts:
        print("  Engagement cobweb (operator-only — not exposed to the agent).")
        print("  One slug ties journal + evidence rows across every lane so a")
        print("  purge erases an engagement in one transaction, while live")
        print("  credential material is bounded by the 24h floor instead of")
        print("  mid-engage scrubbing.")
        print("  Commands:")
        print("    engagement on <slug> [<roe_note>]   (arm; registers in the DB when up)")
        print("    engagement off                      (disarm; rows stay)")
        print("    engagement status")
        print("    engagement purge <slug>             (close + erase journal/evidence; render_findings FIRST)")
        st = eng.db_status()
        armed = st.get("armed_engagement")
        if armed:
            print(f"  Current: ARMED — {armed}   db: {'connected as ' + st['role'] if st.get('connected') else 'UNAVAILABLE (sqlite mirror only)'}")
        else:
            print("  Current: disarmed (dispatches journal with NULL engagement)")
        return

    sub = parts[0].lower()

    if sub == "on":
        if len(parts) < 2:
            print("  Usage: engagement on <slug> [<roe_note>]")
            return
        slug = parts[1]
        note = " ".join(parts[2:])
        state = eng.arm(slug, note)
        st = eng.db_status()
        db_note = (
            f"DB connected as {st.get('role')}"
            if st.get("connected")
            else "DB unavailable — armed locally only (journal rows will carry the slug once the DB is up)"
        )
        print(f"  Engagement armed: {state['slug']}" + (f" — roe: {note}" if note else ""))
        print(f"  {db_note}")

    elif sub == "off":
        eng.disarm()
        print("  Engagement disarmed (existing rows keep their slug).")

    elif sub == "status":
        st = eng.db_status()
        print(f"  armed:  {st.get('armed_engagement') or '(disarmed)'}")
        print(f"  db:     {'connected as ' + st.get('role', '?') if st.get('connected') else 'unavailable'}")
        if st.get("server"):
            print(f"  server: {st.get('server')}")

    elif sub == "purge":
        if len(parts) < 2:
            print("  Usage: engagement purge <slug>")
            print("  Render findings first: report_finding chains -> render_findings;")
            print("  a purge erases journal + evidence for the slug and cannot be undone.")
            return
        slug = parts[1]
        confirm = input(
            f"  Purge ALL journal + evidence rows for '{slug}'? Type the slug to confirm: "
        ).strip()
        if confirm != slug:
            print("  Aborted (slug did not match).")
            return
        try:
            rows = eng.close_and_purge(slug)
        except RuntimeError as e:
            print(f"  Purge refused: {e}")
            return
        local = _local_evidence_purge(slug)
        print(f"  Purged (Postgres): " + ", ".join(f"{s}={n}" for s, n in rows))
        print(f"  Purged (sqlite evidence mirror): {local} entries")

    else:
        print(f"  Unknown engagement subcommand: {sub}")

# ─── budget: ration-engine operator levers ────────────────────────────────────

_BUDGET_DRAIN_DEFAULT = 8  # --batch default (BUDGET_DRAIN_BATCH env is the engine-side knob)


def _budget_flag_args(tokens: list[str], manifest) -> tuple[dict, int]:
    """Split ``--priority N`` out of the tool-arg tokens; type-coerce the
    rest through the tool's own manifest schema (same path as ``run``)."""
    from replkit.core import parse_flag_args

    priority = 0
    rest = list(tokens)
    if "--priority" in rest:
        i = rest.index("--priority")
        if i + 1 < len(rest):
            try:
                priority = int(rest[i + 1])
            except ValueError:
                print(f"  --priority {rest[i + 1]!r} is not an int — ignored")
            del rest[i:i + 2]
    return parse_flag_args(rest, manifest=manifest), priority


def _budget_target(arguments: dict, tool_id: str) -> str:
    from utils.ration_store import find_target
    return find_target(arguments) or tool_id


def _budget_engagement() -> str | None:
    try:
        from utils.engagement import current_slug
        return current_slug()
    except Exception:
        return None


def _budget_drain_dispatcher(manifests):
    """Drain decision mapping: envelope carries a job_id → bind
    ({"job_id": ...}); anything else ran to completion inline — report
    {"finished": True} so operator_tick consumes the item as done (no
    double-execution). Raises propagate; a raise keeps the item queued.

    Ration-aware (§7 Phase D): a drain dispatch is re-admission-checked by
    the same chokepoint every lane uses — a ``budget_deferred`` envelope
    means still short (item stays queued, BudgetStillShort) and a
    ``budget_refused`` envelope means never-fit/fail-closed (item cancels,
    BudgetRefused). An envelope that re-deferred NEVER maps to finished."""
    from replkit.core import run_tool
    from utils.ration import BudgetRefused, BudgetStillShort

    async def _dispatch(item: dict) -> dict:
        args = item.get("arguments_json")
        arguments = json.loads(args) if isinstance(args, str) else (args or {})
        res = await run_tool(item["tool"], arguments, manifests,
                             session_id="ration-drain")
        if isinstance(res, dict) and res.get("status") == "budget_deferred":
            raise BudgetStillShort(queue_id=res.get("queue_id"))
        if isinstance(res, dict) and res.get("status") == "budget_refused":
            raise BudgetRefused(reason=res.get("reason") or "never fit")
        inner = res.get("result") if isinstance(res, dict) else None
        if isinstance(inner, dict):
            if inner.get("status") == "budget_deferred":
                raise BudgetStillShort(queue_id=inner.get("queue_id"))
            if inner.get("status") == "budget_refused":
                raise BudgetRefused(reason=inner.get("reason") or "never fit")
            job = inner.get("job_id")
            if job:
                return {"job_id": job}
        if isinstance(res, dict) and res.get("job_id"):
            return {"job_id": res["job_id"]}
        return {"finished": True}

    return _dispatch


async def _budget_command(rest: str):
    """Handle the ``budget`` REPL command — operator levers for the ration
    engine (status / queue / defer / drain / set-phase / purge /
    constitution).  Read-only surfaces are ALSO exposed to the model as the
    ``budget_status`` / ``budget_queue_status`` framework tools; deferring,
    draining, and phase flips stay operator-only (same authority model as
    scope/engagement).  Traffic budgets live in SQLite, independent of the
    Postgres lane."""
    from utils.ration import (constitution, dims_for_target, get_engine,
                              get_ration_store, resolve_declaration)
    from utils.agent_identity import REPL_AGENT_ID

    try:
        parts = shlex.split(rest)
    except ValueError as e:
        print(f"  Argument parse error: {e}")
        return
    if not parts:
        print("  Ration engine (operator levers; the model sees read-only tools).")
        print("  Traffic-budget ledger in SQLite — independent of Postgres, fed by")
        print("  the scope gate so the system stays standalone when PG is down.")
        print("  Commands:")
        print("    budget status")
        print("    budget queue [state] [tool_substr]")
        print("    budget defer <tool_id> [--flag value ...] [--json '{...}'] [--priority N]")
        print("    budget drain [--batch N]")
        print("    budget set-phase <normal|hold> [--engagement S] [--host IP] [--range R] [--exit E] [--principal P]")
        print("    budget reserve [list]")
        print("    budget reserve mint <PARTITION> --requests N [--packets N] [--auth N] [--bytes N]")
        print("                 [--tag T] [--ttl-h H] [--entry P] [--exit E] [--range R] [--host H] [--principal P]")
        print("                 [--any-engagement]")
        print("    budget reserve release <token_id>   (frozen token → free-form usable)")
        print("    budget reserve freeze <token_id>    (pull back the release tag)")
        print("    budget purge <slug>")
        print("    budget constitution")
        return

    sub = parts[0].lower()
    store = get_ration_store()
    engine = get_engine()

    if sub == "status":
        print("  " + _json_or_none(engine.status()))

    elif sub == "queue":
        state: str | None = None
        tool_filter: str | None = None
        for p in parts[1:]:
            if not p.startswith("-"):
                if state is None:
                    state = p
                else:
                    tool_filter = p
        items = store.list_items(state=state, tool=tool_filter)
        print(f"  {len(items)} item(s)"
              + (f" [state={state}]" if state else "")
              + (f" [tool~{tool_filter}]" if tool_filter else ""))
        for it in items[:50]:
            print(json.dumps(dict(it), default=str))

    elif sub == "defer":
        if len(parts) < 2:
            print("  Usage: budget defer <tool_id> [--flag value ...] "
                  "[--json '{...}'] [--priority N]")
            return
        tool_id = parts[1]
        from replkit.core import discover_tools, find_manifest
        manifests = discover_tools()
        manifest = find_manifest(tool_id, manifests)
        if manifest is None:
            print(f"  Unknown tool_id: {tool_id}")
            return
        arguments, priority = _budget_flag_args(parts[2:], manifest)
        target = _budget_target(arguments, manifest.module_id)
        decl, decl_name, basis = resolve_declaration(
            manifest.module_id, target, arguments)
        dims = dims_for_target(target)
        qid = store.enqueue_item(
            tool=manifest.module_id, arguments=arguments, decl=decl,
            dims=dims, reason="operator_defer", agent_id=REPL_AGENT_ID,
            engagement=_budget_engagement(), priority=priority)
        print(f"  Deferred {manifest.module_id} -> {qid}")
        print(f"  Declared ({decl_name or basis}): {json.dumps(decl, default=str)}")
        print("  dims: " + json.dumps(
            {k: v for k, v in dims.items() if k != "exit_ids"}, default=str))
        print("  Drain later with: budget drain")

    elif sub == "drain":
        batch = _BUDGET_DRAIN_DEFAULT
        tail = parts[1:]
        if "--batch" in tail:
            i = tail.index("--batch")
            if i + 1 < len(tail):
                try:
                    batch = int(tail[i + 1])
                except ValueError:
                    print(f"  --batch {tail[i + 1]!r} is not an int — using {batch}")
        from replkit.core import discover_tools
        results = await engine.operator_tick(
            dispatcher=_budget_drain_dispatcher(discover_tools()), batch=batch)
        if not results:
            print("  Queue drained (or nothing due).")
        for r in results:
            print("  " + json.dumps(r, default=str))

    elif sub == "set-phase":
        if len(parts) < 2 or parts[1] not in ("normal", "hold"):
            print("  Usage: budget set-phase <normal|hold> [--engagement S] "
                  "[--host IP] [--range R] [--exit E] [--principal P]")
            return
        mode = parts[1]
        sel_names = {"--engagement": "engagement", "--host": "host_axis",
                     "--range": "range_axis", "--exit": "exit_id",
                     "--principal": "principal"}
        sel: dict = {}
        tail = parts[2:]
        i = 0
        while i < len(tail):
            if tail[i] in sel_names and i + 1 < len(tail):
                sel[sel_names[tail[i]]] = tail[i + 1]
                i += 2
            else:
                print(f"  Unparsed token {tail[i]!r} — expected --selector value pairs")
                return
        if not sel:
            print("  Refused: set-phase needs at least one selector "
                  "(--engagement/--host/--range/--exit/--principal) — blanket "
                  "flips would wedge every lane at once.")
            return
        n = store.set_phase(mode=mode, **sel)
        print(f"  set-phase {mode}: {n} node row(s) updated")
        for k, v in sel.items():
            print(f"    {k}={v}")

    elif sub == "reserve":
        if len(parts) < 2 or parts[1] in ("list", "ls"):
            engagement = None if (len(parts) > 2 and parts[2] == "--all") \
                else _budget_engagement()
            rows = store.list_reserves(engagement=engagement)
            print(f"  {len(rows)} reserve token(s)"
                  + ("" if engagement is None else f" [{engagement}]")
                  + " (frozen tokens only spend once the operator releases them)")
            for r in rows:
                state = ("released" if r.get("released") is not None
                         else "frozen")
                print(f"  {r['token_id']} [{r['partition']}] {state} "
                      f"tag={r.get('tag') or '-'} "
                      f"remaining={_json_or_none(r.pop('remaining', None))} "
                      f"dims={_json_or_none(r['dims'])} "
                      f"ttl={r.get('ttl_expiry') or 'never'} "
                      f"note={r.get('note') or '-'}")
            return
        if parts[1] in ("release", "freeze"):
            if len(parts) < 3:
                print(f"  Usage: budget reserve {parts[1]} <token_id>")
                return
            token, want_release = parts[2], parts[1] == "release"
            out = store.release_reserve(token, release=want_release)
            print(f"  {token}: "
                  + ("released — free-form consumption now applies"
                     if want_release else
                     "frozen — consumption suspended") if out
                  else f"  Unknown token: {token}")
            return
        if parts[1] == "mint":
            if len(parts) < 3:
                print("  Usage: budget reserve mint <PARTITION> --requests N ...")
                return
            partition = parts[2]
            tail = parts[3:]
            names = {"--requests": "requests", "--packets": "packets",
                     "--bytes": "bytes"}
            dims = {"entry_partition": None, "exit_id": None,
                    "range_axis": None, "host_axis": None,
                    "principal": None}
            max_vector: dict = {}
            tag = note = None
            ttl_h = None
            any_engagement = False
            sel = {"--entry": "entry_partition", "--exit": "exit_id",
                   "--range": "range_axis", "--host": "host_axis",
                   "--principal": "principal"}
            i = 0
            while i < len(tail):
                t = tail[i]
                if t in names and i + 1 < len(tail):
                    max_vector[names[t]] = float(tail[i + 1])
                    i += 2
                elif t == "--auth" and i + 1 < len(tail):
                    max_vector["auth_events"] = float(tail[i + 1])
                    i += 2
                elif t == "--tag" and i + 1 < len(tail):
                    tag = tail[i + 1]
                    i += 2
                elif t == "--note" and i + 1 < len(tail):
                    note = tail[i + 1]
                    i += 2
                elif t == "--ttl-h" and i + 1 < len(tail):
                    ttl_h = float(tail[i + 1])
                    i += 2
                elif t in sel and i + 1 < len(tail):
                    dims[sel[t]] = tail[i + 1]
                    i += 2
                elif t == "--any-engagement":
                    any_engagement = True
                    i += 1
                else:
                    print(f"  Unparsed token {t!r} — see 'budget'")
                    return
            max_vector.setdefault("auth_events", 0.0)
            try:
                out = store.mint_reserve(
                    partition=partition, dims=dims, max_vector=max_vector,
                    tag=tag, ttl_hours=ttl_h, note=note,
                    engagement=None if any_engagement else _budget_engagement())
            except ValueError as e:
                print(f"  Refused: {e}")
                return
            print(f"  Minted {out['token_id']} [{out['partition']}] — FROZEN "
                  "(list shows it; 'budget reserve release <id>' arms "
                  "free-form consumption for matching dispatches)")
            print(f"  max_vector: {_json_or_none(out['max_vector'])}")
            print("  dims (None = wildcard): "
                  + _json_or_none(dims))
        else:
            print(f"  Unknown reserve subcommand: {parts[1]!r}. "
                  "Try 'budget' for help.")
        return

    elif sub == "purge":
        if len(parts) < 2:
            print("  Usage: budget purge <slug>")
            return
        slug = parts[1]
        confirm = input(
            f"  Purge ALL budget rows (nodes/emissions/queue/principals/"
            f"reserves) for '{slug}'? Type the slug to confirm: ").strip()
        if confirm != slug:
            print("  Aborted (slug did not match).")
            return
        counts = store.purge_engagement(slug)
        print("  Purged budget rows for " + _json_or_none(
            {slug: counts}).replace("\n", " "))

    elif sub == "constitution":
        from dataclasses import asdict as _asdict
        import os as _os
        _raw = _os.getenv("BUDGET_CONSTITUTION", "").strip()
        _rawf = _os.getenv("BUDGET_CONSTITUTION_FILE", "").strip()
        try:
            const = constitution()
        except Exception as e:
            print("  Constitution INVALID — the engine is fail-closed "
                  "until the authored config is fixed.")
            print(f"    {e}")
            return
        _prov = ("file " + _rawf) if _rawf else (
            "inline JSON (BUDGET_CONSTITUTION)" if _raw
            else "built-in defaults (code)")
        print("  Source: " + _prov)
        print("  " + _json_or_none(_asdict(const)))

    else:
        print(f"  Unknown budget subcommand: {sub!r}. Try 'budget' for help.")
