"""Operator-only CLI commands: the scope gate + the engagement cobweb.

These are the ONLY control surfaces for arming the packet-scope gate and for
arming/purging the engagement cobweb key; both are deliberately NOT exposed
as ``@framework_tool`` entries, so the secretary agent can never toggle the
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
    "on": "arm the gate: on <handle> [--platform P] [--no-strict]",
    "off": "disarm — lab mode, tools unrestricted",
    "status": "armed state, asset counts, manifest_age_s",
    "add-ip": "add-ip <ip> [<hostname>] — bless a resolved in-scope IP",
    "add-host": "add-host <hostname> <ip> — bless a vhost hostname (IP must already be blessed)",
    "rm-host": "rm-host <hostname> — remove a blessed hostname",
    "rm-ip": "rm-ip <ip> — remove a blessed IP",
    "list-ips": "show the operator allowlist",
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
    "--platform": "h1|bugcrowd|intigriti (default h1)",
    "--no-strict": "unconfirmed targets warn instead of refuse",
    "--ip-boundary": "hostname/manifest assets must resolve into the blessed IP set (lab drift guard)",
}


def _json_or_none(res) -> str:
    return json.dumps(res, indent=2, default=str)


def _scope_command(rest: str):
    """Handle the ``scope`` REPL command — operator-only packet-scope gate.
    This is the ONLY control surface for the packet-scope gate; it is
    deliberately not exposed as an ``@framework_tool``, so the secretary
    agent cannot arm/disarm or bless IPs.  When armed, ``send_packet``
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
            print("  Usage: scope on <handle> [--platform h1|bugcrowd|intigriti] [--no-strict] [--ip-boundary]")
            return
        handle = parts[1]
        platform = "h1"
        strict = True
        ip_boundary = False
        i = 2
        while i < len(parts):
            tok = parts[i]
            if tok == "--no-strict":
                strict = False
                i += 1
            elif tok == "--ip-boundary":
                ip_boundary = True
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
        res = scope_gate.arm(handle, platform, strict, ip_boundary=ip_boundary)

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
    purge path; deliberately not exposed as an ``@framework_tool``, so the
    secretary can never tag rows with a new engagement key or erase the
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