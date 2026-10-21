# Engagement Cobweb + Journal

The engagement slug (`blue.htb`) is the **cobweb key** that ties every store
row — journal dispatches, evidence entries, validation attempts — to one
engagement. One slug enables one **purge** that erases an engagement in a
single transaction while the rest of the audit trail stays append-only.

The agent should know these tools exist (they're `infra`-tagged and
callable past the tool budget) — but arming/disarming/purging is
**operator-only** via the REPL/CLI, mirroring the scope-gate authority
model.

## journal — what happened

`journal.entries` (Postgres schema `journal`) records **one row per tool
dispatch across every lane**, written at the executor choke point. This is
the reconstruction spine for reporting, resuming after a break, and
answering "did we ever touch X" — the GIN-indexed `args` JSONB makes
target-mention queries indexed lookups.

- Rows survive material expiry: each carries a tiny self-contained
  `result_digest` (status + key scalars); full payloads stay in scratch
  behind its own TTL.
- The single redaction: session `handle` args become `{"$sessref":
  session_id}` pointers.
- **Residency rule**: args (including credential material: session_post
  bodies, MSF options, cookies) are stored as-is — mid-engage scrubbing
  would break the reuse sweep. Bounds are structural instead: 24h cred TTL
  + engagement purge.
- Append-only is structural: DB roles for lanes hold INSERT/SELECT only;
  no lane holds DELETE. The retention sweep (`engagement.sweep_expired()`)
  and engagement purge (`engagement.purge()`, operator-only) are the only
  deletion paths.
- Attribution: the `lane` column comes from the **authenticated DB role**
  (inferred per entry point: tool_repl → repl_lane, api_gateway/bootstrap →
  gateway_lane, thebrain → brain_lane) — not self-report.

The agent never calls the journal directly; it journals *you* (every
dispatch through `execute_tool`), including preflight rejects.

## engagement — operator verbs

Operator-only, from the REPL or CLI (`python tool_repl.py ...`):

```
engagement on <slug> [<roe_note>]   # arm — registers the slug; every new
                                    # row is stamped with it
engagement off                      # disarm (rows keep their slug)
engagement status                   # armed? db connected? as which lane?
engagement purge <slug>             # close + erase journal + evidence;
                                    # requires typing the slug to confirm.
                                    # IMPORTANT: render_findings FIRST —
                                    # exports are not purged, DB rows are.
```

The armed state lives in `engagement/.armed_engagement.json`
(mtime-checked per dispatch, same mechanism as the scope gate's armed
file); the arming verbs are deliberately NOT exposed as framework tools.

## what the agent CAN do with the engagement lane

1. **Read the engagement-stamped context**: evidence entries carry the
   armed slug automatically (no parameter for it — it's stamped at write
   time from the armed state).
2. **The reuse sweep worklist**: `list_open_evidence()` — a credential
   entry with zero attempts is the standing next action (the
   `next_hints` on `report_finding` nudges this).
3. **Journal answers on request**: ask the operator to run
   `what_touched`-style queries — "have we ever dispatched against
   `10.10.10.50`?" is one SELECT on the journal, and the operator can
   paste the result into the conversation.

## what the agent CANNOT do (by DB design, verified live)

- **Erase** journal/evidence rows: lanes hold no DELETE privilege.
- **Rewrite** the spine: journal.entries is not UPDATE-able by lanes.
- **Edit evidence history**: `summary`/`content`/`engagement` columns are
  frozen (column-level UPDATE grants; only status-flip columns +
  `resolved_by` can change).
- **Purge an engagement**: `engagement.purge()` executes only for
  `harness_operator`.

## where the stores live

- Postgres (primary): one DB (`harness`), schema-per-store (`engagement` /
  `journal` / `evidence`) — reachable from every lane (see
  `AGENTS.md` → "Engagement cobweb + journal").
- SQLite mirror (phase-1 fallback, no-DB lanes): `evidence/evidence.db` —
  same kinds/statuses, same one-attempt constraint.
- The engagement lane degrades silently when Postgres is down
  (journaling skipped, evidence keeps running on the mirror) — by design;
  the DB lane is additive.

Cross-references: `knowledge/findings.md` (report rendering + evidence
lifecycle), `AGENTS.md` (architecture deep-dive), `memories.py` (vector
memory service).