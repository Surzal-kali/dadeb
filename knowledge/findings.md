# Findings Lifecycle

## report_finding

`report_finding` (`utils/findings.py`) is the terminal action for any tool
chain. It mints a structured `Finding` in the SQLite findings store
(`ids.db`) and stores a lightweight one-line pointer in vector memory so the
secretary can recall that the finding exists later without bloating its
context with the full evidence payload.

## finding fields

- `title`: Short summary, e.g. "SQL Injection in /login"
- `severity`: P1 (critical), P2 (high), P3 (medium), P4 (info)
- `asset`: The affected host/URL/endpoint
- `cwe`: CWE identifier, e.g. "CWE-89" (optional)
- `evidence`: JSON dict with request, response, excerpt
- `repro`: JSON list of reproduction steps
- `tool_chain`: JSON list of tools used in the chain
- `memory_ref`: One-line vector-memory pointer

## finding IDs

Sequential `F-0001`-style IDs. Concurrent adds (gateway + secretary + MCP
clients all share `ids.db`) can compute the same F-id; the PRIMARY KEY turns
that into a loud IntegrityError instead of a duplicate. The store recounts
and retries so the caller just gets their finding, slightly later. A lost
id race falls back to `F-<uuid4>`.

## lifecycle statuses

Findings start as `open`. Status transitions:
- `open` → `closed` (resolved)
- `open` → `false_positive` (not a real finding)
- `open` → `duplicate` (same as another finding)
- `open` → `superseded` (replaced by a newer finding, `superseded_by` field)

Lifecycle columns (`status`, `superseded_by`, `closed_by`, `closed_reason`,
`closed_ts`) are added by idempotent `ALTER TABLE` migration — see
`FindingStore._init_table`.

## render_findings

`render_findings` reads the findings store and returns a markdown report
suitable as a bug-bounty submission draft or lab documentation. The
secretary can call it mid-session to review what has been found so far.
Filters by severity, asset, and status.

## credential-reuse sweep

Every recovered credential — dumped (secretsdump), cracked (hashcat/john),
decoded (GPP cpassword, Base64 config blobs) — gets ONE validation attempt
against each other reachable service before deeper work continues. This is a
standing step: SSH, web login forms, HTTP Basic, MySQL, PostgreSQL, SMB,
FTP. A single failure means "not reused here" — do not brute-force. Log
each validation via `report_finding` so the chain is auditable. The
`report_finding` tool carries a `next_hints` entry that nudges the
secretary to do this sweep automatically.

## unknown ledger (open questions)

Where a finding records a *conclusion*, an unknown records an explicit
"don't know yet" — an unprobed service, a credential recovered but not yet
validated against other services, an ambiguous result, a scope question.
Same SQLite store (`ids.db`, `unknowns` table), separate from findings so
conclusion reports stay clean. Inspired by REA's
`record_unknown`/`list_unknowns` (morluto/rea).

Tools (all `infra`-tagged, all in the terminal lane — callable past the
per-turn tool budget):

- `record_unknown(question, domain, asset, context, tool_chain)` — mint an
  unknown (U-001 style sequential IDs, same lost-id-race handling as findings).
  Domains: recon|web|creds|enum|postex|scope|general.
- `list_unknowns(status="open", domain, asset, include_closed)` — compact
  listing; default shows only open unknowns ("what haven't we answered yet").
- `resolve_unknown(unknown_id, status, resolution, resolved_by)` — close the
  loop: `resolved` (answered), `wontfix` (deliberately not pursuing), or
  `promoted` (question became a finding — pass `resolved_by="F-012"` so
  reports link the chain).

`render_findings` output carries an **Open questions (unresolved)** appendix
listing open unknowns — including when zero findings exist yet, so an
early-days engagement report still shows the open threads. The appendix
disappears once every unknown is closed.

`report_finding` carries a `next_hints` entry nudging the secretary to sweep
open ledger questions (e.g. creds pending validation) before continuing
deeper.

## evidence ledger (the promoted unknown ledger)

**Successor to the unknown ledger** (which still runs in parallel and is
being retired). The evidence store (2026-10-19 design,
`utils/evidence.py`; Postgres schema `evidence` in
`dockered/postgres/init/002_schemas.sql`, SQLite mirror at
`evidence/evidence.db`) gives open items *typed kinds*, *TTLs*, and — the
headline — a **database-enforced credential-reuse sweep**.

Tools (all agent-callable, `infra` terminal lane, engagement-stamped
automatically when the operator has armed an engagement):

- `record_evidence(kind, summary, asset, content_json, source, scratch_ref,
  ttl_hours)` — mint an open item: `credential` (recovered cred awaiting the
  reuse sweep) | `service` (unprobed port/banner) | `ambiguity`
  (contradictory/unclear result) | `scope_question` | `observation`.
  `content_json` is a JSON object for the typed material (e.g.
  `{"username": "svc_sql", "ntlm": "<hash>"}`) — stored as-is: secret
  material is bounded by TTL + engagement purge, never mid-engage scrubbing.
- `add_validation_attempt(evidence_id, service, target, outcome, note)` —
  the reuse sweep, journalled: outcome is one of `hit|miss|error|undecided`.
  **A second attempt against the same (entry, service, target) is REFUSED**
  by the store with re-mint guidance — one honest attempt per service, then
  move on. A `hit` reply says outright: report_finding (P2/P3), resolve as
  `promoted`.
- `list_open_evidence(kind, engagement)` — the sweep worklist: open items
  with their attempt ledger attached; credential entries with ZERO attempts
  are the standing next action.
- `resolve_evidence(evidence_id, status, resolution, resolved_by)` — close
  as `resolved` | `wontfix` | `promoted` (promoted REQUIRES the finding ID
  in `resolved_by`, same contract as the unknown ledger).

Retention defaults (env-tunable, see `.env.example`): credential material
24h (the engagement floor), scope questions never expire (safety-adjacent),
everything else 7d. Expired open entries are collected lazily by the
retention sweep; resolved skeletons keep their readable summary + attempt
ledger for reconciliation.

Standing workflow after recovering ANY credential:

1. `record_evidence(kind="credential", ...)` — pin the material while hot.
2. Enumerate other reachable services that accept authentication
   (ssh/smb/ftp/http-basic/http-form/mysql/postgres/winrm/...).
3. `add_validation_attempt` exactly once per service — a miss means "not
   reused here", a hit means `report_finding` immediately.
4. `resolve_evidence(status="promoted", resolved_by="F-004")` when it
   graduates to a finding.