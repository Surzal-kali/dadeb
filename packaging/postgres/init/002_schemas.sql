-- Harness Postgres: session role + work schemas.
-- 002: schemas, engagement registry, journal, evidence, grants.

BEGIN;

-- ─── Work schemas ────────────────────────────────────────────────────────────
CREATE SCHEMA IF NOT EXISTS engagement;
CREATE SCHEMA IF NOT EXISTS journal;
CREATE SCHEMA IF NOT EXISTS evidence;

-- ─── engagement.schema ───────────────────────────────────────────────────────
-- The cobweb key. One slug ('blue.htb') ties every lane's rows together; the
-- single-database choice makes "DELETE everything for this engagement" one
-- transaction across all schemas (see engagement.purge() in 003.functions.sql).
CREATE TABLE IF NOT EXISTS engagement.engagements (
    slug        TEXT PRIMARY KEY,                     -- 'blue.htb' / 'foo.example'
    roe_note    TEXT,                                 -- operator's rules-of-engagement note
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at   TIMESTAMPTZ                           -- purge refuses while open
);

-- ─── journal.schema ──────────────────────────────────────────────────────────
-- The spine: one row per tool dispatch, stitched across every lane.
CREATE TABLE IF NOT EXISTS journal.entries (
    entry_id    BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    engagement  TEXT REFERENCES engagement.engagements(slug),
    lane        TEXT NOT NULL DEFAULT 'unknown',   -- secretary|gateway|repl|brain|owui|mcp
    tool_id     TEXT NOT NULL,
    args        JSONB NOT NULL DEFAULT '{}'::jsonb, -- material tier: secrets stay (scrubbing is a mid-engage self-own), 24h TTL applies, purge wipes
    scope_verdict TEXT,
    approval_path TEXT,                              -- secretary_approval|gateway|repl_direct|mcp|owui
    status      TEXT NOT NULL,                       -- ok|error|timeout|budget_exhausted
    duration_s  REAL,
    result_mode TEXT,                                 -- large|digest|page
    scratch_ref TEXT,                                 -- pointer to scratch-store payload
    result_digest TEXT,                               -- tiny self-contained summary (status + key scalars)
    envelope_meta JSONB,                              -- provenance stamp, job_id, degraded flag, etc.
    expires_at  TIMESTAMPTZ                           -- NULL = engagement-bound (purge wipes); set = retention sweep collects
);

CREATE INDEX IF NOT EXISTS idx_journal_engagement_ts
    ON journal.entries (engagement, ts DESC);
CREATE INDEX IF NOT EXISTS idx_journal_tool_ts
    ON journal.entries (tool_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_journal_args_gin
    ON journal.entries USING gin (args jsonb_path_ops);
CREATE INDEX IF NOT EXISTS idx_journal_expiry
    ON journal.entries (expires_at) WHERE expires_at IS NOT NULL;

-- ─── evidence.schema ─────────────────────────────────────────────────────────
-- The unknown ledger, promoted. A finding records a conclusion; an evidence
-- entry records an observation/question with typed content.
CREATE TABLE IF NOT EXISTS evidence.entries (
    entry_id      BIGSERIAL PRIMARY KEY,
    engagement    TEXT REFERENCES engagement.engagements(slug),
    agent_id      TEXT NOT NULL DEFAULT 'unknown',
    kind          TEXT NOT NULL CHECK (kind IN (
                      'credential', 'service', 'ambiguity',
                      'scope_question', 'observation')),
    status        TEXT NOT NULL DEFAULT 'open' CHECK (status IN (
                      'open', 'promoted', 'resolved', 'wontfix')),
    source        TEXT,          -- where it came from ('session_get', 'operator', ...)
    summary       TEXT NOT NULL, -- one readable line
    content       JSONB NOT NULL DEFAULT '{}'::jsonb,
    result_digest TEXT,          -- tiny material summary (same discipline as journal)
    scratch_ref   TEXT,          -- soft ref to full material (no FK — may expire)
    related_journal BIGINT REFERENCES journal.entries(entry_id),
    resolved_by   TEXT,          -- finding id when status='promoted'
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ    -- NULL = engagement-bound; set = retention sweep collects
);

CREATE INDEX IF NOT EXISTS idx_evidence_engagement_kind
    ON evidence.entries (engagement, status, kind);
CREATE INDEX IF NOT EXISTS idx_evidence_expiry
    ON evidence.entries (expires_at) WHERE expires_at IS NOT NULL;

-- Kind-dependent TTL defaults applied at insert: scope questions never rot
-- (safety-adjacent state), credentials carry the 24h engagement floor the
-- operator set (2026-10-19 decision: cred TTL ≤ engagement length, and a
-- 24h engagement is the planning horizon), other opens fade on a week.
CREATE OR REPLACE FUNCTION evidence.default_ttl() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.expires_at IS NOT NULL THEN
        RETURN NEW;                          -- explicit TTL wins
    END IF;
    IF NEW.kind = 'scope_question' THEN
        NEW.expires_at := NULL;              -- never rots
    ELSIF NEW.kind = 'credential' THEN
        NEW.expires_at := now() + INTERVAL '24 hours';
    ELSE
        NEW.expires_at := now() + INTERVAL '7 days';
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS evidence_default_ttl ON evidence.entries;
CREATE TRIGGER evidence_default_ttl
    BEFORE INSERT ON evidence.entries
    FOR EACH ROW EXECUTE FUNCTION evidence.default_ttl();

-- The credential-reuse sweep: each validation attempt is an auditable event.
-- The UNIQUE (entry_id, service, target) enforces the standing runbook rule —
-- "exactly one attempt per service" — at the DB, where the secretary's
-- 'one more try' impulses can't reach.
CREATE TABLE IF NOT EXISTS evidence.attempts (
    attempt_id    BIGSERIAL PRIMARY KEY,
    entry_id      BIGINT NOT NULL REFERENCES evidence.entries(entry_id) ON DELETE CASCADE,
    service       TEXT NOT NULL,   -- ssh|smb|ftp|http-basic|http-form|mysql|postgres|winrm|...
    target        TEXT NOT NULL,   -- host:port or URL the credential was tried against
    outcome       TEXT NOT NULL CHECK (outcome IN ('hit', 'miss', 'error', 'undecided')),
    result_digest TEXT,
    scratch_ref   TEXT,
    journal_ref   BIGINT REFERENCES journal.entries(entry_id),
    attempted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (entry_id, service, target)
);

CREATE INDEX IF NOT EXISTS idx_attempts_entry ON evidence.attempts (entry_id);

-- ─── Lane grants ─────────────────────────────────────────────────────────────
-- journal: INSERT + SELECT only — no role holds UPDATE/DELETE, so append-only
-- is structural, not aspirational. (evidence does get UPDATE: status flips.)
GRANT SELECT, INSERT ON journal.entries, evidence.entries, evidence.attempts
    TO brain_lane, gateway_lane, repl_lane;
-- Evidence UPDATE is status-flip ONLY (column-level grants): lanes may flip
-- open→resolved/wontfix/promoted but never rewrite summary/content/engagement
-- — burying a resolution by editing history is as forbidden as erasure.
GRANT SELECT, INSERT ON evidence.entries TO brain_lane, gateway_lane, repl_lane;
GRANT UPDATE (status, resolved_by, updated_at, expires_at, scratch_ref, related_journal)
    ON evidence.entries TO brain_lane, gateway_lane, repl_lane;
GRANT SELECT, INSERT ON engagement.engagements TO brain_lane, gateway_lane, repl_lane;
GRANT UPDATE ON evidence.attempts TO repl_lane;   -- operator-only correction
-- Table grants do NOT confer schema entry: lanes + operator need USAGE on
-- every schema they touch (owner-only otherwise → 'permission denied for
-- schema journal' on the first lane write).
GRANT USAGE ON SCHEMA engagement, journal, evidence
    TO brain_lane, gateway_lane, repl_lane, harness_operator;
GRANT USAGE ON SEQUENCE
    journal.entries_entry_id_seq,
    evidence.entries_entry_id_seq,
    evidence.attempts_attempt_id_seq
    TO brain_lane, gateway_lane, repl_lane;

-- Operator read visibility (the human's psql session + the editor's
-- PostgreSQL extension connect as this role): read-only browse of every
-- store. Holds no writes here; erase power comes from engagement.purge()
-- (SECURITY DEFINER, 003_functions.sql).
GRANT SELECT ON journal.entries, evidence.entries, evidence.attempts,
    engagement.engagements TO harness_operator;

COMMIT;