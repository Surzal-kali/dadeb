-- Harness Postgres: stream dev-diary schema (dacustoms.diary).
-- 005: the narrative layer the diary tools read/write. DDL stays
-- operator-run (daharness-pg init re-runs it idempotently) — the diary
-- module never self-creates: diary_schema_status reports a missing
-- schema instead of guessing at columns.

BEGIN;

-- ─── stream schema ───────────────────────────────────────────────────────────
-- One row per stream session + one row per timeline beat. The beats are
-- byte-stable (archive pipeline + Resolve marker list key on them): the
-- events CHECK below enforces the same tuple dacustoms.diary.BEATS carries.
-- drift is a CREATE-order bug, not a runtime edit — keep the two in sync
-- BY HAND and one commit at a time.
CREATE SCHEMA IF NOT EXISTS stream;

CREATE TABLE IF NOT EXISTS stream.sessions (
    session_key BIGSERIAL PRIMARY KEY,
    slug        TEXT,                                  -- armed engagement (NULL = lab noodling, not cobwebbed)
    platform    TEXT NOT NULL CHECK (platform IN ('htb','pg','lab')),
    box         TEXT NOT NULL,
    difficulty  TEXT,
    attempt_no  INT    NOT NULL DEFAULT 1,
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at    TIMESTAMPTZ,
    note        TEXT,
    cold_open   TEXT,                                  -- the one-sentence opener, written LAST (at wrap)
    takeaways   JSONB,                                 -- ["...","...","..."]
    seeds       JSONB,                                 -- concrete next-session seeds the next state beat reads
    UNIQUE (slug, box, attempt_no)
);

CREATE TABLE IF NOT EXISTS stream.events (
    event_id     BIGSERIAL PRIMARY KEY,
    session_key  BIGINT NOT NULL REFERENCES stream.sessions(session_key),
    beat         TEXT NOT NULL CHECK (beat IN
                    ('cold_open','state','intent','grind','value','stuck',
                     'valve','framework','later','wrap')),
    summary      TEXT NOT NULL,
    screen       INT NOT NULL DEFAULT 1,               -- OBS screen the beat happened on
    clip         BOOLEAN NOT NULL DEFAULT FALSE,       -- clip-worthy: consumed by the Resolve marker list
    at_wall      TIMESTAMPTZ NOT NULL DEFAULT now(),   -- absolute wall-clock for marker math
    journal_ref  BIGINT REFERENCES journal.entries(entry_id),  -- optional: the dispatch row that produced this beat
    layer        TEXT,                                 -- suspected layer for framework beats ('dns','web','auth',...
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_stream_events_session
    ON stream.events (session_key, at_wall);
CREATE INDEX IF NOT EXISTS idx_stream_events_clip
    ON stream.events (session_key) WHERE clip;
CREATE INDEX IF NOT EXISTS idx_stream_sessions_slug
    ON stream.sessions (slug) WHERE slug IS NOT NULL;

-- ─── Lane grants ─────────────────────────────────────────────────────────────
-- Same shape as the other stores: lanes INSERT + SELECT, nothing deletes —
-- append-only is structural. Retention/purge runs through engagement.purge()
-- in future operators' passes; for now the diary is operator-copied data.
GRANT SELECT, INSERT ON stream.sessions, stream.events
    TO brain_lane, gateway_lane, repl_lane;
GRANT UPDATE (note, cold_open, takeaways, seeds, ended_at) ON stream.sessions
    TO brain_lane, gateway_lane, repl_lane;
GRANT USAGE ON SCHEMA stream TO brain_lane, gateway_lane, repl_lane, harness_operator;
GRANT USAGE ON SEQUENCE
    stream.sessions_session_key_seq,
    stream.events_event_id_seq
    TO brain_lane, gateway_lane, repl_lane;

-- Operator read visibility (same browse posture as journal/evidence).
GRANT SELECT ON stream.sessions, stream.events TO harness_operator;

COMMIT;
