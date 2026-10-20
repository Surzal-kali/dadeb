-- Harness Postgres: engagement purge + retention sweep functions.
-- 003: SECURITY DEFINER functions and the final grant map.
-- Loaded by docker-entrypoint-initdb.d AFTER 002_schemas.sql.

BEGIN;

-- ─── engagement.purge() ──────────────────────────────────────────────────────
-- The cobweb pull: one transaction, all schemas, one slug. Refuses while the
-- engagement is open — export findings first (render_findings markdown lane
-- already exists; render-then-purge is the closing step, not a DB function).
-- SECURITY DEFINER because lanes hold INSERT/SELECT only and must never hold
-- DELETE; this function is the sole delete path for journal + evidence.
CREATE OR REPLACE FUNCTION engagement.purge(p_slug TEXT,
    OUT store TEXT, OUT deleted BIGINT)
RETURNS SETOF RECORD
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = engagement, journal, evidence
AS $$
DECLARE
    v_closed TIMESTAMPTZ;
    d_att BIGINT := 0;
    d_evi BIGINT := 0;
    d_jrn BIGINT := 0;
BEGIN
    SELECT closed_at INTO v_closed
        FROM engagement.engagements WHERE slug = p_slug;

    IF v_closed IS NULL THEN
        RAISE EXCEPTION 'engagement % is not closed — close it before purge (export findings first)', p_slug;
    END IF;

    DELETE FROM evidence.attempts
        WHERE entry_id IN (SELECT entry_id FROM evidence.entries WHERE engagement = p_slug);
    GET DIAGNOSTICS d_att = ROW_COUNT;

    DELETE FROM evidence.entries WHERE engagement = p_slug;
    GET DIAGNOSTICS d_evi = ROW_COUNT;

    DELETE FROM journal.entries  WHERE engagement = p_slug;
    GET DIAGNOSTICS d_jrn = ROW_COUNT;

    -- Tombstone stays: the registry row deliberately survives (with its
    -- closed_at stamp) so the audit story records that an erasure happened.
    store := 'evidence.attempts'; deleted := d_att; RETURN NEXT;
    store := 'evidence.entries';  deleted := d_evi; RETURN NEXT;
    store := 'journal.entries';   deleted := d_jrn; RETURN NEXT;
END $$;

-- ─── engagement.sweep_expired() ─────────────────────────────────────────────
-- The material tier's floor, on top of the per-kind defaults (cred 24h):
-- expired OPEN evidence is deleted outright; non-open (reconciliation-tier)
-- skeletons get their material columns tombstoned; journal args are wiped
-- past their TTL. Every row carries expires_at; the engagement purge is the
-- second mechanism (defense in depth). Called lazily on every journal write
-- — the same purge-on-mutation pattern scratch/cookie-jar already use.
CREATE OR REPLACE FUNCTION engagement.sweep_expired()
RETURNS INTEGER
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = engagement, journal, evidence
AS $$
DECLARE
    gone_evi INTEGER := 0;
BEGIN
    WITH swept AS (
        DELETE FROM evidence.entries
        WHERE status = 'open'
          AND expires_at IS NOT NULL
          AND expires_at < now()
        RETURNING entry_id
    )
    SELECT count(*) INTO gone_evi FROM swept;

    -- Reconciliation-tier rows: skeleton stays, material is tombstoned.
    UPDATE evidence.entries
    SET content = '{}'::jsonb,
        updated_at = now()
    WHERE status <> 'open'
      AND expires_at IS NOT NULL
      AND expires_at < now()
      AND content <> '{}'::jsonb;

    -- Journal args: redacted once their TTL passes (journal rows themselves
    -- stay — they are the spine; only the material expires).
    UPDATE journal.entries
    SET args = '{}'::jsonb
    WHERE expires_at IS NOT NULL
      AND expires_at < now()
      AND args <> '{}'::jsonb;

    RETURN gone_evi;
END $$;

GRANT EXECUTE ON FUNCTION engagement.sweep_expired()
    TO brain_lane, gateway_lane, repl_lane;

-- ─── Final role grants: only the operator purges ────────────────────────────
-- Same authority model as the scope gate: the secretary can never toggle
-- scope, so no agent lane can ever erase the audit trail. Only the
-- operator's psql session (harness_operator) runs engagement.purge().
GRANT EXECUTE ON FUNCTION engagement.purge(TEXT) TO harness_operator;
REVOKE EXECUTE ON FUNCTION engagement.purge(TEXT) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION engagement.purge(TEXT) FROM brain_lane;
REVOKE EXECUTE ON FUNCTION engagement.purge(TEXT) FROM gateway_lane;
REVOKE EXECUTE ON FUNCTION engagement.purge(TEXT) FROM repl_lane;

COMMIT;