# Harness Postgres: operator authority on the engagement registry.

-- 004: close_and_purge() stamps closed_at on engagement.engagements as
-- harness_operator BEFORE calling engagement.purge(). 002 granted SELECT
-- only, so the first purge attempt died with "permission denied for table
-- engagements". The registry is operator-writable by design: lanes still
-- hold INSERT+SELECT just like before (registry upsert on arm), and the
-- lane-facing audit spine (journal.entries) stays append-only. DELETE on the
-- registry is the operator's tombstone-removal option; the purge() SECURITY
-- DEFINER function deliberately does not touch this table.
GRANT UPDATE, DELETE ON TABLE engagement.engagements TO harness_operator;