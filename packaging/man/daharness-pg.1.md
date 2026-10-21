% DAHARNESS-PG(1) daharness 0.1.0 | daharness manual

# NAME

daharness-pg — provision the optional engagement-cobweb Postgres lane

# SYNOPSIS

**daharness-pg** *init* | *start* | *stop* | *status*

# DESCRIPTION

The deb ships the engagement journal/evidence lane with its Postgres
drivers wired but no server: out of the box the lane is silently off and
the SQLite stores carry the journal. When a Postgres-backed cobweb is
wanted, **daharness-pg** (run via *sudo*) provisions a **dedicated
cluster** named `daharness` on **port 5433** with **pg_createcluster**.
It never touches msfdb's `main` cluster on 5432 — in either direction:
an msfdb re-init cannot drop the harness database, and the harness
cluster cannot collide with msf's port.

`daharness-pg init`:

- verifies the Postgres server tooling exists (`pg_createcluster`,
  `pg_ctlcluster`, `psql`, `createdb`); absent tooling prints the exact
  **apt install postgresql** remediation and changes nothing;
- creates and starts the dedicated cluster (autostart, so it returns
  after reboots via *postgresql.service*);
- creates the `harness` database;
- runs the shipped init bundle (roles + password ALTERs, schemas,
  SECURITY DEFINER `engagement.purge()`, operator registry ACL) from
  `/usr/share/daharness/postgres/init/` with `-v ON_ERROR_STOP=1`;
- writes resolved knobs to `/etc/daharness/pg.env`
  (HARNESS_DB_HOST/PORT/NAME plus one
  HARNESS_DB_PASSWORD_{OPERATOR,BRAIN,GATEWAY,REPL} per lane role),
  mode 0640 root:daharness — the systemd units read it via a tolerant
  `EnvironmentFile=-` line, and an operator shell sources it before
  running the REPL.

`init` is idempotent: it reuses lane passwords already recorded in
pg.env, re-runs the bundle (roles are IF NOT EXISTS; schemas/functions
are CREATE IF NOT EXISTS) and rewrites pg.env from live state. Lane
passwords are 128-bit random hex minted at first init; **rotate** by
moving pg.env aside, re-running `init`, and restarting the daharness
units.

Without the lane, `utils/engagement.py` degrades honestly (it logs once
that Postgres is unavailable and journals stay on SQLite); lane role and
host selection honor the HARNESS_DB_* environment knobs documented in
*daharness.env*(5).

# SUBCOMMANDS

**init** — provision or repair the lane; requires root.

**start** / **stop** — start/stop the dedicated cluster
(*pg_ctlcluster*; requires root).

**status** — cluster presence, readiness on 127.0.0.1:5433, and whether
pg.env is in place. Works as any user.

# FILES

`/etc/daharness/pg.env` — generated lane knobs (not a package conffile:
it survives upgrades; `apt purge` collects it — `init` re-mints it
losslessly).

`/usr/share/daharness/postgres/init/001_roles.sh`,
`002_schemas.sql`, `003_functions.sql`,
`004_operator_registry_acl.sql` — shipped init bundle.

# SEE ALSO

*daharness.env*(5), *daharness-safety*(7), *daharness*(1)