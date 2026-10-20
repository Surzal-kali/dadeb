================================================================================
 DADEB FALL-INVENTORY / DAMAGE REPORT — 4hr Copilot packaging session
 Snapshot: git@github.com:Surzal-kali/dadeb.git @ 7218134 (tree clean, git status
 empty, git pull => "Already up to date"). Generated 2026-10-20 by Kai.
 All facts below verified against this snapshot. Pull-only clone; never push.
================================================================================

1) HEADLINE VERDICT
-------------------
The 4hr Copilot chat (commits cd9bb4f..7218134, ~19 commits) was surgical:
it touched 32 files NET, and every one is packaging-lane (debian/, packaging/,
sitecustomize.py, kali-package-pitch.md, pyproject.toml, requirements.txt).
ZERO commits touched utils/, auxiliaries/, payloads/, listeners/, encoders/,
evasion/, owui-tools/, or any core module. H1 + scope integration are fully
intact and compile. No fallout in the payload.

2) SESSION FOOTPRINT (git diff --name-status f2addad..HEAD)
-------------------
ADDED (30): debian/{changelog,control,copyright,daharness.manpages,
  daharness.postinst,rules,source/format}, kali-package-pitch.md,
  packaging/bin/{daharness,daharness-chroma,daharness-kernel,daharness-repl},
  packaging/l2_import_floor.py, packaging/man/*.1|.5|.7 (+.md sources, 6 pages,
  12 files), packaging/systemd/{98-daharness.preset,daharness-chroma.service},
  packaging/systemd/{daharness-kernel.service,daharness.service} (new-to-deb),
  sitecustomize.py
MODIFIED (2): pyproject.toml, requirements.txt
Commit arc: 44c15cd pitch(346L) -> e0cc8b9 man pages(633L) -> 4f0dc77 l2 floor
  driver(125L) -> 42d5136 debian build lane -> vendoring arc (7f8f430
  chromadb+pydantic-ai-slim, 5372bb9 wrapper PYTHONPATH, 5fa927f dh_prep wipe
  fix, 00af92b sitecustomize vendor-prepend) -> 6736279 brain.sock + chroma
  unit -> c0a41b2 pydantic-ai-slim[openai] -> 0ec74bd/0847b70 preset (zz- -> 98-
  rename after preset-policy decode) -> fa5dad0/7218134 ledger commits.

3) HACKERONE INTEGRATION — INTACT
-------------------
auxiliaries/program_scope.py (74,527 bytes) = full copy:
  - 23 "hackerone" mentions; _H1_API = "https://api.hackerone.com/v1"
  - _h1_auth() reads H1_API_USERNAME + H1_API_TOKEN (both in .env.example
    lines 128-131 AND referenced in program_scope)
  - per-handle cache: _save_cache/_load_cache/_scope_cache_path default
    platform="h1"; clean "auth_required: set H1_API_USERNAME and H1_API_TOKEN"
    failure message (line ~186)
  - 107 intigriti/bugcrowd mentions in the same file — all three platform
    lanes (search_programs + scope fetch) present.
py_compile clean. No session commit touched this file.

4) SCOPE INTEGRATION — INTACT
-------------------
utils/scope_gate.py (36,874 B), utils/engagement.py (13,781 B),
utils/findings.py (16,970 B) present; daharness/registry.py carries
ALLOWED_TOOL_ROOTS = [auxiliaries, payloads, listeners, utils, encoders,
evasion] + prefix guard (lines 92-99, 190-198); script-path gate unchanged.
All five files compile (COMPILE_OK). Ship-set: debian/rules TREE_DIRS =
"daharness utils auxiliaries payloads listeners encoders evasion owui-tools"
(line 3) -> scope + H1 lanes ship in the deb. Packaging/l2_import_floor.py
ROOTS additionally include owui-tools, engagement, knowledge. Registry roots
do NOT include owui-tools (consistent with the six-roots prod census — noted,
not damage). Tests remain amputated in dadeb (by design, not fallout).

5) METADATA DELTAS (the session's only core-tree edits; known-good)
-------------------
pyproject.toml: +urllib3>=2.0 floor; -python-nmap; pg8000 moved main ->
  db extra (symmetric with psycopg, both guarded honest degraders).
requirements.txt: -python-nmap.
Matches the Oct-20 on-box dep-census ledger entry.

6) FINDINGS AGAINST THIS TIP (observation-only; no patches applied)
-------------------
F1 HIGH — GATEWAY_API_KEY can never arm from the package:
  api_gateway.py:444-466 middleware ships intact (X-API-Key + Bearer,
  secrets.compare_digest, gates REST + /mcp; /docs /redoc /openapi.json
  /health exempt; logs "unauthenticated dev mode" when unset).
  But: bootstrap.py loads ONLY <tree>/.env; the deb ships no .env (only
  .env.example at /usr/share/daharness/.env.example, NOT loaded);
  packaging/etc/daharness.env has no GATEWAY_API_KEY line; zero
  GATEWAY_API_KEY references in debian/ or packaging/bin/; postinst =
  adduser only. => stock deb boots unauth.
  Stack detail: bootstrap.py:624 start_api_server => host="0.0.0.0",
  port=5000 hardcoded; no GATEWAY_HOST/PORT knob anywhere. Unauth +
  0.0.0.0 = LAN-reachable tool-execution gateway.
  Fix options (when patching): conffile placeholder line, or postinst
  openssl rand -hex 32 generation, and/or GATEWAY_HOST knob default
  127.0.0.1 (mirror the ZAP pattern).

F2 HIGH — /etc/daharness/daharness.env is read by nothing except chroma:
  Only daharness-chroma.service:21 has EnvironmentFile=. The daemon unit
  (daharness.service:21) and kernel unit (daharness-kernel.service:18)
  carry the inert Environment=DAHARNESS_ENV=... form; grep of all *.py
  finds ZERO references to /etc/daharness or DAHARNESS_ENV — nothing
  reads the conffile in Python. Pitch/runbook step 6 claims
  "EnvironmentFile= in the units, 2026-10-20 wiring" — true for 1 of 3
  units only.
  Sharp blast radius (verified in constants.py:97-122): resolve_workspace_
  root() with WORKSPACE_ROOT unset (or set-but-nonexistent) falls back to
  the CODE CHECKOUT = /usr/share/daharness (root-owned via dpkg). Daemon
  runs as User=daharness -> ids.db/scratch.db/scope/findings_md/.memory
  writes FAIL on permission. Meanwhile the unit hand-provisions the correct
  root (StateDirectory=daharness, WorkingDirectory=/var/lib/daharness) that
  nothing points at. brain.sock is SAVED by the unit's Environment=
  BRAIN_SOCKET=/run/dahanvas/brain.sock override (constants env wins).
  NOTE: green smoke did not exercise daemon-side conffile reads or state
  writes — the runbook step-6 precedence "marker var" test on the DAEMON
  unit would have caught this; recommend running it explicitly on the VM.

F3 LOW — with a key armed, docs/redoc/openapi/health stay open; fine
  practice generally, worth a daharness-safety(7) line at 0.0.0.0 binds.

F4 COSMETIC — retired-lane residue: .env.example commented
  OPEN_TERMINAL_URL/OPEN_TERMINAL_API_KEY (open_terminal lane retired Sep 18
  2026); devdocs/dockered-README.md references. Fold into the pitch's
  existing "[open] devdocs/burpconfig.json fate" ticket.

F5 LOW/DOC — pitch freshness: pitch "Python 3.13" blurb stale (Kali ships
  3.14.7-3); Debian names for Depends: python3-bs4 (=beautifulsoup4),
  python3-dotenv; python3-impacket 0.13.1-1 exact pin already resolved.

7) POSTGRES OPTION — WIRED AS DECIDED (drivers), SERVER-SIDE ABSENT
-------------------
  WIRED: debian/control:34 Suggests python3-pg8000 + python3-psycopg
  (opt-in; python3-psycopg 3.3.5-1 already on the VM). Zero postgres in
  Depends or debian/rules — intentional per Oct-20 ledger.
  Code: utils/engagement.py connect() lazy-imports psycopg; ImportError ->
  one debug log + lane disabled; down -> 2s-per-host tries then backoff
  retries, never blocks dispatch. Per-lane role INFERENCE from argv0
  (tool_repl -> repl_lane, api_gateway/bootstrap -> gateway_lane,
  thebrain -> brain_lane) maps correctly onto packaged entrypoints;
  HARNESS_DB_LANE stays as explicit override. Password defaults =
  *_change_me compose placeholders, env-overridable per lane.
  auxiliaries/db_client.py pg8000 adapter lazy-imports with _DriverMissing
  + remediation string.
  NOT WIRED: no server provision in the deb. packaging/postgres/init/
  (001_roles.sh, 002_schemas.sql, 003_functions.sql, 004_operator_
  registry_acl.sql) is compose-lane init material addressed by nothing in
  debian/ or packaging install lines (grep -c postgres debian/rules = 0);
  pitch files it under "Remnants" (fate open). Conffile carries no
  HARNESS_DB_* knobs. _host_candidates() default = ["postgres", "127.0.0.1",
  "172.28.0.20"] — dev-world shape; fresh debs sit in polite retry backoff.
  Fresh-deb experience = stock: lane silently off; +python3-psycopg: lane
  armable; +real PG +hand env +hand-run init bundle: works. Server-side
  provisioning arrives with team mode per ship doctrine — gap is honest.

8) NOT COVERED BY THIS CENSUS / QUEUED FOR NEXT CYCLE
-------------------
  a. Patch decisions F1+F2 (~10 lines total: EnvironmentFile= on daemon +
     kernel units, drop inert DAHARNESS_ENV lines incl. duplicate
     BRAIN_SOCKET, GATEWAY_API_KEY placeholder in conffile, optional
     GATEWAY_HOST knob). NOT applied — per instruction, inventory only.
  b. Pitch "Remnants" paragraph full read -> fate ticket for
     packaging/postgres/init/.
  c. VM leg: runbook steps (python3-mcp/pymetasploit3 probe; precedence
     marker test on DAEMON unit — catches F2 the green smoke missed).
  d. Residue sweep: .env.example OPEN_TERMINAL lines +
     devdocs/dockered-README.md (F4; merge with burpconfig ticket).
  e. Man-page read for posture documentation: daharness-safety(7) should
     state bind + auth posture of the packaged profile.

9) RE-VERIFY (fresh sandbox, if the clone smells stale)
-------------------
  cd /root/dadeb && git fetch && git log --oneline -3 && git status --short
  # empty diff below f2addad..HEAD over utils/ = session never touched core:
  git log --oneline f2addad..HEAD -- utils/
  # census:
  git diff --name-status f2addad..HEAD | wc -l
================================================================================
