# Kali deb pitch — v3 (2026-10-20, system-package staging tree)

Carries forward v2 (full text: /home/kali/github/daharness/kali-package-pitch.txt).
This copy = the staging tree that mirrors what the deb ships (amputation logged in
session 2026-10-20; .git removed — no accidental upstream push). All new decisions
below are stamped in THIS tree unless marked [dev-tree] (implement in the dev copy).

## Runtime layout — FHS verdicts (decided)
- /usr/share/daharness        — the tree, run-from-tree, root-owned, read-only at runtime
- /etc/daharness/daharness.env — the packaged .env (config belongs in /etc, not the
                                socket; sockets are runtime state)
- /run/daharness/brain.sock   — Brain UDS, system profile (systemd RuntimeDirectory,
                                tmpfs, rebound every boot)
- /var/lib/daharness/         — WORKSPACE_ROOT in the system profile (StateDirectory);
                                run/, scope/, engagement/, ids.db, scratch.db,
                                cookie_jar.db, .memory/, dropbox/, findings_md/ live under it
- $XDG_RUNTIME_DIR:/daharness + $XDG_STATE_HOME variant — user profile

## Root is a capability PROFILE, not the baseline (decided)
Rootless socket creation was never the blocker (UDS + TCP >1024 are unprivileged).
The privileged roster is exactly three lanes, and each degrades honestly already:
- masscan — raw sockets; framework_doctor probes CAP_NET_RAW, remediation string
  is the fix itself (sudo setcap cap_net_raw+ep $(which masscan)) [framework_status.py]
- packetcraft (scapy) — sr1/send/sendp/sniff are raw-socket lanes; scapy's own
  permission errors are the honest failure
- collaborator OOB — binds UDP:53/:80/:443 by default; docstring documents the
  retune (COLLAB_HTTP_PORT=8080, funnel mode) — retunable per-profile via the
  /etc conffile, no code needed
nmap silently falls back to connect scans; MSF RPC, ZAP, ssh/impacket, web lanes
are user-space. Root remains an operator opt-in (sudo one-shots / setcap).

## System identity + profiles (decided)
- Dedicated system identity: user `daharness`, group `daharness`; operator users
  added to the group. UMask=0007 keeps socket + state group-shareable so the
  operator CLI reaches the Brain's /run socket.
- Two profiles, chosen at deployment — NOT per-launch. Per-launch divergence
  manufactures the framework's own split-brain pitfall (Brain-held sessions
  invisible to in-process fallback; engagement/scope state diverges). It works
  as configuration because BRAIN_SOCKET + WORKSPACE_ROOT already exist.
  - System (default): packaging/systemd/daharness{,-kernel}.service
  - User (optional):  packaging/systemd/user/daharness{,-kernel}.service

## Out-of-the-box file resolution (decided; [dev-tree] code deltas)
No new knobs. Change existing defaults so the packaged tree boots clean:
1. .env load order (constants.py + api_gateway.py loaders — unify in constants):
   $DAHARNESS_ENV  ->  /etc/daharness/daharness.env  ->  tree .env. First existing
   wins, loaded with override=True as today. Resolves the v2 open nit (the deleted
   "shell exports always win" comment; code prevails).
2. resolve_workspace_root(): unset-default gains a writability branch — tree falls
   back to /var/lib/daharness when the tree itself is not writable (packaged lane);
   logs loudly (existing warning plumbing). Dev behavior unchanged (tree writable).
   Same pattern for brain_socket_path(): $BRAIN_SOCKET -> writable-tree run/ ->
   /run/daharness/brain.sock. Writability (not Path.exists()) per the stale-socket
   pitfall doctrine.

## Ship inventory (= current staging cwd, 2026-10-20)
Kept: daharness/, replkit/, auxiliaries/, utils/, payloads/, listeners/, encoders/,
evasion/, owui-tools/, tool_repl.py, bootstrap.py (daemon launcher; chat loop not
packaged), api_gateway.py, constants.py, memories.py, scripts/ (units + stubs),
LICENSE, pyproject.toml, requirements.txt, .env.example.
Drop-dir skeletons kept (operator workspace roots, tool lanes resolve/appeal to
them): apk/ (jadx doctor probe), binaries/ (r2 BINARY_TARGETS_ROOT), pcaps/
(packetcraft output), dropbox/ (msfvenom/session_upload output).
All 34 .md stay in place for now (man-lane decision below); knowledge/ = all-md
operator reference, zero code coupling — kept.
Amputated: tests/, dabooks/, dockered/ (remnants saved), egg-info, .github,
.vscode, requirements-dev.txt. Remnants: packaging/postgres/init/ now installed
material (daharness-pg lane, 2026-10-20 — see Progress log), packaging/reference/
(chroma-config.yaml, 10-refresh-stubs.sh,
lab-dns-setup.sh), devdocs/ (quarantine: burpconfig.json [zero refs, operator
data — fate open], dabooks/dockered READMEs).

## Man pages (decided — option B, 2026-10-20)
Purpose-written thin man sources in packaging/man/: daharness.1,
daharness-kernel.1, daharness-repl.1, daharness.env.5, daharness-tools.7,
daharness-safety.7. YAML `title: <name>(<section>)` sets pandoc's .TH.
Full tree .mds keep in place (ship in /usr/share/doc/daharness/ via
dh_installdocs at most). Build: pandoc -s -f gfm -t man at build time
(Build-Depends, never ships); dh_installman installs/gzips/places; lintian
checks page-name vs command-name. Preview loop: groff -man -Tutf8 -Wall +
man -l. Auto-converting the 44K README was rejected (bad man etiquette).

## Dependency-mapping smoke (2026-10-20, this box: layers 0/1/3 + impacket
arbiter — layer 2 + fresh-Kali VM leg remain)

Method, layered so nothing ever needs root or `--break-system-packages` (PEP 668
refuses system pip anyway; venvs are exempt):

- **Layer 0 — static import scan, zero installs.** ast-parse every ship file,
  classify `import` tops as stdlib / ship / external (never import the tree —
  same doctrine as registry profiling). Script: session files import_scan.py,
  report: /tmp/da-import-scan.json (persistent copy in session files:
  da-import-scan.json; script import_scan.py alongside). This is the
  dependency ground truth.
- **Layer 1 — bare venv + pip dry-run `--report`, zero writes.**
  `python3 -m venv` (bare = also isolates from the established dev venv) then
  `pip install --dry-run --report out.json -r set.txt`: resolver output as JSON
  without installing. Run twice: pins as-is vs `==`-stripped; diff = the
  ==-loosening surface. Report JSON = full transitive closure + markers.
- **Layer 2 — real install + import floor** (bare venv): `pip install
  --no-deps -e .` then import every ship entry, collect ModuleNotFoundError →
  proves the declared set is complete (not just resolvable); also exposes
  cp-wheel availability vs dry-run (metadata-only, doesn't check wheels).
  REPL one-shot + pytest leg run from the dev tree (tests/ amputated here).
- **Layer 3 — distro baseline:** system python (untouched, apt-owned
  dist-packages) importlib.metadata scan = what the deb's Depends can ride.

Findings (this box):
- Layer 0: 97 files, 31 external roots. All map to pyproject except:
  `urllib3` direct-imported (web_probe.py:38, zap.py:42) but UNDECLARED —
  transitive-of-requests today, must be declared for a deb; `python-nmap` pin
  is DEAD (zero imports, python-nmap's import name is `nmap`, nothing imports
  nmap); `brotli`/`zstandard` = webshape.py graceful soft probes (lines 263,
  269) — soft deps, never hard-pin them. `ollama` in requirements.txt but
  zero imports (httpx-driven) — dead export weight.
- requirements.txt in THIS tree is the full 300+-pin dev venv export (jupyter,
  linters, langchain, boto3...) — the deb dependency mapping keys off
  pyproject [dependencies] (23 core) + extras; re-cut requirements.txt for
  packaging separately.
- Layer 1 (cp314): pinned set resolves clean (131 pkgs). Unpinned float
  resolves clean (132 pkgs); 12/23 direct pins float today, but mcp
  1.29→2.3.0 and pydantic-ai-slim 2.35→2.58 are major-API jumps — float-clean
  ≠ runtime-clean. Loosen with `>=` per validated major, not blanket.
- Layer 3 (apt baseline, 753 dists visible): 18/23 core deps apt-satisfied
  (urllib3 joins at 2.8.0 after its declaration; several at exact pin —
  requests, httpx, dnspython, pyasn1, paramiko, starlette, prompt_toolkit).
  Mismatches:
  OLDER-than-pin: psutil 7.1.0 (<7.2.2), cryptography 49.0.0 (<50.0.0),
  python-dotenv 1.2.1; NEWER-than-pin: impacket 0.14.0.dev0 (pin 0.13.1),
  uvicorn 0.53.0, psycopg 3.3.5, pydantic 2.13.5, scapy 2.7.1. Not packaged
  by the Kali repo (2 of 23 — vendored-wheel candidates, see [decided]):
  chromadb, pydantic-ai-slim. CORRECTION (2026-10-20): the layer-3
  importlib.metadata scan measured INSTALLED state, not REPO state —
  apt-cache search shows Kali packages python3-mcp (1.26.0-0kali1, BEHIND
  the 1.29.0 pin), python3-pg8000, python3-pymetasploit3 (1.0.3+git20250715
  -0kali1, behind the 1.0.6 pin). Deb depends ride repo state, not what
  this box happens to have installed; snapshot-compat probes for the two
  older candidates queue on the VM leg (apt install + API probe).
- Grounded upgrade-vs-relax verdict (2026-10-20, PyPI-tag verified):
  "upgrade the pins" is not available anywhere it would matter — the only
  upstream-stable option where apt is older is cryptography (50.0.2 stable but
  we don't need >49; our x509/hashes/serialization/ec/rsa usage is
  long-stable API). The real move is **relax to `>=` and let apt own the
  version** for: psutil (usage = children()/is_running(), ancient APIs),
  cryptography (>=49), python-dotenv, pydantic, uvicorn, psycopg, scapy,
  requests/httpx/dnspython/pyasn1/paramiko/starlette/prompt_toolkit (exact-
  match or newer on apt) — except:
  **impacket does NOT relax**: apt's python3-impacket is 0.14.0.dev0 = a dev
  snapshot of an UNRELEASED 0.14 (PyPI latest stable = 0.13.1 = our pin), and
  our usage is impacket INTERNEALS (krb5.kerberosv5, tds.MSSQL, smb constants,
  ntlm hashes) that move between minors. Keep the 0.13.1 pin in the pip lane;
  the deb lane (Depends python3-impacket @ 0.14dev) was arbiter-decided GREEN
  on this box (impacket-lane evidence in the Progress log — impacket_suite/
  db_client/smb_scanner lanes passed against the snapshot).
  python-nmap verdict: confirmed dead — run_nmap is subprocess.Popen +
  regex verdict parsing of nmap's text log (no `import nmap`, no -oX XML
  lane); the deb needs the nmap BINARY (apt nmap), not the library.
  Arbiter runtime results land in the Progress log; guardrail: the pyproject
  ==0.13.1 pin STAYS for the pip lane (0.14.0.dev0 evidence does not license
  0.14-STABLE assumptions — relax only when 0.14 stable ships, sweep re-run).

Layer 2 floor (2026-10-20, this box cp314 only; 3.13 present? no — /usr/bin
has just python3.14; cp312/313 coverage comes from PyPI ABI tags below):
- Bare venv `pip install --no-deps -e .` GREEN — [tool.setuptools] config
  builds, metadata resolves, editable finder lands on the source tree.
  PEP 668 never touched; system python untouched.
- Import floor over 105 ship entries (subprocess per module, 15s timeout):
  14 ok / 91 lazy / 0 self_fail / 0 other_fail (after the fix below).
  Zero in-tree failures — no typos, no broken relative imports, no syntax
  rot; every third-party miss is a call-time-lazy import as designed.
- LANDMINE caught (exactly what this layer exists for): frameit.so.
  listeners/thebrain.py:279 `lib = ctypes.CDLL(...)` is UNGUARDED at module
  level, and listeners/__init__.py eagerly exports `lib` — without the .so
  EVERY listeners.* module AND the whole Brain _startup_scan dies. The .so
  is a gitignored build artifact (`*.so` policy): the dev tree has it, a
  git checkout can never carry it, and the staging mirror shipped only the
  sources. Probe-proof: `gcc -shared -o frameit.so -fPIC frameit.c`
  (verbatim from the .c's own trailing comment) rebuilt it and the floor
  went green.
- [decided, packaging] debian/rules override_dh_auto_build compiles
  listeners/plugins/frameit.c → frameit.so in-tree (Build-Depends: gcc).
  Consequence: the deb is Architecture: any (compiled artifact), not all.
  raw_scan.cpp has NO loader anywhere in the tree — unwired; stays
  source-only in the package (no compile, no dead binary).
- Import-time hard roots (the Brain-scan floor — must exist in the deb
  runtime before any scan-dir import): chromadb, dotenv, fastapi, httpx,
  pydantic, scapy — all core-declared; satisfied by the vendored/apt lanes.
- Eager __init__ couplings (hygiene notes, not ship blockers — deps are
  core-declared): utils/__init__ eagerly imports packetcraft → module-level
  scapy chain; listeners/__init__ eagerly imports thebrain + lib.
  Callers drag them regardless of which util they meant to import.
- Wheel availability (PyPI JSON, exact pins; feeds the vendored build step):
  chromadb 1.5.9 = cp39-abi3-manylinux2014_x86_64 23.3MB — abi3 covers
  cp312/313/314 (requires_python >=3.9); matcher note: a naive cp3XX string
  search misses abi3-tagged wheels — match 'abi3' explicitly.
  pydantic-ai-slim 2.35.0 = py3-none-any 1.5MB (universal).
  mcp 1.29.0 = py3-none-any 0.2MB (moot if the apt lane passes its probe).
  pymetasploit3 1.0.6 = sdist only, pure-python, tiny.
  Vendored-closure weight: chromadb drags onnxruntime + tokenizers native
  wheels — order 100MB+ installed for the vendored set. Accepted per the
  self-sufficiency call.

## Man pipeline (manning the man pages)
- Sources: packaging/man/*.md — md2man-style markdown (the authoring
  masters; six: man1 daharness/daharness-repl/daharness-kernel, man5
  daharness.env, man7 daharness-tools/daharness-safety).
- Compile: `pandoc --standalone --from markdown-smart --to man` per page →
  roff .1/.5/.7 committed BESIDE the masters. The -smart extension is
  MANDATORY: default smart typography rewrote `[**--daemon**]` into an
  en-dash `–daemon` in SYNOPSIS (correctness bug — option flags must
  render literally). Caught in the render check.
- Verified: all six groff -man clean AND man-db pipeline green (gzip +
  `man --local-file`, headers/NAME/SYNOPSIS render as intended).
- At package build: dh_installman installs + gzips into
  /usr/share/man/man{1,5,7}/ automatically — no manual gzip, no
  Build-Depends: pandoc (roff is committed; pandoc is only the regen
  recipe for editors).

## Fresh-Kali VM leg (runbook — run IN ORDER on the pristine box)

0. SNAPSHOT the VM immediately post-first-install. Everything below is
   replayable from this state without reinstalling.
1. Interpreter gate: `python3 -V` — must be >= 3.12 (Kali current ships
   3.14; cp wheels all cover it — chromadb via abi3).
2. Pre-install audit (before apt touches anything; deb file in hand):
   DEB=./daharness_0.1.0_amd64.deb; mkdir -p /tmp/da-audit
   `dpkg-deb -c $DEB | grep frameit` → compiled .so ships in-tree;
   `dpkg-deb -c $DEB | grep share/man` → eight .gz man pages;
   `dpkg-deb -c $DEB | grep /etc/daharness/` → conffiles under /etc/.
   `dpkg-deb -x $DEB /tmp/da-audit` extracts WITHOUT installing, then
   `file /tmp/da-audit/usr/share/daharness/listeners/plugins/frameit.so`
   proves ELF x86-64 (the compile-gate decision, byte-level).
   `dpkg-deb -f $DEB Depends` / `-f $DEB Conffiles` → the control lane.
3. `apt install ./daharness_*.deb` — apt must resolve the Depends lane
   (python3-impacket, python3-scapy, nmap, ...). Record which core pins
   ride apt here. apt-cache policy python3-impacket python3-mcp
   python3-pymetasploit3 python3-psycopg python3-pg8000 — capture versions.
4. Import floor on the INSTALLED tree, system python, apt-supplied deps
   (the real deb-lane floor, unlike this box's bare-venv run):
  in-repo `packaging/l2_import_floor.py`: DAHARNESS_TREE=/usr/share/daharness
  (floor PY defaults to the invoking interpreter) — expect 89/89 zero-bad
  (deb tree counts fewer than the dev-tree 105 because the deb ships the
  TREE_DIRS allowlist only). VM-MEASURED (2026-10-20, 4 vCPU/4GB): 73 ok /
  16 lazy / 0 bad in 63s at a 300s budget. The historic >360s timeouts
  were a FLOOR BUG, not VM weakness — `vendor/` is in SKIP_DIRS so the
  pip-closure probes never enumerate. Report is end-buffered: a timeout
  kill yields NO partial output and the interpreter workers survive
  (root PIDs — kill them by PID before re-running, or you stack floors
  and max the box).
5. frameit gate on the installed path: python3 -c CDLL probe of
   /usr/share/daharness/listeners/plugins/frameit.so; grep .so mtime sane.
6. Conffiles: dpkg-query -W -f='${Conffiles}\n' daharness; precedence test
   per man(1) CONFIGURATION: set a marker var in /etc/daharness/daharness.env
   and confirm the service sees it — the env file is systemd-native now
   (EnvironmentFile= in the units, 2026-10-20 wiring; the old
   Environment=DAHARNESS_ENV var was inert dead weight, bootstrap only
   loads <tree>/.env).
7. systemd: `systemctl daemon-reload && systemctl enable --now daharness`;
   `systemctl status` green; journalctl -u daharness -f → startup sequence:
   wordlist preflight → ZAP → gateway on 5000 → msfrpcd handshake → Brain
   scan COMPLETES then socket binds. Chroma rides along:
   `systemctl status daharness-chroma` green and `ss -ltn | grep :9000`
   (the vendored chroma server is the registry backend; the daemon unit
   Wants/After it and tolerantly waits up to 20s for the port).
8. Socket probe — REAL connect(), never Path.exists() (stale-socket
   pitfall): python one-liner connect() to /run/daharness/brain.sock.
   Operator lanes (kernel/REPL CLIs you run as yourself) need group
   membership: `usermod -aG daharness $USER` + re-login — RuntimeDirectory
   is 0770 daharness:daharness and the socket binds group-shareable.
8b. Re-index (fresh deb ships an EMPTY chroma registry): `daharness-index`
    — probes chroma + the Ollama embed model first (exact fix on failure),
    then embeds the ~97-tool universe into the collection (≈ a minute).
    Run it BEFORE the step-9 discovery smoke; an unindexed registry makes
    /tools/search return nothing (404s on /tools/execute) and that is the
    "fresh install looks broken" trap, not a bug. `--clear` rebuilds.
9. Gateway: curl http://127.0.0.1:5000/health (always-open exempt
   endpoint); POST /tools/search top-k smoke WITH the installed key:
   `curl -sS -H "X-API-Key: $(grep -oP '(?<=^GATEWAY_API_KEY=")[^"]+' /etc/daharness/daharness.env)" -H "Content-Type: application/json" -d '{"intent":"port scan","top_k":3}' http://127.0.0.1:5000/tools/search`
   (semantic lane needs the vendored chromadb — proves it; a 401 means
   the gateway didn't see the conffile key through EnvironmentFile=,
   which is F2 regressions in one probe).
10. REPL one-shot: `daharness-repl --selftest` (or equivalent) from a
    fresh shell; registry index count ≈ the 97-tool universe.
11. pytest lane (needs dev tree copied in — tests/ are amputated from the
    deb): full 42-file suite on the VM. PREDICTION to verify: this box's
    35 passed / 2 failed should go greener here — the two failures were
    pip-only-absent pymetasploit3 + chromadb; VM has apt pymetasploit3 +
    vendored chromadb, so test_tool_tags collection may finally pass.
12. impacket arbiter re-run on VM's python3-impacket version: import 8/8
    internals + nthash ground truth (8846f7eaee8fb117ad06bdd830b7586c).
13. Man leg: `man daharness daharness-repl daharness-kernel daharness-pg
    daharness.env daharness-tools daharness-safety` — all render;
    `whatis daharness` hits.
13b. Optional engagement-Postgres lane (deliberate; drivers ride Suggests,
    server provisioned on demand): `sudo apt install -y ./daharness_*.deb
    --install-suggests` (or bare `sudo apt install postgresql`), then
    `sudo daharness-pg init` — dedicated 'daharness' cluster on 5433
    (msfdb's main cluster on 5432 untouched in both directions), harness db
    + lane roles + per-lane passwords into /etc/daharness/pg.env; restart
    `daharness daharness-kernel`, probe:
    PGPASSWORD=$(grep ^HARNESS_DB_PASSWORD_REPL /etc/daharness/pg.env |
    cut -d= -f2) psql -h 127.0.0.1 -p 5433 -U repl_lane -d harness -c
    'select 1' → expect 1. Journal lane then writes PG rows on the next
    dispatch; `daharness-pg stop` drops the lane back to the SQLite stores
    without losing the audit trail. Skip this step = lane silently off
    (fresh-deb experience unchanged).
14. Lifecycle: `apt purge -y daharness` → conffiles purge prompt, verify
    /var/lib/daharness policy (leftover? documented?), snapshot-replay to
    reinstall cleanly. This validates the engagement one-purge design
    promise end-to-end.

## Debian build lane (debian/ authored — first build runs on the VM)

The layer-2 gate on the VM is GREEN (floor `bad: []` with system python
after the frameit compile) — graduated to the build lane. Files authored:

- `debian/source/format` = 3.0 (native): no orig tarball, tree-is-the-source.
- `debian/changelog` → version **0.1.0+pkg1** (drives the artifact name).
- `debian/control`: Build-Depends debhelper-compat (= 13) + gcc;
  Rules-Requires-Root: no; depends lane = the 21 apt-mapped core names
  (python3-bs4/cryptography/dnspython/dotenv/fastapi/httpx/impacket/mcp/
  paramiko/prompt-toolkit/psutil/pyasn1/pydantic/pymetasploit3/pymysql/
  requests/scapy/starlette/urllib3/uvicorn) + nmap;
  Recommends metasploit-framework/owasp-zap/wordlists (heavy, honest
  degrade); Suggests python3-pg8000 + python3-psycopg (the decided opt-in
  postgres lane) + masscan (operator opt-in) + python3-pip (vendored-wheel
  future lane).
- `debian/rules`: override_dh_auto_build = the frameit gcc one-liner (the
  layer-2 landmine, compiled INTO the deb); override_dh_auto_install =
  ship-inventory allowlist copy into /usr/share/daharness (daharness utils
  auxiliaries payloads listeners encoders evasion owui-tools + *.py +
  .env.example), /etc conffile, three /usr/bin wrappers, AND the layer-2
  floor driver cherry-picked to /usr/share/daharness/packaging/ so the
  post-install audit (runbook step 4) runs without the git/zip tree.
  `dh_installsystemd --no-start` — units are auto-ENABLED but NOT
  started on install (system + kernel + chroma units ship via the
  staging tree; KALI PRESET POLICY, 2026-10-20 decoded:
  /usr/lib/systemd/system-preset/99-default.preset carries
  `disable *.service` and preset rules are FIRST-match-wins in
  ascending filename order — that is why Kali's whitelist is 95-kali
  and the catch-all veto is 99). The shipped
  `packaging/systemd/98-daharness.preset` slots between 95 and 99 and
  re-enables all three units during deb-systemd-helper's first-install
  `systemctl preset` pass (wants symlinks are helper-runtime state —
  never staged in the deb, so `dpkg-deb -c | grep wants` is empty BY
  DESIGN). Opt-out: `ln -sf /dev/null
  /etc/systemd/system-preset/98-daharness.preset`. Units installed
  BEFORE the preset fix carry helper state recording the veto no-op and
  stay disabled — one-time `systemctl enable daharness
  daharness-chroma daharness-kernel` un-sticks them; runbook step 7
  (`systemctl start` / `enable --now`) starts them and is idempotent on
  an already-enabled unit. Deliberate.
- New unit entrypoints in `packaging/bin/`: daharness (bootstrap.py),
  daharness-kernel (tool_repl.py --kernel), daharness-repl (tool_repl.py).
- User-profile units ship as /usr/share/doc/daharness/systemd-user/
  examples (not enabled) — profile choice is per-deployment (decided).
- apt-lane notes: repo candidate python3-impacket now 0.13.0+git20251120
  (repo moved since the layer-3 table snapshot — the VM installs the
  candidate, the installed-tree floor arbitrates). python3-mcp 1.26.0 +
  python3-pymetasploit3 1.0.3+git ride Depends with snapshot-compat
  PROBES PENDING: if the installed-tree floor or the /mcp endpoint smoke
  fails, they join the vendored set next build (honest, already decided).
- Vendored-wheel lane MECHANICS (decided 2026-10-20, after the daemon
  exit-1 smoke fail): rules vendoring step runs `pip install --target
  <staging>/usr/share/daharness/vendor chromadb==1.5.9
  pydantic-ai-slim[openai]==2.35.0` + `compileall -q -f` bytecode pass
  (--no-compile saved build seconds but charged every import the full
  source parse; VM-proven 2026-10-20 floor blow-up), (PEP-668-clean:
  private dir, Build-Depends python3-pip, network needed at build); the
  three bin wrappers export
  `PYTHONPATH=/usr/share/daharness` so the tree-root `sitecustomize.py`
  arms at interpreter startup and PREPENDS <tree>/vendor — the exact-pinned
  closure WINS overlaps (order PROVEN empirically twice: script-dir
  sitecustomize pickup does NOT fire on py3.13/3.14; and the original
  append order was killed by the VM 2026-10-20 smoke — apt's partial
  `python3-opentelemetry-api` 1.44.0 shadowed `opentelemetry.attributes`
  and broke chromadb's exporter chain, so "apt wins overlaps" is dead:
  a partial apt copy of the same namespace family is worse than none).
  Inert when vendor/ is absent (dev trees stay pristine). Floor arbitrates any version skew (apt pydantic vs
  vendor-closure minimums) — post-install floor is the judge.
  ORDERING GOTCHA (proven on VM 2026-10-20): the vendoring step MUST live
  in override_dh_auto_install, NOT override_dh_auto_build — dh's implied
  sequence runs dh_prep BETWEEN the two overrides and dh_prep `rm -rf`s
  debian/daharness wholesale; wheels installed in the build override are
  wiped before dh_auto_install re-created the staging tree (symptom:
  deb byte-identical with and without vendoring). Pin is
  `pydantic-ai-slim[openai]==2.35.0` — SLIM lacks the openai optional
  group and the Ollama model raises ImportError at secretary init
  (VM-proven 2026-10-20: gateway died at _init_secretary_agent).
- debhelper is NOT on this dev box (candidate 14.5, compat 13 declared):
  the build belongs to the rootful VM — `sudo apt install -y debhelper
  dpkg-dev make gcc` then in the repo root `dpkg-buildpackage --no-sign
  --build=binary`
  → `../daharness_0.1.0+pkg1_amd64.deb`, then runbook step 2 becomes
  runnable against a REAL artifact and steps 3-14 proceed.

- [2026-11-30] VM floor graduated: frameit compiled on the VM, layer-2
  driver reports `bad: []` (user-verified on system python). Gate
  crossed — build lane unblocked.
- [2026-11-30] debian/ build lane authored + executable: control/rules/
  changelog/manpages/postinst/copyright + packaging/bin wrappers.
  Parse checks green on this box (changelog, make -n); real build
  deferred to the rootful VM (debhelper absent here).
- [2026-11-30] Vendored-pair honesty pass: control Description corrected —
  chromadb/pydantic-ai-slim are NOT in the first build's tree copy; they
  ride the pip lane in /usr (their imports fail=OK at the installed-tree
  floor until vendoring lands as a follow-up build).

## Progress log
- [done 2026-10-20] **VM teardown forensics: three sibling bugs, live-fired
  and fixed** — after the _child_log_fds fix landed, the full systemd
  journal window decoded the rest of the chain (main killed at
  11:21:33, "State 'stop-sigterm' timed out", fresh PPID-1 msfrpcd per
  cycle, ZAP never listening):
  1. **Unprotected boot window, deeper than thought**: handlers-before-
     launch converted mid-boot SIGTERM into a *pending* shutdown, but
     main still sat through the remainder of launch_all (60s ZAP wait)
     while systemd's TimeoutStopSec=30 SIGKILLed it anyway — children
     orphaned again. Fix: the launch is raced against the shutdown
     event (FIRST_COMPLETED in run_framework); a TERM arriving
     mid-launch aborts the remainder and goes straight to stop() —
     verified live: stop 4s into a boot completes in 1.2s with
     Result=success instead of the 30s timeout-kill.
  2. **msfrpcd self-daemonizes**: the tracked launcher exited right
     after fork and the ruby daemon reparented to PID 1, outside every
     stop() reap (its own "already running; connecting to it" path then
     made each boot attach to the previous orphan). Fix: spawn with
     -f (foreground); stop() now reaps it like the Brain/ZAP logs
     ("all-reaped" on the VM post-stop, no left-over-process warnings).
  3. **ZAP never came up on the deb**: zap_home is created under
     framework_root, but the service user is 'daharness' and
     /usr/share/daharness is root-owned — PermissionError killed the
     coroutine BEFORE its "[+] Starting ZAP" log (nothing in the log,
     empty /tmp/zap.log, 60s burn, silent). Fix: $ZAP_HOME override,
     else <state dir>/.zap_home (/var/lib/daharness/.zap_home).
     Verified: ZAP listening post-boot and reaped with the rest.
  Deployed via paramiko SFTP + sudo install; sha256 of the deployed
  file matched the working tree. Full boot→stop cycles on the VM are
  clean: ExecMainStatus=0, zero children (Brain/msfrpcd/ZAP) after
  stop, NRestarts=0.
- [done 2026-10-20] **bootstrap crash: 'FrameworkLoader' object has no
  attribute '_child_log_fds'** — killed daharness.service on the VM
  after a fresh install. Root cause: stop()'s reap loop popped
  `_child_log_fds` directly, but the table is created lazily by the
  spawn sites (MSF/ZAP/Playwright) — the Brain's spawn NEVER registered
  an entry. On the deb (ZAP launcher absent, MSF not installed) the
  Brain is the only child, so any teardown — SIGTERM, or stop() from
  run_framework's finally after a launch error — hit the missing
  attribute; the AttributeError also masked whatever launch error got
  it there. Fix: getattr-tolerant reap in stop() + the Brain's spawn
  site registers its /tmp/brain.log fd (mirroring the other sites,
  closing a standing fd leak for the daemon's lifetime). Simulated
  both paths (unregistered child, registered fd close+drain) green.
- [done 2026-10-20] **packaging gap: replkit/ not staged** — first VM
  reinstall hit "No module named replkit" immediately on
  daharness-repl: the tree-copy loop in debian/rules staged the other
  ALLOWED_TOOL_ROOTS + daharness/utils but not the `replkit` package
  that tool_repl.py imports top-level (daharness-repl + the kernel unit
  both exec tool_repl). Fix: replkit joins TREE_DIRS. Static audit of
  shipped-code imports confirms replkit was the ONLY unshipped top-level
  tree imported by shipped code (apk/binaries/devdocs/dropbox/knowledge/
  pcaps/scripts are data lanes, never imported). evasion/ was NOT the
  gap — staged since pkg1; its absence would show as discovery misses,
  not an import error.
- [done 2026-10-20] **Secretary chat lane trimmed from the packaged
  build** — answers "do we need a secretary model headless?": no. The
  LLM in deb mode is EXTERNAL (Open WebUI / gateway-MCP client);
  bootstrap's interactive branch (index + `_chat` + double-Ctrl+C
  handler) collapses, so bare `daharness` now daemonizes exactly like
  `--daemon` (logged). SECRETARY_MODEL dropped from the packaged conffile
  (it was unread by every packaged lane); EMBED_MODEL + OLLAMA_BASE_URL
  stay (registry/memory lanes read them; one `daharness-index` pass still
  feeds the chroma registry — the operator re-index wrapper, below). pydantic-ai-slim
  vendor STAYS: ToolRegistry.__init__ constructs the agent object at
  boot (VM-proven ImportError otherwise) even though nothing headless
  runs a turn. In-tree interactive secretary remains available via
  `daharness.core --chat` (dev tree). tools(7) framework-loop section +
  daharness(1) OPTIONS + env(5) rewritten to the headless truth.
- [done 2026-10-20] **daharness-index(1) operator re-index wrapper** —
  the runbook had a gap: fresh deb ships an EMPTY chroma registry and
  step-9's discovery smoke would 404/never-match ("fresh install looks
  broken"). The wrapper probes chroma + Ollama/embed first (prints the
  exact fix: systemctl start daharness-chroma / ollama pull
  nomic-embed-text), sources the system conffile for its knobs, then
  execs `python -m daharness.core "$@"` with the PYTHONPATH=<tree>
  vendor lane armed. Writes only through the chroma HTTP server → runs
  as any user, no sudo. New daharness-index.1; runbook step 8b; SEE ALSO
  links in daharness(1)/daharness-repl(1).
- [done 2026-10-20] **Optional engagement-Postgres lane shipped
  (daharness-pg)** — operator-decided pull-forward of the §7 "arrives with
  team mode" doctrine (user: "huge plus, optional command to start up").
  New `/usr/bin/daharness-pg` (init|start|stop|status) provisions a
  DEDICATED pg_createcluster `daharness` on **5433** — msfdb's `main`
  cluster on 5432 untouched in both directions; creates the `harness` db,
  runs the (now-installed) init bundle with ON_ERROR_STOP=1, mints random
  per-lane passwords into `/etc/daharness/pg.env` (0640 root:daharness,
  reused on re-init; rotation = move file aside + re-init). Units gain
  tolerant `EnvironmentFile=-/etc/daharness/pg.env` (daemon + kernel);
  conffile carries the commented HARNESS_DB_* doc block; control Suggests
  +postgresql; new daharness-pg(1); env(5)/safety(7)/daharness(1) updated;
  runbook step 13b + lifecycle/purge note (pg.env is operator data).
  Untouched until an operator runs init: absent postgres = lane silently
  off on the SQLite stores (unchanged fresh-deb experience, §7 honest gap
  honored).
- [2026-10-20] **dh-enable gap ROOT-CAUSED + preset auto-enable shipped**
  (commits `0ec74bd` + `0847b70`): postinst expansion was always correct
  (dh_installsystemd/14.5); the veto is Kali policy —
  `/usr/lib/systemd/system-preset/99-default.preset` = `disable
  *.service`, and preset rules resolve FIRST-match in ascending filename
  order (whitelist at 95, catch-all veto at 99; a `zz-*` name sorts
  last and is never consulted — proven by "Preset files say disable
  daharness.service" under SYSTEMD_LOG_LEVEL=debug). Fix:
  `packaging/systemd/98-daharness.preset` slots between 95-kali and
  99-default; deb-systemd-helper's first-install path
  (`debian_installed()` = helper state file absent → `systemctl preset`
  branch) then enables the units with zero operator steps. VM-validated:
  `systemctl --preset-mode=enable-only preset daharness*` created all
  three wants symlinks, `is-enabled` = enabled ×3. VMs installed before
  this commit: one-shot `systemctl enable daharness daharness-chroma
  daharness-kernel` (helper state recorded the veto permanently).
  Also learned the hard way: `dpkg-deb -c | grep wants` is EMPTY BY
  DESIGN — dh never stages wants links; deb-systemd-helper owns them.
- [2026-10-20] **Floor GREEN on the VM post-vendor-skip** (`f6ef44a`):
  89 modules — 73 ok / 16 lazy / **0 bad** — in **63s** (300s budget)
  on the resized 4 vCPU/4GB box; report /tmp/da-l2-floor.json. The old
  >360s double-timeout pattern (2 AND 4 cores) is fully explained by
  the vendor-closure enumeration bug, not VM sizing.
- [2026-10-20] **Floor blow-up root-caused (MY bug), not VM weakness**: the
  2-core timeout pattern persisted at 4 cores because the floor's
  ship-module walk had no vendor exclusion — the deb tree's vendored
  closure turned the audit into thousands of `vendor.*` `pip`-dep probes
  (15s cap, sequential; floor children env-stripped too — env inherit
  fixed). Floor now skips `vendor/` and inherits os.environ; vendor gain
  a `compileall` bytecode pass (deb ~+0% source-parse charge removed).
  STILL OPEN→SOLVED: the "dh enable gap" was never a dh bug.
  dh_installsystemd enable hook landed deb-systemd-helper logic in
  postinst correctly, but Kali's preset policy vetoed enablement
  (see the dh-enable entry below in this log; fixed via
  packaging/systemd/98-daharness.preset, validated on the VM).
- [2026-10-20] **FULL STACK GREEN on the VM** (direct SSH loop, no
  relay): health `{"status":"ok"}` on 0.0.0.0:5000, Brain socket ready at
  /run/daharness/brain.sock, vendored chroma serving at 9000 (systemd
  unit active), MSF RPC indexed, frameit CDLL gate ok, openai-3.35.1
  resolved by extra-group pin. openai missing surfaced as gateway death
  at _init_secretary_agent — vendor pin changed to
  `pydantic-ai-slim[openai]==2.35.0`.
- [2026-10-20] **VM sizing verdict (measured)**: 2 vCPU / 2GB RAM does
  NOT carry the stack + validation lane. Measured RSS: daemon 272MB +
  Brain 240MB + chroma 140MB (+ msfrpcd Ruby) ≈ 1.1GB steady before any
  tool call; kswapd0 banked 12s CPU (swap churn). The import floor
  fans out interpreter-per-module probes loading onnxruntime/tokenizers/
  grpc — floor exceeded 360s twice (rc=124; report is end-buffered so no
  progress fraction; timeout-killed workers SURVIVE as root PIDs — kill
  them explicitly). Stacked floor runs maxed both cores. Recommendation:
  4 vCPU / 4-6GB, OR arbitrate the floor off the VM (static audit runs
  on the dev box against `dpkg-deb -x` of the artifact — same verdict,
  zero VM tax).
- [2026-10-20] **Daemon boots past chromadb; Brain socket + chroma server
  wired**: journal showed the daemon ACTIVE with a functional vendored
  chromadb (registry dials HttpClient), then two lane gaps: Brain bind
  FileNotFoundError (tree-root run/ absent in the deb; brain.log had 234
  tools registered — vendoring healthy) and nothing listening on 9000.
  Fixes shipped: units get `Environment=BRAIN_SOCKET=/run/daharness/brain.sock`
  (RuntimeDirectory was ALWAYS meant to be the socket home per the unit
  comment) + `EnvironmentFile=/etc/daharness/daharness.env` (the
  DAHARNESS_ENV var was inert — bootstrap loads only <tree>/.env); new
  `daharness-chroma` wrapper + unit serve chroma from vendor/bin/chroma
  (dockerless lane); daemon unit Wants/After chroma with a tolerant 20s
  port-wait ExecStartPre; rules install both; wrapper comments corrected.
- [2026-10-20] **openai optional group missing (pydantic-ai-slim SLIM)**:
  gateway died at _init_secretary_agent — pydantic_ai/models/ollama.py
  raises ImportError without the `openai` package. Vendor pin changed to
  `pydantic-ai-slim[openai]==2.35.0` (extra group syntax; pip resolves
  the openai version against the slim's own constraints).
- [2026-10-20] **Vendor order flipped to PREPEND (apt-wins-overlaps dead)**:
  rebuild #2 rode 343MB of wheels (deb 455KB → 63MB), daemon start still
  exit 1 — ImportError `_clean_attribute_value` from apt's
  python3-opentelemetry-api 1.44.0 (partial copy, no sdk/exporters on the
  box; pulled by unrelated Kali tooling, UNDECLARED by our control). Under
  append order apt shadowed `opentelemetry.attributes`. sitecustomize now
  PREPENDS vendor; exact-pinned closure wins, floor still arbitrates.
- [2026-10-20] **Vendor step wiped by dh_prep — fixed, direct SSH loop up**:
  paramiko runner to the VM landed; tree already at 5372bb9 (user pushed).
  Rebuild #1 green but the deb was byte-identical to the pre-vendor build —
  the wheels never rode. Root cause: pip --target ran in
  override_dh_auto_build and dh's implied dh_prep rm -rf'd the staging tree
  before dh_auto_install. Moved the vendoring step into
  override_dh_auto_install; direct SSH rebuild now the loop (no relay).
- [2026-10-20] **Daemon smoke exit 1 diagnosed at code level**: the deb
  tree imports chromadb at TOP level (daharness/registry.py:22) and the
  daemon boot imports the registry (bootstrap.py:24/154/914) — on build 1
  (no vendoring) that is an uncaught ModuleNotFoundError → exit 1. Fix
  shipped same day: rules now VENDORS chromadb/pydantic-ai-slim wheels via
  pip --target (PEP-668-clean probe validated) and a committed
  sitecustomize.py appends <tree>/vendor (apt wins overlaps, vendor fills
  gaps; inert absent vendor/). Rebuild needed; floor re-arbitrates.
- [2026-10-20] **FIRST BUILD GREEN on the VM**: clean-zip extract (previous
  extraction residue — the suspected empty `debian/compat` ghost — died with
  the rm -rf; unzip-over-the-top had been preserving it) →
  dpkg-checkbuilddeps silent + dpkg-buildpackage green →
  `../daharness_0.1.0+pkg1_*.deb`. Runbook step 2 (dpkg-deb audit) is now
  runnable for real. VM workflow: zip-per-commit until `gh auth login`
  (device flow) replaces it. Rebuild note: if artifacts/staging ended up
  root-owned from a sudo run, `sudo rm -rf debian/daharness debian/.debhelper`
  before the next non-sudo build.
- [done 2026-10-20] man pages option B: six thin sources authored in
  packaging/man/ (three man1 wrappers, one man5, two man7).
- [done 2026-10-20] EMBED_MODEL single knob: registry.py module _EMBED_MODEL +
  class default + native /api/embed fallback; api_gateway explicit pass dropped;
  documented in .env.example. memories.py:49 untouched per v2 verdict.
  staging tree only [dev-tree: port to dev copy]
- [done 2026-10-20] api_gateway load_dotenv comment contradiction: false comment
  sentence deleted, override=True stays.
- [done 2026-10-20] staging-tree amputation to ship shape (inventory above).
- [done 2026-10-20] dependency-mapping smoke layers 0/1/3 + impacket arbiter
  (section above): AST scan (urllib3 undeclared→declared, python-nmap dead pin
  →dropped, brotli/zstandard stay soft), dry-run float diff (12/23 float,
  mcp+pydantic-ai-slim are major-jump risks), apt baseline (18/23 satisfied,
  mismatch table), impacket 0.14.0.dev0 arbiter green on this box (8/8
  internals import; nthash bit-identical 0.13.1 vs 0.14.0.dev0 vs
  pycryptodomex MD4 ground truth; 35 passed / 2 failed — failures are
  pip-only apt-absent dists, zero impacket-version failures).
- [done 2026-10-20] pyproject dep-list hygiene executed in this tree:
  python-nmap pin deleted, urllib3>=2.0 declared; requirements.txt mirror
  export python-nmap line deleted. [dev-tree: mirror both]
- [done 2026-10-20] supply split decided (see [decided] below) with the
  repo-vs-installed correction: apt-cache search verified chromadb,
  pydantic-ai-slim truly unpackaged (vendored set shrinks 5→2);
  python3-mcp / python3-pg8000 / python3-pymetasploit3 exist in Kali repos.
- [done 2026-10-20] pg8000 moved core -> `db` extra in pyproject, symmetric
  with psycopg (both lanes import with guards that degrade honestly:
  db_client.py::_open_postgres raises _DriverMissing with a "pip install
  pg8000" remediation string; engagement.py:224 try/except ImportError).
  pip lane unchanged ([db] extra now declares it; note: the requirements
  export never listed pg8000 either — pre-existing export gap, harmless
  under the degrading-lane contract).
  [dev-tree: mirror]

- [done 2026-10-20] layer 2 floor on THIS box (section above): bare venv
  --no-deps -e . green; 105-entry import floor 14 ok / 91 lazy / 0 bad
  after repairing the frameit.so gate; wheel availability via PyPI JSON
  (chromadb abi3-manylinux covers cp312/313/314; pydantic-ai-slim py3-any);
  frameit.so landmine found + compile-lane decision banked.
  [dev-tree: nothing to mirror — dev tree already carries frameit.so]
  Probe artifacts: /tmp/da-l2 venv kept for follow-up legs; floor report +
  driver persisted to session files, then moved IN-REPO:
  packaging/l2_import_floor.py (env-parameterized: DAHARNESS_FLOOR_PY
  interpreter, DAHARNESS_TREE tree root, DAHARNESS_FLOOR_REPORT path).
  Both paths verified: clean checkout → exit 1 with the landmine + a
  gcc hint; compiled plugin → exit 0 (14 ok / 91 lazy).
- [done 2026-10-20] man roff compiled: six .md masters → `pandoc
  --standalone --from markdown-smart --to man` → roff .1/.5/.7 committed
  beside the masters; all six groff-clean + man-db render verified; caught
  and fixed the smart-typography SYNOPSIS bug (en-dash --daemon). Regeneration recipe is the pandoc line above — pandoc NOT a
  build-dep. [dev-tree: packaging/man/ lives in the staging tree only]
- [note] tool_repl selftest one-shot NOT runnable under --no-deps (needs
  deps-present env) — it rides the full-install/VM leg with the pytest lane.

## Remaining (ordered)
- [fixed 2026-10-20] **operator shells had no route into the system
  profile — "neither root nor kali reaches the shared state"**. Box-verified
  chain: the conffile reaches systemd units only (EnvironmentFile); operator
  shells resolve constants fallbacks (WS=/usr/share/daharness code dir,
  SOCK=/usr/share/daharness/run/brain.sock — a path nothing ever binds),
  so even ROOT reported brain-down from a ghost path while kali also hit
  the DAC wall (group daharness had NO members — nothing ever granted it).
  Three-part provisioning, verified by rehearsal: (1)
  /etc/profile.d/daharness.sh fills exactly WORKSPACE_ROOT + BRAIN_SOCKET
  into shells that lack them (fixture-tested: fills-when-absent, user
  exports win, missing-conffile no-op, quoted values stripped, GATEWAY_API_KEY
  never leaks); (2) wrappers (daharness/daharness-repl/daharness-kernel)
  source it so non-login runs get the same roots — daharness-index already
  tolerant-sourced the full conffile; (3) postinst grants the daharness
  group to sudo-group members at install (zero escalation — sudo members
  are root-equivalent; usermod rehearsal: grants fresh members, skips
  existing), with `usermod -aG daharness <user>` documented for non-sudo
  operators. Docs: conffile deltas section rewritten (exports win, no
  conffile edits needed), daharness(1) gained an OPERATOR ONBOARDING
  section + FILES entry, env(5) cross-ref; roff regenerated.   Complements the framework_health lane_blocked honesty fix (an out-of-group
  operator now gets an accurate permission report rather than a phantom "down").
- [fixed 2026-10-20] **scope manifests were code knowledge — the deb now
  provisions the lab template the dev tree uses**. The manifest layout
  (in_scope/out_of_scope_assets/policy) and the
  scope/<platform>_<handle>.json naming only existed as a dev-tree file
  (scope/lab_local-lab.json) and an unadvertised convention; `scope on`
  help claimed platform was h1|bugcrowd|intigriti when it is actually
  freeform for operator-authored manifests. Shipped: the template rides
  the deb at /usr/share/daharness/examples/scope/lab_local-lab.json;
  postinst pre-creates the state root's scope/ dir daharness-owned 0770
  and seeds it there (0660, group-editable) — strictly guarded, an
  existing/operator-customized manifest is never stomped, rerun is silent;
  help text (REPL + operator CLI) now says <custom> platforms with the
  author-arm recipe (`scope on local-lab --platform lab`). Rehearsed:
  postinst seed/idempotence/no-stomp over a fake root; E2E against the REAL
  gate — WORKSPACE_ROOT=scratch-copied template, arm('local-lab','lab')
  ok, check_scan/check_send accept the 192.168.56.0/24 CI, refuse 8.8.8.8.
  knowledge/scope_gate.md + daharness(1) (onboarding section + FILES)
  updated; roff regenerated.
- [fixed 2026-10-20] board-auth vars were absent from the packaged env
  surface — .env.example carried only H1 (H1_API_USERNAME/H1_API_TOKEN) +
  Intigriti (INTIGRITI_USERNAME/INTIGRITI_API_TOKEN) while the code also
  reads BUGCROWD_USERNAME (public API, falls back to H1 username) and
  RESEARCHER_USERNAME (last-resort fallback), and daharness.env(5)
  documented none of them, and the conffile — the ONLY channel that
  reaches the unit lanes (brain/MCP) on a deb, since program_scope's
  .env loader points at the read-only checkout — had no rows either.
  Now: env(5) gained a BOARD AUTH KNOBS section (per-var semantics +
  fill-where-the-lane-runs + chmod 0600 advice), the conffile carries
  commented rows, .env.example gained the two missing vars + a
  deb-vs-devtree channel note; roff regenerated.
- [fixed 2026-10-20, hygiene] .gitignore's bare `scope/` pattern silently
  ignored packaging/examples/scope/ — the shipped template could never
  enter git and a fresh-clone deb build would ship nothing. Negation
  `!packaging/examples/scope/` added; template staged.
- [fixed 2026-10-20] kernel unit crash loop — the deb shipped no Jupyter
  closure, so daharness-kernel.service died at its lazy import
  (`ModuleNotFoundError: no module named 'ipykernel'`), Restart=on-failure
  looped, and the unit ended canceled/failed. Fix: Depends lane —
  python3-ipykernel + python3-ipython + python3-jupyter-client (Kali
  rolling builds them against the system python 3.14; the 6.29.5 dev pin
  predates that interpreter, so NOT vendored: the vendor set stays
  chromadb + pydantic-ai-slim per ledger). replkit/kernel_lane gained a
  boot tripwire printing the same remediation string per lane, then
  re-raises, so the unit still fails honestly with a journal hint instead
  of a bare traceback.
- [fixed 2026-10-20] **indexer discovered 0 tools on the deb** — discovery
  hung off WORKSPACE_ROOT, which the system profile pins to the state dir
  (/var/lib/daharness exists as StateDirectory but holds no tool code; the
  six ALLOWED_TOOL_ROOTS pointed into empty space, so `daharness-index`
  minted nothing and every `find_best_tool`/MCP dispatch followed). Split
  the roots declaratively: constants.resolve_framework_root() is the
  __file__-derived CODE checkout (mirrors thebrain's _FRAMEWORK_ROOT; no
  env knob — an override would recreate the phantom-root trap this fixes),
  while resolve_workspace_root() keeps its documented state-only contract
  untouched (run/, ids.db, scratch.db, scope, engagement, cookie_jar,
  .pw-browsers). registry.py: ALLOWED_TOOL_ROOTS, the _resolve_script_path
  allow-list base, the discovery walker's target/rel_path bases and the
  dynamic-import sys.path insert all hang off FRAMEWORK_ROOT now (index,
  REPL and kernel lanes share discover_local_tools, so one switch heals
  all three); kernel 0-tool tripwire prints the code root + the split.
  Sequel to the secretary trim above: SECRETARY_MODEL and
  SECRETARY_MAX_APPROVAL_ROUNDS are no longer module/env knobs either —
  daemon bootstrap cannot run the chat loop; the chat-lane default
  (_SECRETARY_MODEL_DEFAULT) stays in-code and approval rounds moved to
  daharness/agent.py. SECRETARY_MAX_TOP_K / ROUTER_MAX_DISTANCE /
  SECRETARY_TURN_TIMEOUT stay on registry.py (API + MCP turn semantics).
  Verified on the deb-shaped env: WORKSPACE_ROOT=<empty state dir> minted
  184 manifests with every root present, manifests root-relative (no
  state-dir path leak), allow-list resolves inside FRAMEWORK_ROOT and
  refuses outside; system python bare import still lazy-degrades.
- [decided] supply split (2026-10-20, repo-fact corrected):
  (a) VENDORED into the deb — core plumbing the Kali repo truly lacks:
      chromadb (tool-registry vector store) + pydantic-ai-slim (registry
      boot: ToolRegistry.__init__ constructs the in-tree secretary agent
      object even though no headless lane RUNS it — see Progress log
      trim entry). Without these the package fails at boot or loses
      semantic tool discovery; onnxruntime/tokenizers
      weight accepted as the price of self-sufficiency. Layer-2 wheel
      availability for cp312/313/314 feeds the actual build step.
  (b) Suggests/Recommends lane — python3-pg8000 + python3-psycopg for the
      opt-in postgres lane (both code guards verified as honest degraders;
      psycopg also rides the installed python3-psycopg 3.3.5-1); server
      side now shipped as `postgresql` Suggests + the daharness-pg
      provisioner (2026-10-20 — see Progress log).
- [probe, VM leg] repo-packaged-but-version-behind compat checks (apt
  install + API probe, needs a rootful box): python3-mcp 1.26.0 vs pin
  1.29.0 (streamable-HTTP server surface used by api_gateway /mcp), and
  python3-pymetasploit3 1.0.3+git vs pin 1.0.6 (MsfRpcClient surface used
  by payloads/metasploiting.py). If either snapshot lacks the API surface,
  it joins the vendored set; otherwise the deb lane Depends on the apt
  version.
- [done] layer 2 on THIS box — see Progress log; the only leftover is the
  tool_repl one-shot which needs a deps-present env and rides the leg below.
- [next, VM] BUILD on the rootful VM: `sudo apt install -y debhelper
  dpkg-dev make gcc` → in repo root `dpkg-buildpackage --no-sign
  --build=binary` →
  `../daharness_0.1.0+pkg1_amd64.deb`. Then runbook — step 2 (dpkg-deb
  audit) now runs against a real artifact, then `apt install ./…deb`,
  then steps 3-14 (floor with DAHARNESS_TREE=/usr/share/daharness,
  services, smoke, mcp/pymetasploit3 compat probes, pytest lane, purge
  round-trip). Build 2+ VENDORS chromadb/pydantic-ai-slim into the tree
  (rules pip --target + sitecustomize append) — the installed-tree floor
  should show them importable; the lazy-miss window was build 1 only.
- [next, dev-tree mirrors, three]: EMBED_MODEL knob port; dep-list hygiene
  mirror (urllib3>=2.0 + python-nmap drop); the three file-resolution deltas
  (unified .env load order in constants; writable-tree fallbacks in
  resolve_workspace_root() and brain_socket_path()).
- [open] devdocs/burpconfig.json fate (zero refs; operator data — keep as
  /usr/share doc or drop).
- [done 2026-10-20] F1+F2 patch (damage-report 8a): gateway auth now
  armable from the package — conffile gains GATEWAY_API_KEY (postinst
  generates a random key when the placeholder is empty; upgrade conffile
  prompt default 'keep current' preserves it) + GATEWAY_HOST knob pinned
  127.0.0.1 in the system profile; bootstrap GATEWAY_HOST/GATEWAY_PORT
  knobs replace the hardcoded 0.0.0.0:5000 (loopback default, ZAP
  pattern) and api_gateway.run() logs an error on unauth + non-loopback.
  F2: EnvironmentFile=/etc/daharness/daharness.env on daemon + kernel
  units (chroma already had it); inert Environment=DAHARNESS_ENV and
  duplicate BRAIN_SOCKET Environment= lines dropped — the conffile is now
  read by all three units. Docs truth: env(5) LOADING section rewritten
  (previous SEARCH ORDER / $DAHARNESS_ENV claim was never implemented);
  safety(7) gains the bind + auth posture section incl. the F3 exempt-
  endpoints note; user-profile unit path corrected to
  /usr/share/doc/daharness/systemd-user. Residue: .env.example
  OPEN_TERMINAL_URL/KEY commented lines removed (retired lane Sep 18
  2026; the quarantined devdocs README mention stays pending the
  burpconfig-fate ticket). Runbook step 1 Python 3.13 → 3.14 freshness;
  step 9 now carries the X-API-Key header so the smoke probes F2+key in
  one call. Version bumped 0.1.0+pkg1 → 0.1.0+pkg2 (pkg1 was already
  built+smoked on the VM).