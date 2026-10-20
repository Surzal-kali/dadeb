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
.vscode, requirements-dev.txt. Remnants: packaging/postgres/init/ (Suggests
conffiles-later), packaging/reference/ (chroma-config.yaml, 10-refresh-stubs.sh,
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
   3.13; cp wheels all cover it — chromadb via abi3).
2. Pre-install audit (before apt touches anything; deb file in hand):
   DEB=./daharness_0.1.0_amd64.deb; mkdir -p /tmp/da-audit
   `dpkg-deb -c $DEB | grep frameit` → compiled .so ships in-tree;
   `dpkg-deb -c $DEB | grep share/man` → six .gz man pages;
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
  (floor PY defaults to the invoking interpreter) — expect 105/105 ok (any "bad" = deb bug).
5. frameit gate on the installed path: python3 -c CDLL probe of
   /usr/share/daharness/listeners/plugins/frameit.so; grep .so mtime sane.
6. Conffiles: dpkg-query -W -f='${Conffiles}\n' daharness; precedence test
   per man(1) CONFIGURATION: set a marker var in /etc/daharness/daharness.env
   and confirm the service sees it (first-existing-file-wins order).
7. systemd: `systemctl daemon-reload && systemctl enable --now daharness`;
   `systemctl status` green; journalctl -u daharness -f → startup sequence:
   wordlist preflight → ZAP → gateway on 5000 → msfrpcd handshake → Brain
   scan COMPLETES then socket binds.
8. Socket probe — REAL connect(), never Path.exists() (stale-socket
   pitfall): python one-liner connect() to /run/daharness/brain.sock.
9. Gateway: curl http://127.0.0.1:5000/health; POST /tools/search top-k
   smoke (semantic lane needs the vendored chromadb — proves it).
10. REPL one-shot: `daharness-repl --selftest` (or equivalent) from a
    fresh shell; registry index count ≈ the 97-tool universe.
11. pytest lane (needs dev tree copied in — tests/ are amputated from the
    deb): full 42-file suite on the VM. PREDICTION to verify: this box's
    35 passed / 2 failed should go greener here — the two failures were
    pip-only-absent pymetasploit3 + chromadb; VM has apt pymetasploit3 +
    vendored chromadb, so test_tool_tags collection may finally pass.
12. impacket arbiter re-run on VM's python3-impacket version: import 8/8
    internals + nthash ground truth (8846f7eaee8fb117ad06bdd830b7586c).
13. Man leg: `man daharness daharness-repl daharness-kernel daharness.env
    daharness-tools daharness-safety` — all render; `whatis daharness` hits.
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
  `dh_installsystemd --no-start` — services are enabled but NOT started on
  install (system + kernel units ship via the staging-tree install; the
  operator starts them, runbook step 7: `systemctl start daharness` or
  `enable --now`, which is idempotent on an already-enabled unit).
  Deliberate.
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
- [decided] supply split (2026-10-20, repo-fact corrected):
  (a) VENDORED into the deb — core plumbing the Kali repo truly lacks:
      chromadb (tool-registry vector store) + pydantic-ai-slim (secretary
      agent loop). Without these the package fails its basic promises
      (semantic tool discovery, the agent loop); onnxruntime/tokenizers
      weight accepted as the price of self-sufficiency. Layer-2 wheel
      availability for cp312/313/314 feeds the actual build step.
  (b) Suggests/Recommends lane — python3-pg8000 + python3-psycopg for the
      opt-in postgres lane (both code guards verified as honest degraders;
      psycopg also rides the installed python3-psycopg 3.3.5-1).
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
  round-trip). Expect lazy misses for chromadb/pydantic-ai-slim at the
  installed-tree floor — they are NOT in the first build's tree (pip
  lane covers them; vendoring is the follow-up build once mechanics
  prove out).
- [next, dev-tree mirrors, three]: EMBED_MODEL knob port; dep-list hygiene
  mirror (urllib3>=2.0 + python-nmap drop); the three file-resolution deltas
  (unified .env load order in constants; writable-tree fallbacks in
  resolve_workspace_root() and brain_socket_path()).
- [open] devdocs/burpconfig.json fate (zero refs; operator data — keep as
  /usr/share doc or drop).