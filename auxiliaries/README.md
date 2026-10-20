# auxiliaries/ — recon & access lanes

The recon and access toolkit: scanners (nmap, masscan, amass), web-surface
probing and stateful HTTP, TLS/binary analysis (radare2, jadx), Windows
post-exploitation (impacket), the HackerOne/Intigriti scope integration, and
the framework's own health/doctor tooling. All tools dispatch via
`BRAIN_DISPATCH` unless noted; long-running scanners follow the
background-job pattern (see
[`../utils/README.md`](../utils/README.md#background-job-pattern-background_jobpy)).

## Tool inventory

| Module | Tools | Notes |
| --- | --- | --- |
| `nmap.py` | port/service scanning | NSE script library via `--script` options (`nmap_scripts` lists 600+ installed scripts) |
| `masscan.py` | fast async port scanning | requires root or `CAP_NET_RAW`; background-job triplets |
| `amass.py` | subdomain enumeration | OWASP Amass v5+, passive mode by default |
| `archived_urls.py` | passive archived-URL discovery | Wayback Machine CDX API; bounty-relevant triage (interesting files, parameterized URLs) |
| `burp_mcp.py` | Burp Suite MCP client | drives the operator's running Burp GUI via the PortSwigger MCP BApp's SSE transport (`127.0.0.1:9876`) |
| `cert_tools.py` | TLS certificate generation/clearing | certs for the OOB collaborator |
| `cors_probe.py` | CORS posture + security-header audit | attacker-controlled `Origin` reflection + `null`-origin checks via the per-hop scope-gated HTTP client |
| `db_client.py` | direct-database connect + enumerate | MySQL (pymysql) / PostgreSQL (pg8000) with KNOWN credentials — deliberately not the injection lane (that's sqlmap) |
| `dns_lookup.py` | forward/reverse DNS resolution | feeds the scope workflow (IP blessing); not scope-gated — it never touches the target |
| `framework_status.py` | `framework_health` + `framework_doctor` | health infra up/down; doctor = per-provider can-I-run-X probes (r2/jadx/masscan/msf/scanners/secretary model/snapshot cache) with remediation strings |
| `ftp_recon.py` | FTP/SFTP recon and transfer | banner, anonymous check, listings, authenticated get/put |
| `impacket_suite.py` | Windows post-exploitation | SMB enum/read, secretsdump, psexec/wmiexec/atexec |
| `jadx.py` | APK/dex/jar decompilation | `apk/` drop folder, cached workspaces, grep/read over decompiled sources |
| `ldap_search.py` | LDAP directory queries | OpenLDAP `ldapsearch` wrapper (argv subprocess, no shell) — structured queries the NSE script can't match |
| `playwright_recon.py` | scope-gated rendered-DOM recon | client for the Playwright sidecar |
| `playwright_sidecar.py` | **Service** | headless-Chromium sidecar enforcing the scope gate at the browser request-routing layer (opt-in via `PLAYWRIGHT_SIDECAR=1`) |
| `program_scope.py` | HackerOne/Intigriti scope integration | see deep-dive below |
| `radare2.py` | static binary analysis | `r2pm -ci r2ghidra` for decompilation; memoized by the snapshot cache |
| `smb_scanner.py` | SMB null-session scanning | null session vulnerability scanner |
| `ssh_exec.py` | SSH batch command execution | persistent connection; see also `../utils/paramiko_client.py` |
| `ssrf_probe.py` | parametric SSRF fuzzer | grades responses and out-of-band callbacks (optionally the collaborator's public redirect endpoint) |
| `tls_info.py` | TLS certificate + protocol posture | subject/SANs, versions, ciphers, expiry runway |
| `web_login_brute.py` | session-aware web-login brute-forcing | CSRF-protected form endpoints, token reuse per session |
| `web_probe.py` | concurrent web-surface prober | turns open ports into live HTTP intel (status, title, stack fingerprints) in one envelope |
| `web_session.py` | stateful HTTP lane | `session_get`/`session_post`/`session_request`/`session_upload`; see the deep-dive below |
| `zap.py` | OWASP ZAP HTTP API client | see deep-dive below |

## OWASP ZAP

1. Install ZAP (`sudo apt install zaproxy` on Debian/Ubuntu/Kali — the plain
   `zap` package name does not resolve — or download from the official
   site). Kali's package installs `/usr/bin/zaproxy` / `/usr/bin/owasp-zap`
   (both wrappers for `/usr/share/zaproxy/zap.sh`); the plain-ZAP layout
   (`zap` on PATH or `/usr/share/zap/zap.sh`) also works. For anything else,
   set `ZAP_BIN` to the launcher path.
2. The launcher is resolved automatically in the order: `$ZAP_BIN` → `zap` →
   `zaproxy` → `owasp-zap` (all PATH) → `/usr/share/zaproxy/zap.sh` →
   `/usr/share/zap/zap.sh`.
3. The framework launches ZAP in `-daemon` mode (loopback-only API) and
   manages its configuration automatically. The home directory is pinned to
   `.zap_home/` in the workspace root. ZAP is never run as root — the
   launcher drops to the original user if the framework was started with
   `sudo`. The ZAP *browser-proxy* listener binds `ZAP_PROXY_BIND`
   (default `0.0.0.0`) for upstream proxying; only the daemon's API is
   restricted to loopback.
4. Set `ZAP_API_KEY` in `.env`; it is sent as the `apikey` query parameter on
   every API call.

Crawls are mirrored by `zap_sync_scope`, which puts ZAP itself in protect
mode against out-of-scope hops.

## Playwright Rendered-DOM Recon Sidecar

The scope-enforcing headless-Chromium sidecar for JS-heavy / SPA recon
(`playwright_sidecar.py` + `playwright_recon.py`). It gates **navigations +
fetch/XHR/websockets** through the operator-armed scope gate at the browser
request-routing layer; passive subresources (img/css/font/media/script) are
allowed from anywhere so pages render.

1. Install the Python package and the Chromium browser binary:

   ```bash
   ./venv/bin/pip install playwright
   # IMPORTANT: install the browser INTO THE REPO (gitignored) so the path
   # is workspace-relative and root can find it. The framework runs as root
   # (HOME=/root), where the default ~/.cache/ms-playwright is empty.
   PLAYWRIGHT_BROWSERS_PATH="$(pwd)/.pw-browsers" \
     ./venv/bin/python -m playwright install chromium
   ```

   The browser lands in `.pw-browsers/` (gitignored). The sidecar
   auto-resolves it from `$WORKSPACE_ROOT/.pw-browsers` (falling back to
   this module's repo root) and sets `PLAYWRIGHT_BROWSERS_PATH` at import —
   so it works whether the framework was launched as root or your user.
2. The framework runs as root, so Chromium is launched with `--no-sandbox`
   (the setuid sandbox cannot run as root and would hang the launch).
   Sandbox isolation is kept when running non-root (lab/dev).
3. Enable the sidecar at launch with `PLAYWRIGHT_SIDECAR=1` (off by
   default). Tools: `playwright_fetch` (one-shot rendered-DOM envelope),
   `playwright_crawl` / `playwright_crawl_status` / `playwright_crawl_stop`
   (bounded launch/poll crawl). If the sidecar is down, the tools return a
   clear "not reachable" error — never a faked result.
   `challenge_detected` flags Cloudflare-class interstitials honestly
   (vanilla only — no stealth patches).
4. Auth'd crawling: set `PLAYWRIGHT_STORAGE_STATE` to a Playwright
   `storageState` JSON path (env / deploy-time injection only — never a
   tool argument).

## HackerOne / Intigriti Scope Integration (`program_scope.py`)

Pulls a program's structured scope, scope exclusions, weakness list, and
policy text from the HackerOne Hacker API v1 (and Intigriti's API) and turns
them into a machine-readable manifest the secretary and scan tools consult.
Caches manifests to `scope/<handle>.json`.

Framework tools:

- **`load_program_scope`** — fetch (or load cached) program scope: in-scope
  assets (typed: URL/WILDCARD/DOMAIN/CIDR/IP/ANDROID/IOS/BLOCKCHAIN with
  `max_severity` and CIA requirements), out-of-scope assets, excluded report
  categories, reportable weakness/CWE allowlist, and policy text. Also
  writes the workspace `.scope` file so `subdomain_enum` auto-filters
  against the real HackerOne scope.
- **`check_scope`** — test whether a target is inside the program's
  authorised scope *before* running any scanner. Out-of-scope asset matches
  always win over in-scope wildcards.
- **`check_reportable`** — test a candidate finding's category/CWE against
  the program's excluded categories and weakness allowlist before filing,
  to avoid burning platform reputation on N/A reports.
- **`program_hacktivity`** — fetch the program's hacktivity feed for
  duplicate-checking. Works without credentials (public feed); includes a
  behavioral guard against silent filter-ignoring.
- **`search_programs`** — keyword search ACROSS the boards' program listings
  (HackerOne authed index, Intigriti PAT list; Bugcrowd exact-handle probe —
  that lane has no public listing API). Rows carry platform/handle/name and
  bounty-relevant flags (`offers_bounties`, per-asset eligibility, tiers);
  `with_assets=True` pulls each match's manifest for a compact asset +
  bounty summary. Also exposed operator-side as `scope search <kw>` in the
  Tool REPL. Dollar bounty tables are not structured on any lane — they live
  in each program's policy prose.

**Authentication:** The structured-scope endpoints require a platform API
token. HackerOne uses Basic auth — set `H1_API_USERNAME` and `H1_API_TOKEN`
in `.env`. `program_hacktivity` works without credentials.

**Intigriti support:** `program_scope.py` also pulls Intigriti program scope
and hacktivity via `INTIGRITI_USERNAME` + `INTIGRITI_API_TOKEN`; manifests
cache to `scope/intigriti_<handle>.scope`.

## Stateful HTTP Lane (`web_session.py`)

`session_get` / `session_post` / `session_request` apply the universal
cookie jar's state (see
[`../utils/README.md#the-universal-cookie-jar--stateful-http-lane`](../utils/README.md#the-universal-cookie-jar--stateful-http-lane-cookie_jarpy))
to a per-call `requests.Session` via `gated_request(session=...)` — **every
redirect hop still passes the operator-armed scope gate**; the jar never
bypasses it. `session_post` auto-injects CSRF: form field into the body +
`X-CSRFToken`-style header derived from the vault/cookie. A Django login is
three plain calls: `session_get /login/` → `session_post` creds →
`session_get /dashboard/`.

`run_nmap` accepts an optional `shaping=` preset from
[`../evasion/shaping.py`](../evasion/shaping.py) — wire-traffic profiles
(quiet/polite/noisy; decoy/fragment are lab-gated) merged so explicit
operator flags always win. The stateful HTTP lane laced itself the same
session: every `session_*` request now carries a realistic **sticky
per-host** User-Agent (`evasion/webshape.sticky_ua` — same host, same
agent, every call; rotating identity mid-session is how authenticated
servers get suspicious) and honors an optional per-host pacing floor
(`SESSION_HOST_FLOOR`). Caller `User-Agent` headers win; `SESSION_UA=legacy`
restores the old `framework-web-session/1.0` self-identifying marker for
RoE documents that require it.

`session_upload` is the multipart delivery step of the msfvenom file-upload
lane — full behavior (local-input `ValueError` discipline, `file_name`
extension games, `SESSION_UPLOAD_MAX_MB`) is documented in
[`../payloads/README.md`](../payloads/README.md#msfvenom-payload-generation--upload-lane).

## Radare2 + the Analysis Snapshot Cache

`run_r2` is a deterministic tool: analysis is a pure function of (target
bytes, verb/addr/count, settings), so successful runs are memoized at
`run/analysis_snapshots.db` (see
[`../utils/README.md#analysis-snapshot-cache`](../utils/README.md#analysis-snapshot-cache-snapshot_cachepy)),
keyed on the target's **sha256** + op key. Identical repeat queries serve
verbatim with a `_snapshot.hit` stamp — exploring a binary pays `aaa` once
instead of once per call. Scanners (nmap/ffuf/masscan) deliberately don't
share this cache — their results are observations of a changing world.