# Appendices — Framework Tool Schema

Complete reference for every tool in the framework registry. 208 tools
across the indexed roots — `auxiliaries`, `payloads`, `listeners`, `utils`
bear them (`encoders/` + `evasion/` are indexed too but currently mint
none: resolvers/loaders, not decorated entry points). All `BRAIN_DISPATCH`
transport unless marked otherwise. Parameters listed as
`name (type, default)` — `(req)` = required.

## ids.db — SQLite database

One SQLite database file at the workspace root (`ids.db`). Shared:
`utils/sessions.py:DatabaseManager` owns `targets` / `sessions` / `notes`;
`daharness/findings.py:FindingStore` owns `findings`. Concurrent access from
the gateway, secretary, and MCP clients is handled with busy-timeout + retry.

`daharness.findings.ensure_ids_db()` creates the file and all five tables on
first call — bootstrap's `launch_all` runs it as a preflight, and
`framework_health` calls it so a fresh checkout reports the DB as up.
Idempotent on an existing database.

### targets table

| Column     | Type    | Notes                  |
|------------|---------|------------------------|
| id         | INTEGER | PRIMARY KEY            |
| ip_address | TEXT    |                        |
| port       | INTEGER |                        |
| status     | TEXT    | inserted as `'active'` |

### sessions table

| Column     | Type     | Notes                                   |
|------------|----------|-----------------------------------------|
| id         | INTEGER  | PRIMARY KEY                             |
| target_id  | INTEGER  | FK → targets.id                         |
| payload    | TEXT     | payload name                            |
| status     | TEXT     | inserted as `'active'`                  |
| start_time | DATETIME | CURRENT_TIMESTAMP on insert             |
| end_time   | DATETIME | nullable                                |
| note       | TEXT     | nullable                                |

### notes table

| Column    | Type    | Notes           |
|-----------|---------|-----------------|
| id        | INTEGER | PRIMARY KEY     |
| target_id | INTEGER | FK → targets.id |
| note      | TEXT    |                 |

### findings table

| Column        | Type | Notes                                                          |
|---------------|------|----------------------------------------------------------------|
| id            | TEXT | PRIMARY KEY — sequential `F-0001`-style, IntegrityError-safe     |
| title         | TEXT | NOT NULL                                                        |
| severity      | TEXT | NOT NULL — P1–P4                                                |
| cwe           | TEXT | optional                                                        |
| asset         | TEXT | NOT NULL                                                        |
| evidence      | TEXT | JSON (request/response/excerpt)                                 |
| repro         | TEXT | JSON list of reproduction steps                                 |
| tool_chain    | TEXT | JSON list of tools used                                         |
| memory_ref    | TEXT | one-line vector-memory pointer                                  |
| ts            | TEXT | NOT NULL — UTC ISO-8601                                         |
| status        | TEXT | NOT NULL DEFAULT `'open'`                                       |
| superseded_by | TEXT | added by migration                                              |
| closed_by     | TEXT | added by migration                                              |
| closed_reason | TEXT | added by migration                                              |
| closed_ts     | TEXT | added by migration                                              |

### unknowns table

Open-questions ledger (companion to findings — conclusions vs. "don't
know yet"). Same root-guard + WAL treatment.

| Column      | Type | Notes                                                        |
|-------------|------|--------------------------------------------------------------|
| id          | TEXT | PRIMARY KEY — sequential `U-001`-style, IntegrityError-safe   |
| question    | TEXT | NOT NULL — what is not known yet                             |
| domain      | TEXT | recon\|web\|creds\|enum\|postex\|scope\|general (default general) |
| asset       | TEXT | related host/URL/endpoint                                    |
| context     | TEXT | how the question arose / what was tried                      |
| opened_by   | TEXT | tool chain or agent that minted it                           |
| resolution  | TEXT | the answer, when resolved                                    |
| resolved_by | TEXT | finding ID (promoted) or agent note                          |
| status      | TEXT | NOT NULL DEFAULT `'open'` — open\|resolved\|wontfix\|promoted  |
| ts          | TEXT | NOT NULL — UTC ISO-8601                                      |
| closed_ts   | TEXT | empty while open                                             |

WAL mode: `PRAGMA journal_mode=WAL` — readers don't block the writer across
processes. A root guard chowns `ids.db` + WAL + SHM back to the workspace
owner when a prior root run left them root-owned.

### Postgres schemas (engagement cobweb lane)

One Postgres DB (`harness`), schema-per-store — the append-only spine
behind `ids.db`-lane stores' engagement awareness (2026-10-19 design; full
map in `engagement_lane.md`, init scripts in
`dockered/postgres/init/`):

| Schema · table | Holds | Lane rights |
|---|---|---|
| `engagement.engagements` | cobweb registry: slug, RoE note, started/closed | INSERT/SELECT |
| `journal.entries` | one row per tool dispatch (all lanes): args JSONB, digest, engagement, lane | INSERT/SELECT (append-only) |
| `evidence.entries` | typed open items: credential/service/ambiguity/scope_question/observation + TTL | INSERT/SELECT + column-level UPDATE (status/resolved_by flips only) |
| `evidence.attempts` | reuse-sweep ledger: UNIQUE(entry, service, target) enforces one attempt per service | INSERT/SELECT |

No lane holds DELETE anywhere — the retention sweep and engagement purge
run as owner-executed SECURITY DEFINER functions; purge executes only for
`harness_operator`. Lanes reach the server by per-entry-point inferred
roles; Postgres absent → journaling skips, evidence falls back to its
SQLite mirror (`evidence/evidence.db`).

## transport types

| Transport       | How it executes                                              |
|-----------------|--------------------------------------------------------------|
| `BRAIN_DISPATCH`| Brain UDS socket → function registry, or in-process fallback |
| `LOCAL_FILE`    | Subprocess: `python <script> --key value` (currently unused) |
| `MCP_RPC`       | External RPC (Metasploit). Only `dispatch_metasploit`.       |

## canonical tag vocabulary

13 buckets from `daharness/tool_tags.py:CANONICAL_TAGS`:
`recon.subdomain`, `recon.web`, `recon.dns-certs`, `recon.scope`,
`web.fuzz`, `web.probe`, `web.auth`, `exploit.web`, `exploit.msf`,
`brute.crack`, `net.raw`, `net.services`, `infra`.

## handle kinds

Tools that consume typed session handles via `utils/handles.py`:
`ssh` (ssh_exec, ssh_shell, ssh_close), `msf` (interact_session,
close_msf_session), `listener` (open/close/read/send_to_listener),
`db` (db_exec, db_close), `collab` (collab_stop). `list_sessions` is the
canonical cross-namespace lister.

## result digest adapters

Tools with `result_digest` adapters (compact projection lane):
`nmap_status`, `ffuf_status`, `hydra_status`, `ldap_search`, `run_r2`,
`run_jadx`, `session_get`, `session_post`, `session_request`,
`session_upload`, `burp_send_http1_request`, `burp_send_http2_request`,
`burp_send_raw`.

## untrusted-target provenance

Tools carrying `untrusted_target=True` (their output embeds analysis-target
content — page HTML, shell output, banners, decompiled code, strings; the
executor stamps result envelopes with `_provenance` and the secretary treats
their content as DATA, never instructions):
`session_get`, `session_post`, `session_request`, `session_upload`,
`ssh_connect`, `ssh_exec`, `ssh_exec_batch`, `interact_session`, `run_r2`,
`run_jadx`, `run_nmap`, `nmap_status`, `run_masscan`, `masscan_status`,
`run_ffuf`, `ffuf_status`, `probe_web`, `extract_js_routes`,
`zap_history_regex`, `zap_alerts`, `zap_alert_message`,
`responders_status`, `responders_captures` (victim-controlled auth
capabilities: user/domain/workstation strings ride the target's own
NTLMSSP blob).

## analysis snapshot cache

`run_r2` memoizes successful analyses in `utils/snapshot_cache.py`
(`run/analysis_snapshots.db`), keyed on the target's **sha256** + op
(verb/addr/count/r2ghidra/output-cap/timeout). Identical repeat calls return
the stored envelope verbatim with a `_snapshot: {hit: true}` stamp —
exploring a binary pays `aaa` once instead of once per call. Deterministic
lane only (never extends to live scanners — nmap/ffuf/masscan observe a
changing world); errors are never cached; identical bytes at a new path get
`target` patched to the current call. `cache=False` skips read+write,
`refresh=True` recomputes and overwrites. TTL `SNAPSHOT_TTL_HOURS` (168h),
per-target cap `SNAPSHOT_MAX_ENTRIES` (200).

---

## auxiliaries/amass.py — subdomain enumeration (background-job)

| tool_id | params | tags |
|---|---|---|
| `auxiliaries.amass.run_amass` | `target` (req, str), `options` (str, ""), `scope_platform` (nullable), `scope_handle` (nullable) | `recon.subdomain` |
| `auxiliaries.amass.amass_status` | `job_id` (req) | `recon.subdomain` |
| `auxiliaries.amass.subdomain_enum` | `target` (req), `options` (""), `scope_platform`, `scope_handle` | `recon.subdomain` |
| `auxiliaries.amass.subdomain_enum_status` | `job_id` (req) | `recon.subdomain` |

## auxiliaries/archived_urls.py

| tool_id | params | tags |
|---|---|---|
| `auxiliaries.archived_urls.archived_urls` | `domain` (req), `limit` (int, 500), `statuscode` (str, ""), `collapse` (bool, True) | `recon.web`, `recon.subdomain` |

## auxiliaries/burp_mcp.py — Burp Suite BApp MCP client (21 tools)

Tools with ¶ have `result_digest` adapters sharing `_burp_response_digest`.

| tool_id | params | tags |
|---|---|---|
| `burp_send_http1_request` ¶ | `content` (req), `target_hostname` (req), `target_port` (req int), `uses_https` (bool, False) | `web.probe` |
| `burp_send_http2_request` ¶ | `pseudo_headers` (req dict), `target_hostname` (req), `target_port` (req int), `uses_https` (True), `headers` (dict, None), `request_body` (str, "") | `web.probe` |
| `burp_send_raw` ¶ | `raw_request` (req), `uses_https` (False) | `web.probe` |
| `burp_get_proxy_history` | `count` (20), `offset` (0) | `recon.web` |
| `burp_get_proxy_history_regex` | `regex` (req), `count` (20), `offset` (0) | `recon.web` |
| `burp_get_proxy_websocket_history` | `count` (20), `offset` (0) | `recon.web` |
| `burp_get_proxy_websocket_history_regex` | `regex` (req), `count` (20), `offset` (0) | `recon.web` |
| `burp_create_repeater_tab` | `content` (req), `target_hostname`, `target_port`, `uses_https` (False), `tab_name` (None) | `web.probe` |
| `burp_create_repeater_tab_http2` | `pseudo_headers`, `target_hostname`, `target_port`, `uses_https` (True), `headers` (None), `request_body` (""), `tab_name` (None) | `web.probe` |
| `burp_send_to_intruder` | `content`, `target_hostname`, `target_port`, `uses_https` (False), `tab_name` (None) | `web.fuzz` |
| `burp_set_proxy_intercept` | `intercepting` (req bool) | `infra` |
| `burp_set_task_engine_state` | `running` (req bool) | `infra` |
| `burp_url_encode` | `content` (req) | `infra` |
| `burp_url_decode` | `content` (req) | `infra` |
| `burp_base64_encode` | `content` (req) | `infra` |
| `burp_base64_decode` | `content` (req) | `infra` |
| `burp_output_project_options` | none | `infra` |
| `burp_output_user_options` | none | `infra` |
| `burp_list_tools` | none | `infra` |
| `burp_reconnect` | none | `infra` |
| `burp_health` | none | `infra` |

## auxiliaries/cert_tools.py

| tool_id | params | tags |
|---|---|---|
| `generate_certs` | `common_name` ("localhost"), `days` (365) | `infra` |
| `clear_certs` | none | `infra` |
| `inspect_host` | `host` (req), `port` (443), `sni` (""), `timeout` (8) | `recon.dns-certs` |
| `inspect_pem` | `cert_data` (req) | `recon.dns-certs` |

## auxiliaries/cors_probe.py

Kernel bare names: `cors` (auto-derived — strips `check_` from
`check_cors`), `security_headers` (auto-derived — strips `check_` from
`check_security_headers`). `cors_probe` was a stale curated alias for
the deleted `run_cors_probe` wrapper.

| tool_id | params | tags |
|---|---|---|
| `check_cors` | `url` (req), `insecure` (False), `timeout` (10.0) | `web.probe` |
| `check_security_headers` | `url` (req), `insecure` (False), `timeout` (10.0) | `web.probe` |

## auxiliaries/db_client.py — DB lane

No `db_client` bare name — the module exposes 5 separate tools.
Kernel bare names: `db_connect`, `db_exec`, `db_exec_batch`,
`db_schema_farm`, `db_close`.

| tool_id | params | notes |
|---|---|---|
| `db_connect` | `host`, `username`, `password` (req), `port` (1433), `dbms` ("mssql"), `database` (""), `domain` (""), `hashes` (""), `timeout` | returns `db:` handle |
| `db_exec` | `handle`, `query` (req), `read_only` (True) | handle `db`; per-exec re-gate |
| `db_exec_batch` | `host`, `username`, `password`, `queries` (list, req), `port` (1433), `dbms` ("mssql"), `database` (""), `domain` (""), `hashes` (""), `read_only` (True), `pace`, `timeout` | stateless batch |
| `db_schema_farm` | same creds + `max_dbs` (20), `max_tables` (100), `max_columns` (1000), `include_samples` (True), `sample_tables` (5), `timeout` | MSSQL-only |
| `db_close` | `handle` (req) | handle `db`; teardown, ungated |

## auxiliaries/dns_lookup.py

Kernel bare names: `resolve_host`, `ptr_lookup` (not `dns_lookup` —
that was a stale curated alias for the deleted `run_dns_lookup` wrapper).

| tool_id | params | tags |
|---|---|---|
| `resolve_host` | `hostnames` (req), `timeout` (5.0) | `recon.dns-certs`, `recon.scope` |
| `ptr_lookup` | `ips` (req), `timeout` (5.0) | `recon.dns-certs` |

## auxiliaries/framework_status.py

| tool_id | params | tags |
|---|---|---|
| `framework_health` | none | `infra` |
| `framework_doctor` | `provider` ("") | `infra` |

`framework_doctor` probes per-lane capability (REA-style):
`{available, reason, remediation}` per provider. Full sweep covers r2
(+-r2ghidra plugin + drop dir), jadx (+java + apk dir), masscan (+raw-socket
CAP_NET_RAW check), msf (+RPC port), scanners (nmap/ffuf/hydra/sqlmap on
PATH), secretary_model (on the Ollama host), and snapshot_cache stats.
Drill down with `provider=` (r2\|jadx\|masscan\|msf\|scanners\|
secretary_model\|snapshot_cache). Remediation strings agree with the tools'
own error paths (pdg's "run: r2pm -ci r2ghidra", masscan's CAP_NET_RAW).

## auxiliaries/ftp_recon.py

No single `ftp_recon` tool — that was a stale curated alias for the
deleted `run_ftp_recon` wrapper. The module exposes 8 separate tools.
Kernel bare names: `ftp_banner`, `ftp_anon_check`, `ftp_list`, `ftp_get`,
`ftp_put`, `sftp_list`, `sftp_get`, `sftp_put`.

| tool_id | params | tags |
|---|---|---|
| `ftp_banner` | `host` (req), `port` (21), `timeout` (8.0), `interface` ("") | `net.services` |
| `ftp_anon_check` | `host` (req), `port` (21), `timeout` (8.0), `interface` ("") | `net.services` |
| `ftp_list` | `host`, `username`, `password` (req), `path` ("."), `port` (21), `timeout` (8.0), `max_lines` (200), `interface` ("") | `net.services` |
| `ftp_get` | `host`, `username`, `password`, `remote`, `local` (req), `port` (21), `timeout` (8.0), `interface` ("") | `net.services` |
| `ftp_put` | `host`, `username`, `password`, `local`, `remote` (req), `port` (21), `timeout` (8.0), `interface` ("") | `net.services` |
| `sftp_list` | `host`, `username`, `password` (req), `path` ("."), `port` (22), `timeout` (8.0), `max_entries` (200) | `net.services` |
| `sftp_get` | `host`, `username`, `password`, `remote`, `local` (req), `port` (22), `timeout` (8.0) | `net.services` |
| `sftp_put` | `host`, `username`, `password`, `local`, `remote` (req), `port` (22), `timeout` (8.0) | `net.services` |

## auxiliaries/impacket_suite.py

| tool_id | params | tags |
|---|---|---|
| `smb_enum_shares` | `target` (req), `username` (""), `password` (""), `domain` ("") | `net.services` |
| `smb_read_file` | `target`, `share`, `path` (req), `username`, `password`, `domain` (""), `max_bytes` (65536) | `net.services` |
| `secretsdump` | `target` (req), `username` (""), `password` (""), `domain` (""), `extra_options` ("") | `net.services` |
| `psexec_exec` | `target`, `command` (req), `username`, `password`, `domain` (""), `extra_options` ("") | `net.services` |
| `wmiexec_exec` | same as psexec | `net.services` |
| `atexec_exec` | same as psexec | `net.services` |
| `kerberoast` | `target` (req), `username` (""), `password` (""), `domain` (""), `dc_ip` (""), `request` (True), `request_user` (""), `output_file` (""), `extra_options` ("") | `net.services` |
| `request_tgs` | `spn`, `domain`, `username` (req), `password` (""), `dc_ip` (""), `hashes` (""), `aes_key` ("") | `net.services` |

## auxiliaries/jadx.py

| tool_id | params | notes |
|---|---|---|
| `list_apk_targets` | none | `infra` |
| `run_jadx` ¶ | `target` (req), `command` (req: decompile/manifest/class/grep/read/tree), `deobf` (False), `show_bad_code` (False), `mode` ("auto"), `threads` (None), `no_res` (False), `force` (False), `single_class` (None), `pattern` (None), `glob` (None), `case_insensitive` (False), `max_matches` (None), `max_files` (None), `path` (None), `offset` (0), `tree_mode` ("files"), `limit` (None) | `infra`; digest adapter |

## auxiliaries/ldap_search.py

| tool_id | params | tags |
|---|---|---|
| `ldap_search` ¶ | `host`, `base_dn` (req), `filter` ("(objectClass=*)"), `scope` ("sub"), `attributes` (""), `bind_dn` (""), `bind_password` (""), `port` (389), `size_limit` (0), `timeout` (30.0), `extra_options` ("") | `net.services` |
| `ldap_rootdse` | `host` (req), `port` (389), `timeout` (15.0), `extra_options` ("") | `net.services` |

## auxiliaries/masscan.py — background-job

Kernel bare name: `masscan` (curated alias). `run_masscan` is the
function name, not the kernel bare name.

| tool_id | params | tags |
|---|---|---|
| `run_masscan` | `target` (req), `ports` (None→"80"), `rate` (None int), `adapter` (None), `flags` (None), `exclude` (None→auto self-exclude), `options` (None) | `net.raw` |
| `masscan_status` | `job_id` (req) | `net.raw` |
| `masscan_cancel` | `job_id` (req) | `net.raw` |

## auxiliaries/nmap.py — background-job

| tool_id | alias | params | notes |
|---|---|---|---|
| `run_nmap` | `nmap` | `target` (req), `options` ("-Pn -sV"), `shaping` (None) | `net.raw`; shaping preset from `evasion/shaping.py` (quiet/polite/noisy; decoy/fragment lab-gated) |
| `nmap_status` ¶ | auto | `job_id` (req) | `net.raw`; digest adapter |
| `nmap_scripts` | auto | `query` (""), `category` (""), `detail` (False), `limit` (40) | `net.raw` |

## auxiliaries/playwright_recon.py

| tool_id | params | tags |
|---|---|---|
| `playwright_fetch` | `url` (req), `wait_until` ("networkidle"), `timeout_ms` (25000) | `recon.web` |
| `playwright_crawl` | `url` (req), `max_pages` (25), `max_depth` (3), `wall_cap` (120.0), `same_origin` (True) | `recon.web` |
| `playwright_crawl_status` | `job_id` (req) | `recon.web` |
| `playwright_crawl_stop` | `job_id` (req) | `recon.web` |

## auxiliaries/program_scope.py

| tool_id | alias | params | tags |
|---|---|---|---|
| `load_program_scope` | auto | `handle` ("crypto"), `refresh` (False), `platform` ("h1") | `recon.scope` |
| `search_programs` | `scope_search_programs` | `query` (""), `platform` ("all"), `limit` (10), `with_assets` (False), `handle` (""), `refresh` (False) | `recon.scope` |
| `check_scope` | auto | `target`, `handle` (req), `platform` ("h1") | `recon.scope` |
| `check_reportable` | auto | `category_or_cwe`, `handle` (req), `platform` ("h1") | `recon.scope` |
| `program_hacktivity` | auto | `handle` ("crypto"), `query` (""), `limit` (25) | `recon.scope` |

## auxiliaries/radare2.py

| tool_id | params | notes |
|---|---|---|
| `run_r2` ¶ | `target` (req), `command` (req — allowlist: aaa afl afi af iI iS iE ii is iR iz izz pdf pdg pd px axt axf ps), `addr` (None), `count` (None), `cache` (True), `refresh` (False) | `infra`; digest adapter; snapshot cache |
| `list_r2_targets` | none | `infra` |

`run_r2` caches successful runs by target sha256 + op — repeat calls on the
same binary return the stored envelope instantly (`_snapshot.hit=true`).
`cache=False` skips, `refresh=True` recomputes and overwrites; errors are
never cached.

## auxiliaries/smb_scanner.py

Kernel bare names: `null_session` (auto-derived — strips `check_`
prefix from `check_null_session`; `smb_null` was a stale curated alias
for the deleted standalone function), `smb_recon` (curated alias for
`run_smb_recon`).

| tool_id | params | tags |
|---|---|---|
| `SMBScanner.check_null_session` | `target` (req), `remoteName` (False) | `net.services` (method) |
| `run_smb_recon` | `targets` (req list) | `net.services` |

## auxiliaries/ssh_exec.py

| tool_id | params | tags |
|---|---|---|
| `ssh_exec_batch` | `hostname`, `username`, `password`, `commands` (list, req), `port` (22), `pace` (0.5) | `net.services` |

## auxiliaries/ssrf_probe.py

| tool_id | params | tags |
|---|---|---|
| `scan_ssrf` | `target` (req), `param` (""), `method` ("GET"), `body` (""), `collab_id` (""), `redirect_to` (""), `insecure` (False), `timeout`, `max_payloads`, `delay` (0.0) | `web.probe` |

## auxiliaries/tls_info.py

| tool_id | params | tags |
|---|---|---|
| `tls_info` | `target` (req), `port` (443), `insecure` (False) | `recon.dns-certs` |

## auxiliaries/web_login_brute.py

| tool_id | params | tags |
|---|---|---|
| `web_login_probe` | `url` (req), `timeout` (8.0), `insecure` (False), `host_header` ("") | `web.auth` |
| `web_login_test` | `url`, `username`, `password` (req), `username_field` ("username"), `password_field` ("password"), `timeout` (8.0), `insecure` (False), `host_header` ("") | `web.auth` |
| `web_login_brute` | `url`, `username` (req), `username_field`, `password_field` (defaults), `wordlist` (""), `max_attempts` (500), `rate` (10.0), `timeout` (8.0), `insecure` (False), `success_marker` (""), `fail_marker` (""), `success_statuses` ("301,302,303,307,308"), `host_header` ("") | `web.auth`, `brute.crack` |

## auxiliaries/web_probe.py

Kernel bare name: `probe_web` (auto-derived; `web_probe` was a stale
curated alias for the deleted `run_web_probe` wrapper).

| tool_id | params | tags |
|---|---|---|
| `probe_web` | `targets` (req), `ports` ("80,443,8080,8443"), `insecure` (False), `timeout` (5.0), `threads` (48), `wall_cap` (90.0) | `recon.web`, `web.probe` |

## auxiliaries/web_session.py — stateful HTTP lane (cookie jar + CSRF)

Every `session_*` call carries ONE browser-coherent identity resolved at
`evasion/webshape.py` — per-host sticky UA ↔ TLS stack ↔ header set ↔
header order. With `curl_cffi` installed (default
`SESSION_IMPERSONATION=auto`) the request travels on the impersonating
client whose template matches the pool pick (full client-hint + sec-fetch
set, canonical per-family order); otherwise the plain python-requests path
ships the same UA claim with the family's canonical header order and a
decodable-only Accept-Encoding fill — the envelope's `fingerprint` field
names the backend (`curl-impersonate` | `python-requests`) plus the reason
whenever degraded. Operator-owned identities (`SESSION_UA`, the legacy
marker, or a caller `User-Agent` header) never impersonate. Optional
per-host pacing floor via `SESSION_HOST_FLOOR` unchanged.

| tool_id | alias | params | tags |
|---|---|---|---|
| `session_get` ¶ | `session_get` | `url` (req), `insecure` (False), `timeout` (12.0), `body_limit` (4096), `follow_redirects` (True), `headers` (None) | `web.auth`, `web.probe` |
| `session_post` ¶ | `session_post` | `url` (req), `data` (None), `json_data` (None), `auto_csrf` (True), `insecure` (False), `timeout` (15.0), `body_limit` (4096), `follow_redirects` (True), `headers` (None) | `web.auth`, `web.probe` |
| `session_request` ¶ | `session_request` | `method`, `url` (req), `data`, `json_data` (None), `insecure`, `timeout` (15.0), `body_limit` (4096), `follow_redirects` (True), `headers` (None) | `web.auth`, `web.probe` |
| `session_upload` ¶ | `session_upload` | `url`, `file_path` (req), `file_field` ("file"), `file_name` (None), `content_type` (None), `data` (None), `auto_csrf` (True), `insecure` (False), `timeout` (30.0), `body_limit` (4096), `follow_redirects` (True), `headers` (None) | `exploit.web`, `web.auth` |

## auxiliaries/zap.py — OWASP ZAP daemon (15 tools)

| tool_id | params | tags |
|---|---|---|
| `zap_open_url` | `target` (req), `scope_handle` (None), `scope_platform` (None) | `web.probe` |
| `zap_spider` | `target` (req), `max_depth` (5), `recurse` (True) | `recon.web` |
| `zap_spider_status` | `scan_id` (req) | `recon.web` |
| `zap_ajax_spider` | `target` (req) | `recon.web` |
| `zap_ajax_spider_status` | none | `recon.web` |
| `zap_active_scan` | `target` (req), `policy` (None) | `exploit.web` |
| `zap_active_scan_status` | `scan_id` (req), `base_url` (None) | `exploit.web` |
| `zap_alerts` | `base_url` (None), `risk_id` (None), `summary` (True), `max_alerts` (50) | `recon.web` |
| `zap_alert_message` | `alert_id` (req) | `recon.web` |
| `zap_history_regex` | `target`, `pattern` (req), `body_only` (True) | `recon.web` |
| `zap_sites` | none | `recon.web` |
| `zap_sites_tree` | `target` (None) | `recon.web` |
| `zap_report` | `report_format` ("html"), `report_file` ("/tmp/zap_report.html"), `report_title` | `infra` |
| `zap_send_raw` | `raw_request` (req), `follow_redirects` (False), `timeout` (30.0) | `web.probe` |
| `zap_sync_scope` | none | `infra` |

---

## payloads/fastcgi.py

| tool_id | params | tags |
|---|---|---|
| `fastcgi_request` | `target` (req), `port` (9000), `script_filename` ("/var/www/html/index.php"), `php_value` (""), `php_admin_value` (""), `method` ("GET"), `query_string` (""), `server_name` ("localhost"), `body` (""), `extra_params` (""), `timeout` (10.0) | `exploit.web` |
| `fastcgi_php_exec` | `target` (req), `port` (9000), `php_code` ("<?php echo shell_exec('id'); ?>"), `script_filename` ("/var/www/html/index.php"), `server_name` ("localhost"), `timeout` (10.0) | `exploit.web` |

## payloads/ffuf.py — background-job

Kernel bare name: `ffuf_payload` (curated alias — NOT `ffuf`, which
was a stale alias for the deleted `auxiliaries.ffuf_tools.run_ffuf`).

| tool_id | alias | params | tags |
|---|---|---|---|
| `run_ffuf` | `ffuf_payload` | `url` (req), `wordlist` (""), `options` (""), `scope_handle` (None), `scope_platform` (None) | `web.fuzz` |
| `ffuf_status` ¶ | auto | `job_id` (req) | `web.fuzz` |
| `ffuf_cancel` | auto | `job_id` (req) | `web.fuzz` |

## payloads/hash_crack.py

No `hash_crack` bare name — that was a stale curated alias for the
deleted `run_hash_crack` wrapper. Kernel bare names: `john` (strips
`run_` from `run_john`), `hashcat` (strips `run_` from `run_hashcat`),
`john_status`, `john_show`, `hashcat_status`, `hashcat_show`,
`suggest_crack_mode`.

| tool_id | params | tags |
|---|---|---|
| `suggest_crack_mode` | `hash_string` (req) | `brute.crack` |
| `run_john` | `hash_input` (req), `options` (""), `wordlist` ("") | `brute.crack` |
| `john_status` | `job_id` (req) | `brute.crack` |
| `john_show` | `hash_input` (req), `options` ("") | `brute.crack` |
| `run_hashcat` | `hash_input` (req), `mode` (req int), `options` (""), `wordlist` ("") | `brute.crack` |
| `hashcat_status` | `job_id` (req) | `brute.crack` |
| `hashcat_show` | `hash_input` (req), `mode` (req int) | `brute.crack` |

## payloads/hydra.py — background-job

| tool_id | alias | params | tags |
|---|---|---|---|
| `run_hydra` | `hydra` | `target` (req), `options` ("") | `brute.crack` |
| `hydra_status` ¶ | auto | `job_id` (req) | `brute.crack` |
| `hydra_cancel` | auto | `job_id` (req) | `brute.crack` |

## payloads/js_recon.py

| tool_id | params | tags |
|---|---|---|
| `extract_js_routes` | `url` (req), `max_scripts` (25), `timeout` (15.0), `insecure` (False) | `recon.web` |

## payloads/metasploiting.py — class MetasploitClient

No `metasploit` bare function — the class exposes 6 separate tools.
Kernel bare names: `msf_dispatch`, `msf_index`, `msf_set_payload`,
`msf_options`, `msf_interact`, `msf_close` (all curated aliases).

| tool_id | alias | transport | params | notes |
|---|---|---|---|---|
| `index_modules` | `msf_index` | BRAIN_DISPATCH | `module_type` (None), `module_name` (None), `limit` (15) | `exploit.msf` |
| `dispatch_metasploit` | `msf_dispatch` | **MCP_RPC** | `module_path` (req), `category` (req: exploit/auxiliary/post), `options` (req dict), `start_handler` (False) | `exploit.msf`; scope-gated; meterpreter supported |
| `set_payload` | `msf_set_payload` | BRAIN_DISPATCH | `payload_name`, `options` (req) | `exploit.msf` |
| `get_options` | `msf_options` | BRAIN_DISPATCH | `module_path` (req) | `exploit.msf` |
| `interact_session` | `msf_interact` | BRAIN_DISPATCH | `handle`, `command` (req) | `exploit.msf`; handle `msf` |
| `close_msf_session` | `msf_close` | BRAIN_DISPATCH | `handle` (req) | `exploit.msf`; handle `msf` |

## payloads/msfvenom_tools.py — payload generation + upload lane

| tool_id | alias | params | tags |
|---|---|---|---|
| `msfvenom_menu` | `msfvenom_menu` | `kind` ("payloads"), `query` ("") | `exploit.msf` |
| `generate_payload` | `msfvenom` | `payload` (None), `lhost` (""), `lport` (0 int), `preset` (None), `format` (None), `out_name` (None), `encoder` (None), `iterations` (1 int), `badchars` (None), `platform` (None), `arch` (None), `encrypt` (None: aes256/aes256cbc/rc4/xor/base64), `encrypt_key` (None hex), `encrypt_iv` (None hex), `extra_options` (None dict), `start_handler` (False) | `exploit.msf`; `--encrypt` emits encrypted RAW shellcode only — pair with an `encoders/` loader |
| `list_dropbox` | `list_dropbox` | none | `exploit.msf` |

## payloads/searchsploiting.py, payloads/sqlmap.py, payloads/wordlists.py

| tool_id | alias | params | tags |
|---|---|---|---|
| `search_exploit` | `searchsploit` | `query` (req) | `exploit.msf` |
| `run_sqlmap` | `sqlmap` | `target_url` (req), `options` ("") | `exploit.web` |
| `sqlmap_status` | auto | `job_id` (req) | `exploit.web` |
| `list_wordlists` | auto | `query` (None), `category` (None), `source` (None), `limit` (25) | `infra` |

---

## listeners/brain_control.py

| tool_id | params | tags |
|---|---|---|
| `list_tool_executions` | none | `infra` (async) |
| `kill_tool_execution` | `exec_id` (req), `force` (False), `reason` ("") | `infra` (async) |

## listeners/collaborator.py — OOB callback listener

| tool_id | params | tags |
|---|---|---|
| `collab_start` | none | `infra` (async; binds 80/443/53) |
| `collab_generate` | none | `infra` |
| `collab_poll` | `since` (0.0 float), `id` ("") | `infra` |
| `collab_stop` | `handle` ("") | `infra`; handle `collab` (async) |

## listeners/responder_analog.py — CAPTURE-ONLY LLMNR/NBT-NS poisoner + SMB2 sink

The Phase-4 credential-motion opener: answers LLMNR (UDP 5355) + NBT-NS
(UDP 137) name queries with our IP (own hostname + `wpad` blacklisted;
LLMNR answers A queries only) and runs a self-contained SMB2 sink on 445
that captures the victim's NTLMv2 response as a hashcat -m 5600 /
john netntlmv2 line, then serves `STATUS_LOGON_FAILURE` — **no relay code
path**. Captures persist to `run/responder/captures.jsonl` (0600) and land
in vector memory (namespace `responder`, marked important). The internal
job main carries the lab gate too, and the module opts out of the static
LOCAL_FILE mint via `_NO_LOCAL_TOOL = True` — the argparse job plumbing
never surfaces as a second, gate-bypassing entry beside these decorated
tools.

| tool_id | params | tags | notes |
|---|---|---|---|
| `responders_start` | `iface` (""), `llmnr_port` (5355), `nbns_port` (137), `smb_port` (445) | `net.services` | lab-gated: `SHAPING_LAB_MODE=1` required; TCP 445 capability probe (setcap/sudo remediation); returns `job_id` |
| `responders_status` | `job_id` (req) | `net.services`; provenance | engine liveness + capture count + most recent captures |
| `responders_stop` | `job_id` (req) | `net.services` | SIGTERM cleanup |
| `responders_captures` | `q` (20) | `net.services`; provenance | full hash lines from the capture file |

## listeners/raw_scan.py — C plugin (ctypes, root required)

| tool_id | params | tags |
|---|---|---|
| `syn_scan` | `target_ip`, `port` (req), `source_ip` (None), `timeout_ms` (250) | `net.raw`; loads `listeners/plugins/raw_scan.so` |

## listeners/listening.py — class TCPListener

| tool_id | alias | params | notes |
|---|---|---|---|
| `send_to_brain` | `send_to_brain` | `event_type`, `session_id`, `data` | `infra` (async) |
| `open_listener` | `listen_tcp` | `host` ("0.0.0.0"), `port` (req int), `auto_answer` (False) | `net.services` (async; returns `listener:` handle) |
| `close_listener` | `close_listener` | `handle` (req) | `net.services`; handle `listener` (async) |
| `read_listener` | auto | `handle` (""), `since` (0.0), `limit` (50) | `net.services`; handle `listener` |
| `send_to_listener` | auto | `handle`, `data` (req), `peer` ("") | `net.services`; handle `listener` (async) |
| `clear_listener_data` | auto | `handle` ("") | `net.services`; handle `listener` |

---

## utils/cookie_jar.py — universal cookie jar management

| tool_id | alias | params | tags |
|---|---|---|---|
| `jar_state` | `jar_state` | `domain` ("") | `infra` |
| `jar_store_cookie` | `jar_store_cookie` | `domain`, `cookie` (req), `value` (""), `path` ("/"), `expires` (0 float), `secure` (False), `httponly` (False), `origin` ("") | `infra` |
| `jar_store_token` | `jar_store_token` | `domain`, `name`, `value` (req), `token_type` ("bearer"), `origin` ("") | `infra` |
| `jar_clear` | `jar_clear` | `domain` (""), `clear_cookies` (True), `clear_tokens` (True) | `infra` |
| `jar_cookie_header` | `jar_cookie_header` | `url` (req) | `infra` |

## utils/crypto_kit.py

| tool_id | params | tags |
|---|---|---|
| `decode_blob` | `blob` (req), `max_rounds` (6) | `brute.crack` |
| `jwt_decode` | `token` (req) | `web.auth`, `brute.crack` |
| `identify_hash` | `hash_string` (req) | `brute.crack` |
| `check_hash_wordlist` | `hash_string` (req), `wordlist` (""), `max_lines` (14.5M) | `brute.crack` |
| `xor_brute` | `data` (req), `top` (5) | `brute.crack` |
| `rot_brute` | `text` (req) | `brute.crack` |
| `rsa_decrypt` | `p`, `q`, `e`, `c` (req ints) | `brute.crack` |

## utils/findings.py

| tool_id | alias | params | tags |
|---|---|---|---|
| `report_finding` | `report_finding` | `title`, `severity`, `asset` (req), `cwe` (""), `evidence_request` (""), `evidence_response` (""), `evidence_excerpt` (""), `repro` (""), `tool_chain` ("") | `infra` |
| `render_findings` | auto | `severity` (""), `asset` (""), `status` (""), `include_closed` (True) | `infra` |
| `close_finding` | auto | `finding_id`, `status` (req), `reason` (""), `closed_by` (""), `duplicate_of` ("") | `infra` |
| `supersede_finding` | auto | `old_id`, `new_id` (req), `reason` (""), `closed_by` ("") | `infra` |
| `record_unknown` | auto | `question` (req), `domain` ("general"), `asset` (""), `context` (""), `tool_chain` ("") | `infra` |
| `list_unknowns` | auto | `status` ("open"), `domain` (""), `asset` (""), `include_closed` (False) | `infra` |
| `resolve_unknown` | auto | `unknown_id`, `status` (req: resolved\|wontfix\|promoted), `resolution` (""), `resolved_by` ("") | `infra` |

All three `*_unknown` tools share the findings store's terminal lane
(`utils.findings.` prefix) and stay callable past the per-turn tool budget.
`record_unknown` mints U-001-style IDs (domains:
recon\|web\|creds\|enum\|postex\|scope\|general); `promoted` requires
`resolved_by` = the finding ID the question became. `list_unknowns` defaults
to open only ("what haven't we answered yet"). `render_findings` output
carries an **Open questions (unresolved)** appendix (renders even with zero
findings).

## utils/log_reader.py

| tool_id | alias | params | tags |
|---|---|---|---|
| `read_logs` | `read_logs` | `log_type` (req: 'brain'\|'msf'), `lines` (50) | `infra` |

## utils/memory_tools.py

| tool_id | alias | params | tags |
|---|---|---|---|
| `remember_text` | `remember_text` | `text` (req), `namespace` ("engagement"), `memory_id` (""), `agent_id` (""), `important` (False) | `infra` |
| `recall_text` | auto | `query` (req), `namespace` ("engagement"), `limit` (5), `agent_id` (""), `target` (""), `since_hours` (0) | `infra` |
| `list_text_namespaces` | auto | none | `infra` |

## utils/evidence.py — evidence ledger (promoted unknown ledger)

| tool_id | alias | params | tags |
|---|---|---|---|
| `record_evidence` | auto | `kind` (req: credential\|service\|ambiguity\|scope_question\|observation), `summary` (req), `asset` (""), `content_json` (""), `source` (""), `scratch_ref` (""), `ttl_hours` (-1 = per-kind default) | `infra` |
| `add_validation_attempt` | auto | `evidence_id`, `service`, `target`, `outcome` (req: hit\|miss\|error\|undecided), `note` ("") | `infra` |
| `list_open_evidence` | auto | `kind` (""), `engagement` ("") | `infra` |
| `resolve_evidence` | auto | `evidence_id`, `status` (req: resolved\|wontfix\|promoted), `resolution` (""), `resolved_by` ("") | `infra` |

The reuse sweep is DB-enforced: `add_validation_attempt` REFUSES a second
attempt for the same `(entry, service, target)` with re-mint guidance — one
honest attempt per service; a `hit` prompt says report_finding + resolve as
`promoted` (which requires `resolved_by`). Kind-default TTLs: credential
24h, scope_question never, others 7d. Rows carry the armed engagement slug
automatically (see `engagement_lane.md`). Terminal-lane `infra` — callable
past the tool budget.

## utils/journal.py — dispatch journal (what-happened spine)

| tool_id | alias | params | tags |
|---|---|---|---|
| `what_touched` | auto | `target` (req), `since_hours` (None), `limit` (100) | `infra`, `recon.scope` |

The agent-facing READ surface of the journal: every dispatch whose `args`
mention the target substring — "have we already scanned / logged into /
dispatched against X?" is one call BEFORE re-running anything. Returns a
prose listing (entry#, timestamp, lane/tool/status, engagement, result
digest). Writes happen automatically at the executor choke point (one row
per dispatch, all lanes) — never agent-called. Engagement
arm/disarm/purge are operator-only REPL/CLI verbs (see
`engagement_lane.md`), journaling is append-only by DB grants, and the
whole lane degrades silently when Postgres is down.

## utils/packetcraft.py — 27 tools (all `net.raw`)

| tool_id | params | notes |
|---|---|---|
| `craft_icmp_echo` | `src_ip`, `dst_ip` (req), `payload` (""), `interface` ("") | |
| `craft_icmp_packet` | same as above | |
| `craft_tcp_packet` | `src_ip`, `dst_ip`, `src_port`, `dst_port` (req ints), `flags` ("S"), `payload` (""), `interface` ("") | |
| `craft_udp_packet` | `src_ip`, `dst_ip`, `src_port`, `dst_port` (req ints), `payload` (""), `interface` ("") | |
| `craft_arp_request` | `src_mac`, `src_ip`, `target_ip` (req), `interface` ("") | |
| `craft_arp_packet` | `src_mac`, `dst_mac`, `src_ip`, `dst_ip` (req), `interface` ("") | |
| `craft_vlan_frame` | `src_mac`, `dst_mac`, `vlan_id` (req int), `payload` (""), `interface` ("") | |
| `craft_dhcp_discover` | `src_mac` (req), `interface` ("") | |
| `craft_dns_query` | `src_ip`, `dst_ip`, `query_name` (req), `interface` ("") | |
| `craft_dns_response` | `src_ip`, `dst_ip`, `query_name`, `answer_ip` (req), `interface` ("") | |
| `craft_dns_response_multi` | `src_ip`, `dst_ip`, `query_name`, `answer_ips` (list, req), `interface` ("") | |
| `craft_mdns_query` | `src_ip`, `dst_ip`, `query_name` (req), `interface` ("") | |
| `craft_http_request` | `src_ip`, `dst_ip` (req), `method` ("GET"), `path` ("/"), `host` (""), `user_agent` (""), `payload` (""), `interface` ("") | |
| `craft_http_response` | `src_ip`, `dst_ip` (req), `status_code` (200 int), `reason` ("OK"), `content_type` ("text/html"), `payload` (""), `interface` ("") | |
| `send_packet` | `hex` (req), `count` (1 int), `interval` (0.1 float), `interface` ("") | scope-gated, root |
| `send_and_receive_packet` | `hex` (req), `timeout` (5 int), `interface` ("") | scope-gated, root |
| `sniff_packets` | `filter` (""), `count` (10 int), `timeout` (30 int), `interface` ("") | root |
| `dissect_packet` | `hex` (req) | |
| `modify_packet` | `hex` (req), `fields` (req dict) | |
| `export_packet_hex` | `hex` (req) | |
| `save_packet` | `hex`, `filename` (req) | |
| `load_packet` | `filename` (req) | |
| `wait_for_packet` | `filter` (""), `timeout` (30 int), `interface` ("") | root |
| `save_pcap` | `hexes` (req list), `filename` ("") | |
| `sniff_to_pcap` | `filter` (""), `count` (50 int), `timeout` (60 int), `interface` (""), `filename` ("") | |
| `load_pcap` | `filename` (req), `offset` (0 int), `limit` (50 int) | |
| `list_pcaps` | none | |

## utils/paramiko_client.py — SSH lane

| tool_id | params | notes |
|---|---|---|
| `ssh_connect` | `hostname`, `username`, `password` (req), `port` (22) | `net.services`; returns `ssh:` handle |
| `ssh_exec` | `handle`, `command` (req) | `net.services`; handle `ssh`; per-exec re-gate |
| `ssh_shell` | `handle`, `command` (req), `timeout` (10.0) | `net.services`; handle `ssh`; PTY lane |
| `ssh_close` | `handle` (req) | `net.services`; handle `ssh` |
| `list_sessions` | none | `infra`; canonical session lister (ssh/msf/listener) |
| `paramiko_client` | `hostname`, `username`, `password`, `command` (req) | `net.services`; one-shot legacy |

---

## utils/memory_tools.py — text memory store (shared with framework_memory_search)

> **`remember_text`/`recall_text` and the bridge `framework_memory_search`
> tool are the same store.** Both read/write the same ChromaDB-backed
> vector memory. `remember_text` is the in-kernel write path;
> `framework_memory_search` is the bridge read path. Both accept
> `namespace` and `agent_id` for scoping. Use `remember_text` inside
> `execute_code` chains to bank durable facts; use
> `framework_memory_search` (or `recall_text` in-kernel) to retrieve
> them in a later block or session.

| tool_id | alias | params | tags |
|---|---|---|---|
| `remember_text` | `remember_text` | `text` (req), `namespace` ("engagement"), `memory_id` (""), `agent_id` (""), `important` (False) | `infra` |
| `recall_text` | auto | `query` (req), `namespace` ("engagement"), `limit` (5), `agent_id` (""), `target` (""), `since_hours` (0) | `infra` |
| `list_text_namespaces` | auto | none | `infra` |

---

## Kernel-only primitives (not @framework_tool — injected into execute_code namespace)

These are not framework tools and do not appear in the tool registry.
They are helpers injected into the Jupyter kernel namespace by the
daharness executor. No import needed — call them directly.

### Envelope helpers

Called on the dict returned by any awaited tool call.

| name | signature | returns | notes |
|---|---|---|---|
| `keys` | `keys(result)` | `list[str]` | Flat list of all keys in the unwrapped result dict |
| `pluck` | `pluck(result, key)` | `list` | **Returns a LIST, not a scalar.** Recursively collects values at any key matching `key`. Index `[0]` for the first/only value. |
| `find` | `find(result, query)` | `list` | Searches key paths for `query` substring; returns found values. Behavior on nested dicts / mixed types needs further documentation. |
| `grep` | `grep(result, pattern)` | `list[tuple]` | Searches all text fields line-by-line. Returns `(field_path, matching_line)` tuples. Most useful helper for extracting specific content from large responses. |

### Cookie jar management

The session cookie jar is framework-side state that persists across
`execute_code` blocks (unlike Python variables, which are per-block
and do not carry forward). These primitives let you inspect and
manipulate the jar directly — essential for multi-block exploit chains
where you log in one block and exploit in the next.

| name | signature | notes |
|---|---|---|
| `jar_state` | `jar_state()` | Current cookie jar contents |
| `jar_cookie_header` | `jar_cookie_header()` | Cookie header string for manual injection |
| `jar_store_cookie` | `jar_store_cookie(...)` | Manually store a cookie |
| `jar_store_token` | `jar_store_token(...)` | Manually store a token (CSRF, etc.) |
| `jar_clear` | `jar_clear()` | Clear all cookies/tokens |

### Generic tool dispatch

Fallback when a base name doesn't resolve (stale alias, missing curated
mapping, or new tool without an alias yet).

| name | signature | notes |
|---|---|---|
| `run_tool` | `run_tool(tool_id, **kwargs)` | In-kernel equivalent of bridge `framework_run_tool`. Takes dotted `tool_id` (e.g. `"auxiliaries.web_probe.probe_web"`). Preferred fallback when a base name fails with `NameError`. |
| `discover_tools` | `discover_tools(intent, top_k=N)` | In-kernel equivalent of bridge `framework_search_tools`. Returns candidate tool menu by semantic match. |

### Scope management (read-only from kernel)

The scope gate fires on every traffic-sending call inside the kernel —
identical enforcement to the bridge. The gate is automatic; no manual
markers needed. Arming is via the REPL (`scope on <handle>`), persisted
to `scope/.armed_packet_scope.json`, mtime-checked every call so REPL
changes apply inside a running Brain. Arming is deliberately NOT exposed
as an `@framework_tool` so the model cannot toggle it.

The following appear in the kernel namespace for **read-only scope
inspection**. They do not arm or disarm the gate.

| name | signature | notes |
|---|---|---|
| `scope_status` | `scope_status()` | Check if gate is armed and for what scope |
| `scope` | `scope()` | Query current scope state |
| `scope_search` | `scope_search(query)` | Search armed scope for matching targets |
| `scope_search_programs` | `scope_search_programs(...)` | Search program scope |
| `load_program_scope` | `load_program_scope(...)` | Load a program scope manifest |

### Other utility primitives

| name | signature | notes |
|---|---|---|
| `scratch` | `scratch(...)` | Scratch storage for large tool results (cf. `framework_scratch_search` on bridge) |
| `reportable` | `reportable(...)` | Check if a finding/action is reportable under current scope |
| `check_trigger` | `check_trigger(...)` | Check trigger condition (details TBD) |
| `list_sessions` | `list_sessions()` | List active typed handles (`ssh`, `msf`, `listener`, `db`) across all namespaces |
| `kill_tool_execution` | `kill_tool_execution(...)` | Kill a running tool execution by job_id |
| `list_tool_executions` | `list_tool_executions(...)` | List recent tool executions |
| `read_logs` | `read_logs(...)` | Read framework logs |
| `b64encode` | `b64encode(data)` | Base64 encode |
| `b64decode` | `b64decode(data)` | Base64 decode |

### Display primitives (IPython)

Standard IPython display classes are available in the kernel namespace.
The correct route for JavaScript rendering is
`display(Javascript(code))` — capital `J` class; lowercase `javascript`
is not defined. The `%%javascript` cell magic works in the notebook
frontend.

Available classes: `HTML`, `Javascript`, `Markdown`, `Image`, `JSON`,
`Code`, `IFrame`, `SVG`, `Latex`, `Math`, `Pretty`, `Video`, `Audio`.

Available functions: `display`, `display_html`, `display_javascript`,
`display_json`, `display_markdown`, `display_png`, `display_svg`,
`update_display`, `clear_output`.

> Whether `display(HTML(...))` or `display(Javascript(...))` renders
> in the OpenWebUI chat interface is frontend-dependent and unconfirmed.
> Text output (stdout) always comes through; rich display rendering
> depends on the OWUI execute_code output handler.
---

### Display primitives (IPython)

Standard IPython display classes are available in the kernel namespace.
The correct route for JavaScript rendering is
`display(Javascript(code))` — capital `J` class; lowercase `javascript`
is not defined.

Available classes: `HTML`, `Javascript`, `Markdown`, `Image`, `JSON`,
`Code`, `IFrame`, `SVG`, `Latex`, `Math`, `Pretty`, `Video`, `Audio`.

Available functions: `display`, `display_html`, `display_javascript`,
`display_json`, `display_markdown`, `display_png`, `display_svg`,
`update_display`, `clear_output`.

### IPython magics in execute_code

The execute_code kernel is a real IPython kernel (ZMQInteractiveShell),
so **line magics, cell magics, and shell escapes are all available**
inside execute_code blocks.

Automagic is ON — the `%` prefix is optional for line magics (`pwd`
works the same as `%pwd`).

| category | syntax | status | notes |
|---|---|---|---|
| Shell capture | `!command` | ✅ confirmed | Raw syntax, output to capture, !! for capture is broken |
| Line magic | `%magic args` | ✅ confirmed | ~90 available (pwd, ls, env, history, timeit, pip, conda, who, whos, prun, etc.) |
| Cell magic | `%%magic` | ✅ confirmed | ~30 available (bash, javascript, html, timeit, writefile, python, capture, prun, latex, markdown, ruby, perl, etc.) |
| Line magic API | `ip.run_line_magic(name, args)` | ✅ confirmed | Programmatic access — works anywhere in the block |
| Cell magic API | `ip.run_cell_magic(name, args, body)` | ✅ confirmed | Programmatic access — works anywhere in the block |
| Shell API | `ip.system('command')` | ✅ confirmed | Programmatic `!` equivalent |
| Shell API | `ip.getoutput('command')` | ✅ confirmed | Programmatic `!!` equivalent — returns SList |

> `%%javascript` and `%%html` return IPython display objects
> (`<IPython.core.display.Javascript object>`). Whether these render
> in the OpenWebUI chat interface is frontend-dependent. Text output
> (stdout) always comes through.
