# payloads/ — offensive lanes

The exploit and payload lanes: Metasploit RPC, msfvenom artifact generation,
web fuzzing, SQL injection, credential cracking, static JS recon, wordlist
discovery. Every module here dispatches via `BRAIN_DISPATCH` (the Brain
sidecar, or in-process fallback when it's down — see
[`../listeners/README.md`](../listeners/README.md)); the long-running CLI
wrappers follow the background-job pattern (see
[`../utils/README.md`](../utils/README.md#background-job-pattern-background_jobpy)).

## Tool inventory

| Module | Tools | Notes |
| --- | --- | --- |
| `metasploiting.py` | `index_modules`, `dispatch_metasploit`, `set_payload`, `get_options`, `list_sessions`, `interact_session`, `close_msf_session` | MSF RPC client (see deep-dive below) |
| `msfvenom_tools.py` | `generate_payload`, `msfvenom_menu`, `list_dropbox` | payload artifact generation into `dropbox/` (see below) |
| `ffuf.py` | fuzzing: directories, files, vhosts, parameters | `run_*` / `*_status` / `*_cancel` triplets; parsed findings capped at `FFUF_MAX_FINDINGS` |
| `hydra.py` | credential brute-force / password spray | background-job triplets |
| `sqlmap.py` | SQL injection detection | background-job triplets, injectable verdict parsing |
| `hash_crack.py` | `run_john` / `run_hashcat` + `*_status` / `*_show` | hash-string mode suggestion; offline compute, not scope-gated |
| `searchsploiting.py` | searchsploit (ExploitDB) lookup | local ExploitDB lookup for known exploits |
| `fastcgi.py` | FastCGI/PHP-FPM exploitation | raw request + `php://input` RCE chain |
| `js_recon.py` | static JavaScript recon | API routes + secrets from pages/bundles; no browser, no heavy deps |
| `wordlists.py` | wordlist discovery | query-based over the source tree incl. Kali symlinked folders; feeds ffuf/hydra |

External CLI binaries each module wraps are listed in the
[External Dependencies table](../README.md#external-dependencies).

## Metasploit Framework

`MetasploitClient` uses `pymetasploit3` RPC against a standalone `msfrpcd`
(launched by `bootstrap.py`'s `start_mcp()`; port `MSF_RPC_PORT`, default
55553). Singleton via `get_instance()` so bootstrap's `start_mcp()` and
in-process tool launches share the same `MsfRpcClient`/daemon.

`dispatch_metasploit(module_path, category, options, start_handler=False)` —
single entry point for all MSF module execution. The `category` argument
('exploit', 'auxiliary', or 'post') is required and must match the prefix of
`module_path`; the wrapper refuses mismatches and `category='post'` requires
a `SESSION` option. Backed internally by
`_execute_module_impl(module_path, options, start_handler, category)`.
The non-obvious parts, all driven by hard-won reproduction against the lab
target:

- **Payload family matters most.** A binary FTP/TFTP-stager payload
  (`cmd/linux/ftp/<arch>/*`, `cmd/linux/tftp/<arch>/*`) cannot stage an ELF
  through a raw-shell backdoor channel (e.g. vsftpd_234_backdoor's port 6200)
  and fails at the command-stager stage with **"Unsupported Binary
  Selected"**. Use a **pure-command** `cmd/unix/*` payload that runs a
  one-liner on the shell (e.g. `cmd/unix/bind_perl`,
  `cmd/unix/reverse_perl`, `cmd/unix/bind_netcat_gaping`).
  `dispatch_metasploit` validates `PAYLOAD` against
  `module.compatible_payloads` and steers the caller at `cmd/unix/*`.
- **Meterpreter payloads run through this client now** — the old
  `AutoLoadExtensions` non-scalar serialization bug no longer reproduces on
  current msfrpcd (dispatch launches verified with non-null job_id). Preset
  defaults stay pure shell; meterpreter is a valid explicit `generate_payload`
  choice, and dispatch holds its callback like any other.
- **`AutoCheck=False` + `ForceExploit=True` are harness defaults** for
  exploit modules (caller can override either via `options`). The operator
  already approved the run via the human-in-the-loop gate, and the check is
  pure friction for backdoor-style exploits — once the backdoor port is open
  from a prior run, `AutoCheck` aborts with "Cannot reliably check
  exploitability … set ForceExploit true".
- **`start_handler` (opt-in).** Over msfrpcd an exploit module's *implicit*
  payload handler does not reliably bind a reverse/bind listener, so the
  payload's callback reaches nothing and no session forms. Pass
  `start_handler=True` to start a separate persistent
  `exploit/multi/handler` job (same `PAYLOAD`/`LHOST`/`LPORT`) first;
  `dispatch_metasploit` then sets `DisablePayloadHandler=True` so the
  exploit doesn't double-bind the port. Pass `start_handler=False` (default)
  for auxiliaries/login scanners and for "manual" exploits that *require*
  their own handler and reject `DisablePayloadHandler` (e.g.
  vsftpd_234_backdoor) — the error message tells the model which case it hit.
- **LHOST must be reachable *from the target*.** A reverse payload makes the
  target call back to `LHOST:LPORT`; if the target can't route to it (e.g. a
  VM behind a tailscale subnet router that can't reach your `100.x`), no
  session forms even with a perfect handler. For such targets use a **bind**
  pure-command payload (`cmd/unix/bind_*`) with `RHOST` set to the target —
  the target opens a port and we connect to it.
- **Launch-failure detection.** `module.execute()` returning
  `{"job_id": null}` (refused to launch — missing/invalid PAYLOAD or a
  required option, or `DisablePayloadHandler` on a module that needs its own
  handler) or an `{"error": true, "error_message": ...}` envelope is
  surfaced immediately as a clear, actionable error instead of being masked
  by the 30s session-poll ("No new sessions detected"). Any `start_handler`
  listener started is stopped on launch failure so it isn't left orphaned.

Confirmed end-to-end on a lab target: `dispatch_metasploit` with
`cmd/unix/bind_perl`, `RHOST` = the target, `LPORT` = the handler port
yields a persistent `msf:` shell session that `interact_session` reads
(`uid=0(root)` on `Linux metasploitable`).

### Session lane

Sessions live on the MSF RPC daemon, not in this process — `list_sessions`
and `interact_session` re-derive state from the daemon on every call, so
they survive Brain restarts. `close_msf_session` tears a session down; the
operator's scope obligations don't lapse with it.

## msfvenom Payload Generation + Upload Lane

The file-upload vulnerability testing lane, closing the "generate an
artifact, push it through a vulnerable upload form" gap. The flow every tool
here is built around:

    generate_payload  ->  session_upload  ->  session_get (trigger URL)
    (start_handler=True)       |                        |
              ^----------------+--- handler catches the callback

- **`generate_payload`** runs msfvenom (subprocess, argv list — no shell)
  into the gitignored `dropbox/` folder at the repo root (override
  `MSFVENOM_DROPBOX`; see [`../dropbox/README.md`](../dropbox/README.md)).
  The envelope returns the absolute `out_path` + `sha256` + `size_bytes` —
  hand `out_path` straight to `session_upload`. `presets`
  (`php`, `jsp`, `war`, `aspx`, `asp`, `python`, `nodejs`, `ruby`, `elf`,
  `exe`, `php_bind`) fill payload+format+extension defaults for a target
  stack; `msfvenom_menu` browses payloads/formats/encoders by substring
  query; `list_dropbox` recovers artifacts from earlier turns when the
  `out_path` was lost.
- **`encrypt` / `encrypt_key` / `encrypt_iv`** invoke msfvenom's real-cipher
  `--encrypt` (aes256, aes256cbc, rc4, xor, base64; key/IV hex-validated
  before the binary runs, exact names via `msfvenom_menu(kind='encrypt')`).
  Emits ENCRYPTED RAW SHELLCODE only — the decrypt-and-execute wrapper is the
  `encoders/` loader lane's job, so pair the artifacts or they just sit there.
- **`start_handler=True`** starts a persistent `exploit/multi/handler` job
  via `MetasploitClient._start_handler_job` — the shared handler-start
  primitive extracted from `_execute_module_impl` so both the dispatch lane
  and this lane start identical listeners. It calls the client *directly*,
  NOT through `dispatch_metasploit`: the handler is an inbound listener with
  no RHOSTS, and the armed scope gate refuses exploit dispatches that lack
  RHOSTS — an end-around that is safe because nothing is sent to a target.
  A handler failure never fails the generation — it lands in the envelope's
  `handler` sub-dict; the artifact exists either way.
- **Scope stance**: generation is offline compute (no gate — same class as
  `hash_crack`); the *delivery* steps are gated: `session_upload` and the
  trigger `session_get` are per-hop scope-gated like all framework HTTP (see
  [`../utils/README.md#scope-gate--operator-armed-scope_gatepy`](../utils/README.md#scope-gate--operator-armed-scope_gatepy)).
- **`session_upload`** (in `../auxiliaries/web_session.py`) is the multipart
  delivery step: reads a local artifact, POSTs `multipart/form-data` with
  jar cookies applied and the stored CSRF token auto-injected as a *form
  field* (multipart can't carry a raw body string — `data` must be a dict of
  form fields). `file_name` overrides the multipart filename independently
  of the local file (extension-filter bypasses are server-side filename
  games: upload `shell.php.jpg` from a local `shell.php`); the content type
  is sniffed from that name. Validation of *local* inputs (missing source,
  size cap via `SESSION_UPLOAD_MAX_MB`, bad `data` shape) raises
  `ValueError` — `ScopeGateError` stays reserved for "the armed gate blocked
  traffic", so the secretary never reads a local-input problem as a scope
  decision.
- **LHOST reachability** is the operator's call, same rule as the MSF lane:
  reverse payloads need the target to route back; for targets that can't,
  use a bind payload (`php_bind` preset, `*/shell_bind_tcp`) and connect
  after triggering.

## C/C++ payload plugins

- `payloads/plugins/listen.cpp` — payload listener stub.

Compiled with `gcc -shared -o listen.so -fPIC listen.cpp`; loaded via
`ctypes.CDLL` in a Python wrapper (always set `argtypes` and `restype`
explicitly — see the plugins convention in
[`AGENTS.md`](../AGENTS.md#language-choice)).