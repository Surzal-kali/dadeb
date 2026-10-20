# tool_repl IPython Playbook
### Scripting the framework arsenal — 196 tools as awaitable callables

- **Snapshot:** verified against git HEAD `7ee2e8e` (tree clean), Oct 9 2026. Regenerate the appendix by re-running the inventory snippet (§9.9) if the codebase has moved.
- **Path:** `/root/stuff/scope/sovereign_hive/tool_repl_playbook.md`
- **Related:** `/root/stuff/scope/sovereign_hive/bench.md` (scoreboard), `/root/bugcheck_ledger.md` (in-flight work)

---

## 1. The mental model in 6 lines

```
python3 /root/stuff/tool_repl.py     # top-level REPL: list | info | run | search | sessions | scope
  └── ipython                        # drops INTO IPython (tools preloaded as async callables)
        └── nmap(target="10.10.14.1", options="-Pn -p-")   # WRONG inside IPython
        └── await nmap(target="10.10.14.1", options="-Pn -p-")   # RIGHT — autoawait is on
```

Every tool is a ghost-text-completing async callable built from its manifest:
- **174 tools discovered live** on the sandbox box + **22 source-extracted** from modules that failed import (listeners/*, utils/findings, utils/memory_tools, auxiliaries/smb_scanner) = **196 total**. See Appendix A for the full table and Appendix B for keyboard shortcuts.

- **`await tool(...)`** returns the `stdout` string from the tool body (most tools return str/JSON-as-str).
- **`print(f"{_!r}")`** on the value shows the envelope, including `_elapsed_s` and any `degraded` flags.
- **`tool?`** prints the manifest: full param schema with descriptions. **`tool??`** prints the tool's source.
- **Syntax highlighting** is ON (Pygments `IPythonPTLexer` + `colors="linux"`). Override with `IPYTHON_COLORS=neutral|lightbg|nocolor|pride|gruvbox-dark`.
- **Bottom toolbar** shows cursor `L:col`, a compact cell overview (`[first line … (+NL)]`), **in-cell variables** (uncommitted — parsed from the current cell text above your cursor, not yet executed), committed globals count + previews, scope-armed marker, and Brain socket status — re-renders every keystroke. Disable with `IPYTHON_TOOLBAR=0`.
- **F1** dumps all user variables — both **in-cell** (uncommitted, parsed via `ast`) and **committed globals** — above the prompt with type names and repr/preview values.
- **Right prompt** shows missing required params when the cursor is inside a `tool(` call — live, right-aligned. Disable with `IPYTHON_RPROMPT=0`.
- **Bad kwarg names are rejected, not dropped** — `run_tool` goes through `preflight.validate_against_manifest` (unknown-key rejection), so a typo produces an explicit error envelope from a healthy run, not a silent no-op.
- **`scope off` is implied**: REPL-local runs bypass the agent-facing scope gate by design (`run_tool` calls `execute_tool` directly; operator-only gate lives in `scope on/off` commands). Know what lane you're in before you fire.

---

## 2. Sessions, handles, and the shared-session trap

Tool state is a `utils/session_manager.SessionManager` PROCESS-LOCAL singleton — whichever process actually executes the tool holds the live object. The Brain sidecar owns everything shared across lanes.

| you invoke | brain.sock up | result |
|---|---|---|
| `await ssh_connect(...)` inside IPython | YES | Brain session → **shared with the agent lane** (the front-end wrapper can `execute_tool` ssh_exec the same handle) |
| `await ssh_connect(...)` inside IPython | NO | in-process fallback. The result dict is tagged `degraded=True` → **any session opened is REPL-local**, invisible to the agent. |
| `await ssh_connect(...)` inside a python subprocess/spawned script | n/a | REPL-local, always |
| `msf_dispatch`, msf session interactions | n/a | msf handles are msfrpcd-backing — shared across lanes no matter who opened them |

**`sessions()`** prints brain-held vs REPL-local sessions side by side. If your handle isn't in the brain-held list, the agent lane can't see it.

**A degraded session result has VOID negative-existence value**: if `degraded: true` is stamped on a "no results" return, treat the negative as unproven until re-run with the socket healthy. Standing rule T-01.

**The one-shot trap.** `python3 tool_repl.py run <tool>` opens tool state in a process that EXITS immediately — never one-shot with stateful tools. Same rule inside IPython for stateful handles: prefer opening handles in the plain REPL (`ssh_connect ...` at the `repl>` prompt), then use them from IPython; or open through the OWUI agent lane itself, and script against what's already there.

**REPL open + script use** (recommended pattern; the plain REPL and `ipython` live in the same process):

```python
# at `repl>`: run utils.paramiko_client.ssh_connect --hostname 10.10.14.5 --username svc --password s3cr3t
# then: ipython  →  await ssh_exec("ssh:sess-0001", "id; cat /etc/passwd")
```

---

## 3. Async essentials for this harness

Autoawait is forced ON (`shell.loop_manager = "asyncio"`), so top-level `await` works in every cell.

1. Top level: **`x = await ssh_exec("ssh:sess-0001", "uname -a")`**
2. Inside sync loops, gather over aliases:
```python
results = await asyncio.gather(*[
    ssh_exec(h, "id") for h in handles
])
```
3. The helpers in §1 are also in the namespace (`run_tool`, `manifest_by_id`, `registry`). Calling `registry.execute_tool(manifest, args)` directly bypasses the print overhead and returns the envelope dict.
4. `asyncio.create_task` works. Keep task handles in a dict keyed by intent so you can await them later.

---

## 4. Argument conventions (don't re-learn tool syntax)

Tool functions are plain python functions — you pass **kwargs**, no CLI flag syntax. Key traps learned in the field (keep paying attention to these; the trap list is the doc's most load-bearing section):

| tool | gotcha |
|---|---|
| ssh_connect | positional `hostname, username, password, port=22` — NOT `user=`. |
| ssh_exec / ssh_shell | takes `handle` ("ssh:sess-0001"; see sessions()), `command`. |
| nmap (run_nmap) | returns a `job_id` immediately. Poll with `await nmap_status(job_id=...)`. Long port sets return while still scanning. `options` is a raw string of nmap switches. |
| masscan | same `job_id` pattern, poll with `masscan_status(job_id=...)`. |
| ffuf (ffuf_payload) | `wordlist` is a bare PATH STRING. Call `await list_wordlists(query="<kw>")` first to pick a file; `payloads.wordlists` registry is box-variable (never assume an entry survives an app update, `run_ffuf` fail-fasts on missing paths). |
| hashcat | `hash_input`, `mode` (number, as str or int), `options`, `wordlist` — poll with `hashcat_status(job_id=...)`. |
| session_request | `method, url, data=None, json_data=None, headers=None` etc. — use kwargs, don't rely on arg order. |
| web_login_brute | requires explicit `username` (the username to try), plus `username_field`/`password_field` (form field names). Read tool? before firing. |
| zap_* | needs the ZAP daemon up; check `framework_status()` first if you're getting weird empties. |
| packetcraft | `send_packet(hex=...)` etc. — the packetcraft tools are raw scapy wrapped; craft_* tools take named parameters (see tool?). |

The `wordlist`-is-a-bare-path and `password`-vs-`passwd`-style traps are the two highest-value habits: preflight catches bad KEYS, and schema coercion fixes type mismatches, but **wrong-meaning strings pass cleanly**. Read `tool?` before the first call; if a call succeeds but the output is absurd (e.g. only 3 lines of crack output for a 10M-entry wordlist), suspect arg semantics before suspecting the tool.

---

## 5. Chain patterns (the real leverage)

### A. Nmap-then-probe in one cell

```python
import asyncio
jid = (await nmap(target="10.10.14.1", options="-Pn -sV -p-")).strip()
print("job:", jid)
await asyncio.sleep(20)
status = await nmap_status(job_id=jid)
print(status)
```

When the scan is done (status shows completion), feed `probe_web` — a single call that fans a whole netblock/port-list probe at 48 threads:

```python
out = await probe_web(targets="10.10.14.1,10.10.14.5", ports="80,443,8080,8443,5985,47001")
print(out)
```

### B. Web session + login test + ffuf chaining

```python
import asyncio
jar = await session_request(method="POST", url="http://target.htb/login",
                            data={"user":"svc","pass":"guess"},
                            headers={"Accept":"*/*"})
print(jar)
probe = await web_login_probe(url="http://target.htb/login", username="svc",
                              password_field="pass", username_field="user")
print(probe)
```

`session_request` / `session_get` / `session_post` share ONE cookie jar automatically — chain auth→enum→post-exploit requests across cells with no manual cookie juggling, and reach for `jar_state()` / `jar_cookie_header()` when you want to inspect or reuse what the jar holds. Manual `headers=...` injection still wins when you need a specific crafted auth blob (JWT replay, host-header attacks).

### C. SSH pivot + command chaining in a single cell

```python
import asyncio
async def sweep(h, cmds):
    return {c: await ssh_exec(h, c) for c in cmds}

h = "ssh:sess-0001"
print(await sweep(h, ["id", "sudo -n -l", "ls -la /etc/cron.d/", "cat /etc/passwd | grep sh$"]))
```


### D. SMB / impacket run-and-poll

```python
out = await smb_enum_shares(target="10.10.14.5")
print(out)
readback = await smb_read_file(target="10.10.14.5", share="Replication", path="\\\\Groups.xml")
print(readback)
```

### E. The "big cell" that closes the chain (one cell per STAGE, not per command)

- stage1: nmap → job_id
- stage2: probe_web on the discovered service IP/port
- stage3: session_request against the app on the discovered port
- stage4: payload/exploit dispatch (msf_dispatch / searchsploit)
- stage5: ssh_connect into the shell handle once creds fall out, then sweep() like §C

Keep each stage's cell short and self-contained. If a stage explodes, copy the one cell above it into a new tab/edit — don't rebuild the whole chain.

---

## 6. MSF lane from inside IPython

MSF tools are thin clients over the msfrpcd daemon — you MUST have msfrpcd reachable first (`transport preflight`: if it fails, start it before scripting msf). From there the scripting surface is real:

```python
import asyncio
mods = await msf_index()                      # module index (job)
await msf_options(module="exploit/multi/http/...")
await msf_dispatch(module="exploit/...", rhosts="10.10.14.5", rport=..., ...)
sids = await msf_sessions()
out = await msf_interact(session=sids[0], command="id")   # interact, then run cmd
print(out)
```

Field rules that hold regardless of lane:

- **transport preflight is mandatory**: before `run`, curl the target both plaintext and with `-sk https://...`; whichever returns 200 sets `RPORT`/`SSL`. Self-signed cert = `SSL true` + `SSLVerify false`, never auto-off.
- **no `sleep N` in ssh_exec/msf commands inside the MCP/bridge lane** — polls must be command-only; long waits → background it to a file and poll later. (Same rule applies to the REPL: don't write `ssh_exec(h, "sleep 30; whoami")` and expect an instant return.)

---

## 7. Listener lane (shared with the agent)

```python
await listen_tcp(host="0.0.0.0", port=9001)   # returns handle like "listener:tcp-9001"
await close_listener(handle="listener:tcp-9001")
```

The `send_to_brain(event=..., data=...)` tool fires a FrameworkEvent into the Brain's event stream — useful when you want the agent lane to log a milestone mid-chain. If you're scripting long-running reverse shells, prefer listeners opened on the Brain (i.e. by the agent) so state stays visible across lanes.

---

## 8. Common failure paths (what the errors mean)

| symptom you see in a cell | root cause | fix |
|---|---|---|
| `await nmap(...)` hangs >60s with no output | preflight reject of bad keys (schema mismatch) — check `x.__manifest__` signature | call `await nmap(target=..., options=...)` with the manifest's exact param names |
| result dict says `degraded: true` | brain.sock down → in-process fallback; your sessions are REPL-local | rerun from `repl>` top level so the brain owns the session; or restart the Brain and re-open handles |
| `preflight` rejection envelope | unknown kwarg / missing required key / enum mismatch | `tool?` and fix the kwargs; `registry.execute_tool(manifest, args)` returns the exact rejection envelope |
| `Error: Unknown tool_id` on a valid-looking alias | alias collision resolved with `top_alias` prefixing (see §1) | use the canonical id via `manifest_by_id("full.id")` and call `run_tool(id, {...}, manifests)` |
| shell feels dead / no stdout echo over relay | legacy pipefail/head SIGPIPE bug in pipe relays | `set +e` first; file-buffer + sed-slice output; ship single-line base64 payloads, compile locally first |
| tool returns fast with plausible-but-wrong data | Brain socket down fallback (degraded) | never trust negative-existence results from degraded runs; re-verify on healthy socket |

---

## 9. Quick reference

### 9.1 Getting in

```bash
cd /root/stuff
python3 tool_repl.py          # top-level REPL
python3 tool_repl.py run auxiliaries.nmap.run_nmap --target 127.0.0.1 --options "-Pn -p 22"   # one-shot
python3 tool_repl.py info auxiliaries.nmap.run_nmap   # manifest without running
python3 tool_repl.py search "brute force ssh"          # semantic search (rank #1 prints at bottom)
python3 tool_repl.py sweep --safe                      # safe-args sweep
```

### 9.2 Inside IPython, one-liner index

```python
sessions(); scope_status(); scope_off()
manifest_by_id("auxiliaries.masscan.run_masscan")
t = manifest_by_id("auxiliaries.web_session.session_request"); print(t.__doc__)
out = await run_tool("auxiliaries.amass.subdomain_enum", {"domain":"example.com"}, manifests)
print(out)
```

### 9.3 Environment

`OLLAMA_COMPLETION_ENABLED=0` to kill ghost-text if a local model keeps lagging the prompt.

`OLLAMA_COMPLETION_MODEL` → falls back SECRETARY_MODEL → `qwen2.5-coder:7b`. Circuit breaker: 5 failures → 15s cooldown. Cold-start: first call gets an extended (10s+) timeout, 3 cold failures then the breaker opens (protects wrong model names / VRAM exhaustion).

**FIM (fill-in-the-middle):** the suggester sends both the text **before** and **after** the cursor, separated by a `<CURSOR>` marker. This lets the model see closing brackets/dedent and know what construct it's completing inside (e.g. `]` after a blank line in `payloads = [...]`). If the model echoes the after-cursor text, `_trim_completion` strips it. Knobs: `OLLAMA_COMPLETION_MAX_AFTER_CHARS` (default 500), `OLLAMA_COMPLETION_CURSOR_MARKER` (default `\n<CURSOR>\n`).

**UI env knobs (all default ON):**
- `IPYTHON_COLORS` — Pygments color scheme: `linux` (default, dark terminal) | `neutral` | `lightbg` | `nocolor` | `pride` | `gruvbox-dark`. Syntax highlighting is always wired (IPythonPTLexer); this controls the style palette.
- `IPYTHON_TOOLBAR=0` — disable the bottom status bar (cursor position, live globals, scope/brain status).
- `IPYTHON_RPROMPT=0` — disable the right-aligned param hints inside tool calls.
- `IPYTHON_TOOLBAR_MAX_VARS=6` — max variable previews shown in the toolbar compact line.
- `IPYTHON_TOOLBAR_REPR_LEN=20` — max repr length per variable in the toolbar.
- `IPYTHON_MOUSE=0` — disable click-to-position-cursor (mouse capture off; terminal-native drag-to-select works without Shift). Default ON: click to move cursor, **Shift+drag** to select text.

### 9.4 The full alias table

See **Appendix A** at bottom of this file — every one of the 197 tools with its alias + full param signature. **Appendix B** has the full IPython keyboard shortcut reference.

### 9.5 Regenerate the appendix

```bash
cd /root/stuff && python3 - <<'EOF'
import sys
from tool_repl import discover_tools, build_tool_aliases
ms = discover_tools()          # RUN FROM /root/stuff — WORKSPACE_ROOT resolves from cwd
amap = build_tool_aliases(ms)
id2alias = {m.module_id: a for a, m in amap.items()}
for m in sorted(ms, key=lambda x: x.module_id):
    props = (m.parameters or {}).get("properties", {})
    req = set((m.parameters or {}).get("required", []))
    params = ", ".join(f"{'*' if p in req else ''}{p}" for p in props)
    print(f"{m.module_id.split('.')[0]:12s}|{id2alias.get(m.module_id,'?'):25s}|{m.module_id}|{params}")
EOF
```

(Cwd discipline here is the same rule as the test suite: `WORKSPACE_ROOT = Path(os.getenv("WORKSPACE_ROOT", os.getcwd()))` — a non-repo-root cwd silently zeroes discovery.)

---

## 10. Scope-gate note (operator-only surface)

`run_tool` inside IPython bypasses the agent-facing scope gate by design (the gate is what keeps the assistant-side `send_packet`/session tools from firing out-of-scope). The operator REPL never arms it. If you're scripting against a bug-bounty target THROUGH the agent lane, arm the gate there (`scope on <handle>`) and script locally against a DIFFERENT, authorized-lab target. Don't mix the two lanes in one script — keep lab lanes lab, live lanes live, and the tool wrapper's preflight/manifest schema will do the rest.

---

## 11. When the box moves fast — live-session cheatsheet

While an engagement is live, you'll want a small set of aliases in muscle memory:

- recon: `await nmap(...)`, `await masscan(...)`, `await probe_web(...)`
- web: `await session_request(method="GET", url=...)`, `await ffuf(url=..., wordlist=...)`, `await js_recon(url=...)`
- auth brute: `await hydra(...)`, `await web_login_brute(...)`
- win lanes: `await smb_recon(...)`, `await secretsdump(target=...)`, `await psexec(target=..., username=..., password=..., command=...)`
- post: `await ssh_connect(...)`, `await ssh_exec(...)`, `await hash_crack(hash_input=..., mode=...)` — verify exact kwarg names with `tool?` (they're in Appendix A)
- listeners: `await open_listener(host="0.0.0.0", port=4444)`, `await read_listener(handle="listener:...")`, `await send_to_listener(handle="...", data="id\n")` — reverse shell drive loop
- OOB collab: `await collab_start()`, `await collab_generate()`, `await collab_poll(since=...)` — blind SSRF/XSS callback catching
- findings: `await report_finding(title=..., severity="P2", asset=...)` (terminal chain action), `await render_findings()` (mid-session review)
- memory: `await remember_text(text="root pw is toor")`, `await recall_text(query="ftp credentials")`, `await recall_text(query="recon", target="10.0.0.5", since_hours=24)` — cross-session persistence with recency-weighted ranking
- zombie control: `await list_tool_executions()`, `await kill_tool_execution(exec_id=...)` — Brain wedged? find and kill
- session hygiene: `sessions()` after any lane switcheroo

---

## 4.5 Shell interop from IPython (`!` prefix) — verified against IPython 9.17

`x = !<shell cmd>` runs the command and captures output as an `SList` (list of lines + str views). Two-way interop works, but the expansion rules have teeth:

**Who expands what, in what order:**

| form | semantics | teeth |
|---|---|---|
| `x = !cmd args` | capture → SList of lines | |
| `x.s` / `x.n` / `x.l` / `x.p` | single-str (spaced) / newlines / list / repr | |
| `x.fields(1)` / `x.grep("pat")` / `x.paths()` | split-column / grep lines / glob-out lines | `.g()` died in IPython 9.x — use `.grep()` |
| `!cmd $pyvar` | `$name` = IPython expands PYTHON ns first; if unset, falls back to the shell env | set a python var named HOME → python wins |
| `!cmd {py_expr}` | `{}` = IPython compiles the expr and splices the literal result BEFORE bash sees the line — quoting does NOT protect it: `!echo "user-{name}"` interpolates even in double quotes | wrap any shell-meaningful `{}` payload in single quotes (unexpanded by IPython? no — single quotes also pass through to bash, which then treats them as literal — test first), or precompute: `lit = "{"; !cmd {lit}}` |
| `!cmd $$LITERAL` | BROKEN IN 9.17: collapses to `{n}LITERAL` in transit (e.g. `$$HOME` → `24774HOME`) | shell-escape with backslash instead: `!echo literal \$HOME` |
| `!!cmd` | "return str not SList" — BROKEN in 9.17: ships `!` into the shell (`/bin/sh: 1: !echo: not found`) | plain `!` + `.s` is the reliable form |

**The shell is `/bin/sh` (dash), not bash** — no arrays, no `<(process substitution)`, no `$( )`-with-bashisms. POSIX-pure pipeline idioms only (pipes, `xargs`, `grep/awk/sed/sort/uniq`, `head/tail -c`, for-loops over vars). Error lines come back `/bin/sh: 1: <cmd>: not found` — read that as dash-isms, not IPython breakage.

**Handoff with `run_tool` results (the standard loop):**

```python
out = str(await run_tool("auxiliaries.nmap.run_nmap", {"target":"..."}, manifests))
open("/tmp/scan.txt","w").write(out)        # python-side file write (no arg-size limits)
!grep -i "open" /tmp/scan.txt | sort -u | head -40
ports = !grep -oE "Ports: [0-9/]+" /tmp/scan.txt      # back into python when you want structure
counts = !cat /tmp/scan.txt | awk '{c[$1]++} END{for (k in c) print c[k], k}' | sort -rn | head -5
```

Rule of thumb: **write-through-a-file** beats passing big strings through `$var` (dash env-size + newline handling in `-c` contexts both flake), and *python-side re/regex beats shell text-munging* whenever the structure matters — shell is for the quick grep/awk/sort class, python for everything else.

Exit codes from `!` are not directly exposed (failed commands yield an empty SList + stderr noise, not an rc). When rc matters, drive subprocess inside python instead.


## 12. Open notes

- `run_tool` prints 4 noisy lines per call (`[repl] Running ...`). Wrap it when you want clean output (see §1's second envelope tip), or patch locally to gate the prints behind a module-level DEBUG flag if the noise gets old in chains.
- The executor has a `_BRAIN_TIMEOUT = 60.0` — long-running calls (wordlists, deep scans) that exceed it will return a timeout envelope with the work still running Brain-side. Treat that envelope as "check the job tool/status" rather than a failure.
- This doc is intentionally example-heavy and theory-light. When a NEW pattern earns its keep in a live session, append it here (§5 or §9) in the same commit that touches the scoreboard.

Appendices follow.


---

# Appendix A — Full tool inventory (196 tools @ 7ee2e8e)

Generated from live discovery (§9.5) + source-extracted signatures for the previously-absent modules. Alias = the name bound in your IPython namespace. `*` marks required params.

NOTE (sandbox copy caveat): modules whose import chain needs `listeners/plugins/frameit.so` (thebrain) fail to IMPORT on this box and are therefore ABSENT from the live-scan appendix. The remaining previously-absent modules (findings, memory_tools, smb_scanner, listening, collaborator, raw_scan, brain_control) are now included below — their signatures were extracted from source rather than live discovery, so verify exact kwarg names with `tool?` on first call (same rule as every other tool). If the .so path is fixed and you re-run §9.5, these will appear in the live scan output as well.

### auxiliaries  (105 tools)

| alias | tool_id | params (* = required) |
|---|---|---|
| `amass_status` | `auxiliaries.amass.amass_status` | *job_id |
| `amass` | `auxiliaries.amass.run_amass` | *target, options, scope_platform, scope_handle |
| `subdomain_enum` | `auxiliaries.amass.subdomain_enum` | *target, options, scope_platform, scope_handle |
| `subdomain_enum_status` | `auxiliaries.amass.subdomain_enum_status` | *job_id |
| `archived_urls` | `auxiliaries.archived_urls.archived_urls` | *domain, limit, statuscode, collapse |
| `burp_base64_decode` | `auxiliaries.burp_mcp.burp_base64_decode` | *content |
| `burp_base64_encode` | `auxiliaries.burp_mcp.burp_base64_encode` | *content |
| `burp_create_repeater_tab` | `auxiliaries.burp_mcp.burp_create_repeater_tab` | *content, *target_hostname, *target_port, uses_https, tab_name |
| `burp_create_repeater_tab_http2` | `auxiliaries.burp_mcp.burp_create_repeater_tab_http2` | *pseudo_headers, *target_hostname, *target_port, uses_https, headers, request_body, tab_name |
| `burp_get_proxy_history` | `auxiliaries.burp_mcp.burp_get_proxy_history` | count, offset |
| `burp_get_proxy_history_regex` | `auxiliaries.burp_mcp.burp_get_proxy_history_regex` | *regex, count, offset |
| `burp_get_proxy_websocket_history` | `auxiliaries.burp_mcp.burp_get_proxy_websocket_history` | count, offset |
| `burp_get_proxy_websocket_history_regex` | `auxiliaries.burp_mcp.burp_get_proxy_websocket_history_regex` | *regex, count, offset |
| `burp_health` | `auxiliaries.burp_mcp.burp_health` |  |
| `burp_list_tools` | `auxiliaries.burp_mcp.burp_list_tools` |  |
| `burp_output_project_options` | `auxiliaries.burp_mcp.burp_output_project_options` |  |
| `burp_output_user_options` | `auxiliaries.burp_mcp.burp_output_user_options` |  |
| `burp_reconnect` | `auxiliaries.burp_mcp.burp_reconnect` |  |
| `burp_send_http1_request` | `auxiliaries.burp_mcp.burp_send_http1_request` | *content, *target_hostname, *target_port, uses_https |
| `burp_send_http2_request` | `auxiliaries.burp_mcp.burp_send_http2_request` | *pseudo_headers, *target_hostname, *target_port, uses_https, headers, request_body |
| `burp_send_raw` | `auxiliaries.burp_mcp.burp_send_raw` | *raw_request, uses_https |
| `burp_send_to_intruder` | `auxiliaries.burp_mcp.burp_send_to_intruder` | *content, *target_hostname, *target_port, uses_https, tab_name |
| `burp_set_proxy_intercept` | `auxiliaries.burp_mcp.burp_set_proxy_intercept` | *intercepting |
| `burp_set_task_engine_state` | `auxiliaries.burp_mcp.burp_set_task_engine_state` | *running |
| `burp_url_decode` | `auxiliaries.burp_mcp.burp_url_decode` | *content |
| `burp_url_encode` | `auxiliaries.burp_mcp.burp_url_encode` | *content |
| `clear_certs` | `auxiliaries.cert_tools.clear_certs` |  |
| `generate_certs` | `auxiliaries.cert_tools.generate_certs` | common_name, days |
| `inspect_host` | `auxiliaries.cert_tools.inspect_host` | *host, port, sni, timeout |
| `inspect_pem` | `auxiliaries.cert_tools.inspect_pem` | *cert_data |
| `cors` | `auxiliaries.cors_probe.check_cors` | *url, insecure, timeout |
| `security_headers` | `auxiliaries.cors_probe.check_security_headers` | *url, insecure, timeout |
| `db_close` | `auxiliaries.db_client.db_close` | *handle |
| `db_connect` | `auxiliaries.db_client.db_connect` | *host, *username, *password, port, dbms, database, domain, hashes, timeout |
| `db_exec` | `auxiliaries.db_client.db_exec` | *handle, *query, read_only |
| `db_exec_batch` | `auxiliaries.db_client.db_exec_batch` | *host, *username, *password, *queries, port, dbms, database, domain, hashes, read_only, pace, timeout |
| `db_schema_farm` | `auxiliaries.db_client.db_schema_farm` | *host, *username, *password, port, dbms, database, domain, hashes, max_dbs, max_tables, max_columns, include_samples, sample_tables, timeout |
| `ptr_lookup` | `auxiliaries.dns_lookup.ptr_lookup` | *ips, timeout |
| `resolve_host` | `auxiliaries.dns_lookup.resolve_host` | *hostnames, timeout |
| `framework_health` | `auxiliaries.framework_status.framework_health` |  |
| `ftp_anon_check` | `auxiliaries.ftp_recon.ftp_anon_check` | *host, port, timeout, interface |
| `ftp_banner` | `auxiliaries.ftp_recon.ftp_banner` | *host, port, timeout, interface |
| `ftp_get` | `auxiliaries.ftp_recon.ftp_get` | *host, *username, *password, *remote, *local, port, timeout, interface |
| `ftp_list` | `auxiliaries.ftp_recon.ftp_list` | *host, *username, *password, path, port, timeout, max_lines, interface |
| `ftp_put` | `auxiliaries.ftp_recon.ftp_put` | *host, *username, *password, *local, *remote, port, timeout, interface |
| `sftp_get` | `auxiliaries.ftp_recon.sftp_get` | *host, *username, *password, *remote, *local, port, timeout |
| `sftp_list` | `auxiliaries.ftp_recon.sftp_list` | *host, *username, *password, path, port, timeout, max_entries |
| `sftp_put` | `auxiliaries.ftp_recon.sftp_put` | *host, *username, *password, *local, *remote, port, timeout |
| `atexec` | `auxiliaries.impacket_suite.atexec_exec` | *target, *command, username, password, domain, extra_options |
| `kerberoast` | `auxiliaries.impacket_suite.kerberoast` | *target, username, password, domain, dc_ip, request, request_user, output_file, extra_options |
| `psexec` | `auxiliaries.impacket_suite.psexec_exec` | *target, *command, username, password, domain, extra_options |
| `request_tgs` | `auxiliaries.impacket_suite.request_tgs` | *spn, *domain, *username, password, dc_ip, hashes, aes_key |
| `secretsdump` | `auxiliaries.impacket_suite.secretsdump` | *target, username, password, domain, extra_options |
| `smb_enum_shares` | `auxiliaries.impacket_suite.smb_enum_shares` | *target, username, password, domain |
| `smb_read_file` | `auxiliaries.impacket_suite.smb_read_file` | *target, *share, *path, username, password, domain, max_bytes |
| `check_null_session` | `auxiliaries.smb_scanner.SMBScanner.check_null_session` | *target, remoteName |
| `run_smb_recon` | `auxiliaries.smb_scanner.run_smb_recon` | *targets |
| `wmiexec` | `auxiliaries.impacket_suite.wmiexec_exec` | *target, *command, username, password, domain, extra_options |
| `list_apk_targets` | `auxiliaries.jadx.list_apk_targets` |  |
| `jadx` | `auxiliaries.jadx.run_jadx` | *target, *command, deobf, show_bad_code, mode, threads, no_res, force, single_class, pattern, glob, case_insensitive, max_matches, max_files, path, offset, tree_mode, limit |
| `ldap_rootdse` | `auxiliaries.ldap_search.ldap_rootdse` | *host, port, timeout, extra_options |
| `ldap_search` | `auxiliaries.ldap_search.ldap_search` | *host, *base_dn, filter, scope, attributes, bind_dn, bind_password, port, size_limit, timeout, extra_options |
| `masscan_cancel` | `auxiliaries.masscan.masscan_cancel` | *job_id |
| `masscan_status` | `auxiliaries.masscan.masscan_status` | *job_id |
| `masscan` | `auxiliaries.masscan.run_masscan` | *target, ports, rate, adapter, flags, exclude, options |
| `nmap_scripts` | `auxiliaries.nmap.nmap_scripts` | query, category, detail, limit |
| `nmap_status` | `auxiliaries.nmap.nmap_status` | *job_id |
| `nmap` | `auxiliaries.nmap.run_nmap` | *target, options |
| `playwright_crawl` | `auxiliaries.playwright_recon.playwright_crawl` | *url, max_pages, max_depth, wall_cap, same_origin |
| `playwright_crawl_status` | `auxiliaries.playwright_recon.playwright_crawl_status` | *job_id |
| `playwright_crawl_stop` | `auxiliaries.playwright_recon.playwright_crawl_stop` | *job_id |
| `playwright_fetch` | `auxiliaries.playwright_recon.playwright_fetch` | *url, wait_until, timeout_ms |
| `reportable` | `auxiliaries.program_scope.check_reportable` | *category_or_cwe, *handle, platform |
| `scope` | `auxiliaries.program_scope.check_scope` | *target, *handle, platform |
| `load_program_scope` | `auxiliaries.program_scope.load_program_scope` | handle, refresh, platform |
| `program_hacktivity` | `auxiliaries.program_scope.program_hacktivity` | handle, query, limit |
| `scope_search_programs` | `auxiliaries.program_scope.search_programs` | query, platform, limit, with_assets, handle, refresh |
| `list_r2_targets` | `auxiliaries.radare2.list_r2_targets` |  |
| `r2` | `auxiliaries.radare2.run_r2` | *target, *command, addr, count |
| `ssh_exec_batch` | `auxiliaries.ssh_exec.ssh_exec_batch` | *hostname, *username, *password, *commands, port, pace |
| `scan_ssrf` | `auxiliaries.ssrf_probe.scan_ssrf` | *target, param, method, body, collab_id, redirect_to, insecure, timeout, max_payloads, delay |
| `tls_info` | `auxiliaries.tls_info.tls_info` | *target, port, insecure |
| `web_login_brute` | `auxiliaries.web_login_brute.web_login_brute` | *url, *username, username_field, password_field, wordlist, max_attempts, rate, timeout, insecure, success_marker, fail_marker, success_statuses, host_header |
| `web_login_probe` | `auxiliaries.web_login_brute.web_login_probe` | *url, timeout, insecure, host_header |
| `web_login_test` | `auxiliaries.web_login_brute.web_login_test` | *url, *username, *password, username_field, password_field, timeout, insecure, host_header |
| `probe_web` | `auxiliaries.web_probe.probe_web` | *targets, ports, insecure, timeout, threads, wall_cap |
| `session_get` | `auxiliaries.web_session.session_get` | *url, insecure, timeout, body_limit, follow_redirects, headers |
| `session_post` | `auxiliaries.web_session.session_post` | *url, data, json_data, auto_csrf, insecure, timeout, body_limit, follow_redirects, headers |
| `session_request` | `auxiliaries.web_session.session_request` | *method, *url, data, json_data, insecure, timeout, body_limit, follow_redirects, headers |
| `session_upload` | `auxiliaries.web_session.session_upload` | *url, *file_path, file_field, file_name, content_type, data, auto_csrf, insecure, timeout, body_limit, follow_redirects, headers |
| `zap_active_scan` | `auxiliaries.zap.zap_active_scan` | *target, policy |
| `zap_active_scan_status` | `auxiliaries.zap.zap_active_scan_status` | *scan_id, base_url |
| `zap_ajax_spider` | `auxiliaries.zap.zap_ajax_spider` | *target |
| `zap_ajax_spider_status` | `auxiliaries.zap.zap_ajax_spider_status` |  |
| `zap_alert_message` | `auxiliaries.zap.zap_alert_message` | *alert_id |
| `zap_alerts` | `auxiliaries.zap.zap_alerts` | base_url, risk_id, summary, max_alerts |
| `zap_history_regex` | `auxiliaries.zap.zap_history_regex` | *target, *pattern, body_only |
| `zap_open_url` | `auxiliaries.zap.zap_open_url` | *target, scope_handle, scope_platform |
| `zap_report` | `auxiliaries.zap.zap_report` | report_format, report_file, report_title |
| `zap_send_raw` | `auxiliaries.zap.zap_send_raw` | *raw_request, follow_redirects, timeout |
| `zap_sites` | `auxiliaries.zap.zap_sites` |  |
| `zap_sites_tree` | `auxiliaries.zap.zap_sites_tree` | target |
| `zap_spider` | `auxiliaries.zap.zap_spider` | *target, max_depth, recurse |
| `zap_spider_status` | `auxiliaries.zap.zap_spider_status` | *scan_id |
| `zap_sync_scope` | `auxiliaries.zap.zap_sync_scope` |  |

### payloads  (29 tools)

| alias | tool_id | params (* = required) |
|---|---|---|
| `fastcgi_php_exec` | `payloads.fastcgi.fastcgi_php_exec` | *target, port, php_code, script_filename, server_name, timeout |
| `fastcgi_request` | `payloads.fastcgi.fastcgi_request` | *target, port, script_filename, php_value, php_admin_value, method, query_string, server_name, body, extra_params, timeout |
| `ffuf_cancel` | `payloads.ffuf.ffuf_cancel` | *job_id |
| `ffuf_status` | `payloads.ffuf.ffuf_status` | *job_id |
| `ffuf_payload` | `payloads.ffuf.run_ffuf` | *url, wordlist, options, scope_handle, scope_platform |
| `hashcat_show` | `payloads.hash_crack.hashcat_show` | *hash_input, *mode |
| `hashcat_status` | `payloads.hash_crack.hashcat_status` | *job_id |
| `john_show` | `payloads.hash_crack.john_show` | *hash_input, options |
| `john_status` | `payloads.hash_crack.john_status` | *job_id |
| `hashcat` | `payloads.hash_crack.run_hashcat` | *hash_input, *mode, options, wordlist |
| `john` | `payloads.hash_crack.run_john` | *hash_input, options, wordlist |
| `suggest_crack_mode` | `payloads.hash_crack.suggest_crack_mode` | *hash_string |
| `hydra_cancel` | `payloads.hydra.hydra_cancel` | *job_id |
| `hydra_status` | `payloads.hydra.hydra_status` | *job_id |
| `hydra` | `payloads.hydra.run_hydra` | *target, options |
| `extract_js_routes` | `payloads.js_recon.extract_js_routes` | *url, max_scripts, timeout, insecure |
| `msf_close` | `payloads.metasploiting.MetasploitClient.close_msf_session` | *handle |
| `msf_dispatch` | `payloads.metasploiting.MetasploitClient.dispatch_metasploit` | *module_path, *category, *options, start_handler |
| `msf_options` | `payloads.metasploiting.MetasploitClient.get_options` | *module_path |
| `msf_index` | `payloads.metasploiting.MetasploitClient.index_modules` | module_type, module_name, limit |
| `msf_interact` | `payloads.metasploiting.MetasploitClient.interact_session` | *handle, *command |
| `msf_set_payload` | `payloads.metasploiting.MetasploitClient.set_payload` | *payload_name, *options |
| `msfvenom` | `payloads.msfvenom_tools.generate_payload` | payload, lhost, lport, preset, format, out_name, encoder, iterations, badchars, platform, arch, extra_options, start_handler |
| `list_dropbox` | `payloads.msfvenom_tools.list_dropbox` |  |
| `msfvenom_menu` | `payloads.msfvenom_tools.msfvenom_menu` | kind, query |
| `searchsploit` | `payloads.searchsploiting.search_exploit` | *query |
| `sqlmap` | `payloads.sqlmap.run_sqlmap` | *target_url, options |
| `sqlmap_status` | `payloads.sqlmap.sqlmap_status` | *job_id |
| `list_wordlists` | `payloads.wordlists.list_wordlists` | query, category, source, limit |

### utils  (49 tools)

| alias | tool_id | params (* = required) |
|---|---|---|
| `jar_clear` | `utils.cookie_jar.jar_clear` | domain, clear_cookies, clear_tokens |
| `jar_cookie_header` | `utils.cookie_jar.jar_cookie_header` | *url |
| `jar_state` | `utils.cookie_jar.jar_state` | domain |
| `jar_store_cookie` | `utils.cookie_jar.jar_store_cookie` | *domain, *cookie, value, path, expires, secure, httponly, origin |
| `jar_store_token` | `utils.cookie_jar.jar_store_token` | *domain, *name, *value, token_type, origin |
| `hash_wordlist` | `utils.crypto_kit.check_hash_wordlist` | *hash_string, wordlist, max_lines |
| `decode_blob` | `utils.crypto_kit.decode_blob` | *blob, max_rounds |
| `identify_hash` | `utils.crypto_kit.identify_hash` | *hash_string |
| `jwt_decode` | `utils.crypto_kit.jwt_decode` | *token |
| `rot_brute` | `utils.crypto_kit.rot_brute` | *text |
| `rsa_decrypt` | `utils.crypto_kit.rsa_decrypt` | *p, *q, *e, *c |
| `xor_brute` | `utils.crypto_kit.xor_brute` | *data, top |
| `read_logs` | `utils.log_reader.read_logs` | *log_type, lines |
| `craft_arp_packet` | `utils.packetcraft.craft_arp_packet` | *src_mac, *dst_mac, *src_ip, *dst_ip, interface |
| `craft_arp_request` | `utils.packetcraft.craft_arp_request` | *src_mac, *src_ip, *target_ip, interface |
| `craft_dhcp_discover` | `utils.packetcraft.craft_dhcp_discover` | *src_mac, interface |
| `craft_dns_query` | `utils.packetcraft.craft_dns_query` | *src_ip, *dst_ip, *query_name, interface |
| `craft_dns_response` | `utils.packetcraft.craft_dns_response` | *src_ip, *dst_ip, *query_name, *answer_ip, interface |
| `craft_dns_response_multi` | `utils.packetcraft.craft_dns_response_multi` | *src_ip, *dst_ip, *query_name, *answer_ips, interface |
| `craft_http_request` | `utils.packetcraft.craft_http_request` | *src_ip, *dst_ip, method, path, host, user_agent, payload, interface |
| `craft_http_response` | `utils.packetcraft.craft_http_response` | *src_ip, *dst_ip, status_code, reason, content_type, payload, interface |
| `craft_icmp_echo` | `utils.packetcraft.craft_icmp_echo` | *src_ip, *dst_ip, payload, interface |
| `craft_icmp_packet` | `utils.packetcraft.craft_icmp_packet` | *src_ip, *dst_ip, payload, interface |
| `craft_mdns_query` | `utils.packetcraft.craft_mdns_query` | *src_ip, *dst_ip, *query_name, interface |
| `craft_tcp_packet` | `utils.packetcraft.craft_tcp_packet` | *src_ip, *dst_ip, *src_port, *dst_port, flags, payload, interface |
| `craft_udp_packet` | `utils.packetcraft.craft_udp_packet` | *src_ip, *dst_ip, *src_port, *dst_port, payload, interface |
| `craft_vlan_frame` | `utils.packetcraft.craft_vlan_frame` | *src_mac, *dst_mac, *vlan_id, payload, interface |
| `dissect_packet` | `utils.packetcraft.dissect_packet` | *hex |
| `export_packet_hex` | `utils.packetcraft.export_packet_hex` | *hex |
| `load_packet` | `utils.packetcraft.load_packet` | *filename |
| `modify_packet` | `utils.packetcraft.modify_packet` | *hex, *fields |
| `save_pcap` | `utils.packetcraft.save_pcap` | *hexes, filename |
| `sniff_to_pcap` | `utils.packetcraft.sniff_to_pcap` | filter, count, timeout, interface, filename |
| `load_pcap` | `utils.packetcraft.load_pcap` | *filename, offset, limit |
| `list_pcaps` | `utils.packetcraft.list_pcaps` |  |
| `save_packet` | `utils.packetcraft.save_packet` | *hex, *filename |
| `send_and_receive_packet` | `utils.packetcraft.send_and_receive_packet` | *hex, timeout, interface |
| `send_packet` | `utils.packetcraft.send_packet` | *hex, count, interval, interface |
| `sniff_packets` | `utils.packetcraft.sniff_packets` | filter, count, timeout, interface |
| `wait_for_packet` | `utils.packetcraft.wait_for_packet` | filter, timeout, interface |
| `list_sessions` | `utils.paramiko_client.list_sessions` |  |
| `paramiko_client` | `utils.paramiko_client.paramiko_client` | *hostname, *username, *password, *command |
| `ssh_close` | `utils.paramiko_client.ssh_close` | *handle |
| `ssh_connect` | `utils.paramiko_client.ssh_connect` | *hostname, *username, *password, port |
| `ssh_exec` | `utils.paramiko_client.ssh_exec` | *handle, *command |
| `ssh_shell` | `utils.paramiko_client.ssh_shell` | *handle, *command, timeout |
| `report_finding` | `utils.findings.report_finding` | *title, *severity, *asset, cwe, evidence_request, evidence_response, evidence_excerpt, repro, tool_chain |
| `render_findings` | `utils.findings.render_findings` | severity, asset, status, include_closed |
| `close_finding` | `utils.findings.close_finding` | *finding_id, *status, reason, closed_by, duplicate_of |
| `supersede_finding` | `utils.findings.supersede_finding` | *old_id, *new_id, reason, closed_by |
| `remember_text` | `utils.memory_tools.remember_text` | *text, namespace, memory_id, agent_id, important |
| `recall_text` | `utils.memory_tools.recall_text` | *query, namespace, limit, agent_id, target, since_hours |
| `list_text_namespaces` | `utils.memory_tools.list_text_namespaces` |  |


### listeners  (13 tools)

| alias | tool_id | params (* = required) |
|---|---|---|
| `send_to_brain` | `listeners.listening.TCPListener.send_to_brain` | *event_type, *session_id, *data |
| `open_listener` | `listeners.listening.TCPListener.open_listener` | *host, *port, auto_answer |
| `close_listener` | `listeners.listening.TCPListener.close_listener` | *handle |
| `read_listener` | `listeners.listening.TCPListener.read_listener` | handle, since, limit |
| `send_to_listener` | `listeners.listening.TCPListener.send_to_listener` | *handle, *data, peer |
| `clear_listener_data` | `listeners.listening.TCPListener.clear_listener_data` | handle |
| `collab_start` | `listeners.collaborator.collab_start` |  |
| `collab_generate` | `listeners.collaborator.collab_generate` |  |
| `collab_poll` | `listeners.collaborator.collab_poll` | since, id |
| `collab_stop` | `listeners.collaborator.collab_stop` | handle |
| `syn_scan` | `listeners.raw_scan.syn_scan` | *target_ip, *port, source_ip, timeout_ms |
| `list_tool_executions` | `listeners.brain_control.list_tool_executions` |  |
| `kill_tool_execution` | `listeners.brain_control.kill_tool_execution` | *exec_id, force, reason |


---

# Appendix B — IPython keyboard shortcuts

IPython (the `ipython` prompt inside `tool_repl.py`) uses GNU readline under the hood, plus its own layer of magic commands and keybinds. Below is the full reference — the ones you'll reach for daily are marked **★**.

## B.1 Navigation & editing (readline, works at the prompt)

| key | action |
|---|---|
| **★** `Ctrl-A` / `Home` | move to start of line |
| **★** `Ctrl-E` / `End` | move to end of line |
| `Ctrl-B` / `←` | move back one char |
| `Ctrl-F` / `→` | move forward one char |
| `Meta-B` / `Alt-←` | move back one word |
| `Meta-F` / `Alt-→` | move forward one word |
| `Ctrl-]` `<char>` | move forward to next occurrence of `<char>` |
| `Ctrl-Meta-]` `<char>` | move back to previous occurrence of `<char>` |
| **★** `Ctrl-W` | delete the word before cursor (to previous whitespace) |
| `Meta-D` | delete the word after cursor |
| `Meta-Backspace` | delete the word before cursor (to word boundary) |
| `Ctrl-U` | delete from cursor to start of line |
| `Ctrl-K` | delete from cursor to end of line |
| `Ctrl-Y` | yank (paste) the last killed text |
| `Meta-Y` | cycle through kill ring after `Ctrl-Y` |
| `Ctrl-_` | undo last edit (incremental) |
| `Ctrl-T` | transpose two chars before cursor |
| `Meta-T` | transpose two words before cursor |
| `Meta-U` | uppercase the word after cursor |
| `Meta-L` | lowercase the word after cursor |
| `Meta-C` | capitalize the word after cursor |
| **★** `Ctrl-L` | clear screen (does not clear history) |
| `Ctrl-D` | delete char under cursor; on empty line = EOF / exit |
| `Ctrl-H` / `Backspace` | delete char before cursor |
| **★** `F1` | dump all user variables (globals from above the current cell) above the prompt |

## B.2 History & recall

| key | action |
|---|---|
| **★** `↑` / `Ctrl-P` | previous history line |
| **★** `↓` / `Ctrl-N` | next history line |
| **★** `Ctrl-R` `<text>` | reverse incremental search through history (press repeatedly to cycle) |
| `Ctrl-S` `<text>` | forward incremental search (may be shadowed by terminal flow control — `stty -ixon` to free it) |
| `Meta-<` | first history line |
| `Meta->` | last history line (current) |
| **★** `Ctrl-O` | accept current line and fetch next history line (run-then-next) |
| `Alt-.` | insert last argument of previous command (press repeatedly to go back through history) |
| `Meta-_` | same as `Alt-.` (yank-last-arg) |
| `Ctrl-Alt-Y` | insert first arg of previous command (yank-nth-arg, then digit-arg to select) |

## B.3 Line execution & multi-line

| key | action |
|---|---|
| **★** `Enter` | execute the line |
| `Ctrl-C` | abort the current input, return to fresh `In [N]:` prompt |
| `Ctrl-D` | on empty line: exit IPython (back to `repl>`) |
| **★** `Ctrl-J` / `Alt-Enter` | insert a newline (for multi-line input blocks) |
| `Ctrl-M` | same as Enter (accept line) |

## B.4 IPython magic commands (prompt-level, not keybinds but essential)

These are the ones you'll use constantly while scripting the framework. All `%`-prefixed.

| command | action |
|---|---|
| **★** `%history` / `%hist` | show input history (use `-n` for line numbers, `-o` for output too) |
| **★** `%recall N` | put history line N into the edit buffer (no execution) |
| **★** `%rerun` / `%rerun N-M` | re-execute history lines N through M |
| **★** `%edit` / `%ed` | open `$EDITOR` to edit a temp file, then exec it on return |
| `%save <file> N-M` | save history lines N–M to a file |
| `%pastebin N-M` | upload lines to a pastebin (needs config) |
| **★** `!cmd` | run shell command; `x = !cmd` captures as `SList` (see §4.5) |
| `%cd <dir>` | change working directory (use `!cd` won't persist!) |
| `%pwd` / `%cwd` | print working directory |
| `%ls` | list directory (IPython-aware, supports python vars) |
| **★** `%who` / `%whos` | list variables (with details) — find your tool aliases |
| `%whols` | like `%whos` but short format |
| `%reset -f` | wipe the namespace (you'll lose your tool aliases — re-enter `ipython` from the REPL) |
| `%xdel <name>` | delete a variable and all its references |
| **★** `%time <stmt>` | time a single statement |
| `%timeit <stmt>` | time with repeated runs (best of N) |
| `%prun <stmt>` | profile with cProfile |
| `%memit <stmt>` | memory profile (needs `%load_ext memory_profiler`) |
| **★** `%load <file>` | load a file's contents into the next cell (edit then run) |
| `%run <file>` | run a .py file in the namespace |
| `%macro <name> N-M` | define a macro from history lines |
| `%store <var>` | persist a variable to disk (restored on next IPython start with `%store -r`) |
| `%store -r` | restore all stored variables |
| `%bookmark <name> <dir>` | set a directory bookmark; `cd -b <name>` jumps to it |
| `%pdef <obj>` | show the call signature of an object |
| **★** `%pdoc <obj>` / `obj?` | show the docstring (tool manifest) |
| `%pinfo <obj>` / `obj?` | same as above (detailed info) |
| **★** `obj??` | show the full source code of an object |
| `%psearch <pattern>` | search for objects by pattern |
| `%who_ls` | list variable names as a Python list (scriptable) |
| `%debug` / `%pdb` | drop into the interactive debugger on an exception |
| `%colors` | set color scheme (`Linux`, `LightBG`, `NoColor`) |
| `%autoindent` | toggle auto-indent for multi-line blocks |
| `%automagic` | toggle whether magic commands need the `%` prefix |

## B.5 Cell-level editing tricks (no Vi-mode — this is plain IPython prompt, not Jupyter)

| trick | action |
|---|---|
| **★** `Ctrl-R` then type part of a command | fuzzy-recall any past `await nmap(...)` etc. without scrolling |
| `Alt-.` repeatedly | cycle through the last args of previous commands — fast for re-entering a `handle` or `target` |
| `%recall 42` | pull the exact line 42 from history into the buffer; edit and Enter |
| `%rerun 38-45` | re-run a whole chain from history (e.g. re-fire a scan+probe sequence) |
| `Ctrl-C` mid-`await` | interrupts the running cell; the Brain-side tool may still be running — check with `list_tool_executions()` |
| `Ctrl-D` on empty line | exit IPython back to `repl>` (Brain-side sessions and listeners stay alive) |

## B.6 Readline configuration (`~/.inputrc`)

IPython respects GNU readline settings. Useful entries for this workflow:

```
# Free Ctrl-S for forward-search (terminal flow control is noise here)
set bind-tty-special-chars off
"\C-s": forward-search-history

# Tab indents 4 spaces inside multi-line blocks (IPython autoindent)
set editing-mode emacs

# Up-arrow does prefix-aware history search (type "await n" then ↑)
"\e[A": history-search-backward
"\e[B": history-search-forward

# Show all completions on first Tab (not ambiguous beep)
set show-all-if-ambiguous on
```

After editing `~/.inputrc`, restart IPython (or `Ctrl-X Ctrl-R` at the prompt to re-read it).

## B.7 Vi-mode (optional)

If you prefer modal editing at the prompt:

```python
%config TerminalInteractiveShell.editing_mode = 'vi'
```

| key | action (vi command mode) |
|---|---|
| `Esc` | enter command mode |
| `i` | insert mode (back to emacs-style editing) |
| `h` / `j` / `k` / `l` | left / down / up / right |
| `w` / `b` | next word / prev word |
| `0` / `$` | start / end of line |
| `dd` | delete line |
| `dw` | delete word |
| `cc` | change line (clear + insert) |
| `p` | paste deleted text after cursor |
| `k` / `j` | history prev / next |

Toggle back: `%config TerminalInteractiveShell.editing_mode = 'emacs'`.
