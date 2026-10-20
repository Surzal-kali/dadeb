---
title: daharness(1)
---

# NAME

daharness — daharness security framework services (Brain, ZAP, MSF MCP, API gateway)

# SYNOPSIS

**daharness** [*--daemon*]

# DESCRIPTION

Runs the daharness service stack for authorized security research:

- **Brain sidecar** — Unix-socket tool dispatch core; the socket lives at
  *$BRAIN_SOCKET* (system profile: **/run/daharness/brain.sock**).
- **OWASP ZAP daemon** — API access list kept to loopback; the browser proxy
  binds *$ZAP_PROXY_BIND* (default 0.0.0.0).
- **Metasploit RPC/MCP** — msfrpcd on *$MSF_RPC_PORT* (default 55553).
- **API gateway** — FastAPI on port 5000 (host lane), exposing
  */tools/execute*, */tools/search*, */memory/\**, */scratch/\** and the
  streamable-HTTP MCP endpoint */mcp*.
- **Wordlist preflight** — wordlist tree sanity-checked before serving.

# OPTIONS

**--daemon**
: Foregrounds the services stack. Passing it is optional — the interactive
  secretary chat loop was trimmed from the packaged build, so bare
  `daharness` behaves identically (interactive tool lane: *daharness-repl*(1);
registry re-index: **daharness-index**(1)).

# CONFIGURATION

The systemd units load **/etc/daharness/daharness.env** via
*EnvironmentFile=* (system profile: WORKSPACE_ROOT, BRAIN_SOCKET,
GATEWAY_HOST, GATEWAY_PORT, GATEWAY_API_KEY); operator shells use the
tree's *.env* (*bootstrap.py*, *api_gateway.py* and *tool_repl.py* load
it with *override=True*). See **daharness.env(5)**.

# OPERATOR ONBOARDING (system profile)

A fresh install provisions operator access instead of leaving it to code
archaeology: **/etc/profile.d/daharness.sh** exports the system-profile
WORKSPACE_ROOT and BRAIN_SOCKET into shells that lack them (wrappers
source it for non-login runs), and *postinst* grants the *daharness*
group to *sudo*-group members and shapes the state root to
*daharness:daharness, mode 2770* (group-write + setgid — the setgid bit
is what makes files created from either lane inherit the shared group;
member-only grants left operator writes as *kali:kali* strays the
service lanes could not see). The wrappers run `umask 0007`, so
operator-written files carry group-write through hardened umasks too.
A sudo operator's shell therefore shares cookie jar, scratch, findings,
and the socket with the service lane after re-login (or `newgrp
daharness`). Non-sudo operators: `sudo usermod -aG daharness <user>`.
An operator outside the group who probes the system-profile state sees
an honest `lane_blocked: true` permission report from
*framework_health* — with the shape check in its repair hint — never a
phantom "down".

Scope manifests get the same treatment: *postinst* seeds the editable
lab template into */var/lib/daharness/scope/lab_local-lab.json* (never
stomping an existing file) so a temp local-lab scope is authored-off-rip
— edit the subnet/ROE lines, then `python tool_repl.py scope on
local-lab --platform lab`. Custom manifests follow
*scope/&lt;platform&gt;_&lt;handle&gt;.json* in the state root and arm
with any `--platform` value. The pristine copy lives at
*/usr/share/daharness/examples/scope/lab_local-lab.json*.

Privileged lanes (raw-socket scanning, low-port OOB) are not part of this
baseline; they degrade honestly and are documented in **daharness-safety(7)**.

# FILES

*/run/daharness/brain.sock* — Brain UDS (system profile)
*/var/lib/daharness/* — engagement state root (system profile)
*/etc/daharness/daharness.env* — configuration
*/etc/profile.d/daharness.sh* — operator-shell plumbing (system-profile
WORKSPACE_ROOT + BRAIN_SOCKET for shells that lack them)
*/usr/share/daharness/examples/scope/lab_local-lab.json* — editable lab
scope-manifest template (postinst seeds it into the state root's *scope/*)

# SEE ALSO

**daharness-repl(1)**, **daharness-kernel(1)**, **daharness-pg(1)**,
**daharness-index(1)**, **daharness.env(5)**, **daharness-tools(7)**,
**daharness-safety(7)**