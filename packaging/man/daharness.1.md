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
  registry re-index: `python -m daharness.core`).

# CONFIGURATION

The systemd units load **/etc/daharness/daharness.env** via
*EnvironmentFile=* (system profile: WORKSPACE_ROOT, BRAIN_SOCKET,
GATEWAY_HOST, GATEWAY_PORT, GATEWAY_API_KEY); operator shells use the
tree's *.env* (*bootstrap.py*, *api_gateway.py* and *tool_repl.py* load
it with *override=True*). See **daharness.env(5)**.

Privileged lanes (raw-socket scanning, low-port OOB) are not part of this
baseline; they degrade honestly and are documented in **daharness-safety(7)**.

# FILES

*/run/daharness/brain.sock* — Brain UDS (system profile)
*/var/lib/daharness/* — engagement state root (system profile)
*/etc/daharness/daharness.env* — configuration

# SEE ALSO

**daharness-repl(1)**, **daharness-kernel(1)**, **daharness-pg(1)**,
**daharness.env(5)**, **daharness-tools(7)**, **daharness-safety(7)**