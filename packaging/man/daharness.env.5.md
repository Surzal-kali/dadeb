---
title: daharness.env(5)
---

# NAME

daharness.env — daharness framework configuration format

# SYNOPSIS

/etc/daharness/daharness.env

# DESCRIPTION

A dotenv file: *KEY=value* lines, `#` comments, values quoted. Every
runtime knob lives here — no baked-in defaults that cannot be overridden.

# LOADING

Each lane wires the file through the loader that owns it — nothing mints
a second loader:

1. *systemd system units* (*daharness*, *daharness-kernel*) —
   `EnvironmentFile=/etc/daharness/daharness.env`; the manager injects
   every key into the unit environment before `ExecStart`, so the daemon
   and kernel lanes all see it (the tool registry is a local
   daemon's own sidecar and reads the same unit environment).
2. *operator REPL / dev-tree lanes* — the *env* file next to the tree
   (*bootstrap.py*, *api_gateway.py*, *tool_repl.py* load it with
   `override=True` for their authoritative-config semantics).

Note the packaged tree carries no *env* file next to the tree — the units
read the conffile; operator shells get the system-profile WORKSPACE_ROOT
and BRAIN_SOCKET from **/etc/profile.d/daharness.sh**, which fills exactly
those two knobs when the shell does not already carry them (the wrapper
scripts source it for non-login invocations). A user-profile lane simply
exports its own values — they win. Seeing the service lane's state further
requires the *daharness* group: the deb does **not** auto-enroll
anyone (Docker pattern — the group is created but membership is the
operator's explicit decision). Add yourself with
`sudo usermod -aG daharness $USER`, then re-login or run `newgrp
daharness`.
Previously documented `$DAHARNESS_ENV` / *Python-level conffile loading*
was never implemented and is retired — the old unit line
`Environment=DAHARNESS_ENV=...` was inert.

# PROFILE KNOBS

System profile (package default; loaded in the systemd units via
`EnvironmentFile=`):

    WORKSPACE_ROOT=/var/lib/daharness
    BRAIN_SOCKET=/run/daharness/brain.sock

User profile (optional; see /usr/share/doc/daharness/systemd-user):

    WORKSPACE_ROOT=$HOME/.local/state/daharness
    BRAIN_SOCKET=$XDG_RUNTIME_DIR/daharness/brain.sock

The two profile knobs MUST match across all participants (Brain, gateway,
kernel, REPL) — choose at deployment, not per launch. Per-launch divergence
splits session state across processes.

WORKSPACE_ROOT is STATE only. Tool discovery follows the code checkout
(FRAMEWORK_ROOT — */usr/share/daharness* on the package), so
*daharness-index* mints the shipped tools no matter where state is pinned.

# KEY POLICY KNOBS

**EMBED_MODEL**
: Embedding model id sent to the embed endpoint, shared by the tool
  registry and memory lanes (default nomic-embed-text). Change it, then
  re-index: `python -m daharness.core`.

**EMBED_URL**
: Full POST target of the embeddings endpoint — provider-agnostic
  (default: `http://localhost:11434/api/embed`, the shipped Ollama-native
  lab stack). Anything that speaks the Ollama-native or OpenAI-compatible
  embeddings wire shape works; provider recipes live in `.env.example`.
  The endpoint receives everything you embed (memory text carries finding
  material) — loopback or LAN only for live engagements.

**EMBED_API_KEY**
: Optional. When set, every embeddings request carries an auth header
  with `EMBED_API_KEY` as the key — covers OpenAI/Together/Mistral/Voyage/
  Jina-style keyed providers. Shipped empty.

**OLLAMA_BASE_URL**
: Dev-checkout driving-LLM endpoint only (registry boot probe; the deb
  conffile deliberately does not carry it — the headless build reads no
  chat model, and embeddings resolve their own `EMBED_URL`). If your
  Ollama daemon runs off-host, this stays a checkout-`.env` knob —
  loopback or LAN only, never a cloud LLM API.

**GATEWAY_API_KEY**
: Arms X-API-Key/Bearer auth over the REST + /mcp surface. Shipped empty;
  *postinst* generates a random key into this file on install when the
  placeholder is still empty. Regenerate: clear the line, then
  `dpkg --configure daharness`. Client lanes (Open WebUI valves) must be
  re-pointed at the new value after a regen.

**GATEWAY_HOST / GATEWAY_PORT**
: Gateway bind, default 127.0.0.1:5000 (loopback — wider binds are a
  conscious operator decision; see daharness-safety(7)).

**COLLAB_HTTP_PORT / COLLAB_HTTPS_PORT / COLLAB_DNS_PORT**
: OOB collaborator bind ports (default 80/443/53, which requires root);
  the rootless profile retunes (e.g. 8080/4443/5353).

**Postgres lane (HARNESS_DB_HOST / HARNESS_DB_PORT / HARNESS_DB_NAME /
HARNESS_DB_PASSWORD_*)**
: Not entries of this file — not even as commented rows. A commented set
  here reads exactly like the live credential set, and on a pkg6 deb
  (2026‑10‑20) an operator copied it for an extension connect and
  authenticated against passwords that exist nowhere. The engagement
  lane stays on the SQLite stores until `daharness-pg init` provisions
  the dedicated `daharness` cluster (port 5433) and writes the resolved
  knobs — plus the four HARNESS_DB_PASSWORD_* lane values
  (operator/brain/gateway/repl roles) — to `/etc/daharness/pg.env`,
  which the systemd units source via a tolerant `EnvironmentFile=-`
  line and operator shells source for the REPL. Editing the lane onto a
  server daharness-pg did not provision belongs in pg.env (a
  HARNESS_DB_PORT other than the cluster's 5433 points the lane at a
  foreign server; a specific non-wildcard HARNESS_DB_HOST pins the
  client endpoint), or in the environment of the shell that runs the
  harness — never in *daharness.env*. Within pg.env HARNESS_DB_HOST
  also drives the dedicated cluster's own bind on the next
  `daharness-pg init`: 127.0.0.1 (the default) keeps the cluster on
  host loopback, while 0.0.0.0/`*` re-binds it to every interface
  (listen `*`) and manages an *pg_hba.conf* block — scram, RFC1918 —
  for the four lane roles, after which container-lane clients reach
  the host at the workbench-bridge gateway (172.28.0.1) through the
  built-in candidate list (loopback first, then the gateway) that the
  wildcard leaves intact.

# BOARD AUTH KNOBS

Credentials for the scope lane (`scope on <handle> --platform P`, the
Researcher* / program_scope tools). Shipped empty in both
*/etc/daharness/daharness.env* (commented rows) and the dev-tree
*.env.example*; fill where the lane runs and `chmod 0600` the file that
holds them.

**H1_API_USERNAME / H1_API_TOKEN**
: HackerOne API, Basic auth (hackerone.com → Settings → API Tokens).
  Without them the H1 tools return a clear `auth_required` error; the
  program hacktivity feed is public and works either way. Dev-tree loads
  come from `.env` (module-level tolerant load with `override=True`,
  deliberate — sudo/stripped-env launches are the normal case).

**INTIGRITI_USERNAME / INTIGRITI_API_TOKEN**
: Intigriti researcher handle + Personal Access Token (PAT). Required for
  authenticated Intigriti lookups.

**BUGCROWD_USERNAME**
: Bugcrowd researcher handle — that board's endpoints are public API, so
  no token knob. Falls back to **H1_API_USERNAME** when unset.

**RESEARCHER_USERNAME**
: Final fallback handle for any other platform's username lookup.

# FILES

*/etc/daharness/pg.env* — generated by **daharness-pg**(1); not a package
conffile (survives upgrades; `apt purge` collects it — **daharness-pg**(1)
`init` re-mints it losslessly).

*/usr/share/daharness/.env.example* — full knob inventory with defaults and
comments.

# SEE ALSO

**daharness(1)**, **daharness-safety(7)**