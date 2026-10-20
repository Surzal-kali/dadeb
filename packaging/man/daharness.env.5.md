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

# SEARCH ORDER

Loaded in precedence order, first existing wins:

1. *$DAHARNESS_ENV*
2. **/etc/daharness/daharness.env** (delivered by this package)
3. *.env* next to the tree.

Loading uses *override=True*: this file wins over shell exports.

# PROFILE KNOBS

System profile (package default; preset in the *daharness.service* units):

    WORKSPACE_ROOT=/var/lib/daharness
    BRAIN_SOCKET=/run/daharness/brain.sock

User profile (optional; see /usr/lib/systemd/user):

    WORKSPACE_ROOT=$HOME/.local/state/daharness
    BRAIN_SOCKET=$XDG_RUNTIME_DIR/daharness/brain.sock

The two profile knobs MUST match across all participants (Brain, gateway,
kernel, REPL) — choose at deployment, not per launch. Per-launch divergence
splits session state across processes.

# KEY POLICY KNOBS

**SECRETARY_MODEL**
: Chat model for the tool secretary (Ollama). Locally hosted only — never a
  cloud LLM API.

**EMBED_MODEL**
: Ollama embedding model shared by the tool registry and memory lanes
  (default nomic-embed-text). Change it, then re-index: `python -m
  daharness.core`.

**OLLAMA_BASE_URL**
: Ollama endpoint — loopback or LAN only, never a cloud LLM API.

**COLLAB_HTTP_PORT / COLLAB_HTTPS_PORT / COLLAB_DNS_PORT**
: OOB collaborator bind ports (default 80/443/53, which requires root);
  the rootless profile retunes (e.g. 8080/4443/5353).

# FILES

*/usr/share/daharness/.env.example* — full knob inventory with defaults and
comments.

# SEE ALSO

**daharness(1)**, **daharness-safety(7)**