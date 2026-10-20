# dockered/ — containerized workbench

A Docker Compose workbench with four services on a `172.28.0.0/24`
`workbench` bridge network: **ChromaDB** (vector registry), **Open WebUI**
(chat front end), **JupyterLab** (the tool nursery), and **code-server**
(browser editor with the framework runtime lane). Everything
bind-mounts the live framework tree — code edits on the host need no
rebuild.

> **History:** an `open-terminal` service (agent shell + file browser that
> hosted the framework gateway + Brain sidecar, port 8000) used to be the
> workbench's core. It was removed (its `open-terminal.Dockerfile` and
> `start_gateway.py` are gone); the gateway and Brain now run on the host
> lane via `python bootstrap.py` / `bootstrap.py --daemon`, and the
> notebook lane reaches the live Brain through the shared socket (see
> below). The stale `open-terminal` comments in `docker-compose.yaml` have
> been cleaned up; one pre-removal env value remains (`FRAMEWORK_GATEWAY_URL`,
> see the note below). The service definitions are the truth.

## Usage

```bash
cd dockered
docker rm -f chroma          # remove a legacy standalone chroma container if present
docker compose up -d --build
```

| Service | Host port | Notes |
| --- | --- | --- |
| ChromaDB | `9000` | mirrors the old standalone `chroma` container; reuses the existing `chroma-data/` volume |
| Open WebUI | `3000` | chat front end; calls the framework via the wrappers in [`../owui-tools/`](../owui-tools/) |
| JupyterLab | `8888` | tool nursery + engagement journals; publishes on all host interfaces (operator choice) |
| code-server | `8443` | browser editor (LAN-only, HTTPS via internal CA); baked framework runtime (python venv, stubs, `daharness` kernel); Microsoft-gallery extensions + Continue → host Ollama |

The framework gateway itself serves **5000 on the host lane** via the host's
`bootstrap.py --daemon` (the `6000` container-lane port predates the
open-terminal removal).

Keys/tokens come from `dockered/.env` (not tracked): `JUPYTER_TOKEN`,
`OPEN_TERMINAL_API_KEY` (now used by Open WebUI → Jupyter integration),
`WEBUI_URL_PREFIX`, `WEBUI_SECRET_KEY`, `CODE_SERVER_PASSWORD`
(code-server editor auth), and — if you expose the gateway to
the wider LAN — `GATEWAY_API_KEY` (host-side `.env`).

## ChromaDB

Mirrored into compose so the workbench is self-contained: same
`chromadb/chroma` image, `chroma-config.yaml` bind-mounted read-only, and
`../chroma-data` reused as the vector store (host port `9000` → container
`8000`). Other services reach it by the DNS name `chroma`
(`CHROMA_HOST=chroma`). Stop the legacy standalone container first —
otherwise you hit a host-port / container-name collision on `chroma`.

## Open WebUI

Chat front end. Notable pins and choices (all documented in the compose
file):

- **Pinned to `:dev`** because the stable `v0.11.3` release breaks the
  interactive terminal shell (the WebSocket proxy omits the
  `X-User-Id`/`X-Session-Id` headers, so PTY attach closes with 4004
  "Session not found"; fix tracked in open-webui/open-webui#29787). Switch
  back to `:main` once a stable release newer than v0.11.3 ships.
- **RAG embedding falls back to Ollama** (`RAG_EMBEDDING_ENGINE=ollama`) —
  the built-in sentence-transformers model loads ~500 MB into RAM on every
  boot. `RAG_EMBEDDING_BATCH_SIZE=50` caps batch spikes.
- **`mem_limit: 4g`** — the OOM kernel killer was shooting the container's
  Python process after ballooning to ~17 GB RSS; a Docker-level limit makes
  the restart deterministic (container restarts via `unless-stopped`)
  instead of the kernel killing a random victim on the host.
- Reaches the framework through the Open WebUI tool wrappers in
  [`../owui-tools/owui-wrapper.py`](../owui-tools/owui-wrapper.py): five
  tools — `framework_search_tools`, `framework_run_tool`,
  `framework_scratch_search`, `framework_memory_search`,
  `framework_health` — with per-chat session isolation. The wrapper's
  `gateway_url` valve **still defaults to `http://open-terminal:6000`**
  (pre-removal); point it at your host gateway (e.g.
  `http://<host>:5000`) for current deployments.

**Approval gate:** the secretary's human-in-the-loop gate is internal to
the harness secretary lane. Tool calls through Open WebUI / the gateway /
MCP execute directly — add your own approval layer in your integrating
harness if you need sign-off there. (The per-turn tool budget in
`utils/tool_budget.py` is the symmetric brake in these lanes.)

## JupyterLab — the tool nursery

Built from `jupyter.Dockerfile` (context is the repo root). Shares the live
framework tree and drives the identical tool lane as the Brain sidecar and
terminal REPL:

- **Bind mounts:** the framework tree → `/home/jovyan/framework` (kernel
  subprocesses run `tool_repl.py` from there), `../dabooks` →
  `/home/jovyan/work` (notebooks, version-controlled on the host — see
  [`../dabooks/README.md`](../dabooks/README.md)), `~/.ipython` persistence,
  and the gitignored `jupyter-nbi/` settings + credential bundle (rebuild-proof).
- **The `daharness` kernel** — installed via
  `python tool_repl.py --install-kernelspec`, preloaded with every
  framework tool as an async wrapper. Notebook cells resolve framework
  tools to bare names (`await session_post(...)`) and drive the same Brain
  session as the terminal REPL, because the kernel runs on the bind-mounted
  tree and the Brain socket (`run/brain.sock`) also lives inside the tree.
  Kernel conventions (always `await`, envelope helpers `keys`/`pluck`/
  `find`/`grep`) are in the Jupyter Kernel section of
  [`AGENTS.md`](../AGENTS.md#jupyter-kernel-dabooksipynb) — the deep dive on
  tool-side behavior lives in
  [`../README.md#tool-repl-tool_replpy`](../README.md#tool-repl-tool_replpy).
- **notebook-intelligence (NBI):** the image bakes `jupyter-nbi-config.json`
  (`/opt/conda/share/jupyter/nbi/config.json`, bind-mounted read-only).
  `jupyter-nbi/` holds the operator's stored settings + GitHub token
  (contains credentials — gitignored). Notably `chatbook_backend_kernel`
  must be pinned so Chatbook code runs on the `daharness` kernel, not
  `python3`.
- **Language-stub refresh:** `10-refresh-stubs.sh` runs at boot and copies
  the baked `dockered/jupyter-lsp-pyright.json` pyright config into the
  bind-mounted work dir (only if the operator hasn't pinned their own) —
  the jupyterlab-lsp pyright lane gets framework-tool completions.
  Keep `jupyter.Dockerfile`'s baked heredoc and this file in sync if
  editing by hand.
- **Two networks:** `workbench` (the framework lane; reaches `chroma` and
  the host lab lanes) plus an `egress` adapter attached after workbench, so
  it wins the default route and supplies normal NAT'd outbound access (pip
  installs, extension registry). `172.28.0.0/24` still routes framework
  traffic via the workbench interface.
- **Lab DNS:** a kali-side dnsmasq at the pinned bridge gateway
  (`172.28.0.1`) serves the host's `/etc/hosts` lab entries so notebook
  resolution matches the host; Docker's embedded resolver keeps container
  names. Reprovisioned idempotently by `lab-dns-setup.sh` (which also
  writes an `After=docker.service` systemd drop-in); design notes in
  [`../knowledge/lab-dns.md`](../knowledge/lab-dns.md).
- **Healthcheck:** the base image's stock health check always flamped
  "unhealthy" (1s timeout vs ~6s boot — NBI + MCP server + 17 tool
  registrations boot before the API answers), so compose overrides it with
  `/etc/jupyter/docker_healthcheck.py` baked by the Dockerfile.

> **Leftover config note:** the compose service still sets
> `FRAMEWORK_GATEWAY_URL=http://open-terminal:6000` — a pre-removal value
> whose DNS name no longer resolves. The kernel lane dispatches through the
> shared Brain socket rather than the gateway, so notebooks work; update
> this env (or drop it) if you wire notebook-side REST calls to the gateway.

## code-server — browser editor (LAN-only, pure-local assistant)

Self-hosted browser VS Code (`lscr.io/linuxserver/code-server`) for the
notebook/RE lane — the tunnel-free alternative: **no Microsoft dev-tunnel
relay in the trust path** and **no marketplace-ToU gray zone** (no
Copilot VSIX side-loading). The framework's own Safety rule ("tool
outputs from live targets must not egress to third parties") stays as
intact in the editor lane as it is in the tool lanes.

- **Extensions via the Microsoft gallery** (revised 2026-10-18; was
  OpenVSX-only), installed idempotently at boot by
  [`code-server-init/00-extensions-and-continue.sh`](code-server-init/00-extensions-and-continue.sh)
  (mounted into the image's `custom-cont-init.d` hook, non-fatal on
  failure, retries next boot): `ms-python.python` + its
  `ms-python.vscode-python-envs` backend, `ms-toolsai.jupyter` (notebook
  UI — its kernel picker finds the baked `daharness` kernelspec),
  `detachhead.basedpyright`,
  `llvm-vs-code-extensions.vscode-clangd`, `continue.continue`. Extension
  state lives in the `code-server-config` volume.
  **Why the gallery swap:** OpenVSX builds of ms-python are *stripped* of
  the bundled native `python-env-tools` binary (`pet` — the interpreter
  discovery engine); every ms-python vsix on OpenVSX lacks it, so
  Select Python Interpreter died with `spawn .../python-env-tools/bin/pet
  ENOENT` and could never see `/opt/framework-venv`. The Microsoft
  marketplace vsix bundles pet — this is the standard code-server
  practice. The old OpenVSX-only stance existed to keep the
  marketplace-ToU gray zone (the Copilot VSIX footwork) out of the lane;
  that rationale lapsed with Copilot resolving at init. **Still no
  Copilot VSIX:** the assistant stays Continue → host-lane Ollama, so
  completions/chat remain local-network only.
- **Docker lane: host-daemon control from the editor** (added
  2026-10-18). The container shares `/var/run/docker.sock` (mount with
  `group_add` set to the HOST socket GID from
  `stat -c %g /var/run/docker.sock`) and bakes `docker.io` +
  `docker-compose-v2`, so the editor's terminal manages the real host
  stack — `docker ps`, build, `docker compose up -d ...`. This is
  root-equivalent by explicit decision: treat untrusted content in this
  container (e.g. a malicious marketplace extension) as holding the
  daemon. Do NOT `chmod 666` the socket — the chmod lands on the HOST.
  Compose from the editor must use the host-identical second mount of
  the tree: `-f /home/kali/github/daharness/dockered/docker-compose.yaml`.
  The `/config/workspace` alias exists only in-container; the host daemon
  resolves `./` bind sources on HOST paths, so alias paths would create
  stray dirs and bind the wrong files.
- **Starship prompt**, installed into `/config/.local/bin` and initialized from
  the persistent `/config/.bashrc` by the same boot hook. A failed download is
  non-fatal and retries on the next boot.
- **Assistant = Continue → host-lane Ollama** (`OLLAMA_BASE_URL`,
  `192.168.56.1:11434` — same host jupyter/open-webui use; both lane
  models are already pulled there). The init script provisions
  `/config/.continue/config.yaml` only when absent — autocomplete
  `qwen2.5-coder:7b`, chat/edit `qwen2.5-coder:14b`; edit the file (or
  use the Continue UI) and your changes survive every reboot.
  Older served builds (e.g. `continue.continue` 2.0.0 for engine
  compat) read the legacy `config.json`, newer read `config.yaml` —
  so BOTH files are provisioned and any Continue version finds the
  Ollama lane.
- **Marketplace wiring:** the Extensions *view* is dead out of the box —
  coder ships this build's `product.json` WITHOUT an `extensionsGallery`
  block   (the CLI install path honors the injected `product.json` gallery).
  The init script injects the **Microsoft gallery**
  (`serviceUrl`/`itemUrl`) into `product.json` at boot, before the
  server starts; idempotent, non-fatal, and re-applied automatically if
  an image upgrade reintroduces the gap. A follow-up check in the same
  hook detects a pet-less (OpenVSX-era) ms-python install and `--force`
  reinstalls from the gallery without uninstalling first (a failed
  fetch leaves the working-but-stripped extension until a later boot).
- **Bind mounts:** the live framework tree → `/config/workspace`
  (same-uid `PUID=1000`), so `run/brain.sock` is reachable from the
  editor terminal — the same Brain lane as jupyter and `tool_repl` — and
  code edits on the host need no rebuild. `/config/workspace` is the
  lsio image's default workspace path AND its `DEFAULT_WORKSPACE`, so the
  editor boots opened on the tree; lsio's first-boot ownership pass
  deliberately prunes that path.
- **Runtime lane (why the service is built, not stock):** the stock lsio
  image only bind-mounts the tree — no python, no stubs, no kernel. A
  compose `build` on
  [`dockered/code-server.Dockerfile`](code-server.Dockerfile) bakes the
  same runtime lane the jupyter image carries: the pinned framework
  venv (`/opt/framework-venv`), build-time stubs
  (`/opt/framework-stubs`), and the `daharness` kernelspec.
  `python`/`python3`/`pip`/`jupyter` resolve from `/usr/local/bin` (sh
  wrappers for the interpreters, console-script symlinks for the tools —
  a bare python symlink cannot work: CPython locates `pyvenv.cfg`
  relative to the *real* executable, so a symlinked python comes up as
  system python with no venv site-packages).
- **Two-layer stubs** (same discipline as the jupyter lane): stubs are
  generated at build from a COPY'd pruned tree (bind mounts don't exist
  during `docker build`), then
  [`code-server-init/10-framework-runtime.sh`](code-server-init/10-framework-runtime.sh)
  refreshes them from the **live** mount at every boot — new tools need
  no rebuild — and hands the venv + stubs to `PUID:PGID`
  (sentinel-guarded, once) so operator pip-installs from the editor
  terminal work. Regen is non-fatal (baked stubs keep the editor lane
  working, just potentially stale) and is skipped with a WARN if the
  mount is incomplete or no user owns `PUID` — the generator's one
  write into the shared tree (`dabooks/ruff.toml` builtins block) must
  land with the host's uid, never root's.
- **Notebook kernel:** the baked `daharness` kernelspec pins
  `/config/workspace/tool_repl.py --kernel` — `.ipynb` cells pick it in
  the `ms-toolsai.jupyter` kernel picker and get the `await`-wrapper
  framework namespace (see the root `AGENTS.md` kernel notes), dispatching
  through the same `run/brain.sock` lane as jupyter and `tool_repl`.
- **Editor settings live in the container, not the workspace:** the boot
  hook provisions the interpreter
  (`/opt/framework-venv/bin/python`) and the
  `python.analysis.stubPath` / `basedpyright.analysis.stubPath` values
  into the persistent `/config/data/User/settings.json` — key-wise
  only-if-absent, operator edits win and a JSONC (commented) file is
  left untouched. Deliberately **not** a `pyrightconfig.json` inside the
  workspace: `/config/workspace` *is* the host tree, and a config file
  there would leak onto the host's own nvim / host-VS Code pyright
  lanes. The tracked `.vscode/settings.json` points
  `python.defaultInterpreterPath` at the host's Python 3.14 venv — dead
  inside this container (Ubuntu 3.12) — so pick `/opt/framework-venv`
  once in the interpreter picker; workspaceStorage (the `config` volume)
  remembers it across reboots.
- **Boot cost:** the stub refresh runs the full discovery import scan on
  every start (a couple of minutes before the server answers) — the same
  accepted latency as the jupyter lane's `10-refresh-stubs.sh`.
- **Networks:** `workbench` (framework lane, static `.50`) +
  `devnet` — a dedicated plain-NAT bridge attached to nothing else,
  separate from the shared `egress` lane. The editor is a full dev
  workbench (marketplace, git, language servers) and gets its own
  outbound lane; it wins the default route, lab DNS stays at `172.28.0.1`.
- **Auth:** `PASSWORD` from `CODE_SERVER_PASSWORD` in `dockered/.env`;
  compose refuses to bring the service up unset, because the editor
  shell has full repo (and bind-mounted framework) access. Serves HTTPS
  on `8443`.
- **TLS:** the init script mints a 10-year internal CA (`ca/ca.crt` in
  the config volume) and serves an 825-day leaf with the host's real
  SANs (`CODE_SERVER_CERT_SANS` in compose; defaults include
  `localhost`, shortname, and the LAN IPs). **Why a CA:** browsers can
  click through TLS warnings, but webview service workers refuse any
  cert error — notebook webviews render dead over LAN IPs unless the
  cert genuinely validates. Install the CA on each device ONCE
  (`docker cp dockered-code-server-1:/config/.local/share/code-server/ca/ca.crt .`
  → system/browser trust store); the leaf can then rotate or the volume
  be wiped without re-trusting anything. **Gotcha:** browsers re-read
  trust stores only after a full restart, and when the "Not secure"
  pill stays red the installed CA copy doesn't match the served one —
  compare `sha256` fingerprints, re-install, then clear the site's
  stored data for the address so the failed webview service worker is
  dropped (its SecurityError kills notebook rendering until then).
  Only-if-absent: leaf is
  reissued automatically if it's absent or not signed by the current CA.

## Network posture

No iptables lockdown / NET_ADMIN cage on any service. Earlier
experiments caged the workbench, but the framework itself is the
scope-lined gateway to the outside world (`check_scope` + the operator-armed
scope gate enforce program scope in-process), and the only thing the cage
actually constrained was the secretary chat loop. Scope discipline is the
in-process layer + operator ROE; the compose file header carries the
full decision record.

## The framework inside these containers

Nothing in this directory runs the framework's gateway or Brain anymore —
the containers consume them:

- the **jupyter kernel** reaches the host Brain via the shared
  `run/brain.sock` (bind-mounted tree);
- **Open WebUI** reaches the gateway over HTTP via `owui-tools/`.

Run the gateway itself on the host (`python bootstrap.py --daemon`) — or,
for a hosted deployment, point the wrappers/valves wherever the gateway
actually serves.