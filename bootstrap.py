import logging
import os
import sys
import asyncio
import threading
import importlib
import signal
from pathlib import Path
from typing import Dict, Optional, List, Any
import socket
import time

# --- Python version guard ----------------------------------------------------
# Refuse to boot on unsupported interpreters with a clear message instead of a
# mid-import syntax/dependency error.
MIN_PYTHON = (3, 12)
if sys.version_info < MIN_PYTHON:
    sys.stderr.write(
        f"[bootstrap] Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ required "
        f"(found {sys.version.split()[0]}). Exiting.\n"
    )
    sys.exit(1)

from daharness import _chat, ToolRegistry, OllamaEmbeddingFunction  # noqa: E402
from daharness.findings import ensure_ids_db  # noqa: E402  -- after .env load
from constants import brain_socket_path  # noqa: E402  -- after .env load

# --- .env loading (sudo-safe) ------------------------------------------------
# When the framework is launched under sudo, the shell environment is stripped
# and .env is never sourced.  Load it here so all env vars (H1 creds, ZAP,
# gateway key, etc.) are available regardless of how the process is started.
# override=True is deliberate (operator decision 2026-09-25): .env is the
# AUTHORITATIVE config channel — the stack boots under root where shell
# exports don't survive env_reset.  Do NOT "fix" this to override=False.
#
# NOTE: this load deliberately sits AFTER the daharness import. The package
# __init__ now loads .env itself (without override) before registry.py bakes
# OLLAMA_BASE_URL into a module constant; this block then re-applies with
# override=True for the rest of the stack's authoritative-.env semantics.
# Keeping both gives: registry constants see .env, and shell exports are still
# overridden by .env for the operator's decision above. Do not move the
# daharness import below this block as a "fix" — that resurrects the bug
# where os.environ at registry-import time is whatever the launcher had.
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent / ".env", override=True)
except Exception:
    pass
# --- Setup Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# --- Configuration ---
FRAMEWORK_ROOT = Path(__file__).parent
MCP_ENDPOINT = os.getenv("MCP_ENDPOINT", "http://127.0.0.1:55553").rstrip("/")
MCP_STARTUP_DELAY = float(os.getenv("MCP_STARTUP_DELAY", "5"))
MCP_STARTUP_TIMEOUT = float(os.getenv("MCP_STARTUP_TIMEOUT", "60"))
MSGRPC_PASSWORD = os.getenv("MSGRPC_PASSWORD", "msfadmin4824")
MSF_RPC_PORT = int(os.getenv("MSF_RPC_PORT", "55553"))

# OWASP ZAP daemon (auxiliaries/zap.py uses these). The daemon is launched
# loopback-only -- api.addrs.addr.name=127.0.0.1 below -- so even if
# api.disablekey is set the API is unreachable off-host. ZAP_API_KEY is sent
# on every call from auxiliaries/zap.py as the ``apikey`` query param.
ZAP_HOST = os.getenv("ZAP_HOST", "127.0.0.1")
ZAP_PORT = int(os.getenv("ZAP_PORT", "8090"))
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")
# Browser-proxy lane: when set (e.g. "0.0.0.0" or a LAN IP), the ZAP
# *listener* binds this address so off-box browsers can proxy through it.
# The API ACL (api.addrs.addr.name) stays pinned to ZAP_HOST regardless,
# so the JSON API keeps its loopback-only defence-in-depth.
ZAP_PROXY_BIND = os.getenv("ZAP_PROXY_BIND", "0.0.0.0")
# Daemon JVM max heap. 512m is the historical default but OOM-kills on
# oversized history entries (single 1.37MB response + regex scan). Raise
# via shell export before restart, e.g.  export ZAP_XMX=2g
ZAP_XMX = os.getenv("ZAP_XMX", "512m")

# Burp Suite MCP Server BApp (auxiliaries/burp_mcp.py uses these).  Unlike
# ZAP/MSF, Burp is NOT launched by this bootstrap — the operator runs the
# Burp GUI with the MCP Server BApp loaded.  These vars configure where the
# BApp's SSE endpoint is (default 127.0.0.1:9876, set in the BApp's MCP tab
# advanced options).  BURP_MCP=1 gates the launch-time healthcheck so the
# framework boots cleanly when Burp isn't running (the common lab case).
BURP_MCP_ENABLED = os.getenv("BURP_MCP", "").lower() in ("1", "true", "yes")
BURP_MCP_HOST = os.getenv("BURP_MCP_HOST", "127.0.0.1")
BURP_MCP_PORT = int(os.getenv("BURP_MCP_PORT", "9876"))

# --- Async Background Runner ---
class AsyncBackgroundRunner:
    """Runs an asyncio event loop in a separate background thread."""
    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()

    def _run_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def run_task(self, coro):
        """Schedules a coroutine to run in the background loop."""
        return asyncio.run_coroutine_threadsafe(coro, self.loop)

    def stop(self):
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join()

def _open_child_log(name: str):
    """Open an append-mode log for a child process, **never raising**.

    A child-process log exists only to capture diagnostics. Letting its
    ``open()`` kill the launch is strictly worse than losing the trace:
    the ZAP/Brain daemon never starts AND there's no log to say why -- the
    exact "permission denied touching zap.log, no trace" failure. So we
    fail *open*: try the classic shared path, then a uid-scoped path (so
    root and non-root runs never collide on ownership / an immutable bit
    left on the shared file by a prior run), then give up to DEVNULL.

    Returns ``(file_or_devnull, path_or_None)``.
    """
    candidates = [f"/tmp/{name}.log", f"/tmp/{name}-{os.geteuid()}.log"]
    for path in candidates:
        try:
            return open(path, "ab"), path
        except OSError as exc:
            logger.warning("[!] Can't open child log %s (%s); trying next", path, exc)
            continue
    logger.warning(
        "[!] All /tmp/%s*.log candidates unwritable; child stdout -> DEVNULL "
        "(check /tmp perms / immutable bits / MAC).", name,
    )
    return asyncio.subprocess.DEVNULL, None


# --- FrameworkLoader ---
class FrameworkLoader:
    def __init__(self, framework_root: Path):
        self.framework_root = framework_root
        self.runner = AsyncBackgroundRunner()
        self.active_tasks: List[Any] = []
        self.api_server = None   # uvicorn.Server, set by api_gateway.run()
        self.api_task = None     # the asyncio task wrapping start_api_server
        self.tool_registry: Dict[str, tuple] = {}
        self.packet_tool = None
        self.vector_registry = None

        # Initialize ToolRegistry
        try:
            from daharness import ToolRegistry, OllamaEmbeddingFunction
            self.vector_registry = ToolRegistry(
                embedding_model=OllamaEmbeddingFunction(),
                rpc_servers={"metasploit": MCP_ENDPOINT}
            )
            logger.info("[+] Tool vector registry initialized.")
        except Exception as exc:
            logger.error("[!] Tool vector registry failed: %s", exc, exc_info=True)

        # Initialize PacketCraft
        try:
            from utils.packetcraft import PacketCraft
            self.packet_tool = PacketCraft()
        except Exception as exc:
            logger.warning("[!] PacketCraft unavailable: %s", exc)

    async def _wait_for_rpc_port(self, host: str = "127.0.0.1", port: int = 55553, timeout: float = 30.0) -> bool:
        """Wait for the RPC port to become available."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                with socket.create_connection((host, port), timeout=1):
                    logger.info("[+] RPC port %s:%s is now open.", host, port)
                    return True
            except (ConnectionRefusedError, socket.timeout):
                await asyncio.sleep(1)
                continue
        logger.warning("[!] RPC port %s:%s did not become available within %s seconds.", host, port, timeout)
        return False


    async def start_metasploit_mcp(self):
        """Starts Metasploit console and handles RPC discovery with retries."""
        try:
            logger.info("[+] Starting Metasploit console for RPC discovery...")
            from payloads.metasploiting import MetasploitClient
            # Shared instance: tool launches resolve to the same client, so
            # they see the live msfconsole handle started here.
            metasploit_client = MetasploitClient.get_instance()
            process = await metasploit_client.start_mcp()
            # start_mcp returns the Process it launched, or None when it reused
            # an already-running msfconsole (nothing to reap) OR on failure.
            # Distinguish the two by whether the RPC client actually connected.
            if process is not None:
                self.active_tasks.append(process)
                # start_mcp redirects msfrpcd stdout/stderr to
                # /tmp/msfconsole_mcp.log and stashes the writer fd on the
                # client instance. Register it under the process id so stop()
                # closes it once the process is reaped (same pattern as the
                # ZAP daemon's /tmp/zap.log writer).
                msf_log_fd = getattr(metasploit_client, "_msf_log_fd", None)
                if msf_log_fd is not None:
                    self._child_log_fds = getattr(self, "_child_log_fds", {})
                    self._child_log_fds[id(process)] = msf_log_fd
            if not getattr(metasploit_client, 'client', None):
                logger.warning("[!] MSF RPC client not connected; skipping tool discovery.")
                return process

            logger.info("[+] MSF RPC client connected; starting tool discovery.")

            async def _vectorize_tools():
                try:
                    if not self.vector_registry:
                        return
                    logger.info("[+] Connecting to MSF RPC for tool discovery...")
                    await asyncio.sleep(MCP_STARTUP_DELAY)

                    # Instead of indexing all MSF modules, we rely on the dynamic 
                    # discovery of @framework_tool functions in metasploiting.py
                    # performed by discover_local_tools().
                    logger.info("[+] Skipping full MSF RPC module indexing to reduce noise.")
                    logger.info("[+] Indexing only high-level framework tools.")
                except Exception as rpc_exc:
                    logger.error("[!] MSF RPC connection failed: %s", rpc_exc, exc_info=True)

            self.active_tasks.append(asyncio.create_task(_vectorize_tools()))
            return process
        except Exception as e:
            logger.error("[!] Metasploit launch failed: %s", e, exc_info=True)
            return None
    
    async def start_brain_server(self):
        """Starts the Brain listener as a sidecar process."""
        try:
            brain_script = self.framework_root / "listeners" / "thebrain.py"
            if not brain_script.exists():
                logger.error("[!] Brain script not found at %s", brain_script)
                return

            # Wait for the socket so dispatchers don't race the sidecar
            socket_path = str(brain_socket_path())

            async def _brain_ready() -> bool:
                """True only when something is actually LISTENING on the socket.

                Path.exists() is a lie for stale sockets: the kernel does not
                unlink a socket when its owner dies, so a killed sidecar leaves
                a file that passes every existence check while connect() bounces
                off it. Probe with a real connection instead.
                """
                try:
                    _, writer = await asyncio.open_unix_connection(socket_path)
                    writer.close()
                    await writer.wait_closed()
                    return True
                except (FileNotFoundError, ConnectionError, OSError):
                    return False

            # Reuse a live Brain if one is already listening. This is the
            # common case after a bootstrap restart whose previous brain
            # survived (start_new_session=True) and is still serving: spawning a
            # second would either bounce off the brain's flock/socket guard and
            # log "exited early", or -- if the socket file was swept while the
            # orphan listens on an unlinked inode -- slip past that guard and
            # produce TWO listeners on one path (the duplicate-brain bug).
            # Returning without appending a process to active_tasks is fine:
            # stop() only terminates tasks we own, and a reused/orphaned brain
            # is intentionally left for its own (or another) bootstrap to reap.
            if await _brain_ready():
                logger.info("[+] Brain already listening at %s; reusing it", socket_path)
                return None

            logger.info("[+] Starting Brain sidecar...")
            # Stream the Brain's output to a log file instead of PIPEs: nothing
            # ever drains PIPEs here, so once the Brain prints enough output the
            # pipe buffer fills, the sidecar blocks on write and effectively
            # dies -- taking the Brain socket down with it (it unlinks the socket
            # on startup, so a crashed sidecar leaves NO socket behind).
            # Opened via _open_child_log so a poisoned/immutable /tmp/brain.log
            # can never kill the sidecar launch the way it killed ZAP.
            brain_log, brain_log_path = _open_child_log("brain")
            process = await asyncio.create_subprocess_exec(
                sys.executable, str(brain_script),
                stdout=brain_log,
                stderr=asyncio.subprocess.STDOUT,
                # Own session: a Ctrl+C on the parent terminal SIGINTs the whole
                # foreground process group, which killed the sidecar and left a
                # stale socket behind. bootstrap.stop() still terminates it.
                start_new_session=True,
            )
            self.active_tasks.append(process)

            # The sidecar runs its startup tool scan (BRAIN_SCAN_DIRS) BEFORE
            # binding the socket, so cold imports (impacket, scapy/packetcraft,
            # dotenv) can take several seconds past process launch — measured
            # ~6-8s with utils/ in the scan set on a cold cache, worse when the
            # systemd kernel is concurrently importing the same modules. The
            # budget is env-tunable so operators with heavy scan dirs can widen
            # it without a code edit.
            ready_timeout = float(os.getenv("BRAIN_READY_TIMEOUT", "30"))
            poll_interval = 0.1
            deadline = time.monotonic() + ready_timeout
            while time.monotonic() < deadline:
                if await _brain_ready():
                    logger.info("[+] Brain socket ready at %s", socket_path)
                    return process
                if process.returncode is not None:
                    logger.error(
                        "[!] Brain sidecar exited early (code %s); see %s",
                        process.returncode, brain_log_path or "<devnull>",
                    )
                    return process
                await asyncio.sleep(poll_interval)
            logger.warning(
                "[!] Nothing listening on %s within %.0fs (BRAIN_READY_TIMEOUT); "
                "dispatch will fall back to in-process launches. "
                "If the startup scan is slow (utils/scapy, cold cache), raise "
                "BRAIN_READY_TIMEOUT or trim BRAIN_SCAN_DIRS.",
                socket_path, ready_timeout,
            )
            return process
        except Exception as e:
            logger.error("[!] Brain sidecar failed to launch: %s", e, exc_info=True)

    
    async def start_zap_daemon(self, host=None, port=None):
        """Start the OWASP ZAP daemon as a subprocess.

        Same lifecycle shape as ``start_brain_server``: asyncio subprocess,
        appended to ``active_tasks`` so ``stop()`` reaps it via the
        SIGTERM-then-SIGKILL filter on ``asyncio.subprocess.Process``.

        The daemon is bound loopback-only (``api.addrs.addr.name=127.0.0.1``
        + ``api.disablekey`` left at its default -- keys are still sent on
        every API call from ``auxiliaries/zap.py`` so a defence-in-depth
        posture holds if a future config flip exposes it).
        """
        import pwd
        import shutil
        import subprocess
        host = host or ZAP_HOST
        port = port or ZAP_PORT

        # ZAP launcher resolution across distro layouts. Official tarball /
        # older Debian: `zap` on PATH or /usr/share/zap/zap.sh. Kali (and
        # modern Debian/Ubuntu zaproxy packages): /usr/bin/zaproxy and
        # /usr/bin/owasp-zap -- both sh wrappers that `cd /usr/share/zaproxy`
        # and `exec ./zap.sh "$@"`, so -daemon/-config args pass through
        # unchanged. ZAP_BIN (env) wins over everything for non-standard
        # installs. First existing candidate is used.
        zap_candidates = [
            os.getenv("ZAP_BIN", ""),
            shutil.which("zap") or "",
            shutil.which("zaproxy") or "",
            shutil.which("owasp-zap") or "",
            "/usr/share/zaproxy/zap.sh",
            "/usr/share/zap/zap.sh",
        ]
        zap_bin = next(
            (c for c in zap_candidates if c and Path(c).exists()), None
        )
        if not zap_bin:
            logger.error(
                "[!] ZAP launcher not found (tried: %s). Install zaproxy "
                "(apt install zaproxy) or set ZAP_BIN to the zap.sh path.",
                ", ".join(c or "<unset>" for c in zap_candidates),
            )
            return

        # Daemon JVM heap — sized by $ZAP_XMX (default 512m, bump for large
        # history windows). -daemon forks the JVM (no GUI). Logs go to a
        # /tmp log so failures are inspectable after a crash. Opened via
        # _open_child_log so a poisoned/immutable /tmp/zap.log can never
        # kill the launch.
        log_fd, log_path = _open_child_log("zap")
        
        # Force 127.0.0.1 to avoid UnresolvedAddressException (IPv6/localhost issues)
        host = host or "127.0.0.1"
        # Listener bind may be widened for the browser-proxy lane, but the
        # API ACL below ALWAYS stays on ZAP_HOST (loopback default).
        bind_addr = ZAP_PROXY_BIND or host
        
        cmd = [
            zap_bin, "-daemon",
            "-port", str(port),
            "-host", bind_addr,
            "-config", f"api.addrs.addr.name={host}",
            "-config", "api.addrs.addr.regex=true",
            "-config", "api.disablekey=true",
            "-config", f"network.localServers.mainProxy.address={host}",
            f"-Xmx{ZAP_XMX}",
        ]
        # Pin the home dir using -dir argument; ZAP often ignores ZAP_HOME env var.
        zap_home = self.framework_root / ".zap_home"
        zap_home.mkdir(exist_ok=True)
        cmd.extend(["-dir", str(zap_home)])

        # --- Root guard: never run the ZAP daemon as root. -----------------
        # ZAP checks write access to its home at startup
        # (OptionsParamCheckForUpdates -> "No write access to directory
        # .../plugin") and aborts the daemon if it can't write. When the
        # framework is launched as root but ``.zap_home`` is owned by a
        # normal user (the common case -- the project lives under the
        # operator's $HOME), a root ZAP run *can* write (root bypasses DAC)
        # so the root launch itself starts, but it silently chowns the home
        # tree (config.xml, db/permanent.*, plugin/, ...) to root:root.
        # Every subsequent *non-root* launch then fails ZAP's write-access
        # check and the daemon refuses to come up -- i.e. "starting as root"
        # is what poisons later runs.
        #
        # Fix: when we're root, drop the ZAP subprocess to the user who owns
        # ``.zap_home`` (ZAP needs no root) and chown the home tree + log
        # file back to them so any corruption from a prior root run is
        # repaired in the same launch. Ownership then stays consistent across
        # root / non-root framework launches.
        launch_user = None  # pwent of the user to run ZAP as, or None
        if os.geteuid() == 0:
            home_st = zap_home.stat()
            if home_st.st_uid != 0:
                launch_user = pwd.getpwuid(home_st.st_uid)
                # Repair ownership corrupted by an earlier root run (no-op if
                # already correct). Scoped to .zap_home only -- the ZAP log is
                # opened uid-safely by _open_child_log, so it needs no chown.
                chown_spec = f"{launch_user.pw_uid}:{home_st.st_gid}"
                subprocess.run(
                    ["chown", "-R", chown_spec, str(zap_home)],
                    check=False, capture_output=True,
                )
                logger.info(
                    "[+] Framework started as root; dropping ZAP daemon "
                    "privileges to '%s' and (re)chowning %s to match.",
                    launch_user.pw_name, zap_home,
                )
            # If .zap_home is already root-owned there's no mismatch to fix;
            # leave ZAP running as root.

        if launch_user is not None:
            # runuser(1) (util-linux) execs the command as the target user
            # without a login shell, so our env + -dir arg pass straight
            # through. No --login: that would scrub ZAP_HOME/HOME. It lives
            # in /usr/sbin (not always on a non-root PATH), so check the
            # canonical locations too. su(1) is the universal fallback when
            # invoked by root (passwordless); we feed it a shlex-quoted -c
            # string so the arg array survives the shell round-trip intact.
            import shlex
            runuser = (
                shutil.which("runuser")
                or next((p for p in ("/usr/sbin/runuser", "/sbin/runuser")
                         if os.path.exists(p)), None)
            )
            if runuser:
                cmd = [runuser, "-u", launch_user.pw_name, "--", *cmd]
            else:
                su = shutil.which("su") or "/usr/bin/su"
                cmd = [su, launch_user.pw_name, "-s", "/bin/sh", "-c",
                       " ".join(shlex.quote(a) for a in cmd)]
                logger.info(
                    "[+] (runuser unavailable; using su to drop ZAP to '%s')",
                    launch_user.pw_name,
                )

        env = {**os.environ, "ZAP_HOME": str(zap_home)}
        if launch_user is not None:
            # Point HOME at the real user so ZAP/JVM scratch paths resolve
            # correctly even though we didn't use a login shell.
            env["HOME"] = launch_user.pw_dir

        try:
            logger.info("[+] Starting ZAP daemon on %s:%s (log: %s)",
                        host, port, log_path or "<devnull>")
            # log_fd was opened non-fatally by _open_child_log above; never
            # re-open here (the open is the thing that used to kill the
            # launch with PermissionError on a poisoned /tmp/zap.log).
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=log_fd,
                stderr=asyncio.subprocess.STDOUT,
                env=env,
            )
            self.active_tasks.append(process)
            # Track the log fd so ``stop()`` can close it when the daemon
            # terminates -- otherwise the fd leaks for the lifetime of the
            # parent process. Keyed by the Process object so we don't have
            # to mutate it with a private attribute. Only track real file
            # objects (DEVNULL is an int and has no .close()).
            if hasattr(log_fd, "close"):
                self._child_log_fds = getattr(self, "_child_log_fds", {})
                self._child_log_fds[id(process)] = log_fd
        except Exception as e:
            logger.error("[!] ZAP daemon failed to start: %s", e, exc_info=True)

    async def wait_for_zap(self, host=None, port=None, timeout=60):
        """Block until the ZAP daemon's HTTP API responds.

        Polls ``http://<host>:<port>/`` once a second up to ``timeout``
        seconds. ZAP's first launch also has to extract/initialise its DB
        (cold start ~10-20s on a fresh home dir), so the default budget is
        generous. Call this from interactive / daemon startup right after
        scheduling ``start_zap_daemon``.
        """
        import requests as _requests
        host = host or ZAP_HOST
        port = port or ZAP_PORT
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                _requests.get(f"http://{host}:{port}/", timeout=2)
                logger.info("[+] ZAP daemon is up at %s:%s", host, port)
                return True
            except Exception:
                await asyncio.sleep(1)
        logger.warning("[!] ZAP daemon did not respond within %ss; "
                       "zap_* tools will fail until it does", timeout)
        return False

    async def wait_for_burp_mcp(self, timeout=15):
        """Probe the Burp MCP Server BApp's SSE endpoint.

        Unlike ZAP/MSF, we do NOT launch Burp — it's a GUI app the operator
        runs with the MCP Server BApp loaded.  This healthcheck just verifies
        the SSE endpoint is reachable so ``burp_*`` tools won't hang on first
        call.  Non-fatal: if Burp isn't running, the framework boots fine and
        ``burp_*`` tools return a structured 'not reachable' error when
        called.  Only runs when BURP_MCP=1 (opt-in, same pattern as the
        Playwright sidecar gate).
        """
        from auxiliaries.burp_mcp import BurpMCPClient
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                if BurpMCPClient.get_instance().healthcheck():
                    logger.info("[+] Burp MCP server is up at %s:%s",
                                BURP_MCP_HOST, BURP_MCP_PORT)
                    return True
            except Exception:
                pass
            await asyncio.sleep(1)
        logger.warning("[!] Burp MCP server did not respond within %ss; "
                       "burp_* tools will return a not-reachable error until "
                       "Burp is running with the BApp enabled", timeout)
        return False

    async def start_playwright_sidecar(self, host=None, port=None):
        """Start the scope-enforcing Playwright recon sidecar as a subprocess.

        Env-gated (PLAYWRIGHT_SIDECAR=1) -- only called when the operator
        opts in.  Same lifecycle shape as ``start_zap_daemon``: asyncio
        subprocess appended to ``active_tasks`` so ``stop()`` reaps it.

        The sidecar drives a headless Chromium and gates every navigation +
        fetch/XHR/websocket through the operator-armed scope gate (passive
        subresources allowed so pages render).  Bound loopback-only.  Logs
        to /tmp via ``_open_child_log`` so a crash is inspectable.

        If the playwright package or chromium binary is missing, the sidecar
        process exits immediately with a clear message; the ``playwright_*``
        client tools then return a 'sidecar not reachable' error guiding the
        operator to install -- they never fake a result.
        """
        host = host or os.getenv("PLAYWRIGHT_SIDECAR_HOST", "127.0.0.1")
        port = port or int(os.getenv("PLAYWRIGHT_SIDECAR_PORT", "8484"))
        venv_py = str(self.framework_root / "venv" / "bin" / "python")
        if not Path(venv_py).exists():
            venv_py = sys.executable
        log_fd, log_path = _open_child_log("playwright_sidecar")
        env = {**os.environ,
               "PLAYWRIGHT_SIDECAR_HOST": host,
               "PLAYWRIGHT_SIDECAR_PORT": str(port)}
        cmd = [venv_py, "-m", "auxiliaries.playwright_sidecar"]
        try:
            logger.info("[+] Starting Playwright sidecar on %s:%s (log: %s)",
                        host, port, log_path or "<devnull>")
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=log_fd,
                stderr=asyncio.subprocess.STDOUT,
                env=env,
            )
            self.active_tasks.append(process)
            if hasattr(log_fd, "close"):
                self._child_log_fds = getattr(self, "_child_log_fds", {})
                self._child_log_fds[id(process)] = log_fd
            await self.wait_for_playwright(host, port, timeout=20)
        except Exception as e:
            logger.error("[!] Playwright sidecar failed to start: %s", e,
                         exc_info=True)

    async def wait_for_playwright(self, host="127.0.0.1", port=8484, timeout=20):
        """Block until the sidecar /health endpoint responds."""
        import requests as _requests
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                r = _requests.get(f"http://{host}:{port}/health", timeout=2)
                if r.ok and r.json().get("ok"):
                    logger.info("[+] Playwright sidecar is up at %s:%s",
                                host, port)
                    return True
            except Exception:
                pass
            await asyncio.sleep(1)
        logger.warning("[!] Playwright sidecar did not respond within %ss; "
                       "playwright_* tools will return a not-reachable error "
                       "until it does", timeout)
        return False

    async def reload_module(self, module):
        """Reloads a given module and updates the tool registry."""
        try:
            importlib.reload(module)
            logger.info("[+] Module %s reloaded successfully.", module.__name__)
            for tool_name, (mod_path, func_name) in self.tool_registry.items():
                if mod_path == module.__name__:
                    self.tool_registry[tool_name] = (module.__name__, func_name)
                    logger.info("[+] Tool registry updated for %s.", tool_name)
        except Exception as e:
            logger.error("[!] Failed to reload module %s: %s", module.__name__, e, exc_info=True)
            raise

    async def start_api_server(self):
        """Starts the API server as an async task."""
        try:
            from api_gateway import run as FrameworkAPI
            await FrameworkAPI(loader=self, host="0.0.0.0", port=5000)
        except Exception as e:
            logger.error("[!] API server failed to start: %s", e, exc_info=True)

    async def stop(self):
        """Stop all background tasks and WAIT for child processes to exit.

        The old version fired terminate()/cancel() and returned without
        awaiting: SIGTERM was sent but the child's finally-block cleanup (the
        Brain unlinking /tmp/brain.sock, the SSL server tearing down) was never
        confirmed before the parent exited. Worse, in interactive mode there's
        no SIGINT handler, so a second impatient Ctrl+C aborted this loop
        mid-iteration -- some children never got terminate() at all and were
        left orphaned (PPID=1), still holding a live socket on an unlinked
        inode. Now: SIGTERM every child, await each exit concurrently with a
        grace period, SIGKILL stragglers, then await cancelled asyncio tasks.
        """
        logger.info("[*] Stopping background tasks...")
        procs = [t for t in self.active_tasks if isinstance(t, asyncio.subprocess.Process)]
        tasks = [t for t in self.active_tasks if not isinstance(t, asyncio.subprocess.Process)]

        # --- Graceful uvicorn shutdown -------------------------------------------------
        # Cancelling the API-server task mid-serve() leaves starlette's lifespan
        # handler parked on `await receive()`, which surfaces as a noisy
        # CancelledError traceback. Instead, flip uvicorn's should_exit flag so
        # serve() returns cleanly via its own shutdown path, then await the task
        # with a short grace period. If it doesn't wind down in time (or there
        # is no server reference), it falls through to the cancel loop below.
        if self.api_server is not None:
            self.api_server.should_exit = True
        if self.api_task is not None and not self.api_task.done():
            try:
                await asyncio.wait_for(asyncio.shield(self.api_task), timeout=3)
            except asyncio.TimeoutError:
                logger.warning("[!] API server didn't shut down in 3s; will cancel its task")
            except asyncio.CancelledError:
                pass
            except Exception:
                pass  # serve() may raise on forced exit; the task is done either way

        # Cancel any remaining asyncio tasks (API task may already be done now)
        for t in tasks:
            if not t.done():
                t.cancel()
        for p in procs:
            try:
                p.terminate()  # SIGTERM
            except ProcessLookupError:
                pass

        async def _reap_proc(p):
            try:
                await asyncio.wait_for(p.wait(), timeout=5)
                return
            except asyncio.TimeoutError:
                logger.warning("[!] Child pid %s didn't exit on SIGTERM; sending SIGKILL", p.pid)
            except ProcessLookupError:
                return
            except Exception as e:
                logger.warning("[!] Error awaiting child pid %s: %s", p.pid, e)
                return
            try:
                p.kill()  # SIGKILL
            except ProcessLookupError:
                return
            try:
                await p.wait()
            except Exception:
                pass

        async def _reap():
            if tasks:
                await asyncio.gather(*(t for t in tasks), return_exceptions=True)
            if procs:
                await asyncio.gather(*(_reap_proc(p) for p in procs), return_exceptions=True)
            # Close any child log fds (e.g. the ZAP daemon's /tmp/zap.log
            # writer) once the matching Process has been reaped.
            for proc in procs:
                fd = self._child_log_fds.pop(id(proc), None)
                if fd is not None:
                    try:
                        fd.close()
                    except Exception:
                        pass

        # Shield so a task cancellation (asyncio.run's KeyboardInterrupt path)
        # can't cut reaping short; children already got SIGTERM above, and the
        # Brain's own SIGTERM handler unlinks its socket regardless.
        try:
            await asyncio.shield(_reap())
        except asyncio.CancelledError:
            pass

        self.runner.stop()
        logger.info("[*] All background tasks stopped.")

    def _hard_kill_children(self):
        """Last-resort SIGKILL of every child process we know about. Called
        when a second KeyboardInterrupt aborts stop() before it can finish
        reaping, so no sidecar is left orphaned on a live socket."""
        for t in self.active_tasks:
            if isinstance(t, asyncio.subprocess.Process):
                try:
                    t.kill()
                except ProcessLookupError:
                    pass
                except Exception:
                    pass

    def _preflight_wordlists(self):
        """Launch-time wordlist sanity check for ffuf/hydra.

        Both brute-force tools consume wordlist file paths verbatim, so a
        missing/empty wordlist tree is the dominant silent-failure mode:
        ffuf exits with "could not read wordlist" and hydra errors on
        ``-P``/``-L`` paths mid-run.  Running this check at launch turns a
        runtime mystery into a startup warning the operator can fix before
        any run is attempted.  Read-only and idempotent; failures here are
        logged but never fatal — the framework still boots.
        """
        try:
            from utils.wordlists import preflight_wordlists
            report = preflight_wordlists()
        except Exception as exc:  # defensive: never block boot on a preflight
            logger.warning("[!] Wordlist preflight raised: %s", exc, exc_info=True)
            return
        if report["ok"]:
            logger.info(
                "[+] Wordlist preflight: %s .txt files under %s "
                "(common present: %s; absent: %s)",
                report["txt_count"], report["root"],
                ", ".join(report["common_present"]) or "none",
                ", ".join(report["common_absent"]) or "none",
            )
        else:
            logger.warning(
                "[!] Wordlist preflight FAILED for %s: %s",
                report["root"],
                "; ".join(report["warnings"]) or "unknown",
            )
            logger.warning(
                "[!] ffuf/hydra wordlist-based runs will fail until the tree "
                "is populated (install SecLists or set WORDLISTS_ROOT)."
            )

    async def launch_all(self):
        """Launches all servers in the background."""
        self.tool_registry.update({
            "smb_scan": ("auxiliaries.smb_scanner", "run_smb_recon"),
            "generate_certs": ("auxiliaries.cert_tools", "generate_certs"),
            "clear_certs": ("auxiliaries.cert_tools", "clear_certs"),
            "mcp": ("metasploiting", "start_mcp")
        })

        # Lazily create ids.db (findings + targets/sessions/notes tables) on
        # a fresh checkout so the first report_finding / framework_health
        # probe doesn't trip over a missing database file.  Idempotent — a
        # no-op when the file already exists.
        try:
            ensure_ids_db()
        except Exception as exc:
            logger.warning("[!] ids.db preflight raised: %s", exc, exc_info=True)

        # Preflight the wordlist tree BEFORE any tool can be dispatched so a
        # missing /usr/share/wordlists (or an undecompressed rockyou.txt) is
        # surfaced as a launch warning, not a silent ffuf/hydra failure later.
        self._preflight_wordlists()

        # Start services
        self.active_tasks.append(asyncio.create_task(self.start_brain_server()))
        self.active_tasks.append(asyncio.create_task(self.start_zap_daemon()))
        self.api_task = asyncio.create_task(self.start_api_server())
        self.active_tasks.append(self.api_task)
        self.active_tasks.append(asyncio.create_task(self.start_metasploit_mcp()))

        # Playwright scope-enforcing recon sidecar (env-gated, opt-in).  Off
        # by default — only starts when PLAYWRIGHT_SIDECAR=1, so a host
        # without chromium installed never tries to launch it.  When on, it
        # drives a headless Chromium that gates navigations + fetch/XHR/ws
        # through the operator-armed scope gate (passive subresources
        # allowed so pages render).  See auxiliaries/playwright_sidecar.py.
        if os.getenv("PLAYWRIGHT_SIDECAR", "").lower() in ("1", "true", "yes"):
            self.active_tasks.append(
                asyncio.create_task(self.start_playwright_sidecar())
            )

        # Wait for the ZAP API to answer before declaring launch complete;
        # the spider/ascan tools will otherwise fail their first call with
        # ConnectionError on a half-initialised daemon.
        await self.wait_for_zap()

        # Burp MCP healthcheck (env-gated, opt-in — BURP_MCP=1).  Unlike
        # ZAP/MSF we do NOT launch Burp; this just verifies the BApp's SSE
        # endpoint is reachable if the operator said they're running it.
        # Non-fatal: the framework boots fine without Burp; burp_* tools
        # return a structured not-reachable error when called.
        if BURP_MCP_ENABLED:
            await self.wait_for_burp_mcp()

        # Post-launch: if an operator-armed scope exists, mirror it into ZAP
        # (context includes/excludes) and flip mode=protect — ZAP itself then
        # refuses every out-of-scope request (redirect hops, spider crawls,
        # scan traffic, proxied manual browsing). Fire-and-forget: lab mode
        # without an armed scope is a legitimate state and sync failures are
        # logged, never fatal to the launch.
        self.active_tasks.append(
            asyncio.create_task(_zap_protect_launch_sync())
        )

        logger.info("[+] API Control Panel started on port 5000")
        logger.info("[*] Background servers initialized.")

# --- Main ---
async def _zap_protect_launch_sync() -> None:
    """Post-launch ZAP hardening: mirror the armed scope, set mode=protect.

    Non-fatal by design: with no scope armed (lab mode) the sync reports a
    clean skip; with ZAP down it times out and logs — never blocks launch.
    """
    try:
        from auxiliaries.zap import sync_protect_scope

        result = await asyncio.to_thread(sync_protect_scope)
        if result.get("status") == "Success":
            logger.info(
                "[+] ZAP protect-mode ON (context '%s', mode='%s', "
                "includes=%d, excludes=%d, skipped=%d)",
                result.get("context"),
                result.get("mode"),
                result.get("include_count"),
                result.get("exclude_count"),
                len(result.get("skipped") or []),
            )
        else:
            logger.warning(
                "[!] ZAP protect-mode sync not applied: %s",
                result.get("error", result),
            )
    except Exception as e:  # noqa: BLE001 - launch must never hinge on ZAP sync
        logger.warning("[!] ZAP protect-mode sync failed (non-fatal): %s", e)


async def run_framework():
    daemon_mode = "--daemon" in sys.argv
    loader = FrameworkLoader(FRAMEWORK_ROOT)
    loop = asyncio.get_running_loop()
    main_task = asyncio.current_task()
    sigint_count = 0

    def _graceful_sigint():
        """First Ctrl+C: cancel the main task so it flows into the finally ->
        stop() reaping path (clean socket unlink, awaited child exits). Second
        Ctrl+C: don't wait for graceful stop() -- it may be stuck -- hard-kill
        children and exit immediately so nothing is orphaned on a live socket.
        """
        nonlocal sigint_count
        sigint_count += 1
        if sigint_count == 1:
            logger.info("[*] Interrupt received; shutting down gracefully "
                        "(Ctrl+C again to force-quit)...")
            main_task.cancel()
        else:
            logger.warning("[!] Second interrupt: force-killing children and exiting")
            loader._hard_kill_children()
            os._exit(130)  # 128 + SIGINT(2); bypasses finally -- children already killed

    try:
        await loader.launch_all()
        if daemon_mode:
            shutdown_event = asyncio.Event()
            def request_shutdown(*_):
                shutdown_event.set()
            signal.signal(signal.SIGTERM, request_shutdown)
            signal.signal(signal.SIGINT, request_shutdown)
            await shutdown_event.wait()
        else:
            # Interactive mode (restricted). Install a graceful SIGINT handler
            # so a single Ctrl+C cancels the main task and flows into the
            # finally -> stop() reaping path, instead of raising a raw
            # KeyboardInterrupt mid-await that could leave cleanup half-done and
            # children orphaned. add_signal_handler dispatches the callback on
            # the loop thread (safe to cancel a task); fall back to signal.signal
            # on platforms (e.g. Windows) that don't implement it.
            try:
                loop.add_signal_handler(signal.SIGINT, _graceful_sigint)
            except NotImplementedError:
                signal.signal(signal.SIGINT, lambda *_: _graceful_sigint())
            logger.info("[*] Indexing framework tools...")
            await loader.vector_registry.bootstrap_registry()
            logger.info("[*] Entering interactive mode. Type 'exit' to quit.")
            while True:
                    await _chat(registry=loader.vector_registry)
                    break
    except asyncio.CancelledError:
        # Expected: our SIGINT handler cancelled main_task. Swallow it and fall
        # through to the finally so stop() can reap children gracefully. (We
        # deliberately suppress the cancellation here -- this is the graceful
        # shutdown path, not an error.)
        pass
    except Exception as e:
        logger.error("[-] Exception in main: %s", e, exc_info=True)
        try:
            with open("/tmp/framework_error.log", "w") as f:
                f.write(str(e))
        except Exception:
            pass
    finally:
        try:
            await loader.stop()
        except KeyboardInterrupt:
            # Defence in depth: a raw KeyboardInterrupt still reached stop()
            # (e.g. SIGTERM in interactive mode, or a platform where the
            # add_signal_handler fallback didn't take). Force-kill children so
            # none are orphaned on a live socket, then propagate.
            logger.warning("[!] Interrupt during shutdown: force-killing child processes")
            loader._hard_kill_children()
            raise

if __name__ == "__main__":
    asyncio.run(run_framework())