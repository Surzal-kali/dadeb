import subprocess
import asyncio
import ipaddress
import os
import json
import time as _time
from typing import Any, Dict, List, Literal, Optional
from constants import TransportType
import dotenv
from dotenv import load_dotenv

from constants import framework_tool
from pymetasploit3.msfrpc import MsfRpcClient
from utils.handles import format_handle, parse_handle

load_dotenv(override=True)

MSGRPC_PASSWORD = os.getenv("MSGRPC_PASSWORD", "msfadmin4824")
MSF_RPC_PORT = int(os.getenv("MSF_RPC_PORT", "55553"))
MSF_RPC_HOST = os.getenv("MSF_RPC_HOST", "127.0.0.1")

# How long dispatch_metasploit polls for new sessions after firing the module.
# ssh_login / similar auxiliaries take a few seconds to connect and create
# a session; without polling, the tool returns before the session exists
# and the caller never learns the session ID.
MSF_SESSION_POLL_SECONDS = float(os.getenv("MSF_SESSION_POLL_SECONDS", "60"))
MSF_SESSION_POLL_INTERVAL = float(os.getenv("MSF_SESSION_POLL_INTERVAL", "2"))

# Hard cap on how much of a module's 'module.results' output we render into
# the tool's return string.  A wide portscan or large cred dump can be many
# KB; letting that flow straight into the model's context is wasteful and
# noisy.  Truncate with a marker so the caller knows there's more.
MSF_RESULT_RENDER_MAX = int(os.getenv("MSF_RESULT_RENDER_MAX", "2000"))


def _render_module_result(result):
    """Render the 'result' field from MSF 'module.results' into a short,
    human-readable string.

    The shape varies by module: a bare string ("Login Successful: ..."), a
    single CheckCode hash ({"code":"...","reason":"..."}), or a hash of
    host => result for multi-host auxiliaries.  We JSON-format structured
    data and bound the length.
    """
    if result is None:
        return ""
    if isinstance(result, str):
        rendered = result.strip()
    elif isinstance(result, dict):
        # Common case: {"<host>": {"code":..., "reason":...}, ...} or a single
        # check-code hash like {"code":"vulnerable","reason":"..."}.
        rendered = json.dumps(result, indent=2, default=str, sort_keys=True)
    elif isinstance(result, (list, tuple)):
        rendered = json.dumps(list(result), indent=2, default=str)
    else:
        rendered = str(result)
    if len(rendered) > MSF_RESULT_RENDER_MAX:
        rendered = rendered[:MSF_RESULT_RENDER_MAX] + "\n...[truncated]"
    return rendered


class MetasploitClient:
    _shared: "MetasploitClient | None" = None

    def __init__(self, mcp_path="msfrpcd"):
        self.mcp_path = mcp_path

    @classmethod
    def get_instance(cls) -> "MetasploitClient":
        """Return the shared client so bootstrap and in-process tool launches
        bind to the SAME msfconsole handle."""
        if cls._shared is None:
            cls._shared = cls()
        return cls._shared

    async def _ensure_running(self) -> bool:
        """Ensure a live msgrpc RPC connection exists, lazily starting one if needed.

        Returns False (and explains why) instead of silently returning None,
        which upstream used to report as 'Success'.
        """
        if not hasattr(self, 'client') or self.client is None:
            print("[i] No MSF RPC client on this instance; attempting lazy start...")
            await self.start_mcp()
            # start_mcp returns a Process or None (None when it reused an
            # already-running msfconsole, or on failure); success is signalled
            # by the client actually being populated, not by the return value.
            if not getattr(self, 'client', None):
                print(
                    "[!] Metasploit RPC could not be started (msfrpcd may "
                    "not be running or failed to bind)."
                )
                return False
        return True

    async def _wait_for_port(self, host=MSF_RPC_HOST, port=MSF_RPC_PORT,
                             timeout=90, interval=2):
        """Poll until the msfrpcd TCP port accepts a connection.

        msfrpcd can take 30-60+ seconds to boot and build the module cache
        (especially on first run).  Connecting before the port is open
        causes MsfRpcClient.login() to fail with an auth/connection error
        that the 3-try retry in post_request cannot out-wait.  This poller
        gives the RPC server time to come up before we attempt
        authentication.
        """
        import socket as _socket
        deadline = _time.time() + timeout
        while _time.time() < deadline:
            try:
                with _socket.create_connection((host, port), timeout=2):
                    return True
            except (ConnectionRefusedError, OSError, _socket.timeout):
                pass
            await asyncio.sleep(interval)
        return False

    async def start_mcp(self):
        """
        Start the Metasploit RPC daemon (msfrpcd) and connect to it.

        Launches msfrpcd with a fixed set of credentials and binding options,
        then polls until the RPC port is accepting connections before
        creating the MsfRpcClient.
        """
        user = "msfadmin"
        pwd = MSGRPC_PASSWORD
        host = MSF_RPC_HOST
        port = MSF_RPC_PORT
        try:
            # Check if msfrpcd is already running so we don't spawn a
            # duplicate that would fail to bind the port.  Use -f (full
            # cmdline match) and the '[m]sfrpcd' regex trick so pgrep
            # cannot match its own command line or the shell running it.
            # create_subprocess_exec (no shell) avoids an intermediate
            # bash process whose argv could be matched.
            proc = await asyncio.create_subprocess_exec(
                "pgrep", "-f", "[m]sfrpcd",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()

            launched_process = None
            if not stdout:
                print("[i] msfrpcd is not running; launching it...")
                # Stream msfrpcd's output to a log file so models can read back
                # the console stdout/stderr via the read_logs('msf') tool. The
                # old code piped to PIPE, which was never drained, so the tool
                # always reported the log missing. Append-mode keeps history
                # across framework restarts (matches the Brain/ZAP pattern in
                # bootstrap.start_brain_server / start_zap_daemon).
                # Non-fatal: a poisoned/immutable /tmp/msfconsole_mcp.log must
                # not kill the msfrpcd launch -- fall back to a uid-scoped path
                # then DEVNULL (same pattern as bootstrap._open_child_log).
                msf_log = None
                for _msf_path in (f"/tmp/msfconsole_mcp.log",
                                  f"/tmp/msfconsole_mcp-{os.geteuid()}.log"):
                    try:
                        msf_log = open(_msf_path, "ab")
                        break
                    except OSError:
                        continue
                if msf_log is None:
                    msf_log = asyncio.subprocess.DEVNULL
                    print("[!] /tmp/msfconsole_mcp*.log unwritable; msfrpcd stdout -> DEVNULL")
                launched_process = await asyncio.create_subprocess_exec(
                    self.mcp_path,
                    "-U", user,
                    "-P", pwd,
                    "-S",
                    "-a", host,
                    "-p", str(port),
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=msf_log,
                    stderr=asyncio.subprocess.STDOUT,
                    start_new_session=True,
                )
                # Track the log fd so bootstrap.stop() can close it when it
                # reaps this process -- otherwise the fd leaks for the
                # lifetime of the interpreter. bootstrap.register_child_log_fd
                # picks this up via start_metasploit_mcp. Only track real file
                # objects (DEVNULL is an int with no .close()).
                self._msf_log_fd = msf_log if hasattr(msf_log, "close") else None
            else:
                print("[i] msfrpcd already running; connecting to it...")

            # Poll for the RPC port to come up before attempting to connect.
            ready = await self._wait_for_port(host=host, port=port)
            if not ready:
                print(
                    f"[!] msfrpcd did not come up on {host}:{port} within "
                    f"the timeout."
                )
                self.client = None
                return launched_process

            # Connect to the RPC interface now that the port is confirmed open.
            self.client = MsfRpcClient(
                password=pwd, port=port, server=host, username=user
            )
            # Return the Process we own so bootstrap can reap it, or None if
            # we reused an already-running msfrpcd (nothing for us to kill).
            return launched_process
        except Exception as e:
            print(f"An error occurred while trying to start MSF RPC: {e}")
            return None

    # This one goes through the Brain's logic
    @framework_tool(
        "Look up Metasploit modules by type and name. Use this to find "
        "exploits, auxiliaries, payloads, and post-exploitation modules "
        "matching a known vulnerability or service (e.g. vsftpd backdoor, "
        "ssh_login, samba usermap_script). Returns a JSON list of objects, "
        "each with a 'module_path' field AND a 'category' field. The "
        "'category' is one of 'exploit', 'auxiliary', or 'post' and tells "
        "dispatch_metasploit which execution path to use. Copy BOTH fields "
        "verbatim from a single result row when calling dispatch_metasploit. "
        "Do not abbreviate or shorten the path.",
        transport=TransportType.BRAIN_DISPATCH,
    )
    async def index_modules(
        self,
        module_type: Optional[str] = None,
        module_name: Optional[str] = None,
        limit: int = 15,
    ):
        """
        Search for a Metasploit module by type and name.

        Args:
            module_type: Optional module type filter (exploit, auxiliary, payload, post).
            module_name: Module name or keyword to search for (e.g. 'ssh', 'vsftpd').
            limit: Maximum number of results to return (default 15). Caps
                   result size so the secretary model's context isn't flooded
                   with 50+ matches, which causes it to abbreviate paths.
        """
        if not await self._ensure_running():
            return None

        try:
            query = ""
            if module_type and module_name:
                query = f"type:{module_type} name:{module_name}"
            elif module_type:
                query = f"type:{module_type}"
            elif module_name:
                query = module_name
            else:
                return "Please provide either a module_type or a module_name to search."

            results = self.client.modules.search(query)

            if not results:
                return f"No modules found matching query: {query}"

            # Build a structured list with a clearly-labeled module_path
            # field. Returning JSON (instead of formatted text like
            # "path (type) — name") makes it much harder for the secretary
            # model to abbreviate or mangle the path when it passes it to
            # dispatch_metasploit. The model copies a labeled JSON value far more
            # reliably than it parses and re-types a formatted string.
            #
            # MSF RPC module.search returns results in variable formats
            # depending on the Metasploit version and RPC client:
            #   Format A: {"modules": [{"fullname": "type/name", "name": "Title", ...}]}
            #   Format B: {"exploit": [{"fullname": "exploit/...", ...}], "auxiliary": [...]}
            #   Format C: [{"fullname": "type/name", ...}]
            # The 'fullname' key holds the full module path (e.g.
            # 'exploit/unix/ftp/vsftpd_234_backdoor') and is the ONLY
            # reliable source for the path. The 'name' key holds the
            # human-readable TITLE (e.g. 'VSFTPD 2.3.4 Backdoor Command
            # Execution') and must NOT be used as a module_path — it will
            # cause dispatch_metasploit to fail with "invalid module_path".
            structured = []

            def _extract_module(mod, fallback_type="?"):
                """Extract module_path, type, and display name from a search result dict.

                Tries keys in priority order: fullname (the real path),
                module_name, refname, path. Falls back to reconstructing
                type/shortname when no path-like key is found. Never uses
                the human-readable 'name'/'description' as a module_path.
                """
                if isinstance(mod, dict):
                    # fullname is the authoritative full path in MSF RPC.
                    path = mod.get('fullname')
                    if path and '/' in path:
                        return {
                            "module_path": path,
                            "category": path.split('/')[0],
                            "name": mod.get('name', mod.get('description', path)),
                        }
                    # module_name / refname may hold the short path (after type/).
                    for key in ('module_name', 'refname', 'path'):
                        val = mod.get(key)
                        if val and '/' in val:
                            # Looks like a module path segment — reconstruct.
                            full = f"{mod.get('type', fallback_type)}/{val}"
                            return {
                                "module_path": full,
                                "category": mod.get('type', fallback_type),
                                "name": mod.get('name', mod.get('description', full)),
                            }
                    # Last resort: if 'name' looks like a path (contains /),
                    # use it. Otherwise reconstruct from type + whatever we have.
                    raw_name = mod.get('name', '')
                    if raw_name and '/' in raw_name:
                        full = f"{mod.get('type', fallback_type)}/{raw_name}" if not raw_name.startswith(fallback_type) else raw_name
                        return {
                            "module_path": full,
                            "category": mod.get('type', fallback_type),
                            "name": mod.get('description', full),
                        }
                    # Give up — return what we have and flag it for the caller.
                    return {
                        "module_path": f"{fallback_type}/{raw_name or 'unknown'}",
                        "category": mod.get('type', fallback_type),
                        "name": mod.get('name', mod.get('description', 'unknown')),
                    }
                elif hasattr(mod, 'name') and hasattr(mod, 'type'):
                    return {
                        "module_path": getattr(mod, 'fullname', None) or getattr(mod, 'name', '?'),
                        "category": getattr(mod, 'type', '?'),
                        "name": getattr(mod, 'name', '?'),
                    }
                else:
                    return {
                        "module_path": str(mod),
                        "category": fallback_type,
                        "name": str(mod),
                    }

            # Unwrap the {"modules": [...]} envelope if present.
            # MSF RPC sometimes wraps results this way; treat "modules" as
            # a list, not as a module type name.
            if isinstance(results, dict) and 'modules' in results and isinstance(results['modules'], list):
                mod_list = results['modules']
                for mod in mod_list:
                    structured.append(_extract_module(mod))
            elif isinstance(results, dict):
                for mod_type, mod_list in results.items():
                    if not isinstance(mod_list, list):
                        mod_list = [mod_list]
                    for mod in mod_list:
                        structured.append(_extract_module(mod, fallback_type=mod_type))
            elif isinstance(results, list):
                for mod in results:
                    structured.append(_extract_module(mod))
            else:
                return str(results)

            # Cap the result count so the model's context window isn't
            # overwhelmed by a long list (which causes abbreviation/truncation).
            max_results = int(limit) if limit else 15
            total = len(structured)
            if total > max_results:
                structured = structured[:max_results]

            if not structured:
                return f"No modules found matching query: {query}"

            return {
                "query": query,
                "total_matches": total,
                "returned": len(structured),
                "modules": structured,
                "note": "Use the 'module_path' value verbatim as the module_path argument to dispatch_metasploit, and copy the 'category' field alongside it. Do not abbreviate.",
            }
        except Exception as e:
            print(f"An error occurred while searching for the module: {e}")
            return None

    # This one is tagged to use the direct RPC path
    @framework_tool(
        "Execute any Metasploit module — exploit, auxiliary, or post — "
        "against a target. This is the single entry point for all MSF module "
        "execution; pick the 'category' field returned by index_modules "
        "(one of 'exploit', 'auxiliary', 'post') and pass it VERBATIM alongside "
        "the module_path. Examples:\n"
        "  - exploit (vsftpd_234_backdoor): category='exploit', "
        "    options={RHOSTS: '...', PAYLOAD: 'cmd/unix/interact'}\n"
        "    (interact-class backdoor: no LHOST/LPORT, start_handler=False)\n"
        "  - auxiliary (ssh_login): category='auxiliary', "
        "    options={RHOSTS: '...', USERNAME: '...', PASSWORD: '...'}\n"
        "  - post (gather enum_info): category='post', "
        "    options={SESSION: <int>, ...}\n\n"
        "For exploit modules using a reverse or bind payload, pass "
        "start_handler=True to start a separate persistent exploit/multi/handler "
        "listener first (required over msfrpcd because the exploit module's "
        "implicit handler does not reliably bind). Pass start_handler=False "
        "(the default) for auxiliaries, login scanners, post modules, and "
        "exploits that handle their own connection (e.g. vsftpd_234_backdoor).\n\n"
        "After execution, polls for new sessions and returns their 'msf:' "
        "handles. The module_path MUST be the exact value returned by "
        "index_modules's module_path field — do not abbreviate, shorten, or "
        "paraphrase it. Use cmd/unix/* or cmd/linux/* shell payloads; "
        "meterpreter payloads may work on some setups but are less reliable "
        "through this pymetasploit3 RPC client.",
        transport=TransportType.MCP_RPC,
    )
    async def dispatch_metasploit(
        self,
        module_path: str,
        category: Literal["exploit", "auxiliary", "post"],
        options: Dict[str, Any],
        start_handler: bool = False,
    ):
        """
        Dispatch any Metasploit module to the right execution path based on
        its category. Single entry point; the underlying execution logic
        branches internally.

        Args:
            module_path: Full MSF module path, e.g. 'exploit/unix/ftp/vsftpd_234_backdoor'.
            category: One of 'exploit', 'auxiliary', 'post'. MUST match the
                prefix of module_path (e.g. 'exploit' for 'exploit/.../foo').
                Copy this verbatim from index_modules's category field.
            options: Dict of option name -> value (RHOSTS, USERNAME, PAYLOAD,
                LHOST, LPORT, SESSION, etc.). PAYLOAD is required for exploit
                modules; SESSION is required for post modules.
            start_handler: Only used when category='exploit'. If True, start a
                SEPARATE persistent exploit/multi/handler job before firing
                the module (required for reverse/bind payloads over msfrpcd).
        """
        # Scope gate (operator-armed from the Tool REPL; no-op when disarmed).
        # dispatch_metasploit is the ONLY target-bearing entry point: every
        # exploit/auxiliary launch must carry a gate-confirmed target.
        # Post modules run inside an existing (already-gated) session, so
        # SESSION-only options are exempt from the missing-target refusal.
        # 2026-09-19 gap: this dispatch shipped without any gate check.
        from utils.scope_gate import check_scan, is_armed, ScopeGateError
        if is_armed():
            _opts = options if isinstance(options, dict) else {}
            _targets = [
                str(_opts.get(_k))
                for _k in ("RHOSTS", "RHOST", "RHOST6", "rhosts", "rhost")
                if _opts.get(_k)
            ]
            if category in ("exploit", "auxiliary") and not _targets:
                raise ScopeGateError(
                    "scope gate: no RHOST/RHOSTS option on a target-bearing "
                    f"{category} dispatch; the armed gate cannot verify the "
                    "target and refuses. Pass RHOSTS explicitly, or run "
                    "'scope off' for lab mode."
                )
            for _t in _targets:
                _ok, _reason = check_scan(_t)
                if not _ok:
                    raise ScopeGateError(f"scope gate: {_reason}")

        # Validate category matches the module_path prefix. Catches model
        # confusion (passing an auxiliary module with category='exploit')
        # BEFORE we waste 30s polling for sessions that will never appear.
        # Return a structured error dict (not a string) so the executor
        # surfaces this as status=Failed — the secretary then narrates it
        # correctly instead of treating it as a successful execution.
        if "/" in module_path:
            inferred = module_path.split("/", 1)[0]
            if inferred != category:
                return {
                    "status": "Failed",
                    "error": (
                        f"Category mismatch: module_path '{module_path}' starts "
                        f"with '{inferred}' but category='{category}' was passed. "
                        f"These must agree (an exploit/... module requires "
                        f"category='exploit', etc.). Copy the 'module_path' and "
                        f"'category' fields together from the same index_modules "
                        f"result row."
                    ),
                }

        # Post modules need an existing session id. Validate up front so we
        # don't waste a 30s poll on a guaranteed-empty session list.
        if category == "post":
            session_id = options.get("SESSION") if isinstance(options, dict) else None
            if session_id is None or session_id == "":
                return {
                    "status": "Failed",
                    "error": (
                        "category='post' requires a 'SESSION' option (the numeric "
                        "id of an existing Metasploit session returned by a prior "
                        "exploit or auxiliary dispatch). Call list_sessions to see "
                        "active session ids; pass the integer as a string, e.g. "
                        "options={'SESSION': '1'}."
                    ),
                }

        # Delegate to the existing implementation. The category is used by
        # the impl for category-specific guards (PAYLOAD validation for
        # exploit, AutoCheck defaults, etc.); passing it through keeps the
        # internal logic untouched.
        return await self._execute_module_impl(
            module_path=module_path,
            options=options,
            start_handler=start_handler,
            category=category,
        )

    async def _start_handler_job(self, payload_name: str, lhost, lport):
        """Start a standalone persistent ``exploit/multi/handler`` job for an
        already-chosen reverse/bind payload.

        Shared by ``_execute_module_impl`` (``start_handler=True`` on an
        exploit dispatch) and the msfvenom lane
        (``payloads/msfvenom_tools.py:generate_payload`` with
        ``start_handler=True``) so the bind/listen semantics — load handler
        module, load payload module, set LHOST/LPORT, execute, settle —
        live in exactly one place.  The caller resolves LHOST/LPORT from its
        own context (MSF options dict / PayloadModule defaults / the
        generate call) before invoking.

        Returns ``(job_id, None)`` on success, ``(None, error_string)`` on
        failure.  A handler that won't start is not fatal to the exploit
        itself, but for reverse payloads it usually means no session will
        form — the caller surfaces the error rather than silently proceeding
        to the 30s poll with no listener.
        """
        try:
            # Use the direct RPC path instead of pymetasploit3's
            # module.execute(payload=PayloadModule).  The PayloadModule path
            # serializes meterpreter's AutoLoadExtensions as a non-scalar
            # (list/dict), and MSF rejects the launch with "Invalid module
            # option value for AutoLoadExtensions: must be a scalar".
            # Passing PAYLOAD as a string in the runopts dict lets MSF resolve
            # the payload's options itself — no non-scalar serialization.
            from pymetasploit3.msfrpc import MsfRpcMethod
            handler_runopts = {"PAYLOAD": payload_name, "LHOST": lhost, "LPORT": lport}
            handler_result = self.client.call(
                MsfRpcMethod.ModuleExecute,
                ["exploit", "multi/handler", handler_runopts],
            )
            handler_job = (
                handler_result.get("job_id")
                if isinstance(handler_result, dict)
                else handler_result
            )
            if handler_job is None:
                return None, (
                    "Failed to start exploit/multi/handler (MSF returned "
                    f"no job_id for {payload_name} LHOST={lhost} LPORT={lport}). "
                    "The port may already be bound by another handler, or the "
                    "payload/LHOST/LPORT are invalid."
                )
            # Give the listener a moment to bind before the payload fires,
            # so the callback never arrives ahead of the bind.
            await asyncio.sleep(1.0)
            return handler_job, None
        except Exception as e:  # noqa: BLE001 - surface, never mask
            return None, (
                f"Failed to start exploit/multi/handler for "
                f"{payload_name} on {lhost}:{lport}: {e}. The listener "
                "could not bind (port in use?) or the payload is invalid."
            )

    async def _execute_module_impl(
        self,
        module_path: str,
        options: Dict[str, Any],
        start_handler: bool,
        category: str,
    ):
        """Internal implementation backing dispatch_metasploit. Not a
        @framework_tool — call directly only when category is already known
        and validated (dispatch_metasploit does that)."""
        if not await self._ensure_running():
            return None

        try:
            # Record sessions that exist BEFORE execution so we can detect
            # new ones created by this module run.
            before = set(self.client.sessions.list.keys())

            # pymetasploit3 ModuleManager has use(mtype, mname), not load().
            # Split 'auxiliary/scanner/ssh/ssh_login' into type='auxiliary'
            # and name='scanner/ssh/ssh_login'.
            parts = module_path.split("/", 1)
            if len(parts) != 2:
                return f"Invalid module_path '{module_path}'. Expected 'type/name', e.g. 'auxiliary/scanner/ssh/ssh_login'."
            mtype, mname = parts[0], parts[1]
            # Belt-and-suspenders: the public entry already validated this,
            # but if anything else calls us directly (tests, the API gateway)
            # we still want the guard.
            if mtype != category:
                return (
                    f"Internal category mismatch: module_path='{module_path}' "
                    f"has type '{mtype}' but caller passed category='{category}'."
                )
            module = self.client.modules.use(mtype, mname)

            # Type coercion: the secretary model passes all option values as
            # strings (from JSON), but pymetasploit3 enforces types — boolean
            # options raise TypeError if given "true"/"false" strings, and
            # integer options may misbehave with string numbers.  Inspect each
            # option against the module's option metadata and coerce.
            def _coerce(opt_name, opt_val, target_module):
                if opt_name not in target_module.options:
                    return opt_val  # payload-level option, handle separately
                # pymetasploit3 stores option metadata in _moptions
                mopt = target_module._moptions.get(opt_name, {})
                opt_type = mopt.get("type", "")
                if opt_type == "bool":
                    if isinstance(opt_val, str):
                        return opt_val.lower() in ("true", "1", "yes")
                    return bool(opt_val)
                elif opt_type == "integer":
                    try:
                        return int(opt_val)
                    except (ValueError, TypeError):
                        return opt_val
                return opt_val

            # CRITICAL: pymetasploit3 exploit modules do NOT accept PAYLOAD,
            # LHOST, or LPORT as regular datastore options (module['PAYLOAD']
            # raises KeyError).  These are payload-level options that must be
            # set on a PayloadModule object and passed to execute().  Worse,
            # calling execute() with no payload kwarg sets
            # DisablePayloadHandler=True — the exploit fires but never listens
            # for the reverse shell, so no session is ever created.
            #
            # The fix: if PAYLOAD is in the options, load it as a
            # PayloadModule, set LHOST/LPORT/etc. on it, and pass the
            # PayloadModule to execute().  pymetasploit3's execute() merges
            # the payload's runoptions (LHOST, LPORT, etc.) into the final
            # RPC call — this is the ONLY way those values reach MSF.
            opts = dict(options)  # copy so we don't mutate the caller's dict
            payload_name = opts.pop("PAYLOAD", None)


            # PAYLOAD format hygiene: the secretary model occasionally
            # hallucinates an MSF-internal 'payload/' prefix (e.g.
            # 'payload/cmd/unix/reverse_awk') because module listings
            # sometimes render payloads that way. MSF itself wants the bare
            # fullname; 'payload/x' is never a valid payload name, so
            # stripping exactly one leading 'payload/' is a lossless fix.
            if isinstance(payload_name, str):
                cleaned = payload_name.strip()
                if cleaned.lower().startswith("payload/"):
                    fixed = cleaned[len("payload/"):]
                    print(
                        f"[i] Stripped hallucinated 'payload/' prefix from "
                        f"PAYLOAD: {payload_name!r} -> {fixed!r} (MSF payload "
                        f"names never carry the 'payload/' prefix)."
                    )
                    payload_name = fixed

            # Interact-class exploit guard. Some exploits deliver NO payload
            # at all: the trigger makes the TARGET spawn an inline service
            # (e.g. vsftpd_234_backdoor binds a root shell on target port
            # 6200 after the ':)' username) and the module itself connects
            # to that port to interact (payload class cmd_interact,
            # connection type 'find'). Passing any custom reverse/bind
            # payload is incompatible, and omitting PAYLOAD entirely makes
            # execute() set DisablePayloadHandler=True — which kills the
            # module's own connect-to-6200 step. The ONLY working invocation
            # is PAYLOAD='cmd/unix/interact' with start_handler=False.
            INTERACT_FORCE_MODULES = {
                "exploit/unix/ftp/vsftpd_234_backdoor",
            }
            if mtype == "exploit" and module_path in INTERACT_FORCE_MODULES:
                if payload_name != "cmd/unix/interact":
                    old = payload_name if payload_name else "(none)"
                    payload_name = "cmd/unix/interact"
                    print(
                        f"[i] Interact-class module guard: '{module_path}' "
                        f"delivers NO payload — it triggers a shell ON the "
                        f"target (vsftpd_234_backdoor binds root on port 6200 "
                        f"after the ':)' username) and connects inbound. "
                        f"Forcing PAYLOAD {old!r} -> 'cmd/unix/interact' "
                        f"(no LHOST/LPORT needed; start_handler must be False)."
                    )
                for dropped in ("LHOST", "LPORT", "ListenerBindAddress", "ListenerBindPort"):
                    if dropped in opts:
                        opts.pop(dropped)
                        print(
                            f"[i] Interact-class module guard: dropped "
                            f"'{dropped}' from options (not used by "
                            f"'{module_path}')."
                        )

            # Route-affinity guard for reverse/bind callbacks. NON-FATAL:
            # warns when the callback address (LHOST/SRVHOST/
            # ListenerBindAddress) is not an IP of the interface the route
            # to RHOSTS egresses from. Topology-agnostic — follows the
            # actual kernel route instead of assuming subnet layout, so it
            # works for same-host VM nets, LANs, and VPN tunnels alike.
            if mtype == "exploit":
                _CB_KEYS = ("LHOST", "SRVHOST", "ListenerBindAddress")
                cb_ip = next((opts[k] for k in _CB_KEYS if opts.get(k)), None)
                rhost = opts.get("RHOSTS") or opts.get("RHOST")
                if cb_ip and rhost and not str(cb_ip).startswith("127."):
                    try:
                        _probe = subprocess.run(
                            ["ip", "route", "get", str(rhost).split("/")[0]],
                            capture_output=True, text=True, timeout=5,
                        )
                        toks = _probe.stdout.split()
                        iface = toks[toks.index("dev") + 1] if "dev" in toks else None
                        if iface:
                            _addr = subprocess.run(
                                ["ip", "-4", "-o", "addr", "show", "dev", iface],
                                capture_output=True, text=True, timeout=5,
                            ).stdout
                            iface_ips = [
                                line.split()[3].split("/")[0]
                                for line in _addr.splitlines()
                                if len(line.split()) >= 4
                            ]
                            if iface_ips and str(cb_ip) not in iface_ips:
                                cgnat = ""
                                try:
                                    if ipaddress.ip_address(str(cb_ip)) in ipaddress.ip_network("100.64.0.0/10"):
                                        cgnat = (
                                            " (inside 100.64.0.0/10 CGNAT range "
                                            "- a tailnet address; unreachable "
                                            "from targets that are not tailnet "
                                            "nodes)"
                                        )
                                except ValueError:
                                    pass
                                print(
                                    f"[!] Route-affinity WARNING: callback "
                                    f"address {cb_ip}{cgnat} is NOT an IP of "
                                    f"interface '{iface}' (own IPs: "
                                    f"{iface_ips}), which is the egress toward "
                                    f"{rhost}. The target likely cannot route a "
                                    f"connection back to {cb_ip}. Prefer "
                                    f"{iface_ips[0]} for LHOST, or use a bind "
                                    f"payload with RHOST set to the target."
                                )
                    except Exception:
                        pass  # the guard must never block a launch

            # The secretary model occasionally drops top-level arguments into
            # the `options` dict because the schema is permissive (additionalProperties
            # is implicit). Strip our own framework-level parameters that are
            # NOT valid MSF datastore keys so they don't get forwarded to MSF
            # and rejected as "Invalid option". Each stripped key is logged
            # so the model can self-correct on retry.
            for framework_only in ("start_handler",):
                if framework_only in opts:
                    val = opts.pop(framework_only)
                    print(
                        f"[i] Stripped framework-only key '{framework_only}' "
                        f"from options dict (value={val!r}); it must be a "
                        f"top-level argument to dispatch_metasploit, not nested "
                        f"inside options."
                    )

            # Validate the requested PAYLOAD against the module's compatible
            # payloads BEFORE attempting to launch.  The single most common
            # vsftpd_234_backdoor failure is "Unsupported Binary Selected": the
            # caller picks a binary FTP-stager payload (cmd/linux/ftp/<arch>/*)
            # whose ELF can't be staged through the backdoor's raw shell on
            # port 6200.  Reject those up front and steer the caller at the
            # pure-command cmd/unix/* payloads that run a one-liner on the
            # shell.  Also note that meterpreter payloads are unusable through
            # this pymetasploit3 client (it serializes AutoLoadExtensions as a
            # non-scalar and MSF rejects it with "Invalid module option value
            # for AutoLoadExtensions: must be a scalar").
            # Interact-class exemption: module.payloads LIES for
            # cmd_interact modules. vsftpd_234_backdoor declares PayloadType
            # 'cmd_interact' and MSF's own docs set PAYLOAD cmd/unix/interact,
            # yet msfrpc's compatible_payloads list omits it — so the generic
            # compat check below false-negatives the ONE payload that works
            # and makes the module unrunnable. The interact guard above has
            # already sanitized/forced the correct payload for these modules,
            # so skip the compat check entirely for them.
            if mtype == "exploit" and payload_name and module_path not in INTERACT_FORCE_MODULES:
                # NOTE: the previous hard-block on meterpreter payloads was
                # removed.  It was written for an older pymetasploit3/MSF combo
                # where AutoLoadExtensions serialized as a non-scalar and MSF
                # rejected the launch.  That bug no longer reproduces on current
                # setups — cmd/linux/http/*/meterpreter/* payloads launch fine
                # via msfrpcd (verified job_id non-null).  If a meterpreter
                # payload DOES fail, MSF's own job_id=null response surfaces it
                # through the launch-failure detection below with a clear error.
                try:
                    compatible = list(module.payloads)
                except Exception:
                    compatible = []
                if compatible and payload_name not in compatible:
                    # Group compatible payloads by stager family so the error
                    # message steers toward payloads that actually work with
                    # this module's arch/platform/stager — not just cmd/unix/*
                    # (which is the vsftpd backdoor guidance and wrong for
                    # ARCH_CMD + Platform linux modules like freepbx that
                    # need cmd/linux/http/* stagers).
                    cmd_unix = [p for p in compatible if p.startswith("cmd/unix/")]
                    cmd_linux_http = [p for p in compatible if p.startswith("cmd/linux/http/")]
                    cmd_linux_ftp = [p for p in compatible if p.startswith("cmd/linux/ftp/")]
                    generic = [p for p in compatible if p.startswith("generic/")]
                    meterp = [p for p in compatible if "meterpreter" in p]
                    non_meterp = [p for p in compatible if "meterpreter" not in p]
                    # Prefer non-meterpreter shell payloads from the most
                    # relevant stager family; fall back to whatever exists.
                    suggestions = (cmd_linux_http or cmd_linux_ftp or
                                   cmd_unix or generic or non_meterp or compatible)
                    return (
                        f"PAYLOAD '{payload_name}' is not compatible with "
                        f"'{module_path}' (its compatible payloads do not include "
                        f"it). MSF would reject the launch (job_id=null). "
                        f"Compatible payloads by family:\n"
                        f"  cmd/linux/http: {cmd_linux_http[:6]}\n"
                        f"  cmd/linux/ftp:  {cmd_linux_ftp[:6]}\n"
                        f"  cmd/unix:       {cmd_unix[:6]}\n"
                        f"  generic:        {generic[:6]}\n"
                        f"  meterpreter:    {len(meterp)} listed ({meterp[:3]})\n"
                        f"Try one of: {suggestions[:8]}"
                    )

            # Set non-payload options on the module datastore first.
            # Check against module.options (the list of valid option names),
            # NOT `option in module` — __contains__ checks _runopts which is
            # the runtime datastore and may not contain options that haven't
            # been set yet, causing valid options like RHOSTS to be skipped.
            for option, value in opts.items():
                if option in module.options:
                    coerced = _coerce(option, value, module)
                    module[option] = coerced

            # CRITICAL: For exploit modules with a reverse payload, set
            # ExitOnSession=false so the handler job stays alive after the
            # first session connects.  The MSF default (ExitOnSession=true)
            # causes the handler to exit the instant a session is created;
            # for staged payloads (e.g. windows/meterpreter/reverse_tcp) the
            # stage transfer is still in flight when the handler dies, so the
            # TCP connection drops and the session closes within ~1 second.
            # The caller can still override this by passing ExitOnSession in
            # options, but the safe default is false.
            if mtype == "exploit" and payload_name and "ExitOnSession" in module.options:
                if "ExitOnSession" not in opts:
                    module["ExitOnSession"] = False
                # If the caller explicitly passed it, _coerce already set it
                # in the loop above.

            # Harness defaults for exploit modules: skip the exploitability
            # check (AutoCheck=false) and force execution even when the check
            # is inconclusive (ForceExploit=true).  The operator has already
            # approved this run via the human-in-the-loop gate, so the check
            # is pure friction — and for backdoor-style exploits it actively
            # misfires: once the backdoor port (e.g. 6200) is open from a
            # prior run, AutoCheck aborts with "Cannot reliably check
            # exploitability … set ForceExploit true".  Both options are
            # settable datastore options and the caller can override either
            # by passing it in `options` (the loop above already applied it).
            if mtype == "exploit":
                if "AutoCheck" in module.options and "AutoCheck" not in opts:
                    module["AutoCheck"] = False
                if "ForceExploit" in module.options and "ForceExploit" not in opts:
                    module["ForceExploit"] = True

            # Build the payload argument for execute().
            payload_arg = None
            if payload_name:
                # Load the payload as a PayloadModule so LHOST/LPORT can be
                # set on it.  pymetasploit3's execute() only merges payload
                # runoptions when it receives a PayloadModule, not a string.
                payload_mod = self.client.modules.use("payload", payload_name)
                # Set any payload-level options that the exploit module
                # didn't accept (LHOST, LPORT, LURI, etc.).
                for opt_name, opt_val in opts.items():
                    if opt_name not in module.options and opt_name in payload_mod.options:
                        coerced = _coerce(opt_name, opt_val, payload_mod)
                        payload_mod[opt_name] = coerced
                payload_arg = payload_mod

            # Optional explicit listener: over msfrpcd an exploit module's
            # *implicit* payload handler does NOT reliably bind a reverse/bind
            # listener, so the payload's callback reaches nothing and no
            # session is created.  A standalone 'exploit/multi/handler' job
            # DOES bind and persist.  When start_handler=True (and the caller
            # supplied PAYLOAD + LHOST + LPORT), start one now so there is a
            # live listener for the callback.  Not every module needs this
            # (auxiliaries, login scanners), so it is opt-in via the
            # start_handler parameter rather than automatic.
            handler_job = None
            if start_handler:
                if not payload_name:
                    return (
                        "start_handler=True requires a PAYLOAD in options (a "
                        "reverse/bind payload), but none was provided. Either "
                        "set PAYLOAD/LHOST/LPORT and retry, or set "
                        "start_handler=False if this module needs no listener."
                    )
                # Resolve LHOST/LPORT from options (case-sensitive key lookup;
                # MSF option names are uppercase by convention).
                lhost = opts.get("LHOST")
                lport = opts.get("LPORT")
                # Fall back to whatever the PayloadModule already has set.
                if not lhost and payload_arg is not None and "LHOST" in payload_arg.options:
                    lhost = payload_arg["LHOST"]
                if not lport and payload_arg is not None and "LPORT" in payload_arg.options:
                    lport = payload_arg["LPORT"]
                if not lhost or not lport:
                    return (
                        "start_handler=True requires LHOST and LPORT in options "
                        f"(got LHOST={lhost!r}, LPORT={lport!r}). LHOST must be an "
                        "IP the TARGET can route a connection back to. Set "
                        "PAYLOAD, LHOST, LPORT and retry."
                    )
                handler_job, _handler_err = await self._start_handler_job(
                    payload_name, lhost, lport
                )
                if handler_job is None:
                    return _handler_err

                # We are providing the listener ourselves, so the exploit
                # module must NOT start its own implicit handler — otherwise
                # both try to bind LHOST:LPORT and the exploit fails with
                # Rex::BindFailed ("address already in use").  DisablePayloadHandler
                # IS a regular datastore option on exploit modules, so it is
                # settable via __setitem__ (unlike ExitOnSession).
                if mtype == "exploit" and "DisablePayloadHandler" in module.options:
                    module["DisablePayloadHandler"] = True

            # CRITICAL: bypass pymetasploit3's module.execute() for exploit
            # modules with payloads.  execute() has two fatal bugs:
            #
            # 1. The DisablePayloadHandler `pass` branch (EternalBlue root
            #    cause): when DisablePayloadHandler=True is set (our line above
            #    for start_handler=True), execute() skips the PayloadModule
            #    merge entirely — PAYLOAD/LHOST/LPORT never reach MSF.
            #
            # 2. The AutoLoadExtensions non-scalar bug: when execute() DOES
            #    merge the PayloadModule (start_handler=False path), it copies
            #    payload.runoptions verbatim into the RPC call.  Meterpreter
            #    payloads have AutoLoadExtensions as a list/dict, and MSF
            #    rejects it with "Invalid module option value for
            #    AutoLoadExtensions: must be a scalar".
            #
            # Both bugs are avoided by calling the RPC directly: we build a
            # flat dict of string/scalar values (PAYLOAD as a string, LHOST /
            # LPORT as scalars) and pass it to c.call(ModuleExecute, ...).
            # MSF resolves the payload's own options itself — we never
            # serialize a PayloadModule.  This is exactly what msfconsole does
            # when you `set PAYLOAD ...` and it works every time.
            from pymetasploit3.msfrpc import MsfRpcMethod

            if mtype == "exploit" and payload_name:
                # Build the runopts from the module's datastore (RHOSTS, SSL,
                # etc. set above) plus PAYLOAD and payload-level options as
                # scalars.  Only copy scalar values — lists/dicts (like
                # AutoLoadExtensions) are left for MSF to resolve itself.
                runopts = dict(module.runoptions)
                runopts["PAYLOAD"] = payload_name
                runopts["TARGET"] = module.target
                for opt_name, opt_val in opts.items():
                    if opt_name not in module.options:
                        # Payload-level option (LHOST, LPORT, etc.) — pass as
                        # scalar if it's a simple type.
                        if isinstance(opt_val, (str, int, float, bool)):
                            runopts[opt_name] = opt_val
                result = self.client.call(
                    MsfRpcMethod.ModuleExecute,
                    [mtype, mname, runopts],
                )
            else:
                # Auxiliaries and payload-less exploits: the PayloadModule
                # bugs don't apply, so module.execute() is fine.
                result = module.execute()

            # module.execute() normally returns {'job_id': <int>, 'uuid': <str>}
            # from the MSF RPC 'module.execute' endpoint.  Three failure shapes
            # must be detected here and surfaced as a clear error instead of
            # being masked by the 30s session-poll below:
            #
            #   1. MSF refuses to launch (no/invalid PAYLOAD, missing required
            #      option, or DisablePayloadHandler on a module that needs its
            #      own handler):  {'job_id': None, 'uuid': None}.
            #   2. MSF rejects the option set outright (e.g. pymetasploit3
            #      serializing a meterpreter payload's AutoLoadExtensions as a
            #      non-scalar):  {'error': true, 'error_message': '...',
            #      'error_string': '...', 'error_code': 400}.
            #   3. Older pymetasploit3 that omits the key entirely, so the
            #      '.get(..., "?")' placeholder "?" slips through the None
            #      check below.
            launch_error_msg = None
            if isinstance(result, dict) and result.get("error"):
                launch_error_msg = (
                    result.get("error_message")
                    or result.get("error_string")
                    or str(result)
                )
                job_id = None
                run_uuid = result.get("uuid")
            elif isinstance(result, dict):
                job_id = result.get("job_id", result.get("jobID"))
                run_uuid = result.get("uuid")
            else:
                # Older MSF/pymetasploit3 may return a bare job id.
                job_id = result
                run_uuid = None

            # job_id is "missing" when it is None, or the "?" placeholder
            # (older client that returned no job_id/jobID key), or an empty
            # string.  Treat all of these as "MSF refused to launch".
            job_missing = (
                job_id is None
                or (isinstance(job_id, str) and not job_id.strip())
            )

            if launch_error_msg is not None or job_missing:
                # We may have started a separate handler expecting this module
                # to launch handler-less; if the module refused to launch
                # (e.g. a "manual" exploit like vsftpd_234_backdoor that REQUIRES
                # its own handler and rejects DisablePayloadHandler), stop the
                # handler we started so it isn't left orphaned on LHOST:LPORT.
                if handler_job is not None:
                    try:
                        self.client.jobs.stop(str(handler_job))
                    except Exception:
                        pass
                hint = ""
                if mtype == "exploit":
                    if not payload_name:
                        hint = (
                            " For an exploit module this usually means no PAYLOAD "
                            "was supplied — MSF needs a payload (and LHOST/LPORT for "
                            "reverse/bind payloads) to launch. Add PAYLOAD, LHOST, "
                            "LPORT to options and set start_handler=True."
                        )
                    elif start_handler:
                        hint = (
                            " A PAYLOAD was supplied and start_handler=True disabled "
                            "the module's own handler (DisablePayloadHandler), but MSF "
                            "refused to launch. Some 'manual' exploits (e.g. "
                            "vsftpd_234_backdoor) REQUIRE their own handler and reject "
                            "DisablePayloadHandler. Retry with start_handler=False and a "
                            "LHOST the TARGET can route a connection back to."
                        )
                    else:
                        hint = (
                            " A PAYLOAD was supplied but MSF still refused to launch "
                            "— verify the payload is compatible with this module/"
                            "target and that all required options (RHOSTS, etc.) are "
                            "set and correctly typed."
                        )
                if launch_error_msg is not None:
                    return (
                        f"MSF rejected the launch of '{module_path}': "
                        f"{launch_error_msg}. The module never ran, so no session "
                        f"can be created.{hint}"
                    )
                return (
                    f"MSF refused to launch module '{module_path}' (job_id=null, "
                    f"uuid={run_uuid}). The module never ran, so no session can be "
                    f"created.{hint}"
                )

            # Poll for new sessions.  ssh_login and similar auxiliaries take
            # a few seconds to connect and create a session; without this
            # loop the tool returns before the session exists.
            #
            # We also track TRANSIENT sessions — session IDs that appeared
            # briefly and then vanished before the next poll.  This happens
            # when a session is created but dies almost immediately (staged
            # payload staging failure, AV killing the payload process, etc.).
            # Without this tracking, the loop would simply never see the
            # session and report "No new sessions detected", hiding the real
            # failure from the caller.
            #
            # In the same loop we poll 'module.results' by uuid so we can
            # surface the module's own output (login results, scan findings,
            # check codes, run errors) as soon as the run finishes.  For
            # exploit handler jobs that stay alive (ExitOnSession=false) the
            # status never leaves "running", so those rely on the session
            # signal; scanners/ssh_login reach "completed" quickly and we
            # break as soon as they do.
            new_sessions = []
            transient_sessions = set()
            seen_once = set()  # session IDs we observed at least once
            module_result = None  # parsed module.results payload when finished
            deadline = _time.time() + MSF_SESSION_POLL_SECONDS
            while _time.time() < deadline:
                await asyncio.sleep(MSF_SESSION_POLL_INTERVAL)
                after = set(self.client.sessions.list.keys())
                current_new = after - before
                # Detect sessions that appeared since the last poll but are
                # already gone — they were transient.
                gone = seen_once - after
                transient_sessions |= gone
                seen_once |= current_new
                new_sessions = sorted(current_new, key=int)

                # Poll module.results by uuid.  Returns e.g.
                # {"status":"completed","result":...},
                # {"status":"running"}, or
                # {"status":"errored","error":...}.  MSF builds/versions
                # without a job_status_tracker answer with an error dict
                # (no "status" key); treat that as "no data yet".
                if run_uuid is not None and module_result is None:
                    try:
                        mr = self.client.jobs.info_by_uuid(run_uuid)
                    except Exception:
                        mr = None
                    if isinstance(mr, dict) and "status" in mr:
                        if mr["status"] in ("completed", "errored"):
                            module_result = mr

                if new_sessions or module_result is not None:
                    break

            # Render the module's own output (the "good info" that used to be
            # dropped).  Keep it bounded so a huge scan result doesn't blow
            # up the model's context window.
            results_blurb = ""
            if module_result is not None:
                status = module_result.get("status")
                if status == "errored":
                    results_blurb = (
                        "\nModule run errored: "
                        f"{module_result.get('error', '?')}"
                    )
                else:
                    rendered = _render_module_result(module_result.get("result"))
                    if rendered:
                        results_blurb = "\nModule output:\n" + rendered

            # Build a readable summary of any new sessions.  Emit TYPED
            # handles (Layer 1) so the caller cannot confuse an MSF numeric
            # session id with a paramiko "sess-NNNN" id — both are plausible-
            # looking arguments to the wrong tool.  The "msf:" prefix ties
            # the id to interact_session/close_msf_session unambiguously.
            session_summaries = []
            all_sessions = self.client.sessions.list
            for sid in new_sessions:
                info = all_sessions.get(sid, {})
                handle = format_handle("msf", str(sid))
                session_summaries.append(
                    f"  {handle}: type={info.get('type', '?')} "
                    f"target={info.get('target_host', '?')} "
                    f"desc={info.get('desc', '?')}"
                )

            if session_summaries:
                msg = (
                    f"Module {module_path} executed (job_id={job_id}). "
                    f"{len(new_sessions)} new session(s) created:\n"
                    + "\n".join(session_summaries)
                    + "\nUse interact_session with the msf: handle(s) above to run commands."
                )
                if transient_sessions:
                    msg += (
                        f"\n\n[!] WARNING: {len(transient_sessions)} additional "
                        f"session(s) were created but died immediately (IDs: "
                        f"{sorted(transient_sessions, key=int)}). This usually "
                        "means the staged payload's handler exited before the "
                        "stage transfer completed (ExitOnSession was true), or "
                        "the payload process was killed on the target (AV/EDR)."
                    )
                return msg + results_blurb
            elif transient_sessions:
                return (
                    f"Module {module_path} executed (job_id={job_id}). "
                    f"{len(transient_sessions)} session(s) were created but "
                    f"closed immediately (IDs: {sorted(transient_sessions, key=int)}). "
                    "The payload likely connected back but the session died "
                    "before stabilizing. Common causes:\n"
                    "  - Handler exited before staging completed (ExitOnSession)\n"
                    "  - AV/EDR killed the payload process on the target\n"
                    "  - Architecture/platform mismatch in the payload\n"
                    "  - Network instability dropping the reverse connection\n"
                    "Check the msfconsole log for details. Consider a stageless "
                    "payload or verify the payload architecture matches the target."
                    + results_blurb
                )
            else:
                return (
                    f"Module {module_path} executed (job_id={job_id}). "
                    f"No new sessions detected within {MSF_SESSION_POLL_SECONDS:.0f}s. "
                    "The module may still be running; call list_sessions to check later."
                    + results_blurb
                )
        except Exception as e:
            print(f"An error occurred while executing the module: {e}")
            return None

    @framework_tool(
        "Configure a Metasploit payload (e.g. cmd/unix/reverse, "
        "windows/meterpreter/reverse_tcp) with options like LHOST and LPORT. "
        "Use this to set up the payload before executing an exploit module."
    )
    async def set_payload(self, payload_name: str, options: Dict[str, Any]):
        """
        Configure a Metasploit payload with specified options.

        In the RPC model there is no global console 'set PAYLOAD' command;
        instead we load the payload module and apply options to it.  The
        configured payload can then be referenced by an exploit module via
        its PAYLOAD option (see dispatch_metasploit).
        """
        if not await self._ensure_running():
            return None

        try:
            # Load the payload module via RPC so we can set options on it.
            # payload_name is expected as a path like 'cmd/unix/reverse_python'.
            module = self.client.modules.use("payload", payload_name)
            for option, value in options.items():
                module[option] = value
            return f"Payload '{payload_name}' configured with options: {options}\nAvailable options: {module.options}"
        except Exception as e:
            print(f"An error occurred while setting the payload: {e}")
            return None

    @framework_tool(
        "Show the available options and required parameters for a specific "
        "Metasploit module (e.g. RHOSTS, USERNAME, PAYLOAD, LHOST). Use this "
        "before executing a module to see what needs to be set."
    )
    async def get_options(self, module_path: str):
        """
        Retrieve the options for a given Metasploit module.
        """
        if not await self._ensure_running():
            return None

        try:
            # pymetasploit3 ModuleManager has use(mtype, mname), not load().
            parts = module_path.split("/", 1)
            if len(parts) != 2:
                return f"Invalid module_path '{module_path}'. Expected 'type/name', e.g. 'auxiliary/scanner/ssh/ssh_login'."
            mtype, mname = parts[0], parts[1]
            module = self.client.modules.use(mtype, mname)
            options = module.options
            return str(options)
        except Exception as e:
            print(f"An error occurred while retrieving options: {e}")
            return None

    @framework_tool(
        "Run a command on an active Metasploit session (shell or meterpreter). "
        "Use this after dispatch_metasploit creates a session to run commands like "
        "'id', 'whoami', 'cat /etc/shadow' on the compromised target. Pass the "
        "'msf:' handle returned by dispatch_metasploit (e.g. 'msf:1'). The session "
        "stays alive for follow-up commands.",
        accepted_handle_kinds=["msf"],
        untrusted_target=True,
    )
    async def interact_session(self, handle: str, command: str):
        """
        Send a command to a specific active Metasploit session and read the
        response.  Works with both shell and meterpreter sessions.

        The session stays alive in MSF after this call returns, so you can
        call interact_session again with the same handle for follow-up
        commands.

        For shell sessions, an exit-code marker is appended after the command
        so the caller can tell whether a command that produced no stdout (like
        'touch', 'mkdir', 'cp') actually succeeded.  The return string always
        includes an explicit success/failure indicator.

        Args:
            handle: The 'msf:' handle returned by dispatch_metasploit (e.g. 'msf:1').
            command: The command to execute within the session.
        """
        if not await self._ensure_running():
            return None

        try:
            kind, sid = parse_handle(handle)
            sessions = self.client.sessions.list
            if sid not in sessions:
                return f"MSF session {handle} not found. Call list_sessions to see active sessions."

            session = self.client.sessions.session(sid)
            session_type = sessions[sid].get("type", "")

            # --- Shell sessions: append an exit-code sentinel ---
            # A bare 'touch /tmp/foo' produces no stdout — read() returns just
            # the next prompt, which the LLM cannot interpret as success or
            # failure.  By echoing a unique sentinel with the exit code, we
            # can parse a definitive result regardless of stdout volume.
            if "shell" in session_type:
                sentinel = "__CMD_EXIT_CODE__"
                full_cmd = f"{command}; echo {sentinel}_$?_"
                session.write(full_cmd)
                await asyncio.sleep(2.0)

                output = session.read()
                if isinstance(output, bytes):
                    output = output.decode("utf-8", errors="replace")

                # Drain any remaining output (slow shells may still be writing).
                if sentinel not in output:
                    await asyncio.sleep(1.5)
                    more = session.read()
                    if isinstance(more, bytes):
                        more = more.decode("utf-8", errors="replace")
                    output += more

                # Parse the exit code sentinel: __CMD_EXIT_CODE___0_
                exit_code = None
                clean_output = output
                import re as _re
                m = _re.search(r"__CMD_EXIT_CODE__(?:_)?(\d+)(?:_)?", output)
                if m:
                    exit_code = int(m.group(1))
                    # Strip the sentinel and everything after it from the
                    # displayed output so the model sees only the command's
                    # actual stdout.
                    clean_output = output[:m.start()].strip()

                # Also strip a leading echo of the sentinel command if the
                # shell echoed it back (common in raw shells).
                if full_cmd in clean_output:
                    clean_output = clean_output.replace(full_cmd, "").strip()
                # Strip leading prompt artifacts.
                for prompt_char in ("$", "#", ">"):
                    if clean_output.startswith(prompt_char):
                        clean_output = clean_output[1:].lstrip()

                if exit_code is not None and exit_code == 0:
                    if clean_output:
                        return f"[SUCCESS exit=0] {clean_output}"
                    return f"[SUCCESS exit=0] Command completed with no stdout output (normal for touch/mkdir/cp/etc)."
                elif exit_code is not None:
                    return f"[FAILED exit={exit_code}] {clean_output or '(no stdout)'}"
                else:
                    # Sentinel not found — the command may still be running or
                    # the shell is unresponsive.  Return what we have.
                    return f"[UNKNOWN] Raw output: {output!r}"
            else:
                # --- Meterpreter sessions: use write/read directly ---
                session.write(command)
                await asyncio.sleep(2.0)

                output = session.read()
                if isinstance(output, bytes):
                    output = output.decode("utf-8", errors="replace")

                if not output or not output.strip():
                    await asyncio.sleep(2.0)
                    output = session.read()
                    if isinstance(output, bytes):
                        output = output.decode("utf-8", errors="replace")

                if output and output.strip():
                    return f"[OUTPUT] {output.strip()}"
                return f"[NO OUTPUT] Command sent to meterpreter session {handle}; no stdout returned (may be normal for this command type)."
        except Exception as e:
            print(f"An error occurred while interacting with session {handle}: {e}")
            return f"MSF session interaction error: {e}"

    @framework_tool(
        "Close and kill a specific Metasploit session. Pass the 'msf:' handle "
        "returned by dispatch_metasploit. Use this to clean up after exploitation "
        "when the session is no longer needed.",
        accepted_handle_kinds=["msf"],
    )
    async def close_msf_session(self, handle: str):
        """
        Kill and remove a Metasploit session.

        Args:
            handle: The 'msf:' handle of the MSF session to close (e.g. 'msf:1').
        """
        if not await self._ensure_running():
            return None

        try:
            kind, sid = parse_handle(handle)
            sessions = self.client.sessions.list
            if sid not in sessions:
                return f"MSF session {handle} not found."

            session = self.client.sessions.session(sid)
            # Both session types inherit stop() from MsfSession.
            session.stop()
            return f"MSF session {handle} closed."
        except Exception as e:
            print(f"An error occurred while closing session {handle}: {e}")
            return f"MSF session close error: {e}"
