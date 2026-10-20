"""Short-alias derivation for discovered tools.

Per-tool ``async def`` wrappers land in the IPython/kernel namespace under a
short, ergonomic alias instead of the full dotted ``module_id`` (tool ids
are quoted strings, so Jedi has nothing to index). Curated aliases win;
everything else is derived and collisions are resolved deterministically.

``scripts/gen_repl_stubs.py`` consumes ``build_tool_aliases`` **verbatim**
("reimplementing alias logic here would guarantee drift") — a rename in
this module must keep that script generating the same map. The curated
table is keyed by full ``module_id`` so a rename in the source tree breaks
loudly here, not silently at the keyboard.
"""

from typing import Dict, List

from daharness.models import ToolManifest

# Prefixes stripped during auto-derivation of short aliases.
_ALIAS_STRIP_PREFIXES = ("run_", "check_", "exec_", "do_", "perform_")
# Suffixes stripped during auto-derivation.
_ALIAS_STRIP_SUFFIXES = ("_tool",)


def _derive_alias(module_id: str) -> str:
    """Derive a short alias from a ``module_id`` when no curated one exists.

    Strategy: take the last dotted segment, strip common verb prefixes and
    ``_tool`` suffixes, and if it's a method on a class (``Class.method``),
    prefer the method name alone — unless it's generic (``run``, ``check``,
    ``list``), in which case prefix with a snake-cased class name.

    Collisions are *not* resolved here — the caller collects all aliases and
    de-duplicates by appending a module qualifier when two tools claim the
    same short name.
    """
    parts = module_id.split(".")
    last = parts[-1]

    # Strip common prefixes
    for pfx in _ALIAS_STRIP_PREFIXES:
        if last.startswith(pfx):
            last = last[len(pfx):]
            break
    # Strip common suffixes
    for sfx in _ALIAS_STRIP_SUFFIXES:
        if last.endswith(sfx):
            last = last[: -len(sfx)]
            break

    # If the last segment is too generic and there's a class name before it,
    # qualify with the class.
    if last.lower() in ("run", "check", "list", "exec", "scan", "status", "info") and len(parts) >= 3:
        cls_seg = parts[-2]
        last = f"{cls_seg.lower()}_{last}"

    return last


def build_tool_aliases(manifests: List[ToolManifest]) -> Dict[str, ToolManifest]:
    """Return ``{alias: manifest}`` for all discovered tools.

    Curated aliases from ``_TOOL_ALIASES`` win.  Unmatched tools get
    auto-derived aliases.  Collisions are resolved by appending the
    top-level module name (``auxiliaries``, ``payloads``, etc.) as a
    prefix — if that *also* collides, append a numeric suffix.
    """
    result: Dict[str, ToolManifest] = {}
    # First pass: curated aliases (explicit, may collide → resolved later)
    pending: List[tuple] = []  # (alias, manifest)
    for m in manifests:
        curated = _TOOL_ALIASES.get(m.module_id)
        if curated:
            pending.append((curated, m))
        else:
            pending.append((_derive_alias(m.module_id), m))

    for alias, m in pending:
        if alias not in result:
            result[alias] = m
            continue
        # Collision — prefix with the top-level module segment
        top = m.module_id.split(".")[0]
        qualified = f"{top}_{alias}"
        if qualified not in result:
            result[qualified] = m
            continue
        # Still colliding — numeric suffix
        i = 2
        while f"{qualified}_{i}" in result:
            i += 1
        result[f"{qualified}_{i}"] = m
    return result


# Curated short aliases for the most-used tools.  Keyed by the full
# ``module_id`` (so a rename in the source tree breaks loudly here, not
# silently at the keyboard).  Tools not in this map fall through to
# auto-derivation via _derive_alias().
_TOOL_ALIASES: Dict[str, str] = {
    # auxiliaries/
    "auxiliaries.nmap.run_nmap": "nmap",
    "auxiliaries.masscan.run_masscan": "masscan",
    "auxiliaries.ffuf_tools.run_ffuf": "ffuf",
    "auxiliaries.smb_scanner.check_null_session": "smb_null",
    "auxiliaries.smb_scanner.run_smb_recon": "smb_recon",
    "auxiliaries.ftp_recon.run_ftp_recon": "ftp_recon",
    "auxiliaries.dns_lookup.run_dns_lookup": "dns_lookup",
    "auxiliaries.tls_info.run_tls_info": "tls_info",
    "auxiliaries.cors_probe.run_cors_probe": "cors_probe",
    "auxiliaries.ssrf_probe.run_ssrf_probe": "ssrf_probe",
    "auxiliaries.web_probe.run_web_probe": "web_probe",
    "auxiliaries.web_login_brute.run_web_login_brute": "web_brute",
    "auxiliaries.ldap_search.ldap_rootdse": "ldap_rootdse",
    "auxiliaries.ldap_search.ldap_search": "ldap_search",
    "auxiliaries.ssh_exec.run_ssh_exec": "ssh_exec",
    "auxiliaries.impacket_suite.secretsdump": "secretsdump",
    "auxiliaries.impacket_suite.psexec_exec": "psexec",
    "auxiliaries.impacket_suite.wmiexec_exec": "wmiexec",
    "auxiliaries.impacket_suite.atexec_exec": "atexec",
    "auxiliaries.impacket_suite.smb_enum_shares": "smb_enum_shares",
    "auxiliaries.impacket_suite.smb_read_file": "smb_read_file",
    "auxiliaries.amass.run_amass": "amass",
    "auxiliaries.archived_urls.run_archived_urls": "archived_urls",
    "auxiliaries.cert_tools.run_cert_tools": "cert_tools",
    "auxiliaries.radare2.run_radare2": "radare2",
    "auxiliaries.jadx.run_jadx": "jadx",
    "auxiliaries.playwright_recon.run_playwright_recon": "pw_recon",
    "auxiliaries.playwright_sidecar.run_playwright_sidecar": "pw_sidecar",
    "auxiliaries.burp_mcp.run_burp_mcp": "burp_mcp",
    "auxiliaries.zap.run_zap": "zap",
    "auxiliaries.framework_status.run_framework_status": "framework_status",
    "auxiliaries.program_scope.search_programs": "scope_search_programs",
    # payloads/
    "payloads.ffuf.run_ffuf": "ffuf_payload",
    "payloads.hydra.run_hydra": "hydra",
    "payloads.sqlmap.run_sqlmap": "sqlmap",
    "payloads.hash_crack.run_hash_crack": "hash_crack",
    "payloads.searchsploiting.search_exploit": "searchsploit",
    "payloads.js_recon.run_js_recon": "js_recon",
    "payloads.wordlists.run_wordlists": "wordlists",
    "payloads.metasploiting.MetasploitClient.index_modules": "msf_index",
    "payloads.metasploiting.MetasploitClient.dispatch_metasploit": "msf_dispatch",
    "payloads.metasploiting.MetasploitClient.get_options": "msf_options",
    "payloads.metasploiting.MetasploitClient.set_payload": "msf_set_payload",
    "payloads.metasploiting.MetasploitClient.list_sessions": "msf_sessions",
    "payloads.metasploiting.MetasploitClient.interact_session": "msf_interact",
    "payloads.metasploiting.MetasploitClient.close_msf_session": "msf_close",
    "payloads.msfvenom_tools.generate_payload": "msfvenom",
    "payloads.msfvenom_tools.msfvenom_menu": "msfvenom_menu",
    "payloads.msfvenom_tools.list_dropbox": "list_dropbox",
    "payloads.fastcgi.run_fastcgi": "fastcgi",
    # listeners/
    "listeners.listening.TCPListener.open_listener": "listen_tcp",
    "listeners.listening.TCPListener.close_listener": "close_listener",
    "listeners.listening.TCPListener.send_to_brain": "send_to_brain",
    "listeners.raw_scan.syn_scan": "syn_scan",
    "listeners.collaborator.run_collaborator": "collaborator",
    "listeners.execution_tracker.run_execution_tracker": "execution_tracker",
    "listeners.brain_control.run_brain_control": "brain_control",
    # utils/
    "utils.memory_tools.remember_text": "remember_text",
    "utils.memory_tools.search_text": "mem_search",
    "utils.memory_tools.recall_text": "recall_text",
    "utils.memory_tools.get_text": "mem_get",
    "utils.memory_tools.forget_text": "mem_forget",
    "utils.session_manager.list_sessions": "list_sessions",
    "utils.cookie_jar.jar_state": "jar_state",
    "utils.cookie_jar.jar_store_cookie": "jar_store_cookie",
    "utils.cookie_jar.jar_store_token": "jar_store_token",
    "utils.cookie_jar.jar_clear": "jar_clear",
    "utils.cookie_jar.jar_cookie_header": "jar_cookie_header",
    "auxiliaries.web_session.session_get": "session_get",
    "auxiliaries.web_session.session_post": "session_post",
    "auxiliaries.web_session.session_request": "session_request",
    "auxiliaries.web_session.session_upload": "session_upload",
    "utils.findings.report_finding": "report_finding",
    "utils.findings.list_findings": "list_findings",
    "utils.log_reader.read_logs": "read_logs",
}


def curated_alias_name(module_id: str) -> str:
    """The curated (or derived) alias name for a tool — used by the wrapper
    factory so ``__name__`` matches what the namespace actually binds."""
    return _TOOL_ALIASES.get(module_id) or _derive_alias(module_id)