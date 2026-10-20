"""Tool category taxonomy + the bulk tag map (semantic-search viability).

154 registry tools is past the point where every tool surfaces for every
reasonable phrasing.  Category tags fix discoverability: a tool's tags are
appended to its embedded capability text (``...\\n\\nCategories: web.fuzz``)
so a search that uses category language ("recon", "fuzz", "brute", "packet")
matches the tagged tools even when the tool's own prose never used that word.

DESIGN (three small pieces, no find_tools changes):

1. ``CANONICAL_TAGS`` — the frozen 13-bucket vocabulary the operator defined:
   recon.subdomain, recon.web, recon.dns-certs, recon.scope, web.fuzz,
   web.probe, web.auth, exploit.web, exploit.msf, brute.crack, net.raw,
   net.services, infra.
   ("infra" = main framework tooling and internals; "net.services" = non-HTTP
   network-service tooling — SSH/SMB/FTP access, remote exec, secrets dump,
   callback listeners.)  Extending it is a one-tuple edit here; discovery
   WARNS on non-canonical tags but keeps them (warn-and-keep: a typo never
   silently kills a tag's discoverability, and the operator sees the warning
   in the bootstrap/reindex log).

2. ``TOOL_TAGS`` — the bulk assignment for EXISTING tools, keyed by exact
   registry tool_id (module.function / module.Class.method).  One reviewable
   table instead of a 154-call-site diff across ~30 modules.  Deliberately
   UNTAGGED tools (fit is genuinely ambiguous — see PENDING below) are absent:
   absence degrades to today's behaviour, a wrong tag would mislead.

3. ``@framework_tool(..., tags=[...])`` (constants.py) — per-tool override for
   FUTURE tools; the decorator wins over the map so an inline tag can never be
   shadowed by a stale map row.

Embedding: ``tagged_doc`` appends ``"\\n\\nCategories: <csv>"`` to the tool doc.
Because the doc IS the embedded text (``internal_semantic_capability``), a tag
change alters the doc -> ``register_tool``'s change-detection re-embeds it on
the next ``python -m daharness.core`` with no extra logic.  Tags also persist
in ChromaDB metadata (``tags_json``) and surface in ``describe_manifest`` so
the secretary sees the category next to every search hit.

OPERATOR DECISION 2026-09-22 — 13th bucket ``net.services`` ADDED as the
landing zone for non-HTTP network-service tooling: SSH/FTP/SFTP access,
impacket (SMB enum/read + secretsdump + psexec/wmiexec/atexec exec), SMB
null-session recon, reverse-shell listeners — and, going forward, the default
category for tool-nursery candidates from model suggestions during lab runs
(a model proposing a new service-shaped tool: tag it ``net.services`` at
authoring).  All 27 formerly-pending tools are tagged ``net.services`` (see
the map section below; pinned by tests/test_tool_tags.py NET_SERVICES_IDS).
Line kept deliberate: port SCANNERS (nmap/masscan/syn_scan) stay ``net.raw``
(scan lane) — ``net.services`` is for INTERACTING with a discovered service.
  (utils.paramiko_client.list_sessions and TCPListener.send_to_brain ARE
  tagged infra: framework control-plane, not target-facing.)
Judgment-call interims (tagged, but operator may disagree — one-line edits):
  nmap/masscan -> net.raw (scan lane; could move to net.services if the
  operator prefers a scan/interact split there); radare2/jadx ->
  infra (static artifact analysis, framework tooling); zap_active_scan ->
  exploit.web (web.fuzz alternative); zap_alerts/zap_alert_message ->
  recon.web; zap_report/zap_sync_scope -> infra; search_exploit -> exploit.msf
  (ExploitDB research feeding the msf lane); scan_ssrf -> web.probe.
  Optional secondary still open (not adopted): secretsdump +brute.crack.
"""

from typing import Dict, Iterable, Optional, Tuple

CANONICAL_TAGS: Tuple[str, ...] = (
    "recon.subdomain",
    "recon.web",
    "recon.dns-certs",
    "recon.scope",
    "web.fuzz",
    "web.probe",
    "web.auth",
    "exploit.web",
    "exploit.msf",
    "brute.crack",
    "net.raw",
    "net.services",
    "infra",
)


# --- Bulk tag map -----------------------------------------------------------
# Keys MUST be exact registry tool_ids (mirrors discover_local_tools id
# construction: module.function or module.Class.method).  Values are tuples of
# canonical categories (multi-tagging allowed when a tool genuinely straddles).
# Absence = untagged (deliberate for the PENDING set above).
TOOL_TAGS: Dict[str, Tuple[str, ...]] = {
    # --- recon.subdomain ---------------------------------------------------
    "auxiliaries.amass.run_amass": ("recon.subdomain",),
    "auxiliaries.amass.amass_status": ("recon.subdomain",),
    "auxiliaries.amass.subdomain_enum": ("recon.subdomain",),
    "auxiliaries.amass.subdomain_enum_status": ("recon.subdomain",),
    # --- recon.web (+ subdomain secondary where CDX lists subdomains) ------
    "auxiliaries.archived_urls.archived_urls": ("recon.web", "recon.subdomain"),
    "auxiliaries.playwright_recon.playwright_fetch": ("recon.web",),
    "auxiliaries.playwright_recon.playwright_crawl": ("recon.web",),
    "auxiliaries.playwright_recon.playwright_crawl_status": ("recon.web",),
    "auxiliaries.playwright_recon.playwright_crawl_stop": ("recon.web",),
    "payloads.js_recon.extract_js_routes": ("recon.web",),
    "auxiliaries.web_probe.probe_web": ("recon.web", "web.probe"),
    "auxiliaries.zap.zap_spider": ("recon.web",),
    "auxiliaries.zap.zap_spider_status": ("recon.web",),
    "auxiliaries.zap.zap_ajax_spider": ("recon.web",),
    "auxiliaries.zap.zap_ajax_spider_status": ("recon.web",),
    "auxiliaries.zap.zap_alerts": ("recon.web",),
    "auxiliaries.zap.zap_alert_message": ("recon.web",),
    "auxiliaries.zap.zap_history_regex": ("recon.web",),
    "auxiliaries.zap.zap_sites": ("recon.web",),
    "auxiliaries.zap.zap_sites_tree": ("recon.web",),
    # --- recon.dns-certs ----------------------------------------------------
    "auxiliaries.dns_lookup.resolve_host": ("recon.dns-certs", "recon.scope"),
    "auxiliaries.dns_lookup.ptr_lookup": ("recon.dns-certs",),
    "auxiliaries.tls_info.tls_info": ("recon.dns-certs",),
    "auxiliaries.cert_tools.inspect_host": ("recon.dns-certs",),
    "auxiliaries.cert_tools.inspect_pem": ("recon.dns-certs",),
    # --- recon.scope ---------------------------------------------------------
    "auxiliaries.program_scope.load_program_scope": ("recon.scope",),
    "auxiliaries.program_scope.search_programs": ("recon.scope",),
    "auxiliaries.program_scope.check_scope": ("recon.scope",),
    "auxiliaries.program_scope.check_reportable": ("recon.scope",),
    "auxiliaries.program_scope.program_hacktivity": ("recon.scope",),
    # --- web.fuzz ------------------------------------------------------------
    "payloads.ffuf.run_ffuf": ("web.fuzz",),
    "payloads.ffuf.ffuf_status": ("web.fuzz",),
    "payloads.ffuf.ffuf_cancel": ("web.fuzz",),
    # --- web.probe -------------------------------------------------------------
    "auxiliaries.cors_probe.check_cors": ("web.probe",),
    "auxiliaries.cors_probe.check_security_headers": ("web.probe",),
    "auxiliaries.ssrf_probe.scan_ssrf": ("web.probe",),
    "auxiliaries.zap.zap_open_url": ("web.probe",),
    "auxiliaries.zap.zap_send_raw": ("web.probe",),
    # --- web.auth (+ brute.crack where it is genuinely a brute) ---------------
    "auxiliaries.web_login_brute.web_login_probe": ("web.auth",),
    "auxiliaries.web_login_brute.web_login_test": ("web.auth",),
    "auxiliaries.web_login_brute.web_login_brute": ("web.auth", "brute.crack"),
    "utils.crypto_kit.jwt_decode": ("web.auth", "brute.crack"),
    "auxiliaries.web_session.session_get": ("web.auth", "web.probe"),
    "auxiliaries.web_session.session_post": ("web.auth", "web.probe"),
    "auxiliaries.web_session.session_request": ("web.auth", "web.probe"),
    # --- exploit.web -----------------------------------------------------------
    "payloads.sqlmap.run_sqlmap": ("exploit.web",),
    "payloads.sqlmap.sqlmap_status": ("exploit.web",),
    "payloads.fastcgi.fastcgi_request": ("exploit.web",),
    "payloads.fastcgi.fastcgi_php_exec": ("exploit.web",),
    "auxiliaries.zap.zap_active_scan": ("exploit.web",),
    "auxiliaries.zap.zap_active_scan_status": ("exploit.web",),
    # --- exploit.msf -----------------------------------------------------------
    "payloads.metasploiting.MetasploitClient.index_modules": ("exploit.msf",),
    "payloads.metasploiting.MetasploitClient.dispatch_metasploit": ("exploit.msf",),
    "payloads.metasploiting.MetasploitClient.set_payload": ("exploit.msf",),
    "payloads.metasploiting.MetasploitClient.get_options": ("exploit.msf",),
    "payloads.metasploiting.MetasploitClient.interact_session": ("exploit.msf",),
    "payloads.metasploiting.MetasploitClient.close_msf_session": ("exploit.msf",),
    "payloads.searchsploiting.search_exploit": ("exploit.msf",),
    # --- brute.crack -----------------------------------------------------------
    "payloads.hash_crack.suggest_crack_mode": ("brute.crack",),
    "payloads.hash_crack.run_john": ("brute.crack",),
    "payloads.hash_crack.john_status": ("brute.crack",),
    "payloads.hash_crack.john_show": ("brute.crack",),
    "payloads.hash_crack.run_hashcat": ("brute.crack",),
    "payloads.hash_crack.hashcat_status": ("brute.crack",),
    "payloads.hash_crack.hashcat_show": ("brute.crack",),
    "payloads.hydra.run_hydra": ("brute.crack",),
    "payloads.hydra.hydra_status": ("brute.crack",),
    "payloads.hydra.hydra_cancel": ("brute.crack",),
    "utils.crypto_kit.decode_blob": ("brute.crack",),
    "utils.crypto_kit.identify_hash": ("brute.crack",),
    "utils.crypto_kit.check_hash_wordlist": ("brute.crack",),
    "utils.crypto_kit.xor_brute": ("brute.crack",),
    "utils.crypto_kit.rot_brute": ("brute.crack",),
    "utils.crypto_kit.rsa_decrypt": ("brute.crack",),
    # --- net.raw (raw sockets / packet lane + port scanners, interim) ---------
    "utils.packetcraft.craft_icmp_echo": ("net.raw",),
    "utils.packetcraft.craft_icmp_packet": ("net.raw",),
    "utils.packetcraft.craft_tcp_packet": ("net.raw",),
    "utils.packetcraft.craft_udp_packet": ("net.raw",),
    "utils.packetcraft.craft_arp_request": ("net.raw",),
    "utils.packetcraft.craft_arp_packet": ("net.raw",),
    "utils.packetcraft.craft_vlan_frame": ("net.raw",),
    "utils.packetcraft.craft_dhcp_discover": ("net.raw",),
    "utils.packetcraft.craft_dns_query": ("net.raw",),
    "utils.packetcraft.craft_dns_response": ("net.raw",),
    "utils.packetcraft.craft_dns_response_multi": ("net.raw",),
    "utils.packetcraft.craft_mdns_query": ("net.raw",),
    "utils.packetcraft.craft_http_request": ("net.raw",),
    "utils.packetcraft.craft_http_response": ("net.raw",),
    "utils.packetcraft.send_packet": ("net.raw",),
    "utils.packetcraft.send_and_receive_packet": ("net.raw",),
    "utils.packetcraft.sniff_packets": ("net.raw",),
    "utils.packetcraft.dissect_packet": ("net.raw",),
    "utils.packetcraft.modify_packet": ("net.raw",),
    "utils.packetcraft.export_packet_hex": ("net.raw",),
    "utils.packetcraft.save_packet": ("net.raw",),
    "utils.packetcraft.load_packet": ("net.raw",),
    "utils.packetcraft.save_pcap": ("net.raw",),
    "utils.packetcraft.load_pcap": ("net.raw",),
    "utils.packetcraft.sniff_to_pcap": ("net.raw",),
    "utils.packetcraft.list_pcaps": ("net.raw",),
    "utils.packetcraft.wait_for_packet": ("net.raw",),
    "listeners.raw_scan.syn_scan": ("net.raw",),
    "auxiliaries.nmap.run_nmap": ("net.raw",),
    "auxiliaries.nmap.nmap_status": ("net.raw",),
    "auxiliaries.nmap.nmap_scripts": ("net.raw",),
    "auxiliaries.masscan.run_masscan": ("net.raw",),
    "auxiliaries.masscan.masscan_status": ("net.raw",),
    "auxiliaries.masscan.masscan_cancel": ("net.raw",),
    # --- Burp Suite MCP integration (precision web testing via BApp) ---------
    # Burp complements ZAP: ZAP is the autonomous spider/scan workhorse;
    # Burp is the precision instrument for crafted requests, history grep,
    # and Repeater/Intruder hand-off.  No active scan via MCP (use ZAP).
    "auxiliaries.burp_mcp.burp_send_http1_request": ("web.probe",),
    "auxiliaries.burp_mcp.burp_send_http2_request": ("web.probe",),
    "auxiliaries.burp_mcp.burp_send_raw": ("web.probe",),
    "auxiliaries.burp_mcp.burp_get_proxy_history": ("recon.web",),
    "auxiliaries.burp_mcp.burp_get_proxy_history_regex": ("recon.web",),
    "auxiliaries.burp_mcp.burp_get_proxy_websocket_history": ("recon.web",),
    "auxiliaries.burp_mcp.burp_get_proxy_websocket_history_regex": ("recon.web",),
    "auxiliaries.burp_mcp.burp_create_repeater_tab": ("web.probe",),
    "auxiliaries.burp_mcp.burp_create_repeater_tab_http2": ("web.probe",),
    "auxiliaries.burp_mcp.burp_send_to_intruder": ("web.fuzz",),
    # infra (framework tooling + internals) ---------------------------------
    "auxiliaries.burp_mcp.burp_set_proxy_intercept": ("infra",),
    "auxiliaries.burp_mcp.burp_set_task_engine_state": ("infra",),
    "auxiliaries.burp_mcp.burp_url_encode": ("infra",),
    "auxiliaries.burp_mcp.burp_url_decode": ("infra",),
    "auxiliaries.burp_mcp.burp_base64_encode": ("infra",),
    "auxiliaries.burp_mcp.burp_base64_decode": ("infra",),
    "auxiliaries.burp_mcp.burp_output_project_options": ("infra",),
    "auxiliaries.burp_mcp.burp_output_user_options": ("infra",),
    "auxiliaries.burp_mcp.burp_list_tools": ("infra",),
    "auxiliaries.burp_mcp.burp_reconnect": ("infra",),
    "auxiliaries.burp_mcp.burp_health": ("infra",),
    # --- infra (framework tooling + internals) ---------------------------------
    "auxiliaries.framework_status.framework_health": ("infra",),
    "auxiliaries.framework_status.framework_doctor": ("infra",),
    "auxiliaries.cert_tools.generate_certs": ("infra",),
    "auxiliaries.cert_tools.clear_certs": ("infra",),
    "auxiliaries.radare2.run_r2": ("infra",),
    "auxiliaries.radare2.list_r2_targets": ("infra",),
    "auxiliaries.jadx.list_apk_targets": ("infra",),
    "auxiliaries.jadx.run_jadx": ("infra",),
    "payloads.wordlists.list_wordlists": ("infra",),
    "listeners.brain_control.list_tool_executions": ("infra",),
    "listeners.brain_control.kill_tool_execution": ("infra",),
    "listeners.collaborator.collab_start": ("infra",),
    "listeners.collaborator.collab_generate": ("infra",),
    "listeners.collaborator.collab_poll": ("infra",),
    "listeners.collaborator.collab_stop": ("infra",),
    "listeners.listening.TCPListener.send_to_brain": ("infra",),
    "utils.findings.report_finding": ("infra",),
    "utils.findings.render_findings": ("infra",),
    "utils.findings.close_finding": ("infra",),
    "utils.findings.supersede_finding": ("infra",),
    "utils.findings.record_unknown": ("infra",),
    "utils.findings.list_unknowns": ("infra",),
    "utils.findings.resolve_unknown": ("infra",),
    "utils.log_reader.read_logs": ("infra",),
    "utils.memory_tools.remember_text": ("infra",),
    "utils.memory_tools.recall_text": ("infra",),
    "utils.memory_tools.list_text_namespaces": ("infra",),
    "utils.cookie_jar.jar_state": ("infra",),
    "utils.cookie_jar.jar_store_cookie": ("infra",),
    "utils.cookie_jar.jar_store_token": ("infra",),
    "utils.cookie_jar.jar_clear": ("infra",),
    "utils.cookie_jar.jar_cookie_header": ("infra",),
    "utils.paramiko_client.list_sessions": ("infra",),
    "auxiliaries.zap.zap_report": ("infra",),
    "auxiliaries.zap.zap_sync_scope": ("infra",),
    # --- net.services (non-HTTP service interaction; operator-added 09/22) ---
    "auxiliaries.ssh_exec.ssh_exec_batch": ("net.services",),
    "utils.paramiko_client.ssh_connect": ("net.services",),
    "utils.paramiko_client.ssh_exec": ("net.services",),
    "utils.paramiko_client.ssh_shell": ("net.services",),
    "utils.paramiko_client.ssh_close": ("net.services",),
    "utils.paramiko_client.paramiko_client": ("net.services",),
    "auxiliaries.impacket_suite.smb_enum_shares": ("net.services",),
    "auxiliaries.impacket_suite.smb_read_file": ("net.services",),
    "auxiliaries.impacket_suite.secretsdump": ("net.services",),
    "auxiliaries.impacket_suite.psexec_exec": ("net.services",),
    "auxiliaries.impacket_suite.wmiexec_exec": ("net.services",),
    "auxiliaries.impacket_suite.atexec_exec": ("net.services",),
    "auxiliaries.impacket_suite.kerberoast": ("net.services",),
    "auxiliaries.impacket_suite.request_tgs": ("net.services",),
    "auxiliaries.ldap_search.ldap_search": ("net.services",),
    "auxiliaries.ldap_search.ldap_rootdse": ("net.services",),
    "auxiliaries.smb_scanner.SMBScanner.check_null_session": ("net.services",),
    "auxiliaries.smb_scanner.run_smb_recon": ("net.services",),
    "auxiliaries.ftp_recon.ftp_banner": ("net.services",),
    "auxiliaries.ftp_recon.ftp_anon_check": ("net.services",),
    "auxiliaries.ftp_recon.ftp_list": ("net.services",),
    "auxiliaries.ftp_recon.ftp_get": ("net.services",),
    "auxiliaries.ftp_recon.ftp_put": ("net.services",),
    "auxiliaries.ftp_recon.sftp_list": ("net.services",),
    "auxiliaries.ftp_recon.sftp_get": ("net.services",),
    "auxiliaries.ftp_recon.sftp_put": ("net.services",),
    "listeners.listening.TCPListener.open_listener": ("net.services",),
    "listeners.listening.TCPListener.close_listener": ("net.services",),
    "listeners.listening.TCPListener.read_listener": ("net.services",),
    "listeners.listening.TCPListener.send_to_listener": ("net.services",),
    "listeners.listening.TCPListener.clear_listener_data": ("net.services",),
}


def resolve_tags(
    tool_id: str,
    decorator_tags: Iterable[str] = (),
    warn=None,
) -> Tuple[str, ...]:
    """Merge decorator tags with the bulk map.  Decorator wins; map fills.

    Non-canonical tags are KEPT (discoverability preserved) but a warning is
    emitted through ``warn`` (the registry passes ``logger.warning``) so the
    bootstrap/reindex log surfaces typos and vocabulary drift.  Pass a
    recorder callable in tests to assert on the warnings.
    """
    raw = tuple(decorator_tags) if decorator_tags else TOOL_TAGS.get(tool_id, ())
    tags = tuple(
        str(t).strip() for t in raw if t is not None and str(t).strip()
    )
    unknown = [t for t in tags if t not in CANONICAL_TAGS]
    if unknown and warn is not None:
        warn(
            f"[tool_tags] '{tool_id}' carries non-canonical tag(s) {unknown}; "
            f"canonical vocabulary: {', '.join(CANONICAL_TAGS)}"
        )
    return tags


def tagged_doc(doc: str, tags: Iterable[str]) -> str:
    """Append the Categories line to a tool doc (the embedded capability text).

    No tags -> doc returned unchanged.  Because the doc is the embedded text,
    a tag change alters the doc and register_tool's change-detection
    re-embeds it on the next reindex automatically.
    """
    tags = tuple(tags)
    if not tags:
        return doc
    return f"{doc}\n\nCategories: {', '.join(tags)}"


def unknown_tags(tags: Iterable[str]) -> Tuple[str, ...]:
    """Tags not in CANONICAL_TAGS (empty tuple when all canonical)."""
    return tuple(t for t in tags if t not in CANONICAL_TAGS)
