"""SAFE defaults + sweep skip-set.

These are TEST VALUES, not schema — the schema lives in the manifests.
``SAFE_ARGS`` is the bare-``run <tool_id>`` fallback (no args given): it
carries only runtime values that are harmless on their own (localhost,
dry-run, benign test strings). ``REQUIRES_SERVICE`` lists tools that need a
live backend (msfrpcd, searchsploit DB, sqlmap) and were skipped in the
REPL's legacy smoke-``sweep``; the table also feeds
``replkit.core.run_selftest`` so the pytest macro skips the same lanes
implicitly.
"""

from typing import Any, Dict, Set

SAFE_ARGS: Dict[str, Dict[str, Any]] = {
    "auxiliaries.nmap.run_nmap": {"target": "127.0.0.1", "options": "-Pn -p 22"},
    "auxiliaries.smb_scanner.SMBScanner.check_null_session": {"host": "127.0.0.1"},
    "auxiliaries.smb_scanner.run_smb_recon": {"host": "127.0.0.1"},
    "auxiliaries.impacket_suite.atexec_exec": {"target": "127.0.0.1", "username": "guest", "password": "guest", "command": "echo test"},
    "auxiliaries.impacket_suite.psexec_exec": {"target": "127.0.0.1", "username": "guest", "password": "guest", "command": "echo test"},
    "auxiliaries.impacket_suite.wmiexec_exec": {"target": "127.0.0.1", "username": "guest", "password": "guest", "command": "echo test"},
    "auxiliaries.impacket_suite.secretsdump": {"target": "127.0.0.1"},
    "auxiliaries.impacket_suite.smb_enum_shares": {"target": "127.0.0.1"},
    "auxiliaries.impacket_suite.smb_read_file": {"target": "127.0.0.1", "share": "C$", "path": "\\"},
    "listeners.listening.TCPListener.open_listener": {"host": "127.0.0.1", "port": 9999},
    "listeners.listening.TCPListener.close_listener": {"handle": "listener:tcp-9999"},
    "listeners.listening.TCPListener.send_to_brain": {"event": "TEST", "data": "repl sweep test"},
    "listeners.raw_scan.syn_scan": {"target": "127.0.0.1", "ports": "22"},
    "utils.log_reader.read_logs": {"log_type": "brain", "lines": 5},
    "utils.memory_tools.remember_text": {"text": "REPL test memory", "namespace": "test"},
    "utils.memory_tools.recall_text": {"query": "REPL test", "namespace": "test", "limit": 3},
    "utils.paramiko_client.list_sessions": {},
    "utils.paramiko_client.ssh_connect": {"host": "127.0.0.1", "username": "test", "password": "test"},
    "utils.paramiko_client.ssh_exec": {"handle": "ssh:sess-0000", "command": "echo test"},
    "utils.paramiko_client.ssh_shell": {"handle": "ssh:sess-0000", "command": "echo test"},
    "utils.paramiko_client.ssh_close": {"handle": "ssh:sess-0000"},
    "utils.paramiko_client.paramiko_client": {"host": "127.0.0.1", "username": "test", "password": "test", "command": "echo test"},
    "auxiliaries.ldap_search.ldap_rootdse": {"host": "127.0.0.1"},
    "auxiliaries.ldap_search.ldap_search": {"host": "127.0.0.1", "base_dn": "dc=example,dc=com"},
}

# Tools that require a live service and were skipped in legacy sweep mode;
# still consulted safe-mode skips in the selftest macro.
REQUIRES_SERVICE: Set[str] = {
    "payloads.metasploiting.MetasploitClient.index_modules",
    "payloads.metasploiting.MetasploitClient.dispatch_metasploit",
    "payloads.metasploiting.MetasploitClient.get_options",
    "payloads.metasploiting.MetasploitClient.interact_session",
    "payloads.metasploiting.MetasploitClient.set_payload",
    "payloads.metasploiting.MetasploitClient.close_msf_session",
    "payloads.searchsploiting.search_exploit",
    "payloads.sqlmap.run_sqlmap",
}