import asyncio
import importlib.util
from impacket.smbconnection import SMBConnection
from pathlib import Path

from constants import framework_tool, brain_socket_path
from listeners.thebrain import pack_message

class SMBScanner:
    def __init__(self, brain_socket=None):
        self.brain_socket = brain_socket or str(brain_socket_path())

    async def report_to_brain(self, event_type, session_id, data):
        """Pipes the finding back to the Brain sidecar."""
        try:
            reader, writer = await asyncio.open_unix_connection(path=self.brain_socket)
            # Using your framing logic: event|session_id|data
            # We use a dummy session_id 0 for general recon events
            payload = f"{event_type}|0|{data}"
            
            writer.write(pack_message(payload.encode()))
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            print(f"[!] Brain reporting failed: {e}")

    @framework_tool("Test if a target is vulnerable to SMB Null Sessions.")
    def check_null_session(self, target, remoteName=False):
        """Attempts a Null Session connection to a target SMB share."""
        from utils.scope_gate import check_scan, ScopeGateError
        _sc_ok, _sc_reason = check_scan(target)
        if not _sc_ok:
            raise ScopeGateError(f"scope gate: {_sc_reason}")
        try:
            # timeout=2 to keep the scan moving
            conn = SMBConnection(target, target, timeout=2)
            # Attempt login with empty user and empty password
            conn.login('', '') 
            conn.logoff()
            return True
        except Exception:
            return False
    
    async def scan_subnet(self, targets: list):
        """Iterates through targets and reports vulnerabilities."""
        print(f"[*] Starting SMB Null Session scan on {len(targets)} targets...")
        for target in targets:
            # Run the blocking Impacket call in a thread to avoid freezing the loop
            loop = asyncio.get_event_loop()
            is_vuln = await loop.run_in_executor(None, self.check_null_session, target)
            
            if is_vuln:
                print(f"[+] Target {target} is vulnerable to Null Sessions!")
                await self.report_to_brain("vuln_found", 0, f"SMB_NULL_SESSION:{target}")
            else:
                print(f"[-] Target {target} secure.")

# Integration Example for bootstrap.py
@framework_tool("Run an SMB Null Session scan on a list of targets.")
async def run_smb_recon(targets):
    scanner = SMBScanner()
    await scanner.scan_subnet(targets)
