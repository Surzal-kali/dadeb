#!/usr/bin/env python3
"""Raw LSP probe: does pyright serve signatureHelp at an SSH-style call site?

Compares three contexts in one server session:
  A. module-level call, no await:      x = ssh_connect("h")
  B. call inside async def (valid py): wrapped await
  C. top-level await (IPython style):  await ssh_connect("h")  <- scratch-cell reality

Each gets: signatureHelp (after the paren), hover (on the name), completion
control at same position.  Read-only; kills the server at exit.
"""
import json
import subprocess
import sys
import time
from pathlib import Path

LS = Path.home() / ".local/share/nvim/mason/bin/pyright-langserver"
STUBS_DIR = Path.home() / ".local/share/framework-stubs"

HEADER = "# vim: ft=python\nfrom framework_tools import *\n"

FILE_A = HEADER + "x = ssh_connect(\"h\")\n"            # line 3 (0-based 2)
FILE_B = HEADER + "async def cc():\n    await ssh_connect(\"h\")\n"  # line 4 (0-based 3)
FILE_C = HEADER + "await ssh_connect(\"h\")\n"          # line 3 (0-based 2)

NAME = "ssh_connect"
PAREN = "("  # position = index of '(' + 1 in the call line


def find_pos(text: str, want_after_paren: bool = True):
    lines = text.split("\n")
    for ln, line in enumerate(lines):
        if NAME in line:
            i = line.index(NAME) + len(NAME)
            return {"line": ln, "character": i + 1 if want_after_paren else i + 2}
    raise ValueError("no call site")


class LSClient:
    def __init__(self):
        self.p = subprocess.Popen(
            [str(LS), "--stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        self._id = 0
        self.nid = 0  # notification id counter (unused)

    def send(self, obj):
        body = json.dumps(obj).encode()
        self.p.stdin.write(b"Content-Length: %d\r\n\r\n" % len(body) + body)
        self.p.stdin.flush()

    def request(self, method, params):
        self._id += 1
        rid = self._id
        self.send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        return rid

    def notify(self, method, params):
        self.send({"jsonrpc": "2.0", "method": method, "params": params})

    def read_until(self, rid, timeout=30.0):
        t0 = time.time()
        buf = b""
        while time.time() - t0 < timeout:
            chunk = self.p.stdout.read1(65536)
            if not chunk:
                time.sleep(0.05)
                continue
            buf += chunk
            while True:
                idx = buf.find(b"\r\n\r\n")
                if idx < 0:
                    break
                head = buf[:idx].decode()
                clen = int([l for l in head.split("\r\n") if l.lower().startswith("content-length")][0].split(":")[1])
                total = idx + 4 + clen
                if len(buf) < total:
                    break
                body = buf[idx + 4 : total]
                buf = buf[total:]
                msg = json.loads(body)
                if msg.get("id") == rid and ("result" in msg or "error" in msg):
                    return msg.get("result", msg.get("error"))
                # ignore notifications / other responses (registrations etc.)
        return None


def probe(c: LSClient, name: str, text: str, after_paren=True):
    pos = find_pos(text, after_paren)
    uri = f"file:///tmp/lane/{name}.py"
    Path(f"/tmp/lane/{name}.py").write_text(text)
    c.notify("textDocument/didOpen", {
        "textDocument": {"uri": uri, "languageId": "python", "version": 1, "text": text},
    })
    time.sleep(1.5)  # let analysis settle
    rid = c.request("textDocument/signatureHelp", {
        "textDocument": {"uri": uri}, "position": pos,
    })
    sig = c.read_until(rid, timeout=25)
    rid = c.request("textDocument/completion", {
        "textDocument": {"uri": uri}, "position": pos,
    })
    comp = c.read_until(rid, timeout=25)
    items = []
    if isinstance(comp, dict):
        items = comp.get("items", [])
    elif isinstance(comp, list):
        items = comp
    nmap_hits = sum(1 for i in items if (i.get("label") or "").startswith("nma"))
    return {
        "sig": None if sig in (None, []) else sig,
        "sig_label": (sig.get("signatures") or [{}])[0].get("label") if isinstance(sig, dict) else "NIL",
        "sig_nparams": len(sig["signatures"][0]["parameters"]) if isinstance(sig, dict) and sig.get("signatures") else 0,
        "comp_total": len(items),
        "comp_nmap": nmap_hits,
        "pos": (pos["line"], pos["character"]),
    }


def main():
    c = LSClient()
    root_uri = "file:///tmp/lane"
    Path(STUBS_DIR.name and "/tmp/lane").mkdir(exist_ok=True)
    (Path("/tmp/lane") / "pyrightconfig.json").write_text(
        json.dumps({"extraPaths": [str(STUBS_DIR)], "diagnosticMode": "openFilesOnly"})
    )
    rid = c.request("initialize", {
        "processId": 0, "rootUri": root_uri, "workspaceFolders": [{"uri": root_uri, "name": "lane"}],
        "capabilities": {"textDocument": {"synchronization": {"didOpen": True}}},
    })
    init = c.read_until(rid, timeout=30)
    assert init, "no initialize response"
    c.notify("initialized", {})
    out = {}
    for name, text in [
        ("A_module_call_no_await", FILE_A),
        ("B_wrapped_await_async_def", FILE_B),
        ("C_toplevel_await", FILE_C),
    ]:
        out[name] = probe(c, name, text)
    c.notify("shutdown", {})
    c.p.terminate()
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()