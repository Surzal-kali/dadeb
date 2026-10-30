"""Burp replay worker — the subprocess each Burp fleet unit launches.

This module is INTERNAL plumbing (the fleet unit's argv), not an operator
CLI: `_NO_LOCAL_TOOL = True` skips the discovery static mint so the
argparse here never surfaces as a second entry point beside the fleet
twins (`payloads/burp_fleet.py` is the operator lane).

Unit shape: ONE raw HTTP request, replayed ``retries`` times verbatim
through the live Burp MCP BApp (`send_http1_request`). Results are
written to the job log as:

  BURP-RETRY i=1 status_code=200 elapsed_ms=312 ok=true
  ...
  BURP-VERDICT json={"attempts": 3, "ok": 3, "status_codes": [200, ...]}

The verdict line is what `register_verdict_parser("burp", ...)` reads;
everything else in the log is operator-visible context. Target traffic
is DATA — the child never acts on response content beyond counting.
"""

from __future__ import annotations

# Internal plumbing, not an operator CLI: the discovery static pass must
# not mint this module's argparse as a second entry point beside the
# fleet twins (payloads/burp_fleet.py is the operator lane).
_NO_LOCAL_TOOL = True

import argparse
import json
import sys
import time
from pathlib import Path

# The child runs from an arbitrary cwd (job store launches); make the
# framework root importable before the Burp client import.
_FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
if str(_FRAMEWORK_ROOT) not in sys.path:
    sys.path.insert(0, str(_FRAMEWORK_ROOT))


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Burp fleet replay worker")
    parser.add_argument("--manifest", required=True,
                        help="unit manifest JSON (burp_replay_fleet output)")
    args = parser.parse_args(argv)

    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    content = manifest["request"]
    host = manifest["host"]
    port = int(manifest["port"])
    uses_https = bool(manifest["https"])
    retries = max(1, min(64, int(manifest.get("retries", 1))))

    verdict: dict[str, object] = {
        "attempts": 0, "ok": 0, "status_codes": [], "errors": [], "aborted": None,
    }

    def _finish(code: int) -> int:
        print(f"BURP-VERDICT json={json.dumps(verdict, sort_keys=True)}", flush=True)
        return code

    # The BApp must be up; a fleet child never starts Burp itself.
    from auxiliaries.burp_mcp import BurpMCPClient

    client = BurpMCPClient.get_instance()
    try:
        if not client.healthcheck():
            verdict["aborted"] = "burp MCP not reachable — start Burp with the MCP Server BApp enabled"
            return _finish(1)
    except Exception as e:  # transport down = honest abort, not silent
        verdict["aborted"] = f"burp MCP transport error: {e}"
        return _finish(1)

    from auxiliaries.burp_mcp import burp_send_http1_request
    from utils.scope_gate import ScopeGateError

    for i in range(1, retries + 1):
        verdict["attempts"] = i
        t0 = time.time()
        try:
            result = burp_send_http1_request(
                content=content, target_hostname=host,
                target_port=port, uses_https=uses_https,
            )
        except ScopeGateError as e:
            # The operator-armed gate is the authority; stop the whole
            # unit — replaying the next attempt is still a blocked send.
            verdict["aborted"] = str(e)
            return _finish(2)
        except Exception as e:
            verdict["errors"].append(str(e))  # type: ignore[union-attr]
            print(f"BURP-RETRY i={i} ok=false error={e}", flush=True)
            continue
        elapsed = int((time.time() - t0) * 1000)
        code = result.get("status_code")
        print(f"BURP-RETRY i={i} status_code={code} elapsed_ms={elapsed} ok=true",
              flush=True)
        verdict["status_codes"].append(code)  # type: ignore[union-attr]
        verdict["ok"] += 1  # a sent request gets a response; send errors go to errors
    return _finish(0)


if __name__ == "__main__":
    raise SystemExit(_main())