"""Scan-shaping presets + resolver for nmap lanes.

Shaping = deliberate wire-traffic shape: timing, padding, fragmenting.
The honest taxonomy (encoded in the preset names on purpose):

  scan SPEED presets (-T) tune the scanner's own accuracy/latency trade;
  they are NOT evasion — the full sweep pattern still lands on the wire.
  WIRE presets (--max-rate / --scan-delay / --data-length) are the real
  shaping levers: they change what the far-side observer records.
  lab_only presets (decoy, fragment) are noisy and fingerprintable; they
  are refused on live-lane surfaces unless SHAPING_LAB_MODE=1 is set.

Resolver contract (mirrors msfvenom PRESETS discipline):
  resolve(opts, preset, lab_mode) -> dict with:
    merged  — list of flags: preset flags first, explicit opts appended
              LAST so operator-explicit flags always win on repeats
              (flag ordering = precedence for value-carrying flags).
    applied — preset name actually applied ("none" when preset is falsy).
    notes   — wire-semantics per flag, for the manifest/doc.
  Raises ShapingError (subclass ValueError) on: unknown preset,
  lab_only preset with lab_mode=False, non-token chars.
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_-]*$")

# Preset values are LISTS so the resolver can merge + de-dup cleanly.
# Wire semantics live in _WIRE_NOTES so the resolver can self-describe.
SCAN_SHAPING_PRESETS: Dict[str, Dict[str, Any]] = {
    "quiet": {
        "flags": ["-T2", "--max-rate", "50"],
        "lab_only": False,
        "notes": (
            "Half-rate serial-ish probe pacing with a 50 pkt/s ceiling. "
            "Slows the sweep; does NOT hide the scan from an observer."
        ),
    },
    "polite": {
        "flags": ["-T1", "--max-rate", "10", "--scan-delay", "1s"],
        "lab_only": False,
        "notes": (
            "Serial probes, 1s between probes, 10 pkt/s ceiling. Slow "
            "and gentle for shared lab/production-adjacent networks."
        ),
    },
    "noisy": {
        "flags": ["-T4"],
        "lab_only": False,
        "notes": (
            "Aggressive timing for speed. NOT evasion — full sweep pattern "
            "lands at once; observer sees everything, just faster."
        ),
    },
    "decoy": {
        "flags": ["-D", "RND:5,ME", "-T2"],
        "lab_only": True,
        "notes": (
            "5 random spoofed decoys + your real IP. Modern stacks log "
            "real-source hits and route decoys far slower (Egress checks) "
            "— mostly fingerprint theater. Lab toy."
        ),
    },
    "fragment": {
        "flags": ["-f", "--mtu", "24"],
        "lab_only": True,
        "lab_note": (
            "8-byte probe fragments — ineffective against modern stack "
            "reassembly (Windows/IDS reassemble then inspect); useful "
            "only vs legacy/regex-line scanners. Flag order matters: "
            "--mtu AFTER -f."
        ),
    },
}

_WIRE_NOTES: Dict[str, str] = {
    "-T2": "timing template: slower probe pacing (accuracy/speed trade)",
    "-T4": "timing template: aggressive (speed, no stealth value)",
    "-T1": "timing template: serial probes, slowest",
    "--max-rate": "hard packets-per-second ceiling on the wire",
    "--scan-delay": "pause between probes",
    "--data-length": "random padding bytes appended to probes",
    "-D": "spoofed decoy sources mixed into the sweep",
    "-f": "probe fragmentation into 8-byte pieces",
    "--mtu": "custom fragmentation unit",
}


def _token_ok(name: str) -> bool:
    return bool(SAFE_TOKEN.match(name))


class ShapingError(ValueError):
    """Raised by resolve() for unknown/refused/malformed shaping requests."""


def resolve(
    preset: Optional[str],
    options: str = "",
    lab_mode: Optional[bool] = None,
) -> Dict[str, Any]:
    """Merge a shaping preset with explicit operator options.

    Args:
        preset: preset name or None/"" (no shaping).
        options: operator's explicit flag string (shlex-split into argv;
            appended AFTER preset flags so explicit wins on repeats).
        lab_mode: gate for lab_only presets. None = read $SHAPING_LAB_MODE.
    """
    import shlex as _shlex

    if lab_mode is None:
        lab_mode = os.getenv("SHAPING_LAB_MODE", "").strip().lower() in (
            "1", "true", "yes", "on")

    merged: List[str] = []
    applied = "none"
    notes: List[str] = []

    if preset:
        preset = str(preset).strip().lower()
        if not _token_ok(preset):
            raise ShapingError(
                f"Invalid shaping name {preset!r} — see scan_shaping_menu().")
        spec = SCAN_SHAPING_PRESETS.get(preset)
        if spec is None:
            raise ShapingError(
                f"Unknown shaping preset {preset!r}. Valid: "
                + ", ".join(sorted(SCAN_SHAPING_PRESETS)) + ".")
        if spec.get("lab_only") and not lab_mode:
            raise ShapingError(
                f"Preset '{preset}' is lab_only — requires SHAPING_LAB_MODE=1 "
                "in the root-0600 .env (live surfaces get flagged).")
        merged.extend(spec["flags"])
        applied = preset
        note = spec.get("notes") or spec.get("lab_note") or ""
        if note:
            notes.append(f"[{preset}] {note}")

    if options:
        merged.extend(_shlex.split(options))

    return {"merged": merged, "applied": applied, "notes": notes}
