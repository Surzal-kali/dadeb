"""Deterministic pre-flight validation for tool calls.

Born from the 2026-09-20 fuzz incident: a malformed tool call (JSON-string
arguments, unknown keys, scalar payloads) flowed past every entry gate and
burned the full BRAIN_DISPATCH_TIMEOUT (1900s) inside a tool body that
should never have received the payload. This module is the fail-fast layer:
pure, synchronous, network-free checks that run BEFORE anything that can
block — before Brain dispatch, before the in-process import fallback,
before any secretary model inference.

Contract: validate_* functions return a rejection ENVELOPE (plain dict)
instead of raising, so every entry point can shape its own response from
one source of truth:

    {"status": "Rejected", "phase": "preflight", "tool_id": ...,
     "error": ..., "accepted_keys": [...], "required": [...]}

The single choke point is ``ExecutorMixin.execute_tool`` (daharness/
executor.py): REST, MCP, secretary and REPL all funnel through it.

Dependency-free (stdlib only) so it can be imported anywhere without
import cycles. Type coercion delegates (lazily, at call time) to
``agent._coerce_arg_value`` so there is exactly one coercion
implementation.
"""

import json
import logging
import os
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# --- Caps (env-overridable) -------------------------------------------------
# Total serialized 'arguments' budget. A payload bigger than this is always a
# bug or an abuse; the Brain wire framing would happily carry megabytes into a
# tool that then chokes on them inside the dispatch-timeout window.
MAX_ARGS_BYTES = int(os.getenv("PREFLIGHT_MAX_ARGS_BYTES", "262144"))
# Per-string-value cap. Generous for paths/URLs/host lists; blocks the
# multi-KB garbage payloads the fuzz threw at probe_web.
MAX_ARG_STR_LEN = int(os.getenv("PREFLIGHT_MAX_ARG_STR_LEN", "16384"))
# Per-container item cap (top-level keys, list/dict values).
MAX_ARG_ITEMS = int(os.getenv("PREFLIGHT_MAX_ARG_ITEMS", "256"))


def rejection(
    tool_id: Any,
    error: str,
    accepted: Optional[list] = None,
    required: Optional[list] = None,
) -> Dict[str, Any]:
    """Build a structured Rejection envelope."""
    return {
        "status": "Rejected",
        "phase": "preflight",
        "tool_id": tool_id if isinstance(tool_id, str) else "",
        "error": error,
        "accepted_keys": sorted(accepted or []),
        "required": list(required or []),
    }


def is_rejection(obj: Any) -> bool:
    return (
        isinstance(obj, dict)
        and obj.get("phase") == "preflight"
        and obj.get("status") == "Rejected"
    )


def format_rejection(env: Dict[str, Any]) -> str:
    """Human-readable one-liner for error channels (MCP isError, HTTP 422)."""
    return (
        f"{env.get('error', 'rejected')}"
        f" | accepted_keys={env.get('accepted_keys', [])}"
        f" | required={env.get('required', [])}"
    )


def normalize_arguments(arguments: Any) -> Tuple[Optional[dict], Optional[dict]]:
    """Parse/normalize ``arguments`` and enforce size caps.

    Returns ``(args_dict, None)`` on pass or ``(None, rejection_envelope)``.

    A JSON-encoded STRING is parsed here (OpenWebUI adapters and small
    secretary models both emit strings). Anything that does not parse to a
    JSON OBJECT is rejected — the legacy ``{"_raw": ...}`` passthrough is
    retired: it is exactly what let malformed payloads reach tool bodies and
    hang them until BRAIN_DISPATCH_TIMEOUT.
    """
    if arguments is None:
        return {}, None
    if isinstance(arguments, dict):
        args = dict(arguments)  # copy: coercion below must not mutate callers
    elif isinstance(arguments, str):
        raw = arguments.strip()
        if len(raw.encode("utf-8", errors="replace")) > MAX_ARGS_BYTES:
            return None, rejection(
                raw[:80],
                f"'arguments' payload too large ({len(raw)} chars > {MAX_ARGS_BYTES} bytes).",
            )
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as e:
            return None, rejection(
                raw[:80],
                f"'arguments' is not valid JSON: {e}. "
                "Send arguments as a JSON object of named parameters.",
            )
        if not isinstance(parsed, dict):
            return None, rejection(
                raw[:80],
                f"'arguments' must be a JSON object (named parameters), "
                f"got {type(parsed).__name__}.",
            )
        args = parsed
    else:
        return None, rejection(
            str(arguments)[:80],
            f"'arguments' must be a JSON object (named parameters), "
            f"got {type(arguments).__name__}.",
        )

    if "_raw" in args:
        return None, rejection(
            "",
            "'arguments' contained an unparsed '_raw' payload — arguments must "
            "be a JSON object of named parameters per the tool's schema.",
        )

    try:
        blob = json.dumps(args, default=str)
    except (TypeError, ValueError) as e:
        return None, rejection("", f"'arguments' is not JSON-serializable: {e}")
    if len(blob.encode("utf-8", errors="replace")) > MAX_ARGS_BYTES:
        return None, rejection(
            "",
            f"'arguments' too large ({len(blob)} chars serialized > {MAX_ARGS_BYTES} bytes).",
        )
    if len(args) > MAX_ARG_ITEMS:
        return None, rejection(
            "",
            f"'arguments' has {len(args)} keys > {MAX_ARG_ITEMS} cap.",
        )
    for key, value in args.items():
        if isinstance(value, str) and len(value) > MAX_ARG_STR_LEN:
            return None, rejection(
                key,
                f"argument '{key}' too large ({len(value)} chars > {MAX_ARG_STR_LEN}).",
            )
        if isinstance(value, (list, dict)) and len(value) > MAX_ARG_ITEMS:
            return None, rejection(
                key,
                f"argument '{key}' has {len(value)} items > {MAX_ARG_ITEMS} cap.",
            )
    return args, None


def _is_missing(val: Any) -> bool:
    """Mirror agent._normalize_args_against_manifest's 'missing' semantics.

    2026-09-25 (F-032): an explicitly-supplied empty string is DATA, not
    absence — ``db_connect(password: "")`` (empty-password credential probe)
    must reach the tool.  Only None and empty containers count as missing;
    string content (including "" and whitespace) is the caller's data and
    the tool itself validates its semantics.
    """
    if val is None:
        return True
    if isinstance(val, (dict, list)) and len(val) == 0:
        return True
    return False


def _coerce(name: str, value: Any, schema_type: str) -> Any:
    """Delegate to agent._coerce_arg_value (single source of truth).

    Lazy import: agent -> registry -> executor -> preflight at module load,
    so preflight must not import agent at module level. If the import ever
    fails (partial install), degrade to passthrough and say so — never hang.
    """
    try:
        from .agent import _coerce_arg_value

        return _coerce_arg_value(name, value, schema_type or "")
    except Exception as e:  # pragma: no cover - degraded install only
        logger.warning("[PREFLIGHT] coercion delegate unavailable (%s); passing value through", e)
        return value


def validate_against_manifest(args: dict, manifest: Any) -> Optional[dict]:
    """Schema-level checks against the manifest's ``parameters`` schema.

    Returns None on pass or a rejection envelope. Checks, in order:
      1. unknown keys (skipped when the manifest declares no properties —
         open schema; caps from normalize_arguments still applied);
      2. missing required keys (None / empty containers count as missing;
         explicitly-supplied strings — including "" — are data and pass:
         F-032 empty-password probes, 2026-09-25);
      3. per-key tolerant type coercion + enum membership.
    Mutates ``args`` in place with coerced values (callers pass a fresh dict
    from normalize_arguments).
    """
    tool_id = getattr(manifest, "module_id", "") if manifest is not None else ""
    params = getattr(manifest, "parameters", None)
    params = params if isinstance(params, dict) else {}
    properties = params.get("properties")
    required = params.get("required")
    properties = properties if isinstance(properties, dict) else {}
    required = required if isinstance(required, list) else []

    # 1. Unknown keys.
    if properties:
        declared = set(properties.keys())
        declared_lower = {d.lower() for d in declared}
        extra = [
            k
            for k in args
            if k not in declared
            and k.lower() not in declared_lower
            and not k.startswith("_")
        ]
        if extra:
            return rejection(
                tool_id,
                f"unknown argument(s): {extra}. Tool '{tool_id}' only accepts "
                f"these keys: {sorted(declared)}.",
                accepted=declared,
                required=required,
            )

    # 2. Missing required.
    missing = [r for r in required if r not in args or _is_missing(args[r])]
    if missing:
        return rejection(
            tool_id,
            f"missing required argument(s): {missing}. Tool '{tool_id}' "
            f"requires these fields in 'arguments'.",
            accepted=list(properties.keys()),
            required=required,
        )

    # 3. Type coercion + enum.
    for name, prop_def in properties.items():
        if name not in args or not isinstance(prop_def, dict):
            continue
        schema_type = prop_def.get("type") or ""
        try:
            args[name] = _coerce(name, args[name], schema_type)
        except ValueError as ve:
            return rejection(
                tool_id,
                str(ve),
                accepted=list(properties.keys()),
                required=required,
            )
        allowed = prop_def.get("enum")
        if isinstance(allowed, list) and allowed and args[name] not in allowed:
            return rejection(
                tool_id,
                f"argument '{name}' must be one of {allowed}, got {args[name]!r}. "
                "Copy the allowed value VERBATIM — do not paraphrase.",
                accepted=list(properties.keys()),
                required=required,
            )
    return None


__all__ = [
    "MAX_ARGS_BYTES",
    "MAX_ARG_ITEMS",
    "MAX_ARG_STR_LEN",
    "format_rejection",
    "is_rejection",
    "normalize_arguments",
    "rejection",
    "validate_against_manifest",
]