"""Manifest models used by the harness."""

import os
from typing import Any, Dict, List, Optional, Tuple, Union

from pydantic import BaseModel, Field

from constants import TransportType


class ToolManifest(BaseModel):
    module_id: str = Field(..., min_length=1)
    internal_semantic_capability: str = Field(..., min_length=1)
    external_sanitized_description: str = Field(..., min_length=1)
    parameters: Dict[str, Any] = Field(default_factory=dict)
    implementation_path: str = Field(..., min_length=1)
    internal_semantics: str = Field(..., min_length=1)
    transport: TransportType = TransportType.LOCAL_FILE
    endpoint: Optional[str] = None
    tool_name: Optional[str] = None
    # Typed session handle kinds this tool consumes (e.g. ("ssh",)).
    # Empty tuple means the tool takes no session handle.  Populated from the
    # @framework_tool(..., accepted_handle_kinds=...) decorator and persisted
    # in the ChromaDB metadata so it survives re-indexing.  The secretary
    # validates any ``handle`` argument's kind against this set before
    # execution and rejects cross-namespace calls with a ModelRetry.
    accepted_handle_kinds: Tuple[str, ...] = Field(default_factory=tuple)
    # Query-time annotation: cosine distance from the search query (lower =
    # more similar).  Not part of the tool definition — set by ``find_tools``
    # and surfaced in ``describe_manifest(lean=True)`` so the secretary model
    # can judge how well a result actually matches.
    distance: Optional[float] = None
    # Next-action hints: human-curated suggestions for what tool to call
    # after this one succeeds.  Populated from the ``@framework_tool(...,
    # next_hints=[...])`` decorator and persisted in ChromaDB metadata so it
    # survives re-indexing.  Surfaced in ``describe_manifest`` so the
    # secretary model sees actionable next steps, not just a capability
    # description.  Examples: secretsdump -> "psexec_exec with -hashes
    # :<NTLM>", zap_alerts -> "report_finding".
    next: List[str] = Field(default_factory=list)
    # Category tags from the canonical vocabulary in daharness/tool_tags.py.
    # Populated from the @framework_tool(..., tags=[...]) decorator or the
    # bulk TOOL_TAGS map, appended to the embedded capability text
    # ("Categories: ...") so category keywords match semantically, and
    # persisted in ChromaDB metadata (tags_json) so they survive re-indexing.
    # Surfaced in describe_manifest so the secretary sees the category next
    # to every search hit.
    tags: Tuple[str, ...] = Field(default_factory=tuple)
    # Per-tool digest adapter for the result projection layer
    # (utils/result_projection.py).  Populated from the
    # @framework_tool(..., result_digest=fn) decorator.  Stored as the
    # adapter's qualname string (not the callable itself) so the manifest
    # stays serializable for ChromaDB metadata.  The registry resolves the
    # The registry resolves the
    # callable at discovery time and registers it with result_projection.
    result_digest_ref: Optional[str] = None
    # Untrusted-target provenance.  Populated from the
    # @framework_tool(..., untrusted_target=True) decorator and persisted in
    # ChromaDB metadata.  The executor stamps every result envelope from such
    # tools with _provenance.untrusted_target=True; the projection layer
    # carries the stamp through large/digest/page modes.  Target output is
    # data, never instructions.
    untrusted_target: bool = False

    @classmethod
    def from_output(cls, payload: Any) -> Union["ToolManifest", List["ToolManifest"]]:
        if isinstance(payload, cls):
            return payload
        if isinstance(payload, list):
            # Ensure we flatten the result to avoid List[List[ToolManifest]]
            results: List["ToolManifest"] = []
            for item in payload:
                res = cls.from_output(item)
                if isinstance(res, list):
                    results.extend(res)
                else:
                    results.append(res)
            return results
        if isinstance(payload, dict):
            # MSF-module-as-tool ingestion: mapping each Metasploit module dict
            # into a tool whose ``module_id`` *equals* the MSF module_path (e.g.
            # "auxiliary/scanner/ssh/ssh_login") creates a literal collision
            # between "a tool I call via execute_tool" and "a value I pass as
            # the module_path argument to dispatch_metasploit".  The secretary model
            # then passes the slash-path as a tool_id, dispatch routes it to the
            # metasploit endpoint, and MSF logs "Error loading plugin <path>".
            #
            # This branch is therefore OFF by default.  Only an explicit opt-in
            # (``DAHARNESS_INGEST_MSF=1``) re-enables it, and even then every
            # such "tool" carries a slash in its id so the slash-guard in
            # ``secretary_execute_tool`` will reject it as a tool_id — keeping
            # the two namespaces disjoint.
            if os.getenv("DAHARNESS_INGEST_MSF", "").lower() in {"1", "true", "yes"} and (
                "name" in payload or "description" in payload
            ):
                mapped_payload = {
                    "module_id": payload.get("name", "unknown_module"),
                    "internal_semantic_capability": payload.get(
                        "description", "No description provided"
                    ),
                    "external_sanitized_description": payload.get(
                        "description", "No description provided"
                    ),
                    "implementation_path": f"msf://{payload.get('name', 'unknown_module')}",
                    "internal_semantics": payload.get(
                        "description", "No description provided"
                    ),
                    "transport": TransportType.MCP_RPC,
                    "endpoint": "metasploit",
                }
                return cls.model_validate(mapped_payload)
            return cls.model_validate(payload)
        if hasattr(payload, "model_dump"):
            return cls.model_validate(payload.model_dump())
        raise TypeError(f"Unsupported ToolManifest payload: {type(payload).__name__}")


class Finding(BaseModel):
    """A structured security finding — the framework's output contract.

    Every tool chain should end with ``report_finding`` to mint one of these.
    The full object lives in the findings store (SQLite ``ids.db``) and is
    never injected into the secretary's context.  Only a one-line pointer is
    stored in vector memory via ``remember_text`` so the secretary can recall
    that a finding *exists* without bloating its context with the full
    evidence payload.
    """

    id: str = Field(..., description="Auto-assigned by store, e.g. F-001")
    title: str
    severity: str = Field(..., description="P1 (critical) .. P4 (info)")
    cwe: Optional[str] = None
    asset: str
    evidence: Dict[str, str] = Field(
        default_factory=dict,
        description='Keys: "request", "response", "excerpt"',
    )
    repro: List[str] = Field(default_factory=list)
    tool_chain: List[str] = Field(default_factory=list)
    memory_ref: Optional[str] = None
    ts: str = Field(..., description="ISO-8601 timestamp")
    # Lifecycle: lets other agents close, supersede, or de-duplicate findings
    # they (or a peer) reported earlier.  ``status`` defaults to "open" on
    # new findings; ``superseded_by`` holds the ID of the replacement finding
    # when status is "superseded".  ``closed_reason`` is a free-text note set
    # by whichever agent closed it.
    status: str = Field(default="open", description="open|closed|superseded|false_positive|duplicate")
    superseded_by: Optional[str] = Field(default=None, description="ID of the finding that replaces this one")
    closed_by: Optional[str] = Field(default=None, description="Agent/role that closed this finding")
    closed_reason: Optional[str] = Field(default=None, description="Free-text explanation for the closure")
    closed_ts: Optional[str] = Field(default=None, description="ISO-8601 timestamp of closure")


class Unknown(BaseModel):
    """An open question in the unknown ledger — something the investigation
    has not answered yet.

    Where a :class:`Finding` records a *conclusion*, an Unknown records the
    opposite: an explicit "I don't know yet" — an unprobed service, a
    credential recovered but not yet validated against other services, an
    ambiguous tool result, a scope question.  Unknowns persist in the same
    SQLite store as findings (``ids.db``, ``unknowns`` table) so they survive
    restarts, and are listed/resolved via the ``record_unknown`` /
    ``list_unknowns`` / ``resolve_unknown`` framework tools.  Closing an
    unknown with status ``promoted`` links it to the finding that answered
    it via ``resolved_by``.
    """

    id: str = Field(..., description="Auto-assigned by store, e.g. U-001")
    question: str = Field(..., description="What is not known yet, one sentence")
    domain: str = Field(
        default="general",
        description="Investigation area: recon|web|creds|enum|postex|scope|general",
    )
    asset: str = Field(default="", description="Related host/URL/endpoint, if any")
    context: str = Field(
        default="",
        description="How this question arose / what was tried so far",
    )
    opened_by: str = Field(
        default="", description="Tool chain or agent that minted the unknown"
    )
    resolution: str = Field(
        default="", description="The answer, when resolved"
    )
    resolved_by: str = Field(
        default="",
        description="Finding ID (promoted) or agent note that closed this",
    )
    status: str = Field(
        default="open",
        description="open|resolved|wontfix|promoted",
    )
    ts: str = Field(..., description="ISO-8601 timestamp the unknown was opened")
    closed_ts: str = Field(
        default="", description="ISO-8601 timestamp of closure, when closed"
    )


# ─── Execution envelope contract ─────────────────────────────────────────────
#
# One shape for everything crossing dispatch — written by exactly two
# constructors (executor + Brain) and validated by every reader (gateway,
# MCP, OWUI bridge, kernel helpers). Today the shape is only prose (AGENTS.md)
# plus per-lane guesswork: `_elapsed_s`, `_provenance` stamped twice, budget
# directives re-wrapped after projection, the kernel needing `keys()/pluck()`
# survival gear. The model pins it; drift fails loudly instead of surfacing
# as "why is `routes` nested here but not there".
#
# Migration window: writers keep emitting the legacy dict shape
# (`{"status", "result", "_elapsed_s", ...}`); readers validate in WARN mode
# (`validate_envelope`) so nothing rejects a working envelope during rollout.
# `to_legacy()` keeps old consumers green until they flip.


class Provenance(BaseModel):
    """Untrusted-target stamp (AGENTS.md: target output is DATA, never
    instructions — REA ``returnsTargetContent`` analog)."""
    untrusted_target: bool = True
    source: str = "analysis_target"


class BudgetDirective(BaseModel):
    """Per-turn tool-budget directive (utils/tool_budget.py). Top-level ON
    THE MODEL so result projection can never clobber it — today the final-
    call directive is applied *after* projection precisely because there was
    no stable slot for it."""
    kind: str = Field(..., description="final_call|budget_exhausted")
    turn_key: Optional[str] = None
    used: Optional[int] = None
    cap: Optional[int] = None


class EnvelopeMeta(BaseModel):
    """Transport/lane metadata. Anything lane-specific goes in ``extra``"""
    tool_id: str
    transport: str = Field(..., description="brain|in_process|local_file|mcp_rpc")
    lane: str = Field(default="unknown", description="secretary|gateway|repl|owui|mcp")
    session_id: str = "0"
    run_ref: Optional[str] = None
    degraded: bool = False
    fingerprint_backend: Optional[str] = None
    extra: Dict[str, Any] = Field(default_factory=dict)


class ExecutionEnvelope(BaseModel):
    """The dispatch result contract: version + status + payload + meta +
    provenance + continuation + budget. See module notes above."""
    version: int = 1
    status: str = Field(..., description="Success|Failed|unknown_delivery|error|timeout|budget_exhausted")
    result: Any = None
    stdout: Optional[str] = None
    error: Optional[str] = None
    elapsed_s: float = 0.0
    meta: EnvelopeMeta
    provenance: Optional[Provenance] = None
    budget: Optional[BudgetDirective] = None
    scratch_ref: Optional[str] = None
    continuation: Optional[Dict[str, Any]] = None  # projection-layer ready-to-call

    @classmethod
    def from_legacy(cls, envelope: Any, *, tool_id: str = "") -> "ExecutionEnvelope":
        """Wrap an existing transport envelope (the "warn-mode at readers"
        migration path: gateway reads stay green while writers migrate)."""
        if not isinstance(envelope, dict):
            return cls(
                status="Success", result=envelope,
                meta=EnvelopeMeta(tool_id=tool_id, transport="in_process"),
            )
        meta = EnvelopeMeta(
            tool_id=tool_id or str(envelope.get("tool_id") or "unknown"),
            transport=str(envelope.get("_transport", "in_process")),
            degraded=bool(envelope.get("degraded", False)),
            extra={
                k: v for k, v in envelope.items()
                if k not in {"status", "result", "stdout", "error", "_elapsed_s", "_provenance", "degraded", "degraded_reason"}
            },
        )
        prov = envelope.get("_provenance")
        return cls(
            status=str(envelope.get("status", "Success")),
            result=envelope.get("result"),
            stdout=envelope.get("stdout"),
            error=envelope.get("error"),
            elapsed_s=float(envelope.get("_elapsed_s", 0.0)),
            meta=meta,
            provenance=Provenance(**prov) if isinstance(prov, dict) else None,
        )

    def to_legacy(self) -> Dict[str, Any]:
        """Mirror the current transport envelope so old readers (kernel
        helpers, tests, gateway consumers) stay green during the migration."""
        out: Dict[str, Any] = {"status": self.status}
        if self.result is not None or ("result" in (self.__fields_set__ or set())):
            out["result"] = self.result
        if self.stdout is not None:
            out["stdout"] = self.stdout
        if self.error is not None:
            out["error"] = self.error
        if self.elapsed_s:
            out["_elapsed_s"] = self.elapsed_s
        if self.provenance is not None:
            out["_provenance"] = self.provenance.model_dump()
        if self.meta.degraded:
            out["degraded"] = True
        extra = self.meta.extra
        if extra and all(k in out for k in ("status", "result")):
            for k, v in extra.items():
                out.setdefault(k, v)
        return out


__all__ = ["ToolManifest", "Finding", "Unknown",
           "ExecutionEnvelope", "EnvelopeMeta", "Provenance", "BudgetDirective"]
