"""
title: Framework Bridge (daharness gateway)
author: framework
description: Search + execute the framework's gated tool registry via the API gateway, with per-chat session isolation and framework memory access. Bug-bounty chat surface for Open Web UI.
version: 0.3.2
"""

import json
import os
import re
import time
import urllib.error
import urllib.request

from pydantic import BaseModel, Field


class Tools:
    class Valves(BaseModel):
        gateway_url: str = Field(
            default="http://open-terminal:6000",
            description="Framework gateway base URL (from inside the open-webui container use http://open-terminal:6000; from the host use http://localhost:6000).",
        )
        api_key: str = Field(
            default="",
            description="GATEWAY_API_KEY (sent as X-API-Key). Falls back to the GATEWAY_API_KEY env var if the open-webui container has it exported.",
        )
        default_top_k: int = Field(
            default=5,
            ge=1,
            le=20,
            description="Default number of candidates returned by framework_search_tools.",
        )
        request_timeout: int = Field(
            default=600,
            ge=5,
            description="Seconds to wait on the gateway before giving up (long scans: prefer the framework's terminal_exec/terminal_status pattern).",
        )

    def __init__(self):
        self.valves = self.Valves()
        if not self.valves.api_key and os.getenv("GATEWAY_API_KEY"):
            self.valves.api_key = os.getenv("GATEWAY_API_KEY")
        # Memory-namespace enumeration cache: (fetched_at, names|None).
        self._ns_cache: tuple = (0.0, None)

    # ------------------------------------------------------------------ helpers

    def _resolve_model_id(
        self, __model__: dict | None = None, md: dict | None = None
    ) -> str:
        """Running-model id for agent naming, sanitized for use as an id.
        Sources, in order: the __model__ special param (dict with 'id'),
        then __metadata__ 'model_id' / 'model'. Empty when unavailable."""
        if md is None:
            md = getattr(self, "__metadata__", None) or {}
        model_id = ""
        if isinstance(__model__, dict):
            model_id = str(__model__.get("id") or "").strip()
        if not model_id:
            raw = md.get("model_id") or md.get("model")
            if isinstance(raw, dict):
                model_id = str(raw.get("id") or "").strip()
            else:
                model_id = str(raw or "").strip()
        return re.sub(r"[^A-Za-z0-9._-]+", "_", model_id)[:48]

    def _chat_agent_id(
        self, __model__: dict | None = None, __metadata__: dict | None = None
    ) -> str:
        """Agent id for Brain session isolation. Mirrors the running model id
        (user convention: agent identity = the running model) plus the chat id,
        so parallel chats of the same model still get isolated tool state.
        Open WebUI only injects special params that are DECLARED — __model__
        carries the model, __metadata__ carries chat_id; both fall back
        (attribute read, then chat-only 'owui-<chat>' naming)."""
        md = __metadata__ or getattr(self, "__metadata__", None) or {}
        chat_id = md.get("chat_id") or md.get("id") or "0"
        model_id = self._resolve_model_id(__model__, md)
        if model_id:
            return f"owui-{model_id}-{chat_id}"
        return f"owui-{chat_id}"

    def _known_namespaces(self) -> list | None:
        """Best-effort enumeration of existing memory namespaces (cached 5 min).

        Returns None when enumeration is unavailable (list_text_namespaces not
        indexed yet, gateway hiccup) — callers must treat None as 'cannot
        verify' and proceed normally."""
        stamp, names = self._ns_cache
        now = time.time()
        if names is not None and now - stamp < 300:
            return names
        try:
            raw = self._post(
                "/tools/execute",
                {"tool_id": "utils.memory_tools.list_text_namespaces", "arguments": {}},
                timeout=15,
            )
            data = json.loads(raw)
            res = data.get("result", data) if isinstance(data, dict) else data
            inner = res.get("result", res) if isinstance(res, dict) else res
            if isinstance(inner, str):
                inner = json.loads(inner)
            if isinstance(inner, list):
                names = [str(n) for n in inner]
                self._ns_cache = (now, names)
                return names
        except Exception:
            pass
        return None

    def _request(
        self, method: str, path: str, payload: dict, timeout: int | None = None
    ) -> str:
        url = self.valves.gateway_url.rstrip("/") + path
        headers = {"Content-Type": "application/json"}
        if self.valves.api_key:
            headers["X-API-Key"] = self.valves.api_key
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8") if method == "POST" else None,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(
                req, timeout=timeout or self.valves.request_timeout
            ) as resp:
                body = json.loads(resp.read().decode("utf-8", errors="replace"))
            return json.dumps(body, indent=2, default=str)
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")[:500]
            return f"GATEWAY HTTP {e.code}: {detail}"
        except Exception as e:  # DNS failure, conn refused, timeout ...
            return (
                f"GATEWAY UNREACHABLE at {url}: {e!r}. "
                "Is the framework stack up? (dockered/up.sh; gateway on :6000)"
            )

    def _post(self, path: str, payload: dict, timeout: int | None = None) -> str:
        return self._request("POST", path, payload, timeout)

    def _get(self, path: str, timeout: int | None = None) -> str:
        return self._request("GET", path, {}, timeout)

    # ------------------------------------------------------------------- tools

    def framework_search_tools(self, intent: str, top_k: int = 0) -> str:
        """Search the framework tool registry for tools matching a natural-language
        intent (e.g. "port scan a host", "check certificate details for a domain",
        "run zap against a url"). Returns a candidate menu: tool_id, capability,
        parameters JSON schema, semantic distance, and suggested next tools.

        ALWAYS call this first and pick a tool_id from the results; then call
        framework_run_tool with that exact tool_id. Do not guess tool ids.

        :param intent: Natural-language description of what you want to do.
        :param top_k: Max candidates to return (default from valve settings).
        """
        payload = {"intent": intent}
        payload["top_k"] = top_k if top_k and top_k > 0 else self.valves.default_top_k
        return self._post("/tools/search", payload)

    def framework_run_tool(
        self,
        tool_id: str,
        arguments: str = "{}",
        agent_id: str = "",
        result_mode: str = "large",
        page_offset: int = 0,
        page_limit: int = 50,
        __model__: dict | None = None,
        __metadata__: dict | None = None,
    ) -> str:
        """Execute a framework tool by exact tool_id (from framework_search_tools).

        :param tool_id: Exact tool_id from the search menu, e.g. 'auxiliaries.nmap.nmap_scan'.
        :param arguments: JSON object string of tool arguments, matching the
            parameters schema from the search menu. Unknown keys are rejected by
            the gateway with a 422 listing accepted keys. Example:
            '{"target": "10.10.10.50", "ports": "1-1000"}'
        :param agent_id: Optional explicit Brain session id. Leave empty to
            get an isolated per-chat session, auto-named from the running
            model id + chat id (owui-<model>-<chat>), so parallel bug-bounty
            chats never share tool state. Reuse the same explicit value
            across chats to deliberately share state.
        :param result_mode: Result projection — controls what enters your
            context window. 'large' (default) returns the actual data with
            field-caps so a single response can't blow up your context —
            results under 16KB pass through unchanged; larger results are
            field-truncated and the full copy is stored in scratch
            (retrievable with framework_scratch_search). 'digest' stores the
            full result in scratch and returns a compact one-liner summary +
            a scratch_ref. 'page' returns a bounded page of list results +
            a scratch_ref. 'full' is gone (aliased to 'large') — it was an
            unbounded passthrough that could 6x a cloud model's context.
        :param page_offset: Page offset (page mode only).
        :param page_limit: Page size cap (page mode only, default 50).
        """
        try:
            args = json.loads(arguments or "{}")
            if not isinstance(args, dict):
                return "ERROR: 'arguments' must be a JSON object string, e.g. '{\"target\": \"10.10.10.50\"}'"
        except json.JSONDecodeError as e:
            return f"ERROR: 'arguments' is not valid JSON ({e}). Pass a JSON object string."
        payload = {"tool_id": tool_id, "arguments": args}
        payload["agent_id"] = agent_id or self._chat_agent_id(__model__, __metadata__)
        payload["result_mode"] = result_mode or "large"
        if result_mode and result_mode.lower() == "page":
            payload["page_offset"] = page_offset
            payload["page_limit"] = page_limit
        # Per-turn tool budget key: Open WebUI passes 'message_id' in
        # __metadata__ on newer builds, so every user message gets a fresh
        # budget of framework tool executions. On older builds it is absent
        # and the gateway falls back to a rolling idle-TTL counter per chat.
        md = __metadata__ or getattr(self, "__metadata__", None) or {}
        chat = md.get("chat_id") or md.get("id")
        message_id = md.get("message_id")
        if chat:
            payload["turn_key"] = f"{chat}:{message_id}" if message_id else str(chat)
        return self._post("/tools/execute", payload)

    def framework_scratch_search(
        self,
        scratch_ref: str,
        agent_id: str = "",
        offset: int = 0,
        limit: int = 0,
        filter: str = "",
        regex: str = "",
        fields: str = "",
        context_lines: int = 0,
        __model__: dict | None = None,
        __metadata__: dict | None = None,
    ) -> str:
        """Retrieve the full or filtered output of a prior tool call whose
        result_mode was 'large'/'digest'/'page'. The scratch_ref comes from the
        result envelope of a framework_run_tool call.

        **Important**: retrieved payloads are field-capped the same way as
        large-mode tool results — a 1.6MB JS file enters your context as
        ~16KB of capped fields, NOT the full payload. To pull specific
        content from a large result, use one of these parameters instead of
        retrieving the full payload:

        - **filter**: case-insensitive substring that greps long text fields
          (HTML bodies, logs) line-by-line AND narrows list items. E.g.
          ``filter='csrf'`` pulls only lines containing "csrf" from a 40KB
          HTML response.
        - **regex**: Python regex for pattern extraction. E.g.
          ``regex='<input[^>]*type=["\\']hidden["\\']'`` extracts all hidden
          inputs from HTML.
        - **fields**: comma-separated field names to select (drops all
          others). E.g. ``fields='body_head,http_status'`` for just the
          response body and status code.
        - **context_lines**: N lines of context around each grep match
          (like ``grep -C``).

        All filters run server-side on the stored data before it enters
        your context.

        :param scratch_ref: The scratch:<hex> reference from a prior result.
        :param agent_id: Leave empty to use this chat's auto-derived agent id
            (must match the agent_id used for the original framework_run_tool call).
        :param offset: Skip the first N items in list-bearing results.
        :param limit: Return at most N items (0 = no limit; use sparingly).
        :param filter: Case-insensitive substring — greps text fields
            line-by-line and narrows list items.
        :param regex: Python regex applied to text fields (line-by-line)
            and list items. Use for pattern extraction.
        :param fields: Comma-separated field names to select (drops others).
        :param context_lines: Lines of context around each grep match.
        """
        payload = {
            "scratch_ref": scratch_ref,
            "offset": offset,
            "limit": limit,
            "context_lines": context_lines,
        }
        if filter:
            payload["filter"] = filter
        if regex:
            payload["regex"] = regex
        if fields:
            payload["fields"] = fields
        payload["agent_id"] = agent_id or self._chat_agent_id(__model__, __metadata__)
        # Pass turn_key so scratch_search counts against the same per-turn
        # tool budget as framework_run_tool (utils/tool_budget.py).
        md = __metadata__ or getattr(self, "__metadata__", None) or {}
        chat = md.get("chat_id") or md.get("id")
        message_id = md.get("message_id")
        if chat:
            payload["turn_key"] = f"{chat}:{message_id}" if message_id else str(chat)
        return self._post("/scratch/search", payload)

    def framework_memory_search(
        self, query_text: str, namespace: str, agent_id: str = ""
    ) -> str:
        """Semantic (vector) search over the framework's memory service. Your
        query is embedded (nomic-embed-text) and matched by vector similarity,
        searching the shared pool across all agents by default.

        Use it to recall what the framework already knows about a
        program/surface before re-running work.

        :param query_text: What to look for, e.g. 'grindr certificate pinning phase 0 results'.
        :param namespace: Memory namespace to search — REQUIRED, non-empty
            (e.g. 'engagement', 'ops', 'findings'). Empty namespaces are
            rejected with an error; "" is not a valid value.
        :param agent_id: Optional agent/session filter. Leave EMPTY (default) to
            search the shared pool across all agents — this is the recommended
            behavior, since most memories are written untagged or by other
            sessions. Pass an explicit value to scope results to one session.
        """
        if not str(namespace).strip():
            return (
                "ERROR: 'namespace' is required and must be non-empty "
                "(gateway rejects empty namespaces with 500). "
                "Try e.g. 'engagement', 'ops' or 'findings'."
            )
        # Typo guard: the store auto-creates unknown namespaces on write, so a
        # typo would silently return [] forever. Refuse loudly when enumeration
        # is available; proceed (degraded) when it is not.
        known = self._known_namespaces()
        if known is not None and namespace not in known:
            return (
                f"ERROR: namespace '{namespace}' does not exist. Unknown "
                "namespaces auto-create silently on write and search as []. "
                f"Known namespaces: {', '.join(known) if known else '(none)'}. "
                "Use one of those, or confirm with the user before creating "
                "a new one."
            )
        arguments = {"query": query_text, "namespace": namespace}
        if agent_id:
            arguments["agent_id"] = agent_id  # only filter when explicitly asked
        # Route through the sidecar's recall_text memory tool: /memory/search
        # is a keyword-substring filter, NOT semantic. recall_text embeds the
        # query and does true vector recall, sharing the pool across agents
        # when agent_id is omitted. The /tools/execute payload agent_id is the
        # Brain *session* id (tool-state isolation) and is intentionally NOT
        # set here — memory scoping is driven solely by the tool argument.
        return self._post(
            "/tools/execute",
            {
                "tool_id": "utils.memory_tools.recall_text",
                "arguments": arguments,
            },
        )

    def framework_health(
        self, __model__: dict | None = None, __metadata__: dict | None = None
    ) -> str:
        """Check that the framework gateway is reachable, and report this
        chat's derived agent id (self-serve diagnostic).

        No-op call: run this first if any framework_ tool errors.

        NOTE: /health is UNAUTHENTICATED by design — it answers 'is the stack
        up' fast and unambiguously (framework may be down at any time), but
        it does NOT validate the API key. A stale key passes health and then
        401s on the data tools; treat green-health + 401s as a key/config
        problem, not an outage.

        The response always includes this chat's agent_id (the
        ``owui-<model>-<chat>`` id framework_run_tool derives for Brain
        session isolation when agent_id is left empty), so the naming can be
        verified from chat, or the id reused as an explicit agent_id.
        """
        md = __metadata__ or getattr(self, "__metadata__", None) or {}
        chat_id = md.get("chat_id") or md.get("id") or "0"
        model_id = self._resolve_model_id(__model__, md)
        agent_id = f"owui-{model_id}-{chat_id}" if model_id else f"owui-{chat_id}"
        try:
            md_keys = sorted(str(k) for k in md.keys())
        except Exception:
            md_keys = []
        report = {
            "gateway": self._get("/health", timeout=10),
            "agent_id": agent_id,
            "chat_id": chat_id,
            "model_id": model_id or None,
            "model_param_received": isinstance(__model__, dict),
            "metadata_keys": md_keys,
        }
        return json.dumps(report, indent=2, default=str)
