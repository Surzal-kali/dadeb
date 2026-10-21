"""Tool discovery and semantic registry API.

Owns the configuration constants, the Ollama embedding function and the
:class:`ToolRegistry` — the ChromaDB-backed inventory of tool manifests plus
discovery/embedding/search. Execution behaviour is mixed in from
:mod:`daharness.executor` and the secretary agent loop from
:mod:`daharness.agent`, so this module stays focused on the registry itself.
"""

import ast
import importlib
import inspect
import json
import logging
import os
import sys
import threading

from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

import chromadb
import httpx
from chromadb.utils import embedding_functions
from pydantic import ValidationError

from constants import TransportType, resolve_framework_root

from ._param_docs import parse_param_docs, annotation_to_schema_type, annotation_to_schema_extras
from .tool_tags import resolve_tags, tagged_doc
from .models import ToolManifest
from .executor import ExecutorMixin
from .agent import (
    SecretaryMixin,
    _cli_confirmer,
)

# --- Setup Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# --- Configuration ---
# Ollama endpoint: defaults to the local Ollama daemon. Both forms are
# accepted and normalized here: "http://host:11434" (native) and
# "http://host:11434/v1" (OpenAI-compatible). The normalized "/v1" value is
# what pydantic-ai's OllamaProvider requires (it posts <base>/chat/completions)
# while the API-path consumers (embeddings, memory, REPL ghost text) strip the
# "/v1" themselves. Set OLLAMA_BASE_URL in .env to override (loopback or LAN
# only — see README Legal Addendum; cloud LLM APIs leak target data).
# Re-index after changing it.
_OLLAMA_BASE_RAW = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1").rstrip(
    "/"
)
if not _OLLAMA_BASE_RAW.endswith("/v1"):
    OLLAMA_BASE_URL = _OLLAMA_BASE_RAW + "/v1"
    logger.info(
        "OLLAMA_BASE_URL was set without the /v1 suffix (%s) — normalized to %s "
        "(the OpenAI-compatible endpoint pydantic-ai requires).",
        _OLLAMA_BASE_RAW,
        OLLAMA_BASE_URL,
    )
else:
    OLLAMA_BASE_URL = _OLLAMA_BASE_RAW
if "OLLAMA_BASE_URL" not in os.environ:
    logger.warning(
        "OLLAMA_BASE_URL is not set — using the default %s. Set it in .env "
        "(copy .env.example to .env) if your Ollama daemon runs elsewhere.",
        OLLAMA_BASE_URL,
    )
CHROMA_HOST = os.getenv("CHROMA_HOST", "localhost")
CHROMA_PORT = int(os.getenv("CHROMA_PORT", "9000"))
# --- tool-discovery roots (code checkout, NOT the state root) ---------------
# Discovery (index, REPL, kernel walker) hangs off the CODE checkout — the
# deb system profile pins WORKSPACE_ROOT to the state dir (/var/lib/daharness)
# where no tool code lives, which minted 0 tools (observed 2026-10-20, see
# resolve_framework_root()). The Brain sidecar independently scans the same
# tree via its own _FRAMEWORK_ROOT, so both walkers agree by construction.
FRAMEWORK_ROOT = resolve_framework_root()
ALLOWED_TOOL_ROOTS = [
    (FRAMEWORK_ROOT / "auxiliaries").resolve(),
    (FRAMEWORK_ROOT / "payloads").resolve(),
    (FRAMEWORK_ROOT / "listeners").resolve(),
    (FRAMEWORK_ROOT / "utils").resolve(),
    (FRAMEWORK_ROOT / "encoders").resolve(),
    (FRAMEWORK_ROOT / "evasion").resolve(),
]

# Semantic top_k ceiling — bound to the API/MCP search lanes (find_tools
# clamps per-request top_k with this), NOT the secretary chat loop.
SECRETARY_MAX_TOP_K = 10
# Router abstention: with no human in the loop, the API dispatch path
# refuses to run anything whose semantic match is not this close.
# Distance is chromadb L2 on nomic-embed-text normalized vectors
# (0 = identical). 1.1 calibrated live: good matches ~0.3-0.9.
ROUTER_MAX_DISTANCE = float(os.getenv("ROUTER_MAX_DISTANCE", "1.1"))
# Turn wall-clock cap — MCP/semantic dispatch semantics.
SECRETARY_TURN_TIMEOUT = float(os.getenv("SECRETARY_TURN_TIMEOUT", "600"))  # 10 min
# NOTE: SECRETARY_MODEL and SECRETARY_MAX_APPROVAL_ROUNDS used to be module
# knobs here and were removed — daemon-mode bootstrap cannot run the chat
# loop at all, so there is no secretary model to read from env. The chat
# lanes (dev REPL) carry their own in-code defaults where they still run.
_SECRETARY_MODEL_DEFAULT = "ornith-1.5:35b"


# --- Ollama Embedding Function ---
# Embed model knob — the bring-your-own-model contract ($EMBED_MODEL in .env),
# same convention as utils/memory_tools.py's _EMBED_MODEL. Default stays
# nomic-embed-text; re-index (python -m daharness.core) after a change.
_EMBED_MODEL = os.getenv("EMBED_MODEL", "nomic-embed-text")


class OllamaEmbeddingFunction(embedding_functions.EmbeddingFunction):
    def __init__(
        self, model_name: str = _EMBED_MODEL, base_url: str = OLLAMA_BASE_URL
    ):
        self.model_name = model_name
        self.base_url = base_url.rstrip("/v1")
        self.embed_url = f"{self.base_url}/api/embed"

    async def __call__(self, texts: List[str]) -> List[List[float]]:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                self.embed_url,
                json={"model": self.model_name, "input": texts},
            )
            response.raise_for_status()
            payload = response.json()
            if "embeddings" in payload:
                return payload["embeddings"]
            raise ValueError(f"Unexpected Ollama embedding response: {payload}")

    def name(self) -> str:
        return self.model_name


# --- Tool Registry ---
class ToolRegistry(ExecutorMixin, SecretaryMixin):
    def __init__(
        self,
        embedding_model: OllamaEmbeddingFunction,
        rpc_servers: Optional[Dict[str, str]] = None,
        secretary_model: Optional[str] = None,
        confirmer: Optional[Callable[[Dict[str, Any]], Any]] = None,
    ):
        self.embedding_model = embedding_model
        self.rpc_registry = rpc_servers or {}
        self.client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
        self.collection = self.client.get_or_create_collection(
            name="tool_inventory",
            metadata={"hnsw:space": "cosine"},
            embedding_function=self.embedding_model,
        )
        self.secretary_model = secretary_model or _SECRETARY_MODEL_DEFAULT
        # Human-in-the-loop gate for executions. Sync or async callables that
        # take a full-metadata summary dict and return a truthy value to approve.
        self.confirmer = confirmer or _cli_confirmer
        # Headless lanes (gateway/MCP/daemon boot) never run the chat loop;
        # an eager agent build made pydantic-ai a BOOT dependency of every
        # ToolRegistry construction. Built on first use instead (the
        # SecretaryMixin.secretary property); assign a test double to
        # replace it.
        self._secretary: Optional[Any] = None
        # Lazily-created class instances for in-process launches of
        # @framework_tool methods (e.g. MetasploitClient, SMBScanner).
        # One instance per class per registry, so stateful clients keep
        # their process/handles across calls.
        self._tool_instances: Dict[str, Any] = {}
        # Brain session-id mapping. The Brain wire protocol carries session_id
        # as a C int; non-numeric caller ids (agent_id / secretary session) are
        # mapped to stable unique ints here so concurrent agents get isolated
        # Brain sessions (and thus isolated stateful tool instances on the
        # sidecar) instead of all sharing session 0. ``"0"`` is the default
        # shared session.
        self._brain_session_map: Dict[str, int] = {}
        self._next_brain_session: int = 1
        self._brain_session_lock = threading.Lock()

        # Removed automatic background bootstrap to avoid race conditions
        # and duplicate indexing when called explicitly from bootstrap.py

    @staticmethod
    def _ensure_valid_manifest(manifest: Any) -> ToolManifest:
        try:
            result = ToolManifest.from_output(manifest)
            if isinstance(result, list):
                raise ValueError("Expected a single ToolManifest, got a list")
            return result
        except ValidationError as exc:
            raise ValueError(f"Invalid ToolManifest payload: {exc}") from exc

    @staticmethod
    def _resolve_script_path(script_path: Union[str, Path]) -> Path:
        candidate = Path(script_path)
        if not candidate.is_absolute():
            candidate = (FRAMEWORK_ROOT / candidate).resolve()
        candidate = candidate.resolve()

        allowed = any(
            try_path == candidate or str(candidate).startswith(str(try_path) + os.sep)
            for try_path in ALLOWED_TOOL_ROOTS
        )
        if not allowed:
            raise ValueError(
                f"Script path is outside the allowed tool roots: {script_path}"
            )
        return candidate

    async def _embed_text(self, text: str):
        """Use Ollama's native embedding endpoint for $EMBED_MODEL (default nomic-embed-text).

        pydantic_ai's OllamaModel is a chat model wrapper, not a direct embedding client.
        The embedding model must be called via the Ollama API endpoint.

        Derives the embed endpoint from OLLAMA_BASE_URL by stripping /v1 suffix.
        """
        if hasattr(self.embedding_model, "embed_query"):
            implementation = getattr(type(self.embedding_model), "__dict__", {}).get(
                "__call__"
            )
            if implementation is not None and not inspect.iscoroutinefunction(
                implementation
            ):
                closure = getattr(implementation, "__closure__", ()) or ()
                for cell in closure:
                    candidate = cell.cell_contents
                    if inspect.iscoroutinefunction(candidate):
                        implementation = candidate
                        break
            if implementation is not None and inspect.iscoroutinefunction(
                implementation
            ):
                embedding = implementation(self.embedding_model, [text])
                embedding = await embedding
                return embedding[0]

            embedding = self.embedding_model.embed_query(text)
            return await embedding if inspect.isawaitable(embedding) else embedding

        embed = getattr(self.embedding_model, "embed", None)
        if callable(embed):
            embedding = embed(text)
            return await embedding if inspect.isawaitable(embedding) else embedding

        # Strip /v1 suffix from OLLAMA_BASE_URL to get the base endpoint
        embed_base = OLLAMA_BASE_URL.rstrip("/")
        if embed_base.endswith("/v1"):
            embed_base = embed_base[:-3]

        embed_url = f"{embed_base}/api/embed"

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                embed_url,
                json={
                    "model": _EMBED_MODEL,
                    "input": text,
                },
            )
            response.raise_for_status()
            payload = response.json() or {}

        if "embedding" in payload:
            return payload["embedding"]
        if "embeddings" in payload:
            embedding = payload["embeddings"]
            if (
                isinstance(embedding, list)
                and embedding
                and isinstance(embedding[0], list)
            ):
                return embedding[0]
            return embedding

        raise ValueError(f"Unexpected Ollama embedding response: {payload}")

    async def register_tool(self, manifest: Union[ToolManifest, List[ToolManifest]]):
        manifests = manifest if isinstance(manifest, list) else [manifest]
        results = []
        for m in manifests:
            m = self._ensure_valid_manifest(m)

            if m.transport == TransportType.LOCAL_FILE:
                m.implementation_path = str(
                    self._resolve_script_path(m.implementation_path)
                )
            existing = self.collection.get(
                ids=[m.module_id], include=["documents", "metadatas"]
            )
            if existing and existing.get("ids"):
                old_doc = (existing.get("documents") or [""])[0] or ""
                old_meta = (existing.get("metadatas") or [{}])[0] or {}
                new_meta_json = json.dumps(m.parameters or {})
                new_kinds_json = json.dumps(list(m.accepted_handle_kinds or []))
                new_next_json = json.dumps(list(m.next or []))
                new_untrusted = json.dumps(bool(m.untrusted_target))
                unchanged = (
                    old_doc == m.internal_semantic_capability
                    and str(old_meta.get("implementation_path", "")) == m.implementation_path
                    and old_meta.get("transport") == m.transport.value
                    and old_meta.get("parameters_json") == new_meta_json
                    and old_meta.get("accepted_handle_kinds") == new_kinds_json
                    and old_meta.get("next_hints") == new_next_json
                    and old_meta.get("untrusted_target") == new_untrusted
                )
                if unchanged:
                    continue
                # Definition changed (doc/args/transport/path): drop the stale
                # vector so the re-embed below refreshes it.
                logger.info(
                    f"[register] Tool '{m.module_id}' changed; re-embedding"
                )
                self.collection.delete(ids=[m.module_id])

            vector = await self._embed_text(m.internal_semantic_capability)
            self.collection.add(
                ids=[m.module_id],
                embeddings=[vector],
                metadatas=[
                    {
                        "internal_semantics": m.internal_semantics,
                        "external_description": m.external_sanitized_description,
                        "implementation_path": m.implementation_path,
                        "transport": m.transport.value,
                        "parameters_json": json.dumps(m.parameters or {}),
                        # Typed handle kinds (Layer 1).  Stored as a JSON list
                        # so the secretary can validate handle args against the
                        # tool's accepted namespaces after a re-index.
                        "accepted_handle_kinds": json.dumps(
                            list(m.accepted_handle_kinds or [])
                        ),
                        "next_hints": json.dumps(list(m.next or [])),
                        "tags_json": json.dumps(list(m.tags or [])),
                        "untrusted_target": json.dumps(bool(m.untrusted_target)),
                    }
                ],
                documents=[m.internal_semantic_capability],
            )
            results.append(m.module_id)
        return results

    def extract_module_profile(self, path: Path) -> dict:
        """Static, execution-free profile of a Python module: docstring + argparse options.

        Parses with `ast` only — never imports the module, so hostile or broken
        code can't run at bootstrap time. Defensive by design: any module that
        fails to parse yields an empty profile instead of killing the scan.
        """
        profile = {"docstring": "", "options": []}
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except (SyntaxError, ValueError, OSError) as exc:
            logger.debug(f"[profile] Could not parse {path}: {exc}")
            return profile

        profile["docstring"] = ast.get_docstring(tree) or ""

        # Modules may opt OUT of the static LOCAL_FILE mint with
        # ``_NO_LOCAL_TOOL = True`` (any assignment targeting that name):
        # module-level argparse that is INTERNAL plumbing (job subprocess
        # runners, not a secretary CLI contract) would otherwise be minted
        # as a second, gate-bypassing entry point beside its own decorated
        # tools.  Decorated @framework_tool members still mint normally.
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                if any(isinstance(t, ast.Name) and t.id == "_NO_LOCAL_TOOL"
                       for t in node.targets):
                    profile["_no_local_tool"] = True
                    break
            elif isinstance(node, ast.AnnAssign) and isinstance(
                    node.target, ast.Name) and node.target.id == "_NO_LOCAL_TOOL":
                profile["_no_local_tool"] = True
                break

        def _add_argument_call(node: ast.Call) -> bool:
            fn = node.func
            return (isinstance(fn, ast.Attribute) and fn.attr == "add_argument") or (
                isinstance(fn, ast.Name) and fn.id == "add_argument"
            )

        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and _add_argument_call(node)):
                continue

            # Flag strings: prefer the long form ("--target") over short ("-t").
            constants = [
                a.value
                for a in node.args
                if isinstance(a, ast.Constant) and isinstance(a.value, str)
            ]
            if not constants:
                continue
            longs = [c for c in constants if c.startswith("--")]
            raw = longs[0] if longs else constants[0]

            # Pull kwargs we care about.
            kw = {k.arg: k.value for k in node.keywords if k.arg}

            def const_str(key: str) -> Optional[str]:
                v = kw.get(key)
                return (
                    v.value
                    if isinstance(v, ast.Constant) and isinstance(v.value, str)
                    else None
                )

            def const_bool(key: str) -> bool:
                v = kw.get(key)
                return isinstance(v, ast.Constant) and v.value is True

            # Name: explicit dest wins, else the flag with dashes stripped.
            dest = const_str("dest")
            if dest:
                name = dest
            elif raw.startswith("-"):
                name = raw.lstrip("-").replace("-", "_")
            else:
                name = raw  # positional argument

            # Type inference: action= first, then type=, else string.
            action = const_str("action") or ""
            if action in {"store_true", "store_false", "count"}:
                py_type = "boolean"
            else:
                t = kw.get("type")
                t_name = getattr(t, "id", None) or getattr(
                    getattr(t, "value", None), "id", ""
                )
                py_type = {"int": "integer", "float": "number", "bool": "boolean"}.get(
                    t_name, "string"
                )

            positional = not raw.startswith("-")
            profile["options"].append(
                {
                    "name": name,
                    "flag": raw,
                    "type": py_type,
                    "help": const_str("help") or "",
                    # Positionals are required unless nargs='?'; keep the '?' edge case simple for now.
                    "required": positional or const_bool("required"),
                }
            )

        return profile

    def discover_local_tools(
        self, root: Optional[str | Path] = None, include_tests: bool = False
    ):
        """Discover Python modules and mint ToolManifests from their docstrings/argparse.

        This now performs a two-pass scan:
        1. Static analysis of argparse modules (LOCAL_FILE).
        2. Dynamic import of functions decorated with @framework_tool (BRAIN_DISPATCH).
        """
        target_root = Path(root) if root is not None else FRAMEWORK_ROOT
        target_root = target_root.resolve()

        skip_dirs = {
            "venv",
            ".venv",
            "env",
            "ENV",
            "node_modules",
            ".git",
            "__pycache__",
            ".pytest_cache",
            ".tox",
            "build",
            "dist",
        }

        skip_files = {
            "bootstrap.py",
            "daharness.py",
            "memories.py",
            "owui-tool.py",
        }

        manifests = []
        for base in ALLOWED_TOOL_ROOTS:
            if not base.exists():
                continue
            for path in sorted(base.rglob("*.py")):
                if any(part in skip_dirs for part in path.parts):
                    continue
                if path.name in skip_files:
                    continue
                if not path.is_file():
                    continue
                if path.name.startswith("__") and path.name.endswith("__.py"):
                    continue
                if path.name == "daharness.py":
                    continue
                if not include_tests and "tests" in path.parts:
                    continue

                rel_path = path.relative_to(FRAMEWORK_ROOT)

                # --- PASS 1: Static Analysis (LOCAL_FILE) ---
                profile = self.extract_module_profile(path)
                # Only index as a LOCAL_FILE tool if the module has BOTH a
                # docstring (embedding text) AND at least one argparse option
                # (i.e. it's actually a CLI script). A docstring with no
                # add_argument calls means it's a library module (e.g.
                # utils.session_manager, utils.paramiko_client) whose large
                # module-level docstring pollutes the vector space with
                # non-tool noise.  ``_NO_LOCAL_TOOL = True`` opts out
                # entirely (see extract_module_profile).
                if profile.get("_no_local_tool"):
                    pass  # skip the static mint; PASS 2 still runs
                elif profile["docstring"] and profile["options"]:
                    # Use the module's top-level docstring as the capability
                    # map the argparse options to parameters
                    params = {"type": "object", "properties": {}}
                    required = []
                    for opt in profile["options"]:
                        params["properties"][opt["name"]] = {
                            "type": opt["type"],
                            "description": opt["help"]
                        }
                        if opt["required"]:
                            required.append(opt["name"])
                    params["required"] = required

                    module_id = rel_path.with_suffix("").as_posix().replace("/", ".")
                    manifests.append(
                        ToolManifest(
                            module_id=module_id,
                            internal_semantic_capability=profile["docstring"],
                            external_sanitized_description=profile["docstring"],
                            parameters=params,
                            implementation_path=str(rel_path),
                            internal_semantics=f"Static argparse module: {module_id}",
                            transport=TransportType.LOCAL_FILE,
                        )
                    )

                # --- PASS 2: Dynamic Analysis (BRAIN_DISPATCH) ---
                try:
                    # Ensure root is in path for the import to work
                    if str(FRAMEWORK_ROOT) not in sys.path:
                        sys.path.insert(0, str(FRAMEWORK_ROOT))

                    module_name = rel_path.with_suffix("").as_posix().replace("/", ".")
                    mod = importlib.import_module(module_name)

                    # Candidates: (tool_id, function, is_method)
                    candidates: List[tuple] = []
                    for name, obj in inspect.getmembers(mod):
                        # Module-level @framework_tool functions — only those
                        # DEFINED in this module, not imported from elsewhere.
                        # The __module__ guard prevents re-minting an imported
                        # @framework_tool under the wrong module_id (e.g.
                        # remember_text imported into utils/findings.py being
                        # registered as utils.findings.remember_text).
                        if (inspect.isfunction(obj)
                                and getattr(obj, "_is_framework_tool", False)
                                and obj.__module__ == module_name):
                            candidates.append((f"{module_name}.{name}", obj, False))
                        # @framework_tool METHODS on classes defined in THIS module.
                        # The __module__ guard stops imported classes from being
                        # re-minted under the wrong module_id.
                        elif inspect.isclass(obj) and obj.__module__ == module_name:
                            for m_name, m_obj in inspect.getmembers(obj, inspect.isfunction):
                                if getattr(m_obj, "_is_framework_tool", False):
                                    candidates.append(
                                        (
                                            f"{module_name}.{obj.__name__}.{m_name}",
                                            m_obj,
                                            True,
                                        )
                                    )

                    for tool_id, func, is_method in candidates:
                        doc = getattr(func, "_tool_doc", "No description")

                        # Category tags (daharness/tool_tags.py): decorator
                        # tags win, the bulk TOOL_TAGS map fills the rest.
                        # The tags are appended to the doc ("Categories: ...")
                        # BEFORE embedding so category keywords match
                        # semantically, and carried on the manifest so they
                        # persist in ChromaDB metadata + describe_manifest.
                        tags = resolve_tags(
                            tool_id,
                            getattr(func, "_tool_tags", ()) or (),
                            warn=logger.warning,
                        )
                        if tags:
                            doc = tagged_doc(doc, tags)

                        # Extract per-parameter descriptions from the function
                        # docstring (Google/NumPy Args: sections) and type
                        # annotations so the manifest schema is informative
                        # instead of generic "Parameter X" placeholders.
                        param_docs = parse_param_docs(func)

                        # Build parameter schema from the function signature,
                        # using type annotations for JSON Schema types and
                        # docstring-derived descriptions. Annotation extras
                        # (e.g. Literal -> enum) are merged in so the model
                        # sees the full constraint set, not just the type.
                        sig = inspect.signature(func)
                        params = {"type": "object", "properties": {}}
                        required = []
                        for idx, (p_name, p_param) in enumerate(sig.parameters.items()):
                            if is_method and idx == 0 and p_name in ("self", "cls"):
                                continue  # bound at launch time via a class instance
                            p_type = annotation_to_schema_type(p_param.annotation)
                            prop_def: Dict[str, Any] = {
                                "type": p_type,
                                "description": param_docs.get(
                                    p_name, f"Parameter {p_name}"
                                ),
                            }
                            extras = annotation_to_schema_extras(p_param.annotation)
                            if extras:
                                prop_def.update(extras)
                            params["properties"][p_name] = prop_def
                            if p_param.default is inspect.Parameter.empty:
                                required.append(p_name)
                        params["required"] = required

                        semantics = (
                            f"Brain-dispatched method: {tool_id} (launched in-process via class instance)"
                            if is_method
                            else f"Brain-dispatched function: {tool_id}"
                        )
                        # Respect the transport set by @framework_tool instead
                        # of hardcoding BRAIN_DISPATCH. The decorator stores it
                        # on _transport; default to BRAIN_DISPATCH if missing.
                        tool_transport = getattr(
                            func, "_transport", TransportType.BRAIN_DISPATCH
                        )
                        # Typed session handle kinds this tool consumes (Layer 1).
                        # Stored on the manifest so the secretary can validate
                        # any `handle` arg against the tool's accepted namespaces
                        # before execution (prevents cross-namespace calls like
                        # passing an msf: handle to an ssh_exec tool).
                        handle_kinds = getattr(func, "_accepted_handle_kinds", ()) or ()
                        next_hints = getattr(func, "_next_hints", ()) or ()
                        # Result projection: register the per-tool digest
                        # adapter (if set via @framework_tool(...,
                        # result_digest=fn)) under the EXACT tool_id.  The
                        # decorator registers a provisional key at import
                        # time; this re-registers under the discovery-
                        # constructed tool_id so the projection layer finds
                        # it by the id the model actually calls.
                        result_digest_fn = getattr(func, "_result_digest", None)
                        result_digest_ref = None
                        if callable(result_digest_fn):
                            result_digest_ref = getattr(
                                result_digest_fn, "__qualname__",
                                result_digest_fn.__name__,
                            )
                            try:
                                from utils.result_projection import (
                                    register_digest_adapter as _reg_digest,
                                )
                                _reg_digest(tool_id, result_digest_fn)
                            except ImportError:
                                pass
                        # Untrusted-target provenance (REA's
                        # returnsTargetContent contract): tools whose results
                        # embed analysis-target content get their result
                        # envelopes stamped by the executor, and the flag is
                        # surfaced in the manifest so the secretary sees it.
                        untrusted_target = bool(
                            getattr(func, "_untrusted_target", False)
                        )
                        manifests.append(
                            ToolManifest(
                                module_id=tool_id,
                                internal_semantic_capability=doc,
                                external_sanitized_description=doc,
                                parameters=params,
                                implementation_path=tool_id,
                                internal_semantics=semantics,
                                transport=tool_transport,
                                accepted_handle_kinds=tuple(handle_kinds),
                                next=list(next_hints),
                                tags=tags,
                                result_digest_ref=result_digest_ref,
                                untrusted_target=untrusted_target,
                            )
                        )
                except Exception as e:
                    logger.error(f"[discovery] Dynamic scan failed for {rel_path}: {e}", exc_info=True)

        return manifests

    # add to the imports at the top

    async def bootstrap_registry(
        self, root: Optional[str | Path] = None, include_tests: bool = False
    ):
        """Discover local tools and ingest tools from known MCP servers."""
        # Discover and register local tools
        discovered = self.discover_local_tools(root=root, include_tests=include_tests)
        print(
            f"[bootstrap] Discovered {len(discovered)} Python modules to embed and register..."
        )
        for i, manifest in enumerate(discovered, 1):
            print(f"[{i}/{len(discovered)}] Registering {manifest.module_id}...")
            await self.register_tool(manifest)
        total = len(self.collection.get(include=[]).get("ids", []))
        print(f"[bootstrap] Complete! Total tools registered: {total}")
        return total

    async def find_tool_by_id(self, tool_id: str) -> Optional[ToolManifest]:
        """Retrieve a tool manifest by its module_id."""
        if not tool_id or not tool_id.strip():
            return None

        existing = self.collection.get(
            ids=[tool_id], include=["metadatas", "documents"]
        )
        if not existing or not existing.get("ids"):
            return None

        meta = (existing.get("metadatas") or [{}])[0]
        doc = (existing.get("documents") or [{}])[0]

        return ToolManifest(
            module_id=tool_id,
            internal_semantic_capability=str(doc),
            external_sanitized_description=str(meta.get("external_description", "")),
            implementation_path=str(meta.get("implementation_path", "")),
            parameters=self._safe_parse_params(meta.get("parameters_json", "{}")),
            internal_semantics=str(meta.get("internal_semantics", "")),
            transport=TransportType(
                meta.get("transport", TransportType.LOCAL_FILE.value)
            ),
            accepted_handle_kinds=self._safe_parse_kinds(
                meta.get("accepted_handle_kinds")
            ),
            next=list(self._safe_parse_kinds(meta.get("next_hints"))),
            tags=self._safe_parse_kinds(meta.get("tags_json")),
            untrusted_target=str(meta.get("untrusted_target", "false")).lower()
            in ("true", "1", "yes"),
        )

    def _safe_parse_tool_args(self, raw: Any) -> dict:
        """ToolCallPart.args may be a dict or a JSON string; normalize defensively."""
        if isinstance(raw, dict):
            return raw
        if isinstance(raw, str) and raw.strip():
            try:
                parsed = json.loads(raw)
                return parsed if isinstance(parsed, dict) else {"_raw": raw}
            except json.JSONDecodeError:
                return {"_raw": raw}
        return {}

    def _safe_parse_params(self, raw: Any) -> dict:
        if isinstance(raw, dict):
            return raw  # in case chroma ever hands it back as a dict
        try:
            parsed = json.loads(raw) if raw else {}
            return parsed if isinstance(parsed, dict) else {}
        except (json.JSONDecodeError, TypeError):
            return {}

    def _safe_parse_kinds(self, raw: Any) -> tuple:
        """Parse the ``accepted_handle_kinds`` metadata (a JSON list) back to a
        tuple.  Returns ``()`` for missing/empty/invalid values so the absence
        of the field (e.g. tools indexed before Layer 1) degrades cleanly to
        'no handle validation' rather than raising.
        """
        if raw is None:
            return ()
        if isinstance(raw, (list, tuple)):
            return tuple(str(k) for k in raw)
        try:
            parsed = json.loads(raw) if isinstance(raw, str) and raw else None
            if isinstance(parsed, list):
                return tuple(str(k) for k in parsed)
        except (json.JSONDecodeError, TypeError):
            pass
        return ()

    async def find_tools(self, user_intent: str, top_k: int = 5) -> List[ToolManifest]:
        """Semantic search using ChromaDB's HNSW index, returning up to `top_k` manifests."""
        if not user_intent or not user_intent.strip():
            return []

        intent_vector = await self._embed_text(user_intent)

        results = self.collection.query(
            query_embeddings=[intent_vector],
            n_results=max(1, top_k),
        )
        if not results or not results.get("ids") or not results["ids"][0]:
            return []

        ids = results["ids"][0]
        metadatas = results.get("metadatas") or []
        documents = results.get("documents") or []
        distances = (results.get("distances") or [[]])[0]
        if not metadatas or not documents or not metadatas[0] or not documents[0]:
            return []

        manifests: List[ToolManifest] = []
        for i, (best_id, meta, doc, dist) in enumerate(
            zip(ids, metadatas[0], documents[0], distances), 1
        ):
            if not meta or not doc:
                continue
            logger.info(
                f"[TOOL_ACTIVATION] Intent: '{user_intent}' -> Match {i}/{len(ids)}: {best_id} | Capability: {doc} | distance={dist:.4f}"
            )
            manifests.append(
                ToolManifest(
                    module_id=best_id,
                    internal_semantic_capability=doc,
                    external_sanitized_description=str(
                        meta.get("external_description", "")
                    ),
                    implementation_path=str(meta.get("implementation_path", "")),
                    parameters=self._safe_parse_params(meta.get("parameters_json")),
                    internal_semantics=str(meta.get("internal_semantics", "")),
                    transport=TransportType(
                        meta.get("transport", TransportType.LOCAL_FILE.value)
                    ),
                    accepted_handle_kinds=self._safe_parse_kinds(
                        meta.get("accepted_handle_kinds")
                    ),
                    next=list(self._safe_parse_kinds(meta.get("next_hints"))),
                    tags=self._safe_parse_kinds(meta.get("tags_json")),
                    untrusted_target=str(meta.get("untrusted_target", "false")).lower()
                    in ("true", "1", "yes"),
                    distance=round(float(dist), 4) if dist is not None else None,
                )
            )
        # T-002: Explicitly sort by distance ascending so array position ==
        # relevance order. ChromaDB's HNSW query usually returns ascending
        # order, but this is not contractually guaranteed across versions /
        # configurations; an unsorted (or worst-first) array causes agents
        # that read array position instead of the distance field to
        # mis-select the worst match.
        manifests.sort(
            key=lambda m: m.distance if m.distance is not None else float("inf")
        )
        return manifests

    async def find_best_tool(self, user_intent: str, top_k=1):
        """Best single match for an intent (kept for the direct-dispatch API path).

        Abstention gate: on the API path there is no human confirmer, so the
        router refuses to execute anything whose semantic match is not close.
        Without this the router never abstains and a vague intent resolves to
        whatever sibling happens to win the cosine tie (verified live:
        'framework health status check' ran a ZAP spider-status read).
        Returns None on no-match-or-too-far, which the gateway already
        handles as a 404. The secretary path (find_tools) is untouched:
        she sees fuzzy candidates plus a human confirmer, so she judges.
        """
        manifests = await self.find_tools(user_intent, top_k=top_k)
        if not manifests:
            return None
        best = manifests[0]
        if best.distance is not None and best.distance > ROUTER_MAX_DISTANCE:
            logger.info(
                f"[TOOL_ACTIVATION] Abstaining: best distance {best.distance} > "
                f"ROUTER_MAX_DISTANCE {ROUTER_MAX_DISTANCE} for intent '{user_intent}'"
            )
            return None
        logger.info(
            f"[TOOL_ACTIVATION] Accepted: distance {best.distance} for intent "
            f"'{user_intent}' -> tool '{best.module_id}'"
        )
        return best

    def describe_manifest(self, manifest: ToolManifest, lean: bool = False) -> Dict[str, Any]:
        """Full (non-sanitized) view of a manifest for the secretary and the confirmer.

        When lean=True, returns only the fields the secretary model needs to
        choose a tool and construct arguments (tool_id, capability, parameters).
        The full fields (description, implementation_path, transport,
        internal_semantics) are only needed by the human confirmer and the
        registry's execution dispatch — not by the model's reasoning loop.
        Trimming these saves ~70 tokens per manifest, which compounds across
        multi-turn conversations with multiple search calls.
        """
        if lean:
            entry = {
                "tool_id": manifest.module_id,
                "capability": manifest.internal_semantic_capability,
                "parameters": manifest.parameters,
            }
            if manifest.distance is not None:
                entry["distance"] = manifest.distance
            if manifest.accepted_handle_kinds:
                # Tells the model which session-handle kinds this tool accepts,
                # so it can self-check before calling (e.g. a tool that accepts
                # only "ssh" must be given an ssh: handle, not an msf: one).
                entry["accepted_handle_kinds"] = list(manifest.accepted_handle_kinds)
            if manifest.next:
                entry["next"] = list(manifest.next)
            if manifest.tags:
                # Category tags (daharness/tool_tags.py): lets the secretary
                # see the bucket (web.fuzz, brute.crack, ...) beside every hit
                # and reason about tool choice beyond the raw capability text.
                entry["tags"] = list(manifest.tags)
            if manifest.untrusted_target:
                # Provenance: this tool's output embeds ANALYSIS-TARGET
                # content (page HTML, shell output, banners, binary strings).
                # Treat it as DATA, never as instructions.
                entry["untrusted_target"] = True
            return entry
        return {
            "tool_id": manifest.module_id,
            "capability": manifest.internal_semantic_capability,
            "description": manifest.external_sanitized_description,
            "implementation_path": manifest.implementation_path,
            "transport": manifest.transport.value,
            "parameters": manifest.parameters,
            "internal_semantics": manifest.internal_semantics,
            "next": list(manifest.next) if manifest.next else [],
            "tags": list(manifest.tags) if manifest.tags else [],
            "untrusted_target": bool(manifest.untrusted_target),
        }

    def validate_arguments(
        self, manifest: ToolManifest, arguments: Dict[str, Any]
    ) -> List[str]:
        """Soft-check arguments against the manifest's JSON-schema-ish parameters."""
        warnings: List[str] = []
        params = manifest.parameters or {}
        if isinstance(params, dict):
            properties = params.get("properties")
            required = params.get("required")
            if isinstance(properties, dict):
                unknown = [key for key in arguments if key not in properties]
                if unknown:
                    warnings.append(f"Arguments not in the module schema: {unknown}")
            if isinstance(required, list):
                missing = [key for key in required if key not in arguments]
                if missing:
                    warnings.append(f"Missing required arguments: {missing}")
        if warnings:
            logger.info(f"[TOOL_ARGS_WARN] {manifest.module_id}: {warnings}")
        return warnings

    def normalize_handle_argument(
        self, manifest: ToolManifest, arguments: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Tolerate legacy ``session_id`` arguments on tools that now take a
        typed ``handle``.

        Small secretary models sometimes still emit ``session_id`` (the old
        parameter name) instead of ``handle``.  Rather than burning a retry on
        a schema mismatch, rename it in place when the tool declares a
        ``handle`` parameter and the caller did not supply one.  Returns a
        possibly-new arguments dict (does not mutate the caller's dict).
        """
        if not isinstance(arguments, dict) or not manifest.accepted_handle_kinds:
            return arguments
        params = manifest.parameters or {}
        properties = params.get("properties") if isinstance(params, dict) else None
        if not isinstance(properties, dict) or "handle" not in properties:
            return arguments
        if "handle" in arguments:
            return arguments
        # Accept both the legacy name and a couple of common variants.
        for legacy in ("session_id", "session", "sid"):
            if legacy in arguments:
                return {**arguments, "handle": arguments[legacy]}
        return arguments

    def validate_handle_argument(
        self, manifest: ToolManifest, arguments: Dict[str, Any]
    ) -> Optional[str]:
        """Return ``None`` if the tool's ``handle`` argument is acceptable,
        otherwise a human-readable reason string suitable for a ``ModelRetry``.

        This is the core Layer 1 disambiguation gate: it refuses to let a
        handle from one namespace flow into a tool of another (e.g. an
        ``msf:`` handle into ``ssh_exec``), and the reason string tells the
        model which tool to use instead.
        """
        if not manifest.accepted_handle_kinds or not isinstance(arguments, dict):
            return None
        handle = arguments.get("handle")
        if not isinstance(handle, str) or not handle:
            return None
        from utils.handles import validate_handle_for_tool
        return validate_handle_for_tool(handle, manifest.accepted_handle_kinds)

    def get_sanitized_view(self, manifest: ToolManifest):
        """Returns only the opaque ID and the boring description for the main model."""
        return {
            "id": manifest.module_id,
            "description": manifest.external_sanitized_description,
        }


__all__ = ["OllamaEmbeddingFunction", "ToolRegistry"]
