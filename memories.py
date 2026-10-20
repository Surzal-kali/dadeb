from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Any

import chromadb

from listeners.thebrain import framework_tool

logger = logging.getLogger(__name__)

# --- forget() 3-strikes protection -------------------------------------------
# A "strike" is an attempt to delete a memory the caller isn't allowed to:
#   * an entry flagged ``important`` (protected from everyone), or
#   * an entry owned by a different agent (agent_id mismatch), or
#   * a shared-pool entry (no owner) by a scoped agent (who should only touch
#     its own entries).
# After ``MEMORY_FORGET_STRIKE_LIMIT`` strikes (default 3) the caller is locked
# out of ``forget`` for the process lifetime. State is process-global (module
# level) so it is shared across every MemoryService instance in this process
# (the secretary's ``_default_service``, the gateway's instance, etc.). The
# Brain sidecar is a separate process and does not call forget.
_FORGET_LOCK = threading.Lock()
_FORGET_STRIKES: dict[str, int] = {}
_FORGET_BANNED: set[str] = set()
_FORGET_STRIKE_LIMIT = int(os.getenv("MEMORY_FORGET_STRIKE_LIMIT", "3"))


def _is_important(metadata: dict[str, Any]) -> bool:
    """True if a memory's metadata marks it important/protected."""
    value = metadata.get("important")
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in ("1", "true", "yes", "y")


class MemoryService:
    """Persistent, namespaced vector memory for cross-harness recall."""

    def __init__(self, storage_path: str = ".memory/chroma"):
        self.storage_path = str(Path(storage_path))
        self.client = chromadb.PersistentClient(path=self.storage_path)
        self._collections: dict[str, Any] = {}
    def create_collection(self, namespace: str, embedding_model: str = "nomic-embed-text"):
        """Create a new collection for a given namespace."""
        name = self._namespace_name(namespace)
        if name in self._collections:
            raise ValueError(f"Collection for namespace '{namespace}' already exists.")
        collection = self.client.get_or_create_collection(
            name=name,
            metadata={"hnsw:space": "cosine"},
        )

        self._collections[name] = collection
        return collection
    @staticmethod
    def _normalize_session_id(session_id: str | None) -> str | None:
        if session_id is None:
            return None
        session_id = str(session_id).strip()
        return session_id or None

    def _namespace_name(self, namespace: str) -> str:
        namespace = str(namespace).strip()
        if not namespace:
            raise ValueError("namespace must be a non-empty string")
        return f"memory_{namespace}"

    def _get_collection(self, namespace: str):
        name = self._namespace_name(namespace)
        if name not in self._collections:
            self._collections[name] = self.client.get_or_create_collection(
                name=name,
                metadata={"hnsw:space": "cosine"},
            )
        return self._collections[name]

    @staticmethod
    def _normalize_agent_id(agent_id: str | None) -> str | None:
        """Normalize an agent id the same way a session id is normalized.

        ``agent_id`` identifies the *running model/agent* that owns a memory
        entry, so concurrent agents operating on the same target can keep
        their memory banks disjoint (or, by omitting it, share a common pool).
        Reuses the session-id normalization (strip + non-empty) since the
        rules are identical.
        """
        return MemoryService._normalize_session_id(agent_id)

    @staticmethod
    def _build_filters(
        session_id: str | None = None,
        agent_id: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        filters: dict[str, Any] = {}
        normalized_session_id = MemoryService._normalize_session_id(session_id)
        if normalized_session_id is not None:
            filters["session_id"] = normalized_session_id
        normalized_agent_id = MemoryService._normalize_agent_id(agent_id)
        if normalized_agent_id is not None:
            filters["agent_id"] = normalized_agent_id
        if extra:
            filters.update({key: value for key, value in extra.items() if value is not None})
        return filters or None

    def list_namespaces(self) -> list[str]:
        """Return all namespaces that currently have a collection."""
        collections = self.client.list_collections()
        names = []
        for collection in collections:
            name = collection.name
            if name.startswith("memory_"):
                names.append(name.replace("memory_", "", 1))
        return sorted(names)
    @framework_tool("Store a memory entry with text and embedding in a namespace.")
    def remember(
        self,
        namespace: str,
        memory_id: str,
        text: str,
        embedding: list[float],
        session_id: str | None = None,
        agent_id: str | None = None,
        **metadata: Any,
    ) -> str:
        collection = self._get_collection(namespace)
        normalized_session_id = self._normalize_session_id(session_id)
        normalized_agent_id = self._normalize_agent_id(agent_id)
        payload = dict(metadata)
        if normalized_session_id is not None:
            payload["session_id"] = normalized_session_id
        if normalized_agent_id is not None:
            payload["agent_id"] = normalized_agent_id
        # ChromaDB rejects an empty metadata dict; pass None when there is
        # nothing to tag (no session_id / agent_id / extra metadata).
        collection.upsert(
            ids=[str(memory_id)],
            documents=[str(text)],
            embeddings=[list(embedding)],
            metadatas=[payload if payload else None],
        )
        return str(memory_id)
    @framework_tool("Search for memory entries in a namespace using keyword matching.")
    def search(
        self,
        namespace: str,
        query_text: str,
        limit: int = 5,
        session_id: str | None = None,
        agent_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Simple keyword-style search over stored document text within a namespace.

        ``agent_id`` scopes results to memories owned by a specific running
        model; omit it to search the shared pool across all agents.
        """
        collection = self._get_collection(namespace)
        query = str(query_text).strip()
        if not query:
            return []

        results = collection.get(
            where=self._build_filters(session_id=session_id, agent_id=agent_id),
            include=["documents", "metadatas"],
        )
        ids = results.get("ids", [])
        documents = results.get("documents", [])
        metadatas = results.get("metadatas", [])

        hits: list[dict[str, Any]] = []
        for index, memory_id in enumerate(ids):
            document = documents[index] if index < len(documents) else ""
            if query.lower() in document.lower():
                hits.append(
                    {
                        "id": memory_id,
                        "document": document,
                        "metadata": metadatas[index] if index < len(metadatas) else {},
                    }
                )
            if len(hits) >= max(1, int(limit)):
                break
        return hits

    @framework_tool("Recall memory entries in a namespace using vector similarity.")
    def recall(
        self,
        namespace: str,
        query_embedding: list[float],
        limit: int = 5,
        session_id: str | None = None,
        agent_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Recall by vector similarity. ``agent_id`` scopes to one running
        model's memories; omit it to recall across all agents."""
        collection = self._get_collection(namespace)
        results = collection.query(
            query_embeddings=[list(query_embedding)],
            n_results=max(1, int(limit)),
            where=self._build_filters(session_id=session_id, agent_id=agent_id),
            include=["documents", "metadatas", "distances"],
        )

        ids = results.get("ids", [[]])[0]
        documents = results.get("documents", [[]])[0]
        metadatas = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]

        hits: list[dict[str, Any]] = []
        for index, memory_id in enumerate(ids):
            hits.append(
                {
                    "id": memory_id,
                    "document": documents[index] if index < len(documents) else None,
                    "metadata": metadatas[index] if index < len(metadatas) else {},
                    "distance": distances[index] if index < len(distances) else None,
                }
            )
        return hits
    @framework_tool("Retrieve a specific memory entry by ID from a namespace.")
    def get(self, namespace: str, memory_id: str, session_id: str | None = None, agent_id: str | None = None) -> dict[str, Any] | None:
        collection = self._get_collection(namespace)
        result = collection.get(
            ids=[str(memory_id)],
            where=self._build_filters(session_id=session_id, agent_id=agent_id),
            include=["documents", "metadatas", "embeddings"],
        )
        ids = result.get("ids", [])
        if not ids or str(memory_id) not in ids:
            return None

        index = ids.index(str(memory_id))
        return {
            "id": str(memory_id),
            "document": result.get("documents", [None])[index],
            "metadata": result.get("metadatas", [{}])[index],
            "embedding": result.get("embeddings", [None])[index],
        }

    @framework_tool(
        "Remove a memory entry by ID from a namespace. Protected (important) "
        "entries and entries owned by another agent cannot be deleted; "
        "repeated invalid attempts (3 by default, MEMORY_FORGET_STRIKE_LIMIT) "
        "lock the caller out of forget entirely. Pass your agent_id."
    )
    def forget(self, namespace: str, memory_id: str, agent_id: str | None = None) -> str:
        """Delete a memory by id, guarded by ownership + importance rules.

        Returns a short status string. Raises ``PermissionError`` (surfaced to
        the secretary as a Failed result) when the deletion is refused or the
        caller has been locked out.
        """
        collection = self._get_collection(namespace)
        caller = self._normalize_agent_id(agent_id) or "anonymous"

        with _FORGET_LOCK:
            if caller in _FORGET_BANNED:
                logger.warning("[memory] '%s' is locked out of forget", caller)
                raise PermissionError(
                    f"Agent '{caller}' is locked out of forget after "
                    f"{_FORGET_STRIKE_LIMIT} invalid deletion attempts."
                )

        # Inspect the target so we can enforce ownership / importance before
        # deleting. (``ids`` are always returned by ``get`` regardless of
        # ``include``.)
        result = collection.get(ids=[str(memory_id)], include=["metadatas"])
        ids = result.get("ids") or []
        if str(memory_id) not in ids:
            # Idempotent no-op: deleting a non-existent id is not a strike.
            return f"nothing to forget: {memory_id}"
        meta = (result.get("metadatas") or [None])[0] or {}
        owner = self._normalize_agent_id(meta.get("agent_id"))
        important = _is_important(meta)

        strike = False
        reason = ""
        if important:
            strike = True
            reason = "entry is marked important/protected"
        elif owner is not None and owner != caller:
            strike = True
            reason = f"entry is owned by agent '{owner}', not '{caller}'"
        elif owner is None and caller != "anonymous":
            strike = True
            reason = "entry is in the shared pool; scoped agents cannot delete shared entries"
        # else: owner == caller (own entry) OR (shared entry + anonymous/admin)
        #       -> allowed, provided it isn't important.

        if strike:
            with _FORGET_LOCK:
                _FORGET_STRIKES[caller] = _FORGET_STRIKES.get(caller, 0) + 1
                count = _FORGET_STRIKES[caller]
                banned = count >= _FORGET_STRIKE_LIMIT
                if banned:
                    _FORGET_BANNED.add(caller)
            logger.warning(
                "[memory] forget refused for '%s': %s (strike %d/%d%s)",
                caller, reason, count, _FORGET_STRIKE_LIMIT,
                " -> LOCKED OUT" if banned else "",
            )
            suffix = (
                f" Agent '{caller}' is now locked out of forget."
                if banned else ""
            )
            raise PermissionError(
                f"Refused: {reason}. Strike {count}/{_FORGET_STRIKE_LIMIT}.{suffix}"
            )

        collection.delete(ids=[str(memory_id)])
        return f"forgotten: {memory_id} from {namespace}"

    @classmethod
    def reset_forget_strikes(cls, agent_id: str | None = None) -> None:
        """Clear forget strike counters. If ``agent_id`` is given, clear only
        that caller; otherwise reset everyone (including the banned set)."""
        with _FORGET_LOCK:
            if agent_id is None:
                _FORGET_STRIKES.clear()
                _FORGET_BANNED.clear()
            else:
                _FORGET_STRIKES.pop(agent_id, None)
                _FORGET_BANNED.discard(agent_id)


_default_service = MemoryService()


def store_embedding(
    key: str,
    embedding: list[float],
    namespace: str = "shared",
    session_id: str | None = None,
    agent_id: str | None = None,
) -> str:
    """Compatibility wrapper for storing a raw embedding under a namespaced key."""
    return _default_service.remember(
        namespace=namespace,
        memory_id=key,
        text=key,
        embedding=list(embedding),
        source="embedding",
        session_id=session_id,
        agent_id=agent_id,
    )


def retrieve_embedding(
    key: str,
    namespace: str = "shared",
    session_id: str | None = None,
    agent_id: str | None = None,
) -> tuple[list[float] | None, str | None]:
    """Compatibility wrapper returning the stored embedding and id for a key."""
    result = _default_service.get(namespace=namespace, memory_id=key, session_id=session_id, agent_id=agent_id)
    if result is None:
        return None, None
    return result.get("embedding"), result.get("id")


def store_id(key: str, id_value: str, namespace: str = "shared", session_id: str | None = None, agent_id: str | None = None) -> str:
    """Compatibility wrapper for storing a key-to-id mapping in a namespace."""
    return _default_service.remember(
        namespace=namespace,
        memory_id=str(id_value),
        text=str(key),
        embedding=[0.0],
        source="id",
        key=str(key),
        session_id=session_id,
        agent_id=agent_id,
    )


def retrieve_id(key: str, namespace: str = "shared", session_id: str | None = None, agent_id: str | None = None) -> str:
    """Compatibility wrapper for retrieving the id assigned to a key."""
    collection = _default_service._get_collection(namespace)
    where = {"key": str(key)}
    normalized = MemoryService._normalize_session_id(session_id)
    if normalized is not None:
        where["session_id"] = normalized
    normalized_agent = MemoryService._normalize_agent_id(agent_id)
    if normalized_agent is not None:
        where["agent_id"] = normalized_agent
    results = collection.get(where=where, include=["ids", "metadatas"])
    ids = results.get("ids", [])
    return ids[0] if ids else ""


__all__ = [
    "MemoryService",
    "store_embedding",
    "retrieve_embedding",
    "store_id",
    "retrieve_id",
]


