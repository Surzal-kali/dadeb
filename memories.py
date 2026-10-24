from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Any

from daharness.vector_store import VectorStore

from constants import resolve_workspace_root
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

    def __init__(self, storage_path: str | None = None):
        # Lane-safe default: resolve_workspace_root() understands the deb
        # lane (read-only /usr/share/daharness -> /var/lib/daharness). The
        # old ".memory/chroma" default was CWD-relative, so on the deb lane
        # it aimed into the root-owned checkout.
        if storage_path is None:
            storage_path = default_chroma_path()
        self.storage_path = str(Path(storage_path))
        # Before the client: create the dir with the unit's intended shape
        # and warn (instead of a raw sqlite code-8) when the lane cannot
        # write an existing foreign DB. After the client: align whatever
        # mode the client's own creations landed at under this umask.
        self._repair_chroma_permissions()
        self.client = VectorStore(self.storage_path)
        self._repair_chroma_permissions()
        self._collections: dict[str, Any] = {}

    def _repair_chroma_permissions(self) -> None:
        """Best-effort permission hygiene for the chroma dir; never raises.

        Mirrors the scratch-store root guard (utils/scratch_store.py) and
        fixes two deb-lane incident classes:

        * Prior root run leaves root-owned files (root runs masscan /
          packetcraft); later non-root runs then hit sqlite "attempt to
          write a readonly database". As root, chown the tree to the
          workspace-root owner; a non-root run meeting root-owned files
          warns loudly (it cannot chown).
        * The unit provisions a group-shareable state root
          (StateDirectoryMode=2770, UMask=0007 — "group-shareable to
          operator CLIs"), but the sqlite file can be created under a
          tighter umask (2026-10-21: chroma.sqlite3 landed 0640 while the
          operator account sits in the daharness group) — every operator-
          lane open of the existing DB then dies with sqlite code 8. The
          owner process restores group-write on what it owns so one fixed
          service boot heals it for the group; a non-owner that still
          cannot write warns with the operator remediation.
        """
        log = logging.getLogger(__name__)
        root = Path(self.storage_path)
        # The storage path is now a single SQLite file (vectors.db); ensure
        # its parent dir exists with the group-shareable shape.
        try:
            root.parent.mkdir(parents=True, exist_ok=True, mode=0o2770)
        except OSError:
            return  # no writable parent — let the client surface the real error
        try:
            ws_stat = resolve_workspace_root().stat()
        except OSError:
            ws_stat = None
        is_root = os.geteuid() == 0
        foreign_root_owned = False
        blocked_not_group_writable = False

        for p in [root.parent, root]:
            # Also check for WAL sidecar files.
            for suffix in ("", "-wal", "-shm"):
                p_s = p.with_name(p.name + suffix) if suffix else p
                if not p_s.exists():
                    continue
                try:
                    if p_s.is_symlink():
                        continue
                    st = p_s.stat()
                    if is_root and ws_stat and st.st_uid != ws_stat.st_uid:
                        os.chown(p_s, ws_stat.st_uid, ws_stat.st_gid)
                    if st.st_uid == 0 and not is_root:
                        foreign_root_owned = True
                    # Owner (or root-after-repair) restores the unit's
                    # intended group-shareable shape: dirs 2770, files 0660.
                    if is_root or st.st_uid == os.geteuid():
                        if p_s.is_dir():
                            os.chmod(p_s, 0o2770)
                        else:
                            os.chmod(p_s, 0o660)
                    elif (st.st_mode & 0o020) == 0:
                        # Not owner, not root, and group-write missing on
                        # an existing DB file — the sqlite code-8 trap.
                        blocked_not_group_writable = True
                except OSError:
                    continue

        if blocked_not_group_writable:
            log.warning(
                "Memory DB at %s is not group-writable but we are neither "
                "owner nor root — operator lanes sharing the state group "
                "will hit sqlite 'attempt to write a readonly database'. "
                "Remediation: restart the daharness service once with this "
                "build (the owner self-heals the mode), or chmod g+w the "
                "DB files manually.", self.storage_path,
            )
        if foreign_root_owned:
            log.warning(
                "Root-owned files found in memory DB at %s from a prior "
                "root run and we are not root — restart the framework as "
                "root once to trigger the ownership repair, or chown them "
                "to the workspace owner manually.", self.storage_path,
            )
    def create_collection(self, namespace: str, embedding_model: str = "nomic-embed-text"):
        """Create a new collection for a given namespace."""
        name = self._namespace_name(namespace)
        if name in self._collections:
            raise ValueError(f"Collection for namespace '{namespace}' already exists.")
        collection = self.client.get_or_create_collection(
            name=name,

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
        # The vector store stores None metadata as NULL; pass None when there is
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


def default_chroma_path() -> str:
    """Lane-safe default vector store path — under the workspace root, never CWD.

    Returns a single SQLite file (``vectors.db``) under ``.memory/`` — the
    SQLite+numpy vector store replaces the old ChromaDB PersistentClient
    which used a directory. The path is kept under the workspace root (state
    root on the deb) so the DB lives in a writable location, not the
    read-only code tree.
    """
    return str(resolve_workspace_root() / ".memory" / "vectors.db")


_DEFAULT_SERVICE: MemoryService | None = None
_DEFAULT_SERVICE_LOCK = threading.Lock()


def get_default_service() -> MemoryService:
    """Shared MemoryService, built lazily on first use — never at import.

    Tool discovery dynamically imports modules that reach this module
    (utils/findings.py -> utils/memory_tools.py), so import-time
    construction used to open chroma inside whatever CWD the scanning
    process had — and a failure poisoned the tool scan itself. First-use
    construction means a chroma failure fails the memory call, not the
    scan.
    """
    global _DEFAULT_SERVICE
    if _DEFAULT_SERVICE is None:
        with _DEFAULT_SERVICE_LOCK:
            if _DEFAULT_SERVICE is None:
                _DEFAULT_SERVICE = MemoryService()
    return _DEFAULT_SERVICE


def __getattr__(name: str):
    # PEP 562 back-compat: `from memories import _default_service` still
    # resolves, but only builds the service when actually referenced.
    if name == "_default_service":
        return get_default_service()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def store_embedding(
    key: str,
    embedding: list[float],
    namespace: str = "shared",
    session_id: str | None = None,
    agent_id: str | None = None,
) -> str:
    """Compatibility wrapper for storing a raw embedding under a namespaced key."""
    return get_default_service().remember(
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
    result = get_default_service().get(namespace=namespace, memory_id=key, session_id=session_id, agent_id=agent_id)
    if result is None:
        return None, None
    return result.get("embedding"), result.get("id")


def store_id(key: str, id_value: str, namespace: str = "shared", session_id: str | None = None, agent_id: str | None = None) -> str:
    """Compatibility wrapper for storing a key-to-id mapping in a namespace."""
    return get_default_service().remember(
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
    collection = get_default_service()._get_collection(namespace)
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


