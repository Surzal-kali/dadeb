"""SQLite + numpy vector store — the ChromaDB replacement.

ChromaDB was overkill for ~200 tool entries: it pulled in 27 transitive
deps (onnxruntime, kubernetes, grpcio, opentelemetry, tokenizers, ...),
needed a running HTTP server process (the sidecar), and that server's
pip install fails on network-isolated builds (Kali/Debian offline,
NetHunter). This module replaces it with a SQLite table per collection
and brute-force cosine similarity via numpy — which is already a
transitive dependency through scapy and others.

The API mirrors the exact ChromaDB surface the harness uses:

- ``VectorStore(path)`` — replaces ``chromadb.PersistentClient(path=...)``
- ``get_or_create_collection(name)`` → ``Collection``
- ``Collection.add(ids, embeddings, metadatas, documents)``
- ``Collection.upsert(ids, embeddings, metadatas, documents)``
- ``Collection.get(ids?, where?, include?)`` — exact-id or filter lookup
- ``Collection.query(query_embeddings, n_results, where?, include?)``
  — cosine similarity search, returns best-first
- ``Collection.delete(ids)``
- ``Collection.count()``

Cosine distance (not similarity) is returned in the ``distances`` field
to match ChromaDB's convention: ``distance = 1 - cosine_similarity``.
A distance of 0 means identical; 2 means opposite. The harness's
``ROUTER_MAX_DISTANCE`` (default 1.1) and the memory recall path both
consume distances, so the scale must match.

At ~200 entries × 768 dims, the full matrix is ~2.4 MB of float32 —
fits in memory trivially, and brute-force cosine on it is sub-millisecond
(numpy vectorised matmul). No HNSW index, no server process, no network
dependency.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import struct
import threading
import time
from pathlib import Path
from typing import Any, Callable

import numpy as np
import re

logger = logging.getLogger(__name__)

# Collection names flow into SQLite table identifiers (``vs_<name>``).
# SQLite does not support parameterized identifiers — the table name is
# always interpolated into the SQL string. A malicious or careless name
# like ``"; DROP TABLE vs_tool_inventory; --"`` would reach the parser
# raw. Validate at construction time: only alphanumeric + underscore
# are allowed, so the name is always a safe identifier.
_VALID_NAME = re.compile(r"^[A-Za-z0-9_]+$")


def _sanitize_collection_name(name: str) -> str:
    """Validate a collection name is a safe SQLite identifier.

    Collection names are interpolated into SQL as table identifiers
    (``vs_<name>``). SQLite has no parameterized-identifier path, so a
    name containing ``;``, spaces, or quotes would reach the parser raw —
    enabling DoS (error spam) or error-based information leakage. Reject
    anything outside ``[A-Za-z0-9_]+`` at construction time so the table
    name is always a safe identifier.
    """
    if not name or not _VALID_NAME.match(name):
        raise ValueError(
            f"Invalid collection name {name!r}: must be alphanumeric + "
            f"underscore only (flows into a SQLite table identifier)"
        )
    return name


def _serialize_vector(vec: list[float]) -> bytes:
    """Pack a float vector into a compact little-endian blob."""
    arr = np.asarray(vec, dtype=np.float32)
    return arr.tobytes()


def _deserialize_vector(blob: bytes) -> list[float]:
    """Unpack a float vector from its blob."""
    arr = np.frombuffer(blob, dtype=np.float32)
    return arr.tolist()


def _normalize_where(where: dict[str, Any] | None) -> dict[str, Any] | None:
    """Normalize a ChromaDB-style ``where`` dict into a plain dict.

    ChromaDB accepts ``{"key": value}`` (equality) and operators like
    ``{"key": {"$in": [...]}}``. We support equality and ``$in``; other
    operators degrade to no-match (logged at debug).
    """
    if not where:
        return None
    flat: dict[str, Any] = {}
    for key, value in where.items():
        if isinstance(value, dict) and "$in" in value:
            flat[key] = ("$in", value["$in"])
        elif isinstance(value, dict):
            # Unsupported operator — degrade to match-NONE, not match-all.
            # Returning None here would mean "no filter" in _where_matches,
            # which silently admits every row. A sentinel that _where_matches
            # treats as always-false is the honest degradation.
            logger.debug("[vector_store] unsupported where operator for %s: %s", key, list(value))
            return {"__unsupported__": True}
        else:
            flat[key] = value
    return flat


def _where_matches(meta_json: str, where: dict[str, Any] | None) -> bool:
    """Check whether a row's metadata JSON satisfies the ``where`` filter."""
    if not where:
        return True
    # Sentinel from _normalize_where: an unsupported operator was seen.
    # Degrade to match-NONE (not match-all) — returning True here would
    # silently admit every row when the caller asked for a filter.
    if where.get("__unsupported__"):
        return False
    try:
        meta = json.loads(meta_json) if meta_json else {}
    except (json.JSONDecodeError, TypeError):
        meta = {}
    for key, expected in where.items():
        if isinstance(expected, tuple) and expected[0] == "$in":
            if meta.get(key) not in expected[1]:
                return False
        else:
            if meta.get(key) != expected:
                return False
    return True


class Collection:
    """A named collection of vectors + metadata backed by a SQLite table."""

    def __init__(
        self,
        get_conn: Callable[[], sqlite3.Connection],
        name: str,
        space: str = "cosine",
    ):
        # Per-thread connection provider (delegated to VectorStore). Each
        # call returns the calling thread's own sqlite3.Connection so
        # concurrent lanes never share a single connection object — which
        # would raise system errors or corrupt cursor state under load.
        self._get_conn = get_conn
        self.name = _sanitize_collection_name(name)
        self._space = space
        # Table name is the collection name with a prefix to avoid collisions
        # with SQLite system tables. The name is validated (alphanumeric +
        # underscore only) so it is a safe SQLite identifier — never
        # interpolated raw from untrusted input.
        self._table = f"vs_{self.name}"
        # In-memory vector cache (loaded lazily, invalidated on mutation).
        self._cache: dict[str, np.ndarray] = {}
        self._cache_valid = False
        # RLock (reentrant) so query() can hold the guard and still call
        # _load_cache() without deadlocking.
        self._lock = threading.RLock()
        self._ensure_table()

    @property
    def _conn(self) -> sqlite3.Connection:
        """Per-thread connection (resolved lazily via the store's provider)."""
        return self._get_conn()

    def _ensure_table(self) -> None:
        with self._lock:
            self._conn.execute(
                f"""CREATE TABLE IF NOT EXISTS {self._table} (
                    id TEXT PRIMARY KEY,
                    embedding BLOB,
                    document TEXT,
                    metadata TEXT
                )"""
            )
            self._conn.commit()

    def _load_cache(self) -> None:
        """Load all vectors into memory for brute-force search."""
        with self._lock:
            if self._cache_valid:
                return
            self._cache.clear()
            for row in self._conn.execute(
                f"SELECT id, embedding FROM {self._table}"
            ):
                self._cache[row[0]] = np.frombuffer(row[1], dtype=np.float32)
            self._cache_valid = True

    def _invalidate_cache(self) -> None:
        with self._lock:
            self._cache_valid = False
            self._cache.clear()

    def add(
        self,
        ids: list[str],
        embeddings: list[list[float]],
        metadatas: list[dict[str, Any]] | None = None,
        documents: list[str] | None = None,
    ) -> None:
        """Add entries. Raises if an id already exists (use upsert to replace)."""
        metadatas = metadatas or [None] * len(ids)
        documents = documents or [""] * len(ids)
        with self._lock:
            for i, entry_id in enumerate(ids):
                existing = self._conn.execute(
                    f"SELECT 1 FROM {self._table} WHERE id = ?", (entry_id,)
                ).fetchone()
                if existing:
                    raise ValueError(f"Duplicate id: {entry_id}")
                meta_json = json.dumps(metadatas[i]) if metadatas[i] else None
                self._conn.execute(
                    f"INSERT INTO {self._table} (id, embedding, document, metadata) VALUES (?, ?, ?, ?)",
                    (
                        entry_id,
                        _serialize_vector(embeddings[i]),
                        documents[i] or "",
                        meta_json,
                    ),
                )
            self._conn.commit()
            self._invalidate_cache()

    def upsert(
        self,
        ids: list[str],
        embeddings: list[list[float]],
        metadatas: list[dict[str, Any]] | None = None,
        documents: list[str] | None = None,
    ) -> None:
        """Add or replace entries (INSERT OR REPLACE)."""
        metadatas = metadatas or [None] * len(ids)
        documents = documents or [""] * len(ids)
        with self._lock:
            for i, entry_id in enumerate(ids):
                meta_json = json.dumps(metadatas[i]) if metadatas[i] else None
                self._conn.execute(
                    f"INSERT OR REPLACE INTO {self._table} (id, embedding, document, metadata) VALUES (?, ?, ?, ?)",
                    (
                        entry_id,
                        _serialize_vector(embeddings[i]),
                        documents[i] or "",
                        meta_json,
                    ),
                )
            self._conn.commit()
            self._invalidate_cache()

    def delete(self, ids: list[str]) -> None:
        """Delete entries by id. No-op for missing ids."""
        if not ids:
            return
        placeholders = ",".join("?" * len(ids))
        with self._lock:
            self._conn.execute(
                f"DELETE FROM {self._table} WHERE id IN ({placeholders})", ids
            )
            self._conn.commit()
            self._invalidate_cache()

    def get(
        self,
        ids: list[str] | None = None,
        where: dict[str, Any] | None = None,
        include: list[str] | None = None,
    ) -> dict[str, Any]:
        """Retrieve entries by id and/or metadata filter.

        Returns a ChromaDB-shaped dict:
        ``{"ids": [...], "documents": [...], "metadatas": [...], "embeddings": [...]}``

        ``include`` controls which fields are populated (default: all).
        """
        include = include or ["documents", "metadatas", "embeddings"]
        flat_where = _normalize_where(where)

        with self._lock:
            if ids:
                placeholders = ",".join("?" * len(ids))
                rows = self._conn.execute(
                    f"SELECT id, embedding, document, metadata FROM {self._table} "
                    f"WHERE id IN ({placeholders})",
                    ids,
                ).fetchall()
            else:
                rows = self._conn.execute(
                    f"SELECT id, embedding, document, metadata FROM {self._table}"
                ).fetchall()

            result_ids: list[str] = []
            result_docs: list[str] = []
            result_metas: list[dict[str, Any]] = []
            result_embs: list[list[float]] = []

            for row in rows:
                entry_id, emb_blob, doc, meta_json = row
                if flat_where and not _where_matches(meta_json or "", flat_where):
                    continue
                result_ids.append(entry_id)
                if "documents" in include:
                    result_docs.append(doc or "")
                if "metadatas" in include:
                    try:
                        result_metas.append(json.loads(meta_json) if meta_json else {})
                    except (json.JSONDecodeError, TypeError):
                        result_metas.append({})
                if "embeddings" in include:
                    result_embs.append(_deserialize_vector(emb_blob) if emb_blob else [])

            out: dict[str, Any] = {"ids": result_ids}
            if "documents" in include:
                out["documents"] = result_docs
            if "metadatas" in include:
                out["metadatas"] = result_metas
            if "embeddings" in include:
                out["embeddings"] = result_embs
            return out

    def query(
        self,
        query_embeddings: list[list[float]],
        n_results: int = 10,
        where: dict[str, Any] | None = None,
        include: list[str] | None = None,
    ) -> dict[str, Any]:
        """Brute-force cosine similarity search.

        Returns a ChromaDB-shaped dict with nested lists (one per query):
        ``{"ids": [[...]], "documents": [[...]], "metadatas": [[...]], "distances": [[...]]}``

        Results are sorted by distance ascending (best match first).
        Distance = 1 - cosine_similarity (0 = identical, 2 = opposite).
        """
        include = include or ["documents", "metadatas", "distances"]
        flat_where = _normalize_where(where)

        with self._lock:
            self._load_cache()

            # Load all rows for metadata/document filtering.
            all_rows = self._conn.execute(
                f"SELECT id, embedding, document, metadata FROM {self._table}"
            ).fetchall()

            # Build filtered candidate list.
            candidates: list[tuple[str, np.ndarray, str, str]] = []
            for row in all_rows:
                entry_id, emb_blob, doc, meta_json = row
                if flat_where and not _where_matches(meta_json or "", flat_where):
                    continue
                vec = self._cache.get(entry_id)
                if vec is None:
                    vec = np.frombuffer(emb_blob, dtype=np.float32) if emb_blob else np.zeros(1, dtype=np.float32)
                candidates.append((entry_id, vec, doc or "", meta_json or ""))

            all_ids: list[list[str]] = []
            all_docs: list[list[str]] = []
            all_metas: list[list[dict[str, Any]]] = []
            all_dists: list[list[float]] = []

            for query_vec in query_embeddings:
                q = np.asarray(query_vec, dtype=np.float32)
                q_norm = np.linalg.norm(q)
                if q_norm == 0:
                    # Zero query vector — can't compute similarity; return empty.
                    all_ids.append([])
                    all_docs.append([])
                    all_metas.append([])
                    all_dists.append([])
                    continue

                scored: list[tuple[float, str, str, str]] = []
                for entry_id, vec, doc, meta_json in candidates:
                    v_norm = np.linalg.norm(vec)
                    if v_norm == 0:
                        continue
                    cosine = float(np.dot(q, vec) / (q_norm * v_norm))
                    distance = 1.0 - cosine
                    scored.append((distance, entry_id, doc, meta_json))

                scored.sort(key=lambda x: x[0])
                scored = scored[: max(1, n_results)]

                ids_list: list[str] = []
                docs_list: list[str] = []
                metas_list: list[dict[str, Any]] = []
                dists_list: list[float] = []
                for dist, entry_id, doc, meta_json in scored:
                    ids_list.append(entry_id)
                    if "documents" in include:
                        docs_list.append(doc)
                    if "metadatas" in include:
                        try:
                            metas_list.append(json.loads(meta_json) if meta_json else {})
                        except (json.JSONDecodeError, TypeError):
                            metas_list.append({})
                    if "distances" in include:
                        dists_list.append(round(dist, 6))

                all_ids.append(ids_list)
                all_docs.append(docs_list)
                all_metas.append(metas_list)
                all_dists.append(dists_list)

            out: dict[str, Any] = {"ids": all_ids}
            if "documents" in include:
                out["documents"] = all_docs
            if "metadatas" in include:
                out["metadatas"] = all_metas
            if "distances" in include:
                out["distances"] = all_dists
            return out

    def count(self) -> int:
        with self._lock:
            row = self._conn.execute(
                f"SELECT COUNT(*) FROM {self._table}"
            ).fetchone()
            return int(row[0])


class VectorStore:
    """SQLite-backed vector store — replaces ``chromadb.PersistentClient``.

    One SQLite database file holds every collection (each collection is a
    table named ``vs_<collection_name>``). No server process, no network
    dependency, no HNSW index — brute-force cosine similarity on an
    in-memory numpy matrix is sub-millisecond at the harness's scale
    (~200 tool entries, ~768-dim vectors).

    Concurrency: each thread gets its own ``sqlite3.Connection`` via a
    ``threading.local`` slot, so concurrent lanes never share a single
    connection object (which would raise system errors under load). WAL
    mode allows concurrent readers + one writer; ``busy_timeout`` makes
    writers wait instead of failing instantly on lock contention. The
    WAL switch itself is retried on cold-start lock races.
    """

    # SQLite busy-timeout (ms): how long a writer waits for a lock before
    # raising SQLITE_BUSY. 5 s is generous for the harness's scale.
    _BUSY_TIMEOUT_MS = 5000
    # WAL cold-start retry: the first connection on a fresh or recovering
    # store may race another process holding the recovery lock.
    _WAL_RETRIES = 5
    _WAL_RETRY_BASE_SLEEP = 0.1

    def __init__(self, path: str):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._collections: dict[str, Collection] = {}
        self._lock = threading.Lock()
        # Prime the calling thread's connection eagerly so WAL is set up
        # before any collection is created (and before another thread
        # races us on the journal-mode switch).
        self._local.conn = self._connect()

    def _connect(self) -> sqlite3.Connection:
        """Open a new per-thread connection with WAL + busy_timeout."""
        conn = sqlite3.connect(
            self.path,
            check_same_thread=False,
            timeout=self._BUSY_TIMEOUT_MS / 1000,
        )
        conn.execute(f"PRAGMA busy_timeout={self._BUSY_TIMEOUT_MS}")
        # WAL switch with cold-start retry: on a fresh or recovering store
        # another process (or the hot recovery lock) may hold the DB,
        # making the journal-mode switch fail with "database is locked".
        # Retry a few times before giving up — a failure here leaves the
        # store in default rollback-journal mode, which serializes all
        # readers and is the exact contention we're trying to avoid.
        for attempt in range(self._WAL_RETRIES):
            try:
                row = conn.execute("PRAGMA journal_mode=WAL").fetchone()
                if row and str(row[0]).lower() == "wal":
                    break
            except sqlite3.OperationalError as exc:
                if "locked" in str(exc).lower() and attempt < self._WAL_RETRIES - 1:
                    time.sleep(self._WAL_RETRY_BASE_SLEEP * (attempt + 1))
                    continue
                raise
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    @property
    def _conn(self) -> sqlite3.Connection:
        """Per-thread connection (lazily created, cached in thread-local)."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._connect()
            self._local.conn = conn
        return conn

    def _get_conn(self) -> sqlite3.Connection:
        """Per-thread connection provider (passed to Collection instances)."""
        return self._conn

    def get_or_create_collection(
        self, name: str, metadata: dict[str, Any] | None = None,
    ) -> Collection:
        """Get or create a named collection (a SQLite table).

        ``metadata`` is accepted for API compatibility but ignored — we
        always use cosine similarity (no HNSW index to configure).
        """
        with self._lock:
            if name not in self._collections:
                self._collections[name] = Collection(self._get_conn, name)
            return self._collections[name]

    def list_collections(self) -> list[Collection]:
        """Return all known collections. Mirrors ChromaDB's API."""
        with self._lock:
            # Discover any tables that exist in the DB but aren't cached.
            rows = self._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'vs_%'"
            ).fetchall()
            for row in rows:
                table_name = row[0]
                coll_name = table_name[3:]  # strip "vs_" prefix
                if coll_name not in self._collections:
                    self._collections[coll_name] = Collection(self._get_conn, coll_name)
            return list(self._collections.values())

    def close(self) -> None:
        """Close the calling thread's connection.

        With per-thread connections, only the current thread's connection
        is closed; other threads' connections are left for their own
        ``close()`` call or process teardown. This is fine for the harness
        shutdown path (the process exits after).
        """
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None