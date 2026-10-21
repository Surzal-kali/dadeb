"""Provider-agnostic embedding endpoint helpers.

The embed lane is plain HTTP — no SDK, no Ollama lock-in: every consumer
posts the SAME body shape, ``{"model": <name>, "input": [texts]}`` (both the
Ollama-native embed API and OpenAI-compatible endpoints accept it), to
``EMBED_URL`` and parses one of the common wire shapes back. Anything that
"speaks web" embeddings works: Ollama, OpenAI, Together, Mistral, Voyage,
Jina, LM Studio, vLLM, llama.cpp server, ...

Knobs (all optional, from .env / packaging env):

- ``EMBED_URL``     — full POST target of the embeddings endpoint.
                      Default: ``http://localhost:11434/api/embed`` (the
                      shipped lab stack's Ollama native endpoint), expressed
                      here as a bare constant — NOT derived from
                      ``OLLAMA_BASE_URL`` (the driving-LLM lane has its own
                      endpoint; the two no longer piggyback on each other).
- ``EMBED_MODEL``   — the model id sent in the body. Single knob shared by
                      the tool registry and memory embed lanes; default
                      ``nomic-embed-text``. Re-index after changing it.
- ``EMBED_API_KEY`` — optional. When set, an ``Authorization: Bearer`` header
                      is sent (covers OpenAI-style keyed providers; loopback
                      labs leave it empty).

Egress note: whatever ``EMBED_URL`` points at receives the text being
embedded — memory contents carry finding text (credentials, hosts), so a
cloud embeddings provider is a real data-egress channel for engagement
material. Keep it loopback/LAN for live work (README legal addendum).
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Tuple

DEFAULT_EMBED_URL = "http://localhost:11434/api/embed"


def embed_model() -> str:
    """Model id for the embed body (``EMBED_MODEL``, default nomic-embed-text)."""
    return os.getenv("EMBED_MODEL", "").strip() or "nomic-embed-text"


def resolve_embed_url() -> str:
    """Full POST target for the embeddings endpoint.

    ``EMBED_URL`` verbatim when set; otherwise the bare shipped default.
    Trailing slashes are stripped so string-appends stay sane.
    """
    url = os.getenv("EMBED_URL", "").strip()
    return url.rstrip("/") if url else DEFAULT_EMBED_URL


def auth_headers() -> Dict[str, str]:
    """Headers for the embed POST: Bearer auth iff ``EMBED_API_KEY`` is set."""
    headers = {"Content-Type": "application/json"}
    key = os.getenv("EMBED_API_KEY", "").strip()
    if key:
        headers["Authorization"] = f"Bearer {key}"
    return headers


def embed_body(texts: List[str], model: str = "") -> Dict[str, Any]:
    """Request body shared by every embed consumer: ``{"model", "input"}``.

    ``input`` is always a list — the native Ollama embed API and the
    OpenAI-compatible shape both accept arrays, so one body serves all.
    """
    return {"model": model or embed_model(), "input": list(texts)}


def parse_embed_response(payload: Any) -> List[List[float]]:
    """Decode any of the three common embeddings wire shapes.

    - Ollama native (``/api/embed``): ``{"embeddings": [[...], ...]}``
      (tolerates a flat single vector ``{"embeddings": [...]}``)
    - Legacy single-vector: ``{"embedding": [...]}``
    - OpenAI-compatible: ``{"data": [{"embedding": [...], ...}, ...]}``
      (returned in the provider's order, matching the request's ``input``)

    Anything else raises — a silent wrong-shape guess would poison vectors
    into a collection quietly.
    """
    embeddings = payload.get("embeddings") if isinstance(payload, dict) else None
    if embeddings is not None:
        if embeddings and isinstance(embeddings[0], (int, float)):
            return [[float(v) for v in embeddings]]
        return [[float(v) for v in vector] for vector in embeddings]
    if isinstance(payload, dict) and isinstance(payload.get("embedding"), list):
        return [[float(v) for v in payload["embedding"]]]
    data = payload.get("data") if isinstance(payload, dict) else None
    if isinstance(data, list) and data and isinstance(data[0], dict):
        return [[float(v) for v in item["embedding"]] for item in data]
    keys = list(payload) if isinstance(payload, dict) else type(payload).__name__
    raise ValueError(f"Unrecognized embedding response shape (keys={keys})")


def embed_request(
    texts: List[str], model: str = ""
) -> Tuple[str, Dict[str, str], Dict[str, Any]]:
    """Convenience trio: (url, headers, body) for one embeddings POST."""
    return resolve_embed_url(), auth_headers(), embed_body(texts, model)
