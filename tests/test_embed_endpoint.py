"""Embed-lane tests for the provider-agnostic endpoint resolver.

Covers daharness/embedding.py pure helpers plus the registry's
OllamaEmbeddingFunction HTTP lane against an httpx.MockTransport — no
network, no Ollama daemon, no ChromaDB required.

Knobs under test: EMBED_URL / EMBED_MODEL / EMBED_API_KEY (all read at
call time, not import time — every test pins the full triple explicitly
so a developer's real .env cannot bleed in).
"""

import asyncio
import json

import httpx
import pytest

from daharness import embedding
from daharness.embedding import (
    DEFAULT_EMBED_URL,
    auth_headers,
    embed_body,
    embed_model,
    embed_request,
    parse_embed_response,
    resolve_embed_url,
)


@pytest.fixture(autouse=True)
def _clean_embed_env(monkeypatch):
    """Pin the embed triple so the operator's real .env cannot leak in."""
    for key in ("EMBED_URL", "EMBED_MODEL", "EMBED_API_KEY"):
        monkeypatch.delenv(key, raising=False)


# --- resolve_embed_url ------------------------------------------------------


def test_resolve_default_is_bare_ollama_native():
    assert resolve_embed_url() == DEFAULT_EMBED_URL == "http://localhost:11434/api/embed"


def test_resolve_env_override(monkeypatch):
    monkeypatch.setenv("EMBED_URL", "http://10.40.0.7:1234/v1/embeddings")
    assert resolve_embed_url() == "http://10.40.0.7:1234/v1/embeddings"


def test_resolve_trailing_slash_stripped(monkeypatch):
    monkeypatch.setenv("EMBED_URL", "https://api.openai.com/v1/embeddings/")
    assert resolve_embed_url() == "https://api.openai.com/v1/embeddings"


def test_resolve_empty_env_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("EMBED_URL", "   ")
    assert resolve_embed_url() == DEFAULT_EMBED_URL


def test_resolve_never_derives_from_ollama_base_url(monkeypatch):
    # Decoupling guard: OLLAMA_BASE_URL is the LLM/health knob only. Even
    # with it pointed elsewhere and EMBED_URL unset, the embed endpoint
    # stays the bare default.
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://10.40.0.9:11434/v1")
    assert resolve_embed_url() == DEFAULT_EMBED_URL


# --- embed_model ------------------------------------------------------------


def test_embed_model_default():
    assert embed_model() == "nomic-embed-text"


def test_embed_model_env_override(monkeypatch):
    monkeypatch.setenv("EMBED_MODEL", "bge-m3")
    assert embed_model() == "bge-m3"


def test_embed_model_empty_env_falls_back(monkeypatch):
    monkeypatch.setenv("EMBED_MODEL", "")
    assert embed_model() == "nomic-embed-text"


# --- auth_headers -----------------------------------------------------------


def test_auth_headers_without_key():
    headers = auth_headers()
    assert headers == {"Content-Type": "application/json"}


def test_auth_headers_with_bearer_key(monkeypatch):
    monkeypatch.setenv("EMBED_API_KEY", "sk-test-key")
    headers = auth_headers()
    assert headers["Content-Type"] == "application/json"
    assert headers["Authorization"] == "Bearer sk-test-key"


def test_auth_headers_empty_key_means_no_header(monkeypatch):
    monkeypatch.setenv("EMBED_API_KEY", "")
    assert "Authorization" not in auth_headers()


# --- embed_body -------------------------------------------------------------


def test_embed_body_shape():
    body = embed_body(["one", "two"])
    assert body == {"model": "nomic-embed-text", "input": ["one", "two"]}


def test_embed_body_model_override():
    body = embed_body(["hello"], model="text-embedding-3-small")
    assert body["model"] == "text-embedding-3-small"
    assert body["input"] == ["hello"]


def test_embed_body_copies_texts():
    texts = ["a"]
    body = embed_body(texts)
    assert body["input"] is not texts


# --- parse_embed_response ---------------------------------------------------


def test_parse_ollama_native_list():
    payload = {"embeddings": [[1.0, 2.0], [3.0, 4.0]]}
    assert parse_embed_response(payload) == [[1.0, 2.0], [3.0, 4.0]]


def test_parse_ollama_native_flat_single_vector():
    payload = {"embeddings": [1.0, 2.0, 3.0]}
    assert parse_embed_response(payload) == [[1.0, 2.0, 3.0]]


def test_parse_legacy_single_embedding():
    payload = {"embedding": [0.5, 0.6]}
    assert parse_embed_response(payload) == [[0.5, 0.6]]


def test_parse_openai_shape():
    payload = {"data": [{"embedding": [9.0, 9.5]}, {"embedding": [8.0, 8.5]}]}
    assert parse_embed_response(payload) == [[9.0, 9.5], [8.0, 8.5]]


def test_parse_preserves_input_order():
    vectors = [[float(i)] for i in range(5)]
    assert parse_embed_response({"data": [{"embedding": v} for v in reversed(vectors)]}) == list(
        reversed(vectors)
    )


def test_parse_unknown_shape_rejects_with_keys():
    with pytest.raises(ValueError) as excinfo:
        parse_embed_response({"foo": [1.0], "bar": "x"})
    msg = str(excinfo.value)
    for key in ("foo", "bar"):
        assert key in msg


def test_parse_empty_payload_rejects():
    with pytest.raises(ValueError):
        parse_embed_response({})


# --- embed_request trio -----------------------------------------------------


def test_embed_request_trio():
    url, headers, body = embed_request(["text"], model="m1")
    assert url == DEFAULT_EMBED_URL
    assert headers == {"Content-Type": "application/json"}
    assert body == {"model": "m1", "input": ["text"]}


# --- OllamaEmbeddingFunction network lane -----------------------------------


def _install_capture_transport(monkeypatch, responder):
    """Route registry's AsyncClient through an in-memory transport.

    ``daharness.registry.__call__`` constructs ``httpx.AsyncClient``
    directly, so shim the module's ``httpx`` handle: every construction
    gets the MockTransport injected. Requests are captured in ``captured``.
    """
    captured = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return responder(request)

    transport = httpx.MockTransport(handler)

    class _HttpxShim:
        @staticmethod
        def AsyncClient(**kwargs):
            kwargs["transport"] = transport
            kwargs.pop("base_url", None)  # registry never sets one, keep shim honest
            return httpx.AsyncClient(**kwargs)

    monkeypatch.setattr("daharness.registry.httpx", _HttpxShim)
    return captured


def _unwrapped_call(fn, texts):
    """Invoke the async __call__ the chroma wrapper hides.

    chromadb 1.5.9's ``EmbeddingFunction.__init_subclass__`` re-wraps every
    subclass ``__call__`` into a sync function that immediately validates
    the result — a coroutine has no ``len()``, so the wrapped lane explodes
    before any HTTP logic runs. The registry never lets chroma call this EF
    with text inputs (documents are embedded via ``ToolRegistry._embed_text``
    and upserted as vectors), so the wrapper lane never executes in
    production either. The true async original survives in the wrapper's
    closure; grab it and test the actual HTTP lane.
    """
    wrapper = type(fn).__dict__["__call__"]
    original = wrapper.__closure__[0].cell_contents
    return asyncio.run(original(fn, texts))


def _native_response(request: httpx.Request) -> httpx.Response:
    dim = [0.1, 0.2]
    return httpx.Response(
        200, json={"embeddings": [dim for _ in range(2)]}, request=request
    )


def test_registry_embedding_function_default_lane(monkeypatch):
    from daharness.registry import OllamaEmbeddingFunction

    captured = _install_capture_transport(monkeypatch, _native_response)
    fn = OllamaEmbeddingFunction()
    vectors = _unwrapped_call(fn, ["alpha", "beta"])

    assert vectors == [[0.1, 0.2], [0.1, 0.2]]
    (req,) = captured
    assert req.url == "http://localhost:11434/api/embed"  # native lane, bare default
    assert json.loads(req.read().decode()) == {
        "model": "nomic-embed-text",
        "input": ["alpha", "beta"],
    }
    assert not req.headers.get("Authorization")  # no key configured -> no header


def test_registry_embedding_function_openai_provider(monkeypatch):
    from daharness.registry import OllamaEmbeddingFunction

    monkeypatch.setenv("EMBED_URL", "https://api.openai.example/v1/embeddings/")
    monkeypatch.setenv("EMBED_API_KEY", "sk-live")
    monkeypatch.setenv("EMBED_MODEL", "text-embedding-3-small")

    def _openai_response(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"data": [{"embedding": [1.0]}, {"embedding": [2.0]}, {"embedding": [3.0]}]},
            request=request,
        )

    captured = _install_capture_transport(monkeypatch, _openai_response)
    fn = OllamaEmbeddingFunction()
    vectors = _unwrapped_call(fn, ["x", "y", "z"])

    assert vectors == [[1.0], [2.0], [3.0]]
    (req,) = captured
    assert req.url == "https://api.openai.example/v1/embeddings"  # trailing slash stripped
    assert req.headers["Authorization"] == "Bearer sk-live"
    assert json.loads(req.read().decode())["model"] == "text-embedding-3-small"


def test_registry_embedding_function_explicit_kwargs_win(monkeypatch):
    from daharness.registry import OllamaEmbeddingFunction

    monkeypatch.setenv("EMBED_URL", "http://env-says:1234/v1/embeddings")
    monkeypatch.setenv("EMBED_MODEL", "env-model")

    captured = _install_capture_transport(monkeypatch, _native_response)
    fn = OllamaEmbeddingFunction(model_name="kwarg-model", embed_url="http://kwarg-says:9000/api/embed")
    vectors = _unwrapped_call(fn, ["t"])

    assert vectors == [[0.1, 0.2], [0.1, 0.2]]
    (req,) = captured
    assert req.url == "http://kwarg-says:9000/api/embed"
    assert "kwarg-model" in req.read().decode()
    assert fn.name() == "kwarg-model"


def test_registry_embedding_function_http_error_surfaces(monkeypatch):
    from daharness.registry import OllamaEmbeddingFunction

    def _boom(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "upstream exploded"}, request=request)

    _install_capture_transport(monkeypatch, _boom)
    fn = OllamaEmbeddingFunction()
    with pytest.raises(httpx.HTTPStatusError):
        _unwrapped_call(fn, ["boom"])