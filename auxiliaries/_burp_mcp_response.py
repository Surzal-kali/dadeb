"""Response-parsing lane for ``burp_mcp.py``.

Carved guts of ``auxiliaries/burp_mcp.py`` (2026-10-30): the Java-
toString response parse machinery (``_parse_burp_response`` + regexes),
the HTML→markdown body converter (``_html_to_markdown``), and the
result-projection digest adapter the ``burp_send_*`` tools register
(``_burp_response_digest``).  Pure functions over parsed strings —
docstring-only sibling so static discovery never mints it; the facade
imports its parse + digest names back and remains the tool surface.
"""

from __future__ import annotations

import json
import re
from typing import Any

# ---------------------------------------------------------------------------
# Response parser — Burp BApp returns Java toString(), not structured JSON
# ---------------------------------------------------------------------------
# The BApp's send_http1_request / send_http2_request tools return the
# Montoya API's ``HttpRequestResponse.toString()`` — a Java debug string
# shaped like:
#
#   HttpRequestResponse{httpRequest=GET / HTTP/1.1\r\nHost: example.com\r\n\r\n, httpResponse=HTTP/1.1 200 OK\r\nDate: ...\r\n\r\n<html>...</html>, messageAnnotations=Annotations{comment='', highlightColor=NONE}}
#
# This is NOT structured data — it's a toString dump.  Returning it raw to
# the model / Open WebUI means:
#   1. The full HTML body is inline in a string field → context blowup.
#   2. Open WebUI tries to render the HTML tags → unhealthy state.
#   3. The Java wrapper syntax (HttpRequestResponse{...}) is noise.
#
# ``_parse_burp_response`` splits this into a clean structured dict:
#   - ``status_code`` / ``status_line`` — parsed from the response line.
#   - ``response_headers`` — dict of header name -> value.
#   - ``body_text`` — the response body converted to clean markdown/text
#     (HTML tags stripped, scripts/styles removed, ``<pre>``/``<code>``
#     preserved, ``<a href>`` rendered as ``[text](url)``).  Non-HTML
#     bodies (JSON, XML, plain text) are passed through with minimal cleanup.
#   - ``body_bytes`` — original body size for size-awareness without the size.
#   - ``request_raw`` / ``response_raw`` — the original raw sections, kept
#     for the scratch store (full fidelity) but NOT in the default model
#     context unless the model retrieves them.
#
# The conversion uses BeautifulSoup (bs4, already in requirements.txt) — this
# is the codebase's first bs4 usage.  We import it lazily so the module
# loads even if bs4 is somehow absent (degrading to a regex strip).

_BURP_RESPONSE_RE = re.compile(
    r"HttpRequestResponse\{httpRequest=(.*?),\s*httpResponse=(.*?),\s*messageAnnotations=",
    re.DOTALL,
)
# Fallback for response-only or differently-shaped toStrings.
_BURP_RESPONSE_ONLY_RE = re.compile(
    r"httpResponse=(.*?)(?:,\s*messageAnnotations=|$)",
    re.DOTALL,
)


def _html_to_markdown(html: str, max_len: int = 8192) -> str:
    """Convert an HTML string to clean, compact markdown-ish text.

    Uses BeautifulSoup (bs4) to strip ``<script>`` / ``<style>`` / ``<svg>``,
    render ``<a href=\"...\">text</a>`` as ``[text](url)``, preserve
    ``<pre>`` / ``<code>`` blocks, and collapse whitespace.  Falls back to a
    regex tag-strip if bs4 is unavailable (the module must never fail to
    import because of an optional dep).

    ``max_len`` caps the converted text so a single response can't blow up
    the model context — the full body is in the scratch store when
    ``result_mode=digest``.
    """
    try:
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html, "html.parser")
        # Remove non-content tags that add noise / zero value to the model.
        for tag in soup.find_all(["script", "style", "svg", "noscript", "template"]):
            tag.decompose()
        # Render <a href="url">text</a> as [text](url) — the one structurally
        # meaningful HTML transform for a security model (links are endpoints).
        for a in soup.find_all("a", href=True):
            a.replace_with(f"[{a.get_text(strip=True)}]({a['href']})")
        # Preserve <pre>/<code> blocks with a fenced marker so the model
        # can distinguish source code from prose.  The fence is built from
        # a separate string (triple-backtick inside an f-string literal is
        # a Python syntax error).
        _fence = "```"
        for pre in soup.find_all(["pre"]):
            pre.replace_with(f"\n{_fence}\n{pre.get_text()}\n{_fence}\n")
        text = soup.get_text(separator="\n", strip=True)
    except Exception:
        # Fallback: regex strip.  Less pretty but never fails.
        text = re.sub(r"<(script|style|svg|noscript)[^>]*>.*?</\1>", "", html, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"\s+", " ", text).strip()
    if len(text) > max_len:
        text = text[:max_len] + f"\n...[truncated {len(text) - max_len} chars]"
    return text


def _parse_burp_response(raw: str) -> dict[str, Any]:
    """Parse the BApp's Java ``HttpRequestResponse.toString()`` into a dict.

    Returns:
        ``{status_code, status_line, response_headers, body_text,
        body_bytes, content_type, request_raw, response_raw}``

    The ``body_text`` field is HTML-to-markdown converted (see
    ``_html_to_markdown``); the ``response_raw`` field preserves the original
    raw response (headers + body) for the scratch store.  Non-HTML bodies
    (JSON, XML, CSS, JS, plain text) are passed through with whitespace
    cleanup only.
    """
    if not raw or not isinstance(raw, str):
        return {
            "status_code": None,
            "status_line": "",
            "response_headers": {},
            "body_text": str(raw) if raw else "<no response>",
            "body_bytes": 0,
            "content_type": "",
            "request_raw": "",
            "response_raw": "",
        }

    # Extract the httpResponse section from the Java toString.
    m = _BURP_RESPONSE_RE.search(raw)
    if m:
        request_raw = m.group(1)
        response_raw = m.group(2)
    else:
        m2 = _BURP_RESPONSE_ONLY_RE.search(raw)
        if m2:
            request_raw = ""
            response_raw = m2.group(1)
        else:
            # Unrecognised shape — return the raw text as body_text.
            return {
                "status_code": None,
                "status_line": "",
                "response_headers": {},
                "body_text": raw[:8192],
                "body_bytes": len(raw),
                "content_type": "",
                "request_raw": "",
                "response_raw": raw,
            }

    # Split the raw response into headers and body at the first blank line.
    # Burp's toString uses \r\n internally; normalize to \n for splitting.
    normalized = response_raw.replace("\r\n", "\n")
    parts = normalized.split("\n\n", 1)
    header_block = parts[0]
    body = parts[1] if len(parts) > 1 else ""

    # Parse the status line and headers.
    header_lines = header_block.split("\n")
    status_line = header_lines[0] if header_lines else ""
    status_code = None
    status_tokens = status_line.split()
    if len(status_tokens) >= 2:
        try:
            status_code = int(status_tokens[1])
        except ValueError:
            pass

    response_headers: dict[str, str] = {}
    content_type = ""
    for ln in header_lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            k = k.strip()
            v = v.strip()
            response_headers[k] = v
            if k.lower() == "content-type":
                content_type = v

    body_bytes = len(body.encode("utf-8", errors="replace"))

    # Convert the body: HTML -> markdown; JSON -> pretty-printed; other ->
    # whitespace-collapsed text.  The content_type drives the decision.
    ct_lower = content_type.lower()
    if "html" in ct_lower:
        body_text = _html_to_markdown(body)
    elif "json" in ct_lower:
        try:
            parsed = json.loads(body)
            body_text = json.dumps(parsed, indent=2)
            if len(body_text) > 8192:
                body_text = body_text[:8192] + f"\n...[truncated {len(body_text) - 8192} chars]"
        except (json.JSONDecodeError, ValueError):
            body_text = body[:8192]
    else:
        # XML, CSS, JS, plain text, binary-as-text: collapse whitespace.
        body_text = re.sub(r"\n{3,}", "\n\n", body)
        if len(body_text) > 8192:
            body_text = body_text[:8192] + f"\n...[truncated {len(body_text) - 8192} chars]"

    return {
        "status_code": status_code,
        "status_line": status_line,
        "response_headers": response_headers,
        "body_text": body_text,
        "body_bytes": body_bytes,
        "content_type": content_type,
        "request_raw": request_raw.replace("\r\n", "\n").strip(),
        "response_raw": normalized.strip(),
    }


def _burp_response_digest(result: dict[str, Any]) -> dict[str, str]:
    """Result-projection digest for burp_send_* tools.

    Compacts a parsed Burp response into a one-liner: status code, content
    type, body size, and the first ~500 chars of the cleaned body text.  The
    full response (headers + raw body) is in scratch — the model retrieves it
    with ``scratch_search`` when it needs the full headers or body.
    """
    if result.get("status") != "Success":
        return {"summary": f"failed: {result.get('error', 'unknown')}", "row_hint_format": ""}
    parsed = result.get("response") or {}
    if not isinstance(parsed, dict):
        # Fallback if the response wasn't parsed (shouldn't happen after the
        # _parse_burp_response call, but be honest about it).
        return {"summary": f"response (unparsed, {len(str(parsed))} bytes)", "row_hint_format": ""}
    status = parsed.get("status_code") or "?"
    ct = (parsed.get("content_type") or "").split(";")[0] or "unknown"
    size = parsed.get("body_bytes", 0)
    body_preview = (parsed.get("body_text") or "")[:500]
    parts = [f"HTTP {status}", f"{ct}", f"{size}B"]
    if body_preview:
        parts.append(f"body[:500]={body_preview!r}")
    summary = " | ".join(parts)
    return {
        "summary": summary,
        "row_hint_format": "full response incl. headers + raw body is in scratch; filter with scratch_search",
    }