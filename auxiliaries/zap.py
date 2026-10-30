"""OWASP ZAP HTTP API client + framework tools.

Talks to a headless ZAP daemon (launched via ``-daemon``; Kali's
``zaproxy``/``owasp-zap`` wrappers and the upstream ``zap.sh`` both take the
same flags) over its plain-HTTP API
(loopback only). The daemon is launched by ``bootstrap.start_zap_daemon`` and
exposes the API at ``http://127.0.0.1:<ZAP_PORT>`` with the configured
``ZAP_API_KEY`` sent as the ``apikey`` query parameter on every call.

Why HTTP-API rather than the ZAP MCP add-on
-------------------------------------------
The MCP add-on (port 8282) is fine but adds a second protocol layer the model
would have to reason about. The HTTP API has been stable since 2.x and gives
us exactly the primitives we want: spider, AJAX spider, active scan, alerts,
alerts by id, raw HTTP messages by URL, sites tree, and report generation.
We get "ZAP-as-grep" via ``zap_history_regex`` which calls ``core/view/getMessage``
to pull the raw response and runs a local ``re.search`` on it -- the model
can then ask things like "show me every form on the page that lacks a CSRF
token" without standing up a second LLM loop.

The client is a stateful singleton (``ZAPClient.get_instance()``) following
the same pattern as ``MetasploitClient`` -- this lets the Brain's instance
cache and the in-process fallback share one ``requests.Session`` and one
configured base URL / API key.

All public methods are wrapped as ``@framework_tool``-decorated module-level
functions so the static AST discovery pass + Brain scan both pick them up.
Sync only: every call hits a local daemon and never blocks longer than a
couple of seconds, but they're invoked in worker threads by both dispatchers
anyway, so we don't pay the async tax.
"""

from __future__ import annotations
import logging

import json
import re
from typing import Any, cast

import requests
import requests.adapters
from urllib3.util.retry import Retry

# --- carved guts (tool surface never moves; plain-helper shims are lane-legal)
from auxiliaries._zap_api import (
    ZAP_API_KEY,
    ZAP_BASE,
    ZAP_HOST,  # noqa: F401 - facade re-export (daemon binds it via ZAP_BASE)
    ZAP_PORT,  # noqa: F401 - facade re-export (bootstrap probes ZAP via env)
    ZAPAPIError,
    _canonical,
    _canonical_from_envelope,
    _status_from_headers,
    _zap_error_guard,
)
from auxiliaries._zap_scope_sync import (
    _host_from_raw_request,
    drift_guard,
)
from auxiliaries._zap_scope_sync import (
    sync_protect_scope as _scope_sync_impl,
)
from constants import framework_tool

# Prefix for replacer / rate-limit rule descriptions so we can find and
# remove our own rules without touching user-defined ones.
_RI_PREFIX = "intigriti-roar-"


class ZAPClient:
    """Single shared client; configured once from env at first instantiation.

    Tools reach the daemon via ``ZAPClient.get_instance()`` so the API key,
    base URL, and ``requests.Session`` (which keeps a TCP keep-alive) are
    reused across the whole process.
    """

    _instance: ZAPClient | None = None

    @classmethod
    def get_instance(cls) -> ZAPClient:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self) -> None:
        self.base = ZAP_BASE
        self.api_key = ZAP_API_KEY
        self.session = requests.Session()
        # Retry budget for VIEW endpoints only (read-only, idempotent): the
        # daemon can return 503 briefly while initialising its DB, and 500
        # during heavy scans / OOM-adjacent GC pauses.
        #
        # IMPORTANT: this retry is mounted on self.session and applies to ALL
        # requests that go through it.  ACTION endpoints (sendRequest, scan,
        # spider, etc.) are side-effecting — retrying a sendRequest that
        # timed out means ZAP sends the raw request to the target AGAIN,
        # and each retry blocks for ZAP's internal connection timeout
        # (~30s to an unreachable host).  5 retries × 30s = 150s+ of frozen
        # worker thread, which compounds against BRAIN_DISPATCH_TIMEOUT and
        # freezes the whole stack.
        #
        # Fix: action endpoints use a SEPARATE session (_action_session)
        # with NO retry adapter and a shorter per-call timeout.  _get()
        # routes automatically based on the view string.
        retry = Retry(
            total=5, backoff_factor=0.5,
            status_forcelist=(500, 502, 503, 504),
            allowed_methods=frozenset(["GET"]),
        )
        self.session.mount("http://", requests.adapters.HTTPAdapter(max_retries=retry))
        # Action session: no retries, no keep-alive surprises.  Used for any
        # view string containing "/action/".
        self._action_session = requests.Session()

    # ---- raw transport ---------------------------------------------------

    def _get(self, view: str, expect_json: bool = True, timeout: float = 120.0, **q: Any) -> Any:
        params = dict(q)
        if self.api_key:
            params["apikey"] = self.api_key
        # ZAP 2.17 requires the /JSON/ URL prefix for JSON responses. Without
        # it the request returns 400 Bad Format (the daemon's old path-based
        # format detection is broken: it tries to parse the first path
        # segment -- e.g. "core" -- as the format enum and dies).
        url = f"{self.base}/JSON/{view}"
        # Route action endpoints through the no-retry session so a timed-out
        # sendRequest doesn't get retried 5× (each retry blocks for ZAP's
        # internal connection timeout to the target — the "freeze the whole
        # stack" root cause).
        is_action = "/action/" in view
        sess = self._action_session if is_action else self.session
        r = sess.get(url, params=params, timeout=timeout)
        if not r.ok:
            # Extract the ZAP error body so callers see the actual reason
            # (e.g. "url_not_found: URL Not Found in the Scan Tree") instead
            # of a useless "400 Client Error" from raise_for_status().
            code = ""
            message = r.text[:2000]
            try:
                body = r.json()
                if isinstance(body, dict):
                    code = body.get("code", code)
                    message = body.get("message", message)
            except (ValueError, json.JSONDecodeError):
                pass
            raise ZAPAPIError(r.status_code, code, message)
        if expect_json:
            return r.json()
        return r.text

    def healthcheck(self) -> bool:
        """Return True if the daemon responds with any HTTP status (it always
        answers 200 on the root even before the API is fully wired). Used by
        ``bootstrap.wait_for_zap`` during launch."""
        try:
            self.session.get(self.base, timeout=2)
            return True
        except requests.RequestException:
            return False

    # ---- primitives ------------------------------------------------------

    def open_url(self, url: str, follow_redirects: bool = False) -> dict[str, Any]:
        """Load a URL into the session; passive scanner observes it.

        ``core/action/accessUrl`` supports an optional ``followRedirects``
        param — defaults here to False (redirect-locked at tool/call level):
        a 3xx hop to an out-of-scope host must never be followed ungated.
        """
        _zap_scope_drift_guard()
        return self._get(
            "core/action/accessUrl",
            url=url,
            followRedirects=str(bool(follow_redirects)).lower(),
        )

    # ---- mode + protect-scope (2026-09-19) ------------------------------

    def get_mode(self) -> str:
        resp = self._get("core/view/mode")
        if isinstance(resp, dict):
            return str(resp.get("mode", ""))
        return str(resp)

    def set_mode(self, mode: str) -> None:
        self._get("core/action/setMode", mode=mode)

    def _context_exists(self, name: str) -> bool:
        try:
            resp = self._get("context/view/contextList")
            names = resp.get("contextList", []) if isinstance(resp, dict) else []
            return name in names
        except Exception:  # noqa: BLE001 - a failed list is not proof of absence
            return False

    def context_new(self, name: str) -> None:
        if self._context_exists(name):
            return
        self._get("context/action/newContext", contextName=name)
        self._get(
            "context/action/setContextInScope",
            contextName=name,
            booleanInScope="true",
        )

    def context_include(self, name: str, regex: str) -> None:
        self._get("context/action/includeInContext", contextName=name, regex=regex)

    def context_exclude(self, name: str, regex: str) -> None:
        self._get("context/action/excludeFromContext", contextName=name, regex=regex)

    # ---- scan-config enforcement (Intigriti RoE) -------------------------

    def clear_ri_rules(self) -> list[dict[str, str]]:
        """Remove all framework-managed replacer + rate-limit rules.

        ZAP replacer and rate-limit rules are **daemon-global** — they
        persist across scope switches.  After an Adobe session, a stale
        ``X-Intigriti-Username`` header and Adobe's rate cap would still
        be applied to whatever you scan next (cross-program header leak).

        This method enumerates all rules whose description starts with
        ``_RI_PREFIX`` and removes them.  Called at the start of
        ``configure_scan_config`` so stale rules from a previous program
        are cleared before new ones are applied.

        Returns a list of ``{"type": ..., "description": ..., "status": ...}``
        dicts so callers can audit what was cleared.
        """
        cleared: list[dict[str, str]] = []

        # --- Replacer rules ---
        # ZAP 2.17 wraps the list under the "rules" key (NOT "replacerRules").
        try:
            rules = self._get("replacer/view/rules")
            rule_list = rules.get("rules", []) if isinstance(rules, dict) else []
            if not isinstance(rule_list, list):
                rule_list = []
            for r in rule_list:
                desc = r.get("description", "")
                if desc.startswith(_RI_PREFIX):
                    try:
                        self._get("replacer/action/removeRule", description=desc)
                        cleared.append({"type": "replacer", "description": desc, "status": "removed"})
                    except Exception as e:
                        cleared.append({"type": "replacer", "description": desc, "status": f"remove_failed: {e}"})
        except Exception as e:
            cleared.append({"type": "replacer", "description": "_list", "status": f"list_failed: {e}"})

        # --- Rate-limit rules ---
        # ZAP 2.17's endpoint is network/view/getRateLimitRules (NOT
        # rateLimitRules), and the response key is "getRateLimitRules".
        try:
            rules = self._get("network/view/getRateLimitRules")
            rule_list = rules.get("getRateLimitRules", []) if isinstance(rules, dict) else []
            if not isinstance(rule_list, list):
                rule_list = []
            for r in rule_list:
                desc = r.get("description", "")
                if desc.startswith(_RI_PREFIX):
                    try:
                        self._get("network/action/removeRateLimitRule", description=desc)
                        cleared.append({"type": "ratelimit", "description": desc, "status": "removed"})
                    except Exception as e:
                        cleared.append({"type": "ratelimit", "description": desc, "status": f"remove_failed: {e}"})
        except Exception as e:
            cleared.append({"type": "ratelimit", "description": "_list", "status": f"list_failed: {e}"})

        return cleared

    def configure_scan_config(self, target: str,
                              scope_handle: str,
                              scope_platform: str) -> dict[str, Any] | None:
        """Auto-apply mandatory testing requirements from the program manifest.

        When ``scope_platform`` is ``"intigriti"`` and the cached manifest
        mandates a custom User-Agent, request header, or req/sec cap, this
        method configures the live ZAP daemon so that *every* subsequent
        request (spider, active scan, send_raw) carries the required headers
        and respects the rate limit:

        - **Replacer rules** (``replacer/action/addRule``): inject each
          mandated header into all outgoing requests.  Rules are idempotent
          — re-calling with the same description is a no-op (old rule is
          removed first).
        - **Rate limit rule** (``network/action/addRateLimitRule``): cap
          requests per second to the target host.  ZAP 2.17+ supports this
          natively in the ``network`` component.
        - **Thread limits**: spider and active-scan threads are capped to
          a conservative number derived from the req/sec cap, so the rate
          limit isn't overwhelmed by concurrency.

        **Stale-rule cleanup**: all framework-managed rules (prefixed
        ``_RI_PREFIX``) are cleared at the start so rules from a previous
        program session don't leak into the current one (cross-program
        header contamination).

        **Rate-only programs**: rate caps are injected independently of
        headers — a program that mandates only a req/sec cap (no custom
        UA/header) still gets its rate limit enforced.

        Returns the resolved scan config dict augmented with a
        ``"rule_status"`` list (per-rule apply/clear outcome) for surfacing
        in the tool envelope, or ``None`` when no config applies.
        """
        try:
            from auxiliaries.program_scope import get_scan_config
            cfg = get_scan_config(scope_handle, scope_platform)
        except Exception:
            return None
        if not cfg:
            return cfg

        from urllib.parse import urlparse
        host = urlparse(target if "://" in target else f"http://{target}").hostname or target

        rule_status: list[dict[str, str]] = []

        # --- Clear stale framework rules from previous scope switches -----
        # Replacer/rate rules are daemon-global; without this, an Adobe
        # session's X-Intigriti-Username header leaks into the next scan.
        rule_status.extend(self.clear_ri_rules())

        # --- Replacer rules: inject headers into all requests ------------
        # Rate-only configs have no headers — skip this block cleanly.
        for hname, hval in (cfg.get("headers") or {}).items():
            desc = f"{_RI_PREFIX}header-{hname.lower()}"
            # Idempotent: remove an existing rule with the same description
            # before adding the fresh one.
            try:
                self._get("replacer/action/removeRule", description=desc)
            except Exception:
                # rule doesn't exist yet — fine (i guess..)
                logging.getLogger(__name__).debug(
                    "swallowed exception in configure_scan_config", exc_info=True)
            try:
                self._get(
                    "replacer/action/addRule",
                    description=desc,
                    enabled="true",
                    matchType="REQ_HEADER",
                    matchString=hname,
                    replacement=hval,
                    initiators="",
                    matchRegex="false",
                )
                rule_status.append({"type": "replacer", "description": desc, "status": "applied"})
            except Exception as e:
                # Don't swallow — surface the failure so the envelope
                # reports it.  A RoE-mandated header that silently failed
                # to apply is a compliance violation, not a best-effort nicety.
                rule_status.append({"type": "replacer", "description": desc, "status": f"failed: {e}"})

        # --- Rate limit rule: cap req/sec to the target host --------------
        # Injected independently of headers so rate-only programs are enforced.
        rate = cfg.get("max_requests_per_second")
        if rate and rate > 0:
            rl_desc = f"{_RI_PREFIX}ratelimit-{host}"
            try:
                self._get("network/action/removeRateLimitRule", description=rl_desc)
            except Exception:
                logging.getLogger(__name__).debug(
                    "swallowed exception in configure_scan_config", exc_info=True)
            try:
                self._get(
                    "network/action/addRateLimitRule",
                    description=rl_desc,
                    enabled="true",
                    matchRegex="false",
                    matchString=host,
                    requestsPerSecond=str(rate),
                    groupBy="host",
                )
                rule_status.append({"type": "ratelimit", "description": rl_desc, "status": "applied"})
            except Exception as e:
                rule_status.append({"type": "ratelimit", "description": rl_desc, "status": f"failed: {e}"})

            # Cap threads to a conservative number so concurrency doesn't
            # overwhelm the rate limiter.  ~1 thread per 5 req/sec, min 1.
            threads = max(1, min(8, rate // 5))
            try:
                self._get("spider/action/setOptionThreadCount", Integer=str(threads))
                rule_status.append({"type": "spider_threads", "description": str(threads), "status": "applied"})
            except Exception as e:
                rule_status.append({"type": "spider_threads", "description": str(threads), "status": f"failed: {e}"})
            try:
                self._get("ascan/action/setOptionThreadPerHost", Integer=str(threads))
                rule_status.append({"type": "ascan_threads", "description": str(threads), "status": "applied"})
            except Exception as e:
                rule_status.append({"type": "ascan_threads", "description": str(threads), "status": f"failed: {e}"})

        cfg["rule_status"] = rule_status
        return cfg

    def send_raw(self, raw_request: str,
                 follow_redirects: bool = False,
                 timeout: float = 30.0) -> dict[str, Any]:
        """Send a raw HTTP request byte-for-byte through ZAP's HTTP sender.

        Uses the core ``core/action/sendRequest`` endpoint (no add-on
        required). The sent message is recorded in ZAP history and the
        passive scanner observes the response, exactly like a proxied
        request. Returns the standard message envelope (requestHeader /
        responseHeader / responseBody / id).

        Drift-guarded like every traffic-bearing ZAP method (2026-09-20):
        the protect-mode mirror is re-synced at call time when the armed
        scope changed, so a scope edit never leaves the mirror stale.

        Timeout: defaults to 30s (NOT the 120s view-endpoint default).
        ``sendRequest`` blocks while ZAP's internal HTTP client connects to
        the target — an unreachable host hangs for ZAP's connection-timeout
        budget.  The action session has NO retry, so a timeout surfaces
        immediately as a ``requests.exceptions.ReadTimeout`` instead of
        retrying 5× and freezing the stack for minutes.
        Scheme fallback (2026-09-29): origin-form request lines are
        scheme-forced to https first (see ``_ensure_https_scheme``). When
        that forced attempt fails BEFORE any HTTP exchange — ZAP 2.17's
        new sender turns a TLS/connect exception into an API-500
        ``internal_error`` and a silent port into the synthetic zero
        envelope — the request is retried ONCE over the scheme as written
        (plain http → port 80 for origin-form lines). Nothing was
        delivered by the failed attempt, so the retry cannot double-send.
        Client-side timeouts are never retried: the request may already
        be in flight.
        """
        _zap_scope_drift_guard()
        as_written = raw_request
        wire = self._ensure_https_scheme(raw_request)
        scheme_forced = wire != as_written
        try:
            resp = self._send_request_once(wire, follow_redirects, timeout)
        except ZAPAPIError as first_err:
            # Retry only for pre-HTTP failures: API-500 (the raised TLS/
            # connect exception in ZAP 2.17, e.g. "SSLException:
            # Unsupported or unrecognized SSL message" against a non-TLS
            # :443) or the synthetic zero envelope.  The HTTP request
            # never left in either case, so one as-written retry is
            # side-effect safe.  Client timeouts (code "timeout") mean the
            # request may already have been delivered — never retried.
            fallback = scheme_forced and (
                first_err.status_code >= 500 or first_err.code == "no_response")
            if not fallback:
                raise
            try:
                resp = self._send_request_once(as_written, follow_redirects, timeout)
            except ZAPAPIError as retry_err:
                raise ZAPAPIError(
                    retry_err.status_code, retry_err.code,
                    f"https send failed ({first_err.code}: "
                    f"{first_err.message}); the request as written also "
                    f"failed: {retry_err.message}"
                ) from retry_err
            resp["scheme_fallback"] = (
                "https probe failed before any HTTP exchange (TLS "
                "handshake/connect error) — retried once over the request "
                "as written (origin-form → plain http, default port)."
            )
            return resp
        return resp

    def _send_request_once(self, request: str, follow_redirects: bool,
                           timeout: float) -> dict[str, Any]:
        """One ``sendRequest`` attempt: returned envelope, or raise.

        The synthetic zero-response envelope (target never spoke HTTP;
        status line ``HTTP/1.0 0``) is raised as ``ZAPAPIError(0,
        "no_response")`` so send_raw's scheme fallback treats it like any
        other pre-HTTP failure.
        """
        try:
            resp = self._get(
                "core/action/sendRequest",
                request=request,
                followRedirects=str(follow_redirects).lower(),
                timeout=timeout,
            )
            # core/action/sendRequest wraps the message envelope under a
            # "sendRequest" key; return the envelope itself.
            if isinstance(resp, dict) and "sendRequest" in resp:
                inner = resp["sendRequest"]
                # some ZAP builds return the envelope(s) as a list.
                if isinstance(inner, list) and inner:
                    resp = inner[0]
                else:
                    resp = inner
            # Detect ZAP's "zero response" envelope: when the target is
            # unreachable, ZAP returns 200 OK with a synthetic response
            # whose status line is "HTTP/1.0 0" and an empty body.  Surface
            # this as a clear error so the caller knows the target didn't
            # respond, rather than treating it as a successful empty page.
            # The status TOKEN is compared, not the raw line: splitlines()
            # strips \r, so a " 0\r" substring check can never match.
            rh = (resp or {}).get("responseHeader", "")
            first_line = rh.splitlines()[0] if rh.splitlines() else ""
            toks = first_line.split()
            status = toks[1] if len(toks) >= 2 else ""
            if status == "0":
                req_h = (resp or {}).get("requestHeader", "")
                first = req_h.splitlines()[0] if req_h else "(unknown)"
                raise ZAPAPIError(
                    0, "no_response",
                    "ZAP sent the request but the target did not respond "
                    "(connection failed/timed out). Synthetic zero-status "
                    f"response for: {first}"
                )
            return cast(dict[str, Any], resp)
        except requests.exceptions.Timeout as e:
            # The action session has no retry, so this fires once and
            # surfaces immediately.  Wrap it so the _zap_error_guard
            # returns a structured dict instead of a bare exception.
            raise ZAPAPIError(
                0, "timeout",
                f"ZAP sendRequest timed out after {timeout}s — the target "
                f"is likely unreachable. {e}"
            ) from e
        except requests.HTTPError as e:
            # Fallback for non-ZAP HTTP errors (proxy, network, etc.).
            if e.response is not None and e.response.status_code == 400:
                raise ValueError(
                    f"ZAP rejected the raw request: {e.response.text[:2000]}"
                ) from e
            raise

    @staticmethod
    def _ensure_https_scheme(raw_request: str) -> str:
        """Rewrite origin-form request lines to absolute-form so ZAP honors
        the scheme. ZAP's sendRequest infers port 80 for origin-form lines
        ("GET /path HTTP/1.1") -- the Host header alone does not carry the
        scheme, so TLS hosts get probed over plain HTTP and come back as
        301s. This prepends ``https://<host>`` to the request target (https
        by default, since plain-http targets are rare in the wild).

        To force plain http for a specific request, write the request line
        in absolute form yourself, e.g. ``GET http://host/path HTTP/1.1``.
        Any line whose target already contains ``://`` is treated as
        absolute-form and passed through untouched, so ZAP honors whichever
        scheme you wrote.

        The following are also passed through unchanged: single-line
        requests with no header section, malformed request lines (not
        exactly three whitespace-separated tokens), and origin-form
        requests that carry no Host header (there is nothing to derive
        the host from).

        The https-default is safe against plain-http origins: send_raw
        retries once over the as-written scheme when the forced attempt
        fails before any HTTP exchange (TLS handshake error / silent
        port), so origin-form requests land on the origin's plain http
        port instead of surfacing a ZAP 500.
        """
        first, sep, rest = raw_request.partition("\n")
        if not sep:
            return raw_request
        parts = first.split()
        if len(parts) != 3 or "://" in parts[1]:
            return raw_request  # malformed, or already absolute-form
        host = ""
        for line in rest.split("\n"):
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip()
                break
        if not host:
            return raw_request
        parts[1] = f"https://{host}{parts[1]}"
        return " ".join(parts) + "\n" + rest

    def spider(self, url: str, max_depth: int = 5, recurse: bool = True) -> str:
        """Start the traditional crawler; returns the scan id (e.g. ``"0"``).

        ``max_depth`` is applied via ``setOptionMaxDepth`` because
        ``spider/action/scan`` does NOT accept a ``maxDepth`` query
        parameter (ZAP silently ignores unknown params).  The accepted
        scan-action params are: ``url``, ``maxChildren``, ``recurse``,
        ``contextName``, ``subtreeOnly``.
        """
        _zap_scope_drift_guard()
        # Set the global max-depth option before launching — the scan
        # action has no maxDepth parameter of its own.
        if max_depth != 5:
            try:
                self._get("spider/action/setOptionMaxDepth", Integer=str(max_depth))
            except Exception:
                # non-fatal: scan still runs with the previous depth
                logging.getLogger(__name__).debug(
                    "swallowed exception in spider", exc_info=True)
        return self._get(
            "spider/action/scan", url=url,
            recurse=str(recurse).lower(),
        ).get("scan", "")

    def spider_status(self, scan_id: str) -> int:
        """0..100 progress; 100 means done."""
        return int(self._get("spider/view/status", scanId=scan_id).get("status", 0))

    def ajax_spider(self, url: str) -> str:
        _zap_scope_drift_guard()
        """Start the headless-browser AJAX spider.

        The AJAX spider is a **singleton** — there is no per-scan ID like
        the traditional spider or active scanner.  The API returns
        ``{"Result": "OK"}`` with no ``scan`` key.  Poll progress with
        ``ajax_spider_status()`` (takes no scan-id).  Returns ``"OK"``
        so the wrapper can report a non-empty, meaningful value.
        """
        result = self._get("ajaxSpider/action/scan", url=url)
        # The response is {"Result": "OK"} — no scan ID.  Return the result
        # string so the caller gets a truthy, non-empty value instead of "".
        if isinstance(result, dict):
            return result.get("Result", "started")
        return "started"

    def ajax_spider_status(self) -> str:
        """Running / stopped / finished."""
        return self._get("ajaxSpider/view/status").get("status", "unknown")

    def active_scan(self, url: str, policy: str | None = None) -> str:
        _zap_scope_drift_guard()
        """Run an active scan against a URL (optionally with a named policy)."""
        q: dict[str, Any] = {"url": url, "recurse": "true"}
        if policy:
            q["scanPolicyName"] = policy
        return self._get("ascan/action/scan", **q).get("scan", "")

    def active_scan_status(self, scan_id: str) -> int:
        """0..100 progress."""
        return int(self._get("ascan/view/status", scanId=scan_id).get("status", 0))

    def alerts_summary(self, base_url: str | None = None) -> dict[str, int]:
        """Number of alerts grouped by risk level (the lightweight triage view).

        Uses ``alert/view/alertsSummary`` so we get just counts — not the giant
        per-alert objects — which is what ``zap_active_scan_status`` surfaces
        when a scan reaches 100 so the secretary gets actionable triage in the
        same poll instead of a bare progress integer with ~0% information.
        """
        q: dict[str, Any] = {}
        if base_url:
            q["baseurl"] = base_url
        raw = self._get("alert/view/alertsSummary", **q)
        # ZAP wraps the result as {"alertsSummary": {"High": N, ...}} in some
        # builds and returns the flat dict in others; normalise both.
        summary = raw.get("alertsSummary", raw)
        return {k: int(v) for k, v in summary.items() if isinstance(v, (int, str))}

    def alerts(
        self,
        base_url: str | None = None,
        risk_id: int | None = None,
        summary: bool = True,
        max_alerts: int = 50,
    ) -> list[dict[str, Any]]:
        """List all alerts raised (optionally filtered by URL prefix and risk
        level: 0 informational, 1 low, 2 medium, 3 high, 4 informational).

        ZAP alert objects are huge -- each carries multi-paragraph ``desc``,
        ``solution``, a ``reference`` URL block, a full ``instance`` array of
        every occurrence, plus ``attack``/``evidence``/``other`` payloads. A
        modest scan of 40 alerts is 100KB+ of JSON, which dominates the model
        context window. By default we project each alert down to the compact
        triage fields the model needs to *prioritise* (id, name, risk,
        confidence, cweid, count, first occurrence url/param/method/evidence).
        Pass ``summary=False`` for the raw ZAP objects, or use
        ``zap_alert_message`` to drill into a single alert's full metadata +
        HTTP wire bytes.
        """
        q: dict[str, Any] = {}
        if base_url:
            q["baseurl"] = base_url
        if risk_id is not None:
            q["riskId"] = risk_id
        raw = self._get("alert/view/alerts", **q).get("alerts", [])
        if not summary:
            return raw
        projected: list[dict[str, Any]] = []
        for a in raw[:max_alerts]:
            inst = a.get("instance") or []
            first = inst[0] if inst else {}
            projected.append({
                "id": a.get("id"),
                "name": a.get("name"),
                "riskcode": a.get("riskcode"),
                "risk": a.get("risk"),
                "confidence": a.get("confidence"),
                "cweid": a.get("cweid"),
                "count": a.get("count"),
                "occurrences": len(inst),
                "url": first.get("uri", ""),
                "method": first.get("method", ""),
                "param": first.get("param", ""),
                # Cap evidence so a giant reflected payload can't blow up a
                # single summary record; the full bytes live in zap_alert_message.
                "evidence": (first.get("evidence", "") or "")[:120],
            })
        if len(raw) > max_alerts:
            projected.append({
                "_truncated": True,
                "_total_alerts": len(raw),
                "_returned": max_alerts,
                "_hint": "call zap_alerts again with max_alerts raised, or "
                         "filter by risk_id, to see more",
            })
        return projected

    def alert_message(self, alert_id: str) -> dict[str, Any]:
        """Return the alert metadata AND the full HTTP message that triggered it.

        ZAP 2.17 dropped ``alert/view/message`` (returns ``BAD_VIEW``). The
        supported path is two hops: ``alert/view/alert?id=...`` gives us the
        alert metadata including ``messageId``, then ``core/view/message?id=...``
        returns the actual HTTP wire bytes for that message. We return both
        so the model can see what rule fired AND what request it fired on.
        """
        alert_envelope = self._get("alert/view/alert", id=alert_id)
        alert = alert_envelope.get("alert", {})
        message_id = alert.get("messageId")
        if not message_id:
            return {"alert": alert, "message": None,
                    "error": "alert has no messageId (no associated request)"}
        msg_envelope = self._get("core/view/message", id=message_id)
        msg = msg_envelope.get("message", {})
        return {
            "alert": alert,
            "message": {
                "request": msg.get("requestHeader", ""),
                "response_headers": msg.get("responseHeader", ""),
                "response_body": msg.get("responseBody", ""),
                "response_status": _status_from_headers(msg.get("responseHeader", "")),
            },
        }

    def history_regex(
        self, url: str, pattern: str, body_only: bool = True,
    ) -> dict[str, Any]:
        """Fetch the raw HTTP message for ``url`` and run ``re.search`` over
        it. This is the "ZAP-as-grep" entry point: the model can ask for any
        substring/regex across a previously-spidered response -- e.g. all
        ``<input type="hidden"`` fields, every form action, every JS endpoint.

        Implementation note: ZAP 2.17 renamed ``core/view/getMessage`` (now
        ``BAD_VIEW``); the supported endpoint is ``core/view/messages?url=...``
        which returns a list of full message envelopes. We take the first
        match -- sufficient for any URL the spider actually fetched.
        """
        msgs = self._get("core/view/messages", url=url).get("messages", [])

        # ZAP's ``messages?url=...`` is fuzzy: it returns any envelope whose
        # URL *contains* the requested string, and if no match exists it
        # returns the entire history. We must verify the envelope we got
        # actually corresponds to ``url`` before grepping it, or we'd silently
        # grep a different page and the model would never know.
        target = _canonical(url)
        exact = [m for m in msgs if target in _canonical_from_envelope(m)]
        if not exact:
            return {
                "url": url,
                "pattern": pattern,
                "error": (
                    f"no history entry for {url!r} (have you spidered it "
                    f"yet? messages endpoint returned {len(msgs)} unrelated "
                    "envelopes)"
                ),
                "match_count": 0,
                "matches": [],
            }
        envelope = exact[0]
        if body_only:
            body = envelope.get("responseBody", "")
        else:
            # Stitch the raw HTTP wire bytes: response headers + blank line + body.
            body = (
                envelope.get("responseHeader", "")
                + "\r\n\r\n"
                + envelope.get("responseBody", "")
            )
        try:
            rx = re.compile(pattern, re.DOTALL)
        except re.error as e:
            return {"error": f"invalid regex: {e}", "matches": []}
        matches = rx.findall(body)
        return {
            "url": url,
            "pattern": pattern,
            "body_bytes": len(body),
            "match_count": len(matches),
            "matches": matches[:200],  # cap so the model doesn't drown in output
            "truncated": len(matches) > 200,
        }

    def sites(self) -> list[str]:
        """Top-level hosts discovered by the session."""
        return self._get("core/view/sites").get("sites", [])

    def sites_tree(self, url: str | None = None) -> str:
        """Full discovered-URL hierarchy as a JSON string.

        ZAP 2.17 removed ``core/view/sitesTree`` (it returns ``BAD_VIEW`` /
        HTTP 400 on every call), so we reconstruct the tree client-side from
        ``core/view/urls``, which returns every URL the session has seen.
        Pass ``url`` to scope to a single subtree via ZAP's ``baseurl``
        filter.

        The returned shape is ``{"sites": {host: {path: {...}}}}`` -- a
        nested dict keyed by ``scheme://host:port`` then by path segments,
        with a ``"__urls__"`` leaf listing the full URLs that terminate each
        node. This mirrors the old native tree well enough for triage.

        ``url`` is lenient: a bare host (``"10.10.10.110"``) or a host with
        a port but no scheme is normalised to ``http://...`` so it matches
        the ``baseurl`` prefix filter ZAP applies server-side. A leading
        scheme is preserved; trailing slashes are kept since ZAP's filter is
        a plain prefix match.
        """
        from urllib.parse import urlsplit

        q: dict[str, Any] = {}
        if url:
            u = url.strip()
            # Accept bare hosts ("10.10.10.110") and "host:port" forms that
            # lack a scheme; urlsplit mis-parses those (host -> path), so we
            # prepend a default scheme before handing to baseurl.
            if "://" not in u:
                u = "http://" + u
            q["baseurl"] = u
        try:
            urls = self._get("core/view/urls", **q).get("urls", [])
        except ZAPAPIError as e:
            return json.dumps({
                "error": True,
                "zap_error_code": e.code,
                "zap_error_body": e.message,
                "fallback_sites": self.sites(),
            })
        except requests.HTTPError as e:
            resp = getattr(e, "response", None)
            body = resp.text[:2000] if resp is not None else ""
            return json.dumps({
                "error": True,
                "zap_error_body": body,
                "fallback_sites": self.sites(),
            })

        tree: dict[str, Any] = {}
        for raw in urls:
            try:
                parts = urlsplit(raw)
            except ValueError:
                continue
            if not parts.scheme or not parts.netloc:
                continue
            root = f"{parts.scheme}://{parts.netloc}"
            node = tree.setdefault(root, {})
            segments = [s for s in parts.path.split("/") if s]
            for seg in segments:
                node = node.setdefault(seg, {})
            node.setdefault("__urls__", []).append(raw)

        return json.dumps({"sites": tree}, indent=2)

    def report(
        self,
        report_format: str = "html",
        report_file: str = "/tmp/zap_report.html",
        report_title: str = "Framework ZAP scan",
    ) -> dict[str, Any]:
        """Generate a local report (html / xml / json / md). Returns the path.

        The ZAP ``reports`` add-on is NOT bundled into the daemon JAR --
        a vanilla daemon invocation returns ``no_implementor`` (HTTP 400)
        for any /report/ endpoint. We detect that case and return a
        structured error instead of letting the exception bubble, so the
        model can suggest installing the add-on from the marketplace.
        """
        _addon_hint = (
            "ZAP reports add-on is not installed. The vanilla ZAP daemon "
            "image does not bundle it. Run the daemon once with "
            "`-addoninstall reports` (Kali: `zaproxy -daemon -addoninstall "
            "reports`, plain ZAP: `zap.sh -daemon -addoninstall reports`) "
            "to install, or fetch the reports add-on from the ZAP "
            "marketplace, then restart the daemon."
        )
        try:
            self._get(
                "report/action/generate",
                reportFormat=report_format,
                reportFileName=report_file,
                reportTitle=report_title,
            )
        except ZAPAPIError as e:
            # 400 + body containing "no_implementor" -> add-on missing.
            if "no_implementor" in e.message:
                return {"path": None, "error": _addon_hint}
            raise
        except requests.exceptions.HTTPError as e:
            # Fallback for non-ZAP HTTP errors.
            if (e.response is not None
                    and "no_implementor" in (e.response.text or "")):
                return {"path": None, "error": _addon_hint}
            raise
        return {"path": report_file}


def _zap() -> ZAPClient:
    return ZAPClient.get_instance()


# --- @framework_tool wrappers ----------------------------------------------
#
# Doc strings here are what the registry embeds for semantic matching. Keep
# them concrete ("...returns a scan_id you poll with zap_spider_status")
# rather than vague ("runs a scan") -- the secretary picks tools by meaning.


@framework_tool(
    "Open a URL in the ZAP session (passive scan starts observing). "
    "When scope_handle+scope_platform are given for an Intigriti program, "
    "mandatory testing requirements (custom User-Agent, X-Intigriti-Username "
    "header, req/sec cap) are auto-applied to the ZAP daemon so every "
    "subsequent spider/active-scan request respects the RoE.",
)
@_zap_error_guard
def zap_open_url(target: str,
                 scope_handle: str | None = None,
                 scope_platform: str | None = None) -> dict[str, Any]:
    """Open a single URL so ZAP observes it. Use this before spidering or
    scanning to seed the session with a known-good entry point.

    When ``scope_handle`` and ``scope_platform`` are provided for an
    Intigriti program, the program manifest's testing requirements are
    auto-applied to the ZAP daemon (replacer rules for headers, network
    rate-limit rule, conservative thread caps) before the URL is opened.
    This ensures all subsequent traffic carries the required attribution
    headers and respects the req/sec cap.

    Args:
        target: Fully qualified URL including scheme, e.g. ``http://10.10.10.110/``.
            Must be reachable from this host; ZAP fetches it directly.
        scope_handle: Program handle for auto-injection of mandatory testing
            requirements (Intigriti RoE). Pair with ``scope_platform``.
        scope_platform: Platform key (``"intigriti"``, ``"h1"``, etc.).
            Only ``"intigriti"`` has structured testing requirements.
    """
    # Scope gate (operator-armed from the Tool REPL; no-op in lab mode).
    from utils.scope_gate import check_scan, ScopeGateError
    _sc_ok, _sc_reason = check_scan(target)
    if not _sc_ok:
        raise ScopeGateError(f"scope gate: {_sc_reason}")

    zap = _zap()
    scan_cfg = None
    if scope_handle and scope_platform:
        scan_cfg = zap.configure_scan_config(target, scope_handle, scope_platform)
    # Redirect-locked at tool/call level: accessUrl's followRedirects param
    # is passed explicitly as False (2026-09-19 redirect-bypass fix). ZAP
    # has NO API-level global redirect off (network component has no such
    # option) — every direct request tool must carry the lock itself.
    result = zap.open_url(target, follow_redirects=False)
    result["redirect_lock"] = "followRedirects=false (accessUrl)"
    if scan_cfg:
        result["scan_config_applied"] = scan_cfg
    return result


@framework_tool(
    "Start the traditional ZAP spider against a URL; returns spider_id. "
    "Confirm launch with one status call, then hand off to the user; poll "
    "again only when the user requests an update."
)
@_zap_error_guard
def zap_spider(target: str, max_depth: int = 5, recurse: bool = True) -> dict[str, str]:
    """Crawl from ``target`` up to ``max_depth`` hops. Returns the spider id;
    perform one status call to confirm launch, then hand off to the user.
    Poll again only when the user requests an update.

    Args:
        target: Fully qualified URL to start crawling from.
        max_depth: Maximum link depth from ``target`` (default 5).
        recurse: Follow links recursively (default True). Set False for a
            single-page fetch.

    Redirect residual: the spider API has NO follow-redirects parameter
    (ZAP's network component exposes no such option either, verified against
    the 2.16 API catalogue) — redirect following is ZAP-internal here. The
    call-level control that DOES exist is ZAP's own scope (spider
    excludeFromScan / domainsAlwaysInScope) plus ZAP mode=protect, which
    makes ZAP itself refuse out-of-scope hops. Operator-level decision.
    """
    from utils.scope_gate import check_scan, ScopeGateError
    _sc_ok, _sc_reason = check_scan(target)
    if not _sc_ok:
        raise ScopeGateError(f"scope gate: {_sc_reason}")
    return {"spider_id": _zap().spider(target, max_depth=max_depth, recurse=recurse)}


@framework_tool(
    "Get spider progress (0..100) for a given spider_id. Call once only when "
    "the user requests an update; never poll repeatedly until complete."
)
@_zap_error_guard
def zap_spider_status(scan_id: str) -> dict[str, Any]:
    """Args:
        scan_id: The spider id returned by ``zap_spider``.
    """
    return {"spider_id": scan_id, "status": _zap().spider_status(scan_id)}


@framework_tool("Start the AJAX (headless-browser) spider against a URL.")
@_zap_error_guard
def zap_ajax_spider(target: str) -> dict[str, str]:
    """The AJAX spider is a singleton — there is no per-scan ID.  Perform one
    status call to confirm launch, then hand off to the user.  Poll progress
    again only when the user requests an update.

    Args:
        target: Fully qualified URL to start the headless-browser crawl from.
    """
    from utils.scope_gate import check_scan, ScopeGateError
    _sc_ok, _sc_reason = check_scan(target)
    if not _sc_ok:
        raise ScopeGateError(f"scope gate: {_sc_reason}")
    return {"status": _zap().ajax_spider(target)}


@framework_tool(
    "Get AJAX spider progress (running / stopped / finished). Call once only "
    "when the user requests an update; never poll repeatedly until complete."
)
@_zap_error_guard
def zap_ajax_spider_status() -> dict[str, str]:
    return {"status": _zap().ajax_spider_status()}


@framework_tool("Start an active scan against a URL; returns ascan_id.")
@_zap_error_guard
def zap_active_scan(target: str, policy: str | None = None) -> dict[str, str]:
    """Active scan attacks every URL the spider discovered. ``policy`` is
    optional and names a ZAP scan policy (e.g. ``"Default Policy"``).

    Args:
        target: Fully qualified URL; ZAP will attack this URL and anything
            linked from it that's in scope.
        policy: Optional scan policy name. ``None`` uses the default policy.
    """
    from utils.scope_gate import check_scan, ScopeGateError
    _sc_ok, _sc_reason = check_scan(target)
    if not _sc_ok:
        raise ScopeGateError(f"scope gate: {_sc_reason}")
    return {"ascan_id": _zap().active_scan(target, policy=policy)}


@framework_tool(
    "Get active-scan progress (0..100) for a given ascan_id. While the scan "
    "is running you get just the progress integer (lightweight, safe to poll "
    "repeatedly). When the scan reaches 100 (done) the response ALSO carries a "
    "compact alert triage summary — total + counts by risk level (High/Medium/"
    "Low/Informational) — so you can decide whether to pull details with "
    "zap_alerts without a second round-trip. No full_output is ever returned "
    "by this tool; use zap_alerts or zap_report for the detailed payload.",
    next_hints=["zap_alerts", "zap_report"],
)
@_zap_error_guard
def zap_active_scan_status(scan_id: str, base_url: str | None = None) -> dict[str, Any]:
    """Args:
        scan_id: The ascan id returned by ``zap_active_scan``.
        base_url: Optional URL prefix to scope the done-summary alert counts
            (e.g. ``http://target``). Defaults to all alerts.
    """
    pct = _zap().active_scan_status(scan_id)
    result: dict[str, Any] = {
        "ascan_id": scan_id,
        "status": pct,
        "done": pct >= 100,
    }
    # T5: only fetch the triage summary once the scan is complete, so a running
    # poll stays tiny and a completed poll is information-dense. We never
    # attach full_output here — that's what zap_alerts/zap_report are for.
    if pct >= 100:
        try:
            result["alert_summary"] = _zap().alerts_summary(base_url=base_url)
        except Exception as e:
            # The summary is a nicety; never let it mask the status itself.
            result["alert_summary_error"] = str(e)
    return result


@framework_tool(
    "List ZAP alerts (optionally filtered by URL prefix and risk level).",
    next_hints=["zap_alert_message", "report_finding"],
    untrusted_target=True,
)
@_zap_error_guard
def zap_alerts(base_url: str | None = None,
               risk_id: int | None = None,
               summary: bool = True,
               max_alerts: int = 50) -> list[dict[str, Any]]:
    """List all ZAP alerts raised during the session, with optional filtering.

    Risk levels: 0 informational, 1 low, 2 medium, 3 high, 4 informational
    (ZAP uses 0 and 4 for different informational buckets).

    By default returns a COMPACT summary per alert (id, name, risk,
    confidence, cweid, count, first occurrence url/param/method/evidence) so
    a large scan doesn't fill the context window. Set ``summary=False`` for
    the raw, verbose ZAP alert objects (multi-paragraph desc/solution/
    references, full instance arrays) -- expensive, use sparingly. To drill
    into one alert's full detail + the HTTP request/response that triggered
    it, call ``zap_alert_message`` with the alert's ``id``.

    Args:
        base_url: Optional URL prefix to filter by (e.g. ``http://10.10.10.110``).
        risk_id: Optional minimum risk level (0-4). Returns ALL alerts when None.
        summary: If True (default), return compact triage records. If False,
            return the full raw ZAP alert objects.
        max_alerts: Cap on the number of alerts returned (default 50). Only
            applies in summary mode. A ``_truncated`` marker is appended when
            more alerts exist; raise this or filter by ``risk_id`` to page.
    """
    return _zap().alerts(base_url=base_url, risk_id=risk_id,
                        summary=summary, max_alerts=max_alerts)


@framework_tool(
    "Get an alert's metadata plus the full HTTP request/response that triggered it.",
    next_hints=["report_finding"],
    untrusted_target=True,
)
@_zap_error_guard
def zap_alert_message(alert_id: str) -> dict[str, Any]:
    """Returns the alert rule that fired (name, risk, CWE, evidence) AND the
    raw HTTP request + response that triggered it. Use to triage a finding:
    confirm it's a real positive and not a fingerprinting false positive.

    Args:
        alert_id: The ``id`` field of an alert (an integer string from ``zap_alerts``).
    """
    return _zap().alert_message(alert_id)


@framework_tool(
    "Grep the raw HTTP response for a previously-spidered URL using a regex. "
    "This is the ZAP-as-grep tool: pass any regex, get all matches back.",
    untrusted_target=True,
)
@_zap_error_guard
def zap_history_regex(target: str, pattern: str,
                      body_only: bool = True) -> dict[str, Any]:
    """Use cases: enumerate hidden form fields, find all JS endpoints, locate
    comments containing TODOs, etc. Body-only skips the HTTP headers.

    Args:
        target: URL that ZAP has already fetched (must be in history).
        pattern: Python regex to run against the response.
        body_only: If True (default), grep only the response body. If False,
            grep the raw response including headers (useful for header checks).
    """
    return _zap().history_regex(target, pattern, body_only=body_only)


@framework_tool("List top-level hosts discovered by the ZAP session.")
@_zap_error_guard
def zap_sites() -> list[str]:
    return _zap().sites()


@framework_tool("Get the full ZAP sites tree (optionally scoped to a subtree URL).")
@_zap_error_guard
def zap_sites_tree(target: str | None = None) -> str:
    """JSON dump of the entire discovered URL hierarchy.

    Args:
        target: Optional URL to scope the tree to a subtree under that URL.
            None (default) returns the entire hierarchy.
    """
    return _zap().sites_tree(url=target)


@framework_tool("Generate a ZAP report file (html/xml/json/md) and return its path.")
@_zap_error_guard
def zap_report(report_format: str = "html",
               report_file: str = "/tmp/zap_report.html",
               report_title: str = "Framework ZAP scan") -> dict[str, Any]:
    """Requires the ZAP ``reports`` add-on; a vanilla daemon may not have
    it. On failure, returns a dict with an ``error`` field describing
    what's missing instead of raising.

    Args:
        report_format: One of "html", "xml", "json", "md".
        report_file: Absolute path on the local filesystem to write the report.
        report_title: Title embedded in the report header.
    """
    return _zap().report(
        report_format=report_format,
        report_file=report_file,
        report_title=report_title,
    )


@framework_tool(
    "Send a raw HTTP request with full control over method, path, headers "
    "(Host, Cookie, User-Agent, Referer, any custom header) and body, "
    "through ZAP's HTTP sender. Use this when a target requires a specific "
    "Host header (vhost-gated apps), session cookies, CSRF tokens, or any "
    "hand-crafted request that zap_open_url cannot express. The response is "
    "recorded in ZAP history (grep it with zap_history_regex) and the "
    "passive scanner observes it.",
    next_hints=["zap_history_regex", "report_finding"],
)
@_zap_error_guard
def zap_send_raw(raw_request: str,
                 follow_redirects: bool = False,
                 timeout: float = 30.0) -> dict[str, Any]:
    """Send a raw HTTP/1.1 request exactly as written.

    First line must be ``METHOD /path HTTP/1.1``; separate headers from the
    body with one blank line. ``\\n`` line endings are normalized to
    ``\\r\\n`` before sending, so plain-text requests are wire-legal.

    Args:
        raw_request: The raw request, e.g. ``"GET / HTTP/1.1\\nHost: "
            "earth.local\\n\\n"`` -- always include a Host header for
            vhost-gated targets.
        follow_redirects: If True, ZAP follows 3xx responses automatically.
        timeout: Per-request timeout in seconds (default 30). If the target
            is unreachable, ZAP's sendRequest blocks until this fires —
            there is NO retry on action endpoints, so the timeout surfaces
            immediately as a structured error instead of freezing the stack.
    """
    lines = raw_request.lstrip().splitlines()
    if not lines or " HTTP/1." not in lines[0]:
        raise ValueError(
            "raw_request must start with 'METHOD /path HTTP/1.1'"
        )
    # Scope gate (operator-armed from the Tool REPL; no-op in lab mode).
    from utils.scope_gate import check_scan, ScopeGateError
    _sc_ok, _sc_reason = check_scan(_host_from_raw_request(raw_request))
    if not _sc_ok:
        raise ScopeGateError(f"scope gate: {_sc_reason}")
    # Model-written requests use \n; the wire needs \r\n. Normalize.
    wire = raw_request.replace("\r\n", "\n").replace("\n", "\r\n")
    # Failures flow as ZAPAPIError -> _zap_error_guard structured dict.
    # Scheme-forced https probes of non-TLS origins are auto-retried once
    # over the scheme as written (plain http) inside send_raw; when the
    # fallback fires the envelope carries a "scheme_fallback" note.
    env = _zap().send_raw(wire, follow_redirects=follow_redirects, timeout=timeout)
    result = {
        "message_id": env.get("id", ""),
        "status": _status_from_headers(env.get("responseHeader", "")),
        "request_header": env.get("requestHeader", ""),
        "response_header": env.get("responseHeader", ""),
        "response_body": env.get("responseBody", ""),
    }
    if env.get("scheme_fallback"):
        result["scheme_fallback"] = env["scheme_fallback"]
    return result


# ---- protect-mode scope sync (2026-09-19) -----------------------------------
# ZAP has no API-level redirect off; mode=protect + a context mirroring the
# operator-armed scope is the architectural control: ZAP itself refuses every
# out-of-scope request (redirect hops, spider crawls, scan traffic, proxied
# manual browsing). Implementation carved to auxiliaries/_zap_scope_sync.py
# (client-injected — the sibling holds no facade name); this facade owns
# client acquisition and keeps the import surface bootstrap binds. The armed
# manifest is read here — never written.

def sync_protect_scope(zap: ZAPClient | None = None) -> dict[str, Any]:
    """Mirror the armed scope into a ZAP context and set mode=protect.

    Facade wrapper over ``auxiliaries._zap_scope_sync.sync_protect_scope``:
    injects the shared singleton client when none is passed, then delegates.
    Reads ``scope/.armed_packet_scope.json`` + the cached manifest; never
    writes scope state.
    """
    return _scope_sync_impl(zap or _zap())


def _zap_scope_drift_guard() -> dict[str, Any] | None:
    """Detect armed-scope drift and auto-repair the ZAP mirror (mechanism:
    ``auxiliaries._zap_scope_sync.drift_guard``).

    Compares the armed state file's mtime against the last-synced mtime
    (sidecar ``.zap_protect_sync.json``). Called at the top of every
    traffic-bearing ZAP client method so a scope change the operator made
    without a re-sync is picked up BEFORE the next request fires; repair
    failures are reported but never block the tool call.
    """
    return drift_guard(_zap())


@framework_tool(
    "ZAP scope sync: mirror the operator-armed scope into the ZAP daemon "
    "and set mode=protect. Builds the 'framework-armed-<handle>' context "
    "from the armed allowlist + in-scope assets (out-of-scope assets become "
    "excludes), then flips ZAP to protect mode so ZAP ITSELF refuses every "
    "out-of-scope request — redirect hops, spider crawls, active scans, "
    "and proxied manual browsing. Automatic web recon follows the "
    "guidelines by construction; RUN THIS AFTER ANY SCOPE ARM/CHANGE and "
    "before ZAP-heavy work when in doubt (it is also auto-run at framework "
    "launch and drift-guarded on every traffic-bearing ZAP call). The "
    "armed scope manifest is read, never written; CIDR assets must be "
    "blessed as IPs (scope add-ip).",
    next_hints=["zap_open_url", "zap_spider", "zap_active_scan", "report_finding"],
)
@_zap_error_guard
def zap_sync_scope() -> dict[str, Any]:
    """Sync ZAP's context + mode with the operator-armed scope (read-only on scope)."""
    return sync_protect_scope()
