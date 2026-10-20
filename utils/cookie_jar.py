"""Universal cookie jar + token vault — shared, durable web-session state.

The blind spot this closes (operator request 2026-10-02): almost every
web tool in the framework is a one-shot.  ``gated_get``/``gated_request``
build a fresh ``requests.Session`` per call and throw it away, so any
app with middleware-managed state (CSRF tokens, session cookies, bearer
flows) foils the audit at the front door — Django's ``csrfmiddlewaretoken``
being the canonical case (192.168.56.106).  Cookies and tokens are just
strings; this module is the shared place those strings live so the audit
can actually walk a stateful surface.

Why SQLite and not a process-local dict (the SessionManager pattern):
cookies must be visible from EVERY lane — the Brain sidecar, the
in-process fallback, the tool REPL, the API gateway, a fresh secretary
process.  Disk is the only broker all lanes share for free, which also
sidesteps the documented SessionManager limitation (state stranded in
whichever process hit the fallback).  Low contention, small rows: SQLite
with WAL is plenty.  The store is a lazy singleton (``get_jar``); module
import opens NOTHING (the Brain imports scanned modules at startup).

Model:

- **Cookies** — RFC 6265-shaped rows keyed ``(domain, name, path)``:
  value, expiry, secure/httponly flags, origin URL, timestamps.  Host-only
  cookies match their exact host; ``Domain=``-specified cookies carry the
  leading-dot form and match subdomains.  IP hosts never match dot-forms.
- **Tokens** — arbitrary named strings keyed ``(domain, name)``: CSRF form
  fields (``csrfmiddlewaretoken``, ``authenticity_token``, ``_token`` ...),
  meta/header CSRF tokens, bearer tokens, anything.  Upsert semantics,
  latest wins.  ``extract_csrf_tokens`` pulls them out of HTML + response
  headers; ``session_post`` (auxiliaries/web_session.py) injects them back.

Hygiene: server-set expiries are honoured; a wall-clock age cap
(``COOKIE_JAR_TTL_HOURS``, default 72h) bounds growth (scratch-store
philosophy — stale session state rots an audit anyway).  Purge runs
opportunistically on every store/read.

The jar is deliberately *not* scope-gated itself (it stores strings, it
fires no traffic); the tools that APPLY jar state — the ``session_*`` lane —
route every hop through the armed scope gate like all framework HTTP.
"""

from __future__ import annotations

import html as _html
import ipaddress
import os
import re
import sqlite3
import threading
import time
from http.cookiejar import Cookie as JarCookie
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from constants import framework_tool, resolve_workspace_root

_DEFAULT_ROOT = resolve_workspace_root()
_TTL_HOURS = float(os.getenv("COOKIE_JAR_TTL_HOURS", "72"))


def _db_path() -> Path:
    override = (os.getenv("COOKIE_JAR_DB") or "").strip()
    if override:
        return Path(override).expanduser()
    return resolve_workspace_root() / "cookie_jar.db"


def _host_of(url_or_host: str) -> str:
    """Host (lowercased) from a URL or bare host.  Empty when unparsable."""
    raw = (url_or_host or "").strip()
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    host = raw.split("/", 1)[0].split(":", 1)[0].split("@")[-1]
    return host.strip().lower()


def _host_is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def domain_matches(cookie_domain: str, host: str) -> bool:
    """RFC 6265 domain-match of ``cookie_domain`` against request ``host``.

    Leading-dot domains (``Domain=`` specified) cover the exact domain and
    its subdomains; host-only cookies match their exact host only.  IP
    hosts never match dot-forms (an out-of-scope sibling suffix like
    ``.56.106`` must not leak a cookie onto ``192.168.56.106``).
    """
    host = (host or "").lower()
    dom = (cookie_domain or "").lower()
    if not host or not dom:
        return False
    if _host_is_ip(host):
        return host == dom.lstrip(".")
    if dom.startswith("."):
        base = dom[1:]
        return host == base or host.endswith("." + base)
    return host == dom


def path_matches(cookie_path: str, request_path: str) -> bool:
    """RFC 6265 path-match (used to build ready-made Cookie headers)."""
    cpath = cookie_path or "/"
    rpath = request_path or "/"
    if not rpath.startswith("/"):
        rpath = "/" + rpath
    if cpath == rpath:
        return True
    if rpath.startswith(cpath):
        if cpath.endswith("/"):
            return True
        if rpath[len(cpath):len(cpath) + 1] == "/":
            return True
    return False


# ---------------------------------------------------------------------------
# CSRF token extraction (HTML + response headers) — pure, no store needed
# ---------------------------------------------------------------------------

_HIDDEN_INPUT_RX = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
_INPUT_NAME_RX = re.compile(r"name=[\"']([^\"']+)[\"']", re.IGNORECASE)
_INPUT_VALUE_RX = re.compile(r"value=[\"']([^\"']*)[\"']", re.IGNORECASE)
_INPUT_TYPE_RX = re.compile(r"type=[\"']([^\"']+)[\"']", re.IGNORECASE)
_META_CSRF_RX = re.compile(
    r"<meta\b[^>]*name=[\"'](?:csrf[-_]?token|_token|csrfmiddlewaretoken)[\"']"
    r"[^>]*content=[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
_META_CSRF_RX2 = re.compile(
    r"<meta\b[^>]*content=[\"']([^\"']+)[\"'][^>]*"
    r"name=[\"'](?:csrf[-_]?token|_token|csrfmiddlewaretoken)[\"']",
    re.IGNORECASE,
)
# Field names that smell like CSRF middleware.  Ordered: framework-specific
# first so the reported "best" token prefers the canonical field.
_CSRF_FIELD_NAMES = (
    "csrfmiddlewaretoken",  # Django
    "authenticity_token",  # Rails
    "_token",  # Laravel
    "__RequestVerificationToken",  # ASP.NET
    "csrfmiddlewaretokeninput",
    "csrf_token",
    "csrf-token",
    "_csrfToken",
    "csrftoken",
    "anti_forgery_token",
    "csrf",
    "_csrf",
)
_CSRF_FIELD_RX = re.compile(
    r"^(?:csrf[-_]?middleware[-_]?token|authenticity[-_]?token|_token"
    r"|__requestverificationtoken|csrf[-_]?(?:middleware)?[-_]?token"
    r"|anti[-_]?forgery[-_]?token|_csrf(?:token)?|csrf)$",
    re.IGNORECASE,
)
_CSRF_HEADER_NAMES = ("X-CSRFToken", "X-CSRF-Token", "X-XSRF-TOKEN", "CSRF-Token")


def _looks_csrf(name: str) -> bool:
    return bool(_CSRF_FIELD_RX.match((name or "").strip()))


def extract_csrf_tokens(
    html_text: str, headers: Optional[Dict[str, str]] = None
) -> List[Dict[str, str]]:
    """Pull CSRF tokens out of an HTML body and/or response headers.

    Returns a list of ``{"name", "value", "source"}`` dicts — ``source``
    is ``"form"``, ``"meta"`` or ``"header:<Header-Name>"`` so the caller
    (and the audit log) can tell WHERE each string came from.  Values are
    HTML-unescaped (template entities are common).  Bounded scan: only the
    first 512 KiB of body text is considered.
    """
    out: List[Dict[str, str]] = []
    text = (html_text or "")[:524288]
    for tag in _HIDDEN_INPUT_RX.findall(text):
        name_m = _INPUT_NAME_RX.search(tag)
        if not name_m:
            continue
        type_m = _INPUT_TYPE_RX.search(tag)
        itype = (type_m.group(1).lower() if type_m else "text").strip()
        if itype != "hidden":
            continue
        name = name_m.group(1).strip()
        if not _looks_csrf(name):
            continue
        val_m = _INPUT_VALUE_RX.search(tag)
        value = _html.unescape(val_m.group(1)) if val_m else ""
        if value:
            out.append({"name": name, "value": value, "source": "form"})
    for rx in (_META_CSRF_RX, _META_CSRF_RX2):
        for m in rx.finditer(text):
            value = _html.unescape(m.group(1))
            if value:
                out.append({"name": "csrf-token", "value": value, "source": "meta"})
    if headers:
        for hname in _CSRF_HEADER_NAMES:
            value = None
            for key, val in headers.items():
                if key.lower() == hname.lower() and val:
                    value = val
                    break
            if value:
                out.append(
                    {"name": "csrf-token", "value": value, "source": f"header:{hname}"}
                )
    # Stable order: framework-canonical form fields first, keep page order.
    def _rank(t: Dict[str, str]) -> Tuple[int, str]:
        name = t["name"]
        return (
            _CSRF_FIELD_NAMES.index(name) if name in _CSRF_FIELD_NAMES else 99,
            name,
        )

    return sorted(out, key=_rank)


# ---------------------------------------------------------------------------
# The store
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cookies (
    domain  TEXT NOT NULL,
    name    TEXT NOT NULL,
    value   TEXT NOT NULL,
    path    TEXT NOT NULL DEFAULT '/',
    expires REAL,
    secure  INTEGER NOT NULL DEFAULT 0,
    httponly INTEGER NOT NULL DEFAULT 0,
    domain_specified INTEGER NOT NULL DEFAULT 0,
    origin  TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    PRIMARY KEY (domain, name, path)
);
CREATE TABLE IF NOT EXISTS tokens (
    domain  TEXT NOT NULL,
    name    TEXT NOT NULL,
    value   TEXT NOT NULL,
    token_type TEXT NOT NULL DEFAULT 'csrf',
    origin  TEXT,
    context TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    PRIMARY KEY (domain, name)
);
"""


class CookieJarStore:
    """Thread-safe SQLite-backed cookie jar + token vault.

    Use :func:`get_jar` for the shared singleton (env-keyed path).  Tests
    may construct their own instance against a temp path.  Every mutation
    and read takes the instance lock; SQLite's own locking handles the
    cross-process case (WAL where available).
    """

    def __init__(self, db_path: Optional[Path] = None, ttl_hours: float = _TTL_HOURS) -> None:
        self.db_path = Path(db_path) if db_path else _db_path()
        self.ttl_seconds = max(0.0, float(ttl_hours)) * 3600.0
        self._lock = threading.RLock()
        parent = self.db_path.parent
        if str(parent):
            try:
                parent.mkdir(parents=True, exist_ok=True)
            except OSError:
                pass  # e.g. root-owned dir while running as non-root: connect will tell us
        # Root guard (mirrors utils/scratch_store.py): chown the DB + WAL +
        # SHM files back to the workspace owner BEFORE opening the connection.
        # A prior root run (bootstrap/IPython for masscan/packetcraft) leaves
        # these root-owned; WAL mode needs write access to all three files,
        # and a non-root process that can't write the WAL/SHM sidecars gets
        # "database is locked" instead of a clean permission error.
        self._repair_ownership_if_needed()
        self._conn = sqlite3.connect(str(self.db_path), timeout=10.0, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def _repair_ownership_if_needed(self) -> None:
        """Chown cookie-jar DB + WAL + SHM back to the workspace owner.

        Mirrors utils/scratch_store.py's root guard.  When the framework
        runs as root (masscan/packetcraft/IPython REPL), SQLite creates
        cookie_jar.db, cookie_jar.db-wal, and cookie_jar.db-shm as
        root-owned.  WAL mode needs write access to all three DB files; a
        subsequent non-root run (the agent / gemma) can't write the WAL/SHM
        sidecars and gets "database is locked" instead of a clean permission
        error — which looks like contention rather than the real cause.

        When root: chown the files back to the owner of WORKSPACE_ROOT.
        When non-root and the files are root-owned: warn loudly (can't
        chown; operator must restart as root once to trigger the repair or
        chown manually).  Never raises — a failed chown is logged but
        doesn't block the store (the non-root process can still read the
        main DB file; it just degrades to a locked-write failure that the
        operator will see and fix).
        """
        import logging
        log = logging.getLogger(__name__)
        db_p = self.db_path
        workspace_root = resolve_workspace_root()

        try:
            ws_stat = workspace_root.stat()
            target_uid = ws_stat.st_uid
            target_gid = ws_stat.st_gid
        except OSError:
            return

        if target_uid == 0:
            return  # workspace is root-owned; consistent

        is_root = os.geteuid() == 0
        files_to_check = [
            db_p,
            db_p.with_name(db_p.name + "-wal"),
            db_p.with_name(db_p.name + "-shm"),
        ]

        needs_repair = False
        for f in files_to_check:
            try:
                if f.exists() and f.stat().st_uid == 0:
                    needs_repair = True
                    break
            except OSError:
                pass

        if not needs_repair:
            return

        if not is_root:
            log.warning(
                "[cookie_jar] %s and/or WAL/SHM files are root-owned but "
                "the framework is running as non-root (uid=%d). SQLite WAL "
                "mode needs write access to all three DB files. The jar will "
                "fail with 'database is locked' on writes. Fix: run once as "
                "root to trigger the auto-repair, or run: sudo chown %d:%d "
                "%s %s-wal %s-shm",
                db_p, os.geteuid(), target_uid, target_gid, db_p, db_p, db_p,
            )
            return

        import subprocess
        chown_spec = f"{target_uid}:{target_gid}"
        for f in files_to_check:
            if f.exists():
                try:
                    subprocess.run(
                        ["chown", chown_spec, str(f)],
                        check=False, capture_output=True, timeout=5,
                    )
                except Exception:
                    pass
        log.info(
            "[cookie_jar] Root guard: chowned cookie_jar DB + WAL + SHM "
            "back to uid=%d (workspace owner). A prior root run had "
            "root-owned these files, which would make the next non-root run "
            "fail with 'database is locked'.",
            target_uid,
        )

    # -- internals ----------------------------------------------------------

    def _purge(self) -> int:
        """Drop expired + age-capped cookies/tokens. Caller holds the lock."""
        now = time.time()
        gone = 0
        cur = self._conn.execute(
            "DELETE FROM cookies WHERE (expires IS NOT NULL AND expires < ?)"
            " OR updated_at < ?",
            (now, now - self.ttl_seconds),
        )
        gone += cur.rowcount or 0
        cur = self._conn.execute(
            "DELETE FROM tokens WHERE updated_at < ?", (now - self.ttl_seconds,)
        )
        gone += cur.rowcount or 0
        if gone:
            self._conn.commit()
        return gone

    @staticmethod
    def _row_to_cookie(row: Dict[str, Any]) -> JarCookie:
        """Row dict -> ``http.cookiejar.Cookie`` (requests-compatible)."""
        domain = row["domain"]
        return JarCookie(
            version=0,
            name=row["name"],
            value=row["value"],
            port=None,
            port_specified=False,
            domain=domain,
            domain_specified=bool(row.get("domain_specified")),
            domain_initial_dot=domain.startswith("."),
            path=row.get("path") or "/",
            path_specified=True,
            secure=bool(row.get("secure")),
            expires=row.get("expires"),
            discard=row.get("expires") is None,
            comment=None,
            comment_url=None,
            rest={"HttpOnly": ""} if row.get("httponly") else {},
        )

    # -- cookies -------------------------------------------------------------

    def store_cookie(
        self,
        domain: str,
        name: str,
        value: str,
        path: str = "/",
        expires: Optional[float] = None,
        secure: bool = False,
        httponly: bool = False,
        domain_specified: bool = False,
        origin: str = "",
    ) -> Dict[str, Any]:
        """Upsert one cookie.  ``domain_specified=True`` marks a
        ``Domain=``-style cookie (leading-dot domain, subdomain-matching)."""
        domain = (domain or "").strip().lower()
        name = (name or "").strip()
        if not domain or not name:
            return {"stored": False, "error": "domain and name are required"}
        now = time.time()
        with self._lock:
            self._purge()
            self._conn.execute(
                "INSERT INTO cookies (domain, name, value, path, expires, secure,"
                " httponly, domain_specified, origin, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(domain, name, path) DO UPDATE SET"
                "  value=excluded.value, expires=excluded.expires,"
                "  secure=excluded.secure, httponly=excluded.httponly,"
                "  domain_specified=excluded.domain_specified,"
                "  origin=excluded.origin, updated_at=excluded.updated_at",
                (
                    domain, name, value, path or "/", expires,
                    int(secure), int(httponly), int(domain_specified),
                    origin or "", now, now,
                ),
            )
            self._conn.commit()
        return {"stored": True, "domain": domain, "name": name, "path": path or "/"}

    def store_response_cookies(
        self, cookies: Iterable[JarCookie], origin: str = ""
    ) -> List[Dict[str, Any]]:
        """Persist ``http.cookiejar.Cookie`` objects (a requests session's
        jar) into the store.  Returns per-cookie ``{name, domain, value,
        path, changed}`` summaries — ``changed`` marks new/updated rows."""
        out: List[Dict[str, Any]] = []
        now = time.time()
        with self._lock:
            self._purge()
            for c in cookies:
                name = getattr(c, "name", None)
                if not name:
                    continue
                dom = (getattr(c, "domain", "") or "").lower() or _host_of(origin)
                cur = self._conn.execute(
                    "SELECT value FROM cookies WHERE domain=? AND name=? AND path=?",
                    (dom, name, getattr(c, "path", "/") or "/"),
                ).fetchone()
                changed = cur is None or cur[0] != c.value
                self._conn.execute(
                    "INSERT INTO cookies (domain, name, value, path, expires,"
                    " secure, httponly, domain_specified, origin, created_at,"
                    " updated_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?)"
                    " ON CONFLICT(domain, name, path) DO UPDATE SET"
                    "  value=excluded.value, expires=excluded.expires,"
                    "  secure=excluded.secure, httponly=excluded.httponly,"
                    "  domain_specified=excluded.domain_specified,"
                    "  origin=excluded.origin, updated_at=excluded.updated_at",
                    (
                        dom, name, c.value, getattr(c, "path", "/") or "/",
                        getattr(c, "expires", None), int(bool(getattr(c, "secure", False))),
                        int("HttpOnly" in (getattr(c, "_rest", {}) or {})),
                        int(bool(getattr(c, "domain_specified", False))),
                        origin or "", now, now,
                    ),
                )
                out.append({
                    "name": name,
                    "domain": dom,
                    "value": c.value,
                    "path": getattr(c, "path", "/") or "/",
                    "changed": changed,
                })
            self._conn.commit()
        return out

    def cookies_for(self, host_or_url: str) -> List[JarCookie]:
        """All live ``http.cookiejar.Cookie`` objects matching a host/URL
        (domain-matched; requests applies path rules when sending)."""
        host = _host_of(host_or_url)
        if not host:
            return []
        now = time.time()
        with self._lock:
            self._purge()
            rows = self._conn.execute(
                "SELECT domain, name, value, path, expires, secure, httponly,"
                " domain_specified FROM cookies"
            ).fetchall()
        out: List[JarCookie] = []
        for r in rows:
            if r[4] is not None and r[4] < now:
                continue
            if not domain_matches(r[0], host):
                continue
            out.append(self._row_to_cookie({
                "domain": r[0], "name": r[1], "value": r[2], "path": r[3],
                "expires": r[4], "secure": r[5], "httponly": r[6],
                "domain_specified": r[7],
            }))
        return out

    def apply_to_session(self, session: Any, url: str) -> List[str]:
        """Seed a ``requests.Session`` with every jar cookie matching
        ``url``'s host.  Returns the cookie names applied."""
        names: List[str] = []
        for c in self.cookies_for(url):
            try:
                session.cookies.set_cookie(c)
                names.append(c.name)
            except Exception:  # noqa: BLE001 - jar apply must never kill a run
                continue
        return names

    def cookie_header(self, url: str) -> Optional[str]:
        """Build a ready-to-send ``Cookie:`` header value for ``url``
        (domain- AND path-matched, expiry-honoured) — for feeding
        non-jar-aware tools (ffuf/sqlmap raw modes, ZAP reclient)."""
        from urllib.parse import urlparse

        parsed = urlparse(url if "://" in (url or "") else "http://" + (url or ""))
        host = (parsed.hostname or "").lower()
        rpath = parsed.path or "/"
        if not host:
            return None
        now = time.time()
        with self._lock:
            self._purge()
            rows = self._conn.execute(
                "SELECT domain, name, value, path, expires FROM cookies"
            ).fetchall()
        pairs: List[str] = []
        for dom, name, value, cpath, expires in rows:
            if expires is not None and expires < now:
                continue
            if not domain_matches(dom, host) or not path_matches(cpath or "/", rpath):
                continue
            pairs.append(f"{name}={value}")
        return "; ".join(pairs) if pairs else None

    def import_cookie_string(self, domain: str, cookie_header: str, origin: str = "") -> Dict[str, Any]:
        """Parse a raw ``Cookie:``-style string (``a=1; b=2``) and store each
        pair for ``domain`` — the "cookies are just strings" on-ramp for
        values pasted from a browser or another tool."""
        domain = _host_of(domain) or (domain or "").strip().lower()
        pairs = re.split(r"\s*;\s*", (cookie_header or "").strip())
        stored: List[str] = []
        for pair in pairs:
            if not pair or "=" not in pair:
                continue
            name, _, value = pair.partition("=")
            name, value = name.strip(), value.strip()
            if not name:
                continue
            self.store_cookie(domain, name, value, origin=origin)
            stored.append(name)
        return {"domain": domain, "stored": stored}

    # -- tokens -------------------------------------------------------------

    def store_token(
        self,
        domain: str,
        name: str,
        value: str,
        token_type: str = "csrf",
        origin: str = "",
        context: str = "",
    ) -> Dict[str, Any]:
        """Upsert a named token string for a domain (latest wins)."""
        domain = _host_of(domain) or (domain or "").strip().lower()
        name = (name or "").strip()
        if not domain or not name:
            return {"stored": False, "error": "domain and name are required"}
        now = time.time()
        with self._lock:
            self._purge()
            self._conn.execute(
                "INSERT INTO tokens (domain, name, value, token_type, origin,"
                " context, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?)"
                " ON CONFLICT(domain, name) DO UPDATE SET"
                "  value=excluded.value, token_type=excluded.token_type,"
                "  origin=excluded.origin, context=excluded.context,"
                "  updated_at=excluded.updated_at",
                (domain, name, value, token_type or "csrf", origin, context, now, now),
            )
            self._conn.commit()
        return {"stored": True, "domain": domain, "name": name, "token_type": token_type}

    def tokens_for(self, domain: str) -> List[Dict[str, Any]]:
        """All live tokens for a host (or, with ``domain=""``, everything)."""
        want = _host_of(domain) or (domain or "").strip().lower()
        with self._lock:
            self._purge()
            if want:
                rows = self._conn.execute(
                    "SELECT domain, name, value, token_type, origin, context,"
                    " updated_at FROM tokens WHERE domain=? ORDER BY updated_at DESC",
                    (want,),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT domain, name, value, token_type, origin, context,"
                    " updated_at FROM tokens ORDER BY domain, updated_at DESC"
                ).fetchall()
        return [
            {
                "domain": r[0], "name": r[1], "value": r[2], "token_type": r[3],
                "origin": r[4], "context": r[5], "updated_at": r[6],
            }
            for r in rows
        ]

    def get_token(self, domain: str, name: str) -> Optional[str]:
        """Latest value for one named token, or ``None``."""
        for t in self.tokens_for(domain):
            if t["name"] == name:
                return t["value"]
        return None

    def csrf_for(self, host_or_url: str) -> Dict[str, Any]:
        """Best-effort CSRF pair for a host: the canonical form field
        (Django/Rails/Laravel order) plus a header token.

        The header value prefers a domain ``csrftoken``/``csrf``-named
        COOKIE (Django validates header==cookie), falling back to a stored
        meta/header token.  Returns ``{form_name, form_value, header_value}``
        — missing pieces are ``None``.
        """
        host = _host_of(host_or_url)
        # Form token: first csrf-typed token whose NAME is a real form field
        # (not the generic meta/header name "csrf-token"), preferring the
        # canonical field order extract_csrf_tokens ranked them by.
        form: Optional[Dict[str, str]] = None
        for t in self.tokens_for(host):
            if t["token_type"] != "csrf":
                continue
            if t["name"] != "csrf-token":
                form = {"name": t["name"], "value": t["value"]}
                break
        meta_header = self.get_token(host, "csrf-token")
        cookie_val: Optional[str] = None
        for c in self.cookies_for(host):
            if (c.name or "").lower() in ("csrftoken", "csrf", "xcsrftoken", "xsrf-token"):
                cookie_val = c.value
                break
        return {
            "form_name": form["name"] if form else None,
            "form_value": form["value"] if form else None,
            "header_value": cookie_val or meta_header,
        }

    # -- state / maintenance --------------------------------------------------

    def list_state(self, domain: str = "") -> Dict[str, Any]:
        """Structured view of the jar: cookies + tokens (optionally scoped)."""
        want = _host_of(domain) or (domain or "").strip().lower()
        now = time.time()
        with self._lock:
            self._purge()
            if want:
                crows = self._conn.execute(
                    "SELECT domain, name, value, path, expires, secure, httponly,"
                    " domain_specified, origin, updated_at FROM cookies WHERE domain=?"
                    " ORDER BY updated_at DESC",
                    (want,),
                ).fetchall()
            else:
                crows = self._conn.execute(
                    "SELECT domain, name, value, path, expires, secure, httponly,"
                    " domain_specified, origin, updated_at FROM cookies"
                    " ORDER BY domain, updated_at DESC"
                ).fetchall()
        cookies = [
            {
                "domain": r[0], "name": r[1], "value": r[2], "path": r[3],
                "expires": r[4],
                "expires_in_s": round(r[4] - now) if r[4] is not None else None,
                "secure": bool(r[5]), "httponly": bool(r[6]),
                "domain_wide": bool(r[7]), "origin": r[8], "updated_at": r[9],
            }
            for r in crows
        ]
        tokens = self.tokens_for(want)
        return {
            "domain": want or "(all)",
            "cookies": cookies,
            "tokens": tokens,
            "now": now,
        }

    def clear(
        self, domain: str = "", clear_cookies: bool = True, clear_tokens: bool = True
    ) -> Dict[str, Any]:
        """Drop cookies and/or tokens — one host, or everything."""
        want = _host_of(domain) or (domain or "").strip().lower()
        gone_cookies = gone_tokens = 0
        with self._lock:
            if clear_cookies:
                if want:
                    cur = self._conn.execute(
                        "DELETE FROM cookies WHERE domain=?", (want,)
                    )
                else:
                    cur = self._conn.execute("DELETE FROM cookies")
                gone_cookies = cur.rowcount or 0
            if clear_tokens:
                if want:
                    cur = self._conn.execute(
                        "DELETE FROM tokens WHERE domain=?", (want,)
                    )
                else:
                    cur = self._conn.execute("DELETE FROM tokens")
                gone_tokens = cur.rowcount or 0
            self._conn.commit()
        return {
            "cleared": True,
            "domain": want or "(all)",
            "cookies_removed": gone_cookies,
            "tokens_removed": gone_tokens,
        }

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except Exception:  # noqa: BLE001
                pass


# -- singleton ---------------------------------------------------------------

_JAR: Optional[CookieJarStore] = None
_JAR_LOCK = threading.Lock()


def get_jar() -> CookieJarStore:
    """Shared jar singleton.  Honours ``COOKIE_JAR_DB``/``WORKSPACE_ROOT``
    at call time — if the resolved path changed (tests, env overrides), a
    fresh store is built so callers never write to a stale location."""
    global _JAR
    path = _db_path()
    with _JAR_LOCK:
        if _JAR is None or _JAR.db_path != path:
            if _JAR is not None:
                try:
                    _JAR.close()
                except Exception:  # noqa: BLE001
                    pass
            _JAR = CookieJarStore(path)
        return _JAR


# ---------------------------------------------------------------------------
# framework tools (jar management — the session_* tools live in
# auxiliaries/web_session.py and APPLY this state under the scope gate)
# ---------------------------------------------------------------------------

@framework_tool(
    "Universal cookie jar + token vault state: list every stored cookie and "
    "token for one host (or all hosts) — session cookies (sessionid, "
    "PHPSESSID, JSESSIONID), CSRF tokens, bearer tokens, with values, "
    "expiry, and where each came from. This is the shared web-session "
    "state that session_get/session_post carry between calls; inspect it "
    "after a login flow or before a manual request. The jar is durable "
    "across tools and processes, so state from any lane is visible here.",
    next_hints=["session_get to browse with this state", "jar_clear to wipe it"],
)
def jar_state(domain: str = "") -> Dict[str, Any]:
    """Show the jar's cookies + tokens (optionally scoped to one host).

    Args:
        domain: Host or URL to filter by (e.g. ``192.168.56.106``); empty
            lists every host in the jar.
    """
    return get_jar().list_state(domain)


@framework_tool(
    "Store cookies in the universal cookie jar by hand — the on-ramp for "
    "cookie strings recovered elsewhere (browser devtools, a CTF hint, "
    "another tool). Accepts one pair (name=value) or a full Cookie-header "
    "style string ('a=1; b=2'), stored for the given host so the "
    "session_get/session_post tools send them automatically. Use it to "
    "import a known sessionid or paste an auth cookie into the flow.",
    next_hints=["session_get to browse with the imported cookie", "jar_state"],
)
def jar_store_cookie(
    domain: str,
    cookie: str,
    value: str = "",
    path: str = "/",
    expires: float = 0,
    secure: bool = False,
    httponly: bool = False,
    origin: str = "",
) -> Dict[str, Any]:
    """Store one cookie (or a ``a=1; b=2`` multi-pair string) for a host.

    Args:
        domain: Host (or URL) the cookie belongs to, e.g. ``192.168.56.106``.
        cookie: Either ``name`` (with the value in ``value``) or a raw
            Cookie-header string like ``sessionid=abc; csrftoken=xyz``.
        value: Cookie value when ``cookie`` is a single name.
        path: Cookie path (default ``/``).
        expires: Unix-epoch expiry; 0 = session cookie (age-capped only).
        secure: Mark the cookie Secure.
        httponly: Mark the cookie HttpOnly.
        origin: Optional provenance note (URL/tool it came from).
    """
    jar = get_jar()
    host = _host_of(domain) or domain.strip().lower()
    if value or "=" not in cookie:
        if not cookie.strip():
            return {"stored": False, "error": "empty cookie name"}
        return jar.store_cookie(
            host, cookie.strip(), value, path=path,
            expires=(expires or None), secure=secure, httponly=httponly,
            origin=origin,
        )
    return jar.import_cookie_string(host, cookie, origin=origin)


@framework_tool(
    "Store a named token string in the universal token vault: bearer "
    "tokens, CSRF tokens, API keys, session identifiers — anything that "
    "is 'just a string' a stateful web flow needs. Tokens are keyed by "
    "host + name (latest wins) and live alongside the cookie jar so "
    "session_get/session_post can inject them automatically. Use this "
    "after decoding a JWT, recovering an API key, or reading a token out "
    "of any tool output.",
    next_hints=["session_get", "jar_state", "report_finding"],
)
def jar_store_token(
    domain: str,
    name: str,
    value: str,
    token_type: str = "bearer",
    origin: str = "",
) -> Dict[str, Any]:
    """Upsert a named token for a host (latest wins).

    Args:
        domain: Host (or URL) the token belongs to.
        name: Token name, e.g. ``authorization``, ``api_key``,
            ``csrfmiddlewaretoken``. The session tools auto-inject tokens
            whose type is ``csrf``.
        value: The token string itself.
        token_type: Free-form label — ``bearer``, ``csrf``, ``api_key``,
            ``session_id``; ``csrf`` participates in auto-injection.
        origin: Optional provenance note (URL/tool it came from).
    """
    return get_jar().store_token(
        domain, name, value, token_type=token_type, origin=origin
    )


@framework_tool(
    "Wipe the universal cookie jar: drop cookies and/or tokens for one "
    "host, or clear everything. Use it between audit phases (fresh "
    "identity), when a login flow went stale (rotated CSRF tokens), or to "
    "reset before a web_login_brute run so old session state can't "
    "confound the results.",
    next_hints=["session_get", "web_login_probe"],
)
def jar_clear(
    domain: str = "", clear_cookies: bool = True, clear_tokens: bool = True
) -> Dict[str, Any]:
    """Clear jar state — one host or everything.

    Args:
        domain: Host (or URL) to clear; empty clears ALL hosts.
        clear_cookies: Drop stored cookies (default true).
        clear_tokens: Drop stored tokens (default true).
    """
    return get_jar().clear(domain, clear_cookies=clear_cookies, clear_tokens=clear_tokens)


@framework_tool(
    "Build a ready-to-send Cookie header string ('name=value; name2=...') "
    "from the universal cookie jar for a given URL — domain- and "
    "path-matched, expiry-honoured. For feeding tools that take a raw "
    "Cookie header but don't carry state themselves (ffuf -H, sqlmap "
    "--cookie, ZAP reclient), so jar state from a session_get login flow "
    "works everywhere.",
    next_hints=["jar_state", "run_ffuf", "run_sqlmap"],
)
def jar_cookie_header(url: str) -> Dict[str, Any]:
    """Return the ``Cookie:`` header value the jar would send for ``url``.

    Args:
        url: Target URL (host + path are used for matching).
    """
    header = get_jar().cookie_header(url)
    return {
        "url": url,
        "cookie_header": header,
        "note": (
            "Send as a 'Cookie:' request header. No matching cookies in the "
            "jar yields null — session_get a login page first."
            if header is None
            else "Send as a 'Cookie:' request header."
        ),
    }


__all__ = [
    "CookieJarStore",
    "get_jar",
    "extract_csrf_tokens",
    "domain_matches",
    "path_matches",
    "jar_state",
    "jar_store_cookie",
    "jar_store_token",
    "jar_clear",
    "jar_cookie_header",
]