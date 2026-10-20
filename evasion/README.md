# evasion/ — contract-readiness lane: wire-shaping + fingerprint policy

Readiness framing: built to contract-grade shapes, exercised on LAB targets
unless a permitting contract governs the surface. This package holds shaping
**policy** + resolvers consumed by scanner/HTTP tools — it never contacts a
target itself. Boundary: everything beyond this layer (network tunneling,
infra rotation, machine-speed traffic morphing) stays operator-programmed
lanes (REPL/notebooks) — model-adjacent never.

## Modules

| Module | Provides | Consumed by |
| --- | --- | --- |
| `shaping.py` | `SCAN_SHAPING_PRESETS` + `resolve()` — nmap wire profiles | `auxiliaries/nmap.py` via `run_nmap(shaping=)` |
| `webshape.py` | `sticky_profile` identity (UA ↔ curl-impersonate TLS target ↔ header set/order) + `sticky_ua` + `HostFloor` pacing + `canonical_fill_for_family`/`order_headers_for_family` (plain-path realism) | `auxiliaries/web_session.py` (every `session_*` call) |

## Transport-identity stack (browser-coherent web lane)

The web session lane ships ONE identity per hop — UA claim, TLS stack,
header set, header ORDER, all resolved together at
`evasion/webshape.sticky_profile(host)` and carried by
`auxiliaries/web_session._do_session_request`:

- **Identity pool** (5 profiles: Windows Chrome, macOS Safari, Windows
  Firefox, Linux Firefox, macOS Chrome) — deterministic per-host hash pick,
  sticky across processes/restarts. Pool strings are hardcoded, NOT read
  back from the installed lib: a pip upgrade never permutates per-host
  identity.
- **Impersonated lane** (default `auto`): when `curl_cffi`
  (curl-impersonate, pinned in the `web` extra) is installed, the request
  travels on the impersonating client whose TLS ClientHello (JA3) + template
  headers (full client-hint and sec-fetch set, canonical per-family order)
  come from the pool entry's pinned target. Platform-variant pool entries
  (Windows Chrome, Windows/Linux Firefox) apply coherent header overrides
  — template builds carry another platform's UA, and overrides REPLACE
  template values in-place (verified wire behavior: replace-in-position, no
  duplicates), so e.g. a Windows-claiming Chrome keeps Chrome's canonical
  order and its sec-ch-ua/sec-ch-ua-platform claims agree with the UA.
- **Degraded lane** (honest fallback — envelope says
  `fingerprint.backend: python-requests` + reason): plain python-requests
  client with the same sticky UA claim, headers re-emitted in the
  family's canonical browser order (`order_headers_for_family`) + the
  family's realistic Accept/Accept-Language/Accept-Encoding fill (only
  encodings THIS venv can decode — `browser_accept_encoding` checks
  brotli/zstandard importability rather than asserting gzip-claims-it-can).
  Active when: lib missing, `SESSION_IMPERSONATION=off`, identity is
  operator-owned (`SESSION_UA` override, legacy marker, or a caller
  `-User-Agent` header — the TLS stack cannot be reshaped to match an
  arbitrary claimed agent, so impersonation yields), or the multipart
  upload lane (`session_upload`; curl_cffi's files-API is not wired).
- **Jar + CSRF + gate carry over untouched**: cookies seed via the jar's
  RFC 6265 matcher (`cookie_header()`) and persist from the impersonated
  client's inner stdlib CookieJar; per-hop scope-gate validation still
  runs exactly as before (the gate hop loop is backend-agnostic).

Honest limits: the degraded lane still tells a python-requests TLS story
(that's why it's marked, not masked); the impersonated lane does not add
stealth beyond template coherence (a vanilla `playwright` sidecar is, and
stays, policy-vanilla); template fidelity is pinned to `curl_cffi==0.16.3`
— on upgrade, `impersonation_target` refuses un-pinned targets and degrades
rather than guessing; and none of this changes the no-rotation-within-host
contract.

## Honest taxonomy (what evasion is NOT)

- `-T` timing presets tune the scanner's own accuracy/speed trade — the full
  sweep pattern still lands on the wire. They are NOT evasion.
- Wire shaping = `--max-rate` / `--scan-delay` (nmap), `rate=` (masscan;
  already clamped by `MASSCAN_MAX_RATE`), `SESSION_HOST_FLOOR` (HTTP).
  These change what an observer actually records.
- `decoy` / `fragment` presets are `lab_only` — refused without
  `SHAPING_LAB_MODE=1` in the root-0600 .env. Both are fingerprint theater
  against modern stacks, and their preset notes say so.
- UA policy: deterministic per-host from a realistic pool — sticky across a
  session (rotating identity mid-session is how authenticated servers get
  suspicious); spread happens ACROSS hosts via hash distribution.
  `SESSION_UA=legacy` restores the old self-identifying marker; a custom
  `SESSION_UA` value fixes identity fleet-wide. An operator-owned identity
  never impersonates (TLS can't be reshaped to match an arbitrary UA).
- TLS/header impersonation (curl-impersonate via `curl_cffi`) is NOT
  malware theater: it makes the web lane's existing sticky-identity claim
  self-consistent (UA ↔ JA3 ↔ header set/order as one story). The
  degraded path is always honest in the envelope (`fingerprint`), never
  faked.

Errors surface as `ScopeGateError("shaping: ...")` — the scope gate is
untouched and always evaluated first.

Measurement caveat: whether these knobs are evasive in practice needs
differential-testing infra (observe detector behavior with vs. without) —
expansions to this package carry that prerequisite.
