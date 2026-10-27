# Security Policy

daharness is dual-use software: an orchestration harness for offensive
security work (scanning, fuzzing, exploitation support, post-exploitation)
intended for **authorized testing only**. This policy covers three things
that are often conflated:

1. Reporting a **vulnerability in daharness itself** — a defect that harms
   the *operator* running the framework.
2. Reports about the framework's **offensive capabilities** — which are, by
   definition, the product's purpose.
3. The **responsible use policy** every user is expected to follow.

## Reporting a vulnerability in daharness

**Do not open a public issue for a suspected vulnerability.**

Use GitHub **Private vulnerability reporting** (the *Security* tab →
*Report a vulnerability*), which is enabled for this repository.

Please include:

- Affected component and the commit you pulled
- Minimal reproduction steps (tool, arguments, configuration)
- Observed vs. expected behavior, including relevant tool output or logs
- Your assessment of impact

**Response expectations:** acknowledgement within 7 days; fixes are
prioritized by severity and land on `master`.

**Supported versions:** none are versioned — this is pre-release software.
Security fixes land on `master` only. Pin the commit you deploy.

### What counts as a real vulnerability

Defects that harm the *operator*, not the target. In-scope examples:

- Command/shell injection where tool arguments reach a `subprocess` call
- Path traversal escaping the `ALLOWED_TOOL_ROOTS` confinement
- The API gateway failing to authenticate when `GATEWAY_API_KEY` is set
- Unintended secrets leakage (tokens surfacing in logs or scratch storage
  beyond documented retention)
- Any path where the operator approves action X but the executed action
  differs from what was shown (manifest spoofing at the dispatch boundary)
- The driving model acquiring a capability it is not granted — e.g.
  toggling the scope gate, which is deliberately not exposed as a tool

## By design — reported, then closed as non-issues

The framework deliberately ships offensive capability. These are the
product working as intended:

- "It can port-scan / fuzz / brute-force / exploit systems."
- "It runs nmap / MSF / sqlmap / hydra — those tools attack things."
- "With the scope gate disarmed (the default), tools reach any target."
  The armed gate is operator-controlled by design; the disarmed lab default
  is a documented deployment decision, not a bypass.
- "The driving model can request tool executions." That is the
  architecture: the harness ships no conversation model and no approval
  gate — an integrating harness that wants sign-off adds its own layer in
  front of the gateway.
- "It can be used to attack people." See the responsible use policy below.

## Responsible use policy

By using, modifying, or distributing this software, you agree that:

- **Authorization comes first.** Test only systems you are explicitly
  authorized to test — your own lab, written engagement authorization, or a
  bug bounty program's declared scope. Use the framework's scope tooling
  (`check_scope`, `check_reportable`, the operator-armed gate) to enforce
  it.
- **The law still applies to you.** Unauthorized access to computer systems
  is a crime in virtually every jurisdiction (e.g. CFAA in the US, Computer
  Misuse Act in the UK). This software grants no legal permission and
  cannot sign your authorization for you.
- **Target data stays on your hardware.** The driving model must run on a
  locally hosted endpoint (Ollama or equivalent, loopback/LAN); the embed
  lane (`EMBED_URL`) counts too — it receives the text being embedded.
  Pointing the framework at a cloud LLM API transmits every tool result —
  credentials, session tokens, internal IPs, response bodies — to a third
  party, violating most program rules of engagement and, when personal data
  is involved, data-protection law. See the Legal Addendum in `README.md`.
- **No misuse support.** The project provides no assistance for use against
  systems you are not authorized to test, and no help evading the law.

*Vulnerability in the tool → the Security tab above. Someone misusing the
tool against you → the appropriate legal authorities; you may also report
it to the repository owner so the offending fork/account can be denounced
and removed from project spaces.*
