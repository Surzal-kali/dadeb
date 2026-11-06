# Evasion & Budget Engine — Design Doc

**Version:** v0.2 · 2026-11-05
**Status:** v0.1 draft + user red pen folded; 2026-11-05 chat threads (SQLite tier, fleet boundary, principal minting) resolved into the body. Build gate lifts per phase order.
**BUILD GATE:** no implementation until the user signs off. Every "OPEN" item below is a user decision; every "DEFAULT" is my proposed default, vetoable.

---

## Contents
1. Provenance & relationships
2. Problem & goals / non-goals
3. Architecture: the three-concern pipeline
4. Budget model: dimensions, vectors, debit cascade
5. Accounting: declared spend (L0/L1/L2)
6. Refill: epochs, jitter placement, HOLD/NORMAL modes
7. Exhaustion → deferred queue + operator
8. Controller: state machine, constitutional bounds, tripwire learning
9. Reserves: entry/exit partitions
10. Emissions ledger
11. Posture layer seam
12. Observability: status twins & honesty semantics
13. Persistence & restart-resume
14. Placement policy (public vs customs)
15. Phased build order & test hooks
16. Open-questions register
A. Schema sketch
B. Per-tool estimator & actuator cheatsheet

---

## 1. Provenance & relationships

- Origin: 2026-11-05 design chat (rate min/max, traffic encoding, per-tool interaction facets). This file supersedes that chat as working spec; user edits win.
- **Scope gate (`program_scope`) is UNCHANGED.** It remains the authorization predicate (config-authored, static, fail-closed). This engine sits BESIDE it at the same dispatch chokepoint.
- Existing actuation surfaces become the posture layer's hands: `shaping.py` + `run_nmap(shaping=)`, `webshape` + `web_session` (sticky per-host UA, HostFloor pacing), ZAP rate-only configs, `--rate` on masscan/ffuf-class.
- DB tiering doctrine applies with a relocated floor (decided v0.2, user): the ration economy's truth is **SQLite on the tree, always**; Postgres is an optional write-behind mirror (team mode + rollups), never on the dispatch critical path. See §13.

## 2. Problem & goals

**Goal:** keep total campaign signal below what defensive stacks can infer, without baking magic numbers or trusting model judgment with resources.

Standing facts the design must honor:
- The unit of detection is a CAMPAIGN, not a request. Posture is a whole-engagement property.
- Defender tripwires are unreadable configurations (velocity rules, lockout counters, IDS thresholds, bot scoring). You can only learn their shadows.
- Regularity is as detectable as volume: interval entropy matters; metronomic spend is bot-shaped. (HostFloor precedent; bedside 301-flood also showed rate policy is an ANALYSIS-INTEGRITY control — floods drown your own signal.)
- Cross-tool multiplication is invisible to any individual tool (nmap + ffuf + ZAP on one vhost). Only a shared per-host budget fixes it.
- Rails-by-prose is advisory (bench-verified). Integrity mechanisms live in the chassis.

**Non-goals:**
- No synthetic TLS-fingerprint forgery (customs valve — see §14). [revisit]
- No multi-operator distributed budget sync (DB-tiering tracks team mode separately).
- No new scanning capability: the engine makes orchestration quieter, not more capable.

## 3. Architecture: three-concern pipeline

One chokepoint (the existing guarded dispatch path), five steps interleaving NEW machinery with the regulators already there:

```
tool call → [1. AUTHORIZATION]  scope gate (predicate, static config, hard no)         UNCHANGED
           → [2. RATIONING]      budget preflight — READ-ONLY routing decision          NEW
                                 never-fit → REJECT; short → ENQUEUE (budget_short)
           → [3. CONCURRENCY]    fleet request_unit                                     EXISTING
                                 duplicate → SATISFIED; refused → ENQUEUE (host_busy); acquired → continue
           → [4. DEBIT]          cascade debit — one atomic transaction                  NEW
           → [5. POSTURE]        shaping/webshape/session actuation (per-request)        EXISTING, subordinated
           → tool executes       emissions ledger records the transaction               NEW
           → poll/done           fleet release_unit + L1 reconcile                       EXISTING + NEW
```

Division of labor — one axis each, no shared counters (decided v0.2):

- **budget = volume over time** — how much signal this host ate this hour; refill, reserves, HOLD/NORMAL.
- **fleet scheduler = work right now** — same work already live? host slot free? auth-adjacent exclusion? (worker queue = local RAM, JVM pressure).
- Two counters on one host axis would drift: the old §7.3 per-dimension concurrency cap is **DELETED** — fleet slots are the hard ceiling.
- **Span normalization is shared:** budget nodes reuse fleet's `_numeric_span` canonicalization — one normalizer, one notion of "one host."
- The concurrency step applies to job-store launchers (nmap/ffuf/hydra/sqlmap/masscan class); single-emission tools (web_session one-offs) pass through to debit.

Split rationale: scope is a constitution, rationing is a central bank, the fleet scheduler is the concurrency regulator, posture is currency handling. One monolithic "evasion engine" would conflate them. Drain re-enters at step 1 — the queue is still not a bypass lane (§7.3).

## 4. Budget model

### 4.1 Dimension tuples

Budgets are keyed by the tuple defenders actually count on:

```
(entry partition, exit_id, range_cidr, host, principal)
```

- `principal` = account / session-cookie / credential identity — optional fourth axis (lockout counters count per-account; spray-vs-brute shape is a principal-dimension decision).
- One host can sit in several ranges; debit cascades leaf→range→exit→engagement-global.

### 4.2 Budget vectors (DEFAULT: vectors, not scalars)

Defender counters are heterogeneous — normalizing to one scalar throws away the axis each tripwire reads.

```python
class BudgetVector:  # units defenders actually count
    requests: int      # WAF velocity, ffuf/ZAP-class
    packets:  int      # IDS scan thresholds
    auth:     int      # lockout counters
    bytes:    int      # egress monitoring, exfil
```

Live state per node: ring buffer of recent emissions + vector counters per (dimension, window). A busy engagement is kilobytes, never a packet history.

### 4.3 Principal keying (decided v0.2: mint-debit model)

`principal` nodes exist ONLY for auth-relevant dispatches. Three rules make rotation expensive without a principal registry:

1. **Only auth-relevant dispatches key a principal.** A GET to `/login` debits host-level `requests`+`bytes`; a cred-bearing POST also keys the principal. An estimator that cannot identify the principal under-keys (host-level only) — under-keying is ALWAYS conservative: everything lands in a host window regardless, never looser.
2. **Minting is the debit.** First dispatch under a new principal identity debits the parent host/range node's `auth` vector AND increments a per-window `distinct_principals` counter on the host node. Subsequent dispatches under the same principal debit the principal node's (small) budget. Consequence: brute exhausts per-principal; spray exhausts the distinct-principals counter before any single principal notices; rotating cookies eat the host's auth allowance — all three defender shapes bounded by one machinery.
3. **Principal TTL dies with the identity.** Cookie expiry/logout ends the node and its unbanked remainder — aligning with the cookie jar's TTL purge (72h), so identity and budget share one clock. Identity source: account name where known, cookie-jar token hash otherwise.

**`distinct_principals` is a counter, not a vector dim (decided v0.2, user: less vector math).** It's a shape metric only the host node needs; adding it to `BudgetVector` would touch every L0 estimator for nothing the vector math uses.

### 4.4 Auth classification stack (no nomic, no model)

Who decides "this is auth traffic," deterministically — three layers in precedence:

1. **Estimator registry declarations** — dedicated auth tools (kerbrute/hydra-class, MSF login modules, hashcat validators) declare `auth_emitter=True` in the same registry entry that carries their L0 vector. No runtime classification.
2. **Config-authored arg rules** (generic lanes, chiefly web_session): URL/endpoint patterns + credential-bearing kwarg names + jar cookie presence. This is the `FLEET_AUTH_ADJACENT_RE` decision already solved once for fleet scheduling — **one shared auth vocabulary in the config that both consumers read**; a fleet exclusion and a budget debit must not disagree on the same traffic. Budget is fine-grained per (tool, args); fleet's coarse boolean derives from the same table.
3. **Default: non-auth, host-level** — the conservative direction (an unclassified auth request still lands in the host `requests` window).

Precedence: explicit declaration > config regex > under-key. No embeddings involved (nomic stays on registry + memory); the model plays no part — that is §2's goal verbatim ("without trusting model judgment with resources").

**Outcome classification is the §8 response-class harvester — one component, two consumers** (tripwire bounds + auth accounting): web_session stamps `auth_event`/`principal`/outcome from inside its own helper where the response object is already in hand; subprocess tools are parsed by deterministic regex (401/403, lockout text, challenge pages); credit-line long-runners surface outcomes at poll. The engine reads dicts the tools already produce — **no live flow interception anywhere**; L2 pcap stays the opt-in truth lane. Retro-catch-up: a misclassified auth event is caught by L1 (Set-Cookie-after-POST, token grant, 401/403) — the emission row corrects its dims, the auth window catches up, and a **coverage finding** tells the operator to register the rule (classifier gaps surface as ledger evidence, not silent holes). Worst case — a custom endpoint both declaration and regex missed — is bounded: the requests window still saw the volume.

## 5. Accounting: declared spend

**You don't count packets; you declare expenditures and reconcile.**

| Level | What | Cost | Default |
|---|---|---|---|
| **L0 preflight** | wrapper declares estimated vector from args before dispatch | free | ALWAYS (admission gate) |
| **L1 reconcile** | harvest actuals from tool output (nmap/masscan already report stats); true-up retry/redirect drift | free | ALWAYS |
| **L2 pcap truth** | opt-in raw capture count | expensive, session-dependent on phone (proot raw walls) | OPT-IN only, warranted when a tool misreports itself |

L0 failures to declare → dispatch blocked, not guessed (Unknown ≠ healthy — a tool that can't state its cost needs a registered estimator or runs credit-line mode).

**Cascade debit is atomic (v0.2 fix):** admission checks ALL cascade levels (leaf→range→exit→global) then debits all in one `BEGIN IMMEDIATE` transaction — a mid-cascade shortfall rolls back the WHOLE debit; never a partially-charged leaf.

**One harvester, two consumers:** L1's actuals harvest and §8's response-class signal parsing are the SAME component (§4.4 outcome classification); auth-outcome is one response class it emits.

## 6. Refill: epochs, jitter placement, HOLD/NORMAL

### 6.1 Jitter placement (doctrine)

**Defenders observe your spend curve, never your bookkeeping. Jitter BOTH sides — accrual and release on different cadences/distributions.** (v0.2, user red pen: both sides jitter; the sawtooth dies when neither side is metronomic.)

- Token-bucket with hourly epochs is the base; burst capacity + steady replenish.
- A refill that emits a sawtooth (exactly-hour bursts as queued tools wake simultaneously) is itself a behavioral signature — periodic bursts are a hunt pivot.
- Release-side smoothing + interval entropy on spend. Spending BELOW refill rate deliberately (hiding in crowd noise) is a legal posture.

### 6.2 Refill modes (amended invariant)

User invariant (2026-11-05): *"budget doesn't start its jittered refill until the engine itself is done dispersing the backlog."*

Stated literally this deadlocks when a backlog forms at zero budget (drain needs budget; refill waits for drain; neither happens). Amendment preserving the intent:

| Mode | Condition | Refill accrual | Release rules |
|---|---|---|---|
| **HOLD** | node subtree backlog nonempty | accrues at CONSTITUTIONAL FLOOR RATE only | release-eligible ONLY to operator (backlog drain). Fresh dispatches enqueue too; interactive priority jumps ORDERING, never budget |
| **NORMAL** | backlog empty | configured rate, jittered release | all emitters |

- **Epoch re-anchor:** HOLD→NORMAL transition sets a fresh jittered epoch anchor. The clock starts after drain — exactly the user's semantics.
- Modes are PER BUDGET NODE (host with backlog doesn't freeze a different host's economy).
- **Backlog definition (v0.2 fix):** backlog = `state='queued'` items only. Expired/cancelled items take their promised ledger exit and are purged at expiry — lingering terminal rows would latch HOLD forever; a node whose queue holds only terminal items is backlog-empty.
- **Floor 0 is forbidden (v0.2 fix):** a dimension whose constitutional floor rate is 0 never accrues → never drains → stays HOLD forever. The red pen accepts MOMENTARY deadlocks; zero-floor is a permanent one. Constitution keeps every HOLD-mode floor rate > 0; belt-and-braces, a HOLD-stall alarm surfaces at `budget_status` (operator-visible, not auto-escalating) when a node holds backlog > 1 epoch with no drain progress.

## 7. Exhaustion → deferred queue + operator

**DECIDED (user):** exhaustion is DEFER-NOT-DENY via a task scheduler + operator. Budget-insufficient dispatches are queued, not bounced.

### 7.1 Admission rules

| Case | Behavior |
|---|---|
| scope violation | hard NO (unchanged) |
| declared cost > available budget | ENQUEUE (defer), return deferred job id, pollable |
| declared cost can never fit (single call > constitutional ceiling even at full refill) | REJECT with reason ("declare smaller: rate-limited sweep instead of one full call") |
| open-ended tool (ZAP-class), can't preflight | credit-line mode: wrapper meters tool internally against a drawn budget token (draw = admission event) |

**Draw lifetime (v0.2 fix):** a credit-line draw is a reservation bound to the dispatching job's lifetime — unreleased remainder reconciles at fleet `release_unit` / the job store's reaper sweep (an abandoned draw is swept like a stale fleet unit; nothing dangles across a crash or restart).

### 7.2 Queue item

```python
QueueItem:
  qid, tool, args_snapshot,
  declared_vector,            # L0 estimate at enqueue time
  dims (entry, exit, range, host, principal?),
  defer_reason,               # budget_short | host_busy — why it deferred (model/operator reads this)
  agent_id, engagement,       # ownership (agent-attributed like jobs/evidence) + cobweb purge key
  priority,                   # interactive > agent > scheduled — ORDERING ONLY
  ttl_expiry,                 # staleness: 8h-old recon may be fine; stale chain-steps may be pointless
  submit_ts, state            # queued | dispatched | expired | cancelled
  job_ref,                    # set at dispatch; or the satisfying live unit's job_id (§7.3)
```

### 7.3 Operator

- **Front-door invariant: drain NEVER bypasses the chokepoint.** Operator re-dispatches through the normal path: L0 re-declare → scope re-check → fleet `request_unit` → debit → posture actuation → release. The queue is not a bypass lane.
- Tick cadence: operator's own schedule is JITTERED — a metronomic drain is as tell-tale as a metronomic scan.
- Ordering: priority class, then FIFO. Pacing obeys the controller state machine (throttled state = slower drain; drain is just another emitter).
- **Concurrency is the fleet scheduler's job (v0.2: replaces the old per-dimension cap):** drain launches jittered-sequentially per tick; fleet `request_unit` supplies the hard per-host ceiling (slots 2/4, auth-adjacent exclusivity). Two counters on one host axis would drift — the ration engine keeps NO host-concurrency counter.
- **Duplicate = satisfied (v0.2):** a fleet `duplicate` verdict at enqueue OR drain means a live unit with the same canonical key is already running — enqueue returns that job's id immediately; drain completes the item pointing at it. Nothing queued twice, nothing debited twice.
- **Brain no-retry carries into drain (v0.2):** a drain dispatch whose Brain call was accepted but timed out (`BRAIN_DISPATCH_TIMEOUT`) does NOT auto-re-enqueue — it may still be running (executor rule). Item flags for human inspection; ledger stamps what is known.
- TTL expiry is VISIBLE: expired items recorded in the emissions ledger, never silently dropped.
- Priority is ordering-only: an interactive item still debits and obeys pacing. Interactive priority is a UX affordance, not a budget violation.

### 7.4 REPL & model surfaces

Exhausted dispatch returns: defer hint + qid + estimated availability surface (matches status-twin patterns; human-piloted lane polls rather than awaits).

- **Deferred envelopes read as instructions, not transient failures (v0.2):** the model-facing ENQUEUE shape mirrors `budget_exhausted` — qid + defer_reason (`budget_short` | `host_busy`) + availability estimate + explicit "do not retry; poll `queue_status`." A model spinning on a full economy is the failure mode deferral exists to avoid.
- **Turn-budget interaction (decided v0.2):** a returned ENQUEUE consumes the calling turn's tool-budget slot — the call happened, deferral is not free work. `budget_status`/`queue_status` stay terminal-lane (§12), so a deferral never traps the model without observability.

## 8. Controller

### 8.1 Per-dimension state machine

```
normal → soft-signal → throttled → back-off → cooldown
```

Fed by observed response classes from the emissions ledger. **Hysteresis mandatory** (k signals or sustained rate before transition; slow decay back) — one 429 from one CDN node must not flap the state.

Signal vocabulary (reactive half of rate policy): 429/403 after a count (counter-shaped, not signature-shaped), tarpit latency ramps, mid-flow RSTs, challenge interstitials, mid-session cookie issuance, lag-then-resume queue shaping.

### 8.2 Constitutional bounds (safety rail)

The engagement CONFIG authors: ceilings, floors, refill rates, reserve sizes, **and the controller's own authority limits** (max throttle-down, max speed-up, max transitions/hour). The state machine is free only inside the constitution — same philosophy as the scope gate's config-respecting rails. A dynamic controller left unbounded can decide its way into a tripwire.

**Mutation authority (v0.2):** the constitution is config-authored — no model lane adjusts ceilings, floors, refill rates, reserve sizes or controller authority limits; REPL/operator lane only, mirroring the scope-gate and engagement-arm authority. The controller is free INSIDE the constitution; who holds the pen is outside its reach.

### 8.3 Tripwire learning

When 429s onset after ~X requests in window W:
- Hypothesis recorded per host: `tripwire_requests ∈ [lower, upper]`, provenance-tagged.
- Rate R sustained for window T with no reaction ⇒ negative observation, tightens lower bound.
- Both-sided interval estimates, cumulative, stored per host.
- Controller uses bounds to auto-throttle — ONLY within constitutional authority (§8.2).
- Cross-engagement retention: **DECIDED (user red pen): per-engagement, no cross-retention** — tripwire estimates are engagement-scoped rows; `engagement purge` wipes them. Corollary written down: every engagement cold-starts with no bounds, so the constitution's conservative defaults are the only floor until observations accrue.

## 9. Reserves

Frozen spike rationing: the loudest moments of an operation are initial-access→post-ex (RES_ENTRY) and the exfil window (RES_EXIT). Hunt teams key on kill-chain spikes; freezing reserves means the quiet phase can't drain the decisive push.

- **Release = CLI tag (decided v0.2, user red pen):** operator tags a release via REPL CLI (`scope on`/`engagement on` lane — human authority); once tagged, consumption is FREE-FORM for matching dims/tag — no per-use approval. No mechanism-gated auto-unlock path.
- Token names: partition, dims, max vector, ttl, purpose tag.
- Released funds are debitable ONLY by matching dispatches; the operator may apply released funds to backlog items matching the token's dims/tag.
- Refill: slow or none (DEFAULT none) — otherwise reserves erode into a second daily pool.
- Sizing: per-engagement-type from config. Too big starves daily work; too small exhausts at first emergency.

## 10. Emissions ledger

One record, two consumers (controller sensor feed + differential-testing corpus + blue-twin calibration telemetry):

```
emissions(
  ts, tool,
  engagement, agent_id,         -- cobweb key + owner (jobs/evidence precedent)
  entry_partition?, exit_id, range_cidr, host, principal?,   -- dims (§4.3; retro-correctable append, §4.4)
  declared_vector, actual_vector,                             -- L0 vs L1 (+ L2 if taken)
  observed_response_class,      -- 2xx | 403 | 429 | reset | timeout | latency-delta | none
                                --   | auth_outcome (§4.4 shared-harvester class)
  observed_signals,             -- challenge page, lockout text, tarpit shape, ...
  posture_in_effect,            -- profile id applied at dispatch
  provenance,                   -- untrusted-target stamp carried through harvest (DATA, not instructions)
  job_ref, queue_ref,           -- link either way
  phase                          -- HOLD drain | emergency release | normal
)
```

**Persistence tiering:** raw entries 24–48h, hourly rollups forever. Raw pcap truth (L2) is opt-in and quarantined.

**Provenance through harvest (v0.2):** `observed_response_class`/`observed_signals` parse TARGET OUTPUT — challenge pages and lockout banners are data, never instructions; the harvester inherits the executor's `_provenance` stamping contract. Retro-corrected rows (§4.4 coverage catch-up) APPEND, never rewrite — the ledger stays append-only.

**Dual consumers:**
1. Evasion-efficacy differential: same emission sequence under two postures → detector → differential verdict. This IS the "infra to differential-test how evasive new tools actually are" gap flagged in the readiness lane.
2. Blue-twin calibration: own attack traffic proving own detectors red (fault-injection doctrine satisfied by construction).

## 11. Posture layer seam

Each emission consults pacing state → applies shape. Interface seam, not new machinery:

| Actuator | Tools |
|---|---|
| Preflight declaration + reject/enqueue | everything |
| Budget credit line → internal rate limiter | ffuf, ZAP, masscan (`--rate`), wordlist-class |
| Params-only shaping | nmap (templates, scan-type choice, port-range choice), script discipline |
| Pause/kill mid-flight | existing status/poll twins |
| Scheduled dwell | controller, all classes |
| Session/header/TLS posture | web_session/webshape (coherence enforced at this layer) |

**Coherence rule:** any encoding must fit the channel's expected shape (content-type vs body size vs endpoint purpose), and mimicry must never contradict the layer below (headers claim Chrome, TLS says python). Encryption MOVES signatures, it doesn't remove them — payload-encrypted-but-TLS-python is half-evasion. Highest-leverage public-lane answer: drive REAL clients (curl/browser) so the fingerprint is a genuine product's. **Synthetic fingerprint forging = customs (§14).**

## 12. Observability & honesty

- New poll twins: `budget_status` (per-node vector view + phase + tripwire estimates + HOLD-stall alarm) and `queue_status` (backlog depth, heads, defer_reasons, TTL countdowns). Register in the job-id space; hydrate family next_hints per the twins doctrine.
- **Terminal lane (v0.2 fix):** both twins join `TOOL_BUDGET_TERMINAL_ALLOWLIST` (currently only `utils.memory_tools.`, `utils.findings.`) and are infra-tagged (`fleet_host_status` precedent) — a rationed/trapped model must still be able to observe and poll its deferral.
- Honesty semantics port verbatim: sensor-degraded ≠ clean; silence ≠ healthy; a dimension with unknown response state paces conservatively and the ledger says Unknown. Unknown never collapses to Pass.

## 13. Persistence & restart-resume

- **SQLite truth, always (decided v0.2 — user):** the live economy — budgets, queue, tripwire estimates, controller state, raw emissions — lives at `run/budget/budget.db` (scratch-store conventions: 0600/WAL, `state_perms` mode-heal, engagement-scoped rows). A budget that resets on restart re-arms full velocity exactly when a tripwire may already be poking — restart-proofing is a safety property, and a WAL file gives it locally.
- **Postgres demotes to a write-behind mirror** — team mode (networked multi-box) + long-horizon rollups only. Mirror failure/lag is logged and ledger-stamped; **dispatch never blocks on PG**.
- **Degraded mode relocated, not removed:** SQLite store unreadable ⇒ traffic-sending dims fail-closed, verdict Unknown, never green (§12 honesty semantics). The store shares the tree's failure domain with the harness itself — the same scope as "everything is broken anyway," not a new network dependency.
- Multi-lane consistency is proven precedent, not a leap: fleet.db (cross-actor dedupe) and cookie_jar.db already share on-tree SQLite across Brain/gateway/REPL/kernel lanes. PG earned its keep only for networked multi-host — future team mode.
- **Purge (orchestrated, v0.2):** `engagement purge` hits the SQLite store first, then the PG mirror when up — reports both. Budget nodes are NOT audit trail: on next engagement arm they re-mint from the constitution config (cold-start per engagement is the decided §8.3 corollary).
- On restart, operator resumes HOLD/NORMAL from persisted state.
- Ledger rollup sweeps run inside the store on mutation cadence (scratch TTL-cleanup precedent); raw entries still 24–48h per §10.

## 14. Placement policy

**DECIDED (user red pen): public red lane (dadeb).** Rationale: the engine is noise-shaping and resource accounting over existing commodity tools — zero capability-addition; it makes orchestration quieter, not more capable. Same registry/decorator patterns as the rest.

**Customs valve:** synthetic TLS/JA3-forging machinery, anything that manufactures imitation client stacks or persistence-grade concealment. Driving real clients stays public-safe. **Taxonomy placement (v0.2):** the existing `SHAPING_LAB_MODE=1` presets (`decoy`/`fragment`) are **lab_only, not customs** — commodity nmap flags; one vocabulary across both lanes.

**Lane notes (v0.2):** the Phase E differential harness (§10 consumers) is a LAB lane (blue-twin detectors) — this section covers the public dispatch engine only. The PG write-behind mirror (§13) is infrastructure following the DB-tiering doctrine, not a lane of its own.

## 15. Phased build order & test hooks

| Phase | Deliverable |
|---|---|
| A | Budget ledger + vector debit (atomic cascade) + L0 declaration + queue/operator skeleton + `run/budget/budget.db` store (SQLite truth; PG write-behind mirror = team mode later, off the critical path) — **BUILT** (`utils/ration_store.py` + `utils/ration.py`, wired-not: executor integration is Phase B; `pytest tests/test_ration_a.py`, 49 hooks) |
| B | Status twins + REPL defer surfaces + restart-resume — **BUILT** `budget_status`/`budget_queue_status` twins on the terminal lane + REPL `budget` operator command (`status|queue|defer|drain|set-phase|purge|constitution`); async operator_tick drains through the REPL's `run_tool` (bg tools bind `job_id`, inline tools finish in place `dispatched_inline`); restart-resume verified (queue/balances/HOLD/emissions survive; no velocity re-arm); `pytest tests/test_ration_b.py`, 19 hooks) |
| C | Controller state machine + tripwire learning + refill modes + epoch re-anchor — **BUILT** (`Controller` in `utils/ration.py`: 5-state machine normal→soft_signal→throttled→backoff→cooldown paced 1.0/0.7/0.4/0.2/0.1 (cooldown is 0.1, not 0 — full stop stays operator-only §8.2), hysteresis streak `BUDGET_CTRL_HYSTERESIS_K`, quiet decay one level per `BUDGET_CTRL_QUIET_WINDOW_S`, `BUDGET_CTRL_MAX_TRANSITIONS_H` authority ring on ALL transitions; tripwire intervals = per-engagement+host two-sided bounds (reaction onset sets upper=window spend `BUDGET_TRIPWIRE_WINDOW_S`, clean-run ≥3 raises lower, monotone min/max); `apply_backlog_modes` auto HOLD⇄NORMAL per host_axis from live backlog, `manual_phase` pin always wins, hold→normal re-anchors the accrual epoch with ±`BUDGET_JITTER_SPREAD` jitter; release-side drain pacing `_eff_batch = batch·pacing` + per-item jitter `uniform(0, BUDGET_RELEASE_JITTER_S)·(1/pacing)` capped `BUDGET_RELEASE_JITTER_CAP_S`, cooldown items skip without consuming the batch; stall alarm (held + oldest backlog older than one epoch with no drain progress) surfaced on the `budget_status` twin; `pytest tests/test_ration_c.py`, 22 hooks) |
| D | Executor ration gate (§3 chokepoint) + credit-line draws (§7.1) + reserves (§9) + posture dwell (§11 seam) + drain-lane ration-awareness + REPL reserve levers — **BUILT** (`ration_gate` fires in `daharness/executor.py` preflight after the scope-disable check — every lane (gateway REST/MCP/REPL/kernel) funnels through it; unregistered tool = no state, disabled knob = no state, otherwise declared-traffic preflight → debit → dispatch, with `budget_deferred`/`budget_refused` envelopes meaning NO dispatch and `ration_discharge` after every debited dispatch (duplicate/refused fleet verdicts auto-compensate via `engine.compensate` — full refund to every `traces[].node_key` + drift=2 stamp, never binding the LIVE unit's job_id; launched jobs bind `job_ref`; inline harvest tools reconcile actuals from the result); credit-line lifecycle: the emission row IS the draw (§7.1) — closed at poll-release via `reconcile_poll_job` (wired into `poll_job`'s terminal branch, harvests bounded numeric actuals) or by the `sweep_draws` backstop (job row gone / past `BUDGET_DRAW_TTL_HOURS` — declared stands, never invented); reserves: `mint_reserve`/`release`/`freeze`/`list`/`sweep` store API + REPL `budget reserve (list\|release\|freeze\|mint)` — consumption is a same-tx step of `debit_vector` covering the TOTAL cascade deficit across all dims/levels (pay-or-rollback), matching on dims + engagement (`engagement=NULL` tokens are wildcards); posture dwell: `ration_dwell` (§11 seam) sleeps bounded `uniform(0, BUDGET_DWELL_CAP_S)·(1/pacing−1)` in `web_session` after HostFloor.wait when the controller paces below 1.0; drain lane ration-aware: `BudgetStillShort`/`BudgetRefused` escaping `operator_tick` cancel a gate-minted duplicate (original result preserved) with an honest note; e2e verified through `daharness.executor.execute_tool` (registered toll debit + `result["budget"]` stamp + emission row; disabled knob leaves behavior byte-identical); `pytest tests/test_ration_d.py`, 34 hooks). **Honest v1 notes:** `entry_partition` is advisory only (dims-match on host/range/principal is the enforceable contract — tools don't self-report partitions); ZAP traffic metering deferred; masscan/ffuf rate auto-clamp was **REJECTED** (rate hints advisory only); emission rows regrade any partially-open declaration to `credit_line` (any None dim = open-ended spend — the estimator's `declared_basis` stays visible in the gate receipt), `open_draws` excludes compensated/closed draws so nothing masquerades as live accounting debt |
| E | Emissions-ledger differential harness (evasion efficacy + blue-twin feed) |

**Test hooks (fault-injection doctrine: a guard that can't go red is decoration):**
- Overspend-declare reconcile mismatch must trip (L0/L1 drift detection).
- Budget guard must go red under fault injection, not just pass happy path.
- Unknown semantics: sensor-degraded dimension ⇒ conservative pacing + Unknown verdict, never green.
- Restart-resume: kill mid-HOLD, verify no velocity re-arm.
- Jitter shape: no sawtooth (release distribution tests).
- HOLD regression: zero-budget backlog must drain (deadlock regression test).
- Front-door invariant: queue drain goes through L0+scope+debit, verified by ledger traces.
- Differential parity: declared-vs-harvested accounting across nmap/masscan/ffuf fixtures.

## 16. Open-questions register

| # | Question | Status |
|---|---|---|
| 1 | Vector vs scalar budgets | **DECIDED:** vectors, approved (§4.2) |
| 2 | Exhaustion: reject-first vs deferred-queue | **DECIDED (user):** deferred queue + operator, refill gated on drain (§6.2, §7) |
| 3 | Reserve release: human-declared-only? | **DECIDED (user):** CLI-tag release; use free once tagged (§9) |
| 4 | Placement: public dadeb vs customs | **DECIDED (user):** approved to dadeb (§14) |
| 5 | Tripwire memory across engagements | **DECIDED (user):** per-engagement, purge wipes (§8.3) |
| 6 | Refill gate deadlock amendment (HOLD/NORMAL) | **DECIDED (user):** both sides jitter at different rates; momentary deadlocks expected; floor 0 forbidden (§6.1/§6.2) |
| 7 | Deferred-queue vs in-band await at REPL | **DECIDED:** defer+poll (same queue as the model, no exceptions) |
| 8 | Persistence tier: PG-central vs SQLite truth | **DECIDED (v0.2):** SQLite truth always (`run/budget/budget.db`); PG = write-behind mirror (§13) |
| 9 | Fleet scheduler boundary | **DECIDED (v0.2):** budget preflight read-only before fleet; duplicate=satisfied; §7.3 cap deleted; shared span normalizer (§3) |
| 10 | Principal keying + auth sorting | **DECIDED (v0.2):** mint-debit model + shared auth vocabulary + §8 shared harvester (§4.3/§4.4) |

---

## Appendix A — schema sketch

```sql
budget_nodes(
  node_id, engagement,             -- engagement-scoped (red pen #5); re-mints from constitution on arm
  entry_partition?, exit_id, range_cidr, host, principal?,  -- NULL = coarser node; spans via fleet _numeric_span
  vector_remaining  TEXT,          -- JSON {requests, packets, auth, bytes} (SQLite truth tier, §13)
  distinct_principals INT,         -- host-node only (§4.3 counter, NOT a vector dim)
  phase             TEXT,          -- HOLD | NORMAL
  epoch_anchor      TEXT,          -- next jittered refill epoch anchor (§6.2)
  last_refill       TEXT
)

queue_items(
  qid, tool, args TEXT, declared_vector TEXT,
  entry_partition?, exit_id, range_cidr, host, principal?,
  defer_reason,                    -- budget_short | host_busy
  agent_id, engagement,            -- ownership + cobweb purge key (jobs/evidence precedent)
  priority INT, ttl_expiry TEXT, state, submit_ts,
  job_ref                          -- dispatched job OR satisfying live unit (§7.3)
)

tripwire_estimates(
  engagement, host, kind,          -- requests-window | auth-attempts | ... (per-engagement, §8.3)
  lower NUMERIC, upper NUMERIC, window_seconds INT,
  provenance TEXT, updated TEXT
)

-- emissions ledger schema: §10 (+ agent_id, engagement, provenance, retro-correction marks)
```

```python
@dataclass
class BudgetVector:
    requests: int = 0
    packets:  int = 0
    auth:     int = 0
    bytes:    int = 0
    def covers(self, other: "BudgetVector") -> bool: ...
    def debit(self, other: "BudgetVector") -> "BudgetVector": ...  # cascade handled by caller walking leaf→root

class BudgetNode:
    phase: Phase           # HOLD | NORMAL
    remaining: BudgetVector
    def preflight(self, decl: BudgetVector) -> Admission: ...   # ADMIT | ENQUEUE | REJECT
    def refill_tick(self, now) -> None: ...                     # mode-aware accrual

class Operator:
    async def tick(self) -> None:      # jittered cadence; drains per-node queues; obeys controller pacing
        ...                            # FRONT DOOR: L0 → scope → fleet request_unit → debit → posture

class Controller:
    async def observe(self, e: Emission) -> None:   # state transitions, hysteresis
    def pacing(self, dims) -> Pacing                # consumed by posture layer

def release_reserve(token: ReserveToken) -> None:    # approval-gated; funds pinned to token dims/tag
```

## Appendix B — estimator & actuator cheatsheet

| Tool | Debits mostly | L0 estimator | Actuator |
|---|---|---|---|
| nmap | packets | port count × hosts × scan-type packet math (+ script weight) | params shaping: `-T`, scan-type, port-range choice; credit-line for scripts |
| masscan | packets | rate × duration (the knob IS the declaration) | `--rate`; bandwidth caps |
| ffuf/ZAP-class | requests | wordlist size × payloads; ZAP = credit line | budget token → internal rate limiter; pause/kill via twins |
| kerbrute-class | auth (principal dim) | attempts × principals | counter-dimension rotation, spray-vs-brute shape |
| implant/C2 | bytes + sessions | planned beacon volume | sleep+jitter, kill-chain spike discipline, scheduled dwell |
| exfil | bytes | staged size | RES_EXIT partition, channel choice, flow-asymmetry shaping |
| web_session (session_get/post) | requests + bytes (redirect hops) | one-hop default; cred-kwarg + endpoint rules → auth dim (§4.4) | helper-stamped `auth_event` + outcome class; hop metering in-helper |
| hydra-class | auth (principal dim) | attempts × principals | counter-dimension rotation; fleet auth-adjacent exclusion carries |
| ZAP spider | requests (open-ended) | credit line at spider start | credit token → internal metering; outcomes surface at poll |
| sqlmap fleet | requests | per-unit rate × duration | `traffic.log` aggregator = free L1; fleet unit release reconciles the draw |
| msfvenom | — (offline compute) | n/a — zero debits | n/a (delivery via `session_upload` debits there) |

---

*End of doc. v0.2 — red pen + SQLite-tier/fleet-boundary/principal discussions folded. Build gate lifts per phase order.*
