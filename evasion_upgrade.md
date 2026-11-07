# BUDGET × WORDLIST TRAFFIC — GAP MAP + DESIGN SKETCH

Status: DESIGN-STAGE, reviewed 2026-11-06 (operator folds marked DECIDED).
Nothing below is wire today except what's marked [WIRE]. Anchored to dadeb
dev/wip @ 33edb33 (evasion_design.md §7/§13/§15, utils/ration.py ~:493-531
registry, ~:602-635 seeds, ~:1360-1440 metering, ~:1790-1836 envelope;
utils/ration_store.py enqueue_item/queued_position/bind_item).
Author note: drafted after the 2026-11-06 queue-position +
held_pending-honesty patch; review folds (2026-11-06) resolved the
wrapper-vs-fleet interplay, lazy minting, and re-lettered §3 off the
completed §15 phase ladder. Do not treat "proposed" items as shipped.

## 0. WHY THIS EXISTS (the one-paragraph thesis)

Wordlist-shaped traffic (ffuf, hydra, web_login_brute, dirb-class; MSF
CLI modules) fails the allocation economy in one of two ways today:

- If declared TRUTHFULLY (5M-line wordlist vs 600-request epoch
  ceiling), the never-fit guard rejects it forever. Nothing ever runs.
- If declared as open-ended (the REGISTERED-credit_line lanes today:
  masscan/sqlmap estimators, all-None dims, basis="credit_line"), it
  admits NOW and draws uncontained at whatever rate the tool decides
  — metered after the fact at L1 reconcile, but never paced, never
  split, never pausable mid-run. (ffuf/hydra are NOT in this class —
  their seed estimator keys are stale, see 1.1.)

The design premise: chunked-cycles is the third way. The wordlist job
is re-modelled as N bounded dispatches, each individually allocatable,
delivered by the engine's existing deferred queue and drained across
epoch refills. "Never allocate" becomes "allocate per chunk" — fit by
construction instead of fit-by-lie (credit_line) or fit-never (reject).

## 1. VERIFIED GAPS (each: today's wire → gap → owner altitude)

1.1 UNREGISTERED LANES FLY BLIND
  [WIRE] §13 rule: unregistered tools carry zero traffic semantics,
  gate returns None, dispatch un-metered.
  Affected today: metasploit CLI (minted as
  payloads.metasploiting.MetasploitClient.dispatch_metasploit —
  no estimator; user-correct), payloads/ffuf.py + payloads/hydra.py
  (seed estimator keys are STALE — registered as auxiliaries.ffuf.*/ 
  auxiliaries.hydra.* but the tools mint from payloads/; they resolve
  "unregistered" and fly blind, review-verified; user-correct),
  auxiliaries/web_login_brute (in-tree, unregistered — user-correct),
  anything customs registers later.
  NOTE: registering the WRONG (stale) keys is also a blind-flying
  bug — the registry matches exact minted tool_ids.
  Owner altitude: ENGINE — one estimator registry entry per lane,
  keyed by the MINTED id.
  This is the cheapest, highest-leverage closure. Do first.

1.2 CREDIT_LINE IS ADMIT-UNCONTAINED
  [WIRE] the registered open-ended lanes (masscan, sqlmap; seeds at
  ration.py:620-635) return {d: None for d in DIMS}; preflight admits
  (ration.py:464 comment: "credit-line mode: always admit, L1 true-up
  fixes later").
  Gap: no pre-count, no pacing, no mid-run ceiling. A 10M-line ffuf
  (currently UNREGISTERED — 1.1) runs at full blast; meter_draw
  reports exhaustion AFTER it happens ("exhausted mid-flight"
  warning, ration.py:1401).
  Owner altitude: ENGINE (estimator upgrade) + WRAPPER (wordlist
  parsing/pagination flags).

1.3 MID-FLIGHT CONTAINMENT IS DESIGN-STAGE
  [WIRE] ration.py:1402 comment says "non-resumable crawls end;
  resumables pause via twins" — INTENDED behavior, no wrapper on the
  wire carries pause/resume semantics today (ffuf/hydra greps empty).
  Tools run to completion or operator-kills them.
  Owner altitude: WRAPPER — reduced by the chunk lane (§2): per-chunk
  resume IS slice-file replay at offset, which the chunk deliverer
  provides for free (chunk_meta.offset/slice_size). Upstream reality
  (review-verified): ffuf has NO offset-resume flag; hydra -R
  (restore-file replay) exists but is moot once chunks are slices.
  Residual WRAPPER value: in-chunk pause for honest single-shot
  fits (§7.1 "resumables pause") — parked behind the chunk lane.

1.4 NO CHUNKED-CYCLE DELIVERY MODEL
  [WIRE] deferred queue exists (enqueue_item, operator_tick drain,
  bind_item→job_ref grounding, queued_position visibility).
  Gap: nothing mints N bounded queue items from one wordlist job.
  Credit_line dodges the problem; reject punishes honesty; chunk
  delivery is the missing third path.
  Owner altitude: ENGINE (a "wordlist chunk" queue item shape) +
  WRAPPER (slice wordlist into per-cycle segments, one dispatch per).

## 2. DESIGN SKETCH: CHUNKED-CYCLE VIA THE DEFERRED QUEUE

Principle: the queue IS the multi-cycle mechanism. Each chunk is an
ordinary deferred item with honest per-chunk dims; operator_tick drains
across epochs; queued_position shows the model where each chunk stands;
bind_item gives each chunk's launch a job_ref for grounding; discharge
binds actuals per chunk job. Those surfaces exist [WIRE]; the new
shapes are the MINTER (§2.2, lazy frontier + plan column), the poll
lens (§2.3), and ONE drain branch (§2.5, requeued — the fleet
interplay the original sketch missed).

2.1 CHUNK ITEM SHAPE (proposed; lazy frontier minting DECIDED 2026-11-06)
  queue_items gains a real `parent_plan_id` column + index (a
  23K-row notes_json LIKE scan per poll does not stay sane — the
  parent lens must be O(index), and notes_json stays free for its
  existing status notes). Chunk identity rides chunk_meta:
    chunk_meta = { plan_id, total_chunks, chunk_index, wordlist_path,
                   offset, slice_size }
  Mints are WINDOWS, not totals: the minter enqueues only the next
  W = min(total_chunks, per-plan window, default ~drain batch)
  chunks; each finished-chunk observation (drain finished branch, or
  budget_queue_status's advance sweep) mints the next absent index.
  A 5M-14M-line list at max_single 600 = 8,333–23,333 chunks — eager
  minting of totals was rejected (TTL sweeps, row churn, poll cost).
  enqueue_item's ttl_hours is scaled to the plan's expected duration;
  the plan envelope states expected tick count + plan TTL honestly.
  Slices materialize at DISPATCH time (offset/limit in chunk_meta →
  the wrapper cuts the slice file then), never at mint time — N full
  copies of a rockyou-sized list is a disk bomb, and mint-time files
  outlive the queue rows' honesty.
  Drain order stays priority DESC, requested ASC — chunk i inherits
  parent priority; in-chunk FIFO is stamped explicitly
  (enqueue_item(now=now + i*epsilon)) — ties on requested are
  otherwise unspecified under that ORDER BY.

2.2 MINTER CONTRACT (proposed; formula corrected 2026-11-06)
  A run_ffuf-style wrapper, given a wordlist + constitution:
    - wc -l the wordlist (estimation basis, seeds tripwire)
    - NEVER-FIT SLICE SIZE = min(max_single[d]) across the lane's
      BINDING dims — NOT the burst ceiling. Review-verified: never-fit
      is governed by max_single_call (validate() caps ms ≤ ceiling but
      authored ms < ceiling rejects full-chunk declarations → the
      whole plan dead on arrival). ffuf-family: requests. Hydra-
      family (web_login_brute included): auth_events is BINDING
      (1:1 attempt→auth_event, auth max_single/ceiling=60 vs requests
      600 — a 600-request hydra chunk is never-fit by auth). The plan
      envelope quotes the binding dim + resulting chunk count.
    - chunk declared vectors are honest per family: ffuf =
      {requests: slice, bytes/packets/auth: None(open, L1-metered)};
      hydra-class = {requests: slice, auth_events: slice, bytes: None}.
    - GUARD: the chunk lane owns the wordlist flag — `-w`/`-L`/`-P`
      inside the free-text options string is detected and REFUSED
      (multi-list args fork the plan silently).
    - lazy frontier minting (§2.1), return ONE aggregate envelope:
      plan_id + total_chunks + first qid + window size + expected
      tick count + "chunks drain across operator ticks; poll
      budget_queue_status(plan_id=)"
  Model sees ONE call; economy sees bounded per-chunk debits. The
  never-fit guard becomes per-chunk (each chunk must individually
  fit) — which is the honest allocation the current design never had
  for this traffic class.

2.3 PARENT JOB GROUNDING (proposed)
  budget_queue_status gains a parent_plan_id lens (§2.1: real column
  + index, not a notes filter): one poll returns the plan's chunk
  states + per-index progress, so the model's "enqueued then nothing
  to poll" fear stays closed at plan granularity, not just per-qid.
  The existing terminal-lane allowlist already covers
  utils.ration.* (review-verified) — polls survive tool-budget
  exhaustion. The default limit-20 page is fine for PLAN lenses.
  Who mints the next window: the drain's finished-chunk branch and
  the status lane's advance sweep (ENGINE-side machinery), never a
  model call (§8.2).

2.4 TRUE-UP ALREADY FITS [WIRE]
  Each chunk is an ordinary debit; L1 reconcile + meter_draw lifecycle
  apply per chunk, unchanged. Exhausted-mid-flight per chunk means
  that chunk's tool must end — the chunk delivery itself (next
  dispatch at chunk_meta.offset across a fresh slice file) is the
  resume, no wrapper hook needed. The two features close each
  other's loop.

2.5 DRAIN CONTRACT — CHUNKS VS THE FLEET (DECIDED 2026-11-06:
  work with TODAY'S drain; no fleet-key extension)
  The chunk lane rides launch_job(target=...) → fleet request_unit.
  Review-verified today's drain verdict behavior for the two
  non-launch verdicts (utils/background_job.py launch envelope,
  replkit/operator_cli.py:440-476 _dispatch, executor exception
  conversion):
  - fleet DUPLICATE returns {status:"duplicate", job_id:<sibling>}.
    Canonical keys are shape-keyed (tool:host:path:param-NAMES hash)
    — every chunk of one plan is IDENTICAL under it. Today's drain
    maps inner job_id → bind_item → the slice is bound to the
    sibling's job and NEVER RUNS (§7.3 "duplicate = satisfied" was
    decided for other lanes; it silently thins chunk plans).
  - fleet REFUSED (slots_exhausted | host_serialized_auth — both
    TRANSIENT) returns {status:"refused"} with NO job_id → today's
    drain falls through to {"finished": True} — the slice is
    consumed as DONE without running.
  - A tool-body raise CANNOT fix this: the executor converts
    tool-body exceptions to Failed envelopes (executor.py:188-192),
    which the drain also maps to finished. BudgetStillShort raised
    in-body never reaches the drain.
  CHUNK LANE CONTRACT (the one mechanism):
  - The wordlist wrapper, on EITHER fleet verdict at chunk dispatch,
    returns a REQUEUED envelope: status STAYS "duplicate"/"refused"
    (executor's ration_discharge keys exactly on those — the
    debit compensates per non-launch, review-verified, net-zero)
    plus {requeued: true, requeue_reason, unit_key,
    sibling_job_id} — the sibling id is named sibling_job_id so
    NOTHING binds it to this item (no job_id key anywhere
    _find_job_id can match).
  - The drain _dispatch gains ONE branch: requeued → DECISION
    "requeued", record it, keep the item queued — no finish, no
    bind. Next tick re-dispatches; when the sibling's job is done,
    request_unit acquires the freed slot and the slice launches.
    That IS "append the queue when its sibling finishes".
  - Cost model: a requeued chunk re-runs admit → debit → compensate
    per re-observation (ledger churn, honest stamps; no net spend).
  - Serialization is also the PACING answer: two concurrent slices
    of one plan = 2× the epoch draw against the host; fleet slots
    (default 2) would allow it, chunks must not overlap.
  SCALE HONESTY: chunk-sized appetite (batch, windows, tick counts)
  is THEORY until a live lab measures fleet-scale behavior; the
  rhythm-validation wave (§3 U3) owns that evidence. Basic fuzzing
  would stall under the current never-fit/credit-line impl — that
  stall is the concrete motivation for this lane.

2.6 BOUNDED FAILURE EXIT + DEAD-PLAN SETTLE (DECIDED 2026-11-06,
  SHIPPED): the drain's dispatch_failed branch used to keep the
  item queued forever ("item survives for the next tick") with the
  error only in the engine's own log — a deterministic failure
  (ScopeGateError on a deblocked host, tool misconfig, bad
  transport) wedged a 24h plan silently: every tick spent the batch
  on chunk slots that could never run, and budget_queue_status
  showed a healthy-looking queued line with no why. Fixed at THREE
  layers, all under the honest-retry principle (transient hiccups
  keep a real retry budget; permanent failures exit with their
  story):
  - BOUNDED LEDGER (utils/ration_store.py): queue_items gains an
    attempts column (schema + migration, default 0). Every
    dispatch_failed tick stamps attempts+1 AND rewrites notes_json
    with the last error — a queued-but-broken row is readable in
    the lens on tick 1, not only at exit. Past BUDGET_RETRY_MAX
    (default 3, 0 = fail on first raise) the item EXITS as status
    'failed' with "retry budget exhausted (n attempts; max m) —
    last error: ..." on the row. store gains cancel_item→bool,
    fail_item, stamp_attempt.
  - FAILED-ENVELOPE MAPPING (utils/ration.py operator_tick): run_tool
    wraps raised tool-body errors as {"status": "Failed"} envelopes
    instead of raising, so lanes that don't map exceptions consumed
    such items as inline successes (finish_item) — a second silent
    wedge shape. operator_tick now reads out["status"] directly:
    Failed → attempt-stamp + same bounded fate (decisions
    "tool_failed" then "failed_exhausted"); a raise maps to
    "dispatch_failed" then same. No per-lane dispatcher changes
    needed — the engine is the single chokepoint.
  - DEAD-PLAN SETTLE (utils/wordlist_chunking.py advance_plans): a
    plan whose whole frontier is minted and whose minted chunks are
    ALL terminal-without-completion (cancelled/failed) settles
    state='failed' with the terminal chunk's note surfaced in
    advance's result + the budget_queue_status plan lens (no
    eternally-open plan with nothing left to drain or mint). A plan
    with un-minted frontier chunks stays open (operator
    partial-cancels must still lazily mint successors).
  Evidence base: trashcan.ipynb 2026-11-06 session — 16 ffuf
  chunks against an un-scoped host waited 42 min with zero
  dispatch feedback; the model lane had no surface ("just
  erroring without any tell why").

## 3. SEQUENCING — UPGRADE WAVES (re-lettered 2026-11-06; the A–D
   menu collided with evasion_design.md §15's phase ladder, whose
   A–D are BUILT and E — the emissions-ledger differential harness —
   remains open pending live-lab evidence. These are upgrade WAVES
   over the shipped ladder, not new phases.)

  U1. ESTIMATOR KEYS + COVERAGE — ✅ IMPLEMENTED (2026-11-06).
      fix the STALE registrations
      (auxiliaries.ffuf.*/auxiliaries.hydra.* → payloads.ffuf.*/ 
      payloads.hydra.*, minted-id truth per 1.1), register
      web_login_brute + the msf method id (payloads.metasploiting.
      MetasploitClient.dispatch_metasploit). Open-ended None dims
      for ALL of them — a fabricated requests-per-module guess
      over-claims (§4.2 seeds err OPEN: "under-keying beats
      over-claiming"); registration alone ends 1.1 blind flying by
      putting the lanes into metering + the L1 lifecycle.
      Smallest diff, biggest honesty delta. Zero behavior risk:
      registered+open admits exactly as credit-line does today
      (it IS credit-line semantics, now with the machinery engaged).
  U2. CHUNKED-CYCLE LANE — ✅ IMPLEMENTED (2026-11-06; ffuf lane, wordlist
      declarations only — hydra/web_login_brute/MSF stay open-ended and
      whole-run: chunk adoption per lane is a follow-up wave).
      §2 sketch, WITH the wordlist-aware
      declaration folded in (the old "B first" sequencing is
      REJECTED: wordlist-aware ffuf/hydra declarations before the
      chunk lane exist would turn ≥max_single lists from
      always-admit into permanent reject with NO alternative —
      ffuf+rockyou simply stops working; honesty arrives with the
      lane that makes honesty survivable). Deliverables: chunk
      item shape (§2.1), minter (§2.2), parent lens (§2.3),
      drain requeued-branch (§2.5), options wordlist-guard,
      bounded failure exit + dead-plan settle (§2.6).
      Where: utils/wordlist_chunking.py (lane_decision/mint/advance/
      requeue/dead-plan settle), utils/ration_store.py (queue_plans +
      chunk columns, enqueue_item shape, attempts ledger/fail_item/
      stamp_attempt), utils/ration.py (U1 seeds, discharge
      requeued/chunk_plan branches, drain advance hook, plan lens,
      drain Failed-envelope mapping + retry budget), payloads/ffuf.py
      (single/plan/chunk wrapper). Knobs: BUDGET_PLAN_WINDOW
      (default 8), BUDGET_WORDLIST_CHUNK (default on),
      BUDGET_PLAN_TTL_HOURS (default 24),
      BUDGET_RETRY_MAX (default 3; 0 = fail on first raise).
  U3. LIVE-LAB VALIDATION — run a real fleet-scale plan, measure
      rhythm (tick cadence, refill interaction, requeued churn),
      feed the numbers back into defaults + the §15-E differential
      harness. Chunk appetite leaves theory here. No new code
      unless measurement says so.

## 4. HARD CONSTRAINTS (do not violate while building)

- §13 stays: internal/budget tools never mint. Estimators only for
  traffic-sending lanes, keyed by MINTED tool_ids (a wrong key is
  silently-dead registration — 1.1).
- Model lane stays READ-ONLY (§8.2). Chunking is wrapper-initiated;
  the model may see but never mint chunks directly; window
  advancement is engine-side (drain/status sweeps), never a
  model-callable mint.
- Never-fit semantics stay intact for honest single-shot requests —
  chunking is opt-in per tool lane, not a global escape hatch from
  reject. Wordlist-aware single-shot declarations that exceed
  max_single reject EXACTLY as before; the chunk lane is the
  honest alternative, not a raised ceiling.
- duplicate=satisfied (§7.3, other lanes) is NOT redefined. The
  chunk lane adds requeued as its own decision; requeued envelopes
  NEVER bind a sibling's job_id and NEVER consume their item.
- Envelope honesty carries over: chunk parent envelopes must state
  chunk counts + poll surface + expected tick count + plan TTL
  (same class as the held_pending NOT-queued fix, 0e2b687).
- Scope gate unchanged: chunked traffic still passes the gate per
  dispatch; budget never substitutes for authorization.
- Executor discharge contract is load-bearing for requeued chunks:
  preserve top-level status ("duplicate"/"refused") so
  ration_discharge compensates; assert no bindable job_id on the
  requeued copy.

Hand-picked verification anchors for when this lane reopens:
  utils/ration.py    :493-531 (register_estimator + fallback chain)
  utils/ration.py    :602-635 (current estimator bodies — STALE ffuf/
                      hydra keys live here, fix via U1)
  utils/ration.py    :160-238 (dim + max_single defaults; validate's
                      never-fit material)
  utils/ration.py    :1018-1120 (preflight decision surface incl.
                      held_pending + satisfied)
  utils/ration.py    :1360-1440 (L1 true-up + meter_draw + exhaustion)
  utils/ration.py    :1790-1880 (_budget_envelope + position clause)
  utils/ration.py    :2124+ (ration_discharge — status=="duplicate"/
                      "refused" compensation contract, _find_job_id)
  utils/ration_store.py :668+ enqueue_item | :734 queued_position |
                      bind_item (0e2b687)
  utils/background_job.py :186-224 (fleet verdict launch envelopes)
  daharness/executor.py  :188-192 (tool-body exception conversion —
                      why requeued is a RESULT, not a raise)
  replkit/operator_cli.py :406 (drain batch default) | :440-476
                      (_budget_drain_dispatcher — the one new branch)
  utils/tool_budget.py :43 (terminal allowlist incl. utils.ration.)
  evasion_design.md  §7.3 (duplicate=satisfied, drain invariants),
                      §15 (phase ladder A–D built, E open)

## 10. pkg7 — THE DRUM'S WIRE LEG (the shape change, 2026-11-07)

[WIRE] pkg6 fixed funding; pkg7 fixes SHAPE. Two changes, same law, same
throughput:

1. **Minter slices to the epoch budget, not the burst ceiling**
   (`utils/wordlist_chunking.py`): the never-fit plan's chunk size was
   "largest n under max_single" — a 600-request burst — while the
   ledger refilled exactly one epoch per chunk. Result: a funded chunk
   emptied at ffuf's own wire speed (default ~40 workers, seconds for
   600 requests), then minutes of dead air while refill caught up; the
   only visible log line in the window was `budget_short`. The plan
   branch now also folds in `refill_per_epoch` (min over dims,
   clamped ≥ 1, via the new `epoch_funding()`) and shrinks the slice
   whenever the epoch fund is tighter. A slice == one epoch's funding ⇒
   beat #1 fires on the very first tick (cold nodes project full
   ceiling in admit) and every later beat funds in its own epoch.

2. **Chunk launches are paced on the wire**
   (`payloads/ffuf.py:_inject_wire_pacing`): a dispatched chunk carries
   `-t 1 -rate N` with `N = max(1, floor(slice/epoch_s))` — the slice
   spreads across its funding epoch instead of bursting. Caller- and
   scan-config-provided `-t`/`-rate` win per-flag (the helper checks
   before injecting; the scan-config lane sees the injected rate and
   stands down). The envelope reports `wire_pacing` and the chunk_plan
   envelope reports `paced`. Unreadable law ⇒ pacing returns None and
   the launch stays exactly as before pkg7 (no guessed rates).

   Honest limit: ffuf's `-rate` is an integer req/s — a law slower than
   1 req/epoch-second still gets 1/s (the wire floor); per-epoch
   *funding* remains the drum's real governor, and `-t 1` keeps the
   stream from bypassing the rate.

Zero behavior change off the chunk lane: single (fits-in-one) calls are
never paced. `binding_dim`/windows/discharge semantics unchanged; the
slice numbers in older fixtures moved (600 → 150 under code defaults
because requests refill 150 < ceiling 600 binds).

Wire-shaping generalization note: this is ONE tool of ~200. The seam is
written so a tool's chunk body can adopt `_inject_wire_pacing` (rate =
slice/epoch) plus the same minter call — but every other vector-mapped
tool body must be wired individually before it is shaped. Nothing else
inherits pacing implicitly.
