# BUDGET × WORDLIST TRAFFIC — GAP MAP + DESIGN SKETCH

Status: DESIGN-STAGE. Nothing below is wire today except what's marked
[WIRE]. Anchored to dadeb dev/wip @ 0e2b687 (evasion_design.md §7/§13,
utils/ration.py ~:602-635 registry, ~:1360-1440 metering, ~:1790-1836
envelope; utils/ration_store.py queued_position/bind_item).
Author note: this doc was drafted after the 2026-11-06 queue-position +
held_pending-honesty patch. Do not treat "proposed" items as shipped.

## 0. WHY THIS EXISTS (the one-paragraph thesis)

Wordlist-shaped traffic (ffuf, hydra, web_login_brute, dirb-class; MSF
CLI modules) fails the allocation economy in one of two ways today:

- If declared TRUTHFULLY (5M-line wordlist vs 600-request epoch
  ceiling), the never-fit guard rejects it forever. Nothing ever runs.
- If declared as credit_line (current ffuf/hydra/masscan/sqlmap
  estimators: all-None dims, basis="credit_line"), it admits NOW and
  draws uncontained at whatever rate the tool decides — metered after
  the fact at L1 reconcile, but never paced, never split, never
  pausable mid-run.

The design premise: chunked-cycles is the third way. The wordlist job
is re-modelled as N bounded dispatches, each individually allocatable,
delivered by the engine's existing deferred queue and drained across
epoch refills. "Never allocate" becomes "allocate per chunk" — fit by
construction instead of fit-by-lie (credit_line) or fit-never (reject).

## 1. VERIFIED GAPS (each: today's wire → gap → owner altitude)

1.1 UNREGISTERED LANES FLY BLIND
  [WIRE] §13 rule: unregistered tools carry zero traffic semantics,
  gate returns None, dispatch un-metered.
  Affected today: metasploit CLI (no estimator — user-correct), 
  auxiliaries/web_login_brute (in-tree, unregistered — user-correct),
  anything customs registers later.
  Owner altitude: ENGINE — one estimator registry entry per lane.
  This is the cheapest, highest-leverage closure. Do first.

1.2 CREDIT_LINE IS ADMIT-UNCONTAINED
  [WIRE] estimators at ration.py:620-635 return {d: None for d in
  DIMS}; preflight admits (ration.py:464 comment: "credit-line mode:
  always admit, L1 true-up fixes later").
  Gap: no pre-count, no pacing, no mid-run ceiling. A 10M-line ffuf
  runs at full blast; meter_draw reports exhaustion AFTER it happens
  ("exhausted mid-flight" warning, ration.py:1401).
  Owner altitude: ENGINE (estimator upgrade) + WRAPPER (wordlist
  parsing/pagination flags).

1.3 MID-FLIGHT CONTAINMENT IS DESIGN-STAGE
  [WIRE] ration.py:1402 comment says "non-resumable crawls end;
  resumables pause via twins" — INTENDED behavior, no wrapper on the
  wire carries pause/resume semantics today (ffuf/hydra greps empty).
  Tools run to completion or operator-kills them.
  Owner altitude: WRAPPER — resume hooks (ffuf: -of json + offset
  replay; hydra: -o restore file; dirb-class: position bookmarks).

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
binds actuals per chunk job. All four surfaces already exist — the new
shape is the MINTER, not the transport.

2.1 CHUNK ITEM SHAPE (proposed)
  queue_items row gains (or notes_json carries):
    chunk_meta = { total_chunks, chunk_index, wordlist_path, offset,
                   slice_size, parent_plan_id }
  Drain order stays priority DESC, requested ASC — chunk i inherits
  parent priority, requested stamps make in-chunk order FIFO.

2.2 MINTER CONTRACT (proposed, wrapper-altitude entry point)
  A run_ffuf-style wrapper, given a wordlist + constitution ceiling:
    - wc -l the wordlist (estimation basis, seeds tripwire)
    - slice into per-cycle budgets: ceil(lines / ceiling_requests)
      chunks, each declaring requests=slice_size truthfully
    - mint N queue items (existing enqueue_item), return ONE
      aggregate envelope: parent_plan_id + total_chunks + first qid
      + "chunks drain across operator ticks; poll
      budget_queue_status(parent_plan_id)"
  Model sees ONE call; economy sees N bounded debits. The never-fit
  guard becomes per-chunk (each chunk must individually fit) — which
  is the honest allocation the current design never had for this
  traffic class.

2.3 PARENT JOB GROUNDING (proposed)
  budget_queue_status gains (or keeps via notes filter) a
  parent_plan_id lens: one poll returns every chunk's state, so the
  model's "enqueued then nothing to poll" fear stays closed at plan
  granularity, not just per-qid.

2.4 TRUE-UP ALREADY FITS [WIRE]
  Each chunk is an ordinary debit; L1 reconcile + meter_draw lifecycle
  apply per chunk, unchanged. Exhausted-mid-flight per chunk means
  that chunk's tool must end — the wrapper's resume hook (1.3) picks
  up at offset for the NEXT chunk instead. The two features close
  each other's loop.

## 3. SEQUENCING MENU (cheapest-first, no pushing)

  A. ESTIMATOR COVERAGE WAVE — register web_login_brute + a bounded
     msf-class estimator skeleton (even count-of-dispatched-modules ×
     requests-per-module basis) → ends 1.1 blind flying. Smallest
     diff, biggest honesty delta. Customs tooling benefits same-day.
  B. WORDLIST-AWARE ESTIMATORS — ffuf/hydra read -w/-W flags, wc -l,
     declare estimation-basis (no longer credit_line) at dispatch;
     tripwire gets a real seed. Closes half of 1.2.
  C. CHUNKED-CYCLE MINTER — §2 sketch. Engine + wrapper work, real
     design effort, do AFTER A+B give the fleet honest vectors to
     chunk.
  D. RESUME HOOKS — wrapper -o/-restore/offset replay wiring; pairs
     with C's per-chunk exhaustion handoff. Can ship independently
     for plain ffuf/hydra before C.

## 4. HARD CONSTRAINTS (do not violate while building)

- §13 stays: internal/budget tools never mint. Estimators only for
  traffic-sending lanes.
- Model lane stays READ-ONLY (§8.2). Chunking is wrapper-initiated;
  the model may see but never mint chunks directly.
- Never-fit semantics stay intact for honest single-shot requests —
  chunking is opt-in per tool lane, not a global escape hatch from
  reject.
- Envelope honesty carries over: chunk parent envelopes must state
  chunk counts + poll surface (same class as the held_pending
  NOT-queued fix, 0e2b687).
- Scope gate unchanged: chunked traffic still passes the gate per
  dispatch; budget never substitutes for authorization.

Hand-picked verification anchors for when this lane reopens:
  utils/ration.py    :493-531 (register_estimator + fallback chain)
  utils/ration.py    :602-635 (current estimator bodies)
  utils/ration.py    :1018-1040 (preflight decision surface)
  utils/ration.py    :1360-1440 (L1 true-up + meter_draw + exhaustion)
  utils/ration.py    :1790-1836 (_budget_envelope + position clause)
  utils/ration_store.py :668+ enqueue_item | :734 bind_item |
                          queued_position (0e2b687)
  evasion_design.md  §7 (envelope truth), §13 (gate rules)
