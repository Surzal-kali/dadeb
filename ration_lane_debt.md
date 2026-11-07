# Budget/ration lane — known debt & handoff (2026-11-06)

Status: **unit suite fully green (613 tests) and the drum-steady law is the
code/mirror default; the LIVE user workflow is one pkg4 build + install +
live verification wave away.** Everything in §2 is done — do not redo it.
Everything below the drum law section (§4-§7) is the remaining work,
ordered by how badly it blocks the user.

Authoritative product spec (verbatim user scenario):
> "i log in, i launch lab, i queue all my little recon checklist tool uses,
> go grab a cup of coffee, and the queue slowly drains. i check in, i see
> what the tool info coming back is, and i do other work outside of it
> manually, to satisfy curiosity on any new info that comes up."

That is the spec. Every judgment call below should be checked against it.

---

## 1. Current live state (so next session doesn't re-investigate)

- `budget.db` (`/var/lib/daharness/run/budget/budget.db`): 109 items
  `cancelled` (operator bulk-stop + phantom-plan cancels), 17 `finished`
  (all pseudo-finishes from the pre-fix drain bug — none launched), **0
  queued**. All plans `cancelled`/`finished`. No live work in flight.
- Nodes: all `normal`, `remaining_requests ≈ 60.29` (drip accruing).
- Deb package `daharness 0.2.0+pkg3` built 2026-11-06 ~20:04 and running
  (service booted 20:04:20). Dev tree at
  `/home/kali/github/systempackage/daharness` contains all session fixes.
  **pkg3 was built mid-session; the next build must be made AFTER verifying
  §2.5 (explicit-locals rewrite) or the deb will ship an unverified lane.**
- The user's results from today: **gone, unrecoverably.** Details in §6.1.
- Kill switch that exists today: `BUDGET_ENABLED=0` in
  `/etc/daharness/daharness.env` + service restart → lane fully inert.
  This was offered and the user explicitly rejected it as a bandaid. Don't
  offer it again as the fix; it's the operator's emergency lever only.

---

## 2. FIXED this session (all tested — do not redo)

| # | Symptom | Root cause | Fix + tests |
|---|---------|-----------|-------------|
| 2.1 | After reboot, `run_ffuf` returned `duplicate` forever | Dead jobs never observed (JobStore lazy; deb daemon builds no store at boot) → fleet `sweep_stale` reclaimed only on verified `exit_code` | `JobStore.observe()` (public cross-lane liveness stamp): `utils/job_store.py`, wired into `sweep_stale`'s job-backed branch: `utils/fleet_scheduler.py`. Tests: `tests/test_fleet_scheduler.py::test_sweep_reclaims_unstamped_dead_job_after_observer_restart`, `::test_sweep_leaves_running_job_unstamped_by_observe` |
| 2.2 | Every drain chunk preflight-rejected ("unknown argument: chunk_slice") | Chunk lane mints `chunk_slice`; tool declared `chunk_size` | Param renamed in `payloads/ffuf.py` (`chunk_size` → `chunk_slice`). Invariant test: `tests/test_wordlist_chunk.py::test_chunk_lane_keys_declared_on_tool_manifest` |
| 2.3 | Drain consumed preflight rejects as done ("mach 1" empty drain) | Reject envelope has `status="Rejected"` — matched neither budget checks nor the Failed seam → fell to `finished: True` | `replkit/operator_cli.py::_budget_drain_dispatcher` maps Rejected → Failed seam. Tests: `tests/test_ration_b.py::test_preflight_rejected_envelope_propagates_not_finished`, `::test_preflight_rejected_inner_envelope_propagates` |
| 2.4 | Chunk routing permanently disarmed in the Brain | Estimator registry seeded only in `RationEngine.__init__`; every consult site checked engagement BEFORE constructing the engine (Brain never constructs it). "Process lottery" fingerprint: worked in operator lanes, dead in Brain | Seed-at-use: `ensure_seed_estimators()` at top of `_estimator_engaged()` + `resolve_declaration()` (`utils/ration.py`). Cold-process repro now: engaged=True. Doctrine in repo memory |
| 2.5 | Drain loop `still_short` forever (the math) — TWO stacked faults | (a) HOLD accrual used the floor only (2/epoch) vs 600/chunk → `600 = 2/h × ∞`; (b) **short debits burned the drip**: the node UPDATE ran before the deficit check, so each failed attempt wrote balance=0 and stamped `last_refill=now`, destroying exactly the grant that was accumulating | `utils/ration_store.py::_accrue`: held nodes accrue at `max(floor[d], refill[d])`. `debit_vector`: short path persists the PROJECTED grant (balance + `last_refill`) and charges nothing; commit path consumes it. Verified tick-by-tick: balance climbs 100→600, admits at tick 6. Tests: `tests/test_ration_a.py::TestHoldMode::test_hold_accrues_at_refill_drip_not_floor`, `::test_hold_backlog_drain_eventually_admits_ceiling_chunk`, cascade-atomicity test rewritten for grant persistence |

Doctrine recorded (repo memory, daharness-notes.md): seed lazy registries
at the point of use; accrual is a projection until a debit commits — persist
earned grants on failure, charge only on commit; trace a node row across
ticks before calling a "stuck" queue a wedge.

---

## 2A. The drum-steady law (2026-11-06, user-decided — do not quietly revert)

The user picked the tempo profile in an explicit decision: **drum-steady** —
the queue drains as a rhythmic heartbeat, not a burst-and-starve. The law is
the NO-ENV code default (constants in `utils/ration.py` + `utils/budget_drain.py`),
mirrored in `packaging/reference/budget.constitution.yaml`:

```
epoch_seconds:            300   (was 3600)
requests: ceiling 600, refill_per_epoch 150 (was 100), floor 2
release_jitter:  {min: 1.5, max: 6.0} s   (new; authored band)
BUDGET_DRAIN_INTERVAL_S: 30    (was 60 — three literals in budget_drain.py)
BUDGET_DRAIN_BATCH:      2     (was 8 — _DRAIN_BATCH_DEFAULT in ration.py)
```

- **Math**: 150/5 min ≈ 1800 req/h ⇒ a full 4614-line wordlist drains in
  ≈ 2.5 h (the old law's ≈ 40 h is dead). Inter-release gaps jitter 1.5–6 s
  inside each tick, so launches leave in a drumbeat, not a volley.
- **Authored-band self-lift** (`operator_tick`): band delay =
  `min(min + U(0, max-min)/pacing, max(release_cap, authored max))` — the
  env `BUDGET_RELEASE_JITTER_CAP_S=2.0` on the deb CANNOT crush an authored
  6.0 band; the band in the constitution governs. A live deb needs no cap
  change.
- **Zero-band decline** (`{min: 0.0, max: 0.0}` authored = DECLINE):
  `operator_tick` falls back to env pacing (base U(0, BUDGET_RELEASE_JITTER_S
  default 2.0), cap 2.0) — the documented operator opt-out and what every
  multi-dispatch test fixture uses. A band ABSENT from an authoring file
  does NOT decline (keeps the code default band); `release_jitter: null`
  does not decline either (`_parse_release_jitter` → None).
- The mirror carries `release_jitter` as a **commented example block** in the
  OPTIONAL region (the yaml-fidelity test restores commented examples and
  diffs them against the loader schema; an uncommented row would fail the
  "required keys ⊆ restored doc" assertion). The LAW lives in code.
- Tests: `tests/test_ration_a.py` (law values + band/decline semantics),
  fixtures in b/c/d/e/f1 + wordlist_chunk set the decline inline
  (`BUDGET_CONSTITUTION` json inline) so multi-dispatch ticks don't really
  sleep 1.5–6 s.

---

## 3. UNRESOLVED from this session (verify BEFORE building on top)

These were identified at the end of the session and are **not** covered by
the green tests above:

1. **Phantom-plan re-mint mechanism — fixed in code + behaviorally tested;
   LIVE repro still owed.** The explicit-locals rewrite in `run_ffuf`
   kills the `chunk_plan` mint for keyed dispatches at the source, and both
   §3.1 behavioral body tests pass in-process (`test_run_ffuf_chunk_keyed_
   body_launches_slice` proves a keyed dispatch launches the slice — no
   `chunk_plan` at the mint boundary; the bogus-plan path errors honestly).
   **Remaining: the same UDS repro against the pkg4 deb Brain** (connect
   `/run/daharness/brain.sock`, `CALL_TOOL|3|payloads.ffuf.run_ffuf|{args
   with chunk_plan_id...}`) — expect LAUNCH/duplicate/requeued, not
   `chunk_plan`.
2. **Dispatcher consumes `chunk_plan` envelopes as done — fixed.** The
   daemon dispatcher (`utils/budget_drain.py:_budget_drain_dispatcher`)
   detects `chunk_plan`/`plan_id` envelopes at both nested and bare levels,
   requeues the item and does NOT count it finished; unknown envelopes fail
   visibly. Covered by the file's dispatcher tests.
3. **pkg3 shipped mid-session — pkg4 build still owed** (this is now the
   ONLY §3 item): land the deb AFTER the live-wave checklist below, restart
   the service, then run the live repro (§3.1) + §5.1 sanity +
   enqueue-vs-.107 drum watch.

---

## 4. P0 — result capture & visibility ("I will never know the results")

This is the user's deepest complaint and it is real, structural, and
unrelated to budget math. Items 2 and 3 are DONE (see below); 1 and 4
remain the open debt (1 = cancel-loss honesty; 4 = caps surfacing):

1. **Killed ffuf loses everything.** `ffuf -o` JSON is written only on
   clean exit (ffuf 1.1.0). Today's one real run (job `19bec7e6b363`) was
   cancelled → log contains only "Caught keyboard interrupt (Ctrl-C)" →
   **zero results preserved, forever.** The default wordlist run (`-s`
   silent mode) prints no table lines either, so the log has nothing to
   parse. Options to evaluate: drop `-s` so partial table lines exist;
   periodic `-o` snapshot (not supported by ffuf 1.1.0 — check 2.x);
   document "cancel = results lost" honestly in the envelope.
2. **`ffuf_out_*.json` lands in `/tmp` — DONE.** `payloads/ffuf.py` now
   writes `-o` under `<workspace>/run/jobs/ffuf/` (workspace-resolved, with
   a harmless `BG_JOB_LOG_DIR` fallback). Covered by the chunk behavioral
   test's `-o` path assertion.
3. **Who aggregates chunk results? DONE.** `ration_store.plan_verdicts`
   persists terminal chunk verdicts (poll-time parser output) and
   `budget_queue_status(plan_id=...)` renders a per-chunk rollup with
   findings samples long after job logs/TTL age out (`utils/ration.py`
   §4-rollup lens, 2026-11-06).
4. **Finished-cap/TTL silently deletes evidence.** "went to release all the
   jobs... they were in fact gone" — `_enforce_caps` (finished cap 128/agent,
   `BG_JOB_MAX_FINISHED_PER_AGENT`) + `BG_JOB_TTL_HOURS` 24h delete job rows,
   log GC (48h) deletes files. By design for growth-bounding, but for the
   user it read as results vanishing. At minimum: the drain/plan twins
   should harvest verdicts into the plan record BEFORE rows age out, and
   the caps should be surfaced in `budget_status`/doctor.

## 5. P1 — the pacemaker (drain loop) & the default posture

1. **No drain loop exists — RESOLVED 2026-11-06.** `utils/budget_drain.py`
   is the pacemaker: bootstrap `launch_all()` autostarts it
   (`BUDGET_DRAIN_AUTOSTART`, default on), ticks every
   `BUDGET_DRAIN_INTERVAL_S` (code default 30) draining
   `BUDGET_DRAIN_BATCH` (code default 2) per tick, respects
   `manual_phase hold` (operator stop wins), and the state file
   `run/budget/drain_state.json` + `framework_doctor(provider=
   "budget_drain")` expose last-tick ts / backlog / admitted-deferred
   counts. The dispatcher mapping lives in the daemon (single place;
   replkit still reuses its own for the manual `budget drain` command).
2. **Defaults are wrong for the primary environment — RESOLVED BY USER
   DECISION 2026-11-06.** The lane stays ON-by-default, but the default
   posture is now the drum-steady lab profile (§2A): gentle numbers, the
   queue is a metronome, not a straitjacket. `BUDGET_ENABLED=0` remains
   the operator's emergency lever only. The old "default OFF with opt-in"
   option was not taken; the kill switch stays an emergency lever and
   must never be offered again as the fix.
3. **The math must survive the checklist — RESOLVED by §2A.** Drum-steady:
   refill 150/300 s ⇒ ~1800 req/h ⇒ a full 4614-line wordlist in ≈ 2.5 h,
   inter-release gaps 1.5–6 s. The "spends everything on payday, then
   starves" profile is retired; the shipped numbers ARE the lab profile.

## 6. P2 — semantics + copy

1. **Cancel doesn't reconcile the plan/queue ledger**: `ffuf_cancel` on a
   chunk's job doesn't mark its queue item or adjust budget; the item shows
   one state, the job another. (Still open.)
2. **`held_pending` copy** — §5.1 now exists (the daemon pacemaker), so the
   "the drain re-reads your request every tick" claim is TRUE on the deb;
   only the manual-REPL-only lane (bootstrap without the budget daemon) can
   still say it falsely. Copied copy row: DONE as of pkg4's law.
3. **Batch pacing honesty — RESOLVED by §2A + §3.2.**: still_short verdicts
   are budget-state, not launches (dispatcher requeues, launches nothing),
   and real launches pace via the drum band (1.5–6 s) + the 30 s/2 batch
   cadence; the env-pacing fallback only applies on explicit decline.
   Verified in the release-loop tests (band branch + env branch +
   no-gap branch).
4. `ffuf_payload`'s `options` as a JSON-encoded string (user habit from
   notebooks: `options={"wordlist": ...}` — a dict passed where the tool
   wants a flag string) is accepted by preflight coercion in some lanes and
   silently dropped in others — normalize once, in preflight, not per-lane.

---

## 7. The math, spelled out (why today's checklist cannot complete)

RETIRED by §2A (kept for the record — this WAS the old law):

```
requests:   ceiling 600, refill_per_epoch 100, floor 2, max_single 600
epoch_seconds: 3600
```

- Fresh node = burst ceiling 600. First chunk (600) commits → node at 0.
- Normal accrual: drip is pro-rata, capped at 1 epoch of grant per touch
  (BUDGET_ACCRUE_TICK_EPOCHS), recomputed from the STORED balance — with
  grant persistence (§2.5b) the balance now climbs 100/epoch → full
  ceiling back after ~6 epochs (6h). Under HOLD (self-held backlog):
  max(floor=2, drip=100) → same 100/epoch.
- 8-chunk wordlist ⇒ ≈48h end-to-end. With the pre-fix grant-burning the
  projection reset every failed drain ⇒ **never**. Both are wrong for the
  spec; §5.3 must fix the numbers, §5.1 the motion.

---

## 8. Evidence trail (paths that mattered today)

- Fleet ledger: `/var/lib/daharness/run/fleet/fleet.db` (`fleet_units`;
  cross-actor visible; group-rw).
- Job store: `/var/lib/daharness/run/jobs/jobs.db` + logs
  `run/jobs/<tool>/` — **root-owned 700 via the deb lane; kali cannot read
  directly. Probe through the gateway** (`/tools/execute` + `X-API-Key`
  from `/etc/daharness/daharness.env`, e.g. `ffuf_status`).
- Budget store: `/var/lib/daharness/run/budget/budget.db` (readable).
- Brain log: `/tmp/brain.log` (shared, group daharness; euid fallback
  `/tmp/brain-<uid>.log` — the deb Brain currently writes the shared one).
- Dispatch journal (Postgres cobweb):
  `psql -h 127.0.0.1 -p 5433 -U repl_lane -d harness` (password from
  `/etc/daharness/pg.env`, `HARNESS_DB_PASSWORD_REPL`),
  `SELECT ... FROM journal.entries WHERE tool_id LIKE 'payloads.ffuf%'`.
  `result_digest` is a 6-leaf scalar walk — budget-stamp-only digests mean
  "the inner envelope carried no other top-level scalars"; don't over-read.
- The decisive repro snippets (Brain UDS CALL_TOOL dispatch; the
  result_digest candidate-matching) are in the session history; if lost,
  they're 15 lines to rebuild — the UDS framing is 4-byte big-endian
  length-prefixed, `CALL_TOOL|<session-int>|<tool_id>|<args_json>`.

## 9. Test inventory (how to validate next session)

```
cd /home/kali/github/systempackage/daharness
python -m pytest tests/ -q        # full suite: 613 passed (2026-11-06)
# ration-lane baseline, if you want the focused 9:
python -m pytest tests/test_ration_a.py tests/test_ration_b.py \
  tests/test_ration_c.py tests/test_ration_d.py tests/test_ration_e.py \
  tests/test_ration_f1_hold_gate.py tests/test_wordlist_chunk.py \
  tests/test_concurrency.py tests/test_fleet_scheduler.py -q
```

Status at session close: FULL suite 613 green (three consecutive loaded
runs), including the newly hardened stub-timing tests — the suite went from
"flaky in full-run order" to green: `test_sqlmap_fleet` fanout now holds
its h4 slot with a 6 s stub (was 0.2 s — sweep_stale released it mid-loop
under load), `test_job_store` TTL test observes terminal under DEFAULT ttl,
and `test_worker_queue` promotion accepts all three lifecycle states of a
completed one-winner claim. If a wall-clock test flakes again: it is
stub-timing vs suite load, NOT lane logic — widen the window, don't rerun
until green.

## 10. Suggested order of attack for next session

1-6 are DONE (code + tests, see §2, §2A, §3, §5.1/2/3, §4 partial). What
remains, in order:

A. **pkg6 — the drip fix (2026-11-06 drum-starvation, root-caused
   2026-11-07)**: the .107 drum watch (plan wp-0a2807697f96, 8×600-line
   chunks) launched ZERO ffuf jobs in ~1h12m of ticks with a STALL stamp —
   not a law bug, a *plumbing* bug. `admit_vector` is contractually
   read-only, so a starved item's `budget_deferred`/enqueue verdict never
   reaches `debit_vector`'s short-branch grant persistence: the
   accrued-but-unspent refill (hold refill = max(floor, refill) = 150
   req/epoch) was recomputed from the same stale stored balance and
   THROWN AWAY every 30 s tick, while the pre-2026-11-06 `drip commit`
   fix lived only on the unreachable debit path. Fix: a new
   `RationStore.drip_due_nodes(items, epoch_s, now)` walks the due
   batch's nodes, computes the one-epoch-capped accrual, and PERSISTS it
   (remaining + `last_refill`, single write per node per tick) — hooked
   into `operator_tick` after `due_items`, before the dispatch loop, and
   surfaced as `"drip"` in the drained result. The one operator writer
   stays the only mutating lane; model-lane preflights stay read-only.
   Law unchanged: 40 ticks × 15 req funds a 600-line chunk in ~20 min.
   Tests: `test_drain_drip_persists_refill_starved_chunk_launches`
   (zeroed node → 150/300/450 persisted, launch at tick 3) +
   `test_drip_commit_no_double_grant_within_touch` (same-`now` second
   touch grants nothing) in `tests/test_budget_drain_loop.py`;
   `tests/test_ration_b.py`'s restart-resume test updated to the new
   contract (restart never resurrects — the *tick's* writer may grant
   ≤1 lazy epoch). Full suite 619 green.
B. **Stale vector registry on the live box (chore, not code)**: the
   gateway-lane manifests still declare `chunk_size` for run_ffuf —
   preflight rejects every keyed chunk dispatch (the 2026-11-06
   rename-to-`chunk_slice` incident, source fixed at c2edf8a 16:27).
   The deb's postinst does NOT index and bootstrap doesn't either; run
   `sudo daharness-index` after installing pkg6, then restart the
   service. The drain lane (replkit `discover_tools`) is always fresh
   from source, so this only bites registry-manifest lanes (REST /
   MCP / find_best_tool).
C. **Live drum watch, re-run on .107**: enqueue → expect first chunk
   launch within ~20 min of install (40 ticks × 15 req), one chunk per
   ~20 min thereafter, inter-release jitter per the authored band. Note
   honestly: the §6.1 release jitter needs ≥2 affordable launches in one
   tick to fire — with one starved chunk it stays quiet; that is the
   math, not a bug. The 3 "open credit-line draws" in budget_status are
   plan-mint emissions (packets=None, no job) parked in hold; the hold
   TTL sweep exists — cosmetic. Doctor `backlog 6` vs queue `queued=8`
   is a drain-eligibility counting difference — cosmetic.
0. **pkg5 live-crash fix (2026-11-06 22:04 incident)**: the deb service
   lane reads `/etc/daharness/daharness.env` via a systemd EnvironmentFile,
   which keeps inline `# …` comments inside the value; an operator
   uncommenting the packaged `#BUDGET_DRAIN_BATCH=2   # items per tick`
   row crashed the drain loop on `_env_float` before tick one. The
   helpers now strip a trailing `#` comment (residue-blank → unset, so an
   operator's cleared value is a default, not an error; `false # off` is
   honestly false now; garbage `abc#def` still raises) — regression tests
   in `tests/test_budget_drain_loop.py`, shipped in pkg5. Install pkg5 and
   the live file's uncommented rows parse as authored.
1. **pkg4 deb build** DONE as pkg4 (built + installed 22:02-22:04); see
   item 0 for the pkg5 follower (same build + install + service restart).
2. **Live /etc/daharness/budget.yaml overwrite** with the drum-steady law
   (epoch 300, refill 150, band {1.5, 6.0}; keep other dims at shipped
   values) — the constitution is read per-call, no restart needed for it.
3. **§3.1 UDS repro against the live deb Brain** — expect
   LAUNCH/duplicate/requeued for keyed args, never `chunk_plan`.
4. **Drum watch**: enqueue an ffuf plan on 192.168.56.107; confirm the
   30 s ticks drain it 1-2/tick with 1.5-6 s inter-release gaps; rollup
   arrives via `budget_queue_status(plan_id=...)`; scope arming via the
   gateway (kali cannot read /var/lib directly).
5. Only after 1-4: the original deferred topic — a daemon-side anything,
   and how the whole flow composes hands-off (queue → coffee → verdicts).
