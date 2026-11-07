# Budget/ration lane — known debt & handoff (2026-11-06)

Status: **session ends with unit tests green but the LIVE user workflow still
broken.** This doc is the handoff for the next session. Everything in
§3 is fixed and tested — do not re-litigate it. Everything in §4-§7 is the
actual remaining work, ordered by how badly it blocks the user.

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

## 3. UNRESOLVED from this session (verify BEFORE building on top)

These were identified at the end of the session and are **not** covered by
the green tests above:

1. **Phantom-plan re-mint mechanism — partially mitigated, not verified.**
   Observed live: fleet-duplicate retries of chunk dispatches minted fresh
   `wp-` plans with zero traffic (24 ghost items across `wp-b6e3a6054692`,
   `wp-62d9954b5b3a`, `wp-8d9aff23487a`). The decisive repro (dispatch
   chunk-keyed args through the live Brain socket) returned a `chunk_plan`
   envelope — i.e. `lane_decision` decided PLAN mode for a KEYED dispatch
   even with the dict-comp `_lane_args` fix in the shipped tree. The
   explicit-locals rewrite in `run_ffuf` (§4 below) is the attempt to fix
   this; **it has never been verified against the live Brain.** Repro to
   use: the UDS dispatch snippet from the session (connect
   `/run/daharness/brain.sock`, `CALL_TOOL|3|payloads.ffuf.run_ffuf|{args
   with chunk_plan_id...}`), expect a LAUNCH/duplicate/requeued envelope —
   a `chunk_plan` envelope for keyed args = still broken.
2. **Dispatcher still consumes `chunk_plan` envelopes as done.**
   `_budget_drain_dispatcher` maps budget_deferred/refused, `requeued`,
   `job_id`, and Failed/Rejected — a `chunk_plan` envelope (no `job_id`,
   no `requeued`, `status="chunk_plan"`) falls through to
   `{"finished": True}` → queue item consumed + phantom plan minted. Fix:
   handle `chunk_plan` explicitly (requeue the item, do NOT treat the
   plan-issue as finished work) and/or add a safety default: an envelope
   that maps to NOTHING must not be `finished` — fail visibly instead.
   Test does not exist yet.
3. **pkg3 shipped mid-session.** The running deb includes §2.1-2.3 + the
   dict-comp `ffuf` but NOT: the explicit-locals rewrite, the HOLD/grant
   fixes in `ration_store.py`, the updated tests. Next deb build must land
   after 1+2 above are green, and the service restarted.

---

## 4. P0 — result capture & visibility ("I will never know the results")

This is the user's deepest complaint and it is real, structural, and
unrelated to budget math:

1. **Killed ffuf loses everything.** `ffuf -o` JSON is written only on
   clean exit (ffuf 1.1.0). Today's one real run (job `19bec7e6b363`) was
   cancelled → log contains only "Caught keyboard interrupt (Ctrl-C)" →
   **zero results preserved, forever.** The default wordlist run (`-s`
   silent mode) prints no table lines either, so the log has nothing to
   parse. Options to evaluate: drop `-s` so partial table lines exist;
   periodic `-o` snapshot (not supported by ffuf 1.1.0 — check 2.x);
   document "cancel = results lost" honestly in the envelope.
2. **`ffuf_out_*.json` lands in `/tmp`** (`payloads/ffuf.py` line ~576,
   `BG_JOB_LOG_DIR` default "/tmp"). Violates the doctrine "logs live under
   run/jobs — never /tmp": lost on reboot, outside the job store, not
   collected by the log GC. Fix: key it to the job's log dir.
3. **Who aggregates chunk results?** Each chunk's findings arrive via
   `ffuf_status(job_id)` per chunk job, but nothing rolls chunk verdicts up
   to the PLAN. After a plan finishes, the user gets `budget_queue_status`
   counts (queued/finished numbers) — not findings. Needed: a plan-level
   results rollup (per-chunk exit codes + consolidated findings list, from
   the jobs' `-o` files / verdicts) surfaced on `budget_queue_status` and a
   `plan_results`-style twin.
4. **Finished-cap/TTL silently deletes evidence.** "went to release all the
   jobs... they were in fact gone" — `_enforce_caps` (finished cap 128/agent,
   `BG_JOB_MAX_FINISHED_PER_AGENT`) + `BG_JOB_TTL_HOURS` 24h delete job rows,
   log GC (48h) deletes files. By design for growth-bounding, but for the
   user it read as results vanishing. At minimum: the drain/plan twins
   should harvest verdicts into the plan record BEFORE rows age out, and
   the caps should be surfaced in `budget_status`/doctor.

## 5. P1 — the pacemaker (drain loop) & the default posture

1. **No drain loop exists.** `operator_tick` is called from exactly TWO
   places: the manual `budget drain` REPL command and tests. `held_pending`
   envelopes instruct the model to poll "the operator tick" that never
   fires on its own. The coffee-loop spec is unbuildable until a daemon
   drain exists. Sketch (agreed in session): a task in
   `bootstrap.py::launch_all()` next to Brain/ZAP/gateway; every
   `BUDGET_DRAIN_INTERVAL_S` (default ~60) run
   `engine.operator_tick(dispatch=_budget_drain_dispatcher(discover_tools()))`
   + `advance_plans`; respect `manual_phase hold` (operator stop wins over
   the loop); expose last-tick ts / backlog / admitted-deferred counts via
   `framework_doctor(provider="budget_drain")` and `framework_health`.
   The dispatcher mapping must live in ONE place (move it out of replkit if
   the daemon needs it — currently the mapping lives in
   `replkit/operator_cli.py`).
2. **Defaults are wrong for the primary environment.** `DEFAULT_ENABLED =
   True` (hard-coded, `utils/ration.py`) rations BY DEFAULT, while the box
   is an HTB lab where the RoE constraint the lane exists for doesn't
   apply. The user experienced this as "kneecapped the framework." Options
   (pick deliberately, this is a policy decision): default OFF with a
   loud first-run opt-in; or keep ON but ship a LAB-profile constitution
   as the deb default. Do NOT just flip `BUDGET_ENABLED=0` and declare
   victory — the user rejected exactly that.
3. **The math must survive the checklist.** Today: ceiling 600, drip
   100/epoch (3600s), wordlist 4614 lines → 8 chunks of 600 → first chunk
   debits the whole ceiling, then ~5 epochs (≈5h) to refill per chunk →
   **≈40h for one ffuf run.** That is the "spends everything on payday,
   then starves" experience. Whatever profile ships must make a
   full-wordlist run complete on the order of minutes-to-an-hour in a lab.

## 6. P2 — semantics + copy

1. **Cancel doesn't reconcile the plan/queue ledger**: `ffuf_cancel` on a
   chunk's job doesn't mark its queue item or adjust budget; the item shows
   one state, the job another.
2. **`held_pending` copy lies by omission** — "the drain re-reads your
   request every tick" is false until §5.1 exists. Reword to state who
   actually runs the tick.
3. **Batch pacing honesty**: still_short results skip the inter-release
   jitter (only real launches sleep), so a manual drain of failures fires
   at keystroke speed ("mach 1") — fine once §2.3's cause is fixed, but
   verify real launches pace under throttle before trusting the tick.
4. `ffuf_payload`'s `options` as a JSON-encoded string (user habit from
   notebooks: `options={"wordlist": ...}` — a dict passed where the tool
   wants a flag string) is accepted by preflight coercion in some lanes and
   silently dropped in others — normalize once, in preflight, not per-lane.

---

## 7. The math, spelled out (why today's checklist cannot complete)

Constitution defaults (`/etc/daharness/budget.yaml`, mirrors code defaults):

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
python -m pytest tests/test_ration_a.py tests/test_ration_b.py \
  tests/test_ration_c.py tests/test_ration_d.py tests/test_ration_e.py \
  tests/test_ration_f1_hold_gate.py tests/test_wordlist_chunk.py \
  tests/test_concurrency.py tests/test_fleet_scheduler.py -q
```

Run them to files when the terminal's output pipelining flakes
(`> /tmp/x.log 2>&1; tail -1`). Status at session close: ration_a (66,
incl. the two new HOLD tests) and concurrency green; b/c/d/e/f1 +
wordlist_chunk + fleet were green BEFORE the §2.5 store edits — re-run
them first thing next session before anything else.

## 10. Suggested order of attack for next session

1. Re-run §9 suites (baseline).
2. Verify/repair §3.1 (phantom mint) with the UDS repro against a live
   Brain built from current dev tree.
3. Fix §3.2 (dispatcher chunk_plan consumption) + test.
4. §5.1 drain loop (the pacemaker) + §3.3 deb rebuild + service restart.
5. §4 result capture (ffuf -o location, cancel-loss honesty, plan rollup).
6. §5.2/5.3 defaults + lab-profile constitution (policy decision with the
   user — do not unilaterally flip the kill switch).
7. Only after 1-6: the original deferred topic — a daemon-side anything,
   and re-examine how today's five fixes compose in the hands-off flow
   end-to-end (queue → coffee → verdicts).
