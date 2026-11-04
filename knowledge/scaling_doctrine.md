# Scaling Doctrine: Tools, Pipelines, and Where Concurrency Lives

A doctrine for "which tools can take several requests at once" and how to build
scalable orchestration around any of them. Tool-agnostic by design; the sqlmap
fleet design (Annex A) is the first adapter, not the centerpiece.

## 0. The axis that matters

Do not sort tools by speed. Sort by what a *unit of work* is and what
state it carries:

1. **Per-request overhead** — cost of one unit of work (CPU, memory, setup).
2. **Internal parallelism** — can one instance spread units across cores?
3. **State architecture** — are units independent events, or a serialized
   stream through shared state?

Tools that scale hardest refuse to accumulate state per unit. Tools that
cannot scale share state across units in ways threading cannot fix. Memory
(accumulated state) is the wall long before CPU.

## 1. The five architectures

| Architecture | Meaning | Examples | Scaling behavior |
|---|---|---|---|
| A. Stateless-per-request | Each unit is an independent event | ffuf, gobuster, masscan, Turbo Intruder | Embarrassingly parallel. Bounded by target + host policy only |
| B. Session-serial state | Units are a live conversation; ordered inference depends on sequencing | sqlmap per TARGET, anything with ordered oracle logic | Threading = correctness violation. Scale = partition by target, never by request |
| C. Singleton shared store | One process owns mutation of job/session state | Metasploit (job store, msfrpc thin threading), hashcat on one GPU | Process-per-piece (different targets, different devices). Partition the work |
| D. Big-bang invocation | Unit of work = "load and analyze everything" | jadx (per-APK), radare2 (per-binary), Burp Scanner (per-app in one JVM) | Parallel across PROCESSES, never across requests. Wants a queue |
| E. Rate-governed streams | Same as A but paced | nmap, nikto, ZAP | Scales with policy knobs, not threads; the tool has its own pacing |

## 2. Tool verdict table (current fleet)

| Tool | Arch | Per-target scale | Across targets/processes | Notes |
|---|---|---|---|---|
| ffuf/gobuster/dirb/ferox | A | excellent | excellent, trivially | Goroutines; stateless |
| masscan | A | absurd (raw SYN, no handshake) | yes | Needs root/caps; firehose results |
| nmap | E | good with timing knobs | yes (targets are independent) | Default profiles are polite by design |
| wafw00f whatweb nikto | E | good | yes | Single-flight is simplicity, not a limit |
| sqlmap | B | excellent internally; strictly serial | partition by target only | See Annex A — session state per OUTPUT-DIR |
| metasploit | C | one-flight per job | partition by module job; single RPC store | Job store singleton; fine as 1 driver per job |
| hydra | A/C | excellent internally (-t) | yes, per-target | Parallel at both axes |
| hashcat | C | GPU-exclusive; serial queue 1 device | cross-DEVICE only (-d), or distributed | Never 2 instances on one GPU; CPU-side often net-negative |
| searchsploit | none | N/A (indexed) | trivially | Not a request tool |
| jadx | D | parallel WITHIN one APK (-j) | heavy per-invocation; queue, don't stack | Memory is the cap once several run |
| radare2/rizin | D | poor (analysis per process) | batch/one-shot scripting | rz-pipe for pipelines |
| Burp (Pro) | D | throttled pools; ~10 conc. scans machine-class | horizontal = Enterprise (other product) | JVM memory is the ceiling; Turbo Intruder exists to bypass this |

## 3. Doctrine rules

1. **Never parallelize a serialized computation.** (Arch B) If the tool's
   logic depends on the ordering of prior responses, concurrency is a
   correctness violation, not an optimization. Fork by TARGET partition.
2. **Partition at the widest independent axis.** Targets > endpoints >
   params > requests, in that order of safety. Per-target isolation first.
3. **Scheduling scales via subprocesses, not threads.** The orchestrator
   spawns one process per unit-of-serial-state (per sqlmap target, one MSF
   job), with process-group IDs (pgid) for surgical kill. Never `pkill`
   a tool globally — one operator's stop must not kill another lane.
4. **The lock table is the coherence primitive.** `key -> {pgid, slot,
   status, log}` in the scratch store. Dedupe on the SAME canonical key
   convention as findings. Advisory locks: TTL + crash-stale reclaim, but
   the dedupe key is authoritative even after crash-restart.
5. **Per-instance persistent state stays isolated.** (Arch B/D) One output
   directory (or session DB) per unit — crash-restart resume is then
   trivially per-unit. Bulk state wipes (`--purge`-class) are FORBIDDEN in
   any fleet path; per-unit removal only.
6. **Slot limits are host policy, not global caps.** Scaling unit =
   concurrent PROCESSES per target host (default 2, ceiling 4; raising =
   explicit flag + warning, never silent). Host policy table = the courtesy
   contract: total pressure = slots x tool-internal threads.
7. **Auth-adjacent targets serialize.** Paths likely sharing a session
   (auth/api/user paths, same Set-Cookie) belong to ONE slot per host in
   sequence, even under default-2 policy. v1 = regex class list from scope
   notes; token-similarity bucketing later.
8. **Aggregation dedupes; findings cite artifacts.** Tail per-unit logs,
   dedupe on canonical key, and every finding line cites the per-unit log
   + traffic capture as evidence. Severity maps from what the finding IS,
   not from which tool found it.
9. **The adapter never edits tool internals.** Scalable pipeline = process
   orchestration + aggregation around a stock binary. Wrappers pass
   through upstream capability (auth/CSRF passthrough) rather than owning
   it. Override-colliding knobs in the passthrough = error, never
   silent-merge (reserved-arg guard).

## 4. The adapter interface

A "scalable adapter" for any tool under this doctrine has 6 pieces:

  (a) **Key function** — canonical dedupe key for units (host, path,
      params, body-shape — bodies carry per-run CSRF/nonce values, so key
      on the SHAPE not the raw bytes).
  (b) **Lock table** — key -> {pgid, slot, started, log_path, status}.
  (c) **Slot scheduler** — per-host slot policy + serialization classes.
  (d) **Launcher** — subprocess with pgid, per-unit isolated state dir,
      log path, tool-internal concurrency knobs from the policy table.
  (e) **Aggregator** — log/structured tail -> deduped, normalized results.
  (f) **Job surface** — the existing fire-and-poll twins family:
      `run_*_fleet(...) -> job_id`, `*_fleet_status(jid)`,
      `*_fleet_results(jid, dedupe=...)`, `*_fleet_stop(jid)`.

The scheduler itself (b/c/d) is ONE shared module (`fleet_scheduler`);
each tool contributes (a)(e) plus its policy table. New tool => write the
key function + aggregator + policy, mount in scheduler. No tool code is
copied between adapters.

## 5. Follow-on adapters (in rough order of payoff)

- **ffuf/gobuster multi-host**: same skeleton; per-host concurrency policy
  shared with sqlmap; trivial (Arch A) — proves the scheduler generalizes.
- **Metasploit module-job farm**: driver = existing msfrpc surface; the
  singleton store means the scheduler serializes within msfrpc but
  parallelizes across independent msfrpc instances if ever needed. Not
  urgent (nobody runs MSF concurrently today).
- **hashcat device-pool queue**: partition by device (-d) and instance
  (--session); scheduler owns an explicit GPU-residency table (mirrors VRAM
  time-share doctrine).
- **jadx/burp class**: QUEUE with a bounded process count (memory wall);
  scheduler = simple bounded worker pool, no per-host nuance.

## 6. The Rust wedge (where compute eventually goes)

None of this is the Rust core's job — orchestration is IO-bound text
plumbing. Where Rust eventually helps, per the rewrite-verdict lane:

  1. **Tamper-payload prescreen** for Arch B tools: generate-and-filter
     payload mutations against parser heuristics BEFORE the serial lane
     burns wall-clock on them (narrower inference per target). Most likely
     hot loop; measured by target, not bench.
  2. **Log correlation/grepping** across big per-unit logs (regex crate,
     linear-time, ReDoS-immune) — only if aggregation shows measurable cost.
  3. **key-function hashing** at fleet scale — only if unit counts get big.

Gate: differential parity old-vs-new for each wedge, measured on targets.

## Annex A — sqlmap fleet (first adapter)

Anchor point: existing `payloads/sqlmap.py` surface on dev/wip
(`run_sqlmap` / `sqlmap_status`, per-job meta sidecar + disk
reconstruction). Fleet mode mounts ABOVE that unit: scheduler forks one
per-target lane; each lane is a `run_sqlmap`-class unit keyed on the
canonical key. Verified sqlmap mechanics this design leans on (from
sqlmap wiki/Usage):

- `--threads=THREADS` — "Max number of concurrent HTTP(s) requests
  (default 1)". sqlmap is internally parallel-capable; default 1 is the
  serial-conversation norm. Policy: time-based inference => 1 threads
  (parallel char bisection turns the delay into noise on the oracle);
  error/union classes may rise to <=3 per host policy.
- `-m BULKFILE` — "Scan multiple targets given in a textual file"; sqlmap
  itself would walk them ONE BY ONE. Fleet mode is the scheduler that
  gives that walk concurrency, instead of using -m.
- `--output-dir=OUTPUT-DIR` — "sqlmap automatically creates a persistent
  session SQLite file for each target, inside dedicated output directory."
  Per-target dir == session isolation == resume per unit.
- `--flush-session` — "Flush session files for current target. This way
  you can avoid the caching mechanisms implemented by default." Re-test =
  per-unit operator override only, never a fleet-wide default.
- `--purge` — "Safely remove ALL content from sqlmap data directory."
  FORBIDDEN in fleet path (rule 5; targets the shared global data dir).
- `-t` — "Log HTTP(s) traffic to a textual file" per target = report
  evidence artifact.

Per-target launch line shape:

```
sqlmap -u <url> --batch --smart --output-dir=<fleet>/<key>/ \
  --threads=<class policy> --delay=<host policy> \
  --level=<class policy> --risk=<class policy> --tamper=<class set> \
  -t <dir>/traffic.log
```

Findings mapping (rule 8): per-target log lines carry technique tags +
affected params; `sqlmap_fleet_results(jid, dedupe=param|host)` returns
deduped `(host, param, technique, tamper-set, excerpt, log/traffic path)`
triples -> `report_finding` per unique triple.

What fleet mode DOES fix: throughput across targets (partition lanes).
What it does NOT fix: per-target wall-clock for blind inference — a
time-based oracle is a serial conversation no matter what; that's where
the tamper-prescreen wedge (section 6.1) narrows the work later.
