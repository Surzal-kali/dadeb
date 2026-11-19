# Packetcraft Lane — CAP_NET_RAW via systemd AmbientCapabilities

Written 2026-11-18, after `daharness doctor packetcraft` reported down from
the operator shell (uid 1000, no `SOCK_RAW`). The scapy sniff/send craft
family executes **in-process** — file capabilities on a binary don't apply,
unlike the masscan lane (which you can fix with `setcap cap_net_raw+ep` on
the masscan binary). The only honest fix is granting the capability to the
systemd units that host the lanes.

## The one-liner

```bash
sudo mkdir -p /etc/systemd/system/daharness.service.d /etc/systemd/system/daharness-kernel.service.d && printf '[Service]\nAmbientCapabilities=CAP_NET_RAW\n' | sudo tee /etc/systemd/system/daharness.service.d/cap_net_raw.conf /etc/systemd/system/daharness-kernel.service.d/cap_net_raw.conf >/dev/null && sudo systemctl daemon-reload && sudo systemctl restart daharness daharness-kernel
```

What it does:

1. Creates drop-in dirs for the two units that host tool lanes:
   `daharness.service` (Brain/gateway — where most dispatches land) and
   `daharness-kernel.service` (`tool_repl.py --kernel`).
2. Writes one identical drop-in to each: `[Service] AmbientCapabilities=CAP_NET_RAW`.
3. `daemon-reload` picks up the drop-ins; the restart re-execs the services
   with the ambient capability set.

`AmbientCapabilities` is the right knob because the services run as
`User=daharness` (non-root, uid 118): ambient caps survive the uid switch
and land in the *permitted + effective + inheritable* sets of the process,
so plain `socket(AF_PACKET, SOCK_RAW, ...)` calls from scapy succeed
without root and without file caps on the interpreter (never setcap the
Python interpreter — that hands raw sockets to every python program on the
box).

## Verify the grant materialized

Ambient capabilities show up in `/proc/<pid>/status` as `CapAmb`. Bit 13
(`0x2000`) is `CAP_NET_RAW`, so a granted process's CapEff/CapAmb ends in
`...2000`:

```bash
for u in daharness daharness-kernel; do
  k=$(systemctl show $u -p MainPID --value)
  printf '%s (pid %s): ' "$u" "$k"
  grep -E 'CapEff|CapAmb' /proc/$k/status 2>/dev/null \
    || echo '(unit inactive — see the restart-dance gotcha below)'
done
```

The restart bounces ZAP and the MSF RPC connector briefly (children of the
main unit) — give them a few seconds before the first dispatch. And watch
the kernel lane: it can end up quietly dead after a restart dance (see
below).

## Doctor semantics after the fix

- `daharness doctor packetcraft` **from your shell lane will still say
  down** — that's truthful: your uid-1000 shell can't create raw sockets,
  and the probe grades the lane it runs from. Don't "fix" this by setcap'ing
  things; the service lanes are the lanes that matter.
- The systemd lanes are now ungraded-clean. Confirm by dispatching a
  packetcraft tool through the framework (Brain or kernel) — the provider
  should come up on that lane.
- Same pattern applies to the other raw-socket provider: **masscan** can go
  either way. The doctor's masscan remediation (`sudo setcap
  cap_net_raw+ep $(which masscan)`) works because masscan is a binary; use
  whichever grant matches the lane that actually runs scans. If you grant
  via systemd instead, add `CAP_NET_RAW` covers it — the drop-in above also
  serves the masscan lane when scans launch in-process through the services.

## Why the bounding set is left alone

The drop-in sets only `AmbientCapabilities` — `CapabilityBoundingSet` stays
untouched (full inherited bounding from the default). Consequences worth
keeping in mind:

- Setcap'd binaries (Kali's nmap, if you ever setcap it) keep working — the
  bounding set would otherwise strip their file caps at exec time.
- No `NoNewPrivileges` interactions to worry about: ambient caps are the
  mechanism designed exactly for "non-root unit needs one capability".

If you later want a tighter posture, the doctor's full text suggests:

```ini
[Service]
AmbientCapabilities=CAP_NET_RAW CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_NET_ADMIN
```

…bounding only, so setcap'd binaries' exec-time caps still apply within the
bound. Not required for packetcraft; noted for posture upgrades.

## Restart-dance gotcha — the kernel lane can go quietly dead (hit 2026-11-18)

After the first real restart dance (`daemon-reload` + restarts of both
units), this was the observed state:

- `daharness.service` (Brain/gateway): restarted 21:16:01 with
  `CapInh/CapPrm/CapEff/CapAmb = 0000000000002000` — grant verified live.
- `daharness-kernel.service`: got SIGTERM at 21:15:48 and **stayed dead**.
  The unit's policy is `Restart=on-failure`, which only revives *failed*
  exits — a clean SIGTERM stop doesn't count, so nothing relaunched it.

Why that matters beyond a missing service: when the kernel lane is
unreachable, the framework's lanes **silently fall back in-process** (the
`user_authoring.md` failure mode) — a packetcraft dispatch then executes in
*whatever lane called it* (the operator shell, uid 1000, no caps) and fails
with EPERM even though the drop-ins are correct.

Revive + verify:

```bash
sudo systemctl start daharness-kernel && sleep 2 \
  && k=$(systemctl show daharness-kernel -p MainPID --value) \
  && echo "kernel pid: $k" && grep -E 'CapInh|CapPrm|CapEff|CapAmb' /proc/$k/status
```

A fresh-start CapEff ending in `...2000` proves the drop-in applied.

Second trap the same afternoon: the **CLI doctor grades its own lane
in-process** — `daharness doctor packetcraft` reads `os.geteuid()` and
sockprobes the doctor process itself, so from the operator shell it reports
uid 1000 / down **forever**, regardless of the drop-ins. To get a verdict
from a capped lane, run the doctor inside a capability context:

```bash
sudo systemd-run --pipe --wait --uid=daharness \
  --property=AmbientCapabilities=CAP_NET_RAW \
  /usr/bin/daharness doctor packetcraft
```

…or just dispatch a packetcraft tool through the framework and watch for a
clean envelope instead of an EPERM one.

## Lane matrix (as of 2026-11-18, corrected after the restart dance)

| Lane | Runs as | Raw sockets after one-liner |
|---|---|---|
| Operator shell (`daharness doctor`) | uid 1000 (`surzal`) | still down — probe is lane-honest |
| `daharness.service` (Brain/gateway) | user `daharness` | **up** (CapAmb bit 13 set) |
| `daharness-kernel.service` (tool kernel) | user `daharness` | **up once started** — silently dead after the restart dance; see gotcha above |

Related lane-honesty context: the r2ghidra provider had the same shape (see
2026-11-18 session notes — plugin lived under `~/.local/share/radare2/plugins`,
HOME-dependent; the service lanes needed the plugin symlinked into the
HOME-independent `R2_LIBR_PLUGINS=/usr/local/lib/radare2/6.2.1`).
