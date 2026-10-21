# Lab DNS — one hostname list for kali + containers

Shared lab hostname resolution across execution lanes (lab-environment
setup, not part of the deb; the reprovision script lives in
`packaging/reference/lab-dns-setup.sh`). Built 2026-10-17
after notebook-resolution-vs-kali divergence (e.g. `connected.htb` resolving
in one lane, NXDOMAIN in the other). Complements `knowledge/lanes.md`.

## Design

dnsmasq runs **on kali** and the notebook kernel's container uses it as its
DNS. kali's `/etc/hosts` is the single source of truth for lab names; nobody
bind-mounts it, so there is no inode/staleness class of bug at all.

```
kali                                          containers (workbench net)
└─ /etc/hosts  ◄── edited every HTB session      jupyter: dns: [172.28.0.1]
   └─ dnsmasq (inotify re-read)                  └─ Docker DNS keeps resolving
      listens: 127.0.0.1, 172.28.0.1                container names (chroma…)
                ▲                                  and forwards the rest here
                └──────────────────────────────────┘
```

- **Why `172.28.0.1`**: the pinned gateway of the container bridge used by
  the lab compose lane (reference script: `packaging/reference/lab-dns-setup.sh`
  — it picks and pins the subnet), so it survives
  docker/kali restarts. **Never bind `192.168.56.x`** — eth0 is VBox
  NAT/DHCP and churns per boot (and `.1` on that LAN is the VBox host, not
  kali).
- **Containers keep Docker's embedded resolver** for service names — a
  user-defined network's `127.0.0.11` stays authoritative and only forwards
  non-container names upstream to dnsmasq. Container names need no /etc/hosts.
- **Lane parity**: only target-touching execution surfaces get the `dns:`
  entry. Today that is the `jupyter` service (kernel lane). If another lane
  executes target traffic later, give it the same
  `dns:` — same rule as scope-gate coverage.

## Repo-managed pieces (survive reinstalls)

| Piece | File |
|---|---|
| Reprovision script (idempotent, sudo) | `packaging/reference/lab-dns-setup.sh` |
| Container DNS pin on the execution lane | your compose `dns:` entry (see the script) |
| This doc | `knowledge/lab-dns.md` |

Host-only state the script (re)creates on a fresh install:
`/etc/dnsmasq.d/lab.conf`, `/etc/systemd/system/dnsmasq.service.d/override.conf`
(`After=docker.service` + `Restart=on-failure`/`RestartSec=15` — see boot race
below), and `systemctl enable dnsmasq` (the unit ships `disabled`).

## Operational notes

- **HTB IP churn**: box restart → new IP → edit kali's `/etc/hosts` → dnsmasq
  re-reads automatically (inotify). Any editor works, including vim/`sed -i`
  (no mount to go stale). No container recreates, ever.
- **VPN**: no config change needed. dnsmasq's upstream is
  `/etc/resolv.conf` by default and re-reads on every change.
- **Lab names never leak upstream**: `local=/htb/` + `local=/lab.local/`
  (tunneled DNS is common on HTB; these names must resolve locally or not at
  all).
- **Scope gate untouched**: this is name-resolution parity, not a scope
  change — attribution and `check_scope` still see whatever names/IPs the
  tools were given.

## Verify

```bash
dig +short connected.htb @172.28.0.1        # kali side, must match /etc/hosts
# and inside the jupyter container:
python -c "import socket; print(socket.gethostbyname('connected.htb'))"
```

Troubleshooting: `journalctl -u dnsmasq` — the classic fresh-install failure
is a bind error on 172.28.0.1 because the bridge isn't up yet. **Ordering alone
does NOT fix this** (seen live 2026-10-17: dnsmasq failed at boot with
`Cannot assign requested address` on a host where the drop-in was installed):
the workbench bridge is created by `docker compose up -d`, not dockerd, so
`docker.service` reaches active with no bridge in existence and `After=` is
already satisfied. That's why the drop-in also carries `Restart=on-failure` +
`RestartSec=15` — dnsmasq retries until compose brings the bridge — and the
script itself waits up to `BRIDGE_WAIT_S` (default 30) for the gateway before
binding. Second classic is port 53 already taken (`ss -lntu 'sport = :53'`).

When dnsmasq is down, container-side symptom is total public-name resolution
failure (Docker's 127.0.0.11 forwards to 172.28.0.1, which is dead — e.g.
`Failed to resolve 'github.com'` in jupyter server logs), while kali itself
still resolves fine through its own upstream path. Lab names fail in BOTH
lanes' dnsmasq checks.