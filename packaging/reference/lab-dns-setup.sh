#!/usr/bin/env bash
# =============================================================================
# Reprovision kali's lab-DNS lane (dnsmasq) — idempotent, safe to re-run.
#
# Purpose: make lab hostnames (e.g. connected.htb) resolve identically on kali
# AND inside the framework containers (notebook kernel lane). kali-side
# dnsmasq serves kali's own /etc/hosts; containers use it as their DNS.
#
# Writes (unconditionally — this script is the source of truth):
#   /etc/dnsmasq.d/lab.conf                        — the dnsmasq config
#   /etc/systemd/system/dnsmasq.service.d/override.conf — After=docker.service
#     + Restart=on-failure (the 172.28.0.1 bridge gateway only exists once
#     docker *compose* creates the workbench bridge — dockerd being up does
#     not imply the bridge exists, so ordering alone can still lose the bind
#     race at boot; on-failure retry closes that gap)
#   then: enable + restart dnsmasq, and verify port 53 + resolution.
#
# The container side lives IN the repo and needs nothing here:
#   dockered/docker-compose.yaml — jupyter service: dns: [172.28.0.1]
#
# Design notes: knowledge/lab-dns.md
#
# Usage:  sudo dockered/lab-dns-setup.sh
# =============================================================================
set -euo pipefail

LAB_CONF=/etc/dnsmasq.d/lab.conf
DROPIN_DIR=/etc/systemd/system/dnsmasq.service.d
DROPIN_CONF="$DROPIN_DIR/override.conf"
BRIDGE_GW=172.28.0.1

if [[ $EUID -ne 0 ]]; then
    echo "Run as root (sudo) — needs to write $LAB_CONF and the systemd drop-in." >&2
    exit 1
fi

# The bridge gateway must exist BEFORE dnsmasq binds it (fresh-install trap).
# Docker *compose* — not dockerd — creates the workbench bridge, so it can lag
# docker.service and this script. Wait briefly for it; fail with guidance if
# it never shows (BRIDGE_WAIT_S overrides the wait, 0 skips straight to fail).
bridge_wait=${BRIDGE_WAIT_S:-30}
for _ in $(seq 1 "$bridge_wait"); do
    ip -br addr | grep -q "${BRIDGE_GW}/" && break
    sleep 1
done
if ! ip -br addr | grep -q "${BRIDGE_GW}/"; then
    echo "ERROR: ${BRIDGE_GW}/ not present on any interface after ${bridge_wait}s." >&2
    echo "       The workbench bridge comes from docker compose — start it first:" >&2
    echo "         cd dockered && docker compose up -d" >&2
    exit 1
fi

if ! command -v dnsmasq >/dev/null; then
    echo "dnsmasq not installed — installing..."
    apt-get update -qq && apt-get install -y dnsmasq
fi

# ── 1. dnsmasq config ────────────────────────────────────────────────────────
# No `no-resolv` / `server=` lines on purpose: the upstream is
# /etc/resolv.conf, which dnsmasq re-reads on change — VPN DNS swizzle is
# followed with zero config edits. `local=` keeps lab/program names from ever
# going upstream.
cat > "$LAB_CONF" <<'EOF'
# Lab DNS: serves kali's /etc/hosts + forwards everything else upstream.
# Managed by dockered/lab-dns-setup.sh — edit the script, not this file.
listen-address=127.0.0.1,BRIDGE_GW_PLACEHOLDER
bind-interfaces
domain-needed
bogus-priv
local=/htb/
local=/lab.local/
# upstream = /etc/resolv.conf (follows VPN DNS changes automatically)
EOF
sed -i "s/BRIDGE_GW_PLACEHOLDER/${BRIDGE_GW}/" "$LAB_CONF"
chmod 644 "$LAB_CONF"

# ── 2. boot-order drop-in ────────────────────────────────────────────────────
mkdir -p "$DROPIN_DIR"
cat > "$DROPIN_CONF" <<'EOF'
[Unit]
# 172.28.0.1 only exists once docker *compose* creates the workbench bridge —
# docker.service can be fully active with no bridge yet, so ordering alone
# can still lose the bind race at boot.
After=docker.service

[Service]
# First start after boot may precede `docker compose up -d`; retry until the
# bridge appears instead of staying failed with no restart policy.
Restart=on-failure
RestartSec=15
EOF

# ── 3. enable + (re)start ────────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable dnsmasq
systemctl restart dnsmasq

# ── 4. verify ────────────────────────────────────────────────────────────────
echo "== port 53 listener (expect ${BRIDGE_GW}:53 + 127.0.0.1:53) =="
ss -lntu 'sport = :53'

echo
echo "== upstream forwarding (public name through dnsmasq, expect addresses) =="
dig +short example.com "@${BRIDGE_GW}"

echo
echo "== lab name through dnsmasq vs. /etc/hosts (expect identical) =="
lab=$(awk '$1 !~ /^#/ && $1 !~ /^127\./ && $2 !~ /^(localhost|ip6-|ff02)/ {print $2; exit}' /etc/hosts || true)
if [[ -n "${lab:-}" ]]; then
    echo "checking: ${lab}"
    echo "dnsmasq : $(dig +short "@${BRIDGE_GW}" "${lab}" | head -1)"
    echo "/etc/hosts: $(getent hosts "${lab}" | awk '{print $1}')"
else
    echo "No lab entries in /etc/hosts yet. Add one (e.g. 10.129.x.y box.htb),"
    echo "then re-check with: dig +short box.htb @${BRIDGE_GW}"
fi

echo
echo "Done. Container side is already in dockered/docker-compose.yaml (jupyter: dns: [${BRIDGE_GW}])."