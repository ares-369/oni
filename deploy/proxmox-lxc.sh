#!/usr/bin/env bash
# =====================================================================
#  ONIOPS — Proxmox LXC installer
#  Run on a Proxmox VE host. Creates a Debian 12 LXC and installs ONIOPS
#  as a systemd service. Edit the variables below first.
# =====================================================================
set -euo pipefail

CTID="${CTID:-950}"
HOSTNAME="${HOSTNAME:-oniops}"
DISK_GB="${DISK_GB:-8}"
RAM_MB="${RAM_MB:-1536}"
CORES="${CORES:-2}"
BRIDGE="${BRIDGE:-vmbr0}"
STORAGE="${STORAGE:-local-lvm}"
TEMPLATE="${TEMPLATE:-local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst}"
ONIOPS_REPO="${ONIOPS_REPO:-https://github.com/oniops/oniops.git}"

echo "[ONIOPS] creating LXC ${CTID} (${HOSTNAME})..."
pct create "$CTID" "$TEMPLATE" \
  --hostname "$HOSTNAME" \
  --cores "$CORES" --memory "$RAM_MB" \
  --rootfs "${STORAGE}:${DISK_GB}" \
  --net0 "name=eth0,bridge=${BRIDGE},ip=dhcp" \
  --features nesting=1 \
  --unprivileged 1 --onboot 1

pct start "$CTID"
sleep 5

echo "[ONIOPS] installing dependencies inside the container..."
pct exec "$CTID" -- bash -lc '
  set -e
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq python3 python3-venv python3-pip git
  git clone '"$ONIOPS_REPO"' /opt/oniops || (cd /opt/oniops && git pull)
  cd /opt/oniops
  python3 -m venv venv
  ./venv/bin/pip install -q -r requirements.txt
  [ -f config.yaml ] || cp config.example.yaml config.yaml
  [ -f .env ] || cp .env.example .env
  mkdir -p secrets data
  cp deploy/systemd/oniops.service /etc/systemd/system/oniops.service
  systemctl daemon-reload
  systemctl enable oniops
'

echo
echo "[ONIOPS] LXC ${CTID} ready."
echo "  Next: edit /opt/oniops/config.yaml (scope + Kali host), drop your SSH key"
echo "  in /opt/oniops/secrets/, then:  pct exec ${CTID} -- systemctl start oniops"
echo "  Web UI on the container IP, port 8501."
