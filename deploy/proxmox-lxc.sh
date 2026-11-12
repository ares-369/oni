#!/usr/bin/env bash
# =====================================================================
#  OniOps — Proxmox LXC installer
#  Run on a Proxmox VE host. Creates a Debian 12 LXC and installs OniOps
#  into /opt/oniops as a systemd service (not started until you edit config.yaml).
#  The Debian template must already be downloaded (pveam update; pveam download
#  local <template>); override TEMPLATE/STORAGE/BRIDGE/CTID/CT_HOSTNAME as needed.
# =====================================================================
set -euo pipefail

CTID="${CTID:-950}"
# Not called HOSTNAME: bash sets that to the Proxmox host's own name.
CT_HOSTNAME="${CT_HOSTNAME:-oniops}"
DISK_GB="${DISK_GB:-8}"
RAM_MB="${RAM_MB:-1536}"
CORES="${CORES:-2}"
BRIDGE="${BRIDGE:-vmbr0}"
STORAGE="${STORAGE:-local-lvm}"
TEMPLATE="${TEMPLATE:-local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst}"
ONIOPS_REPO="${ONIOPS_REPO:-https://github.com/ares-369/oni-ops.git}"

echo "[OniOps] creating LXC ${CTID} (${CT_HOSTNAME})..."
pct create "$CTID" "$TEMPLATE" \
  --hostname "$CT_HOSTNAME" \
  --cores "$CORES" --memory "$RAM_MB" \
  --rootfs "${STORAGE}:${DISK_GB}" \
  --net0 "name=eth0,bridge=${BRIDGE},ip=dhcp" \
  --features nesting=1 \
  --unprivileged 1 --onboot 1

pct start "$CTID"
sleep 5

echo "[OniOps] installing dependencies inside the container..."
pct exec "$CTID" -- bash -lc '
  set -e
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq python3 python3-venv python3-pip git
  git clone '"$ONIOPS_REPO"' /opt/oniops || (cd /opt/oniops && git pull)
  cd /opt/oniops
  bash scripts/install.sh
  id oniops >/dev/null 2>&1 || useradd --system --home-dir /opt/oniops --shell /usr/sbin/nologin oniops
  chown -R oniops:oniops /opt/oniops
  cp deploy/systemd/oniops.service /etc/systemd/system/oniops.service
  systemctl daemon-reload
  systemctl enable oniops
'

echo
echo "[OniOps] LXC ${CTID} ready."
echo "  Next: edit /opt/oniops/config.yaml (scope + Kali host), drop your SSH key"
echo "  in /opt/oniops/secrets/, then:  pct exec ${CTID} -- systemctl start oniops"
echo "  To open the UI from your network: set oniops.bind_host: \"0.0.0.0\" AND a login"
echo "  (auth.mode) in config.yaml - OniOps refuses to start exposed without one."
echo "  Then browse to the container IP, port 8501."
