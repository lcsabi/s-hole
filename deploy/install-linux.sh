#!/usr/bin/env bash
# Installs s-hole as a systemd service on Linux.
# Run as root: sudo bash install-linux.sh
set -euo pipefail

BINARY=${1:-"./s-hole"}
CONFIG_SRC=${2:-"./config.yaml"}

CONFIG_DIR="/etc/s-hole"
DATA_DIR="/var/lib/s-hole"
INSTALL_BIN="/usr/local/bin/s-hole"

if [[ $EUID -ne 0 ]]; then
  echo "error: this script must be run as root" >&2
  exit 1
fi

echo "==> creating s-hole system user"
id -u s-hole &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin s-hole

echo "==> installing binary to $INSTALL_BIN"
install -m 755 "$BINARY" "$INSTALL_BIN"

echo "==> installing config to $CONFIG_DIR/config.yaml"
mkdir -p "$CONFIG_DIR"
if [[ ! -f "$CONFIG_DIR/config.yaml" ]]; then
  install -m 640 -o root -g s-hole "$CONFIG_SRC" "$CONFIG_DIR/config.yaml"
  echo "    (edit $CONFIG_DIR/config.yaml before starting)"
else
  echo "    (config already exists — skipping)"
fi

echo "==> creating data directory $DATA_DIR"
mkdir -p "$DATA_DIR"
chown s-hole:s-hole "$DATA_DIR"

echo "==> installing systemd unit"
cat > /etc/systemd/system/s-hole.service << 'EOF'
[Unit]
Description=s-hole DNS Sinkhole
Documentation=https://github.com/laszlo/s-hole
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=s-hole
Group=s-hole

ExecStart=/usr/local/bin/s-hole -config /etc/s-hole/config.yaml
WorkingDirectory=/var/lib/s-hole

Restart=on-failure
RestartSec=5s

# Allow binding to port 53 without running as root.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Harden the service process.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/s-hole

[Install]
WantedBy=multi-user.target
EOF
chmod 644 /etc/systemd/system/s-hole.service

echo "==> enabling and starting service"
systemctl daemon-reload
systemctl enable s-hole
systemctl start s-hole
systemctl status s-hole --no-pager

echo ""
echo "┌─ Router setup ──────────────────────────────────────────"
# hostname -I returns space-separated IPs; print one line per address.
for ip in $(hostname -I); do
  # Skip IPv6 addresses (contain colons).
  [[ "$ip" == *:* ]] && continue
  echo "│  DNS server → ${ip}:53"
  echo "│  Admin UI   → http://${ip}:8080"
done
echo "└─────────────────────────────────────────────────────────"
echo "Point your router's DHCP DNS field at the address above."
