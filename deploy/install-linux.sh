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
# Capture the build identity now so the final confirmation can show which
# build is live — a silent installer hides a stale-binary deploy.
installed_build=$("$INSTALL_BIN" -version 2>/dev/null || true)

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
# restart, not start (b/030): on a re-run (upgrade), `install` above replaced the
# binary at a new inode but the running process keeps executing the old one,
# and `systemctl start` is a no-op on an already-active unit — so the old
# build would keep running while the "Installed build" box below advertises
# the new one. `restart` picks up the new binary and is equivalent to `start`
# on a fresh install (an inactive unit is simply started).
systemctl restart s-hole
systemctl status s-hole --no-pager

# The Admin UI line must honor where the API is actually bound: with the
# localhost-only default, printing http://<lan-ip>:8080 would advertise a
# URL that refuses connections from every other device (same fix as the
# in-binary banner, T4). Only show LAN URLs when api_listen is set to a
# non-loopback address.
api_listen=$(grep -E '^[[:space:]]*api_listen:' "$CONFIG_DIR/config.yaml" | tail -1 || true)
# Pull the host:port value out of the YAML line, dropping the key, quotes,
# and surrounding whitespace: `  api_listen: "0.0.0.0:8080"` -> `0.0.0.0:8080`.
api_value=$(echo "$api_listen" | sed -E 's/^[^:]*:[[:space:]]*//; s/^"//; s/"$//; s/[[:space:]]*$//')
# Split off the port (after the last colon) and the host (before it), then
# strip the IPv6 brackets: `[::]:8080` -> host `::`, port `8080`.
api_port=${api_value##*:}
api_port=${api_port:-8080}
api_host=${api_value%:*}
api_host=${api_host#[}
api_host=${api_host%]}
# Mirror isLoopbackHost in cmd/s-hole/main.go so the banner matches the
# in-binary hint (T4; b/031): only 127.x / ::1 / localhost bind loopback-only. An
# empty host (":8080"), 0.0.0.0, ::, or a specific LAN IP are all LAN-visible.
case "$api_host" in
  127.*|::1|localhost) api_on_lan=false ;;
  *)                   api_on_lan=true ;;
esac

echo ""
echo "┌─ Installed build ───────────────────────────────────────"
if [[ -n "$installed_build" ]]; then
  printf '%s\n' "$installed_build" | sed 's/^/│  /'
else
  echo "│  (could not read version — is this an s-hole binary?)"
fi
echo "└─────────────────────────────────────────────────────────"

echo ""
echo "┌─ Router setup ──────────────────────────────────────────"
# hostname -I returns space-separated IPs; print one line per address.
for ip in $(hostname -I); do
  # Skip IPv6 addresses (contain colons).
  [[ "$ip" == *:* ]] && continue
  echo "│  DNS server → ${ip}:53"
  if $api_on_lan; then
    echo "│  Admin UI   → http://${ip}:${api_port}"
  fi
done
if ! $api_on_lan; then
  echo "│  Admin UI   → http://127.0.0.1:${api_port} (this machine only —"
  echo "│               set api_listen: \"0.0.0.0:${api_port}\" for LAN access)"
fi
echo "└─────────────────────────────────────────────────────────"
echo "Point your router's DHCP DNS field at the address above."
