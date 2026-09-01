#!/usr/bin/env bash
# Installs s-hole as a systemd service on Linux.
# Run as root: sudo bash install-linux.sh [--free-port-53] [BINARY] [CONFIG_SRC]
set -euo pipefail

CONFIG_DIR="/etc/s-hole"
DATA_DIR="/var/lib/s-hole"
INSTALL_BIN="/usr/local/bin/s-hole"
# The DNSStubListener=no drop-in that frees port 53; the uninstaller removes it
# under --restore-resolved. README documents the same path and content.
RESOLVED_DROPIN="/etc/systemd/resolved.conf.d/no-stub.conf"

FREE_PORT_53=false

usage() {
  cat <<'USAGE'
Usage: sudo bash install-linux.sh [options] [BINARY] [CONFIG_SRC]

Installs s-hole as a systemd service: creates the s-hole system user, installs
the binary and config, writes the unit, then starts and health-checks the
service.

Arguments (positional, after any options):
  BINARY       Path to the s-hole binary to install. Default: ./s-hole
  CONFIG_SRC   Path to the config.yaml to install (only when none exists yet).
               Default: ./config.yaml

Options:
  --free-port-53  If systemd-resolved is holding port 53, disable its stub
                  listener now (write /etc/systemd/resolved.conf.d/no-stub.conf
                  and restart systemd-resolved). Without this flag the installer
                  only warns and prints the drop-in to create by hand.
  -h, --help      Show this help and exit.
USAGE
}

# Flags come first, then the two positional paths. The first non-flag argument
# ends flag parsing, so BINARY/CONFIG_SRC keep their short positional form.
while [[ $# -gt 0 ]]; do
  case "$1" in
    --free-port-53) FREE_PORT_53=true; shift ;;
    -h|--help)      usage; exit 0 ;;
    --)             shift; break ;;
    -*)             echo "error: unknown option: $1" >&2; usage >&2; exit 1 ;;
    *)              break ;;
  esac
done

BINARY=${1:-"./s-hole"}
CONFIG_SRC=${2:-"./config.yaml"}

if [[ $EUID -ne 0 ]]; then
  echo "error: this script must be run as root" >&2
  exit 1
fi

echo "==> validating arguments"
# Validate the two positional paths before `install` copies them, so a swapped
# invocation (config first, binary second) fails loudly instead of writing YAML
# over $INSTALL_BIN and the ELF over config.yaml (ROADMAP #27).
if [[ ! -r "$CONFIG_SRC" ]]; then
  echo "error: config '$CONFIG_SRC' is not a readable file" >&2
  usage >&2
  exit 1
fi
if [[ ! -f "$BINARY" ]]; then
  echo "error: binary '$BINARY' not found" >&2
  usage >&2
  exit 1
fi

# Cheap structural checks first (via `file`, when present): the config must not
# be an ELF and the binary must be a native ELF for this host. Do this before
# executing the binary as root. The -version exec below is the real proof that
# the file runs here and is s-hole; the structural gate just stops an obviously
# wrong file from being run and gives a clearer swapped-argument message.
if command -v file >/dev/null 2>&1; then
  if file -b "$CONFIG_SRC" | grep -qi 'ELF'; then
    echo "error: config '$CONFIG_SRC' looks like a binary; did you swap the arguments?" >&2
    echo "correct order: sudo bash install-linux.sh [--free-port-53] <s-hole-binary> <config.yaml>" >&2
    exit 1
  fi
  bin_desc=$(file -b "$BINARY")
  if ! grep -qi 'ELF' <<<"$bin_desc"; then
    echo "error: binary '$BINARY' is not an ELF executable; did you swap the arguments?" >&2
    echo "correct order: sudo bash install-linux.sh [--free-port-53] <s-hole-binary> <config.yaml>" >&2
    exit 1
  fi
  case "$(uname -m)" in
    x86_64)            arch_pat='x86-64' ;;
    aarch64|arm64)     arch_pat='aarch64' ;;
    armv7l|armv6l|arm) arch_pat='ARM' ;;
    *)                 arch_pat='' ;;
  esac
  if [[ -n "$arch_pat" ]] && ! grep -qi "$arch_pat" <<<"$bin_desc"; then
    echo "error: binary '$BINARY' is not built for this host ($(uname -m))" >&2
    echo "       file reports: $bin_desc" >&2
    exit 1
  fi
fi

# Prove the file runs on this host and is s-hole. This executes the (now
# structurally-checked) binary once, before install. A wrong-arch, corrupt, or
# non-s-hole file fails here, including a swapped config path that `file` could
# not flag on a host without the `file` command.
if ! "$BINARY" -version >/dev/null 2>&1; then
  echo "error: '$BINARY' did not run as an s-hole binary on this host" >&2
  echo "       (wrong architecture, corrupt, or not an s-hole build)" >&2
  echo "correct order: sudo bash install-linux.sh [--free-port-53] <s-hole-binary> <config.yaml>" >&2
  exit 1
fi

echo "==> creating s-hole system user"
id -u s-hole &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin s-hole

echo "==> installing binary to $INSTALL_BIN"
install -m 755 "$BINARY" "$INSTALL_BIN"
# Capture the build identity now so the final confirmation can show which
# build is live; a silent installer hides a stale-binary deploy.
installed_build=$("$INSTALL_BIN" -version 2>/dev/null || true)

echo "==> installing config to $CONFIG_DIR/config.yaml"
mkdir -p "$CONFIG_DIR"
if [[ ! -f "$CONFIG_DIR/config.yaml" ]]; then
  install -m 640 -o root -g s-hole "$CONFIG_SRC" "$CONFIG_DIR/config.yaml"
  echo "    (edit $CONFIG_DIR/config.yaml before starting)"
else
  echo "    (config already exists, skipping)"
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

echo "==> validating config"
# Dry-run the config through the binary before the service starts, so a bad
# config surfaces here on screen instead of as a failed start (which the health
# check below would then have to diagnose from the journal). Same load-and-
# validate sequence the service runs at startup (ROADMAP #27).
if ! "$INSTALL_BIN" -check-config -config "$CONFIG_DIR/config.yaml"; then
  echo "error: config validation failed; not starting the service" >&2
  echo "       fix $CONFIG_DIR/config.yaml and re-run the installer" >&2
  exit 1
fi

# Port-53 preflight: the most common Linux DNS-server install failure is the
# systemd-resolved stub listener already holding :53, which makes the s-hole
# start fail to bind. A listener on 127.0.0.53:53 is that stub. Default is a
# warning with the exact drop-in to create; --free-port-53 creates it now,
# mirroring the uninstaller's --restore-resolved (ROADMAP #27).
if command -v ss >/dev/null 2>&1 && ss -H -lun 2>/dev/null | grep -q '127.0.0.53:53'; then
  if $FREE_PORT_53; then
    echo "==> freeing port 53: disabling the systemd-resolved stub listener"
    mkdir -p "$(dirname "$RESOLVED_DROPIN")"
    cat > "$RESOLVED_DROPIN" << 'RESOLVED'
[Resolve]
DNSStubListener=no
RESOLVED
    systemctl restart systemd-resolved
  else
    echo "warning: systemd-resolved is listening on port 53 (127.0.0.53:53)." >&2
    echo "         s-hole cannot bind :53 until the stub is disabled. To free it," >&2
    echo "         create $RESOLVED_DROPIN with:" >&2
    echo "           [Resolve]" >&2
    echo "           DNSStubListener=no" >&2
    echo "         then run: systemctl restart systemd-resolved" >&2
    echo "         Or re-run this installer with --free-port-53 to do it now." >&2
  fi
fi

echo "==> enabling and starting service"
systemctl daemon-reload
systemctl enable s-hole
# restart, not start (b/030): on a re-run (upgrade), `install` above replaced the
# binary at a new inode but the running process keeps executing the old one,
# and `systemctl start` is a no-op on an already-active unit, so the old
# build would keep running while the "Installed build" box below advertises
# the new one. `restart` picks up the new binary and is equivalent to `start`
# on a fresh install (an inactive unit is simply started).
systemctl restart s-hole

# Health check: `restart` returns before the unit is necessarily up, and a
# crash-loop (port 53 taken, wrong-arch binary, a config the dry-run above
# could not catch) would otherwise reach the "Router setup" banner at exit 0,
# so a dead service would look green (ROADMAP #27; the b/030 intent that a bad
# deploy must not look installed). Poll is-active for a bounded window; a
# Type=simple unit reports `active` as soon as the process is up, and `failed`
# on a crash, so the timeout only needs to cover the RestartSec=5s cycle.
echo "==> waiting for the service to become active"
state=""
active=false
for _ in $(seq 1 15); do
  state=$(systemctl is-active s-hole || true)
  if [[ "$state" == "active" ]]; then
    active=true
    break
  fi
  if [[ "$state" == "failed" ]]; then
    break
  fi
  sleep 1
done

if ! $active; then
  echo "error: s-hole did not become active (state: ${state:-unknown})." >&2
  echo "       recent log lines:" >&2
  journalctl -u s-hole -n 20 --no-pager >&2 || true
  exit 1
fi
echo "    (service is active)"

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
  echo "│  (could not read version; is this an s-hole binary?)"
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
  echo "│  Admin UI   → http://127.0.0.1:${api_port} (this machine only;"
  echo "│               set api_listen: \"0.0.0.0:${api_port}\" for LAN access)"
fi
echo "└─────────────────────────────────────────────────────────"
echo "Point your router's DHCP DNS field at the address above."
