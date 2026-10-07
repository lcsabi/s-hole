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

Installs s-hole as a systemd service: checks the config with the new binary,
creates the s-hole system user, installs the binary and config, writes the
unit, then starts and health-checks the service.

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
    echo "error: config '$CONFIG_SRC' looks like a binary. Did you swap the arguments?" >&2
    echo "correct order: sudo bash install-linux.sh [--free-port-53] <s-hole-binary> <config.yaml>" >&2
    exit 1
  fi
  bin_desc=$(file -b "$BINARY")
  if ! grep -qi 'ELF' <<<"$bin_desc"; then
    echo "error: binary '$BINARY' is not an ELF executable. Did you swap the arguments?" >&2
    echo "correct order: sudo bash install-linux.sh [--free-port-53] <s-hole-binary> <config.yaml>" >&2
    exit 1
  fi
  case "$(uname -m)" in
    x86_64)            arch_pat='x86-64' ;;
    # A 64-bit ARM kernel also runs 32-bit ARM binaries, such as the armv7
    # (32-bit OS) build; the -version run below proves it runs.
    aarch64|arm64)     arch_pat='aarch64|ARM' ;;
    armv7l|armv6l|arm) arch_pat='ARM' ;;
    *)                 arch_pat='' ;;
  esac
  if [[ -n "$arch_pat" ]] && ! grep -Eqi "$arch_pat" <<<"$bin_desc"; then
    echo "error: binary '$BINARY' is not built for this host ($(uname -m))" >&2
    echo "       file reports: $bin_desc" >&2
    exit 1
  fi
fi

# Prove the file runs on this host and is s-hole. This executes the (now
# structurally-checked) binary once, before install. The output must name
# s-hole (version.String() starts with "s-hole "), so an ELF that merely exits
# 0 on a -version flag but is not s-hole is still rejected. A wrong-arch,
# corrupt, or non-s-hole file fails here, including a swapped config path that
# `file` could not flag on a host without the `file` command.
if ! "$BINARY" -version 2>/dev/null | grep -q '^s-hole '; then
  echo "error: '$BINARY' did not run as an s-hole binary on this host" >&2
  echo "       (wrong architecture, corrupt, or not an s-hole build)" >&2
  echo "correct order: sudo bash install-linux.sh [--free-port-53] <s-hole-binary> <config.yaml>" >&2
  exit 1
fi

echo "==> validating config"
# Dry-run the config through the new binary before anything is installed, so a
# bad config surfaces here on screen instead of as a failed start (which the
# health check below would then have to diagnose from the journal). Same
# load-and-validate sequence the service runs at startup (ROADMAP #27). The
# config in effect is the installed one when it exists (an upgrade keeps it),
# else the one being installed.
# The output is kept: its "config OK" line names admin.listen for the banner.
# -check-config fails on any config problem, including a key renamed in
# s-hole 2.0. On an upgrade with an old config this stops before the binary is
# replaced: the running s-hole and the installed binary stay as they were, so
# a later restart cannot start the new binary with the old config (b/093).
if [[ -f "$CONFIG_DIR/config.yaml" ]]; then
  check_cfg="$CONFIG_DIR/config.yaml"
else
  check_cfg="$CONFIG_SRC"
fi
if ! check_out=$("$BINARY" -check-config -config "$check_cfg" 2>&1); then
  printf '%s\n' "$check_out" >&2
  echo "error: this s-hole build does not accept $check_cfg" >&2
  echo "       The installer changed nothing." >&2
  if grep -q 'was renamed to' <<<"$check_out"; then
    echo "       The config uses s-hole 1.x keys. Do not edit $check_cfg while 1.x runs." >&2
    echo "       See \"Upgrade to 2.0\" in the 2.0.0 release notes (docs/CHANGELOG.md)." >&2
  else
    echo "       Fix $check_cfg, then run the installer again." >&2
  fi
  exit 1
fi
printf '%s\n' "$check_out"

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
# Owner-only: the directory holds the query history when query_log.database
# is on. chmod also tightens a directory from an older install (b/076).
mkdir -p "$DATA_DIR"
# -R: a default uninstall leaves the kept data owned by root, and a
# reinstall must take it back, or s-hole cannot open its database or read its
# blocklist cache (b/092).
chown -R s-hole:s-hole "$DATA_DIR"
chmod 0700 "$DATA_DIR"

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

# `systemctl reload s-hole` re-reads the DoT certificate and the blocklists.
ExecReload=/bin/kill -HUP $MAINPID

# Allow binding to ports 53 and 853 (DNS over TLS) without running as root.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Harden the service process.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/s-hole
# Files s-hole creates (the query database, the blocklist cache) are
# readable by the s-hole user only.
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
chmod 644 /etc/systemd/system/s-hole.service

# Port-53 preflight: the most common Linux DNS-server install failure is the
# systemd-resolved stub listener already holding :53, which makes the s-hole
# start fail to bind. resolved runs two stubs on port 53: 127.0.0.53, which it
# binds to the loopback interface (so ss prints it as 127.0.0.53%lo:53), and,
# on systemd 247 and later, 127.0.0.54. Match both, with or without the
# %interface suffix; an exact "127.0.0.53:53" match missed the %lo form, so
# --free-port-53 silently did nothing (b/058). Each stub holds UDP and TCP :53,
# so probe both (-u -t). Default is a warning with the exact drop-in to create;
# --free-port-53 creates it now, mirroring the uninstaller's
# --restore-resolved (ROADMAP #27).
# The output is captured before grep runs: under pipefail, `ss | grep -q`
# can report no match when grep exits early and ss dies of SIGPIPE.
resolved_stub_on_53() {
  local listeners
  command -v ss >/dev/null 2>&1 || return 1
  listeners=$(ss -H -lunt 2>/dev/null) || return 1
  grep -Eq '127\.0\.0\.5[34](%[^:[:space:]]+)?:53([[:space:]]|$)' <<<"$listeners"
}

if resolved_stub_on_53; then
  if $FREE_PORT_53; then
    echo "==> freeing port 53: disabling the systemd-resolved stub listener"
    mkdir -p "$(dirname "$RESOLVED_DROPIN")"
    cat > "$RESOLVED_DROPIN" << 'RESOLVED'
[Resolve]
DNSStubListener=no
RESOLVED
    systemctl restart systemd-resolved
    if resolved_stub_on_53; then
      echo "warning: systemd-resolved still listens on port 53 after the restart." >&2
      echo "         Check $RESOLVED_DROPIN, then run: systemctl restart systemd-resolved" >&2
    fi
    # With the stub gone, a resolv.conf that points at it leaves this host
    # without DNS for programs that read it directly, including s-hole's own
    # blocklist download. Say how to repoint it; do not change it here.
    if [[ "$(readlink -f /etc/resolv.conf 2>/dev/null)" == /run/systemd/resolve/stub-resolv.conf ]]; then
      echo "note: /etc/resolv.conf points at the stub listener that was just disabled." >&2
      echo "      Programs that read it (apt, curl, and s-hole's blocklist download)" >&2
      echo "      have no DNS until you point it at systemd-resolved's server list:" >&2
      echo "        sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf" >&2
    fi
  else
    echo "warning: systemd-resolved is listening on port 53 (127.0.0.53 or 127.0.0.54)." >&2
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
# in-binary banner, T4). Only show LAN URLs when admin.listen is set to a
# non-loopback address. The value comes from the "config OK" line of the
# dry run above, so the binary's own parser reads the YAML (and the
# environment), not a grep.
api_value=$(sed -n 's/.*msg="config OK".* admin_listen=\([^ ]*\).*/\1/p' <<<"$check_out" | tail -1)
api_value=${api_value#\"}
api_value=${api_value%\"}
api_value=${api_value:-127.0.0.1:8080}
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
  echo "│  (could not read version. Is this an s-hole binary?)"
fi
echo "└─────────────────────────────────────────────────────────"

echo ""
echo "┌─ Router setup ──────────────────────────────────────────"
# LAN IPv4 addresses for the banner: global-scope addresses on interfaces that
# are up and are not a container, VM, or VPN interface. `hostname -I` alone
# also listed the Docker bridge (172.17.0.1), which a router cannot reach
# (b/059). Keep the name list in step with virtualIfacePrefixes in
# cmd/s-hole/main.go; both match case-insensitively. Fall back to
# `hostname -I` if `ip` is missing or finds nothing, so the banner still shows
# an address. `|| true` keeps set -e and pipefail from ending the script when
# `ip` is absent: the service is already running at this point.
lan_ipv4s() {
  ip -4 -o addr show up scope global 2>/dev/null |
    awk 'tolower($2) !~ /^(docker|br-|veth|virbr|vboxnet|vmnet|lxcbr|lxdbr|incusbr|podman|cni|flannel|cali|vxlan|tailscale|wg|zt|tun|tap)/ { sub(/\/.*/, "", $4); print $4 }' || true
}
banner_ips=$(lan_ipv4s)
if [[ -z "$banner_ips" ]]; then
  banner_ips=$(hostname -I 2>/dev/null || true)
fi
for ip in $banner_ips; do
  # Skip IPv6 addresses (contain colons).
  [[ "$ip" == *:* ]] && continue
  echo "│  DNS server → ${ip}:53"
  if $api_on_lan; then
    echo "│  Admin UI   → http://${ip}:${api_port}"
  fi
done
if ! $api_on_lan; then
  echo "│  Admin UI   → http://127.0.0.1:${api_port} (this machine only."
  echo "│               Set admin.listen: \"0.0.0.0:${api_port}\" for LAN access)"
fi
echo "└─────────────────────────────────────────────────────────"
echo "Point your router's DHCP DNS field at the address above."

# Keep the s-hole host off s-hole. After the router change, DHCP also gives
# s-hole's address to this host, unless its resolver is set by hand. Then
# this host has no DNS while s-hole is down: s-hole cannot download its
# blocklists, apt cannot run, and a host without a battery-backed clock may
# not reach its time server. s-hole warns at runtime too; this catches a host
# that already points at itself. 127.0.0.53/54 are the systemd-resolved stubs,
# so the check reads resolved's own server list behind them.
own_addrs=$(ip -o addr show 2>/dev/null | awk '{ sub(/\/.*/, "", $4); print $4 }' || true)
self_resolver=""
for f in /etc/resolv.conf /run/systemd/resolve/resolv.conf; do
  [[ -r "$f" ]] || continue
  while read -r key addr _; do
    [[ "$key" == nameserver ]] || continue
    case "$addr" in 127.0.0.53|127.0.0.54) continue ;; esac
    if [[ "$addr" == 127.* || "$addr" == ::1 ]] || grep -qxF "$addr" <<<"$own_addrs"; then
      self_resolver=$addr
    fi
  done < "$f"
done
echo ""
echo "┌─ Before you change the router ──────────────────────────"
echo "│  Keep this host off s-hole: set this host's own DNS"
echo "│  resolver by hand (your router, or a public resolver), so"
echo "│  it does not take s-hole's address from the router."
echo "│  See \"Keep the s-hole host off s-hole\" in README.md."
if [[ -n "$self_resolver" ]]; then
  echo "│"
  echo "│  WARNING: this host already uses $self_resolver, which is"
  echo "│  s-hole, as its DNS server."
fi
echo "└─────────────────────────────────────────────────────────"
