#!/usr/bin/env bash
# Uninstalls the s-hole systemd service from Linux — reverses install-linux.sh.
# Run as root: sudo bash uninstall-linux.sh [--purge] [--restore-resolved] [-y]
set -euo pipefail

CONFIG_DIR="/etc/s-hole"
DATA_DIR="/var/lib/s-hole"
INSTALL_BIN="/usr/local/bin/s-hole"
UNIT_FILE="/etc/systemd/system/s-hole.service"
# The DNSStubListener=no drop-in the README documents for freeing port 53.
RESOLVED_DROPIN="/etc/systemd/resolved.conf.d/no-stub.conf"

PURGE=false
RESTORE_RESOLVED=false
ASSUME_YES=false

usage() {
  cat <<'USAGE'
Usage: sudo bash uninstall-linux.sh [options]

Removes the s-hole systemd service, binary, config, and system user
installed by install-linux.sh, and prints a summary of what it removed.

Options:
  --purge             Also delete the data directory (/var/lib/s-hole):
                      blocklist caches and the SQLite query log. Off by
                      default, so your query history is preserved.
  --restore-resolved  If a DNSStubListener=no drop-in for systemd-resolved
                      is present (created to free port 53 for s-hole),
                      remove it and restart systemd-resolved.
  -y, --yes           Do not prompt for confirmation.
  -h, --help          Show this help and exit.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge)            PURGE=true ;;
    --restore-resolved) RESTORE_RESOLVED=true ;;
    -y|--yes)           ASSUME_YES=true ;;
    -h|--help)          usage; exit 0 ;;
    *) echo "error: unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
  shift
done

if [[ $EUID -ne 0 ]]; then
  echo "error: this script must be run as root" >&2
  exit 1
fi

# Show the plan before touching anything — an uninstaller changes system
# state, so the destructive set should be explicit and confirmable.
echo "This will:"
echo "  - stop and disable the s-hole service"
echo "  - delete $UNIT_FILE"
echo "  - delete $INSTALL_BIN"
echo "  - delete $CONFIG_DIR (config)"
if $PURGE; then
  echo "  - delete $DATA_DIR (blocklist caches + query log)   [--purge]"
else
  echo "  - keep   $DATA_DIR (blocklist caches + query log; pass --purge to remove)"
fi
echo "  - remove the s-hole system user and group"
if [[ -f "$RESOLVED_DROPIN" ]]; then
  if $RESTORE_RESOLVED; then
    echo "  - delete $RESOLVED_DROPIN and restart systemd-resolved   [--restore-resolved]"
  else
    echo "  - keep   $RESOLVED_DROPIN (pass --restore-resolved to remove it)"
  fi
fi

if ! $ASSUME_YES; then
  read -rp "Proceed? [y/N] " reply || true
  case "$reply" in
    [yY] | [yY][eE][sS]) ;;
    *) echo "aborted."; exit 0 ;;
  esac
fi

# Track outcomes for the summary.
removed=()
kept=()

# 1. Stop + disable the service. Both are safe no-ops on an absent or
#    inactive unit, so run them unconditionally (guarded against set -e).
echo "==> stopping and disabling service"
systemctl stop s-hole 2>/dev/null || true
systemctl disable s-hole 2>/dev/null || true

# 2. Remove the unit file, then reload so systemd forgets it.
if [[ -f "$UNIT_FILE" ]]; then
  echo "==> removing systemd unit"
  rm -f "$UNIT_FILE"
  systemctl daemon-reload
  systemctl reset-failed s-hole 2>/dev/null || true
  removed+=("$UNIT_FILE")
fi

# 3. Remove the binary.
if [[ -e "$INSTALL_BIN" ]]; then
  echo "==> removing binary"
  rm -f "$INSTALL_BIN"
  removed+=("$INSTALL_BIN")
fi

# 4. Remove the config directory.
if [[ -d "$CONFIG_DIR" ]]; then
  echo "==> removing config"
  rm -rf "$CONFIG_DIR"
  removed+=("$CONFIG_DIR")
fi

# 5. Data directory: delete only with --purge; otherwise preserve it.
if [[ -d "$DATA_DIR" ]]; then
  if $PURGE; then
    echo "==> removing data directory (--purge)"
    rm -rf "$DATA_DIR"
    removed+=("$DATA_DIR")
  else
    echo "==> keeping data directory $DATA_DIR (pass --purge to remove)"
    kept+=("$DATA_DIR (blocklist caches + query log)")
  fi
fi

# 6. Remove the system user, then the group if userdel left it behind.
if id -u s-hole &>/dev/null; then
  echo "==> removing s-hole system user"
  userdel s-hole 2>/dev/null || true
  removed+=("system user s-hole")
fi
if getent group s-hole &>/dev/null; then
  groupdel s-hole 2>/dev/null || true
  removed+=("system group s-hole")
fi

# 7. Optionally restore the systemd-resolved stub listener. This is a
#    system-wide change the operator may have made independently of s-hole,
#    so only act on it behind --restore-resolved.
if [[ -f "$RESOLVED_DROPIN" ]]; then
  if $RESTORE_RESOLVED; then
    echo "==> restoring systemd-resolved stub listener"
    rm -f "$RESOLVED_DROPIN"
    systemctl restart systemd-resolved 2>/dev/null || true
    removed+=("$RESOLVED_DROPIN (systemd-resolved restarted)")
  else
    kept+=("$RESOLVED_DROPIN — DNSStubListener=no drop-in; pass --restore-resolved to remove")
  fi
fi

# Summary — the same reporting courtesy as the installer.
echo ""
echo "┌─ Uninstall summary ─────────────────────────────────────"
if [[ ${#removed[@]} -gt 0 ]]; then
  echo "│  Removed:"
  for item in "${removed[@]}"; do echo "│    - $item"; done
else
  echo "│  Nothing to remove — s-hole did not appear to be installed."
fi
if [[ ${#kept[@]} -gt 0 ]]; then
  echo "│  Kept:"
  for item in "${kept[@]}"; do echo "│    - $item"; done
fi
echo "└─────────────────────────────────────────────────────────"

if ! $PURGE && [[ -d "$DATA_DIR" ]]; then
  echo "Query history and caches remain in $DATA_DIR."
  echo "Remove them with: sudo rm -rf $DATA_DIR"
fi
