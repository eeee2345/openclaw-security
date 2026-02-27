#!/usr/bin/env bash
# Panguard AI - Suricata Rule Updater
# Downloads Emerging Threats Open ruleset for Suricata
#
# Usage: sudo ./update-suricata-rules.sh
# Cron:  0 2 * * * /opt/panguard/scripts/update-suricata-rules.sh

set -euo pipefail

RULES_DIR="/var/lib/suricata/rules"
ET_URL="https://rules.emergingthreats.net/open/suricata-7.0/emerging.rules.tar.gz"
TEMP_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

echo "[Panguard] Updating Suricata rules..."

# Check if suricata-update is available (preferred method)
if command -v suricata-update &>/dev/null; then
  echo "[Panguard] Using suricata-update (recommended)"
  suricata-update
  echo "[Panguard] Rules updated via suricata-update"

  # Reload Suricata if running
  if systemctl is-active --quiet suricata 2>/dev/null; then
    echo "[Panguard] Reloading Suricata..."
    suricatasc -c reload-rules 2>/dev/null || systemctl reload suricata
    echo "[Panguard] Suricata reloaded"
  fi

  exit 0
fi

# Fallback: manual download of Emerging Threats Open rules
echo "[Panguard] suricata-update not found, downloading ET Open rules manually..."

mkdir -p "$RULES_DIR"

echo "[Panguard] Downloading from $ET_URL"
curl -sSL "$ET_URL" -o "$TEMP_DIR/emerging.rules.tar.gz"

echo "[Panguard] Extracting rules..."
tar -xzf "$TEMP_DIR/emerging.rules.tar.gz" -C "$TEMP_DIR"

# Merge all rule files into one
if [ -d "$TEMP_DIR/rules" ]; then
  cat "$TEMP_DIR/rules/"*.rules > "$RULES_DIR/suricata.rules" 2>/dev/null || true
  RULE_COUNT=$(grep -c '^\s*alert' "$RULES_DIR/suricata.rules" 2>/dev/null || echo "0")
  echo "[Panguard] Installed $RULE_COUNT alert rules to $RULES_DIR/suricata.rules"
fi

# Reload Suricata if running
if systemctl is-active --quiet suricata 2>/dev/null; then
  echo "[Panguard] Reloading Suricata..."
  suricatasc -c reload-rules 2>/dev/null || systemctl reload suricata
  echo "[Panguard] Suricata reloaded"
elif pgrep -x suricata &>/dev/null; then
  echo "[Panguard] Suricata is running but not managed by systemd."
  echo "[Panguard] Please reload rules manually: suricatasc -c reload-rules"
fi

echo "[Panguard] Suricata rule update complete"
