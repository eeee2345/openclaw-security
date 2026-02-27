#!/usr/bin/env bash
# Update community YARA rules (MIT/BSD/Apache licensed only)
# Usage: ./scripts/update-yara-rules.sh
#
# Clones (or pulls) MIT/BSD/Apache-licensed YARA rule repositories and copies
# .yar/.yara files into config/yara-rules/community/.
#
# IMPORTANT: Only MIT, BSD, and Apache-licensed repos are included.
# GPL, DRL, and Non-Commercial licensed rules are excluded for MIT compatibility.
#
# Excluded repos (license incompatible):
#   - elastic/protections-artifacts  (Elastic License 2.0)
#   - Neo23x0/signature-base         (Detection Rule License 1.1)
#   - Yara-Rules/rules               (GPL-2.0)
#   - avast/ioc                      (Detection Rule License 1.1)
#   - YARAHQ/yara-forge              (GPL-3.0)
#   - malpedia/signator-rules        (CC BY-SA 4.0)

set -euo pipefail

TARGET_DIR="$(cd "$(dirname "$0")/.." && pwd)/config/yara-rules/community"
TEMP_BASE="/tmp/panguard-yara-community"

# MIT/BSD/Apache-compatible YARA rule repositories (bash 3 compatible)
REPO_NAMES="reversinglabs jpcert bartblaze inquest eset trellix chronicle mandiant ditekshen volexity withsecure loldrivers intezer"

repo_url() {
  case "$1" in
    reversinglabs) echo "https://github.com/reversinglabs/reversinglabs-yara-rules.git" ;;
    jpcert)        echo "https://github.com/JPCERTCC/jpcert-yara.git" ;;
    bartblaze)     echo "https://github.com/bartblaze/Yara-rules.git" ;;
    inquest)       echo "https://github.com/InQuest/yara-rules.git" ;;
    eset)          echo "https://github.com/eset/malware-ioc.git" ;;
    trellix)       echo "https://github.com/advanced-threat-research/Yara-Rules.git" ;;
    chronicle)     echo "https://github.com/chronicle/GCTI.git" ;;
    mandiant)      echo "https://github.com/mandiant/red_team_tool_countermeasures.git" ;;
    ditekshen)     echo "https://github.com/ditekshen/detection.git" ;;
    volexity)      echo "https://github.com/volexity/threat-intel.git" ;;
    withsecure)    echo "https://github.com/WithSecureLabs/iocs.git" ;;
    loldrivers)    echo "https://github.com/magicsword-io/LOLDrivers.git" ;;
    intezer)       echo "https://github.com/intezer/yara-rules.git" ;;
  esac
}

repo_license() {
  case "$1" in
    reversinglabs) echo "MIT" ;;
    jpcert)        echo "BSD-2-Clause" ;;
    bartblaze)     echo "MIT" ;;
    inquest)       echo "MIT-compatible" ;;
    eset)          echo "BSD-2-Clause" ;;
    trellix)       echo "Apache-2.0" ;;
    chronicle)     echo "Apache-2.0" ;;
    mandiant)      echo "BSD-2-Clause" ;;
    ditekshen)     echo "BSD-2-Clause" ;;
    volexity)      echo "BSD-2-Clause" ;;
    withsecure)    echo "BSD-2-Clause" ;;
    loldrivers)    echo "Apache-2.0" ;;
    intezer)       echo "MIT" ;;
  esac
}

echo "=== Panguard: Updating community YARA rules (MIT/BSD/Apache only) ==="

mkdir -p "$TEMP_BASE"

# Clean target
rm -rf "$TARGET_DIR"
mkdir -p "$TARGET_DIR"

TOTAL_COUNT=0
VERSION_INFO=""

for name in $REPO_NAMES; do
  url=$(repo_url "$name")
  license=$(repo_license "$name")
  repo_dir="$TEMP_BASE/$name"

  echo ""
  echo "--- $name ($license) ---"

  # Clone or pull (skip on failure)
  if [ -d "$repo_dir/.git" ]; then
    echo "Pulling $name..."
    if ! git -C "$repo_dir" pull --ff-only --quiet 2>/dev/null; then
      echo "  WARNING: Failed to pull $name, skipping"
      continue
    fi
  else
    echo "Cloning $name..."
    if ! git clone --depth 1 --quiet "$url" "$repo_dir" 2>/dev/null; then
      echo "  WARNING: Failed to clone $name, skipping"
      continue
    fi
  fi

  commit=$(git -C "$repo_dir" rev-parse --short HEAD)

  # Copy .yar and .yara files, preserving structure
  dest="$TARGET_DIR/$name"
  mkdir -p "$dest"

  # Find and copy all YARA rule files
  count=0
  while IFS= read -r -d '' file; do
    rel_path="${file#$repo_dir/}"
    dest_file="$dest/$rel_path"
    mkdir -p "$(dirname "$dest_file")"
    cp "$file" "$dest_file"
    count=$((count + 1))
  done < <(find "$repo_dir" -type f \( -name "*.yar" -o -name "*.yara" \) -print0)

  echo "  Copied $count rule files (commit: $commit)"
  TOTAL_COUNT=$((TOTAL_COUNT + count))
  VERSION_INFO="${VERSION_INFO}${name}: commit=${commit} license=${license} files=${count}\n"
done

# Write VERSION file
cat > "$TARGET_DIR/VERSION" <<EOF
updated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')

Sources (all MIT/BSD/Apache compatible):
$(printf '%b' "$VERSION_INFO")
Total: $TOTAL_COUNT rule files

NOTE: GPL, DRL, and Non-Commercial licensed repos are intentionally excluded.
EOF

echo ""
echo "=== Community YARA rules updated ==="
echo "  Total:   $TOTAL_COUNT .yar/.yara files"
echo "  Target:  $TARGET_DIR"
echo ""
