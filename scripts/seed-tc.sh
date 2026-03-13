#!/bin/bash
# Seed rules from local config/ to tc.panguard.ai via batch API
# Usage: ./scripts/seed-tc.sh

set -e

TC="https://tc.panguard.ai"
CONFIG_DIR="$(cd "$(dirname "$0")/.." && pwd)/config"
ATR_DIR="$(cd "$(dirname "$0")/.." && pwd)/packages/atr/rules"
BATCH_SIZE=200
TOTAL=0

echo "Seeding rules to $TC"
echo ""

# Helper: collect files into JSON batch and POST
seed_batch() {
  local source="$1"
  local dir="$2"
  local extensions="$3"
  local base_dir="$4"

  local files=()
  while IFS= read -r -d '' f; do
    files+=("$f")
  done < <(find "$dir" -type f \( -name "*.${extensions%%|*}" $(echo "$extensions" | sed 's/|/ -o -name "*./g; s/$/"/' | sed 's/^/ -o -name "*./' ) \) -print0 2>/dev/null)

  local count=${#files[@]}
  echo "  Found $count ${source} files"

  local batch=()
  local sent=0

  for f in "${files[@]}"; do
    local rel_path="${f#$base_dir/}"
    local rule_id="${source}:${rel_path//\//:}"
    local content
    content=$(cat "$f")

    # Escape for JSON
    local escaped
    escaped=$(python3 -c "import json,sys; print(json.dumps(sys.stdin.read()))" <<< "$content")

    batch+=("{\"ruleId\":\"$rule_id\",\"ruleContent\":$escaped,\"source\":\"$source\",\"publishedAt\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}")

    if [ ${#batch[@]} -ge $BATCH_SIZE ]; then
      local json_arr
      json_arr=$(printf '%s,' "${batch[@]}")
      json_arr="[${json_arr%,}]"

      local resp
      resp=$(curl -s -X POST "$TC/api/rules" \
        -H "Content-Type: application/json" \
        --max-time 120 \
        -d "{\"rules\":$json_arr}")

      sent=$((sent + ${#batch[@]}))
      echo "    Uploaded $sent / $count ($source)"
      batch=()
    fi
  done

  # Send remaining
  if [ ${#batch[@]} -gt 0 ]; then
    local json_arr
    json_arr=$(printf '%s,' "${batch[@]}")
    json_arr="[${json_arr%,}]"

    curl -s -X POST "$TC/api/rules" \
      -H "Content-Type: application/json" \
      --max-time 120 \
      -d "{\"rules\":$json_arr}" > /dev/null

    sent=$((sent + ${#batch[@]}))
    echo "    Uploaded $sent / $count ($source)"
  fi

  TOTAL=$((TOTAL + sent))
}

echo "=== Sigma Rules ==="
seed_batch "sigma" "$CONFIG_DIR/sigma-rules" "yml|yaml" "$CONFIG_DIR/sigma-rules"

echo ""
echo "=== YARA Rules ==="
seed_batch "yara" "$CONFIG_DIR/yara-rules" "yar|yara" "$CONFIG_DIR/yara-rules"

echo ""
echo "=== ATR Rules ==="
seed_batch "atr" "$ATR_DIR" "yaml|yml" "$ATR_DIR"

echo ""
echo "========================================="
echo "  Total seeded: $TOTAL rules"
echo "========================================="

echo ""
echo "Verifying..."
curl -s "$TC/api/stats" | python3 -m json.tool
