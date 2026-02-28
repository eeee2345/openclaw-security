#!/usr/bin/env bash
# dev-docs/update.sh — 開發文件自動更新
# 用法:
#   ./dev-docs/update.sh          # 更新全部
#   ./dev-docs/update.sh scan     # 只更新 scan
#   ./dev-docs/update.sh core     # 只更新 core
#   ./dev-docs/update.sh _project # 只更新專案層級文件
#   ./dev-docs/update.sh --stats  # 只顯示統計，不寫入

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DOCS="$ROOT/dev-docs"
TARGET="${1:-all}"
STATS_ONLY=false

ALL_PRODUCTS="core scan guard chat trap report threat-cloud auth cli website security-hardening"

if [[ "$TARGET" == "--stats" ]]; then
  STATS_ONLY=true
  TARGET="all"
fi

# --- 產品 → 路徑映射 (bash 3.2 相容) ---

pkg_path_for() {
  case "$1" in
    core)               echo "packages/core" ;;
    scan)               echo "packages/panguard-scan" ;;
    guard)              echo "packages/panguard-guard" ;;
    chat)               echo "packages/panguard-chat" ;;
    trap)               echo "packages/panguard-trap" ;;
    report)             echo "packages/panguard-report" ;;
    threat-cloud)       echo "packages/threat-cloud" ;;
    auth)               echo "packages/panguard-auth" ;;
    cli)                echo "packages/panguard" ;;
    website)            echo "packages/website" ;;
    security-hardening) echo "security-hardening" ;;
    *)                  echo "" ;;
  esac
}

# --- 工具函數 ---

count_lines() {
  local dir="$1"
  local ext="${2:-ts}"
  if [[ -d "$dir" ]]; then
    local result
    result=$(find "$dir" -name "*.${ext}" -not -path "*/node_modules/*" -not -path "*/dist/*" -print0 2>/dev/null | xargs -0 wc -l 2>/dev/null | tail -1 | awk '{print $1}')
    echo "${result:-0}"
  else
    echo "0"
  fi
}

count_files() {
  local dir="$1"
  local ext="${2:-ts}"
  if [[ -d "$dir" ]]; then
    find "$dir" -name "*.${ext}" -not -path "*/node_modules/*" -not -path "*/dist/*" 2>/dev/null | wc -l | tr -d ' '
  else
    echo "0"
  fi
}

count_test_files() {
  local dir="$1"
  if [[ -d "$dir" ]]; then
    find "$dir" \( -name "*.test.ts" -o -name "*.spec.ts" \) 2>/dev/null | wc -l | tr -d ' '
  else
    echo "0"
  fi
}

count_exports() {
  local index="$1"
  if [[ -f "$index" ]]; then
    grep -c "^export " "$index" 2>/dev/null || echo "0"
  else
    echo "0"
  fi
}

# BSD/GNU sed 相容
sed_inplace() {
  if sed --version 2>/dev/null | grep -q GNU; then
    sed -i -E "$@"
  else
    sed -i '' -E "$@"
  fi
}

# --- 單一產品更新 ---

update_product() {
  local name="$1"
  local pkg_path
  pkg_path=$(pkg_path_for "$name")

  if [[ -z "$pkg_path" ]]; then
    echo "  [SKIP] $name — 未知產品"
    return
  fi

  local full_path="$ROOT/$pkg_path"

  if [[ ! -d "$full_path" ]]; then
    echo "  [SKIP] $name — 路徑不存在: $pkg_path"
    return
  fi

  local src_dir="$full_path/src"
  local test_dir="$full_path/tests"
  [[ ! -d "$test_dir" ]] && test_dir="$full_path/test"

  local src_lines src_files test_files
  src_lines=$(count_lines "$src_dir")
  src_files=$(count_files "$src_dir")

  # website 包含 tsx
  if [[ "$name" == "website" ]]; then
    local tsx_lines tsx_files
    tsx_lines=$(count_lines "$src_dir" "tsx")
    tsx_files=$(count_files "$src_dir" "tsx")
    src_lines=$((src_lines + tsx_lines))
    src_files=$((src_files + tsx_files))
  fi

  test_files=$(count_test_files "$test_dir")

  local readme="$DOCS/$name/README.md"

  if $STATS_ONLY; then
    printf "  %-20s %6s 行 / %3s 檔 | %2s 測試\n" \
      "$name" "$src_lines" "$src_files" "$test_files"
    return
  fi

  # 更新 README 中的數據行
  if [[ -f "$readme" ]]; then
    sed_inplace "s/\\| 程式碼 \\| .* \\|/| 程式碼 | ${src_lines} 行 \\/ ${src_files} 檔 |/" "$readme"
    sed_inplace "s/\\| 測試 \\| .* \\|/| 測試 | ${test_files} 個測試檔 |/" "$readme"
    echo "  [OK] $name — ${src_lines} 行 / ${src_files} 檔 / ${test_files} 測試"
  else
    echo "  [SKIP] $name — README 不存在: $readme"
  fi
}

# --- 專案層級更新 ---

update_project() {
  if $STATS_ONLY; then
    echo "  [PROJECT] 統計模式不適用於 _project"
    return
  fi

  local total_lines=0
  local total_files=0
  local total_tests=0

  for name in $ALL_PRODUCTS; do
    local pkg_path
    pkg_path=$(pkg_path_for "$name")
    local full_path="$ROOT/$pkg_path"
    [[ ! -d "$full_path" ]] && continue

    local src_dir="$full_path/src"
    local test_dir="$full_path/tests"
    [[ ! -d "$test_dir" ]] && test_dir="$full_path/test"

    local lines files tests
    lines=$(count_lines "$src_dir")
    files=$(count_files "$src_dir")
    tests=$(count_test_files "$test_dir")

    if [[ "$name" == "website" ]]; then
      local tsx_l tsx_f
      tsx_l=$(count_lines "$src_dir" "tsx")
      tsx_f=$(count_files "$src_dir" "tsx")
      lines=$((lines + tsx_l))
      files=$((files + tsx_f))
    fi

    total_lines=$((total_lines + lines))
    total_files=$((total_files + files))
    total_tests=$((total_tests + tests))
  done

  local pkg_count
  pkg_count=$(find "$ROOT/packages" -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
  pkg_count=$((pkg_count - 1))
  [[ -d "$ROOT/security-hardening" ]] && pkg_count=$((pkg_count + 1))

  local readme="$DOCS/README.md"
  if [[ -f "$readme" ]]; then
    sed_inplace "s/\\| 總程式碼 \\| .* \\|/| 總程式碼 | ~${total_lines} 行 |/" "$readme"
    sed_inplace "s/\\| 套件數 \\| .* \\|/| 套件數 | ${pkg_count} |/" "$readme"
    sed_inplace "s/\\| 測試檔 \\| .* \\|/| 測試檔 | ${total_tests} 個 |/" "$readme"
    echo "  [OK] _project — 全專案 ${total_lines} 行 / ${total_files} 檔 / ${total_tests} 測試"
  fi
}

# --- 根 README 更新 ---

update_root_readme() {
  local readme="$DOCS/README.md"
  if [[ -f "$readme" ]]; then
    local today
    today=$(date +%Y-%m-%d)
    sed_inplace "s/\\| 最後更新 \\| .* \\|/| 最後更新 | ${today} |/" "$readme"
    echo "  [OK] README.md — 更新日期: $today"
  fi
}

# --- 驗證目標 ---

is_valid_target() {
  for name in $ALL_PRODUCTS; do
    [[ "$name" == "$1" ]] && return 0
  done
  return 1
}

# --- 主流程 ---

echo ""
echo "Panguard Dev Docs Updater"
echo "========================="
echo ""

if [[ "$TARGET" == "all" ]]; then
  echo "[1/3] 更新所有產品線..."
  for name in $ALL_PRODUCTS; do
    update_product "$name"
  done

  echo ""
  echo "[2/3] 更新專案層級..."
  update_project

  echo ""
  echo "[3/3] 更新根 README..."
  update_root_readme

elif [[ "$TARGET" == "_project" ]]; then
  echo "更新專案層級..."
  update_project
  update_root_readme

elif is_valid_target "$TARGET"; then
  echo "更新 $TARGET..."
  update_product "$TARGET"
  update_root_readme

else
  echo "錯誤: 未知目標 '$TARGET'"
  echo ""
  echo "可用目標:"
  echo "  all              更新全部"
  echo "  _project         更新專案層級統計"
  for name in $ALL_PRODUCTS; do
    printf "  %-18s %s\n" "$name" "$(pkg_path_for "$name")"
  done
  echo ""
  echo "選項:"
  echo "  --stats          只顯示統計，不寫入"
  exit 1
fi

echo ""
echo "完成!"
echo ""
