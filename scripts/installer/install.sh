#!/usr/bin/env bash
# Panguard AI Installer
# Usage: curl -fsSL https://get.panguard.ai | bash
#        or: bash install.sh
#
# Downloads a prebuilt binary from GitHub Releases.
# Falls back to source build if no prebuilt binary is available.
#
# Functions are defined inline so the script is self-contained (works
# when piped via curl|bash). A matching install-functions.sh contains
# only the function definitions for unit-testing.

set -euo pipefail

# ── Repository & Release URLs ────────────────────────────────────
REPO_URL="https://github.com/panguard-ai/panguard-ai"
RELEASE_BASE="https://github.com/panguard-ai/panguard-ai/releases"
FALLBACK_URL="https://github.com/panguard-ai/panguard-ai/archive/refs/heads/main.zip"

# ── Install paths ────────────────────────────────────────────────
INSTALL_DIR="${HOME}/.panguard"
BIN_DIR="${HOME}/.local/bin"
SYMLINK_TARGET="/usr/local/bin/panguard"
MIN_NODE_VERSION=20

# ── Colors ───────────────────────────────────────────────────────
: "${RED:='\033[0;31m'}"
: "${GREEN:='\033[0;32m'}"
: "${YELLOW:='\033[1;33m'}"
: "${BLUE:='\033[0;34m'}"
: "${BOLD:='\033[1m'}"
: "${DIM:='\033[2m'}"
: "${NC:='\033[0m'}"

# ── Logging helpers ──────────────────────────────────────────────
info()    { printf "${BLUE}[INFO]${NC} %s\n" "$1"; }
success() { printf "${GREEN}[ OK ]${NC} %s\n" "$1"; }
warn()    { printf "${YELLOW}[WARN]${NC} %s\n" "$1"; }
fail()    { printf "${RED}[FAIL]${NC} %s\n" "$1" >&2; exit 1; }

# ── print_header() ───────────────────────────────────────────────
print_header() {
  echo ""
  echo -e "  ${BOLD}Panguard AI Installer${NC}"
  echo -e "  ${DIM}=====================${NC}"
  echo ""
  echo -e "  ${DIM}AI-driven adaptive cybersecurity platform${NC}"
  echo ""
}

# ── detect_platform() ───────────────────────────────────────────
# Sets: PLATFORM_OS, PLATFORM_ARCH, PLATFORM
# Returns 0 on success, exits 1 on unsupported OS/arch.
detect_platform() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"

  SKIP_BINARY_DOWNLOAD=false
  info "Detected: ${os} ${arch}"

  case "$os" in
    Darwin)  PLATFORM_OS="darwin" ;;
    Linux)   PLATFORM_OS="linux" ;;
    MINGW*|MSYS*|CYGWIN*)
      warn "Windows detected. Please use WSL (Windows Subsystem for Linux) for full functionality."
      PLATFORM_OS="linux"
      ;;
    *)
      fail "Unsupported OS: ${os}. Panguard AI supports macOS and Linux."
      ;;
  esac

  case "$arch" in
    x86_64|amd64)  PLATFORM_ARCH="x64" ;;
    arm64|aarch64) PLATFORM_ARCH="arm64" ;;
    *) fail "Unsupported architecture: ${arch}. Panguard supports x86_64 and arm64. Report at ${REPO_URL}/issues" ;;
  esac

  PLATFORM="${PLATFORM_OS}-${PLATFORM_ARCH}"
  info "Platform: ${PLATFORM}"
  return 0
}

# ── detect_musl() ────────────────────────────────────────────────
# Sets SKIP_BINARY_DOWNLOAD=true if musl libc is detected.
# Returns 0 if musl detected, 1 otherwise.
detect_musl() {
  if [ "$PLATFORM_OS" = "linux" ] && (ldd --version 2>&1 | grep -qi musl); then
    warn "Detected Alpine/musl Linux. Prebuilt binaries may not work."
    info "Will use npm install method instead of prebuilt binary."
    SKIP_BINARY_DOWNLOAD=true
    return 0
  fi
  return 1
}

# ── check_node_version() ────────────────────────────────────────
# Takes optional min_version arg (default: $MIN_NODE_VERSION).
# Exits 1 with message if node is missing or too old.
check_node_version() {
  local min_ver="${1:-$MIN_NODE_VERSION}"

  if ! command -v node &>/dev/null; then
    fail "Node.js is required but not installed. Install v${min_ver}+ from https://nodejs.org"
  fi

  NODE_OUTPUT=$(node -v 2>/dev/null || echo "unknown")
  NODE_VERSION=$(echo "$NODE_OUTPUT" | grep -oE '^v?[0-9]+' | grep -oE '[0-9]+' || echo "0")

  if ! [[ "$NODE_VERSION" =~ ^[0-9]+$ ]] || [ "$NODE_VERSION" -lt "$min_ver" ]; then
    fail "Node.js v${min_ver}+ is required. Current: ${NODE_OUTPUT}. Please upgrade at https://nodejs.org"
  fi
  success "Node.js ${NODE_OUTPUT}"
}

# ── backup_existing() ───────────────────────────────────────────
backup_existing() {
  if [ -f "${INSTALL_DIR}/bin/panguard" ]; then
    local existing_ver
    existing_ver=$("${INSTALL_DIR}/bin/panguard" --version 2>/dev/null || echo "unknown")
    info "Existing installation found: v${existing_ver}. Creating backup..."
    mv "$INSTALL_DIR" "${INSTALL_DIR}.backup.$(date +%s)"
  fi
}

# ── download_file() ─────────────────────────────────────────────
# Usage: download_file <url> <dest>
# Uses curl or wget. Exits 1 on failure.
download_file() {
  local url="$1"
  local dest="$2"

  if command -v curl &>/dev/null; then
    local http_code
    http_code=$(curl -fsSL -w "%{http_code}" -o "$dest" "$url" 2>/dev/null) || {
      fail "curl failed to download: ${url}"
    }
    if [ "$http_code" -ge 400 ]; then
      fail "Download failed with HTTP ${http_code}: ${url}"
    fi
  elif command -v wget &>/dev/null; then
    wget -q -O "$dest" "$url" 2>/dev/null || fail "wget failed to download: ${url}"
  else
    fail "Neither curl nor wget found. Install one to proceed."
  fi
}

# ── verify_checksum() ───────────────────────────────────────────
# Usage: verify_checksum <file_path> <checksums_file> <expected_name>
# Returns 0 on success (verified or skipped), exits 1 on mismatch.
verify_checksum() {
  local file_path="$1"
  local checksums_file="$2"
  local expected_name="$3"

  if command -v sha256sum &>/dev/null; then
    local expected_hash
    expected_hash=$(grep "$expected_name" "$checksums_file" 2>/dev/null | awk '{print $1}')
    if [ -n "$expected_hash" ]; then
      local actual_hash
      actual_hash=$(sha256sum "$file_path" | awk '{print $1}')
      if [ "$actual_hash" = "$expected_hash" ]; then
        success "Checksum verified"
        return 0
      else
        fail "Checksum mismatch for ${expected_name}. Expected: ${expected_hash}  Got: ${actual_hash}"
      fi
    else
      warn "No checksum entry found for ${expected_name} in SHA256SUMS.txt. Skipping verification."
      return 0
    fi
  elif command -v shasum &>/dev/null; then
    local expected_hash
    expected_hash=$(grep "$expected_name" "$checksums_file" 2>/dev/null | awk '{print $1}')
    if [ -n "$expected_hash" ]; then
      local actual_hash
      actual_hash=$(shasum -a 256 "$file_path" | awk '{print $1}')
      if [ "$actual_hash" = "$expected_hash" ]; then
        success "Checksum verified"
        return 0
      else
        fail "Checksum mismatch for ${expected_name}. Expected: ${expected_hash}  Got: ${actual_hash}"
      fi
    else
      warn "No checksum entry found for ${expected_name} in SHA256SUMS.txt. Skipping verification."
      return 0
    fi
  else
    warn "Neither sha256sum nor shasum found. Skipping checksum verification."
    return 0
  fi
}

# ── download_binary() ───────────────────────────────────────────
# Downloads prebuilt binary, verifies checksum, and extracts.
# Returns 0 on success, 1 if binary download was skipped.
download_binary() {
  if [ "$SKIP_BINARY_DOWNLOAD" = "true" ]; then
    return 1
  fi

  local version="${PANGUARD_VERSION:-latest}"
  local download_url checksum_url

  if [ "$version" = "latest" ]; then
    download_url="${RELEASE_BASE}/latest/download/panguard-${PLATFORM}.tar.gz"
    checksum_url="${RELEASE_BASE}/latest/download/SHA256SUMS.txt"
  else
    download_url="${RELEASE_BASE}/download/${version}/panguard-${PLATFORM}.tar.gz"
    checksum_url="${RELEASE_BASE}/download/${version}/SHA256SUMS.txt"
  fi

  info "Downloading prebuilt binary for ${PLATFORM}..."
  info "URL: ${download_url}"

  mkdir -p "$INSTALL_DIR"

  local tmp_tarball
  tmp_tarball="$(mktemp /tmp/panguard-XXXXXX.tar.gz)"
  local tmp_checksums
  tmp_checksums="$(mktemp /tmp/panguard-SHA256SUMS-XXXXXX.txt)"

  # Trap to clean up temp files on exit/error
  trap 'rm -f "$tmp_tarball" "$tmp_checksums"' EXIT

  # Download the tarball to a temp file
  download_file "$download_url" "$tmp_tarball"

  # Verify tarball is non-empty
  if [ ! -s "$tmp_tarball" ]; then
    fail "Downloaded tarball is empty or corrupted: ${download_url}"
  fi

  # Attempt checksum verification
  local tarball_name="panguard-${PLATFORM}.tar.gz"
  if download_file "$checksum_url" "$tmp_checksums" 2>/dev/null; then
    verify_checksum "$tmp_tarball" "$tmp_checksums" "$tarball_name"
  else
    warn "SHA256SUMS.txt not available for this release. Skipping checksum verification."
  fi

  # Extract the verified tarball
  if ! tar -xzf "$tmp_tarball" -C "$INSTALL_DIR" 2>/dev/null; then
    fail "Failed to extract tarball. The file may be corrupted: ${download_url}"
  fi

  rm -f "$tmp_tarball" "$tmp_checksums"
  trap - EXIT
  return 0
}

# ── clone_from_git() ─────────────────────────────────────────────
clone_from_git() {
  local url="$1"
  local dest="$2"
  info "Cloning from ${url}..."
  git clone --depth 1 "$url" "$dest" 2>/dev/null
}

# ── clone_from_zip() ────────────────────────────────────────────
clone_from_zip() {
  local dest="$1"
  info "Downloading source archive from ${FALLBACK_URL}..."

  local tmp_zip
  tmp_zip="$(mktemp /tmp/panguard-src-XXXXXX.zip)"
  download_file "$FALLBACK_URL" "$tmp_zip"

  if ! command -v unzip &>/dev/null; then
    rm -f "$tmp_zip"
    fail "unzip is required to extract source archive. Install unzip and try again."
  fi

  local tmp_extract
  tmp_extract="$(mktemp -d /tmp/panguard-src-extract-XXXXXX)"
  unzip -q "$tmp_zip" -d "$tmp_extract" || fail "Failed to extract source archive."

  # The zip produces a single top-level directory; move its contents to dest
  local extracted_dir
  extracted_dir="$(ls -d "${tmp_extract}"/*/  2>/dev/null | head -1)"
  if [ -z "$extracted_dir" ]; then
    rm -rf "$tmp_zip" "$tmp_extract"
    fail "Unexpected structure in source archive."
  fi

  mkdir -p "$(dirname "$dest")"
  mv "$extracted_dir" "$dest"
  rm -rf "$tmp_zip" "$tmp_extract"
  success "Source archive extracted to ${dest}"
}

# ── build_from_source() ─────────────────────────────────────────
build_from_source() {
  local source_dir="${INSTALL_DIR}/source"

  # Check git
  if ! command -v git &>/dev/null; then
    fail "git is required for source build. Install git from https://git-scm.com"
  fi
  success "git $(git --version | awk '{print $3}')"

  # Check pnpm (install if missing)
  if ! command -v pnpm &>/dev/null; then
    info "pnpm not found. Installing pnpm globally via npm..."
    if ! command -v npm &>/dev/null; then
      fail "npm is required to install pnpm but was not found."
    fi
    npm install -g pnpm || fail "Failed to install pnpm. Try running: npm install -g pnpm"
    if ! command -v pnpm &>/dev/null; then
      fail "pnpm was installed but cannot be found in PATH. You may need to restart your shell."
    fi
    success "pnpm installed successfully"
  else
    success "pnpm $(pnpm --version)"
  fi

  # Clone or update repository
  if [ -d "$source_dir/.git" ]; then
    info "Existing source found. Updating..."
    cd "$source_dir"
    git fetch origin 2>/dev/null || warn "git fetch failed, continuing with existing code"
    git reset --hard origin/main 2>/dev/null || git reset --hard origin/master 2>/dev/null || warn "git reset failed"
    success "Repository updated"
  else
    [ -d "$source_dir" ] && rm -rf "$source_dir"
    mkdir -p "$(dirname "$source_dir")"

    if ! clone_from_git "${REPO_URL}.git" "$source_dir"; then
      warn "git clone failed. Trying source archive fallback..."
      clone_from_zip "$source_dir"
    else
      success "Repository cloned to ${source_dir}"
    fi
  fi

  # Build
  cd "$source_dir"
  info "Installing dependencies (this may take a minute)..."
  pnpm install --frozen-lockfile 2>/dev/null || pnpm install || fail "Failed to install dependencies"
  success "Dependencies installed"

  info "Building project..."
  pnpm build || fail "Build failed. Please report this issue at ${REPO_URL}/issues"
  success "Build complete"
}

# ── setup_path() ─────────────────────────────────────────────────
# Usage: setup_path <bin_source> <symlink_target> <bin_dir>
# Creates a symlink or falls back to PATH addition.
setup_path() {
  local bin_source="${1}"
  local symlink_target="${2}"
  local bin_dir="${3}"

  if [ ! -f "$bin_source" ]; then
    fail "CLI entry point not found at ${bin_source}. The build may have failed."
  fi

  chmod +x "$bin_source"

  # Prefer user-local bin dir (no sudo required) over system-wide symlink
  local symlink_created=false

  # First try user-local ~/.local/bin (no sudo)
  if mkdir -p "$bin_dir" 2>/dev/null; then
    if ln -sf "$bin_source" "${bin_dir}/panguard" 2>/dev/null; then
      success "Installed to ${bin_dir}/panguard (no sudo required)"
      symlink_created=true
    fi
  fi

  # If user-local failed, try system-wide symlink
  if [ "$symlink_created" = "false" ]; then
    info "Creating symlink at ${symlink_target}..."
    if ln -sf "$bin_source" "$symlink_target" 2>/dev/null; then
      success "Symlink created at ${symlink_target}"
      symlink_created=true
    else
      warn "Permission denied. Requesting sudo to create symlink..."
      if sudo ln -sf "$bin_source" "$symlink_target" 2>/dev/null; then
        success "Symlink created at ${symlink_target} (with sudo)"
        symlink_created=true
      fi
    fi
  fi

  if [ "$symlink_created" = "false" ]; then
    warn "Could not create symlink. Adding ${bin_dir} to shell profiles..."
    mkdir -p "$bin_dir"
    ln -sf "$bin_source" "${bin_dir}/panguard" 2>/dev/null || \
      cp "$bin_source" "${bin_dir}/panguard" 2>/dev/null || \
      warn "Could not copy binary to ${bin_dir}."

    local export_line="export PATH=\"${bin_dir}:\$PATH\""
    local profiles_updated=()
    for profile in "${HOME}/.zshrc" "${HOME}/.zprofile" "${HOME}/.bashrc" "${HOME}/.bash_profile" "${HOME}/.profile"; do
      if [ -f "$profile" ]; then
        if ! grep -qF "$bin_dir" "$profile" 2>/dev/null; then
          printf '\n# Added by Panguard AI installer\n%s\n' "$export_line" >> "$profile"
          profiles_updated+=("$profile")
        fi
      fi
    done

    # On macOS with zsh, create .zprofile if no profile was found
    if [ "${#profiles_updated[@]}" -eq 0 ]; then
      local default_profile
      if [ "$(uname -s)" = "Darwin" ]; then
        default_profile="${HOME}/.zprofile"
      else
        default_profile="${HOME}/.bashrc"
      fi
      printf '\n# Added by Panguard AI installer\n%s\n' "$export_line" >> "$default_profile"
      profiles_updated+=("$default_profile")
      info "Created ${default_profile} with PATH entry"
    fi

    if [ "${#profiles_updated[@]}" -gt 0 ]; then
      success "Added ${bin_dir} to PATH in: ${profiles_updated[*]}"
      warn "Restart your terminal (or run: source ~/.zprofile / source ~/.bashrc) for PATH changes to take effect."
    else
      warn "Could not update any shell profile. Add the following line manually:"
      echo ""
      echo "  ${export_line}"
      echo ""
    fi
  fi
}

# ── verify_installation() ───────────────────────────────────────
verify_installation() {
  local bin_source="$1"

  echo ""
  info "Verifying installation..."

  if command -v panguard &>/dev/null; then
    local installed_ver
    installed_ver=$(panguard --version 2>/dev/null || echo "")
    if [ -n "$installed_ver" ]; then
      success "panguard v${installed_ver} installed and verified"
    else
      fail "panguard is in PATH but cannot execute. Check Node.js installation."
    fi
  elif [ -x "$bin_source" ]; then
    local installed_ver
    installed_ver=$("$bin_source" --version 2>/dev/null || echo "")
    if [ -n "$installed_ver" ]; then
      success "panguard v${installed_ver} installed (via direct path)"
    else
      fail "panguard binary exists but cannot execute. Check Node.js installation."
    fi
  else
    fail "Installation verification failed. Binary not found."
  fi
}

# ── print_quickstart() ──────────────────────────────────────────
print_quickstart() {
  echo ""
  echo -e "  ${BOLD}Quick Start${NC}"
  echo -e "  ${DIM}===========${NC}"
  echo ""
  echo "  # Run a security scan on the current directory"
  echo "  panguard scan"
  echo ""
  echo "  # Start real-time file protection"
  echo "  panguard guard start"
  echo ""
  echo "  # Check protection status"
  echo "  panguard guard status"
  echo ""
  echo "  # Get help"
  echo "  panguard --help"
  echo ""
  echo -e "  ${DIM}Documentation: https://panguard.ai/docs${NC}"
  echo -e "  ${DIM}Report issues: ${REPO_URL}/issues${NC}"
  echo ""
  success "Installation complete!"
}

# ── Main ─────────────────────────────────────────────────────────
main() {
  print_header
  detect_platform
  detect_musl || true  # musl detection is informational, not fatal
  check_node_version
  backup_existing

  BINARY_INSTALLED=false
  if download_binary; then
    success "Prebuilt binary installed to ${INSTALL_DIR}"
    BINARY_INSTALLED=true
  else
    warn "No prebuilt binary available for ${PLATFORM}. Falling back to source build..."
    build_from_source
  fi

  # Determine binary location
  local bin_source
  if [ "$BINARY_INSTALLED" = "true" ]; then
    bin_source="${INSTALL_DIR}/bin/panguard"
  else
    bin_source="${INSTALL_DIR}/source/bin/panguard"
  fi

  setup_path "$bin_source" "$SYMLINK_TARGET" "$BIN_DIR"
  verify_installation "$bin_source"
  print_quickstart
}

# Run main only when executed directly (not when sourced for testing).
# - Direct execution: BASH_SOURCE[0] == $0
# - curl|bash piping: BASH_SOURCE[0] is empty, $0 is "bash" -- use env var fallback
# - Sourced by tests: BASH_SOURCE[0] != $0 and PANGUARD_INSTALLER_RUN is unset
if [[ "${BASH_SOURCE[0]:-}" == "$0" ]] || [[ -z "${BASH_SOURCE[0]:-}" ]] || [[ "${PANGUARD_INSTALLER_RUN:-}" == "1" ]]; then
  main "$@"
fi
