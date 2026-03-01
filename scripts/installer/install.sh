#!/usr/bin/env bash
# Panguard AI Installer
# Usage: curl -fsSL https://get.panguard.ai | bash
#        or: bash install.sh
#
# Downloads a prebuilt binary from GitHub Releases.
# Falls back to source build if no prebuilt binary is available.

set -euo pipefail

# ── Repository & Release URLs ────────────────────────────────────
REPO_URL="https://github.com/panguard-ai/panguard-ai.git"
FALLBACK_REPO="https://github.com/eeee2345/Panguard-AI.git"
RELEASE_BASE="https://github.com/panguard-ai/panguard-ai/releases"

# ── Install paths ────────────────────────────────────────────────
INSTALL_DIR="${HOME}/.panguard"
SYMLINK_TARGET="/usr/local/bin/panguard"
MIN_NODE_VERSION=20

# ── Colors ───────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ── Logging helpers ──────────────────────────────────────────────
info()    { printf "${BLUE}[INFO]${NC} %s\n" "$1"; }
success() { printf "${GREEN}[ OK ]${NC} %s\n" "$1"; }
warn()    { printf "${YELLOW}[WARN]${NC} %s\n" "$1"; }
fail()    { printf "${RED}[FAIL]${NC} %s\n" "$1" >&2; exit 1; }

# ── Header ───────────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}Panguard AI Installer${NC}"
echo -e "  ${DIM}=====================${NC}"
echo ""
echo -e "  ${DIM}AI-driven adaptive cybersecurity platform${NC}"
echo ""

# ── Step 1: Detect OS & Architecture ────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"
info "Detected: ${OS} ${ARCH}"

case "$OS" in
  Darwin)  PLATFORM_OS="darwin" ;;
  Linux)   PLATFORM_OS="linux" ;;
  MINGW*|MSYS*|CYGWIN*)
    warn "Windows detected. Please use WSL (Windows Subsystem for Linux) for full functionality."
    PLATFORM_OS="linux"
    ;;
  *)
    fail "Unsupported OS: ${OS}. Panguard AI supports macOS and Linux."
    ;;
esac

case "$ARCH" in
  x86_64|amd64)  PLATFORM_ARCH="x64" ;;
  arm64|aarch64) PLATFORM_ARCH="arm64" ;;
  *)
    warn "Unknown architecture: ${ARCH}. Trying x64."
    PLATFORM_ARCH="x64"
    ;;
esac

PLATFORM="${PLATFORM_OS}-${PLATFORM_ARCH}"
info "Platform: ${PLATFORM}"

# ── Step 2: Check Node.js >= 20 ─────────────────────────────────
if ! command -v node &>/dev/null; then
  fail "Node.js is required but not installed. Install Node.js v${MIN_NODE_VERSION}+ from https://nodejs.org"
fi

NODE_VERSION=$(node -v | sed 's/v//' | cut -d. -f1)
if [ "$NODE_VERSION" -lt "$MIN_NODE_VERSION" ]; then
  fail "Node.js v${MIN_NODE_VERSION}+ is required. Current version: $(node -v). Please upgrade at https://nodejs.org"
fi
success "Node.js $(node -v)"

# ── Step 3: Download prebuilt binary ─────────────────────────────
VERSION="${PANGUARD_VERSION:-latest}"

if [ "$VERSION" = "latest" ]; then
  DOWNLOAD_URL="${RELEASE_BASE}/latest/download/panguard-${PLATFORM}.tar.gz"
else
  DOWNLOAD_URL="${RELEASE_BASE}/download/${VERSION}/panguard-${PLATFORM}.tar.gz"
fi

download_binary() {
  info "Downloading prebuilt binary for ${PLATFORM}..."
  info "URL: ${DOWNLOAD_URL}"

  mkdir -p "$INSTALL_DIR"

  # Prefer curl, fall back to wget
  if command -v curl &>/dev/null; then
    if curl -fsSL "$DOWNLOAD_URL" | tar -xz -C "$INSTALL_DIR"; then
      return 0
    fi
  elif command -v wget &>/dev/null; then
    if wget -qO- "$DOWNLOAD_URL" | tar -xz -C "$INSTALL_DIR"; then
      return 0
    fi
  else
    warn "Neither curl nor wget found."
    return 1
  fi

  return 1
}

# Try binary download first
BINARY_INSTALLED=false
if download_binary; then
  success "Prebuilt binary installed to ${INSTALL_DIR}"
  BINARY_INSTALLED=true
else
  warn "No prebuilt binary available for ${PLATFORM}. Falling back to source build..."
fi

# ── Step 4 (Fallback): Source build ──────────────────────────────
if [ "$BINARY_INSTALLED" = "false" ]; then
  SOURCE_DIR="${INSTALL_DIR}/source"

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
  clone_repo() {
    local url="$1"
    info "Cloning from ${url}..."
    git clone --depth 1 "$url" "$SOURCE_DIR" 2>/dev/null
  }

  if [ -d "$SOURCE_DIR/.git" ]; then
    info "Existing source found. Updating..."
    cd "$SOURCE_DIR"
    git fetch origin 2>/dev/null || warn "git fetch failed, continuing with existing code"
    git reset --hard origin/main 2>/dev/null || git reset --hard origin/master 2>/dev/null || warn "git reset failed"
    success "Repository updated"
  else
    [ -d "$SOURCE_DIR" ] && rm -rf "$SOURCE_DIR"
    mkdir -p "$(dirname "$SOURCE_DIR")"

    if ! clone_repo "$REPO_URL"; then
      warn "Primary repository not available, trying fallback..."
      if ! clone_repo "$FALLBACK_REPO"; then
        fail "Could not clone repository. Check your internet connection and try again."
      fi
    fi
    success "Repository cloned to ${SOURCE_DIR}"
  fi

  # Build
  cd "$SOURCE_DIR"
  info "Installing dependencies (this may take a minute)..."
  pnpm install --frozen-lockfile 2>/dev/null || pnpm install || fail "Failed to install dependencies"
  success "Dependencies installed"

  info "Building project..."
  pnpm build || fail "Build failed. Please report this issue at ${REPO_URL}/issues"
  success "Build complete"
fi

# ── Step 5: Create symlink ───────────────────────────────────────
if [ "$BINARY_INSTALLED" = "true" ]; then
  BIN_SOURCE="${INSTALL_DIR}/bin/panguard"
else
  BIN_SOURCE="${INSTALL_DIR}/source/bin/panguard"
fi

if [ ! -f "$BIN_SOURCE" ]; then
  fail "CLI entry point not found at ${BIN_SOURCE}. The build may have failed."
fi

chmod +x "$BIN_SOURCE"

info "Creating symlink at ${SYMLINK_TARGET}..."

if ln -sf "$BIN_SOURCE" "$SYMLINK_TARGET" 2>/dev/null; then
  success "Symlink created at ${SYMLINK_TARGET}"
else
  warn "Permission denied. Requesting sudo to create symlink..."
  if sudo ln -sf "$BIN_SOURCE" "$SYMLINK_TARGET"; then
    success "Symlink created at ${SYMLINK_TARGET} (with sudo)"
  else
    warn "Could not create symlink at ${SYMLINK_TARGET}."
    warn "You can add the following to your shell profile instead:"
    echo ""
    echo "  export PATH=\"$(dirname "$BIN_SOURCE"):\$PATH\""
    echo ""
  fi
fi

# ── Step 6: Verify installation ──────────────────────────────────
echo ""
info "Verifying installation..."

if command -v panguard &>/dev/null; then
  panguard --help >/dev/null 2>&1 && success "panguard CLI is working" || warn "panguard is in PATH but --help failed."
elif [ -x "$BIN_SOURCE" ]; then
  "$BIN_SOURCE" --help >/dev/null 2>&1 && success "panguard CLI is working (via direct path)" || warn "panguard exists but --help failed."
else
  warn "Could not verify panguard installation."
fi

# ── Quick Start Guide ────────────────────────────────────────────
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
echo -e "  ${DIM}Report issues: ${REPO_URL%.git}/issues${NC}"
echo ""
success "Installation complete!"
