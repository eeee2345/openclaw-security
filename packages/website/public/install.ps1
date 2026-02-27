# Panguard AI Installer for Windows
# Usage: irm https://get.panguard.ai/windows | iex
#        or: powershell -ExecutionPolicy Bypass -File install.ps1
#
# Installs Panguard AI from GitHub source.
# Clones the repository, builds the project, and adds it to PATH.

$ErrorActionPreference = "Stop"

# ── Repository URLs ──────────────────────────────────────────────────
$RepoUrl = "https://github.com/panguard-ai/panguard-ai.git"
$FallbackRepo = "https://github.com/eeee2345/Panguard-AI.git"

# ── Install paths ────────────────────────────────────────────────────
$InstallDir = Join-Path $env:USERPROFILE ".panguard\source"
$BinDir = Join-Path $env:USERPROFILE ".panguard\bin"
$MinNodeVersion = 18

# ── Logging helpers ──────────────────────────────────────────────────
function Write-Info  { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Blue }
function Write-Ok    { param($msg) Write-Host "[ OK ] $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Fail  { param($msg) Write-Host "[FAIL] $msg" -ForegroundColor Red; exit 1 }

# ── Header ───────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  Panguard AI Installer" -ForegroundColor White
Write-Host "  =====================" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  AI-driven adaptive cybersecurity platform" -ForegroundColor DarkGray
Write-Host ""

# ── Step 1: Check OS ─────────────────────────────────────────────────
$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
Write-Info "Detected: Windows $arch"

# ── Step 2: Check Node.js >= 18 ─────────────────────────────────────
try {
    $nodeVersion = (node -v) -replace 'v', ''
    $nodeMajor = [int]($nodeVersion.Split('.')[0])
    if ($nodeMajor -lt $MinNodeVersion) {
        Write-Fail "Node.js v${MinNodeVersion}+ is required. Current version: v$nodeVersion. Please upgrade at https://nodejs.org"
    }
    Write-Ok "Node.js v$nodeVersion"
} catch {
    Write-Fail "Node.js is required but not installed. Install Node.js v${MinNodeVersion}+ from https://nodejs.org"
}

# ── Step 3: Check git ────────────────────────────────────────────────
try {
    $gitVersion = (git --version) -replace 'git version ', ''
    Write-Ok "git $gitVersion"
} catch {
    Write-Fail "git is required but not installed. Install git from https://git-scm.com"
}

# ── Step 4: Check pnpm (install if missing) ──────────────────────────
try {
    $pnpmVersion = pnpm --version
    Write-Ok "pnpm $pnpmVersion"
} catch {
    Write-Info "pnpm not found. Installing pnpm globally via npm..."
    try {
        npm install -g pnpm
        $pnpmVersion = pnpm --version
        Write-Ok "pnpm $pnpmVersion installed"
    } catch {
        Write-Fail "Failed to install pnpm. Try running: npm install -g pnpm"
    }
}

# ── Step 5: Clone or update repository ───────────────────────────────
if (Test-Path (Join-Path $InstallDir ".git")) {
    Write-Info "Existing installation found at $InstallDir. Updating..."
    Push-Location $InstallDir
    try {
        git fetch origin 2>$null
        git reset --hard origin/main 2>$null
        Write-Ok "Repository updated"
    } catch {
        Write-Warn "git update failed, continuing with existing code"
    }
    Pop-Location
} else {
    if (Test-Path $InstallDir) {
        Remove-Item -Recurse -Force $InstallDir
    }

    $parentDir = Split-Path $InstallDir -Parent
    if (-not (Test-Path $parentDir)) {
        New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
    }

    Write-Info "Cloning from $RepoUrl..."
    $cloned = $false
    try {
        git clone --depth 1 $RepoUrl $InstallDir 2>$null
        $cloned = $true
    } catch {}

    if (-not $cloned) {
        Write-Warn "Primary repository not available, trying fallback..."
        try {
            git clone --depth 1 $FallbackRepo $InstallDir 2>$null
            $cloned = $true
        } catch {}
    }

    if (-not $cloned) {
        Write-Fail "Could not clone repository. Check your internet connection and try again."
    }
    Write-Ok "Repository cloned to $InstallDir"
}

# ── Step 6: Build the project ────────────────────────────────────────
Push-Location $InstallDir

Write-Info "Installing dependencies (this may take a minute)..."
try {
    pnpm install --frozen-lockfile 2>$null
} catch {
    try {
        pnpm install
    } catch {
        Write-Fail "Failed to install dependencies"
    }
}
Write-Ok "Dependencies installed"

Write-Info "Building project..."
try {
    pnpm build
} catch {
    Write-Fail "Build failed. Please report this issue at $RepoUrl/issues"
}
Write-Ok "Build complete"

Pop-Location

# ── Step 7: Create bin wrapper and add to PATH ───────────────────────
if (-not (Test-Path $BinDir)) {
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
}

$wrapperPath = Join-Path $BinDir "panguard.cmd"
$binSource = Join-Path $InstallDir "bin\panguard"
@"
@echo off
node "$binSource" %*
"@ | Set-Content -Path $wrapperPath -Encoding ASCII

# Add to user PATH if not already present
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($userPath -notlike "*$BinDir*") {
    Write-Info "Adding $BinDir to user PATH..."
    [Environment]::SetEnvironmentVariable("PATH", "$userPath;$BinDir", "User")
    $env:PATH = "$env:PATH;$BinDir"
    Write-Ok "Added to PATH (restart your terminal for changes to take effect)"
} else {
    Write-Ok "Already in PATH"
}

# ── Step 8: Verify installation ──────────────────────────────────────
Write-Host ""
Write-Info "Verifying installation..."

try {
    & $wrapperPath --help 2>$null | Out-Null
    Write-Ok "panguard CLI is working"
} catch {
    Write-Warn "panguard exists but --help failed. The build may be incomplete."
}

# ── Quick Start Guide ────────────────────────────────────────────────
Write-Host ""
Write-Host "  Quick Start" -ForegroundColor White
Write-Host "  ===========" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  # Run a security scan on the current directory"
Write-Host "  panguard scan"
Write-Host ""
Write-Host "  # Start real-time file protection"
Write-Host "  panguard guard start"
Write-Host ""
Write-Host "  # Check protection status"
Write-Host "  panguard guard status"
Write-Host ""
Write-Host "  # Get help"
Write-Host "  panguard --help"
Write-Host ""
Write-Host "  Documentation: https://panguard.ai/docs" -ForegroundColor DarkGray
Write-Host "  Report issues: https://github.com/panguard-ai/panguard-ai/issues" -ForegroundColor DarkGray
Write-Host ""
Write-Ok "Installation complete!"
