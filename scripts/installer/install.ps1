# Panguard AI Installer for Windows
# Usage: irm https://get.panguard.ai/windows | iex
#        or: powershell -ExecutionPolicy Bypass -File install.ps1
#
# Downloads a prebuilt binary from GitHub Releases.
# Falls back to source build if no prebuilt binary is available.

$ErrorActionPreference = "Stop"

# ── Repository & Release URLs ────────────────────────────────────
$RepoUrl = "https://github.com/panguard-ai/panguard-ai.git"
$FallbackRepo = "https://github.com/eeee2345/Panguard-AI.git"
$ReleaseBase = "https://github.com/panguard-ai/panguard-ai/releases"

# ── Install paths ────────────────────────────────────────────────
$InstallDir = Join-Path $env:USERPROFILE ".panguard"
$BinDir = Join-Path $InstallDir "bin"
$MinNodeVersion = 20

# ── Logging helpers ──────────────────────────────────────────────
function Write-Info  { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Blue }
function Write-Ok    { param($msg) Write-Host "[ OK ] $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Fail  { param($msg) Write-Host "[FAIL] $msg" -ForegroundColor Red; exit 1 }

# ── Header ───────────────────────────────────────────────────────
Write-Host ""
Write-Host "  Panguard AI Installer" -ForegroundColor White
Write-Host "  =====================" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  AI-driven adaptive cybersecurity platform" -ForegroundColor DarkGray
Write-Host ""

# ── Step 1: Detect Architecture ──────────────────────────────────
$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
Write-Info "Detected: Windows $arch"

# Windows builds use npm install (no prebuilt tarball yet)
# For future: win-x64 tarball support
$Platform = "win-x64"

# ── Step 2: Check Node.js >= 20 ─────────────────────────────────
try {
    $nodeVersion = (node -v) -replace 'v', ''
    $nodeMajor = [int]($nodeVersion.Split('.')[0])
    if ($nodeMajor -lt $MinNodeVersion) {
        Write-Fail "Node.js v${MinNodeVersion}+ is required. Current version: v$nodeVersion. Please upgrade at https://nodejs.org"
    }
    Write-Ok "Node.js v$nodeVersion"
} catch {
    Write-Fail "Node.js is required but not installed. Install Node.js v${MinNodeVersion}+ from https://nodejs.org or run: winget install OpenJS.NodeJS.LTS"
}

# ── Step 3: Try npm global install (preferred for Windows) ───────
$NpmInstalled = $false

Write-Info "Installing Panguard AI via npm..."
try {
    npm install -g @panguard-ai/panguard 2>$null
    $NpmInstalled = $true
    Write-Ok "Panguard AI installed via npm"
} catch {
    Write-Warn "npm install failed. Trying source build..."
}

# ── Step 4 (Fallback): Source build ──────────────────────────────
if (-not $NpmInstalled) {
    $SourceDir = Join-Path $InstallDir "source"

    # Check git
    try {
        $gitVersion = (git --version) -replace 'git version ', ''
        Write-Ok "git $gitVersion"
    } catch {
        Write-Fail "git is required for source build. Install git from https://git-scm.com"
    }

    # Check pnpm
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

    # Clone or update repository
    if (Test-Path (Join-Path $SourceDir ".git")) {
        Write-Info "Existing source found. Updating..."
        Push-Location $SourceDir
        try {
            git fetch origin 2>$null
            git reset --hard origin/main 2>$null
            Write-Ok "Repository updated"
        } catch {
            Write-Warn "git update failed, continuing with existing code"
        }
        Pop-Location
    } else {
        if (Test-Path $SourceDir) {
            Remove-Item -Recurse -Force $SourceDir
        }

        $parentDir = Split-Path $SourceDir -Parent
        if (-not (Test-Path $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }

        Write-Info "Cloning from $RepoUrl..."
        $cloned = $false
        try {
            git clone --depth 1 $RepoUrl $SourceDir 2>$null
            $cloned = $true
        } catch {}

        if (-not $cloned) {
            Write-Warn "Primary repository not available, trying fallback..."
            try {
                git clone --depth 1 $FallbackRepo $SourceDir 2>$null
                $cloned = $true
            } catch {}
        }

        if (-not $cloned) {
            Write-Fail "Could not clone repository. Check your internet connection and try again."
        }
        Write-Ok "Repository cloned to $SourceDir"
    }

    # Build
    Push-Location $SourceDir

    Write-Info "Installing dependencies (this may take a minute)..."
    try {
        pnpm install --frozen-lockfile 2>$null
    } catch {
        try { pnpm install } catch { Write-Fail "Failed to install dependencies" }
    }
    Write-Ok "Dependencies installed"

    Write-Info "Building project..."
    try { pnpm build } catch { Write-Fail "Build failed. Please report this issue at $RepoUrl/issues" }
    Write-Ok "Build complete"

    Pop-Location

    # Create bin wrapper
    if (-not (Test-Path $BinDir)) {
        New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
    }

    $wrapperPath = Join-Path $BinDir "panguard.cmd"
    $jsEntry = Join-Path $SourceDir "packages\panguard\dist\cli\index.js"
    @"
@echo off
node "$jsEntry" %*
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
}

# ── Step 5: Verify installation ──────────────────────────────────
Write-Host ""
Write-Info "Verifying installation..."

try {
    panguard --help 2>$null | Out-Null
    Write-Ok "panguard CLI is working"
} catch {
    Write-Warn "panguard exists but --help failed. The build may be incomplete."
}

# ── Quick Start Guide ────────────────────────────────────────────
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
