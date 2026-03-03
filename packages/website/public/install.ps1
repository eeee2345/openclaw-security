# Panguard AI Installer for Windows
# Usage: irm https://get.panguard.ai/windows | iex
# If blocked by execution policy, run:
#   powershell -ExecutionPolicy Bypass -Command "irm https://get.panguard.ai/windows | iex"
# Or set for current user: Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
#
# Installation order:
#   1. Try prebuilt binary from GitHub Releases
#   2. Fall back to npm global install
#   3. Fall back to source build (git clone or zip archive)

$ErrorActionPreference = "Stop"

# ── Repository & Release URLs ────────────────────────────────────
$RepoUrl     = "https://github.com/panguard-ai/panguard-ai"
$FallbackUrl = "https://github.com/panguard-ai/panguard-ai/archive/refs/heads/main.zip"
$ReleaseBase = "https://github.com/panguard-ai/panguard-ai/releases"

# ── Install paths ────────────────────────────────────────────────
$InstallDir  = Join-Path $env:USERPROFILE ".panguard"
$BinDir      = Join-Path $InstallDir "bin"
$MinNodeVersion = 20

# ── Logging helpers ──────────────────────────────────────────────
function Write-Info { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Blue }
function Write-Ok   { param($msg) Write-Host "[ OK ] $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Fail { param($msg) Write-Host "[FAIL] $msg" -ForegroundColor Red; exit 1 }
function Write-Step { param($msg) Write-Host "[STEP] $msg" -ForegroundColor Cyan }

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

$SkipBinaryDownload = $false

switch ($arch) {
    "X64"   { $Platform = "win-x64" }
    "Arm64" {
        $Platform = "win-arm64"
        Write-Warn "Windows ARM64 detected. Prebuilt binary may not be available."
        $SkipBinaryDownload = $true
    }
    default { Write-Fail "Unsupported architecture: $arch. Panguard supports x64 and arm64." }
}

# ── Step 2: Check Node.js >= 20 ─────────────────────────────────
try {
    $nodeOutput = (node -v 2>$null)
    if (-not $nodeOutput) { throw "node not found" }
    if ($nodeOutput -match '^v?(\d+)') {
        $nodeMajor = [int]$matches[1]
    } else {
        throw "Could not parse Node.js version: $nodeOutput"
    }
    if ($nodeMajor -lt $MinNodeVersion) {
        Write-Fail "Node.js v${MinNodeVersion}+ is required. Current: $nodeOutput. Install: winget install OpenJS.NodeJS.LTS"
    }
    Write-Ok "Node.js $nodeOutput"
} catch {
    Write-Fail "Node.js is required but not installed. Install: winget install OpenJS.NodeJS.LTS`nOr download from https://nodejs.org"
}

# ── Step 3: Backup existing installation if present ─────────────
if (Test-Path "$InstallDir\bin\panguard.cmd") {
    try {
        $existingVer = & "$InstallDir\bin\panguard.cmd" --version 2>$null
        Write-Info "Existing installation found: v$existingVer. Creating backup..."
        $backupDir = "$InstallDir.backup.$(Get-Date -Format 'yyyyMMddHHmmss')"
        Move-Item $InstallDir $backupDir
    } catch {
        Write-Warn "Could not backup existing installation"
    }
}

# ── Step 4: Try prebuilt binary from GitHub Releases ─────────────
$BinaryInstalled = $false

if (-not $SkipBinaryDownload) {
    $version = if ($env:PANGUARD_VERSION) { $env:PANGUARD_VERSION } else { "latest" }

    if ($version -eq "latest") {
        $downloadUrl  = "$ReleaseBase/latest/download/panguard-${Platform}.zip"
        $checksumUrl  = "$ReleaseBase/latest/download/SHA256SUMS.txt"
    } else {
        $downloadUrl  = "$ReleaseBase/download/${version}/panguard-${Platform}.zip"
        $checksumUrl  = "$ReleaseBase/download/${version}/SHA256SUMS.txt"
    }

    Write-Info "Downloading prebuilt binary for ${Platform}..."
    Write-Info "URL: $downloadUrl"

    $tmpZip = Join-Path $env:TEMP "panguard-$Platform-$(Get-Date -Format 'yyyyMMddHHmmss').zip"
    $tmpChecksums = Join-Path $env:TEMP "panguard-SHA256SUMS-$(Get-Date -Format 'yyyyMMddHHmmss').txt"

    try {
        $response = Invoke-WebRequest -Uri $downloadUrl -OutFile $tmpZip -UseBasicParsing -PassThru
        if ($response.StatusCode -ge 400) {
            throw "HTTP $($response.StatusCode)"
        }

        # Verify the zip is non-empty
        $fileInfo = Get-Item $tmpZip
        if ($fileInfo.Length -eq 0) {
            throw "Downloaded file is empty"
        }

        # Attempt checksum verification
        try {
            Invoke-WebRequest -Uri $checksumUrl -OutFile $tmpChecksums -UseBasicParsing
            $expectedName = "panguard-${Platform}.zip"
            $checksumLine = (Get-Content $tmpChecksums | Where-Object { $_ -match $expectedName }) | Select-Object -First 1
            if ($checksumLine) {
                $expectedHash = ($checksumLine -split '\s+')[0]
                $actualHash = (Get-FileHash -Path $tmpZip -Algorithm SHA256).Hash.ToLower()
                if ($actualHash -eq $expectedHash.ToLower()) {
                    Write-Ok "Checksum verified"
                } else {
                    throw "Checksum mismatch. Expected: $expectedHash Got: $actualHash"
                }
            } else {
                Write-Warn "No checksum entry for $expectedName. Skipping verification."
            }
        } catch {
            if ($_.Exception.Message -match "Checksum mismatch") {
                throw $_
            }
            Write-Warn "SHA256SUMS.txt not available. Skipping checksum verification."
        }

        # Extract
        if (-not (Test-Path $InstallDir)) {
            New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        }
        Expand-Archive -Path $tmpZip -DestinationPath $InstallDir -Force
        $BinaryInstalled = $true
        Write-Ok "Prebuilt binary installed to $InstallDir"
    } catch {
        Write-Warn "Prebuilt binary not available for ${Platform}: $($_.Exception.Message)"
        Write-Info "Falling back to npm install..."
    } finally {
        Remove-Item -Force $tmpZip -ErrorAction SilentlyContinue
        Remove-Item -Force $tmpChecksums -ErrorAction SilentlyContinue
    }
}

# ── Step 5: Fall back to npm global install ──────────────────────
$NpmInstalled = $false

if (-not $BinaryInstalled) {
    Write-Info "Installing Panguard AI via npm..."
    try {
        npm install -g @panguard-ai/panguard 2>$null
        $NpmInstalled = $true
        Write-Ok "Panguard AI installed via npm"
    } catch {
        Write-Warn "npm global install failed. Trying source build..."
    }
}

# ── Step 6 (Fallback): Source build ──────────────────────────────
if ((-not $BinaryInstalled) -and (-not $NpmInstalled)) {
    $SourceDir = Join-Path $InstallDir "source"

    # Check git
    $GitAvailable = $false
    try {
        $gitVersion = (git --version) -replace 'git version ', ''
        Write-Ok "git $gitVersion"
        $GitAvailable = $true
    } catch {
        Write-Warn "git not found. Will use zip download fallback."
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

    # Obtain source: git clone or zip fallback
    $SourceObtained = $false

    if ($GitAvailable) {
        if (Test-Path (Join-Path $SourceDir ".git")) {
            Write-Info "Existing source found. Updating..."
            Push-Location $SourceDir
            try {
                git fetch origin 2>$null
                git reset --hard origin/main 2>$null
                Write-Ok "Repository updated"
                $SourceObtained = $true
            } catch {
                Write-Warn "git update failed, continuing with existing code"
                $SourceObtained = $true
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
            try {
                git clone --depth 1 "${RepoUrl}.git" $SourceDir 2>$null
                $SourceObtained = $true
                Write-Ok "Repository cloned to $SourceDir"
            } catch {
                Write-Warn "git clone failed. Trying zip archive fallback..."
            }
        }
    }

    if (-not $SourceObtained) {
        Write-Info "Downloading source archive from $FallbackUrl..."
        $zipPath = Join-Path $env:TEMP "panguard-ai-main.zip"
        $extractPath = Join-Path $env:TEMP "panguard-ai-main"
        try {
            Invoke-WebRequest -Uri $FallbackUrl -OutFile $zipPath -UseBasicParsing
            if (Test-Path $extractPath) {
                Remove-Item -Recurse -Force $extractPath
            }
            Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
            $innerDir = Join-Path $extractPath "panguard-ai-main"
            if (-not (Test-Path $innerDir)) {
                $innerDir = $extractPath
            }
            $parentDir = Split-Path $SourceDir -Parent
            if (-not (Test-Path $parentDir)) {
                New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
            }
            if (Test-Path $SourceDir) {
                Remove-Item -Recurse -Force $SourceDir
            }
            Move-Item $innerDir $SourceDir
            $SourceObtained = $true
            Write-Ok "Source archive extracted to $SourceDir"
        } catch {
            Write-Fail "Could not obtain source code. Check your internet connection and try again."
        } finally {
            Remove-Item -Force $zipPath -ErrorAction SilentlyContinue
            Remove-Item -Recurse -Force $extractPath -ErrorAction SilentlyContinue
        }
    }

    # Build
    Push-Location $SourceDir

    Write-Info "Installing dependencies (this may take a minute)..."
    try {
        pnpm install --frozen-lockfile 2>$null
    } catch {
        try { pnpm install } catch {
            Pop-Location
            Write-Fail "Failed to install dependencies"
        }
    }
    Write-Ok "Dependencies installed"

    Write-Info "Building project..."
    try { pnpm build } catch {
        Pop-Location
        Write-Fail "Build failed. Please report this issue at $RepoUrl/issues"
    }
    Write-Ok "Build complete"

    Pop-Location

    # Create bin wrapper (relative paths)
    if (-not (Test-Path $BinDir)) {
        New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
    }

    $wrapperPath = Join-Path $BinDir "panguard.cmd"
    $wrapperContent = @"
@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
set "JS_ENTRY=%SCRIPT_DIR%..\source\packages\panguard\dist\cli\index.js"
if not exist "%JS_ENTRY%" (
    echo Error: panguard installation appears corrupted.
    exit /b 1
)
node "%JS_ENTRY%" %*
"@
    Set-Content -Path $wrapperPath -Value $wrapperContent -Encoding ASCII

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

# ── Step 7: Verify installation ──────────────────────────────────
Write-Host ""
Write-Step "Verifying installation..."

# Try global command first, then local wrapper
$verified = $false
try {
    $version = (panguard --version 2>$null)
    if ($version) {
        Write-Ok "panguard v$version installed and verified"
        $verified = $true
    }
} catch {}

if (-not $verified) {
    $localCmd = Join-Path $BinDir "panguard.cmd"
    if (Test-Path $localCmd) {
        try {
            $version = (& $localCmd --version 2>$null)
            if ($version) {
                Write-Ok "panguard v$version installed and verified (via local path)"
                Write-Warn "Restart your terminal for the 'panguard' command to be available globally."
                $verified = $true
            }
        } catch {}
    }
}

if (-not $verified) {
    Write-Fail "Installation verification failed. panguard cannot execute.`nCheck Node.js installation and PATH."
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
