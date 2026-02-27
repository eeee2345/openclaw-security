/**
 * One-click Install Script Generator
 * 一鍵安裝腳本生成器
 *
 * Generates platform-specific install scripts for PanguardGuard:
 * - macOS/Linux: Bash script
 * - Windows: PowerShell script
 *
 * @module @panguard-ai/panguard-guard/install
 */

import { platform } from 'node:os';
import { createLogger } from '@panguard-ai/core';

const logger = createLogger('panguard-guard:install');

/**
 * Generate a platform-appropriate install script
 * 產生適合平台的安裝腳本
 *
 * @param options - Install options / 安裝選項
 * @returns The install script content / 安裝腳本內容
 */
export function generateInstallScript(options: {
  dataDir?: string;
  licenseKey?: string;
  autoStart?: boolean;
}): string {
  const os = platform();

  switch (os) {
    case 'darwin':
    case 'linux':
      return generateBashScript(options);
    case 'win32':
      return generatePowerShellScript(options);
    default:
      logger.warn(`Unsupported platform: ${os} / 不支援的平台`);
      return generateBashScript(options);
  }
}

/**
 * Generate bash install script for macOS/Linux
 * 產生 macOS/Linux 的 bash 安裝腳本
 */
function generateBashScript(options: {
  dataDir?: string;
  licenseKey?: string;
  autoStart?: boolean;
}): string {
  const dataDir = options.dataDir ?? '$HOME/.panguard-guard';
  const autoStart = options.autoStart ?? true;

  return `#!/usr/bin/env bash
# PanguardGuard Security - Install Script
# PanguardGuard 安全 - 安裝腳本
# Generated: ${new Date().toISOString()}
set -euo pipefail

echo "========================================="
echo " PanguardGuard Security - Installation"
echo "========================================="

# Check Node.js version / 檢查 Node.js 版本
NODE_VERSION=$(node --version 2>/dev/null || echo "none")
if [ "$NODE_VERSION" = "none" ]; then
  echo "ERROR: Node.js is required. Please install Node.js 18+ first."
  echo "Visit: https://nodejs.org/"
  exit 1
fi
echo "Node.js: $NODE_VERSION"

# Check npm/pnpm / 檢查 npm/pnpm
if command -v pnpm &>/dev/null; then
  PKG_MGR="pnpm"
elif command -v npm &>/dev/null; then
  PKG_MGR="npm"
else
  echo "ERROR: npm or pnpm is required."
  exit 1
fi
echo "Package manager: $PKG_MGR"

# Create data directory / 建立資料目錄
DATA_DIR="${dataDir}"
mkdir -p "$DATA_DIR"
mkdir -p "$DATA_DIR/rules"
mkdir -p "$DATA_DIR/logs"
echo "Data directory: $DATA_DIR"

# Install PanguardGuard / 安裝 PanguardGuard
echo "Installing @panguard-ai/panguard-guard..."
$PKG_MGR install -g @panguard-ai/panguard-guard

# Create default config / 建立預設配置
CONFIG_FILE="$DATA_DIR/config.json"
if [ ! -f "$CONFIG_FILE" ]; then
  cat > "$CONFIG_FILE" << 'CONFIGEOF'
{
  "lang": "zh-TW",
  "mode": "learning",
  "learningDays": 7,
  "actionPolicy": { "autoRespond": 85, "notifyAndWait": 50, "logOnly": 0 },
  "notifications": {},
  "dataDir": "${dataDir}",
  "dashboardPort": 3743,
  "dashboardEnabled": true,
  "verbose": false,
  "monitors": {
    "logMonitor": true,
    "networkMonitor": true,
    "processMonitor": true,
    "fileMonitor": true,
    "networkPollInterval": 5000,
    "processPollInterval": 10000
  },
  "watchdogEnabled": true,
  "watchdogInterval": 30000${options.licenseKey ? `,\n  "licenseKey": "${options.licenseKey}"` : ''}
}
CONFIGEOF
  echo "Default config created: $CONFIG_FILE"
fi

${
  autoStart
    ? `# Install as service / 安裝為服務
echo "Installing as system service..."
panguard-guard install

echo ""
echo "========================================="
echo " PanguardGuard installed successfully!"
echo " Dashboard: http://localhost:3743"
echo " Data dir:  $DATA_DIR"
echo " Status:    panguard-guard status"
echo "========================================="`
    : `echo ""
echo "========================================="
echo " PanguardGuard installed successfully!"
echo " Start:     panguard-guard start"
echo " Dashboard: http://localhost:3743"
echo "========================================="`
}
`;
}

/**
 * Generate PowerShell install script for Windows
 * 產生 Windows 的 PowerShell 安裝腳本
 */
function generatePowerShellScript(options: {
  dataDir?: string;
  licenseKey?: string;
  autoStart?: boolean;
}): string {
  const dataDir = options.dataDir ?? '$env:USERPROFILE\\.panguard-guard';
  const autoStart = options.autoStart ?? true;

  return `# PanguardGuard Security - Install Script (Windows)
# PanguardGuard 安全 - 安裝腳本 (Windows)
# Generated: ${new Date().toISOString()}
#Requires -RunAsAdministrator

Write-Host "========================================="
Write-Host " PanguardGuard Security - Installation"
Write-Host "========================================="

# Check Node.js / 檢查 Node.js
try {
    $nodeVersion = node --version
    Write-Host "Node.js: $nodeVersion"
} catch {
    Write-Host "ERROR: Node.js is required. Please install Node.js 18+ first."
    Write-Host "Visit: https://nodejs.org/"
    exit 1
}

# Create data directory / 建立資料目錄
$dataDir = "${dataDir}"
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
New-Item -ItemType Directory -Force -Path "$dataDir\\rules" | Out-Null
New-Item -ItemType Directory -Force -Path "$dataDir\\logs" | Out-Null
Write-Host "Data directory: $dataDir"

# Install PanguardGuard / 安裝 PanguardGuard
Write-Host "Installing @panguard-ai/panguard-guard..."
npm install -g @panguard-ai/panguard-guard

# Create default config / 建立預設配置
$configFile = "$dataDir\\config.json"
if (-not (Test-Path $configFile)) {
    $config = @{
        lang = "zh-TW"
        mode = "learning"
        learningDays = 7
        actionPolicy = @{ autoRespond = 85; notifyAndWait = 50; logOnly = 0 }
        notifications = @{}
        dataDir = $dataDir
        dashboardPort = 3743
        dashboardEnabled = $true
        verbose = $false
        monitors = @{
            logMonitor = $true
            networkMonitor = $true
            processMonitor = $true
            fileMonitor = $true
            networkPollInterval = 5000
            processPollInterval = 10000
        }
        watchdogEnabled = $true
        watchdogInterval = 30000${options.licenseKey ? `\n        licenseKey = "${options.licenseKey}"` : ''}
    }
    $config | ConvertTo-Json -Depth 5 | Set-Content $configFile
    Write-Host "Default config created: $configFile"
}

${
  autoStart
    ? `# Install as service / 安裝為服務
Write-Host "Installing as Windows service..."
panguard-guard install

Write-Host ""
Write-Host "========================================="
Write-Host " PanguardGuard installed successfully!"
Write-Host " Dashboard: http://localhost:3743"
Write-Host " Data dir:  $dataDir"
Write-Host " Status:    panguard-guard status"
Write-Host "========================================="`
    : `Write-Host ""
Write-Host "========================================="
Write-Host " PanguardGuard installed successfully!"
Write-Host " Start:     panguard-guard start"
Write-Host " Dashboard: http://localhost:3743"
Write-Host "========================================="`
}
`;
}
