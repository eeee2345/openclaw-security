/**
 * Discovery scanner - orchestrates all core discovery functions
 * 偵察掃描器 - 編排所有核心偵察功能
 *
 * Calls all discovery functions from @openclaw/core sequentially to build
 * a complete DiscoveryResult representing the current system's security posture.
 * 依序呼叫 @openclaw/core 中的所有偵察功能，建構代表目前系統安全態勢的完整 DiscoveryResult。
 *
 * @module @openclaw/panguard-scan/scanners/discovery-scanner
 */

import { execSync } from 'node:child_process';
import {
  detectOS,
  getNetworkInterfaces,
  scanOpenPorts,
  getActiveConnections,
  getGateway,
  getDnsServersAsync,
  detectServices,
  detectSecurityTools,
  checkFirewall,
  auditUsers,
  calculateRiskScore,
  createLogger,
  type DiscoveryResult,
  type DiscoveryConfig,
} from '@openclaw/core';

const logger = createLogger('panguard-scan:discovery');

/**
 * Detect pending system updates based on platform.
 * Returns { pendingUpdates, autoUpdateEnabled }.
 */
function detectUpdateStatus(): { pendingUpdates: number; autoUpdateEnabled: boolean } {
  try {
    const platform = process.platform;

    if (platform === 'darwin') {
      // macOS: check Software Update
      const output = execSync('softwareupdate -l 2>&1', { timeout: 10000 }).toString();
      const matches = output.match(/\* /g);
      const pending = matches ? matches.length : 0;
      // Check if auto-update is enabled
      let autoEnabled = false;
      try {
        const autoOutput = execSync('defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null', { timeout: 5000 }).toString().trim();
        autoEnabled = autoOutput === '1';
      } catch {
        // Ignore — cannot determine auto-update status
      }
      return { pendingUpdates: pending, autoUpdateEnabled: autoEnabled };
    }

    if (platform === 'linux') {
      // Try apt (Debian/Ubuntu)
      try {
        const output = execSync('apt list --upgradable 2>/dev/null | grep -c upgradable', { timeout: 10000 }).toString().trim();
        const count = parseInt(output, 10);
        const autoEnabled = (() => {
          try {
            return execSync('systemctl is-enabled unattended-upgrades 2>/dev/null', { timeout: 5000 }).toString().trim() === 'enabled';
          } catch { return false; }
        })();
        return { pendingUpdates: isNaN(count) ? 0 : count, autoUpdateEnabled: autoEnabled };
      } catch { /* not apt-based */ }

      // Try yum/dnf (RHEL/CentOS/Fedora)
      try {
        const output = execSync('yum check-update 2>/dev/null | tail -n +3 | wc -l', { timeout: 10000 }).toString().trim();
        const count = parseInt(output, 10);
        return { pendingUpdates: isNaN(count) ? 0 : count, autoUpdateEnabled: false };
      } catch { /* not yum-based */ }
    }

    // Fallback: unknown
    return { pendingUpdates: 0, autoUpdateEnabled: false };
  } catch (err) {
    logger.warn('Failed to detect update status', { error: err instanceof Error ? err.message : String(err) });
    return { pendingUpdates: 0, autoUpdateEnabled: false };
  }
}

/**
 * Run a complete environment discovery scan
 * 執行完整的環境偵察掃描
 *
 * Orchestrates all core discovery functions sequentially to avoid overloading
 * system commands. In 'quick' mode, active connections are skipped.
 * 依序編排所有核心偵察功能以避免系統命令過載。在 'quick' 模式下，會跳過活躍連線偵測。
 *
 * @param config - Discovery configuration / 偵察配置
 * @returns Complete discovery result / 完整偵察結果
 */
export async function discover(config: DiscoveryConfig): Promise<DiscoveryResult> {
  logger.info('Starting environment discovery', { depth: config.depth, lang: config.lang });

  // Step 1: Detect operating system
  // 步驟 1：偵測作業系統
  logger.info('Detecting operating system');
  const os = await detectOS();

  // Step 2: Get network interfaces
  // 步驟 2：取得網路介面
  logger.info('Enumerating network interfaces');
  const interfaces = getNetworkInterfaces();

  // Step 3: Scan open ports
  // 步驟 3：掃描開放埠
  logger.info('Scanning open ports');
  const openPorts = await scanOpenPorts();

  // Step 4: Get active connections (skip in quick mode)
  // 步驟 4：取得活躍連線（快速模式下跳過）
  let activeConnections: Awaited<ReturnType<typeof getActiveConnections>> = [];
  if (config.depth === 'full') {
    logger.info('Getting active connections');
    activeConnections = await getActiveConnections();
  } else {
    logger.info('Skipping active connections in quick mode');
  }

  // Step 5: Get gateway
  // 步驟 5：取得閘道
  logger.info('Detecting default gateway');
  const gateway = await getGateway();

  // Step 6: Get DNS servers
  // 步驟 6：取得 DNS 伺服器
  logger.info('Detecting DNS servers');
  const dns = await getDnsServersAsync();

  // Step 7: Detect running services
  // 步驟 7：偵測執行中服務
  logger.info('Detecting running services');
  const services = await detectServices();

  // Step 8: Detect security tools
  // 步驟 8：偵測安全工具
  logger.info('Detecting security tools');
  const existingTools = await detectSecurityTools(services);

  // Step 9: Check firewall status
  // 步驟 9：檢查防火牆狀態
  logger.info('Checking firewall status');
  const firewall = await checkFirewall();

  // Step 10: Audit user accounts
  // 步驟 10：稽核使用者帳號
  logger.info('Auditing user accounts');
  const users = await auditUsers();

  // Step 10b: Detect system update status
  // 步驟 10b：偵測系統更新狀態
  logger.info('Detecting system update status');
  const updates = detectUpdateStatus();

  // Assemble partial result for risk scoring
  // 組裝部分結果用於風險評分
  const partialResult: Partial<DiscoveryResult> = {
    os,
    hostname: os.hostname,
    network: {
      interfaces,
      openPorts,
      activeConnections,
      gateway,
      dns,
    },
    openPorts,
    services,
    security: {
      existingTools,
      firewall,
      updates,
      users,
    },
  };

  // Step 11: Calculate risk score
  // 步驟 11：計算風險評分
  logger.info('Calculating risk score');
  const { riskScore, factors } = calculateRiskScore(partialResult);

  // Assemble complete DiscoveryResult
  // 組裝完整 DiscoveryResult
  const result: DiscoveryResult = {
    os,
    hostname: os.hostname,
    network: {
      interfaces,
      openPorts,
      activeConnections,
      gateway,
      dns,
    },
    openPorts,
    services,
    security: {
      existingTools,
      firewall,
      updates,
      users,
    },
    vulnerabilities: factors,
    riskScore,
    discoveredAt: new Date().toISOString(),
  };

  logger.info('Discovery complete', {
    riskScore,
    factorsCount: factors.length,
    portsCount: openPorts.length,
    servicesCount: services.length,
    usersCount: users.length,
  });

  return result;
}
