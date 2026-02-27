/**
 * Security tool detection
 * 安全工具偵測
 *
 * Detects installed and running security tools (antivirus, EDR, firewall,
 * IDS, SIEM) by checking running processes, known service names, and
 * common installation paths.
 * 透過檢查執行中的行程、已知服務名稱和常見安裝路徑，偵測已安裝和執行中的安全工具
 * （防毒、EDR、防火牆、IDS、SIEM）。
 *
 * @module @panguard-ai/core/discovery/security-tools
 */

import { execFile } from 'child_process';
import { promisify } from 'util';
import { platform as osPlatform } from 'os';
import { access } from 'fs/promises';
import { createLogger } from '../utils/logger.js';
import type { SecurityTool, SecurityToolType, ServiceInfo } from './types.js';

const execFileAsync = promisify(execFile);
const logger = createLogger('discovery:security-tools');

/**
 * Known security tool definition for matching against running processes
 * 已知安全工具定義，用於比對執行中行程
 */
interface KnownSecurityTool {
  /** Tool name / 工具名稱 */
  name: string;
  /** Vendor name / 廠商名稱 */
  vendor: string;
  /** Process names to match / 要比對的行程名稱 */
  processNames: string[];
  /** Service name to match / 要比對的服務名稱 */
  serviceName?: string;
  /** Tool category / 工具類別 */
  type: SecurityToolType;
  /** Common install paths (platform-specific) / 常見安裝路徑（平台特定） */
  installPaths?: string[];
}

/**
 * Database of known security tools and their identifiers
 * 已知安全工具及其識別碼的資料庫
 */
const KNOWN_SECURITY_TOOLS: KnownSecurityTool[] = [
  {
    name: 'Windows Defender',
    vendor: 'Microsoft',
    processNames: ['MsMpEng.exe', 'MpCmdRun.exe', 'NisSrv.exe', 'SecurityHealthService.exe'],
    serviceName: 'WinDefend',
    type: 'antivirus',
    installPaths: ['C:\\Program Files\\Windows Defender'],
  },
  {
    name: 'Wazuh',
    vendor: 'Wazuh Inc.',
    processNames: ['wazuh-agentd', 'wazuh-execd', 'wazuh-modulesd', 'ossec-agentd'],
    serviceName: 'wazuh-agent',
    type: 'siem',
    installPaths: ['/var/ossec', '/Library/Ossec'],
  },
  {
    name: 'CrowdStrike Falcon',
    vendor: 'CrowdStrike',
    processNames: ['falcond', 'falcon-sensor', 'CSFalconService.exe', 'CSFalconContainer'],
    serviceName: 'CSFalconService',
    type: 'edr',
    installPaths: ['/opt/CrowdStrike', '/Library/CS', 'C:\\Program Files\\CrowdStrike'],
  },
  {
    name: 'Sophos',
    vendor: 'Sophos',
    processNames: [
      'SophosScanD',
      'SophosAntiVirus',
      'savscand',
      'SophosCleanM.exe',
      'SophosHealth.exe',
    ],
    serviceName: 'Sophos Anti-Virus',
    type: 'antivirus',
    installPaths: ['/opt/sophos-av', '/Library/Sophos Anti-Virus', 'C:\\Program Files\\Sophos'],
  },
  {
    name: 'Trend Micro',
    vendor: 'Trend Micro',
    processNames: ['ds_agent', 'dsa_query', 'coreServiceShell', 'PccNTMon.exe', 'TMBMSRV.exe'],
    serviceName: 'ds_agent',
    type: 'antivirus',
    installPaths: ['/opt/ds_agent', 'C:\\Program Files\\Trend Micro'],
  },
  {
    name: 'Kaspersky',
    vendor: 'Kaspersky',
    processNames: ['klnagent', 'avp', 'avp.exe', 'kavfswh.exe'],
    serviceName: 'klnagent',
    type: 'antivirus',
    installPaths: ['C:\\Program Files\\Kaspersky Lab', 'C:\\Program Files (x86)\\Kaspersky Lab'],
  },
  {
    name: 'Malwarebytes',
    vendor: 'Malwarebytes',
    processNames: ['MBAMService', 'mbamservice.exe', 'RTProtectionDaemon'],
    serviceName: 'MBAMService',
    type: 'antivirus',
    installPaths: ['/Library/Application Support/Malwarebytes', 'C:\\Program Files\\Malwarebytes'],
  },
  {
    name: 'ESET',
    vendor: 'ESET',
    processNames: ['esets_daemon', 'ekrn.exe', 'egui.exe', 'essod'],
    serviceName: 'esets_daemon',
    type: 'antivirus',
    installPaths: ['/opt/eset', 'C:\\Program Files\\ESET'],
  },
  {
    name: 'pfSense',
    vendor: 'Netgate',
    processNames: ['pf', 'pflogd', 'pfctl'],
    type: 'firewall',
    installPaths: ['/usr/local/sbin/pfctl'],
  },
  {
    name: 'Fortinet FortiClient',
    vendor: 'Fortinet',
    processNames: ['forticlient', 'FortiClient.exe', 'FortiTray.exe', 'FCDBLog.exe'],
    serviceName: 'FortiClientMonitor',
    type: 'edr',
    installPaths: ['/opt/forticlient', 'C:\\Program Files\\Fortinet'],
  },
  {
    name: 'Snort',
    vendor: 'Cisco',
    processNames: ['snort'],
    serviceName: 'snort',
    type: 'ids',
    installPaths: ['/usr/local/bin/snort', '/usr/sbin/snort'],
  },
  {
    name: 'Suricata',
    vendor: 'OISF',
    processNames: ['suricata'],
    serviceName: 'suricata',
    type: 'ids',
    installPaths: ['/usr/bin/suricata', '/usr/local/bin/suricata'],
  },
  {
    name: 'OSSEC',
    vendor: 'OSSEC Foundation',
    processNames: ['ossec-analysisd', 'ossec-syscheckd', 'ossec-remoted'],
    serviceName: 'ossec',
    type: 'ids',
    installPaths: ['/var/ossec'],
  },
  {
    name: 'ClamAV',
    vendor: 'ClamAV',
    processNames: ['clamd', 'freshclam', 'clamdscan'],
    serviceName: 'clamav-daemon',
    type: 'antivirus',
    installPaths: ['/usr/bin/clamscan', '/usr/local/bin/clamscan'],
  },
  {
    name: 'Splunk',
    vendor: 'Splunk',
    processNames: ['splunkd', 'splunk-optimize'],
    serviceName: 'Splunkd',
    type: 'siem',
    installPaths: ['/opt/splunk', '/opt/splunkforwarder', 'C:\\Program Files\\Splunk'],
  },
  {
    name: 'Elastic Agent',
    vendor: 'Elastic',
    processNames: ['elastic-agent', 'filebeat', 'metricbeat', 'auditbeat'],
    serviceName: 'elastic-agent',
    type: 'siem',
    installPaths: ['/opt/Elastic', 'C:\\Program Files\\Elastic'],
  },
  {
    name: 'Carbon Black',
    vendor: 'VMware',
    processNames: ['cbagentd', 'cbdaemon', 'CbDefense.exe'],
    serviceName: 'CbDefense',
    type: 'edr',
    installPaths: ['/opt/carbonblack', 'C:\\Program Files\\Confer'],
  },
  {
    name: 'SentinelOne',
    vendor: 'SentinelOne',
    processNames: ['sentinelone-agent', 'SentinelAgent.exe', 'sentineld'],
    serviceName: 'SentinelAgent',
    type: 'edr',
    installPaths: ['/opt/sentinelone', 'C:\\Program Files\\SentinelOne'],
  },
];

/**
 * Safely execute a command and return stdout, or empty string on failure
 * 安全地執行命令並回傳 stdout，失敗時回傳空字串
 *
 * @param cmd - Command to execute / 要執行的命令
 * @param args - Command arguments / 命令參數
 * @returns stdout output trimmed / 修剪後的 stdout 輸出
 */
async function safeExec(cmd: string, args: string[]): Promise<string> {
  try {
    const { stdout } = await execFileAsync(cmd, args, { timeout: 10_000 });
    return stdout.trim();
  } catch (err) {
    logger.debug(`Command failed: ${cmd} ${args.join(' ')}`, {
      error: err instanceof Error ? err.message : String(err),
    });
    return '';
  }
}

/**
 * Get list of currently running process names
 * 取得目前執行中的行程名稱列表
 *
 * @returns Set of lowercase process names / 小寫行程名稱集合
 */
async function getRunningProcesses(): Promise<Set<string>> {
  const processes = new Set<string>();
  const currentPlatform = osPlatform();

  try {
    let output = '';

    switch (currentPlatform) {
      case 'darwin':
      case 'linux':
        output = await safeExec('ps', ['aux']);
        break;
      case 'win32':
        output = await safeExec('tasklist', ['/FO', 'CSV', '/NH']);
        break;
      default:
        return processes;
    }

    if (!output) return processes;

    const lines = output.split('\n');

    for (const line of lines) {
      if (currentPlatform === 'win32') {
        // CSV format: "process.exe","PID",...
        // CSV 格式："process.exe","PID",...
        const match = line.match(/^"([^"]+)"/);
        if (match?.[1]) {
          processes.add(match[1].toLowerCase());
        }
      } else {
        // Unix ps aux format: USER PID ... COMMAND
        // Unix ps aux 格式：USER PID ... COMMAND
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 11) {
          const cmd = parts[10] ?? '';
          // Extract just the binary name from the full path
          // 從完整路徑中僅擷取二進位檔案名稱
          const binaryName = cmd.split('/').pop()?.split('\\').pop() ?? '';
          if (binaryName) {
            processes.add(binaryName.toLowerCase());
          }
        }
      }
    }
  } catch (err) {
    logger.error('Failed to enumerate running processes', {
      error: err instanceof Error ? err.message : String(err),
    });
  }

  return processes;
}

/**
 * Check if a file/directory exists at the given path
 * 檢查給定路徑是否存在檔案/目錄
 *
 * @param filePath - Path to check / 要檢查的路徑
 * @returns Whether the path exists / 路徑是否存在
 */
async function pathExists(filePath: string): Promise<boolean> {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

/**
 * Detect installed and running security tools on the system
 * 偵測系統上已安裝和執行中的安全工具
 *
 * Detection methods:
 * 1. Check running processes against known process names
 * 2. Check service list against known service names
 * 3. Check common installation paths
 * 偵測方法：
 * 1. 比對執行中行程與已知行程名稱
 * 2. 比對服務列表與已知服務名稱
 * 3. 檢查常見安裝路徑
 *
 * @param services - Previously detected services list / 先前偵測到的服務列表
 * @returns Array of detected security tools / 偵測到的安全工具陣列
 */
export async function detectSecurityTools(services: ServiceInfo[]): Promise<SecurityTool[]> {
  const detectedTools: SecurityTool[] = [];
  const processSet = await getRunningProcesses();

  logger.info(
    `Checking ${KNOWN_SECURITY_TOOLS.length} known security tools against ${processSet.size} running processes`
  );

  // Build a set of running service names for quick lookup
  // 建立執行中服務名稱集合以快速查找
  const runningServiceNames = new Set(
    services.filter((s) => s.status === 'running').map((s) => s.name.toLowerCase())
  );

  for (const tool of KNOWN_SECURITY_TOOLS) {
    let running = false;
    let foundViaProcess = false;
    let foundViaService = false;
    let foundViaPath = false;

    // Check 1: Running processes
    // 檢查 1：執行中行程
    for (const processName of tool.processNames) {
      if (processSet.has(processName.toLowerCase())) {
        running = true;
        foundViaProcess = true;
        break;
      }
    }

    // Check 2: Service names
    // 檢查 2：服務名稱
    if (!foundViaProcess && tool.serviceName) {
      if (runningServiceNames.has(tool.serviceName.toLowerCase())) {
        running = true;
        foundViaService = true;
      }
      // Also check if the service exists but isn't running
      // 同時檢查服務是否存在但未執行
      const matchingService = services.find(
        (s) => s.name.toLowerCase() === tool.serviceName!.toLowerCase()
      );
      if (matchingService && !foundViaService) {
        foundViaService = true;
        running = matchingService.status === 'running';
      }
    }

    // Check 3: Install paths
    // 檢查 3：安裝路徑
    if (!foundViaProcess && !foundViaService && tool.installPaths) {
      for (const installPath of tool.installPaths) {
        if (await pathExists(installPath)) {
          foundViaPath = true;
          break;
        }
      }
    }

    if (foundViaProcess || foundViaService || foundViaPath) {
      const detected: SecurityTool = {
        name: tool.name,
        vendor: tool.vendor,
        running,
        type: tool.type,
      };

      logger.info(
        `Detected security tool: ${tool.name} (${tool.vendor}) - ${running ? 'running' : 'installed but not running'}`,
        {
          detectedVia: foundViaProcess ? 'process' : foundViaService ? 'service' : 'path',
        }
      );

      detectedTools.push(detected);
    }
  }

  logger.info(`Total security tools detected: ${detectedTools.length}`);
  return detectedTools;
}
