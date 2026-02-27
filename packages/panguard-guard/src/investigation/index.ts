/**
 * Dynamic Reasoning Investigation Engine
 * 動態推理調查引擎
 *
 * Performs multi-step investigation on suspicious events using a variety
 * of inspection tools. Each tool contributes risk data and may trigger
 * additional investigation steps based on findings.
 * 使用多種檢查工具對可疑事件進行多步驟調查。每個工具貢獻風險數據，
 * 並可能根據發現觸發額外的調查步驟。
 *
 * @module @panguard-ai/panguard-guard/investigation
 */

import { createLogger, checkThreatIntel } from '@panguard-ai/core';
import type { SecurityEvent } from '@panguard-ai/core';
import type {
  InvestigationTool,
  InvestigationStep,
  InvestigationResult,
  InvestigationPlan,
  EnvironmentBaseline,
} from '../types.js';

const logger = createLogger('panguard-guard:investigation');

/** Maximum investigation steps to prevent infinite loops / 最大調查步驟數以防止無限循環 */
const MAX_STEPS = 8;

/**
 * Investigation Engine performs dynamic, multi-step reasoning about security events
 * 調查引擎對安全事件進行動態多步驟推理
 */
export class InvestigationEngine {
  private readonly baseline: EnvironmentBaseline;

  constructor(baseline: EnvironmentBaseline) {
    this.baseline = baseline;
  }

  /**
   * Investigate a security event using dynamic reasoning
   * 使用動態推理調查安全事件
   *
   * Creates an investigation plan based on event characteristics,
   * executes each tool step, and collects findings. Steps may trigger
   * additional investigation based on intermediate results.
   * 根據事件特徵建立調查計畫，執行每個工具步驟並收集發現。
   * 步驟可能根據中間結果觸發額外調查。
   *
   * @param event - The security event to investigate / 要調查的安全事件
   * @returns Completed investigation plan with all results / 包含所有結果的已完成調查計畫
   */
  async investigate(event: SecurityEvent): Promise<InvestigationPlan> {
    logger.info(`Starting investigation for event ${event.id} / 開始調查事件 ${event.id}`);

    const plan = this.createPlan(event);
    const completedSteps: InvestigationStep[] = [];

    for (const step of plan.steps) {
      if (completedSteps.length >= MAX_STEPS) {
        logger.info(`Max investigation steps (${MAX_STEPS}) reached / 已達最大調查步驟數`);
        break;
      }

      const startTime = Date.now();
      const result = await this.executeStep(step.tool, event);
      const durationMs = Date.now() - startTime;

      const completedStep: InvestigationStep = {
        ...step,
        result,
        durationMs,
      };
      completedSteps.push(completedStep);

      logger.info(
        `Step ${step.tool}: risk=${result.riskContribution}, ` +
          `needs_more=${result.needsAdditionalInvestigation} / ` +
          `步驟 ${step.tool}: 風險=${result.riskContribution}`
      );

      // Dynamic reasoning: add follow-up steps if needed
      // 動態推理：如需要則添加後續步驟
      if (result.needsAdditionalInvestigation) {
        const followUpTools = this.getFollowUpTools(step.tool, result);
        for (const followUp of followUpTools) {
          if (
            completedSteps.length < MAX_STEPS &&
            !completedSteps.some((s) => s.tool === followUp) &&
            !plan.steps.some((s) => s.tool === followUp)
          ) {
            const fStart = Date.now();
            const fResult = await this.executeStep(followUp, event);
            const fDuration = Date.now() - fStart;
            completedSteps.push({
              tool: followUp,
              reason: `Follow-up from ${step.tool}: ${result.finding} / 來自 ${step.tool} 的後續調查`,
              result: fResult,
              durationMs: fDuration,
            });
          }
        }
      }
    }

    return {
      steps: completedSteps,
      reasoning: this.buildReasoning(completedSteps),
    };
  }

  /**
   * Create an initial investigation plan based on event characteristics
   * 根據事件特徵建立初始調查計畫
   */
  private createPlan(event: SecurityEvent): InvestigationPlan {
    const steps: InvestigationStep[] = [];

    // Always check time anomaly / 總是檢查時間異常
    steps.push({
      tool: 'checkTimeAnomaly',
      reason: 'Check if event occurred during unusual hours / 檢查事件是否發生在異常時間',
    });

    // Network events: check IP and geo / 網路事件：檢查 IP 和地理位置
    if (event.source === 'network') {
      steps.push({
        tool: 'checkIPHistory',
        reason: 'Check IP reputation and history / 檢查 IP 信譽和歷史',
      });
      steps.push({
        tool: 'checkGeoLocation',
        reason: 'Verify geographic origin of connection / 驗證連線的地理來源',
      });
      steps.push({
        tool: 'checkNetworkPattern',
        reason: 'Analyze network communication patterns / 分析網路通訊模式',
      });
    }

    // Process events: check process tree and file reputation
    // 程序事件：檢查程序樹和檔案信譽
    if (event.source === 'process') {
      steps.push({
        tool: 'checkProcessTree',
        reason: 'Examine parent-child process relationships / 檢查父子程序關係',
      });
      steps.push({
        tool: 'checkFileReputation',
        reason: 'Check executable file reputation / 檢查可執行檔信譽',
      });
    }

    // Auth events: check user privilege and related events
    // 認證事件：檢查使用者權限和相關事件
    if (event.category === 'authentication' || event.category === 'authorization') {
      steps.push({
        tool: 'checkUserPrivilege',
        reason: 'Verify user privilege level / 驗證使用者權限等級',
      });
      steps.push({
        tool: 'checkRelatedEvents',
        reason: 'Look for related suspicious activity / 查找相關可疑活動',
      });
    }

    // File events: check file reputation / 檔案事件：檢查檔案信譽
    if (event.source === 'file') {
      steps.push({
        tool: 'checkFileReputation',
        reason: 'Analyze file reputation and hash / 分析檔案信譽和雜湊',
      });
    }

    return {
      steps,
      reasoning:
        `Investigation plan for ${event.source}/${event.category} event / ` +
        `${event.source}/${event.category} 事件的調查計畫`,
    };
  }

  /**
   * Execute a single investigation step
   * 執行單一調查步驟
   */
  private async executeStep(
    tool: InvestigationTool,
    event: SecurityEvent
  ): Promise<InvestigationResult> {
    switch (tool) {
      case 'checkIPHistory':
        return this.checkIPHistory(event);
      case 'checkUserPrivilege':
        return this.checkUserPrivilege(event);
      case 'checkTimeAnomaly':
        return this.checkTimeAnomaly(event);
      case 'checkGeoLocation':
        return this.checkGeoLocation(event);
      case 'checkRelatedEvents':
        return this.checkRelatedEvents(event);
      case 'checkProcessTree':
        return this.checkProcessTree(event);
      case 'checkFileReputation':
        return this.checkFileReputation(event);
      case 'checkNetworkPattern':
        return this.checkNetworkPattern(event);
      default:
        return {
          finding: `Unknown tool: ${tool} / 未知工具`,
          riskContribution: 0,
          needsAdditionalInvestigation: false,
        };
    }
  }

  /**
   * Determine follow-up investigation tools based on a step's results
   * 根據步驟結果決定後續調查工具
   */
  private getFollowUpTools(
    tool: InvestigationTool,
    result: InvestigationResult
  ): InvestigationTool[] {
    const followUps: InvestigationTool[] = [];

    if (tool === 'checkIPHistory' && result.riskContribution > 50) {
      followUps.push('checkGeoLocation', 'checkRelatedEvents');
    }
    if (tool === 'checkProcessTree' && result.riskContribution > 40) {
      followUps.push('checkFileReputation');
    }
    if (tool === 'checkTimeAnomaly' && result.riskContribution > 60) {
      followUps.push('checkUserPrivilege', 'checkRelatedEvents');
    }
    if (tool === 'checkUserPrivilege' && result.riskContribution > 50) {
      followUps.push('checkRelatedEvents');
    }

    return followUps;
  }

  // ---------------------------------------------------------------------------
  // Investigation tool implementations / 調查工具實作
  // ---------------------------------------------------------------------------

  /** Check IP history against threat intelligence / 檢查 IP 歷史（威脅情報） */
  private checkIPHistory(event: SecurityEvent): InvestigationResult {
    const ip =
      (event.metadata?.['sourceIP'] as string) ?? (event.metadata?.['remoteAddress'] as string);
    if (!ip) {
      return {
        finding: 'No IP address available for lookup / 無可查詢的 IP 地址',
        riskContribution: 0,
        needsAdditionalInvestigation: false,
      };
    }

    const threatEntry = checkThreatIntel(ip);
    if (threatEntry) {
      return {
        finding:
          `IP ${ip} found in threat intel: ${threatEntry.type} (${threatEntry.source}) / ` +
          `IP ${ip} 在威脅情報中: ${threatEntry.type} (${threatEntry.source})`,
        riskContribution: 80,
        needsAdditionalInvestigation: true,
        data: { ip, threat: `${threatEntry.type} (${threatEntry.source})`, type: threatEntry.type },
      };
    }

    return {
      finding: `IP ${ip} not found in threat intel / IP ${ip} 未在威脅情報中`,
      riskContribution: 0,
      needsAdditionalInvestigation: false,
      data: { ip },
    };
  }

  /** Check user privilege level / 檢查使用者權限等級 */
  private checkUserPrivilege(event: SecurityEvent): InvestigationResult {
    const user = (event.metadata?.['user'] as string) ?? (event.metadata?.['username'] as string);
    if (!user) {
      return {
        finding: 'No user information available / 無可用的使用者資訊',
        riskContribution: 0,
        needsAdditionalInvestigation: false,
      };
    }

    // Check if root/admin / 檢查是否為 root/admin
    const isPrivileged = [
      'root',
      'admin',
      'administrator',
      'system',
      'nt authority\\system',
    ].includes(user.toLowerCase());

    if (isPrivileged) {
      return {
        finding: `Privileged user activity: ${user} / 特權使用者活動: ${user}`,
        riskContribution: 60,
        needsAdditionalInvestigation: true,
        data: { user, privileged: true },
      };
    }

    // Check if user is in baseline / 檢查使用者是否在基線中
    const knownUser = this.baseline.normalLoginPatterns.some((l) => l.username === user);
    if (!knownUser) {
      return {
        finding: `Unknown user: ${user} (not in baseline) / 未知使用者: ${user}`,
        riskContribution: 45,
        needsAdditionalInvestigation: true,
        data: { user, known: false },
      };
    }

    return {
      finding: `Known user: ${user} / 已知使用者: ${user}`,
      riskContribution: 0,
      needsAdditionalInvestigation: false,
      data: { user, known: true },
    };
  }

  /** Check time anomaly / 檢查時間異常 */
  private checkTimeAnomaly(event: SecurityEvent): InvestigationResult {
    const eventTime = event.timestamp instanceof Date ? event.timestamp : new Date(event.timestamp);
    const hour = eventTime.getHours();

    // Business hours: 6-22 / 營業時間: 6-22
    const outsideBusinessHours = hour < 6 || hour > 22;

    if (outsideBusinessHours) {
      // Check if this user normally operates at this hour
      // 檢查該使用者是否通常在此時間操作
      const user = (event.metadata?.['user'] as string) ?? (event.metadata?.['username'] as string);
      const hasNightPattern = user
        ? this.baseline.normalLoginPatterns.some(
            (l) => l.username === user && (l.hourOfDay < 6 || l.hourOfDay > 22)
          )
        : false;

      if (hasNightPattern) {
        return {
          finding:
            `Off-hours activity (${hour}:00) but user has night pattern / ` +
            `非工作時間活動但使用者有夜間模式`,
          riskContribution: 15,
          needsAdditionalInvestigation: false,
          data: { hour, outsideBusinessHours: true, hasNightPattern: true },
        };
      }

      return {
        finding: `Activity at unusual hour (${hour}:00) / 在異常時間活動 (${hour}:00)`,
        riskContribution: 40,
        needsAdditionalInvestigation: true,
        data: { hour, outsideBusinessHours: true, hasNightPattern: false },
      };
    }

    return {
      finding: `Activity during normal hours (${hour}:00) / 正常時間活動`,
      riskContribution: 0,
      needsAdditionalInvestigation: false,
      data: { hour, outsideBusinessHours: false },
    };
  }

  /** Check geographic location / 檢查地理位置 */
  private checkGeoLocation(event: SecurityEvent): InvestigationResult {
    const ip =
      (event.metadata?.['sourceIP'] as string) ?? (event.metadata?.['remoteAddress'] as string);
    if (!ip) {
      return {
        finding: 'No IP for geolocation / 無可查詢的 IP',
        riskContribution: 0,
        needsAdditionalInvestigation: false,
      };
    }

    // Check if from known baseline connections / 檢查是否來自已知基線連線
    const knownConnection = this.baseline.normalConnections.some((c) => c.remoteAddress === ip);

    if (!knownConnection) {
      return {
        finding:
          `Connection from new IP: ${ip} (not in baseline) / ` +
          `來自新 IP 的連線: ${ip} (不在基線中)`,
        riskContribution: 35,
        needsAdditionalInvestigation: true,
        data: { ip, known: false },
      };
    }

    return {
      finding: `Connection from known IP: ${ip} / 來自已知 IP 的連線`,
      riskContribution: 0,
      needsAdditionalInvestigation: false,
      data: { ip, known: true },
    };
  }

  /** Check related events / 檢查相關事件 */
  private checkRelatedEvents(_event: SecurityEvent): InvestigationResult {
    // In a production system, this would query the event store
    // 在生產系統中，這會查詢事件儲存庫
    return {
      finding:
        'Related event analysis requires event store integration / ' +
        '相關事件分析需要事件儲存庫整合',
      riskContribution: 0,
      needsAdditionalInvestigation: false,
    };
  }

  /** Check process tree / 檢查程序樹 */
  private checkProcessTree(event: SecurityEvent): InvestigationResult {
    const processName = event.metadata?.['processName'] as string;
    const parentProcess = event.metadata?.['parentProcess'] as string;

    if (!processName) {
      return {
        finding: 'No process information available / 無可用的程序資訊',
        riskContribution: 0,
        needsAdditionalInvestigation: false,
      };
    }

    // Check if process is in baseline / 檢查程序是否在基線中
    const knownProcess = this.baseline.normalProcesses.some((p) => p.name === processName);

    if (!knownProcess) {
      // Suspicious parent processes / 可疑的父程序
      const suspiciousParents = [
        'cmd.exe',
        'powershell.exe',
        'bash',
        'sh',
        'python',
        'python3',
        'perl',
        'ruby',
      ];
      const hasSuspiciousParent = parentProcess
        ? suspiciousParents.some((sp) => parentProcess.toLowerCase().includes(sp))
        : false;

      return {
        finding:
          `New process: ${processName}${hasSuspiciousParent ? ` (suspicious parent: ${parentProcess})` : ''} / ` +
          `新程序: ${processName}`,
        riskContribution: hasSuspiciousParent ? 65 : 40,
        needsAdditionalInvestigation: hasSuspiciousParent,
        data: { processName, parentProcess, known: false, suspiciousParent: hasSuspiciousParent },
      };
    }

    return {
      finding: `Known process: ${processName} / 已知程序: ${processName}`,
      riskContribution: 0,
      needsAdditionalInvestigation: false,
      data: { processName, known: true },
    };
  }

  /** Check file reputation / 檢查檔案信譽 */
  private checkFileReputation(event: SecurityEvent): InvestigationResult {
    const filePath =
      (event.metadata?.['filePath'] as string) ?? (event.metadata?.['processPath'] as string);
    if (!filePath) {
      return {
        finding: 'No file path available for reputation check / 無可用的檔案路徑',
        riskContribution: 0,
        needsAdditionalInvestigation: false,
      };
    }

    // Check for suspicious file locations / 檢查可疑檔案位置
    const suspiciousLocations = ['/tmp/', '/dev/shm/', '\\Temp\\', '\\AppData\\Local\\Temp\\'];
    const inSuspiciousLocation = suspiciousLocations.some((loc) => filePath.includes(loc));

    // Check for suspicious extensions / 檢查可疑副檔名
    const suspiciousExtensions = ['.ps1', '.vbs', '.bat', '.cmd', '.scr', '.pif', '.hta'];
    const hasSuspiciousExt = suspiciousExtensions.some((ext) =>
      filePath.toLowerCase().endsWith(ext)
    );

    if (inSuspiciousLocation || hasSuspiciousExt) {
      return {
        finding:
          `Suspicious file: ${filePath}` +
          `${inSuspiciousLocation ? ' (temp directory)' : ''}` +
          `${hasSuspiciousExt ? ' (suspicious extension)' : ''} / ` +
          `可疑檔案: ${filePath}`,
        riskContribution: inSuspiciousLocation && hasSuspiciousExt ? 70 : 45,
        needsAdditionalInvestigation: true,
        data: {
          filePath,
          suspiciousLocation: inSuspiciousLocation,
          suspiciousExtension: hasSuspiciousExt,
        },
      };
    }

    return {
      finding: `File appears normal: ${filePath} / 檔案看起來正常`,
      riskContribution: 0,
      needsAdditionalInvestigation: false,
      data: { filePath },
    };
  }

  /** Check network communication pattern / 檢查網路通訊模式 */
  private checkNetworkPattern(event: SecurityEvent): InvestigationResult {
    const remoteAddr =
      (event.metadata?.['remoteAddress'] as string) ??
      (event.metadata?.['destinationIP'] as string);
    const remotePort = event.metadata?.['remotePort'] as number | undefined;

    if (!remoteAddr) {
      return {
        finding: 'No network destination available / 無可用的網路目的地',
        riskContribution: 0,
        needsAdditionalInvestigation: false,
      };
    }

    // Check against baseline connections / 與基線連線比較
    const knownConnection = this.baseline.normalConnections.some(
      (c) => c.remoteAddress === remoteAddr && (!remotePort || c.remotePort === remotePort)
    );

    // Check for suspicious ports / 檢查可疑埠
    const suspiciousPorts = [4444, 5555, 8888, 1337, 31337, 6666, 6667, 9001];
    const isSuspiciousPort = remotePort ? suspiciousPorts.includes(remotePort) : false;

    if (!knownConnection) {
      return {
        finding:
          `New network connection: ${remoteAddr}:${remotePort ?? 'unknown'}` +
          `${isSuspiciousPort ? ' (suspicious port)' : ''} / ` +
          `新網路連線: ${remoteAddr}:${remotePort ?? 'unknown'}`,
        riskContribution: isSuspiciousPort ? 75 : 30,
        needsAdditionalInvestigation: isSuspiciousPort,
        data: { remoteAddr, remotePort, known: false, suspiciousPort: isSuspiciousPort },
      };
    }

    return {
      finding: `Known network pattern: ${remoteAddr}:${remotePort ?? 'unknown'} / 已知網路模式`,
      riskContribution: 0,
      needsAdditionalInvestigation: false,
      data: { remoteAddr, remotePort, known: true },
    };
  }

  /**
   * Build human-readable reasoning from investigation steps
   * 從調查步驟建立人類可讀的推理
   */
  private buildReasoning(steps: InvestigationStep[]): string {
    const parts: string[] = ['Investigation Summary / 調查摘要:'];

    for (const step of steps) {
      if (step.result) {
        parts.push(
          `  [${step.tool}] ${step.result.finding} (risk: ${step.result.riskContribution}%)`
        );
      }
    }

    const totalRisk = steps.reduce((sum, s) => sum + (s.result?.riskContribution ?? 0), 0);
    const avgRisk = steps.length > 0 ? Math.round(totalRisk / steps.length) : 0;
    parts.push(`Average risk contribution: ${avgRisk}% / 平均風險貢獻: ${avgRisk}%`);

    return parts.join('\n');
  }
}
