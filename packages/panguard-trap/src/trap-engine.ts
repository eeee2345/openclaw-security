/**
 * PanguardTrap Engine
 * PanguardTrap 引擎
 *
 * Central coordinator that manages all trap services,
 * processes sessions through the attacker profiler,
 * and generates intelligence for Threat Cloud.
 *
 * 管理所有蜜罐服務的中央協調器，
 * 透過攻擊者分析器處理連線，
 * 並產生情報回饋 Threat Cloud。
 *
 * @module @panguard-ai/panguard-trap/trap-engine
 */

import { createLogger } from '@panguard-ai/core';
import type {
  TrapConfig,
  TrapEngineStatus,
  TrapSession,
  TrapStatistics,
  TrapService,
  TrapIntelligence,
  AttackerSkillLevel,
  AttackerIntent,
  TrapServiceType,
} from './types.js';
import { createTrapService } from './services/index.js';
import { AttackerProfiler } from './profiler/index.js';
import { buildTrapIntel, generateIntelSummary } from './intel/index.js';
import { ThreatCloudUploader } from './threat-cloud-uploader.js';

const logger = createLogger('panguard-trap:engine');

/**
 * PanguardTrap Engine - orchestrates all honeypot operations
 * PanguardTrap 引擎 - 協調所有蜜罐操作
 */
export class TrapEngine {
  private readonly config: TrapConfig;
  private readonly profiler: AttackerProfiler;
  private readonly cloudUploader: ThreatCloudUploader | null;
  private services: TrapService[] = [];
  private _status: TrapEngineStatus = 'idle';
  private startTime: Date | null = null;
  private completedSessions: TrapSession[] = [];
  private intelReports: TrapIntelligence[] = [];
  private sessionHandlers: ((session: TrapSession) => void)[] = [];

  constructor(config: TrapConfig) {
    this.config = config;
    this.profiler = new AttackerProfiler();

    // Initialize Threat Cloud uploader if endpoint configured
    // 如有設定端點則初始化 Threat Cloud 上傳器
    if (config.feedThreatCloud && config.threatCloudEndpoint) {
      this.cloudUploader = new ThreatCloudUploader(config.threatCloudEndpoint);
      logger.info(
        `Threat Cloud uploader initialized: ${config.threatCloudEndpoint} / ` +
          `Threat Cloud 上傳器已初始化`
      );
    } else {
      this.cloudUploader = null;
    }
  }

  get status(): TrapEngineStatus {
    return this._status;
  }

  /**
   * Start all enabled trap services
   * 啟動所有已啟用的蜜罐服務
   */
  async start(): Promise<void> {
    if (this._status === 'running') return;

    logger.info('Starting PanguardTrap engine / 啟動 PanguardTrap 引擎');
    this._status = 'running';
    this.startTime = new Date();

    const enabledConfigs = this.config.services.filter((s) => s.enabled);

    for (const serviceConfig of enabledConfigs) {
      try {
        const service = createTrapService(serviceConfig);

        // Register session handler
        service.onSession((session) => {
          this.handleCompletedSession(session);
        });

        await service.start();
        this.services.push(service);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        logger.error(`Failed to start ${serviceConfig.type} trap: ${msg} / 啟動失敗: ${msg}`);
      }
    }

    logger.info(
      `PanguardTrap engine started with ${this.services.length} services / PanguardTrap 引擎已啟動，${this.services.length} 個服務`
    );
  }

  /**
   * Stop all trap services
   * 停止所有蜜罐服務
   */
  async stop(): Promise<void> {
    if (this._status !== 'running') return;

    logger.info('Stopping PanguardTrap engine / 停止 PanguardTrap 引擎');
    this._status = 'stopping';

    // Flush and stop cloud uploader / 清空並停止上傳器
    if (this.cloudUploader) {
      await this.cloudUploader.flush();
      this.cloudUploader.stop();
    }

    for (const service of this.services) {
      try {
        await service.stop();
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        logger.error(`Error stopping ${service.serviceType}: ${msg}`);
      }
    }

    this.services = [];
    this._status = 'idle';
    logger.info('PanguardTrap engine stopped / PanguardTrap 引擎已停止');
  }

  /**
   * Register a handler for completed sessions
   * 註冊已完成連線的處理器
   */
  onSession(handler: (session: TrapSession) => void): void {
    this.sessionHandlers.push(handler);
  }

  /**
   * Get statistics
   * 取得統計資料
   */
  getStatistics(): TrapStatistics {
    const allSessions = [
      ...this.completedSessions,
      ...this.services.flatMap((s) => s.getActiveSessions()),
    ];

    const uniqueIPs = new Set(allSessions.map((s) => s.sourceIP));
    const totalCreds = allSessions.reduce((sum, s) => sum + s.credentials.length, 0);
    const totalCmds = allSessions.reduce((sum, s) => sum + s.commands.length, 0);

    // Sessions by service
    const sessionsByService: Record<TrapServiceType, number> = {
      ssh: 0,
      http: 0,
      ftp: 0,
      smb: 0,
      mysql: 0,
      rdp: 0,
      telnet: 0,
      redis: 0,
    };
    for (const s of allSessions) {
      sessionsByService[s.serviceType] = (sessionsByService[s.serviceType] ?? 0) + 1;
    }

    // Top attacker IPs
    const ipSessionCount = new Map<string, number>();
    for (const s of allSessions) {
      ipSessionCount.set(s.sourceIP, (ipSessionCount.get(s.sourceIP) ?? 0) + 1);
    }
    const topAttackerIPs = Array.from(ipSessionCount.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([ip, sessions]) => {
        const profile = this.profiler.getProfileByIP(ip);
        return { ip, sessions, riskScore: profile?.riskScore ?? 0 };
      });

    // Top usernames and passwords
    const usernameCounts = new Map<string, number>();
    const passwordCounts = new Map<string, number>();
    for (const s of allSessions) {
      for (const c of s.credentials) {
        if (c.username) usernameCounts.set(c.username, (usernameCounts.get(c.username) ?? 0) + 1);
        if (c.password) passwordCounts.set(c.password, (passwordCounts.get(c.password) ?? 0) + 1);
      }
    }

    const topUsernames = Array.from(usernameCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([username, count]) => ({ username, count }));

    const topPasswords = Array.from(passwordCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([password, count]) => ({ password, count }));

    // Skill distribution
    const skillDistribution: Record<AttackerSkillLevel, number> = {
      script_kiddie: 0,
      intermediate: 0,
      advanced: 0,
      apt: 0,
    };
    const intentDistribution: Record<AttackerIntent, number> = {
      reconnaissance: 0,
      credential_harvesting: 0,
      ransomware_deployment: 0,
      cryptomining: 0,
      data_theft: 0,
      botnet_recruitment: 0,
      lateral_movement: 0,
      unknown: 0,
    };

    for (const profile of this.profiler.getAllProfiles()) {
      skillDistribution[profile.skillLevel] = (skillDistribution[profile.skillLevel] ?? 0) + 1;
      intentDistribution[profile.intent] = (intentDistribution[profile.intent] ?? 0) + 1;
    }

    const activeSessions = this.services.reduce((sum, s) => sum + s.getActiveSessions().length, 0);
    const uptimeMs = this.startTime ? Date.now() - this.startTime.getTime() : 0;

    return {
      totalSessions: allSessions.length,
      activeSessions,
      uniqueSourceIPs: uniqueIPs.size,
      totalCredentialAttempts: totalCreds,
      totalCommandsCaptured: totalCmds,
      sessionsByService,
      topAttackerIPs,
      topUsernames,
      topPasswords,
      skillDistribution,
      intentDistribution,
      uptimeMs,
    };
  }

  /**
   * Get the attacker profiler
   * 取得攻擊者分析器
   */
  getProfiler(): AttackerProfiler {
    return this.profiler;
  }

  /**
   * Get collected intel reports
   * 取得收集的情報報告
   */
  getIntelReports(): TrapIntelligence[] {
    return [...this.intelReports];
  }

  /**
   * Get intel summary
   * 取得情報摘要
   */
  getIntelSummary() {
    return generateIntelSummary(this.intelReports);
  }

  /**
   * Get completed sessions
   * 取得已完成的連線
   */
  getCompletedSessions(): TrapSession[] {
    return [...this.completedSessions];
  }

  /**
   * Get running service types
   * 取得運行中的服務類型
   */
  getRunningServices(): TrapServiceType[] {
    return this.services.filter((s) => s.status === 'running').map((s) => s.serviceType);
  }

  // -------------------------------------------------------------------------
  // Internal
  // -------------------------------------------------------------------------

  private handleCompletedSession(session: TrapSession): void {
    // Store session (with memory limit)
    this.completedSessions.push(session);
    if (this.completedSessions.length > this.config.maxSessionsInMemory) {
      this.completedSessions.shift();
    }

    // Profile the attacker
    const profile = this.profiler.processSession(session);

    // Build intel and upload to Threat Cloud / 建立情報並上傳至 Threat Cloud
    if (this.config.feedThreatCloud) {
      const intel = buildTrapIntel(session, profile);
      if (intel) {
        this.intelReports.push(intel);

        // Upload to Threat Cloud if uploader is available
        if (this.cloudUploader) {
          this.cloudUploader.enqueue(intel);
        }

        logger.info(`Intel report generated for ${session.sourceIP} / 情報報告已產生`);
      }
    }

    // Notify session handlers
    for (const handler of this.sessionHandlers) {
      try {
        handler(session);
      } catch {
        // ignore
      }
    }

    logger.info(
      `Session processed: ${session.sessionId} → profile ${profile.profileId} (${profile.skillLevel}/${profile.intent}) / 連線已處理`
    );
  }
}
