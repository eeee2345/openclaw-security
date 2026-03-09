/**
 * GuardEngine - Main orchestrator for PanguardGuard
 * GuardEngine - PanguardGuard 主引擎
 *
 * Orchestrates the complete detection-analysis-response pipeline:
 * 1. Receives security events from MonitorEngine
 * 2. Routes through DetectAgent -> AnalyzeAgent -> RespondAgent -> ReportAgent
 * 3. Manages Context Memory baseline learning and protection transitions
 * 4. Coordinates notifications, threat cloud, and dashboard updates
 *
 * 協調完整的偵測-分析-回應管線：
 * 1. 從 MonitorEngine 接收安全事件
 * 2. 經過 DetectAgent -> AnalyzeAgent -> RespondAgent -> ReportAgent 路由
 * 3. 管理 Context Memory 基線學習和防護轉換
 * 4. 協調通知、威脅雲和儀表板更新
 *
 * @module @panguard-ai/panguard-guard/guard-engine
 */

import { join } from 'node:path';
import {
  createLogger,
  RuleEngine,
  MonitorEngine,
  ThreatIntelFeedManager,
  YaraScanner,
  setFeedManager,
  SmartRouter,
  KnowledgeDistiller,
} from '@panguard-ai/core';
import type { QuotaTier } from '@panguard-ai/core';
import type { SecurityEvent } from '@panguard-ai/core';
import type {
  GuardConfig,
  GuardStatus,
  GuardMode,
  LicenseTier,
  EnvironmentBaseline,
  ThreatVerdict,
  ResponseResult,
  AnalyzeLLM,
  LLMAnalysisResult,
  LLMClassificationResult,
} from './types.js';
import { TIER_FEATURES } from './types.js';

import { DetectAgent, AnalyzeAgent, RespondAgent, ReportAgent } from './agent/index.js';
import {
  loadBaseline,
  saveBaseline,
  isLearningComplete,
  getLearningProgress,
  switchToProtectionMode,
} from './memory/index.js';
import { InvestigationEngine } from './investigation/index.js';
import { sendNotifications } from './notify/index.js';
import { ThreatCloudClient } from './threat-cloud/index.js';
import { DashboardServer } from './dashboard/index.js';
import { PidFile, Watchdog } from './daemon/index.js';
import { validateLicense, hasFeature } from './license/index.js';
import {
  loadSecurityPolicy,
  runSecurityAudit,
  logAuditEvent,
  SyslogAdapter,
} from '@panguard-ai/security-hardening';
import { FalcoMonitor } from './monitors/falco-monitor.js';
import { SuricataMonitor } from './monitors/suricata-monitor.js';
import { LogCollector } from './collectors/index.js';
import { BUILTIN_RULES } from './rules/builtin-rules.js';
import { PanguardAgentClient } from './agent-client/index.js';
import type { AgentHeartbeat } from './agent-client/index.js';
import { GuardATREngine } from './engines/atr-engine.js';

const logger = createLogger('panguard-guard:engine');

/**
 * Attempt to auto-detect and create an LLM provider.
 * Priority: local encrypted config > environment variables > Ollama fallback.
 * Falls back to null if no provider is available (graceful degradation).
 */
async function autoDetectLLM(): Promise<AnalyzeLLM | null> {
  try {
    // Dynamic import to avoid requiring @panguard-ai/core/ai at load time
    const { createLLM } = await import('@panguard-ai/core');
    type LLMProviderType = 'ollama' | 'claude' | 'openai';

    let provider: LLMProviderType | null = null;
    let apiKey: string | undefined;
    let model: string | undefined;

    // 1. Check local encrypted LLM config (~/.panguard/llm.enc)
    try {
      const { homedir } = await import('node:os');
      const { existsSync, readFileSync } = await import('node:fs');
      const { createHash, createDecipheriv } = await import('node:crypto');
      const { hostname, userInfo } = await import('node:os');

      const llmPath = join(homedir(), '.panguard', 'llm.enc');
      if (existsSync(llmPath)) {
        const encrypted = readFileSync(llmPath, 'utf-8');
        const parts = encrypted.split(':');
        if (parts.length === 3) {
          const machineId = `${hostname()}-${userInfo().username}-panguard-ai`;
          const key = createHash('sha256').update(machineId).digest();
          const iv = Buffer.from(parts[0]!, 'base64');
          const authTag = Buffer.from(parts[1]!, 'base64');
          const data = Buffer.from(parts[2]!, 'base64');
          const decipher = createDecipheriv('aes-256-gcm', key, iv);
          decipher.setAuthTag(authTag);
          const decrypted = Buffer.concat([decipher.update(data), decipher.final()]).toString(
            'utf8'
          );
          const llmConfig = JSON.parse(decrypted) as {
            provider?: string;
            apiKey?: string;
            model?: string;
          };
          if (llmConfig.provider && (llmConfig.apiKey || llmConfig.provider === 'ollama')) {
            provider = llmConfig.provider as LLMProviderType;
            apiKey = llmConfig.apiKey;
            model = llmConfig.model;
            logger.info(`LLM config loaded from local encrypted store (provider: ${provider})`);
          }
        }
      }
    } catch {
      // Local config not available, fall through to env vars
    }

    // 2. Fall back to environment variables
    if (!provider) {
      if (process.env['ANTHROPIC_API_KEY']) {
        provider = 'claude';
        apiKey = process.env['ANTHROPIC_API_KEY'];
        model = process.env['PANGUARD_LLM_MODEL'] ?? 'claude-sonnet-4-20250514';
      } else if (process.env['OPENAI_API_KEY']) {
        provider = 'openai';
        apiKey = process.env['OPENAI_API_KEY'];
        model = process.env['PANGUARD_LLM_MODEL'] ?? 'gpt-4o';
      } else {
        // Try Ollama (local, no API key needed)
        provider = 'ollama';
        model = process.env['PANGUARD_LLM_MODEL'] ?? 'llama3';
      }
    }

    // Allow env var model override even when using local config
    if (process.env['PANGUARD_LLM_MODEL']) {
      model = process.env['PANGUARD_LLM_MODEL'];
    }

    // Default model per provider
    const defaultModels: Record<string, string> = {
      claude: 'claude-sonnet-4-20250514',
      openai: 'gpt-4o',
      ollama: 'llama3',
    };
    const resolvedModel = model ?? defaultModels[provider] ?? 'llama3';

    const llmProvider = createLLM({ provider, model: resolvedModel, apiKey, lang: 'en' });
    const available = await llmProvider.isAvailable();
    if (!available) {
      logger.info(`LLM provider '${provider}' not available, running without AI`);
      return null;
    }

    logger.info(`LLM provider '${provider}' (model: ${model}) connected`);

    // Adapt LLMProvider to AnalyzeLLM interface
    const adapter: AnalyzeLLM = {
      async analyze(prompt: string, context?: string): Promise<LLMAnalysisResult> {
        const result = await llmProvider.analyze(prompt, context);
        return {
          summary: result.summary,
          severity: result.severity,
          confidence: result.confidence,
          recommendations: result.recommendations,
        };
      },
      async classify(event: SecurityEvent): Promise<LLMClassificationResult> {
        const result = await llmProvider.classify(event);
        return {
          technique: result.technique,
          severity: result.severity,
          confidence: result.confidence,
          description: result.description,
        };
      },
      async isAvailable(): Promise<boolean> {
        return llmProvider.isAvailable();
      },
    };

    return adapter;
  } catch (err) {
    logger.info(
      `LLM auto-detect failed, running without AI: ${err instanceof Error ? err.message : String(err)}`
    );
    return null;
  }
}

/**
 * GuardEngine is the central orchestrator for all PanguardGuard functionality
 * GuardEngine 是所有 PanguardGuard 功能的中央協調器
 */
export class GuardEngine {
  private readonly config: GuardConfig;
  private mode: GuardMode;
  private baseline: EnvironmentBaseline;
  private readonly baselinePath: string;

  // Agents / 代理
  private readonly ruleEngine: RuleEngine;
  private readonly detectAgent: DetectAgent;
  private readonly analyzeAgent: AnalyzeAgent;
  private readonly respondAgent: RespondAgent;
  private readonly reportAgent: ReportAgent;
  private readonly investigationEngine: InvestigationEngine;

  // Infrastructure / 基礎設施
  private readonly threatCloud: ThreatCloudClient;
  private readonly feedManager: ThreatIntelFeedManager;
  private dashboard: DashboardServer | null = null;
  private readonly pidFile: PidFile;
  private watchdog: Watchdog | null = null;
  private monitorEngine: MonitorEngine | null = null;
  private syslogAdapter: SyslogAdapter | null = null;
  private falcoMonitor: FalcoMonitor | null = null;
  private suricataMonitor: SuricataMonitor | null = null;
  private agentClient: PanguardAgentClient | null = null;
  private logCollector: LogCollector | null = null;

  // YARA scanner / YARA 掃描器
  private readonly yaraScanner: YaraScanner;

  // ATR (Agent Threat Rules) engine / ATR 引擎
  private readonly atrEngine: GuardATREngine;

  // Smart AI routing / 智慧 AI 路由
  private readonly smartRouter: SmartRouter | null = null;
  private readonly knowledgeDistiller: KnowledgeDistiller | null = null;

  // State / 狀態
  private running = false;
  private startTime = 0;
  private eventsProcessed = 0;
  private threatsDetected = 0;
  private actionsExecuted = 0;
  private threatCloudUploaded = 0;
  private statusTimer: ReturnType<typeof setInterval> | null = null;
  private learningCheckTimer: ReturnType<typeof setInterval> | null = null;
  private cloudSyncTimer: ReturnType<typeof setInterval> | null = null;
  private eventCallback?: (type: string, data: Record<string, unknown>) => void;

  constructor(config: GuardConfig, llm: AnalyzeLLM | null = null) {
    this.config = config;
    this.mode = config.mode;
    this.baselinePath = join(config.dataDir, 'baseline.json');

    // Load or create baseline / 載入或建立基線
    this.baseline = loadBaseline(this.baselinePath);

    // Validate license / 驗證授權
    let license = validateLicense(config.licenseKey);

    // If CLI tier is provided, map it to Guard's internal LicenseTier
    // CLI tiers: community/solo/pro/business/enterprise
    // Guard tiers: free/pro/enterprise
    if (config.cliTier) {
      const cliTierMap: Record<string, LicenseTier> = {
        community: 'free',
        solo: 'pro',
        pro: 'pro',
        business: 'enterprise',
        enterprise: 'enterprise',
      };
      const mappedTier = cliTierMap[config.cliTier] ?? 'free';
      const keyTierLevel = { free: 0, pro: 1, enterprise: 2 }[license.tier] ?? 0;
      const cliTierLevel = { free: 0, pro: 1, enterprise: 2 }[mappedTier] ?? 0;

      // Use whichever tier is higher
      if (cliTierLevel > keyTierLevel) {
        license = {
          ...license,
          tier: mappedTier,
          features: TIER_FEATURES[mappedTier],
          isValid: true,
        };
      }
    }

    logger.info(
      `License: ${license.tier} tier (valid: ${license.isValid}) / ` +
        `授權: ${license.tier} 等級 (有效: ${license.isValid})`
    );

    // Initialize rule engine with built-in + bundled Sigma rules
    // 初始化規則引擎（內建 + 打包的 Sigma 規則）
    this.ruleEngine = new RuleEngine({
      rulesDir: join(config.dataDir, 'rules'),
      communityRulesDir: config.bundledSigmaDir,
      hotReload: true,
      customRules: BUILTIN_RULES,
    });

    // Initialize YARA scanner / 初始化 YARA 掃描器
    this.yaraScanner = new YaraScanner();

    // Initialize ATR engine for agent threat detection / 初始化 ATR 引擎
    this.atrEngine = new GuardATREngine({
      rulesDir: join(config.dataDir, 'atr-rules'),
      hotReload: true,
    });

    // Initialize agents / 初始化代理
    this.detectAgent = new DetectAgent(this.ruleEngine);

    const analyzeLLM = hasFeature(license, 'ai_analysis') ? llm : null;
    this.analyzeAgent = new AnalyzeAgent(analyzeLLM);

    // Initialize SmartRouter and KnowledgeDistiller for cost-optimized AI routing
    // 初始化 SmartRouter 和 KnowledgeDistiller 以實現成本最佳化 AI 路由
    if (analyzeLLM) {
      const tierToQuota: Record<string, QuotaTier> = {
        free: 'free',
        pro: 'pro',
        enterprise: 'business',
      };
      const quotaTier = tierToQuota[license.tier] ?? 'free';
      const hasBYOK = !!config.ai?.byokApiKey;

      this.smartRouter = new SmartRouter({
        tier: quotaTier,
        quotaOverride: hasBYOK ? { isBYOK: true } : undefined,
      });

      this.knowledgeDistiller = new KnowledgeDistiller({
        onRuleDistilled: (rule) => {
          logger.info(
            `Knowledge distilled: ${rule.ruleId} (confidence: ${rule.aiConfidence}) / ` +
              `知識蒸餾: ${rule.ruleId} (信心: ${rule.aiConfidence})`
          );
        },
      });
    }

    this.respondAgent = new RespondAgent(config.actionPolicy, this.mode);
    this.reportAgent = new ReportAgent(join(config.dataDir, 'events.jsonl'), this.mode);

    // Initialize investigation engine / 初始化調查引擎
    this.investigationEngine = new InvestigationEngine(this.baseline);

    // Initialize threat cloud - always enable upload for all tiers
    // Full threat cloud API access (rule fetching, stats) gated by enterprise
    this.threatCloud = new ThreatCloudClient(config.threatCloudEndpoint, config.dataDir);

    // Initialize threat intel feed manager
    this.feedManager = new ThreatIntelFeedManager({
      abuseIPDBKey: process.env['ABUSEIPDB_KEY'],
    });
    setFeedManager(this.feedManager);

    // PID file / PID 檔案
    this.pidFile = new PidFile(config.dataDir);

    logger.info('GuardEngine initialized / GuardEngine 已初始化');
  }

  /**
   * Create a GuardEngine with auto-detected LLM provider.
   * Checks env vars for ANTHROPIC_API_KEY, OPENAI_API_KEY, or tries Ollama.
   */
  static async create(config: GuardConfig): Promise<GuardEngine> {
    const llm = await autoDetectLLM();
    return new GuardEngine(config, llm);
  }

  /**
   * Start the guard engine / 啟動守護引擎
   */
  async start(): Promise<void> {
    if (this.running) {
      logger.warn('GuardEngine already running / GuardEngine 已在執行中');
      return;
    }

    logger.info(
      `Starting GuardEngine in ${this.mode} mode / 啟動 GuardEngine（${this.mode} 模式）`
    );

    // Write PID file / 寫入 PID 檔案
    this.pidFile.write();

    // Security self-audit on startup / 啟動時安全自檢
    try {
      const policy = loadSecurityPolicy({});
      const auditReport = runSecurityAudit(policy);
      const unfixed = auditReport.findings.filter((f) => !f.fixed);
      if (unfixed.length > 0) {
        logger.warn(
          `Security audit: ${unfixed.length} issue(s) found (risk score: ${auditReport.riskScore})`
        );
      } else {
        logger.info('Security audit: all checks passed');
      }
    } catch (err: unknown) {
      logger.warn(`Security audit skipped: ${err instanceof Error ? err.message : String(err)}`);
    }

    // Initialize syslog adapter if configured / 如有設定則初始化 Syslog 轉送器
    const syslogServer = process.env['PANGUARD_SYSLOG_SERVER'];
    if (syslogServer) {
      const syslogPort = parseInt(process.env['PANGUARD_SYSLOG_PORT'] ?? '514', 10);
      this.syslogAdapter = new SyslogAdapter(syslogServer, syslogPort);
      logger.info(`Syslog adapter initialized: ${syslogServer}:${syslogPort}`);
    }

    // Start threat intel feeds (non-blocking, best-effort)
    this.feedManager
      .start()
      .then(() => {
        logger.info(
          `Threat intel feeds loaded: ${this.feedManager.getIoCCount()} IoCs, ${this.feedManager.getIPCount()} IPs indexed`
        );
      })
      .catch((err: unknown) => {
        logger.warn(
          `Threat intel feed start failed (using hardcoded list): ${err instanceof Error ? err.message : String(err)}`
        );
      });

    // Load rules / 載入規則
    await this.ruleEngine.loadRules();

    // Load ATR (Agent Threat Rules) / 載入 ATR 規則
    this.atrEngine
      .loadRules()
      .then((count) => {
        if (count > 0) {
          logger.info(`ATR rules loaded: ${count} rules / ATR 規則已載入: ${count} 條`);
        }
        this.atrEngine.startSessionCleanup();
      })
      .catch((err: unknown) => {
        logger.warn(
          `ATR rules load failed: ${err instanceof Error ? err.message : String(err)}`
        );
      });

    // Load ATR rules from Threat Cloud / 從 Threat Cloud 載入 ATR 規則
    this.threatCloud
      .fetchATRRules()
      .then((atrCloudRules) => {
        let added = 0;
        for (const rule of atrCloudRules) {
          try {
            const parsed = JSON.parse(rule.ruleContent) as import('agent-threat-rules').ATRRule;
            if (parsed.id && parsed.title && parsed.detection) {
              this.atrEngine.addCloudRule(parsed);
              added++;
            }
          } catch {
            // skip invalid
          }
        }
        if (added > 0) {
          logger.info(`ATR cloud rules loaded: ${added} rules / ATR 雲端規則已載入: ${added} 條`);
        }
      })
      .catch((err: unknown) => {
        logger.warn(
          `ATR cloud rules fetch skipped: ${err instanceof Error ? err.message : String(err)}`
        );
      });

    // Load community rules from threat cloud / 從威脅雲載入社群規則
    const cloudRules = await this.threatCloud.fetchRules();
    for (const rule of cloudRules) {
      try {
        const parsed = JSON.parse(rule.ruleContent) as import('@panguard-ai/core').SigmaRule;
        if (parsed.id && parsed.title && parsed.detection) {
          this.ruleEngine.addRule(parsed);
        }
      } catch {
        // Skip invalid cloud rules / 跳過無效的雲端規則
      }
    }

    // Fetch IP blocklist from Threat Cloud and inject into feed manager
    // 從 Threat Cloud 取得 IP 封鎖清單並注入威脅情報管理器
    this.threatCloud
      .fetchBlocklist()
      .then((ips) => {
        if (ips.length > 0) {
          const added = this.feedManager.addExternalIPs(ips, 'threat_cloud_blocklist', 85);
          logger.info(
            `Threat Cloud blocklist loaded: ${added} IPs / ` +
              `Threat Cloud 封鎖清單已載入: ${added} 個 IP`
          );
        }
      })
      .catch((err: unknown) => {
        logger.warn(
          `Threat Cloud blocklist fetch skipped: ${err instanceof Error ? err.message : String(err)}`
        );
      });

    // Load YARA rules (non-blocking, best-effort) / 載入 YARA 規則
    // Custom rules from user's dataDir, bundled rules from installation
    {
      const yaraCustomDir = this.config.yaraRulesDir
        ? join(this.config.yaraRulesDir, 'custom')
        : join(this.config.dataDir, 'yara-rules', 'custom');
      const yaraBundledDir = this.config.bundledYaraDir;
      this.yaraScanner
        .loadAllRules(yaraCustomDir, yaraBundledDir)
        .then((count) => {
          logger.info(`YARA rules loaded: ${count} rules / YARA 規則已載入: ${count} 條`);
        })
        .catch((err: unknown) => {
          logger.warn(
            `YARA rules load failed: ${err instanceof Error ? err.message : String(err)}`
          );
        });
    }

    // Periodic Threat Cloud sync (rules + blocklist every hour)
    // 定期同步 Threat Cloud（每小時更新規則和封鎖清單）
    this.cloudSyncTimer = setInterval(
      () => {
        void this.syncThreatCloud();
      },
      60 * 60 * 1000
    ); // 1 hour

    // Start monitor engine / 啟動監控引擎
    this.monitorEngine = new MonitorEngine({
      networkPollInterval: this.config.monitors.networkPollInterval,
      processPollInterval: this.config.monitors.processPollInterval,
    });

    this.monitorEngine.on('event', (event: SecurityEvent) => {
      void this.processEvent(event);
    });

    this.monitorEngine.start();

    // Start Falco eBPF monitor (optional, graceful degradation)
    // 啟動 Falco eBPF 監控（可選，優雅降級）
    this.falcoMonitor = new FalcoMonitor();
    const falcoAvailable = await this.falcoMonitor.checkAvailability();
    if (falcoAvailable) {
      this.falcoMonitor.on('event', (event) => void this.processEvent(event));
      await this.falcoMonitor.start();
      logger.info('Falco eBPF kernel-level monitoring active');
    }

    // Start Suricata network IDS monitor (optional, graceful degradation)
    // 啟動 Suricata 網路 IDS 監控（可選，優雅降級）
    this.suricataMonitor = new SuricataMonitor();
    const suricataAvailable = await this.suricataMonitor.checkAvailability();
    if (suricataAvailable) {
      this.suricataMonitor.on('event', (event) => void this.processEvent(event));
      await this.suricataMonitor.start();
      logger.info('Suricata network IDS monitoring active');
    }

    // Start log collector if configured / 啟動日誌收集器（如已配置）
    if (this.config.monitors.logCollector?.enabled) {
      const lcConfig = this.config.monitors.logCollector;
      this.logCollector = new LogCollector({
        filePaths: lcConfig.filePaths,
        syslogUdp: lcConfig.syslogPort ? { port: lcConfig.syslogPort } : undefined,
      });
      this.logCollector.on('event', (event) => void this.processEvent(event));
      this.logCollector.start();
      logger.info('Log collector active / 日誌收集器已啟動');
    }

    // Start agent client if manager URL is configured (distributed mode)
    // 如有設定 Manager URL 則啟動 Agent 客戶端（分散式模式）
    if (this.config.managerUrl) {
      try {
        this.agentClient = new PanguardAgentClient(this.config.managerUrl);
        const reg = await this.agentClient.register('1.0.0');
        logger.info(`Agent mode active: registered as ${reg.agentId}`);

        this.agentClient.startHeartbeat(
          (): AgentHeartbeat => ({
            eventsProcessed: this.eventsProcessed,
            threatsDetected: this.threatsDetected,
            actionsExecuted: this.actionsExecuted,
            mode: this.mode,
            uptime: Date.now() - this.startTime,
            memoryUsageMB: Math.round((process.memoryUsage().heapUsed / 1024 / 1024) * 10) / 10,
          })
        );
      } catch (err: unknown) {
        logger.warn(
          `Agent registration failed (standalone mode): ${err instanceof Error ? err.message : String(err)}`
        );
        this.agentClient = null;
      }
    }

    // Start dashboard if enabled / 啟動儀表板（如已啟用）
    const license = validateLicense(this.config.licenseKey);
    if (this.config.dashboardEnabled && hasFeature(license, 'dashboard')) {
      this.dashboard = new DashboardServer(this.config.dashboardPort);
      this.dashboard.setConfigGetter(() => this.config);
      await this.dashboard.start();
    }

    // Start watchdog if enabled / 啟動看門狗（如已啟用）
    if (this.config.watchdogEnabled) {
      this.watchdog = new Watchdog(this.config.watchdogInterval, () => {
        logger.error('Watchdog triggered restart / 看門狗觸發重啟');
      });
      this.watchdog.start();
    }

    // Periodic status update / 定期狀態更新
    this.statusTimer = setInterval(() => {
      this.updateDashboardStatus();
      this.eventCallback?.('status', {
        eventsProcessed: this.eventsProcessed,
        threatsDetected: this.threatsDetected,
        actionsExecuted: this.actionsExecuted,
        uploaded: this.threatCloudUploaded,
        mode: this.mode,
        uptime: Date.now() - this.startTime,
      });
      if (this.watchdog) this.watchdog.heartbeat();
    }, 5000);

    // Learning period check / 學習期檢查
    this.learningCheckTimer = setInterval(() => {
      this.checkLearningTransition();
    }, 60000);

    this.running = true;
    this.startTime = Date.now();

    logger.info('GuardEngine started / GuardEngine 已啟動');
  }

  /**
   * Stop the guard engine / 停止守護引擎
   */
  async stop(): Promise<void> {
    if (!this.running) return;

    logger.info('Stopping GuardEngine / 停止 GuardEngine');

    // Clear timers / 清除計時器
    if (this.statusTimer) {
      clearInterval(this.statusTimer);
      this.statusTimer = null;
    }
    if (this.learningCheckTimer) {
      clearInterval(this.learningCheckTimer);
      this.learningCheckTimer = null;
    }
    if (this.cloudSyncTimer) {
      clearInterval(this.cloudSyncTimer);
      this.cloudSyncTimer = null;
    }

    // Stop components / 停止元件
    this.atrEngine.stop();
    this.feedManager.stop();
    setFeedManager(null);
    if (this.monitorEngine) this.monitorEngine.stop();
    if (this.dashboard) await this.dashboard.stop();
    if (this.watchdog) this.watchdog.stop();
    if (this.syslogAdapter) this.syslogAdapter = null;
    if (this.falcoMonitor) {
      this.falcoMonitor.stop();
      this.falcoMonitor = null;
    }
    if (this.suricataMonitor) {
      this.suricataMonitor.stop();
      this.suricataMonitor = null;
    }
    if (this.logCollector) {
      this.logCollector.stop();
      this.logCollector = null;
    }
    if (this.agentClient) {
      this.agentClient.stopHeartbeat();
      this.agentClient = null;
    }

    // Save baseline / 儲存基線
    saveBaseline(this.baselinePath, this.baseline);

    // Flush threat cloud buffer and queue / 清空威脅雲緩衝和佇列
    await this.threatCloud.flushQueue();

    // Clean up / 清理
    this.ruleEngine.destroy();
    this.pidFile.remove();

    this.running = false;
    logger.info('GuardEngine stopped / GuardEngine 已停止');
  }

  /**
   * Process a single security event through the full pipeline
   * 透過完整管線處理單一安全事件
   */
  async processEvent(event: SecurityEvent): Promise<void> {
    this.eventsProcessed++;

    // Audit log every event / 稽核日誌記錄每個事件
    logAuditEvent({
      level: 'info',
      action: 'policy_check',
      target: event.id,
      result: 'success',
      context: { source: event.source, category: event.category },
    });
    if (this.syslogAdapter) {
      this.syslogAdapter.send({
        level: 'info',
        action: 'policy_check',
        target: event.id,
        result: 'success',
        module: 'panguard-guard',
        context: { source: event.source, description: event.description },
        timestamp: new Date().toISOString(),
      });
    }

    try {
      // YARA scan for file events / 對檔案事件執行 YARA 掃描
      if (
        event.source === 'file' &&
        this.yaraScanner.getRuleCount() > 0 &&
        event.metadata?.['filePath'] &&
        event.metadata?.['action'] !== 'deleted'
      ) {
        try {
          const yaraResult = await this.yaraScanner.scanFile(event.metadata['filePath'] as string);
          const yaraEvent = this.yaraScanner.toSecurityEvent(yaraResult);
          if (yaraEvent) {
            // Process YARA match as a separate high-priority event
            // 將 YARA 比對結果作為獨立高優先事件處理
            logger.warn(
              `YARA match: ${yaraResult.matches.map((m) => m.rule).join(', ')} in ${yaraResult.filePath}`
            );
            void this.processEvent(yaraEvent);
          }
        } catch {
          // YARA scan failure is non-fatal / YARA 掃描失敗不影響主流程
        }
      }

      // ATR evaluation for agent-related events / ATR 代理威脅規則評估
      const atrMatches = this.atrEngine.evaluate(event);

      // Stage 1: Detect / 階段 1: 偵測
      let detection = this.detectAgent.detect(event);

      // Merge ATR matches into detection pipeline / 將 ATR 匹配合併入偵測管線
      if (atrMatches.length > 0) {
        const atrRuleMatches = atrMatches.map((m) => ({
          ruleId: m.rule.id,
          ruleName: m.rule.title,
          severity: (m.rule.severity === 'informational' ? 'info' : m.rule.severity) as import('@panguard-ai/core').Severity,
        }));
        const atrMatchData = atrMatches.map((m) => ({
          ruleId: m.rule.id,
          category: m.rule.tags?.category ?? 'agent-threat',
          severity: m.rule.severity,
        }));

        if (detection) {
          // Merge ATR matches into existing detection
          detection.ruleMatches = [...detection.ruleMatches, ...atrRuleMatches];
          detection.atrMatches = atrMatchData;
        } else {
          // Create detection from ATR matches alone
          detection = {
            event,
            ruleMatches: atrRuleMatches,
            atrMatches: atrMatchData,
            timestamp: new Date().toISOString(),
          };
        }
      }

      if (!detection) {
        // No threat detected - update baseline based on mode
        // 未偵測到威脅 - 根據模式更新基線
        if (this.mode === 'learning') {
          const { updateBaseline } = await import('./memory/baseline.js');
          this.baseline = updateBaseline(this.baseline, event);
        } else {
          // Protection mode: continuous baseline update for benign non-detections
          // 防護模式：對良性非偵測事件進行持續基線更新
          const { continuousBaselineUpdate } = await import('./memory/baseline.js');
          this.baseline = continuousBaselineUpdate(this.baseline, event, 'benign');
        }
        return;
      }

      this.threatsDetected++;

      // SmartRouter: assess complexity and skip AI for high-confidence rule matches
      // SmartRouter: 評估複雜度，對高信心規則匹配跳過 AI
      if (this.smartRouter) {
        const maxRuleConfidence = Math.max(
          ...detection.ruleMatches.map((m) => {
            const severityToConfidence: Record<string, number> = {
              critical: 95,
              high: 85,
              medium: 70,
              low: 50,
              info: 30,
            };
            return severityToConfidence[m.severity] ?? 60;
          })
        );
        const hasChain = !!detection.attackChain;
        const complexity = this.smartRouter.assessComplexity(maxRuleConfidence, hasChain);

        if (complexity === 'skip') {
          logger.info(
            `SmartRouter: skipping AI for high-confidence rule match (${maxRuleConfidence}%) / ` +
              `SmartRouter: 高信心規則匹配跳過 AI (${maxRuleConfidence}%)`
          );
        }
      }

      // Stage 2: Analyze (with Dynamic Reasoning investigation)
      // 階段 2: 分析（使用動態推理調查）
      const verdict: ThreatVerdict = await this.analyzeAgent.analyze(detection, this.baseline);

      // Run investigation for suspicious/malicious verdicts
      // 對可疑/惡意判決執行調查
      if (verdict.conclusion !== 'benign') {
        const investigation = await this.investigationEngine.investigate(event);
        verdict.investigationSteps = investigation.steps;
      }

      // Stage 3: Respond / 階段 3: 回應
      const response: ResponseResult = await this.respondAgent.respond(verdict);
      if (response.action !== 'log_only') {
        this.actionsExecuted++;
      }

      // Send notifications if needed / 需要時發送通知
      if (
        response.action === 'notify' ||
        verdict.confidence >= this.config.actionPolicy.notifyAndWait
      ) {
        await sendNotifications(this.config.notifications, verdict, event.description);
      }

      // Stage 4: Report / 階段 4: 報告
      const { updatedBaseline, anonymizedData } = this.reportAgent.report(
        event,
        verdict,
        response,
        this.baseline
      );
      this.baseline = updatedBaseline;

      // Report to Manager if in agent mode / 在 Agent 模式下回報給 Manager
      if (this.agentClient?.isRegistered()) {
        this.agentClient
          .reportEvent({
            event,
            verdict: {
              conclusion: verdict.conclusion,
              confidence: verdict.confidence,
              action: response.action,
            },
          })
          .catch((err: unknown) => {
            logger.warn(
              `Agent event report failed: ${err instanceof Error ? err.message : String(err)}`
            );
          });
      }

      // Upload to threat cloud / 上傳至威脅雲
      if (anonymizedData && this.config.telemetryEnabled !== false) {
        if (this.config.showUploadData) {
          logger.info(
            `[upload-preview] Anonymized data: ${JSON.stringify(anonymizedData, null, 2)}`
          );
        }
        await this.threatCloud.upload(anonymizedData);
        this.threatCloudUploaded++;
      }

      // Notify event callback (for CLI quiet mode display)
      this.eventCallback?.('threat', {
        category: event.category,
        description: event.description,
        conclusion: verdict.conclusion,
        confidence: verdict.confidence,
        action: response.action,
        sourceIP:
          (event.metadata?.['sourceIP'] as string) ??
          (event.metadata?.['remoteAddress'] as string) ??
          'unknown',
      });

      // Update dashboard / 更新儀表板
      if (this.dashboard) {
        this.dashboard.addVerdict(verdict);
        this.dashboard.pushEvent({
          type: 'new_event',
          data: { event: event.id, verdict: verdict.conclusion, confidence: verdict.confidence },
          timestamp: new Date().toISOString(),
        });

        // Update threat map if we have IP / 如有 IP 則更新威脅地圖
        const sourceIP =
          (event.metadata?.['sourceIP'] as string) ?? (event.metadata?.['remoteAddress'] as string);
        if (sourceIP && verdict.conclusion !== 'benign') {
          this.dashboard.addThreatMapEntry({
            sourceIP,
            attackType: event.category,
            count: 1,
            lastSeen: new Date().toISOString(),
          });
        }
      }

      // Save baseline periodically / 定期儲存基線
      if (this.eventsProcessed % 100 === 0) {
        saveBaseline(this.baselinePath, this.baseline);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Event processing failed: ${msg} / 事件處理失敗: ${msg}`);
    }
  }

  /**
   * Check if learning period should transition to protection
   * 檢查學習期是否應轉換為防護模式
   */
  private checkLearningTransition(): void {
    if (this.mode !== 'learning') return;

    if (isLearningComplete(this.baseline, this.config.learningDays)) {
      logger.info('Learning period complete, switching to protection / 學習期完成，切換至防護模式');
      this.baseline = switchToProtectionMode(this.baseline);
      this.mode = 'protection';
      this.respondAgent.setMode('protection');
      this.reportAgent.setMode('protection');
      saveBaseline(this.baselinePath, this.baseline);

      if (this.dashboard) {
        this.dashboard.updateStatus({ mode: 'protection' });
        this.dashboard.pushEvent({
          type: 'learning_progress',
          data: { progress: 100, mode: 'protection' },
          timestamp: new Date().toISOString(),
        });
      }
    }
  }

  /**
   * Periodic Threat Cloud sync: re-fetch rules and blocklist
   * 定期同步 Threat Cloud：重新取得規則和封鎖清單
   */
  private async syncThreatCloud(): Promise<void> {
    try {
      // Refresh rules / 更新規則
      const cloudRules = await this.threatCloud.fetchRules();
      let newRules = 0;
      for (const rule of cloudRules) {
        try {
          const parsed = JSON.parse(rule.ruleContent) as import('@panguard-ai/core').SigmaRule;
          if (parsed.id && parsed.title && parsed.detection) {
            this.ruleEngine.addRule(parsed);
            newRules++;
          }
        } catch {
          // skip invalid
        }
      }

      // Sync ATR rules from Threat Cloud / 從 Threat Cloud 同步 ATR 規則
      let newATRRules = 0;
      try {
        const atrRules = await this.threatCloud.fetchATRRules();
        for (const rule of atrRules) {
          try {
            const parsed = JSON.parse(rule.ruleContent) as import('agent-threat-rules').ATRRule;
            if (parsed.id && parsed.title && parsed.detection) {
              this.atrEngine.addCloudRule(parsed);
              newATRRules++;
            }
          } catch {
            // skip invalid ATR rules
          }
        }
        if (newATRRules > 0) {
          logger.info(
            `ATR cloud sync: ${newATRRules} rules updated / ATR 雲端同步: ${newATRRules} 條規則更新`
          );
        }
      } catch (err: unknown) {
        logger.warn(`ATR cloud sync failed: ${err instanceof Error ? err.message : String(err)}`);
      }

      // Refresh blocklist / 更新封鎖清單
      const ips = await this.threatCloud.fetchBlocklist();
      const added =
        ips.length > 0 ? this.feedManager.addExternalIPs(ips, 'threat_cloud_blocklist', 85) : 0;

      logger.info(
        `Threat Cloud sync: ${newRules} Sigma rules, ${newATRRules} ATR rules, ${added} blocklist IPs / ` +
          `Threat Cloud 同步: ${newRules} 條 Sigma 規則, ${newATRRules} 條 ATR 規則, ${added} 個封鎖 IP`
      );
    } catch (err: unknown) {
      logger.warn(`Threat Cloud sync failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  /**
   * Update dashboard with current status / 更新儀表板狀態
   */
  private updateDashboardStatus(): void {
    if (!this.dashboard) return;

    const memUsage = process.memoryUsage();
    this.dashboard.updateStatus({
      mode: this.mode,
      uptime: Date.now() - this.startTime,
      eventsProcessed: this.eventsProcessed,
      threatsDetected: this.threatsDetected,
      actionsExecuted: this.actionsExecuted,
      learningProgress: getLearningProgress(this.baseline, this.config.learningDays),
      baselineConfidence: this.baseline.confidenceLevel,
      memoryUsageMB: Math.round((memUsage.heapUsed / 1024 / 1024) * 10) / 10,
      cpuPercent: 0, // CPU tracking would need os.cpus()
    });
  }

  /**
   * Register event callback for external consumers (e.g. CLI quiet mode).
   * 註冊事件回調給外部消費者（如 CLI 安靜模式）。
   */
  setEventCallback(cb: (type: string, data: Record<string, unknown>) => void): void {
    this.eventCallback = cb;
  }

  /**
   * Apply a policy update by iterating over its rules and dispatching
   * each to the appropriate agent method.
   * 套用策略更新，遍歷其規則並分派給適當的代理方法。
   *
   * Supported rule types:
   * - block_ip: calls respondAgent.addBlockedIP(condition.ip)
   * - alert_threshold: calls respondAgent.updateActionPolicy({ autoRespond, notifyAndWait })
   * - auto_respond: calls respondAgent.updateActionPolicy({ autoRespond: 90 | 100 })
   * Other rule types are silently ignored.
   */
  private applyPolicy(policy: { rules: Array<{ type: string; condition: Record<string, unknown>; action: string; description: string }> }): void {
    for (const rule of policy.rules) {
      switch (rule.type) {
        case 'block_ip': {
          const ip = rule.condition['ip'] as string | undefined;
          if (ip) {
            void this.respondAgent.addBlockedIP(ip);
          }
          break;
        }
        case 'alert_threshold': {
          const updates: Partial<import('./types.js').ActionPolicy> = {};
          if (typeof rule.condition['autoRespond'] === 'number') {
            updates.autoRespond = rule.condition['autoRespond'] as number;
          }
          if (typeof rule.condition['notifyAndWait'] === 'number') {
            updates.notifyAndWait = rule.condition['notifyAndWait'] as number;
          }
          if (Object.keys(updates).length > 0) {
            this.respondAgent.updateActionPolicy(updates);
          }
          break;
        }
        case 'auto_respond': {
          const enabled = rule.condition['enabled'] as boolean | undefined;
          if (enabled === true) {
            this.respondAgent.updateActionPolicy({ autoRespond: 90 });
          } else if (enabled === false) {
            this.respondAgent.updateActionPolicy({ autoRespond: 100 });
          }
          break;
        }
        default:
          // Unknown rule type: silently ignore
          break;
      }
    }
  }

  /**
   * Poll the Manager for a policy update.
   * Does nothing if the agent client is not registered.
   * 向 Manager 輪詢策略更新。若代理客戶端未登錄則不執行任何操作。
   */
  private async pollPolicy(): Promise<void> {
    if (!this.agentClient) return;
    // agentClient.pollPolicy is invoked here when registered
    // (implementation detail: agentClient may provide this method)
    try {
      if (typeof (this.agentClient as unknown as { pollPolicy?: () => Promise<void> }).pollPolicy === 'function') {
        await (this.agentClient as unknown as { pollPolicy: () => Promise<void> }).pollPolicy();
      }
    } catch (err: unknown) {
      logger.warn(`Policy poll failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  /**
   * Get current engine status / 取得引擎狀態
   */
  getStatus(): GuardStatus {
    const license = validateLicense(this.config.licenseKey);
    const memUsage = process.memoryUsage();

    return {
      running: this.running,
      mode: this.mode,
      uptime: this.running ? Date.now() - this.startTime : 0,
      eventsProcessed: this.eventsProcessed,
      threatsDetected: this.threatsDetected,
      actionsExecuted: this.actionsExecuted,
      learningProgress: getLearningProgress(this.baseline, this.config.learningDays),
      baselineConfidence: this.baseline.confidenceLevel,
      memoryUsageMB: Math.round((memUsage.heapUsed / 1024 / 1024) * 10) / 10,
      licenseTier: license.tier,
      atrRuleCount: this.atrEngine.getRuleCount(),
      atrMatchCount: this.atrEngine.getMatchCount(),
    };
  }

  /**
   * Get loaded rule counts for each engine layer.
   * 取得各引擎層已載入的規則數量。
   */
  getRuleCounts(): { sigma: number; atr: number; yara: number } {
    return {
      sigma: this.ruleEngine.getRules().length,
      atr: this.atrEngine.getRuleCount(),
      yara: this.yaraScanner.getRuleCount(),
    };
  }

  /**
   * Get the current baseline / 取得當前基線
   */
  getBaseline(): EnvironmentBaseline {
    return this.baseline;
  }

  /**
   * Check if engine is running / 檢查引擎是否執行中
   */
  isRunning(): boolean {
    return this.running;
  }
}
