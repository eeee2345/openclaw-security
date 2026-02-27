/**
 * PanguardTrap type definitions
 * PanguardTrap 型別定義
 * @module @panguard-ai/panguard-trap/types
 */

// ---------------------------------------------------------------------------
// Service Types
// 服務類型
// ---------------------------------------------------------------------------

/** Supported honeypot service types / 支援的蜜罐服務類型 */
export type TrapServiceType = 'ssh' | 'http' | 'ftp' | 'smb' | 'mysql' | 'rdp' | 'telnet' | 'redis';

/** Trap service status / 蜜罐服務狀態 */
export type TrapServiceStatus = 'stopped' | 'starting' | 'running' | 'error';

/** Trap engine status / 蜜罐引擎狀態 */
export type TrapEngineStatus = 'idle' | 'running' | 'stopping' | 'error';

// ---------------------------------------------------------------------------
// Service Configuration
// 服務配置
// ---------------------------------------------------------------------------

/** Configuration for a single trap service / 單一蜜罐服務配置 */
export interface TrapServiceConfig {
  /** Service type / 服務類型 */
  type: TrapServiceType;
  /** Listen port / 監聽埠 */
  port: number;
  /** Whether enabled / 是否啟用 */
  enabled: boolean;
  /** Service banner / 服務橫幅 (e.g., "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6") */
  banner?: string;
  /** Max concurrent connections / 最大併發連線 */
  maxConnections?: number;
  /** Session timeout in ms / 連線逾時 (毫秒) */
  sessionTimeoutMs?: number;
  /** Custom response delay to simulate real service / 模擬真實服務的回應延遲 (毫秒) */
  responseDelayMs?: number;
}

/** Default service configurations / 預設服務配置 */
export const DEFAULT_SERVICE_CONFIGS: Record<
  TrapServiceType,
  Omit<TrapServiceConfig, 'enabled'>
> = {
  ssh: {
    type: 'ssh',
    port: 2222,
    banner: 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6',
    maxConnections: 50,
    sessionTimeoutMs: 30_000,
    responseDelayMs: 100,
  },
  http: {
    type: 'http',
    port: 8080,
    banner: 'Apache/2.4.57 (Ubuntu)',
    maxConnections: 100,
    sessionTimeoutMs: 60_000,
    responseDelayMs: 50,
  },
  ftp: {
    type: 'ftp',
    port: 2121,
    banner: '220 ProFTPD 1.3.8 Server (Panguard) [::ffff:0.0.0.0]',
    maxConnections: 30,
    sessionTimeoutMs: 30_000,
    responseDelayMs: 100,
  },
  smb: {
    type: 'smb',
    port: 4450,
    maxConnections: 20,
    sessionTimeoutMs: 30_000,
    responseDelayMs: 150,
  },
  mysql: {
    type: 'mysql',
    port: 3307,
    banner: '5.7.42-0ubuntu0.18.04.1',
    maxConnections: 30,
    sessionTimeoutMs: 30_000,
    responseDelayMs: 80,
  },
  rdp: {
    type: 'rdp',
    port: 3390,
    maxConnections: 10,
    sessionTimeoutMs: 60_000,
    responseDelayMs: 200,
  },
  telnet: {
    type: 'telnet',
    port: 2323,
    banner: 'Ubuntu 22.04 LTS',
    maxConnections: 30,
    sessionTimeoutMs: 30_000,
    responseDelayMs: 100,
  },
  redis: {
    type: 'redis',
    port: 6380,
    maxConnections: 20,
    sessionTimeoutMs: 30_000,
    responseDelayMs: 30,
  },
};

// ---------------------------------------------------------------------------
// Session & Event Tracking
// 連線 & 事件追蹤
// ---------------------------------------------------------------------------

/** A single interaction event in a trap session / 蜜罐連線中的單一互動事件 */
export interface TrapEvent {
  /** Timestamp / 時間戳 */
  timestamp: Date;
  /** Event type / 事件類型 */
  type: TrapEventType;
  /** Raw data from attacker / 攻擊者的原始資料 */
  data: string;
  /** Parsed details / 解析後的細節 */
  details?: Record<string, unknown>;
}

/** Trap event types / 蜜罐事件類型 */
export type TrapEventType =
  | 'connection'
  | 'disconnection'
  | 'authentication_attempt'
  | 'command_input'
  | 'file_upload'
  | 'file_download'
  | 'port_scan'
  | 'exploit_attempt'
  | 'data_exfiltration'
  | 'lateral_movement'
  | 'privilege_escalation';

/** A complete trap session from connect to disconnect / 完整的蜜罐連線，從連線到斷線 */
export interface TrapSession {
  /** Unique session ID / 唯一連線 ID */
  sessionId: string;
  /** Service type / 服務類型 */
  serviceType: TrapServiceType;
  /** Source IP / 來源 IP */
  sourceIP: string;
  /** Source port / 來源埠 */
  sourcePort: number;
  /** Connection start time / 連線開始時間 */
  startTime: Date;
  /** Connection end time / 連線結束時間 */
  endTime?: Date;
  /** Duration in ms / 持續時間 (毫秒) */
  durationMs?: number;
  /** Events recorded / 記錄的事件 */
  events: TrapEvent[];
  /** Credentials attempted / 嘗試的認證資訊 */
  credentials: CredentialAttempt[];
  /** Commands executed / 執行的指令 */
  commands: string[];
  /** MITRE ATT&CK techniques observed / 觀察到的 MITRE ATT&CK 技術 */
  mitreTechniques: string[];
  /** Attacker profile reference / 攻擊者 profile 參照 */
  attackerProfileId?: string;
}

/** Credential attempt / 認證嘗試 */
export interface CredentialAttempt {
  /** Timestamp / 時間戳 */
  timestamp: Date;
  /** Username attempted / 嘗試的使用者名稱 */
  username: string;
  /** Password attempted / 嘗試的密碼 */
  password: string;
  /** Whether the honeypot pretended success / 蜜罐是否假裝成功 */
  grantedAccess: boolean;
}

// ---------------------------------------------------------------------------
// Attacker Profiling
// 攻擊者分析
// ---------------------------------------------------------------------------

/** Attacker skill level / 攻擊者技術水準 */
export type AttackerSkillLevel = 'script_kiddie' | 'intermediate' | 'advanced' | 'apt';

/** Attacker intent / 攻擊者意圖 */
export type AttackerIntent =
  | 'reconnaissance'
  | 'credential_harvesting'
  | 'ransomware_deployment'
  | 'cryptomining'
  | 'data_theft'
  | 'botnet_recruitment'
  | 'lateral_movement'
  | 'unknown';

/** Attacker profile / 攻擊者 profile */
export interface AttackerProfile {
  /** Profile ID / Profile ID */
  profileId: string;
  /** Source IPs associated / 關聯的來源 IP */
  sourceIPs: string[];
  /** First seen / 首次出現 */
  firstSeen: Date;
  /** Last seen / 最近活動 */
  lastSeen: Date;
  /** Total sessions / 總連線數 */
  totalSessions: number;
  /** Estimated skill level / 估計技術水準 */
  skillLevel: AttackerSkillLevel;
  /** Estimated intent / 估計意圖 */
  intent: AttackerIntent;
  /** Tools detected / 偵測到的工具 */
  toolsDetected: string[];
  /** MITRE ATT&CK techniques / MITRE ATT&CK 技術 */
  mitreTechniques: string[];
  /** Credential patterns (common usernames/passwords) / 認證模式 */
  credentialPatterns: {
    commonUsernames: string[];
    commonPasswords: string[];
    totalAttempts: number;
  };
  /** Geographic hints / 地理位置線索 */
  geoHints: {
    country?: string;
    timezone?: string;
    language?: string;
  };
  /** Risk score 0-100 / 風險分數 0-100 */
  riskScore: number;
  /** Human readable summary (bilingual) / 人類可讀摘要（雙語） */
  summary?: { 'zh-TW': string; en: string };
}

// ---------------------------------------------------------------------------
// Trap Intelligence (for Threat Cloud)
// 蜜罐情報（回饋 Threat Cloud）
// ---------------------------------------------------------------------------

/** Anonymized trap intel for upload / 匿名化蜜罐情報，用於上傳 */
export interface TrapIntelligence {
  /** Timestamp / 時間戳 */
  timestamp: Date;
  /** Service targeted / 目標服務 */
  serviceType: TrapServiceType;
  /** Source IP (public only) / 來源 IP（僅公網） */
  sourceIP: string;
  /** Attack type / 攻擊類型 */
  attackType: string;
  /** MITRE techniques / MITRE 技術 */
  mitreTechniques: string[];
  /** Skill level / 技術水準 */
  skillLevel: AttackerSkillLevel;
  /** Intent / 意圖 */
  intent: AttackerIntent;
  /** Tools / 工具 */
  tools: string[];
  /** Top credentials (generic, not customer-specific) / 常見認證（通用，非客戶特定） */
  topCredentials: { username: string; count: number }[];
  /** Region (country-level) / 地區（國家級） */
  region?: string;
}

// ---------------------------------------------------------------------------
// Engine Configuration
// 引擎配置
// ---------------------------------------------------------------------------

/** PanguardTrap main config / PanguardTrap 主要配置 */
export interface TrapConfig {
  /** Services to deploy / 部署的服務 */
  services: TrapServiceConfig[];
  /** Data directory for session logs / 連線日誌資料目錄 */
  dataDir: string;
  /** Max sessions to retain in memory / 記憶體中保留的最大連線數 */
  maxSessionsInMemory: number;
  /** Whether to feed intel to Threat Cloud / 是否回饋情報到 Threat Cloud */
  feedThreatCloud: boolean;
  /** Threat Cloud endpoint / Threat Cloud 端點 */
  threatCloudEndpoint?: string;
  /** Whether to grant fake access after N attempts / 在 N 次嘗試後是否給予假存取 */
  grantFakeAccess: boolean;
  /** Number of failed attempts before granting fake access / 給予假存取前的失敗嘗試次數 */
  fakeAccessAfterAttempts: number;
  /** Notify channels on high-value catches / 高價值捕獲時通知管道 */
  notifyOnHighValue: boolean;
}

/** Default trap configuration / 預設蜜罐配置 */
export const DEFAULT_TRAP_CONFIG: TrapConfig = {
  services: [
    { ...DEFAULT_SERVICE_CONFIGS.ssh, enabled: true },
    { ...DEFAULT_SERVICE_CONFIGS.http, enabled: true },
    { ...DEFAULT_SERVICE_CONFIGS.ftp, enabled: false },
    { ...DEFAULT_SERVICE_CONFIGS.mysql, enabled: false },
    { ...DEFAULT_SERVICE_CONFIGS.telnet, enabled: false },
    { ...DEFAULT_SERVICE_CONFIGS.redis, enabled: false },
    { ...DEFAULT_SERVICE_CONFIGS.smb, enabled: false },
    { ...DEFAULT_SERVICE_CONFIGS.rdp, enabled: false },
  ],
  dataDir: '/var/lib/panguard/trap',
  maxSessionsInMemory: 1000,
  feedThreatCloud: true,
  grantFakeAccess: true,
  fakeAccessAfterAttempts: 3,
  notifyOnHighValue: true,
};

// ---------------------------------------------------------------------------
// Service Interface
// 服務介面
// ---------------------------------------------------------------------------

/** Interface for a trap service implementation / 蜜罐服務實作介面 */
export interface TrapService {
  /** Service type / 服務類型 */
  readonly serviceType: TrapServiceType;
  /** Current status / 目前狀態 */
  readonly status: TrapServiceStatus;
  /** Start the service / 啟動服務 */
  start(): Promise<void>;
  /** Stop the service / 停止服務 */
  stop(): Promise<void>;
  /** Get active sessions / 取得活動中連線 */
  getActiveSessions(): TrapSession[];
  /** Get total sessions count / 取得總連線數 */
  getTotalSessionCount(): number;
  /** Register session handler / 註冊連線處理器 */
  onSession(handler: (session: TrapSession) => void): void;
}

/** Session handler type / 連線處理器類型 */
export type SessionHandler = (session: TrapSession) => void;

// ---------------------------------------------------------------------------
// Statistics
// 統計
// ---------------------------------------------------------------------------

/** Trap statistics / 蜜罐統計 */
export interface TrapStatistics {
  /** Total sessions / 總連線數 */
  totalSessions: number;
  /** Active sessions / 活動中連線數 */
  activeSessions: number;
  /** Unique source IPs / 不重複來源 IP 數 */
  uniqueSourceIPs: number;
  /** Total credential attempts / 總認證嘗試次數 */
  totalCredentialAttempts: number;
  /** Total commands captured / 總捕獲指令數 */
  totalCommandsCaptured: number;
  /** Sessions by service type / 依服務類型分類的連線數 */
  sessionsByService: Record<TrapServiceType, number>;
  /** Top attacker IPs / 前幾名攻擊者 IP */
  topAttackerIPs: { ip: string; sessions: number; riskScore: number }[];
  /** Top usernames / 前幾名嘗試的使用者名稱 */
  topUsernames: { username: string; count: number }[];
  /** Top passwords / 前幾名嘗試的密碼 */
  topPasswords: { password: string; count: number }[];
  /** Attacker skill distribution / 攻擊者技術水準分布 */
  skillDistribution: Record<AttackerSkillLevel, number>;
  /** Attacker intent distribution / 攻擊者意圖分布 */
  intentDistribution: Record<AttackerIntent, number>;
  /** Uptime in ms / 運作時間 (毫秒) */
  uptimeMs: number;
}
