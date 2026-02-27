/**
 * Base trap service implementation
 * 蜜罐基底服務實作
 *
 * Provides common functionality for all trap services:
 * - TCP server lifecycle
 * - Session management
 * - Event recording
 * 提供所有蜜罐服務的共用功能：
 * - TCP 伺服器生命週期
 * - 連線管理
 * - 事件記錄
 *
 * @module @panguard-ai/panguard-trap/services/base-service
 */

import { createLogger } from '@panguard-ai/core';
import type {
  TrapServiceType,
  TrapServiceStatus,
  TrapServiceConfig,
  TrapSession,
  TrapEvent,
  TrapEventType,
  CredentialAttempt,
  TrapService,
  SessionHandler,
} from '../types.js';

const logger = createLogger('panguard-trap:service:base');

let sessionCounter = 0;

/** Generate unique session ID / 產生唯一連線 ID */
function generateSessionId(serviceType: TrapServiceType): string {
  sessionCounter += 1;
  const ts = Date.now().toString(36);
  const cnt = sessionCounter.toString(36).padStart(4, '0');
  return `${serviceType}-${ts}-${cnt}`;
}

/**
 * Abstract base class for all trap services
 * 所有蜜罐服務的抽象基底類別
 */
export abstract class BaseTrapService implements TrapService {
  readonly serviceType: TrapServiceType;
  private _status: TrapServiceStatus = 'stopped';
  protected readonly config: TrapServiceConfig;
  protected activeSessions: Map<string, TrapSession> = new Map();
  protected completedSessionCount = 0;
  private sessionHandlers: SessionHandler[] = [];

  constructor(config: TrapServiceConfig) {
    this.serviceType = config.type;
    this.config = config;
  }

  get status(): TrapServiceStatus {
    return this._status;
  }

  protected setStatus(status: TrapServiceStatus): void {
    this._status = status;
  }

  /**
   * Start the service
   * 啟動服務
   */
  async start(): Promise<void> {
    if (this._status === 'running') return;
    this._status = 'starting';
    try {
      await this.doStart();
      this._status = 'running';
      logger.info(
        `${this.serviceType} trap started on port ${this.config.port} / ${this.serviceType} 蜜罐已啟動於埠 ${this.config.port}`
      );
    } catch (err) {
      this._status = 'error';
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`${this.serviceType} trap start failed: ${msg} / 啟動失敗: ${msg}`);
      throw err;
    }
  }

  /**
   * Stop the service
   * 停止服務
   */
  async stop(): Promise<void> {
    if (this._status === 'stopped') return;
    try {
      // Close all active sessions
      for (const [sessionId, session] of this.activeSessions) {
        this.endSession(sessionId, session);
      }
      await this.doStop();
      this._status = 'stopped';
      logger.info(`${this.serviceType} trap stopped / ${this.serviceType} 蜜罐已停止`);
    } catch (err) {
      this._status = 'error';
      throw err;
    }
  }

  getActiveSessions(): TrapSession[] {
    return Array.from(this.activeSessions.values());
  }

  getTotalSessionCount(): number {
    return this.completedSessionCount + this.activeSessions.size;
  }

  onSession(handler: SessionHandler): void {
    this.sessionHandlers.push(handler);
  }

  // -------------------------------------------------------------------------
  // Session Management (for subclasses)
  // 連線管理（供子類別使用）
  // -------------------------------------------------------------------------

  /** Create a new session / 建立新連線 */
  protected createSession(sourceIP: string, sourcePort: number): TrapSession {
    const session: TrapSession = {
      sessionId: generateSessionId(this.serviceType),
      serviceType: this.serviceType,
      sourceIP,
      sourcePort,
      startTime: new Date(),
      events: [],
      credentials: [],
      commands: [],
      mitreTechniques: [],
    };
    this.activeSessions.set(session.sessionId, session);

    this.recordEvent(session.sessionId, 'connection', `${sourceIP}:${sourcePort}`);

    logger.info(
      `New ${this.serviceType} session from ${sourceIP}:${sourcePort} (${session.sessionId}) / 新連線`
    );
    return session;
  }

  /** End a session / 結束連線 */
  protected endSession(sessionId: string, session?: TrapSession): TrapSession | undefined {
    const s = session ?? this.activeSessions.get(sessionId);
    if (!s) return undefined;

    s.endTime = new Date();
    s.durationMs = s.endTime.getTime() - s.startTime.getTime();
    this.recordEvent(sessionId, 'disconnection', `duration=${s.durationMs}ms`);

    this.activeSessions.delete(sessionId);
    this.completedSessionCount += 1;

    // Notify session handlers
    for (const handler of this.sessionHandlers) {
      try {
        handler(s);
      } catch {
        // ignore handler errors
      }
    }

    logger.info(
      `Session ended: ${sessionId} (${s.durationMs}ms, ${s.events.length} events) / 連線結束`
    );
    return s;
  }

  /** Record an event in a session / 在連線中記錄事件 */
  protected recordEvent(
    sessionId: string,
    type: TrapEventType,
    data: string,
    details?: Record<string, unknown>
  ): TrapEvent | undefined {
    const session = this.activeSessions.get(sessionId);
    if (!session) return undefined;

    const event: TrapEvent = {
      timestamp: new Date(),
      type,
      data,
      details,
    };
    session.events.push(event);
    return event;
  }

  /** Record a credential attempt / 記錄認證嘗試 */
  protected recordCredential(
    sessionId: string,
    username: string,
    password: string,
    grantedAccess: boolean
  ): void {
    const session = this.activeSessions.get(sessionId);
    if (!session) return;

    const attempt: CredentialAttempt = {
      timestamp: new Date(),
      username,
      password,
      grantedAccess,
    };
    session.credentials.push(attempt);

    this.recordEvent(sessionId, 'authentication_attempt', `${username}:***`, {
      username,
      grantedAccess,
    });
  }

  /** Record a command input / 記錄指令輸入 */
  protected recordCommand(sessionId: string, command: string): void {
    const session = this.activeSessions.get(sessionId);
    if (!session) return;

    session.commands.push(command);
    this.recordEvent(sessionId, 'command_input', command);
  }

  /** Add MITRE technique to session / 新增 MITRE 技術到連線 */
  protected addMitreTechnique(sessionId: string, technique: string): void {
    const session = this.activeSessions.get(sessionId);
    if (!session) return;
    if (!session.mitreTechniques.includes(technique)) {
      session.mitreTechniques.push(technique);
    }
  }

  // -------------------------------------------------------------------------
  // Abstract methods (for subclasses)
  // 抽象方法（供子類別實作）
  // -------------------------------------------------------------------------

  /** Subclass starts the actual TCP server / 子類別啟動實際 TCP 伺服器 */
  protected abstract doStart(): Promise<void>;

  /** Subclass stops the actual TCP server / 子類別停止實際 TCP 伺服器 */
  protected abstract doStop(): Promise<void>;
}
