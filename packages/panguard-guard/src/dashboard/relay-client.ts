/**
 * Dashboard Relay Client - Connects the local dashboard to a remote Manager
 * Dashboard Relay Client - 將本地 dashboard 連接到遠端 Manager
 *
 * Establishes a WebSocket connection upstream to the Manager's relay endpoint,
 * forwarding all local dashboard events and receiving commands from the Manager.
 *
 * Uses Node.js built-in http module with native RFC 6455 WebSocket handshake
 * (same approach as dashboard/index.ts).
 *
 * @module @panguard-ai/panguard-guard/dashboard/relay-client
 */

import { EventEmitter } from 'node:events';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { randomBytes } from 'node:crypto';
import type { Socket } from 'node:net';
import { createLogger } from '@panguard-ai/core';

const logger = createLogger('panguard-guard:dashboard-relay');

/** Maximum reconnect backoff in milliseconds / 最大重連延遲（毫秒） */
const MAX_RECONNECT_MS = 30_000;
/** Default reconnect interval in milliseconds / 預設重連間隔（毫秒） */
const DEFAULT_RECONNECT_MS = 2_000;

export interface RelayClientConfig {
  /** Manager URL to connect to / 要連接的 Manager URL */
  readonly managerUrl: string;
  /** Agent ID for identification / 用於識別的 Agent ID */
  readonly agentId: string;
  /** Auth token / 認證 token */
  readonly token: string;
  /** Reconnect interval in ms / 重連間隔（毫秒） */
  readonly reconnectInterval?: number;
}

/**
 * Dashboard relay client -- connects the local dashboard to a remote Manager
 * Dashboard relay client -- 將本地 dashboard 連接到遠端 Manager
 */
export class DashboardRelayClient extends EventEmitter {
  private readonly config: RelayClientConfig;
  private readonly reconnectBaseMs: number;
  private socket: Socket | null = null;
  private connected = false;
  private reconnectAttempts = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private intentionalDisconnect = false;

  constructor(config: RelayClientConfig) {
    super();

    if (!config.managerUrl) {
      throw new Error('managerUrl is required / managerUrl 為必要參數');
    }
    if (!config.agentId) {
      throw new Error('agentId is required / agentId 為必要參數');
    }
    if (!config.token) {
      throw new Error('token is required / token 為必要參數');
    }

    this.config = config;
    this.reconnectBaseMs = config.reconnectInterval ?? DEFAULT_RECONNECT_MS;
  }

  /** Check if connected / 檢查是否已連接 */
  get isConnected(): boolean {
    return this.connected;
  }

  /**
   * Connect to Manager relay endpoint / 連接到 Manager relay 端點
   *
   * Initiates a WebSocket upgrade request to:
   *   ws://{managerUrl}/api/dashboard/relay/{agentId}
   */
  connect(): void {
    if (this.connected || this.socket) {
      logger.warn('Already connected or connecting / 已經連接或正在連接');
      return;
    }

    this.intentionalDisconnect = false;
    this.initiateConnection();
  }

  /**
   * Disconnect from Manager / 斷開與 Manager 的連接
   */
  disconnect(): void {
    this.intentionalDisconnect = true;

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    if (this.socket) {
      try {
        // Send close frame (opcode 0x08) / 發送關閉框架
        const closeFrame = Buffer.alloc(6);
        closeFrame[0] = 0x88; // FIN + close opcode
        closeFrame[1] = 0x80; // masked, 0 payload
        // Write 4 masking key bytes (all zero is fine for close)
        this.socket.write(closeFrame);
        this.socket.destroy();
      } catch {
        /* ignore close errors / 忽略關閉錯誤 */
      }
      this.socket = null;
    }

    this.setConnected(false);
    this.reconnectAttempts = 0;
  }

  /**
   * Send a dashboard event upstream / 向上游發送 dashboard 事件
   */
  sendEvent(event: Record<string, unknown>): void {
    if (!this.connected || !this.socket) {
      logger.debug('Cannot send event: not connected / 無法發送事件：未連接');
      return;
    }

    try {
      const data = JSON.stringify(event);
      const payload = Buffer.from(data, 'utf-8');
      const frame = this.createMaskedWSFrame(payload);
      this.socket.write(frame);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      logger.warn(`Failed to send relay event: ${message} / 發送 relay 事件失敗`);
    }
  }

  // ---------------------------------------------------------------------------
  // Private helpers / 私有輔助函數
  // ---------------------------------------------------------------------------

  /** Initiate WebSocket upgrade connection / 發起 WebSocket 升級連接 */
  private initiateConnection(): void {
    const url = this.buildRelayUrl();
    let parsedUrl: URL;

    try {
      parsedUrl = new URL(url);
    } catch {
      logger.error(`Invalid relay URL: ${url} / 無效的 relay URL`);
      this.emit('error', new Error(`Invalid relay URL: ${url}`));
      return;
    }

    const isHttps = parsedUrl.protocol === 'https:' || parsedUrl.protocol === 'wss:';
    const doRequest = isHttps ? httpsRequest : httpRequest;
    const port = parsedUrl.port || (isHttps ? '443' : '80');
    const wsKey = randomBytes(16).toString('base64');

    const req = doRequest(
      {
        hostname: parsedUrl.hostname,
        port: Number(port),
        path: parsedUrl.pathname,
        method: 'GET',
        headers: {
          'Upgrade': 'websocket',
          'Connection': 'Upgrade',
          'Sec-WebSocket-Key': wsKey,
          'Sec-WebSocket-Version': '13',
          'Authorization': `Bearer ${this.config.token}`,
          'X-Agent-Id': this.config.agentId,
        },
        timeout: 10_000,
      }
    );

    req.on('upgrade', (_res, socket: Socket, _head: Buffer) => {
      this.socket = socket;
      this.reconnectAttempts = 0;
      this.setConnected(true);

      logger.info(
        `Relay connected to Manager for agent ${this.config.agentId} / ` +
          `Relay 已連接到 Manager`
      );

      socket.on('data', (data: Buffer) => {
        this.handleIncomingData(data);
      });

      socket.on('close', () => {
        this.handleSocketClose();
      });

      socket.on('error', (err: Error) => {
        logger.warn(`Relay socket error: ${err.message} / Relay 連線錯誤`);
        this.handleSocketClose();
      });
    });

    req.on('error', (err: Error) => {
      logger.warn(
        `Relay connection failed: ${err.message} / Relay 連接失敗`
      );
      this.emit('error', err);
      this.scheduleReconnect();
    });

    req.on('timeout', () => {
      req.destroy();
      logger.warn('Relay connection timed out / Relay 連接逾時');
      this.scheduleReconnect();
    });

    // Response without upgrade means the server rejected / 非升級回應表示伺服器拒絕
    req.on('response', (res) => {
      logger.warn(
        `Relay upgrade rejected with status ${res.statusCode} / ` +
          `Relay 升級被拒絕，狀態碼 ${res.statusCode}`
      );
      this.emit('error', new Error(`Upgrade rejected: HTTP ${res.statusCode}`));
      this.scheduleReconnect();
    });

    req.end();
  }

  /** Build the relay WebSocket URL / 建構 relay WebSocket URL */
  private buildRelayUrl(): string {
    const base = this.config.managerUrl.replace(/\/+$/, '');
    // Convert ws:// -> http:// and wss:// -> https:// for Node.js http module
    const httpBase = base
      .replace(/^ws:/, 'http:')
      .replace(/^wss:/, 'https:');
    return `${httpBase}/api/dashboard/relay/${this.config.agentId}`;
  }

  /** Handle incoming WebSocket data from Manager / 處理從 Manager 收到的 WebSocket 資料 */
  private handleIncomingData(data: Buffer): void {
    if (data.length < 2) return;

    const firstByte = data[0] ?? 0;
    const opcode = firstByte & 0x0f;

    // Ping frame -> respond with pong / Ping 框架 -> 回應 pong
    if (opcode === 0x09) {
      this.sendPong(data);
      return;
    }

    // Pong frame -> ignore / Pong 框架 -> 忽略
    if (opcode === 0x0a) {
      return;
    }

    // Close frame -> handle disconnection / 關閉框架 -> 處理斷線
    if (opcode === 0x08) {
      this.handleSocketClose();
      return;
    }

    // Text frame -> parse and emit / 文字框架 -> 解析並發送事件
    if (opcode === 0x01) {
      try {
        const payload = this.extractPayload(data);
        if (payload) {
          const message = JSON.parse(payload.toString('utf-8'));
          this.emit('message', message);
        }
      } catch {
        logger.debug('Failed to parse incoming relay message / 無法解析收到的 relay 訊息');
      }
    }
  }

  /** Extract payload from a WebSocket frame (server frames are unmasked) / 從 WebSocket 框架提取載荷 */
  private extractPayload(data: Buffer): Buffer | null {
    if (data.length < 2) return null;

    const secondByte = data[1] ?? 0;
    const masked = (secondByte & 0x80) !== 0;
    let payloadLength = secondByte & 0x7f;
    let offset = 2;

    if (payloadLength === 126) {
      if (data.length < 4) return null;
      payloadLength = data.readUInt16BE(2);
      offset = 4;
    } else if (payloadLength === 127) {
      if (data.length < 10) return null;
      payloadLength = Number(data.readBigUInt64BE(2));
      offset = 10;
    }

    if (masked) {
      // Server frames should not be masked, but handle gracefully
      // 伺服器框架不應被遮罩，但優雅處理
      if (data.length < offset + 4 + payloadLength) return null;
      const maskKey = data.subarray(offset, offset + 4);
      offset += 4;
      const payload = Buffer.alloc(payloadLength);
      for (let i = 0; i < payloadLength; i++) {
        payload[i] = (data[offset + i] ?? 0) ^ (maskKey[i % 4] ?? 0);
      }
      return payload;
    }

    if (data.length < offset + payloadLength) return null;
    return data.subarray(offset, offset + payloadLength);
  }

  /** Send a pong frame in response to a ping / 回應 ping 發送 pong 框架 */
  private sendPong(_pingData: Buffer): void {
    if (!this.socket) return;

    try {
      // Construct a masked pong frame / 建構帶遮罩的 pong 框架
      const pongFrame = Buffer.alloc(6);
      pongFrame[0] = 0x8a; // FIN + pong opcode
      pongFrame[1] = 0x80; // masked, 0 payload length
      // 4 bytes masking key (zeros)
      this.socket.write(pongFrame);
    } catch {
      /* ignore pong errors / 忽略 pong 錯誤 */
    }
  }

  /** Handle socket close event / 處理 socket 關閉事件 */
  private handleSocketClose(): void {
    if (this.socket) {
      try {
        this.socket.destroy();
      } catch {
        /* ignore */
      }
      this.socket = null;
    }

    this.setConnected(false);

    if (!this.intentionalDisconnect) {
      this.scheduleReconnect();
    }
  }

  /** Schedule a reconnection attempt with exponential backoff / 排程指數退避重連 */
  private scheduleReconnect(): void {
    if (this.intentionalDisconnect || this.reconnectTimer) return;

    const delay = Math.min(
      this.reconnectBaseMs * Math.pow(2, this.reconnectAttempts),
      MAX_RECONNECT_MS
    );
    this.reconnectAttempts++;

    logger.info(
      `Scheduling relay reconnect in ${delay}ms (attempt ${this.reconnectAttempts}) / ` +
        `排程 relay 重連於 ${delay}ms 後（第 ${this.reconnectAttempts} 次嘗試）`
    );

    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.initiateConnection();
    }, delay);
  }

  /** Update connected state and emit events / 更新連接狀態並發送事件 */
  private setConnected(value: boolean): void {
    const changed = this.connected !== value;
    this.connected = value;

    if (changed) {
      this.emit(value ? 'connected' : 'disconnected');
    }
  }

  /**
   * Create a masked WebSocket text frame (client->server must be masked per RFC 6455)
   * 建立帶遮罩的 WebSocket 文字框架（客戶端->伺服器依 RFC 6455 必須帶遮罩）
   */
  private createMaskedWSFrame(payload: Buffer): Buffer {
    const length = payload.length;
    const maskKey = randomBytes(4);
    let header: Buffer;

    if (length < 126) {
      header = Buffer.alloc(6);
      header[0] = 0x81; // FIN + text opcode
      header[1] = 0x80 | length; // masked + length
      maskKey.copy(header, 2);
    } else if (length < 65536) {
      header = Buffer.alloc(8);
      header[0] = 0x81;
      header[1] = 0x80 | 126; // masked + 126 indicator
      header.writeUInt16BE(length, 2);
      maskKey.copy(header, 4);
    } else {
      header = Buffer.alloc(14);
      header[0] = 0x81;
      header[1] = 0x80 | 127; // masked + 127 indicator
      header.writeBigUInt64BE(BigInt(length), 2);
      maskKey.copy(header, 10);
    }

    // Mask the payload / 遮罩載荷
    const maskedPayload = Buffer.alloc(length);
    for (let i = 0; i < length; i++) {
      maskedPayload[i] = (payload[i] ?? 0) ^ (maskKey[i % 4] ?? 0);
    }

    return Buffer.concat([header, maskedPayload]);
  }
}
