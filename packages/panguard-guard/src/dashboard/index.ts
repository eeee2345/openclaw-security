/**
 * Web Dashboard - Real-time monitoring interface
 * Web Dashboard - 即時監控介面
 *
 * Provides an HTTP server with WebSocket push for:
 * - System status overview / 系統狀態概覽
 * - Event timeline / 事件時間軸
 * - Threat map visualization / 威脅地圖視覺化
 * - Configuration management / 配置管理
 * - Language toggle (EN/ZH) / 語言切換
 *
 * Uses only Node.js built-in http module with native WebSocket handshake.
 * 僅使用 Node.js 內建 http 模組搭配原生 WebSocket 交握。
 *
 * @module @openclaw/panguard-guard/dashboard
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import type { Socket } from 'node:net';
import { createLogger } from '@openclaw/core';
import type {
  DashboardStatus,
  DashboardEvent,
  ThreatMapEntry,
  GuardConfig,
  ThreatVerdict,
} from '../types.js';

const logger = createLogger('panguard-guard:dashboard');

/** WebSocket client tracking / WebSocket 客戶端追蹤 */
interface WSClient {
  socket: Socket;
  alive: boolean;
  connectedAt: number;
}

/** Rate limiter state per IP / 每個 IP 的速率限制狀態 */
interface RateLimitEntry {
  count: number;
  resetAt: number;
}

/** Maximum requests per minute per IP / 每個 IP 每分鐘最大請求數 */
const RATE_LIMIT_MAX = 120;
const RATE_LIMIT_WINDOW_MS = 60_000;
/** Maximum concurrent WebSocket connections / 最大同時 WebSocket 連線數 */
const MAX_WS_CLIENTS = 20;

/**
 * Dashboard Server manages the HTTP + WebSocket real-time dashboard
 * Dashboard 伺服器管理 HTTP + WebSocket 即時儀表板
 */
export class DashboardServer {
  private server: ReturnType<typeof createServer> | null = null;
  private wsClients: Set<WSClient> = new Set();
  private status: DashboardStatus;
  private recentEvents: DashboardEvent[] = [];
  private threatMap: ThreatMapEntry[] = [];
  private readonly maxRecentEvents = 200;
  private readonly port: number;
  private getConfig: (() => GuardConfig) | null = null;
  /** API authentication token / API 認證 token */
  private readonly authToken: string;
  /** Rate limiter state / 速率限制狀態 */
  private rateLimits: Map<string, RateLimitEntry> = new Map();

  constructor(port: number) {
    this.port = port;
    this.authToken = randomBytes(32).toString('hex');
    this.status = {
      mode: 'learning',
      uptime: 0,
      eventsProcessed: 0,
      threatsDetected: 0,
      actionsExecuted: 0,
      learningProgress: 0,
      baselineConfidence: 0,
      memoryUsageMB: 0,
      cpuPercent: 0,
      recentVerdicts: [],
    };
  }

  /**
   * Set config getter for the settings API / 設定配置 getter 用於設定 API
   */
  setConfigGetter(getter: () => GuardConfig): void {
    this.getConfig = getter;
  }

  /**
   * Start the dashboard HTTP server / 啟動儀表板 HTTP 伺服器
   */
  async start(): Promise<void> {
    return new Promise((resolve) => {
      this.server = createServer((req, res) => this.handleRequest(req, res));

      // Handle WebSocket upgrade / 處理 WebSocket 升級
      this.server.on('upgrade', (req: IncomingMessage, socket: Socket, _head: Buffer) => {
        if (req.url !== '/ws') {
          socket.destroy();
          return;
        }

        // Enforce max WebSocket connections / 限制最大 WebSocket 連線數
        if (this.wsClients.size >= MAX_WS_CLIENTS) {
          logger.warn('Max WebSocket connections reached / WebSocket 連線數已達上限');
          socket.destroy();
          return;
        }

        // Validate origin (localhost only) / 驗證來源（僅 localhost）
        const origin = req.headers.origin ?? '';
        if (origin && !origin.includes('127.0.0.1') && !origin.includes('localhost')) {
          logger.warn(`Rejected WebSocket from origin: ${origin}`);
          socket.destroy();
          return;
        }

        const key = req.headers['sec-websocket-key'];
        if (!key) {
          socket.destroy();
          return;
        }

        const acceptKey = createHash('sha1')
          .update(key + '258EAFA5-E914-47DA-95CA-5AB5DC11E65B')
          .digest('base64');

        socket.write(
          'HTTP/1.1 101 Switching Protocols\r\n' +
          'Upgrade: websocket\r\n' +
          'Connection: Upgrade\r\n' +
          `Sec-WebSocket-Accept: ${acceptKey}\r\n` +
          '\r\n',
        );

        const client: WSClient = { socket, alive: true, connectedAt: Date.now() };
        this.wsClients.add(client);

        // Send initial status / 發送初始狀態
        this.sendToClient(client, {
          type: 'status_update',
          data: this.status,
          timestamp: new Date().toISOString(),
        });

        socket.on('data', (data: Buffer) => {
          // Handle pong frames / 處理 pong 框架
          if (data.length > 0 && ((data[0] ?? 0) & 0x0f) === 0x0a) {
            client.alive = true;
          }
        });

        socket.on('close', () => {
          this.wsClients.delete(client);
        });

        socket.on('error', () => {
          this.wsClients.delete(client);
        });
      });

      this.server.listen(this.port, '127.0.0.1', () => {
        logger.info(
          `Dashboard started on http://127.0.0.1:${this.port} / 儀表板已啟動`,
        );
        logger.info(`Dashboard auth token: ${this.authToken}`);
        resolve();
      });
    });
  }

  /**
   * Stop the dashboard server / 停止儀表板伺服器
   */
  async stop(): Promise<void> {
    return new Promise((resolve) => {
      for (const client of this.wsClients) {
        try { client.socket.destroy(); } catch { /* ignore */ }
      }
      this.wsClients.clear();

      if (this.server) {
        this.server.close(() => {
          logger.info('Dashboard stopped / 儀表板已停止');
          resolve();
        });
      } else {
        resolve();
      }
    });
  }

  /**
   * Update dashboard status / 更新儀表板狀態
   */
  updateStatus(update: Partial<DashboardStatus>): void {
    Object.assign(this.status, update);
    this.broadcast({
      type: 'status_update',
      data: this.status,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Push a new event / 推送新事件
   */
  pushEvent(event: DashboardEvent): void {
    this.recentEvents.push(event);
    if (this.recentEvents.length > this.maxRecentEvents) {
      this.recentEvents.shift();
    }
    this.broadcast(event);
  }

  /**
   * Add a verdict to recent verdicts / 添加判決到最近判決
   */
  addVerdict(verdict: ThreatVerdict): void {
    this.status.recentVerdicts.push(verdict);
    if (this.status.recentVerdicts.length > 50) {
      this.status.recentVerdicts.shift();
    }
    this.broadcast({
      type: 'new_verdict',
      data: verdict,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Update threat map / 更新威脅地圖
   */
  addThreatMapEntry(entry: ThreatMapEntry): void {
    const existing = this.threatMap.find(
      (t) => t.sourceIP === entry.sourceIP && t.attackType === entry.attackType,
    );
    if (existing) {
      existing.count += entry.count;
      existing.lastSeen = entry.lastSeen;
    } else {
      this.threatMap.push(entry);
    }
  }

  // ---------------------------------------------------------------------------
  // HTTP request handling / HTTP 請求處理
  // ---------------------------------------------------------------------------

  /**
   * Get the auth token for API access / 取得 API 認證 token
   */
  getAuthToken(): string {
    return this.authToken;
  }

  private handleRequest(req: IncomingMessage, res: ServerResponse): void {
    // Security headers / 安全標頭
    res.setHeader('Access-Control-Allow-Origin', 'http://127.0.0.1:' + this.port);
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self' ws://127.0.0.1:*");

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    // Rate limiting / 速率限制
    const clientIP = req.socket.remoteAddress ?? 'unknown';
    if (!this.checkRateLimit(clientIP)) {
      res.writeHead(429, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Rate limit exceeded' }));
      return;
    }

    const url = req.url ?? '/';

    // The HTML page is public; API endpoints require auth token
    // HTML 頁面公開；API 端點需要認證 token
    if (url === '/') {
      this.serveIndex(res);
      return;
    }

    // Verify auth token for API endpoints / 驗證 API 端點的認證 token
    if (url.startsWith('/api/')) {
      const authHeader = req.headers.authorization ?? '';
      const queryToken = new URL(url, `http://127.0.0.1:${this.port}`).searchParams.get('token');
      const providedToken = authHeader.replace('Bearer ', '') || queryToken;

      if (providedToken !== this.authToken) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized' }));
        return;
      }
    }

    const pathname = url.split('?')[0];

    switch (pathname) {
      case '/api/status':
        this.jsonResponse(res, this.status);
        break;
      case '/api/events':
        this.jsonResponse(res, this.recentEvents);
        break;
      case '/api/threat-map':
        this.jsonResponse(res, this.threatMap);
        break;
      case '/api/verdicts':
        this.jsonResponse(res, this.status.recentVerdicts);
        break;
      case '/api/config':
        if (this.getConfig) {
          this.jsonResponse(res, this.getConfig());
        } else {
          this.jsonResponse(res, { error: 'Config not available' }, 503);
        }
        break;
      default:
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Not found' }));
    }
  }

  /** Check rate limit for IP / 檢查 IP 的速率限制 */
  private checkRateLimit(ip: string): boolean {
    const now = Date.now();
    const entry = this.rateLimits.get(ip);
    if (!entry || now > entry.resetAt) {
      this.rateLimits.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
      return true;
    }
    entry.count++;
    return entry.count <= RATE_LIMIT_MAX;
  }

  private serveIndex(res: ServerResponse): void {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(DASHBOARD_HTML);
  }

  private jsonResponse(res: ServerResponse, data: unknown, statusCode = 200): void {
    res.writeHead(statusCode, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
  }

  // ---------------------------------------------------------------------------
  // WebSocket helpers / WebSocket 輔助函數
  // ---------------------------------------------------------------------------

  private sendToClient(client: WSClient, event: DashboardEvent): void {
    try {
      const data = JSON.stringify(event);
      const payload = Buffer.from(data);
      const frame = this.createWSFrame(payload);
      client.socket.write(frame);
    } catch {
      this.wsClients.delete(client);
    }
  }

  private broadcast(event: DashboardEvent): void {
    for (const client of this.wsClients) {
      this.sendToClient(client, event);
    }
  }

  /** Create a WebSocket text frame / 建立 WebSocket 文字框架 */
  private createWSFrame(payload: Buffer): Buffer {
    const length = payload.length;
    let header: Buffer;

    if (length < 126) {
      header = Buffer.alloc(2);
      header[0] = 0x81; // FIN + text opcode
      header[1] = length;
    } else if (length < 65536) {
      header = Buffer.alloc(4);
      header[0] = 0x81;
      header[1] = 126;
      header.writeUInt16BE(length, 2);
    } else {
      header = Buffer.alloc(10);
      header[0] = 0x81;
      header[1] = 127;
      header.writeBigUInt64BE(BigInt(length), 2);
    }

    return Buffer.concat([header, payload]);
  }
}

// ---------------------------------------------------------------------------
// Dashboard HTML template / 儀表板 HTML 範本
// ---------------------------------------------------------------------------

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PanguardGuard Dashboard</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f1419; color: #e1e8ed; }
    .header { background: #1a1f2e; padding: 16px 24px; display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #2563eb; }
    .header h1 { font-size: 20px; color: #2563eb; }
    .lang-toggle { background: #2563eb; color: white; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 13px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; padding: 16px 24px; }
    .card { background: #1a1f2e; border-radius: 8px; padding: 16px; border: 1px solid #2d3748; }
    .card h3 { font-size: 12px; text-transform: uppercase; color: #718096; margin-bottom: 8px; }
    .card .value { font-size: 28px; font-weight: bold; }
    .status-learning { color: #f6ad55; }
    .status-protection { color: #48bb78; }
    .section { padding: 0 24px 16px; }
    .section h2 { font-size: 16px; margin-bottom: 12px; color: #a0aec0; }
    .event-list { background: #1a1f2e; border-radius: 8px; border: 1px solid #2d3748; max-height: 400px; overflow-y: auto; }
    .event-item { padding: 10px 16px; border-bottom: 1px solid #2d3748; font-size: 13px; font-family: monospace; }
    .event-item:last-child { border-bottom: none; }
    .malicious { border-left: 3px solid #e53e3e; }
    .suspicious { border-left: 3px solid #f6ad55; }
    .benign { border-left: 3px solid #48bb78; }
    .connected { color: #48bb78; }
    .disconnected { color: #e53e3e; }
    .footer { text-align: center; padding: 16px; color: #4a5568; font-size: 12px; }
  </style>
</head>
<body>
  <div class="header">
    <h1>PanguardGuard Dashboard</h1>
    <div>
      <span id="ws-status" class="disconnected">Disconnected</span>
      <button class="lang-toggle" onclick="toggleLang()">EN/ZH</button>
    </div>
  </div>

  <div class="grid" id="status-grid">
    <div class="card"><h3 data-i18n="mode">Mode</h3><div class="value" id="mode">--</div></div>
    <div class="card"><h3 data-i18n="events">Events Processed</h3><div class="value" id="events">0</div></div>
    <div class="card"><h3 data-i18n="threats">Threats Detected</h3><div class="value" id="threats">0</div></div>
    <div class="card"><h3 data-i18n="actions">Actions Executed</h3><div class="value" id="actions">0</div></div>
    <div class="card"><h3 data-i18n="learning">Learning Progress</h3><div class="value" id="learning">0%</div></div>
    <div class="card"><h3 data-i18n="confidence">Baseline Confidence</h3><div class="value" id="confidence">0%</div></div>
    <div class="card"><h3 data-i18n="memory">Memory Usage</h3><div class="value" id="memory">0 MB</div></div>
    <div class="card"><h3 data-i18n="uptime">Uptime</h3><div class="value" id="uptime">0s</div></div>
  </div>

  <div class="section">
    <h2 data-i18n="timeline">Event Timeline</h2>
    <div class="event-list" id="event-list"></div>
  </div>

  <div class="footer">PanguardGuard Security - OpenClaw Platform</div>

  <script>
    var i18n = {
      en: { mode: 'Mode', events: 'Events Processed', threats: 'Threats Detected', actions: 'Actions Executed', learning: 'Learning Progress', confidence: 'Baseline Confidence', memory: 'Memory Usage', uptime: 'Uptime', timeline: 'Event Timeline' },
      zh: { mode: '\\u6a21\\u5f0f', events: '\\u5df2\\u8655\\u7406\\u4e8b\\u4ef6', threats: '\\u5df2\\u5075\\u6e2c\\u5a01\\u8105', actions: '\\u5df2\\u57f7\\u884c\\u52d5\\u4f5c', learning: '\\u5b78\\u7fd2\\u9032\\u5ea6', confidence: '\\u57fa\\u7dda\\u4fe1\\u5fc3\\u5ea6', memory: '\\u8a18\\u61b6\\u9ad4\\u4f7f\\u7528', uptime: '\\u904b\\u884c\\u6642\\u9593', timeline: '\\u4e8b\\u4ef6\\u6642\\u9593\\u8ef8' }
    };
    var lang = 'en';
    function toggleLang() {
      lang = lang === 'en' ? 'zh' : 'en';
      document.querySelectorAll('[data-i18n]').forEach(function(el) {
        el.textContent = i18n[lang][el.getAttribute('data-i18n')] || el.textContent;
      });
    }

    function connectWS() {
      var ws = new WebSocket('ws://' + location.host + '/ws');
      var statusEl = document.getElementById('ws-status');
      ws.onopen = function() { statusEl.textContent = 'Connected'; statusEl.className = 'connected'; };
      ws.onclose = function() { statusEl.textContent = 'Disconnected'; statusEl.className = 'disconnected'; setTimeout(connectWS, 3000); };
      ws.onmessage = function(e) {
        var msg = JSON.parse(e.data);
        if (msg.type === 'status_update') updateStatus(msg.data);
        if (msg.type === 'new_verdict' || msg.type === 'new_event') addEvent(msg);
      };
    }

    function updateStatus(s) {
      document.getElementById('mode').textContent = s.mode;
      document.getElementById('mode').className = 'value status-' + s.mode;
      document.getElementById('events').textContent = s.eventsProcessed;
      document.getElementById('threats').textContent = s.threatsDetected;
      document.getElementById('actions').textContent = s.actionsExecuted;
      document.getElementById('learning').textContent = s.learningProgress + '%';
      document.getElementById('confidence').textContent = (s.baselineConfidence * 100).toFixed(1) + '%';
      document.getElementById('memory').textContent = s.memoryUsageMB.toFixed(1) + ' MB';
      document.getElementById('uptime').textContent = Math.floor(s.uptime / 1000) + 's';
    }

    function addEvent(msg) {
      var list = document.getElementById('event-list');
      var div = document.createElement('div');
      var cls = (msg.data && msg.data.conclusion) || 'benign';
      div.className = 'event-item ' + cls;
      div.textContent = msg.timestamp + ' | ' + msg.type + ' | ' + JSON.stringify(msg.data).slice(0, 200);
      list.prepend(div);
      while (list.children.length > 100) list.removeChild(list.lastChild);
    }

    connectWS();
    fetch('/api/status').then(function(r) { return r.json(); }).then(updateStatus).catch(function() {});
  </script>
</body>
</html>`;
