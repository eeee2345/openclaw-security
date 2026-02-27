/**
 * HTTP Honeypot Service
 * HTTP 蜜罐服務
 *
 * Simulates a web server with common vulnerabilities to capture
 * web attacks, directory traversal, SQL injection, and reconnaissance.
 * 模擬帶有常見漏洞的網頁伺服器，捕獲網路攻擊、目錄遍歷、SQL 注入及偵察。
 *
 * MITRE ATT&CK Coverage:
 * - T1190: Exploit Public-Facing Application
 * - T1595: Active Scanning
 * - T1083: File and Directory Discovery
 *
 * @module @panguard-ai/panguard-trap/services/http-trap
 */

import { createLogger } from '@panguard-ai/core';
import type { TrapServiceConfig } from '../types.js';
import { BaseTrapService } from './base-service.js';

const logger = createLogger('panguard-trap:service:http');

/** Attack patterns to detect / 偵測的攻擊模式 */
const ATTACK_PATTERNS: { pattern: RegExp; technique: string; type: string }[] = [
  { pattern: /\.\.\/|\.\.\\|%2e%2e/i, technique: 'T1083', type: 'directory_traversal' },
  {
    pattern: /union\s+select|or\s+1\s*=\s*1|'\s*or\s*'/i,
    technique: 'T1190',
    type: 'sql_injection',
  },
  { pattern: /<script|javascript:|onerror=/i, technique: 'T1059.007', type: 'xss' },
  { pattern: /etc\/passwd|etc\/shadow|win\.ini/i, technique: 'T1005', type: 'lfi' },
  { pattern: /cmd\.exe|powershell|\/bin\/bash/i, technique: 'T1059', type: 'rce' },
  { pattern: /wp-admin|wp-login|wp-content/i, technique: 'T1595', type: 'wordpress_scan' },
  { pattern: /phpmyadmin|adminer|phpinfo/i, technique: 'T1595', type: 'admin_scan' },
  { pattern: /\.env|\.git\/config|\.htaccess/i, technique: 'T1083', type: 'config_exposure' },
  { pattern: /robots\.txt|sitemap\.xml/i, technique: 'T1595.002', type: 'reconnaissance' },
  { pattern: /shell|webshell|c99|r57/i, technique: 'T1505.003', type: 'webshell_upload' },
  { pattern: /nmap|nikto|sqlmap|dirbuster/i, technique: 'T1595.002', type: 'scanner_detected' },
];

/** Fake web pages / 假網頁 */
const FAKE_PAGES: Record<string, { status: number; contentType: string; body: string }> = {
  '/': {
    status: 200,
    contentType: 'text/html',
    body: '<!DOCTYPE html><html><head><title>Welcome</title></head><body><h1>Welcome to our server</h1><p>Internal portal - authorized access only</p><form action="/login" method="post"><input name="user" placeholder="Username"><input name="pass" type="password" placeholder="Password"><button>Login</button></form></body></html>',
  },
  '/login': {
    status: 200,
    contentType: 'text/html',
    body: '<!DOCTYPE html><html><head><title>Login</title></head><body><h1>Login</h1><p>Invalid credentials</p></body></html>',
  },
  '/admin': {
    status: 403,
    contentType: 'text/html',
    body: '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>Forbidden</h1><p>You do not have permission to access this resource.</p><p>Apache/2.4.57 (Ubuntu) Server</p></body></html>',
  },
  '/robots.txt': {
    status: 200,
    contentType: 'text/plain',
    body: 'User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /config/\nDisallow: /api/internal/',
  },
  '/wp-login.php': {
    status: 200,
    contentType: 'text/html',
    body: '<!DOCTYPE html><html><head><title>WordPress Login</title></head><body><div id="login"><h1>WordPress</h1><form method="post"><p><label>Username<br><input name="log" type="text"></label></p><p><label>Password<br><input name="pwd" type="password"></label></p><p><input type="submit" value="Log In"></p></form></div></body></html>',
  },
  '/.env': {
    status: 200,
    contentType: 'text/plain',
    body: 'DB_HOST=localhost\nDB_USER=root\nDB_PASS=changeme123\nSECRET_KEY=fake-secret-key-for-honeypot\nAWS_ACCESS_KEY=AKIA_FAKE_HONEYPOT_KEY',
  },
};

/**
 * HTTP Honeypot service
 * HTTP 蜜罐服務
 */
export class HTTPTrapService extends BaseTrapService {
  private server: ReturnType<typeof import('node:http').createServer> | null = null;
  private readonly serverBanner: string;

  constructor(config: TrapServiceConfig) {
    super({ ...config, type: 'http' });
    this.serverBanner = config.banner ?? 'Apache/2.4.57 (Ubuntu)';
  }

  protected async doStart(): Promise<void> {
    const http = await import('node:http');
    this.server = http.createServer((req, res) => {
      this.handleRequest(req, res);
    });

    return new Promise((resolve, reject) => {
      this.server!.listen(this.config.port, () => {
        resolve();
      });
      this.server!.on('error', reject);
    });
  }

  protected async doStop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }

  private handleRequest(
    req: import('node:http').IncomingMessage,
    res: import('node:http').ServerResponse
  ): void {
    const remoteIP = req.socket.remoteAddress ?? 'unknown';
    const remotePort = req.socket.remotePort ?? 0;
    const session = this.createSession(remoteIP, remotePort);

    const url = req.url ?? '/';
    const method = req.method ?? 'GET';
    const userAgent = req.headers['user-agent'] ?? 'unknown';

    logger.info(`HTTP ${method} ${url} from ${remoteIP} / HTTP 請求`);

    // Record the request as a command
    this.recordCommand(session.sessionId, `${method} ${url}`);
    this.recordEvent(session.sessionId, 'command_input', `${method} ${url}`, {
      method,
      url,
      userAgent,
      headers: this.sanitizeHeaders(req.headers),
    });

    // Check for attack patterns
    const fullUrl = `${url}${req.headers.host ?? ''}`;
    for (const attack of ATTACK_PATTERNS) {
      if (attack.pattern.test(fullUrl) || attack.pattern.test(userAgent)) {
        this.addMitreTechnique(session.sessionId, attack.technique);
        this.recordEvent(session.sessionId, 'exploit_attempt', attack.type, {
          technique: attack.technique,
          url,
          matchedPattern: attack.type,
        });
      }
    }

    // Collect POST body if present
    let body = '';
    req.on('data', (chunk: Buffer) => {
      body += chunk.toString();
      if (body.length > 10_000) {
        req.destroy();
      }
    });

    req.on('end', () => {
      if (body) {
        this.recordEvent(session.sessionId, 'command_input', `POST body: ${body.slice(0, 500)}`, {
          bodyLength: body.length,
        });

        // Check for credential submission
        if (url.includes('login') || url.includes('auth')) {
          this.extractCredentials(session.sessionId, body);
        }

        // Check body for attack patterns
        for (const attack of ATTACK_PATTERNS) {
          if (attack.pattern.test(body)) {
            this.addMitreTechnique(session.sessionId, attack.technique);
            this.recordEvent(session.sessionId, 'exploit_attempt', attack.type, {
              technique: attack.technique,
              inBody: true,
            });
          }
        }
      }

      // Send response
      const page = this.getPage(url);
      const delay = this.config.responseDelayMs ?? 50;

      setTimeout(() => {
        res.writeHead(page.status, {
          'Content-Type': page.contentType,
          Server: this.serverBanner,
          'X-Powered-By': 'PHP/8.1.2',
        });
        res.end(page.body);

        // End session after response
        this.endSession(session.sessionId);
      }, delay);
    });
  }

  /** Extract credentials from form data / 從表單資料提取認證資訊 */
  private extractCredentials(sessionId: string, body: string): void {
    // URL-encoded form data
    const params = new URLSearchParams(body);
    const username =
      params.get('user') ??
      params.get('log') ??
      params.get('username') ??
      params.get('email') ??
      '';
    const password = params.get('pass') ?? params.get('pwd') ?? params.get('password') ?? '';

    if (username || password) {
      this.recordCredential(sessionId, username, password, false);
      this.addMitreTechnique(sessionId, 'T1110');
    }
  }

  /** Get fake page for a URL / 取得 URL 的假頁面 */
  private getPage(url: string): { status: number; contentType: string; body: string } {
    // Clean URL
    const cleanUrl = url.split('?')[0] ?? url;

    // Check exact match
    const exact = FAKE_PAGES[cleanUrl];
    if (exact) return exact;

    // Default 404
    return {
      status: 404,
      contentType: 'text/html',
      body: `<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL ${cleanUrl} was not found on this server.</p><hr><address>${this.serverBanner} Server at localhost</address></body></html>`,
    };
  }

  /** Sanitize headers to remove sensitive values / 清理 headers 以移除敏感值 */
  private sanitizeHeaders(
    headers: import('node:http').IncomingHttpHeaders
  ): Record<string, string> {
    const safe: Record<string, string> = {};
    for (const [key, value] of Object.entries(headers)) {
      if (key === 'authorization' || key === 'cookie') {
        safe[key] = '[REDACTED]';
      } else {
        safe[key] = Array.isArray(value) ? value.join(', ') : (value ?? '');
      }
    }
    return safe;
  }
}
