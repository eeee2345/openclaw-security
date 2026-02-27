/**
 * Generic TCP Honeypot Service
 * 通用 TCP 蜜罐服務
 *
 * Handles FTP, Telnet, MySQL, Redis, SMB, and RDP protocols
 * with protocol-specific banners and basic interaction simulation.
 * 處理 FTP、Telnet、MySQL、Redis、SMB 和 RDP 協定，
 * 提供協定專屬橫幅和基本互動模擬。
 *
 * @module @panguard-ai/panguard-trap/services/generic-trap
 */

import { createLogger } from '@panguard-ai/core';
import type { TrapServiceConfig, TrapServiceType } from '../types.js';
import { BaseTrapService } from './base-service.js';

const logger = createLogger('panguard-trap:service:generic');

// ---------------------------------------------------------------------------
// Protocol Handlers
// 協定處理器
// ---------------------------------------------------------------------------

/** Protocol handler interface / 協定處理器介面 */
interface ProtocolHandler {
  /** Welcome banner / 歡迎橫幅 */
  getBanner(config: TrapServiceConfig): string;
  /** Handle input and return response / 處理輸入並回傳回應 */
  handleInput(input: string, state: ConnectionState): string | null;
  /** MITRE technique for initial access / 初始存取的 MITRE 技術 */
  initialTechnique: string;
}

/** Connection state / 連線狀態 */
interface ConnectionState {
  authenticated: boolean;
  authAttempts: number;
  username?: string;
}

/** FTP protocol handler / FTP 協定處理器 */
const ftpHandler: ProtocolHandler = {
  initialTechnique: 'T1110',
  getBanner(config) {
    return config.banner ?? '220 ProFTPD 1.3.8 Server (Panguard) [::ffff:0.0.0.0]\r\n';
  },
  handleInput(input, state) {
    const cmd = input.trim().toUpperCase();
    const parts = input.trim().split(' ');
    const command = parts[0]?.toUpperCase() ?? '';
    const arg = parts.slice(1).join(' ');

    if (command === 'USER') {
      state.username = arg;
      return `331 Password required for ${arg}\r\n`;
    }
    if (command === 'PASS') {
      state.authAttempts++;
      if (state.authAttempts >= 3) {
        state.authenticated = true;
        return `230 User ${state.username ?? 'anonymous'} logged in\r\n`;
      }
      return '530 Login incorrect.\r\n';
    }
    if (command === 'QUIT' || command === 'EXIT') {
      return null; // signal disconnect
    }
    if (!state.authenticated) {
      return '530 Please login with USER and PASS.\r\n';
    }
    // Post-auth commands
    if (command === 'LIST' || command === 'LS') {
      return '150 Opening data connection\r\n-rw-r--r-- 1 admin admin 8192 Jan 14 backup.tar.gz\r\n-rwxr-xr-x 1 admin admin  512 Jan 12 deploy.sh\r\n226 Transfer complete\r\n';
    }
    if (command === 'PWD') {
      return '257 "/home/admin" is current directory\r\n';
    }
    if (cmd === 'SYST') {
      return '215 UNIX Type: L8\r\n';
    }
    return `500 '${command}': command not understood\r\n`;
  },
};

/** Telnet protocol handler / Telnet 協定處理器 */
const telnetHandler: ProtocolHandler = {
  initialTechnique: 'T1110',
  getBanner(config) {
    const os = config.banner ?? 'Ubuntu 22.04 LTS';
    return `\r\n${os}\r\nlogin: `;
  },
  handleInput(input, state) {
    const trimmed = input.trim();
    if (!state.username) {
      state.username = trimmed;
      return 'Password: ';
    }
    if (!state.authenticated) {
      state.authAttempts++;
      if (state.authAttempts >= 3) {
        state.authenticated = true;
        return `\r\nWelcome to Ubuntu 22.04 LTS\r\nLast login: Mon Jan 15 10:30:00 2025\r\n${state.username}@server:~$ `;
      }
      state.username = undefined;
      return '\r\nLogin incorrect\r\nlogin: ';
    }
    if (trimmed === 'exit' || trimmed === 'quit' || trimmed === 'logout') {
      return null;
    }
    return `bash: ${trimmed.split(' ')[0]}: command not found\r\n${state.username}@server:~$ `;
  },
};

/** MySQL protocol handler / MySQL 協定處理器 */
const mysqlHandler: ProtocolHandler = {
  initialTechnique: 'T1110',
  getBanner(config) {
    const version = config.banner ?? '5.7.42-0ubuntu0.18.04.1';
    // Simplified MySQL greeting (not actual protocol, text-based simulation)
    return `Welcome to the MySQL monitor. Server version: ${version}\r\nType 'help;' for help.\r\n\r\nmysql> `;
  },
  handleInput(input, _state) {
    const trimmed = input.trim().replace(/;$/, '');
    const upper = trimmed.toUpperCase();

    if (upper === 'EXIT' || upper === 'QUIT' || upper === '\\Q') {
      return null;
    }
    if (upper === 'HELP' || upper === '\\H') {
      return 'For information about MySQL products, visit: https://www.mysql.com\r\nmysql> ';
    }
    if (upper.startsWith('SELECT')) {
      return 'ERROR 1045 (28000): Access denied for user\r\nmysql> ';
    }
    if (upper.startsWith('SHOW')) {
      if (upper.includes('DATABASES')) {
        return '+--------------------+\r\n| Database           |\r\n+--------------------+\r\n| information_schema |\r\n| mysql              |\r\n| performance_schema |\r\n| webapp             |\r\n+--------------------+\r\n4 rows in set\r\nmysql> ';
      }
      if (upper.includes('TABLES')) {
        return '+-------------------+\r\n| Tables_in_webapp  |\r\n+-------------------+\r\n| users             |\r\n| sessions          |\r\n| orders            |\r\n+-------------------+\r\n3 rows in set\r\nmysql> ';
      }
    }
    if (
      upper.startsWith('DROP') ||
      upper.startsWith('DELETE') ||
      upper.startsWith('INSERT') ||
      upper.startsWith('UPDATE')
    ) {
      return 'ERROR 1142 (42000): command denied to user\r\nmysql> ';
    }
    return `ERROR 1064 (42000): You have an error in your SQL syntax near '${trimmed.slice(0, 20)}'\r\nmysql> `;
  },
};

/** Redis protocol handler / Redis 協定處理器 */
const redisHandler: ProtocolHandler = {
  initialTechnique: 'T1190',
  getBanner() {
    return ''; // Redis has no banner
  },
  handleInput(input, _state) {
    const trimmed = input.trim();
    const upper = trimmed.toUpperCase();
    const parts = trimmed.split(' ');
    const cmd = parts[0]?.toUpperCase() ?? '';

    if (cmd === 'QUIT') return null;
    if (cmd === 'PING') return '+PONG\r\n';
    if (cmd === 'INFO') {
      return '$redis_version:6.2.14\r\nos:Linux 5.15.0-91-generic x86_64\r\nused_memory:1024000\r\nconnected_clients:1\r\n';
    }
    if (cmd === 'CONFIG') {
      if (upper.includes('SET')) {
        return '-ERR CONFIG SET is disabled\r\n';
      }
      return '+OK\r\n';
    }
    if (cmd === 'KEYS') {
      return '*3\r\n$7\r\nsession\r\n$5\r\ncache\r\n$4\r\nuser\r\n';
    }
    if (cmd === 'GET') {
      return '$-1\r\n'; // nil
    }
    if (cmd === 'SET' || cmd === 'DEL') {
      return "-READONLY You can't write against a read only replica.\r\n";
    }
    if (cmd === 'SLAVEOF' || cmd === 'REPLICAOF') {
      return '-ERR not allowed\r\n';
    }
    if (cmd === 'EVAL' || cmd === 'SCRIPT') {
      return '-ERR scripting is disabled\r\n';
    }
    return `-ERR unknown command '${cmd}'\r\n`;
  },
};

/** SMB protocol handler (simplified) / SMB 協定處理器（簡化版） */
const smbHandler: ProtocolHandler = {
  initialTechnique: 'T1021.002',
  getBanner() {
    return 'SMB server ready. Authentication required.\r\nUsername: ';
  },
  handleInput(input, state) {
    const trimmed = input.trim();
    if (!state.username) {
      state.username = trimmed;
      return 'Password: ';
    }
    if (!state.authenticated) {
      state.authAttempts++;
      if (state.authAttempts >= 3) {
        state.authenticated = true;
        return '\r\nAuthenticated. Available shares:\r\n  \\\\SERVER\\Public\r\n  \\\\SERVER\\Admin$\r\n  \\\\SERVER\\IPC$\r\n> ';
      }
      state.username = undefined;
      return '\r\nAccess denied.\r\nUsername: ';
    }
    if (trimmed === 'exit' || trimmed === 'quit') return null;
    return 'Access denied to resource.\r\n> ';
  },
};

/** RDP protocol handler (simplified) / RDP 協定處理器（簡化版） */
const rdpHandler: ProtocolHandler = {
  initialTechnique: 'T1021.001',
  getBanner() {
    return 'Remote Desktop Protocol - Connection Established\r\nCredential prompt sent.\r\n';
  },
  handleInput(input, state) {
    const trimmed = input.trim();
    if (!state.username) {
      state.username = trimmed;
      return 'Password: ';
    }
    state.authAttempts++;
    state.username = undefined;
    return 'Authentication failed. NLA Error: CredSSP.\r\nUsername: ';
  },
};

/** Protocol handler registry / 協定處理器註冊表 */
const PROTOCOL_HANDLERS: Partial<Record<TrapServiceType, ProtocolHandler>> = {
  ftp: ftpHandler,
  telnet: telnetHandler,
  mysql: mysqlHandler,
  redis: redisHandler,
  smb: smbHandler,
  rdp: rdpHandler,
};

// ---------------------------------------------------------------------------
// Generic Trap Service
// 通用蜜罐服務
// ---------------------------------------------------------------------------

/**
 * Generic TCP trap service that handles multiple protocols
 * 處理多種協定的通用 TCP 蜜罐服務
 */
export class GenericTrapService extends BaseTrapService {
  private server: ReturnType<typeof import('node:net').createServer> | null = null;
  private readonly handler: ProtocolHandler;

  constructor(config: TrapServiceConfig) {
    super(config);
    const handler = PROTOCOL_HANDLERS[config.type];
    if (!handler) {
      throw new Error(`No protocol handler for service type: ${config.type}`);
    }
    this.handler = handler;
  }

  protected async doStart(): Promise<void> {
    const net = await import('node:net');
    this.server = net.createServer((socket) => {
      this.handleConnection(socket);
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

  private handleConnection(socket: import('node:net').Socket): void {
    const remoteIP = socket.remoteAddress ?? 'unknown';
    const remotePort = socket.remotePort ?? 0;
    const session = this.createSession(remoteIP, remotePort);

    this.addMitreTechnique(session.sessionId, this.handler.initialTechnique);

    const state: ConnectionState = {
      authenticated: false,
      authAttempts: 0,
    };

    // Send banner
    const banner = this.handler.getBanner(this.config);
    if (banner) {
      socket.write(banner);
    }

    // Set timeout
    const timeout = this.config.sessionTimeoutMs ?? 30_000;
    socket.setTimeout(timeout);

    socket.on('data', (data: Buffer) => {
      const input = data.toString();
      const lines = input.split('\n').filter(Boolean);

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;

        // Record credential attempts
        if (!state.authenticated && state.username && !trimmed.includes(':')) {
          this.recordCredential(
            session.sessionId,
            state.username,
            trimmed,
            state.authAttempts >= 2 // will grant on next attempt
          );
        }

        // Record as command if authenticated
        if (state.authenticated) {
          this.recordCommand(session.sessionId, trimmed);
        }

        const response = this.handler.handleInput(trimmed, state);

        if (response === null) {
          // Disconnect signal
          socket.end();
          return;
        }

        const delay = this.config.responseDelayMs ?? 100;
        setTimeout(() => {
          try {
            socket.write(response);
          } catch {
            // socket may be closed
          }
        }, delay);
      }
    });

    socket.on('timeout', () => {
      logger.info(`${this.serviceType} session timeout: ${session.sessionId}`);
      socket.end();
    });

    socket.on('close', () => {
      this.endSession(session.sessionId);
    });

    socket.on('error', (err) => {
      logger.debug(`${this.serviceType} socket error: ${err.message}`);
      this.endSession(session.sessionId);
    });
  }
}
