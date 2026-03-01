/**
 * Generic TCP Honeypot Service
 * 通用 TCP 蜜罐服務
 *
 * Handles text-based protocols (FTP, Telnet) with enhanced command
 * simulation, MITRE ATT&CK detection, and realistic interaction.
 *
 * Binary protocols (MySQL, Redis, SMB, RDP) have dedicated service files.
 *
 * @module @panguard-ai/panguard-trap/services/generic-trap
 */

import { createLogger } from '@panguard-ai/core';
import type { TrapServiceConfig, TrapServiceType } from '../types.js';
import { BaseTrapService } from './base-service.js';

const logger = createLogger('panguard-trap:service:generic');

// ---------------------------------------------------------------------------
// Protocol Handlers
// ---------------------------------------------------------------------------

interface ProtocolHandler {
  getBanner(config: TrapServiceConfig): Buffer;
  handleInput(input: string, state: ConnectionState): HandleResult;
  initialTechnique: string;
}

interface HandleResult {
  response: string | null; // null = disconnect
  mitre?: string[]; // techniques to add
  eventType?: 'exploit_attempt' | 'file_upload' | 'file_download';
}

interface ConnectionState {
  authenticated: boolean;
  authAttempts: number;
  username?: string;
  cwd: string;
  pasv: boolean;
}

// ---------------------------------------------------------------------------
// Telnet IAC negotiation bytes (sent before banner)
// ---------------------------------------------------------------------------

const TELNET_IAC = Buffer.from([
  0xff,
  0xfb,
  0x01, // IAC WILL ECHO
  0xff,
  0xfb,
  0x03, // IAC WILL SUPPRESS-GO-AHEAD
  0xff,
  0xfd,
  0x18, // IAC DO TERMINAL-TYPE
  0xff,
  0xfd,
  0x1f, // IAC DO NAWS (window size)
]);

// ---------------------------------------------------------------------------
// FTP MITRE patterns
// ---------------------------------------------------------------------------

const FTP_MITRE_PATTERNS: [RegExp, string][] = [
  [/STOR\s+.*\.(php|jsp|asp|sh|py|pl|cgi)/i, 'T1505.003'], // Web shell upload
  [/STOR\s+.*\.(exe|dll|bat|ps1|vbs|msi)/i, 'T1105'], // Ingress tool transfer
  [/RETR\s+.*(passwd|shadow|\.ssh|\.env|\.htaccess|\.git)/i, 'T1005'], // Data from local system
  [/SITE\s+EXEC/i, 'T1059'], // Command execution
  [/SITE\s+CHMOD\s+777/i, 'T1222'], // File permission modification
  [/MKD\s+\.\./i, 'T1083'], // Directory traversal
  [/CWD\s+\.\./i, 'T1083'],
  [/DELE\s+/i, 'T1485'], // Data destruction
  [/RMD\s+/i, 'T1485'],
];

// ---------------------------------------------------------------------------
// Telnet MITRE patterns (post-auth shell commands)
// ---------------------------------------------------------------------------

const TELNET_MITRE_PATTERNS: [RegExp, string][] = [
  [/wget\s|curl\s/i, 'T1105'], // Ingress tool transfer
  [/chmod\s+777/i, 'T1222'], // File permission modification
  [/\/etc\/(shadow|passwd)/i, 'T1003'], // OS credential dumping
  [/crontab/i, 'T1053'], // Scheduled task
  [/base64\s+-d|echo.*\|\s*(sh|bash)/i, 'T1140'], // Deobfuscation
  [/\bnc\b|\bnetcat\b/i, 'T1571'], // Non-standard port
  [/iptables\s+-D/i, 'T1562'], // Impair defenses
  [/rm\s+-rf\s+\//i, 'T1485'], // Data destruction
  [/xmrig|minerd|cryptonight/i, 'T1496'], // Resource hijacking
  [/ssh-keygen|authorized_keys/i, 'T1098'], // Account manipulation
  [/\buname\b|\bwhoami\b|\bid\b/i, 'T1082'], // System information discovery
  [/ifconfig|ip\s+addr/i, 'T1016'], // System network configuration
  [/\bps\b\s+(aux|ef)/i, 'T1057'], // Process discovery
  [/cat\s+\/etc\/passwd/i, 'T1087'], // Account discovery
  [/find\s+.*-perm/i, 'T1083'], // File & directory discovery
];

// ---------------------------------------------------------------------------
// Fake shell responses for Telnet post-auth
// ---------------------------------------------------------------------------

const FAKE_SHELL_RESPONSES: Record<string, string> = {
  id: 'uid=1000(admin) gid=1000(admin) groups=1000(admin),27(sudo)',
  whoami: 'admin',
  'uname -a':
    'Linux server 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 GNU/Linux',
  uname: 'Linux',
  hostname: 'prod-web-01',
  uptime: ' 14:32:01 up 42 days, 3:17, 1 user, load average: 0.08, 0.03, 0.01',
  pwd: '/home/admin',
  ls: 'backup.tar.gz  deploy.sh  logs  www',
  'ls -la':
    'total 32\ndrwxr-xr-x 4 admin admin 4096 Jan 15 10:00 .\ndrwxr-xr-x 3 root  root  4096 Jan  1 00:00 ..\n-rw------- 1 admin admin  512 Jan 15 10:30 .bash_history\n-rw-r--r-- 1 admin admin 8192 Jan 14 12:00 backup.tar.gz\n-rwxr-xr-x 1 admin admin  512 Jan 12 08:00 deploy.sh\ndrwxr-xr-x 2 admin admin 4096 Jan 15 10:00 logs\ndrwxr-xr-x 5 www-data www-data 4096 Jan 10 14:00 www',
  'cat /etc/passwd':
    'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nadmin:x:1000:1000:admin:/home/admin:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nmysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false',
  ifconfig:
    'eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255',
  'ps aux':
    'USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.1 169024 11264 ?        Ss   Jan01   0:05 /sbin/init\nadmin     1234  0.0  0.0   8072  4096 pts/0    Ss   14:32   0:00 -bash\nwww-data  5678  0.0  0.5 256000 40960 ?        S    Jan10   1:23 nginx: worker',
  w: ' 14:32:01 up 42 days,  3:17,  1 user,  load average: 0.08, 0.03, 0.01\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\nadmin    pts/0    10.0.2.2         14:32    0.00s  0.01s  0.00s w',
  'df -h':
    'Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        50G   12G   35G  26% /\ntmpfs           2.0G     0  2.0G   0% /dev/shm',
  'free -m':
    '              total        used        free      shared  buff/cache   available\nMem:           3951        1024         512         128        2415        2600\nSwap:          2048           0        2048',
  'netstat -tlnp':
    'Proto Recv-Q Send-Q Local Address     Foreign Address   State       PID/Program\ntcp        0      0 0.0.0.0:22        0.0.0.0:*         LISTEN      845/sshd\ntcp        0      0 0.0.0.0:80        0.0.0.0:*         LISTEN      5678/nginx\ntcp        0      0 127.0.0.1:3306    0.0.0.0:*         LISTEN      1122/mysqld',
  'cat /etc/os-release':
    'NAME="Ubuntu"\nVERSION="22.04.3 LTS (Jammy Jellyfish)"\nID=ubuntu\nVERSION_ID="22.04"',
};

// ---------------------------------------------------------------------------
// FTP Protocol Handler (enhanced)
// ---------------------------------------------------------------------------

const ftpHandler: ProtocolHandler = {
  initialTechnique: 'T1110',

  getBanner(config) {
    const banner = config.banner ?? '220 ProFTPD 1.3.8 Server (Panguard) [::ffff:0.0.0.0]\r\n';
    return Buffer.from(banner, 'utf-8');
  },

  handleInput(input, state): HandleResult {
    const parts = input.trim().split(' ');
    const command = parts[0]?.toUpperCase() ?? '';
    const arg = parts.slice(1).join(' ');

    // MITRE detection
    const mitre: string[] = [];
    for (const [pattern, technique] of FTP_MITRE_PATTERNS) {
      if (pattern.test(input)) {
        mitre.push(technique);
      }
    }

    // Pre-auth commands
    if (command === 'USER') {
      state.username = arg;
      return { response: `331 Password required for ${arg}\r\n` };
    }
    if (command === 'PASS') {
      state.authAttempts++;
      if (state.authAttempts >= 3) {
        state.authenticated = true;
        return {
          response: `230 User ${state.username ?? 'anonymous'} logged in\r\n`,
          mitre: ['T1078'], // Valid accounts
        };
      }
      return { response: '530 Login incorrect.\r\n' };
    }
    if (command === 'QUIT' || command === 'EXIT') {
      return { response: null };
    }
    if (command === 'FEAT') {
      return { response: '211-Features:\r\n PASV\r\n UTF8\r\n SIZE\r\n MDTM\r\n211 End\r\n' };
    }
    if (command === 'AUTH' && arg.toUpperCase() === 'TLS') {
      return { response: '534 TLS not available\r\n' };
    }

    if (!state.authenticated) {
      return { response: '530 Please login with USER and PASS.\r\n' };
    }

    // Post-auth commands
    switch (command) {
      case 'LIST':
      case 'NLST':
      case 'LS':
        return {
          response:
            '150 Opening ASCII mode data connection for file list\r\n' +
            '-rw-r--r-- 1 admin admin   8192 Jan 14 12:00 backup.tar.gz\r\n' +
            '-rwxr-xr-x 1 admin admin    512 Jan 12 08:00 deploy.sh\r\n' +
            'drwxr-xr-x 2 admin admin   4096 Jan 15 10:00 logs\r\n' +
            'drwxr-xr-x 5 www-data www-data 4096 Jan 10 14:00 www\r\n' +
            '-rw-r--r-- 1 admin admin  16384 Jan 13 09:00 database.sql\r\n' +
            '-rw------- 1 admin admin    256 Jan 11 07:00 .env\r\n' +
            '226 Transfer complete\r\n',
        };

      case 'PWD':
        return { response: `257 "${state.cwd}" is current directory\r\n` };

      case 'CWD':
        if (arg.includes('..')) {
          const parent = state.cwd.split('/').slice(0, -1).join('/') || '/';
          state.cwd = parent;
        } else if (arg.startsWith('/')) {
          state.cwd = arg;
        } else {
          state.cwd = `${state.cwd}/${arg}`.replace(/\/+/g, '/');
        }
        return { response: `250 CWD command successful. "${state.cwd}"\r\n`, mitre };

      case 'TYPE':
        return { response: `200 Type set to ${arg === 'A' ? 'A' : 'I'}\r\n` };

      case 'PASV':
        state.pasv = true;
        // Fake PASV response (address doesn't matter - honeypot)
        return { response: '227 Entering Passive Mode (10,0,2,15,156,64)\r\n' };

      case 'PORT':
        return { response: '200 PORT command successful\r\n' };

      case 'SYST':
        return { response: '215 UNIX Type: L8\r\n' };

      case 'SIZE':
        return { response: `213 ${Math.floor(Math.random() * 50000)}\r\n` };

      case 'MDTM':
        return { response: '213 20250115120000\r\n' };

      case 'RETR':
        return {
          response: '150 Opening BINARY mode data connection\r\n550 Permission denied\r\n',
          mitre,
          eventType: 'file_download',
        };

      case 'STOR':
        return {
          response: '150 Opening BINARY mode data connection\r\n226 Transfer complete\r\n',
          mitre,
          eventType: 'file_upload',
        };

      case 'DELE':
        return { response: `250 DELE command successful. "${arg}"\r\n`, mitre };

      case 'MKD':
        return { response: `257 "${arg}" directory created\r\n`, mitre };

      case 'RMD':
        return { response: `250 RMD command successful. "${arg}"\r\n`, mitre };

      case 'SITE':
        return { response: '200 SITE command ok\r\n', mitre };

      case 'STAT':
        return {
          response:
            '211-Status of ProFTPD 1.3.8\r\n' +
            ` Connected to ${state.username ?? 'anonymous'}\r\n` +
            ` Working directory: ${state.cwd}\r\n` +
            '211 End of status\r\n',
        };

      case 'HELP':
        return {
          response:
            '214-The following commands are recognized:\r\n' +
            ' USER PASS QUIT LIST PWD CWD TYPE PASV PORT SYST SIZE MDTM RETR STOR DELE MKD RMD STAT HELP FEAT NLST SITE\r\n' +
            '214 Help OK.\r\n',
        };

      case 'NOOP':
        return { response: '200 NOOP ok\r\n' };

      default:
        return { response: `500 '${command}': command not understood\r\n` };
    }
  },
};

// ---------------------------------------------------------------------------
// Telnet Protocol Handler (enhanced with IAC and shell simulation)
// ---------------------------------------------------------------------------

const telnetHandler: ProtocolHandler = {
  initialTechnique: 'T1110',

  getBanner(config) {
    const os = config.banner ?? 'Ubuntu 22.04 LTS';
    const textBanner = Buffer.from(`\r\n${os}\r\nlogin: `, 'utf-8');
    return Buffer.concat([TELNET_IAC, textBanner]);
  },

  handleInput(input, state): HandleResult {
    // Strip any IAC sequences from client input
    const trimmed = input.replace(/\xff[\xfb\xfc\xfd\xfe]./g, '').trim();
    if (!trimmed) return { response: '' };

    // Pre-auth: username
    if (!state.username) {
      state.username = trimmed;
      return { response: 'Password: ' };
    }

    // Pre-auth: password
    if (!state.authenticated) {
      state.authAttempts++;
      if (state.authAttempts >= 3) {
        state.authenticated = true;
        return {
          response:
            `\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n` +
            ` * Documentation:  https://help.ubuntu.com\r\n` +
            ` * Management:     https://landscape.canonical.com\r\n` +
            `\r\nLast login: Mon Jan 15 10:30:00 2025 from 10.0.2.2\r\n` +
            `${state.username}@prod-web-01:~$ `,
          mitre: ['T1078'], // Valid accounts
        };
      }
      state.username = undefined;
      return { response: '\r\nLogin incorrect\r\nlogin: ' };
    }

    // Post-auth: shell simulation
    if (trimmed === 'exit' || trimmed === 'quit' || trimmed === 'logout') {
      return { response: null };
    }

    // MITRE detection
    const mitre: string[] = [];
    for (const [pattern, technique] of TELNET_MITRE_PATTERNS) {
      if (pattern.test(trimmed)) {
        mitre.push(technique);
      }
    }

    // Check fake shell responses
    const exactResponse = FAKE_SHELL_RESPONSES[trimmed];
    if (exactResponse) {
      return {
        response: `${exactResponse}\r\n${state.username}@prod-web-01:${state.cwd}$ `,
        mitre: mitre.length > 0 ? mitre : undefined,
      };
    }

    // Pattern-based responses
    const cmd = trimmed.split(' ')[0] ?? '';

    if (cmd === 'cd') {
      const dir = trimmed.split(' ')[1] ?? '/home/admin';
      if (dir === '~' || dir === '') {
        state.cwd = '~';
      } else if (dir === '..') {
        state.cwd = state.cwd === '~' ? '/' : '~';
      } else {
        state.cwd = dir;
      }
      return {
        response: `${state.username}@prod-web-01:${state.cwd}$ `,
        mitre: mitre.length > 0 ? mitre : undefined,
      };
    }

    if (cmd === 'echo') {
      const output = trimmed.slice(5);
      return {
        response: `${output}\r\n${state.username}@prod-web-01:${state.cwd}$ `,
        mitre: mitre.length > 0 ? mitre : undefined,
      };
    }

    if (cmd === 'cat') {
      const file = trimmed.split(' ')[1] ?? '';
      const known = FAKE_SHELL_RESPONSES[`cat ${file}`];
      if (known) {
        return {
          response: `${known}\r\n${state.username}@prod-web-01:${state.cwd}$ `,
          mitre: mitre.length > 0 ? mitre : undefined,
        };
      }
      return {
        response: `cat: ${file}: No such file or directory\r\n${state.username}@prod-web-01:${state.cwd}$ `,
        mitre: mitre.length > 0 ? mitre : undefined,
      };
    }

    if (cmd === 'wget' || cmd === 'curl') {
      return {
        response: `--2025-01-15 14:32:05--\r\nConnecting... failed: Connection refused.\r\n${state.username}@prod-web-01:${state.cwd}$ `,
        mitre: ['T1105', ...mitre],
        eventType: 'exploit_attempt',
      };
    }

    // Generic "command not found" for unknown commands
    return {
      response: `bash: ${cmd}: command not found\r\n${state.username}@prod-web-01:${state.cwd}$ `,
      mitre: mitre.length > 0 ? mitre : undefined,
    };
  },
};

// ---------------------------------------------------------------------------
// Handler Registry (FTP + Telnet only; other protocols have dedicated files)
// ---------------------------------------------------------------------------

const PROTOCOL_HANDLERS: Partial<Record<TrapServiceType, ProtocolHandler>> = {
  ftp: ftpHandler,
  telnet: telnetHandler,
};

// ---------------------------------------------------------------------------
// Generic Trap Service
// ---------------------------------------------------------------------------

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
    this.server = net.createServer((socket) => this.handleConnection(socket));

    return new Promise((resolve, reject) => {
      this.server!.listen(this.config.port, () => resolve());
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
      cwd: '/home/admin',
      pasv: false,
    };

    // Send banner (may include binary IAC bytes for Telnet)
    const banner = this.handler.getBanner(this.config);
    if (banner.length > 0) {
      socket.write(banner);
    }

    const timeout = this.config.sessionTimeoutMs ?? 30_000;
    socket.setTimeout(timeout);

    socket.on('data', (data: Buffer) => {
      const input = data.toString('utf-8');
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
            state.authAttempts >= 2
          );
        }

        // Record as command if authenticated
        if (state.authenticated) {
          this.recordCommand(session.sessionId, trimmed);
        }

        const result = this.handler.handleInput(trimmed, state);

        // Add MITRE techniques
        if (result.mitre) {
          for (const t of result.mitre) {
            this.addMitreTechnique(session.sessionId, t);
          }
        }

        // Record exploit events
        if (result.eventType) {
          this.recordEvent(session.sessionId, result.eventType, trimmed, {
            mitre: result.mitre,
          });
        }

        if (result.response === null) {
          socket.end();
          return;
        }

        const delay = this.config.responseDelayMs ?? 100;
        setTimeout(() => {
          try {
            socket.write(result.response!);
          } catch {
            // socket closed
          }
        }, delay);
      }
    });

    socket.on('timeout', () => {
      logger.info(`${this.serviceType} session timeout: ${session.sessionId}`);
      socket.end();
    });

    socket.on('close', () => this.endSession(session.sessionId));
    socket.on('error', (err) => {
      logger.debug(`${this.serviceType} socket error: ${err.message}`);
      this.endSession(session.sessionId);
    });
  }
}
