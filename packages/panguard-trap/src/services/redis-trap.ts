/**
 * Redis RESP Protocol Honeypot
 * Redis RESP 協議蜜罐
 *
 * Speaks the real Redis Serialization Protocol (RESP):
 * - Parses inline commands and RESP bulk strings
 * - Handles AUTH, CONFIG, EVAL, SLAVEOF with realistic responses
 * - Detects exploit patterns (CVE-2022-0543, rogue server, etc.)
 *
 * @module @panguard-ai/panguard-trap/services/redis-trap
 */

import { createLogger } from '@panguard-ai/core';
import type { TrapServiceConfig } from '../types.js';
import { BaseTrapService } from './base-service.js';

const logger = createLogger('panguard-trap:service:redis');

// ---------------------------------------------------------------------------
// RESP builder helpers
// ---------------------------------------------------------------------------

function respSimple(msg: string): string {
  return `+${msg}\r\n`;
}
function respError(msg: string): string {
  return `-${msg}\r\n`;
}
function respInt(n: number): string {
  return `:${n}\r\n`;
}
function respBulk(s: string): string {
  return `$${Buffer.byteLength(s)}\r\n${s}\r\n`;
}
function respNullBulk(): string {
  return '$-1\r\n';
}

function respArray(items: string[]): string {
  let out = `*${items.length}\r\n`;
  for (const item of items) {
    out += respBulk(item);
  }
  return out;
}

// ---------------------------------------------------------------------------
// RESP parser - handles both inline and multibulk commands
// ---------------------------------------------------------------------------

function parseRESP(buf: string): string[][] {
  const commands: string[][] = [];
  const lines = buf.split('\r\n');
  let i = 0;

  while (i < lines.length) {
    const line = lines[i]!;
    if (line.length === 0) {
      i++;
      continue;
    }

    if (line.startsWith('*')) {
      // Multibulk
      const count = parseInt(line.slice(1), 10);
      if (isNaN(count) || count < 0) {
        i++;
        continue;
      }

      const args: string[] = [];
      i++;
      for (let j = 0; j < count && i < lines.length; j++) {
        const header = lines[i]!;
        if (header.startsWith('$')) {
          i++;
          if (i < lines.length) {
            args.push(lines[i]!);
            i++;
          }
        } else {
          args.push(header);
          i++;
        }
      }
      if (args.length > 0) commands.push(args);
    } else {
      // Inline command
      const parts = line.trim().split(/\s+/);
      if (parts.length > 0 && parts[0]) {
        commands.push(parts);
      }
      i++;
    }
  }

  return commands;
}

// ---------------------------------------------------------------------------
// MITRE patterns for Redis exploitation
// ---------------------------------------------------------------------------

const REDIS_MITRE_PATTERNS: [RegExp, string][] = [
  [/CONFIG\s+SET\s+dir/i, 'T1059'], // Arbitrary file write
  [/CONFIG\s+SET\s+dbfilename/i, 'T1059'],
  [/SLAVEOF|REPLICAOF/i, 'T1219'], // Rogue server / C2
  [/MODULE\s+LOAD/i, 'T1129'], // Shared modules
  [/EVAL.*os\.execute/i, 'T1059'], // Lua RCE (CVE-2022-0543)
  [/EVAL.*io\.popen/i, 'T1059'],
  [/EVAL.*loadlib/i, 'T1059'],
  [/DEBUG\s+SET-ACTIVE-EXPIRE/i, 'T1499'], // DoS
  [/FLUSHALL|FLUSHDB/i, 'T1485'], // Data destruction
  [/BGSAVE|SAVE/i, 'T1005'], // Data access
];

// ---------------------------------------------------------------------------
// Fake INFO response
// ---------------------------------------------------------------------------

const FAKE_INFO = [
  '# Server',
  'redis_version:6.2.14',
  'redis_git_sha1:00000000',
  'redis_mode:standalone',
  'os:Linux 5.15.0-91-generic x86_64',
  'arch_bits:64',
  'tcp_port:6379',
  'uptime_in_seconds:172800',
  'uptime_in_days:2',
  '',
  '# Clients',
  'connected_clients:1',
  'blocked_clients:0',
  '',
  '# Memory',
  'used_memory:1024000',
  'used_memory_human:1000.00K',
  'used_memory_peak:2048000',
  '',
  '# Keyspace',
  'db0:keys=42,expires=5,avg_ttl=86400000',
].join('\r\n');

// ---------------------------------------------------------------------------
// Redis Trap Service
// ---------------------------------------------------------------------------

export class RedisTrapService extends BaseTrapService {
  private server: ReturnType<typeof import('node:net').createServer> | null = null;

  constructor(config: TrapServiceConfig) {
    super({ ...config, type: 'redis' });
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

    this.addMitreTechnique(session.sessionId, 'T1190'); // Exploit public-facing

    let authAttempts = 0;

    const timeout = this.config.sessionTimeoutMs ?? 30_000;
    socket.setTimeout(timeout);

    // Redis has no banner - waits for client command

    socket.on('data', (data: Buffer) => {
      const raw = data.toString('utf-8');
      const commands = parseRESP(raw);

      for (const args of commands) {
        if (args.length === 0) continue;

        const cmd = args[0]!.toUpperCase();
        const fullCmd = args.join(' ');
        this.recordCommand(session.sessionId, fullCmd);

        // MITRE detection
        for (const [pattern, technique] of REDIS_MITRE_PATTERNS) {
          if (pattern.test(fullCmd)) {
            this.addMitreTechnique(session.sessionId, technique);
            this.recordEvent(session.sessionId, 'exploit_attempt', fullCmd, { technique });
          }
        }

        const delay = this.config.responseDelayMs ?? 30;
        const respond = (resp: string) => {
          setTimeout(() => {
            try {
              socket.write(resp);
            } catch {
              /* closed */
            }
          }, delay);
        };

        // Handle AUTH
        if (cmd === 'AUTH') {
          authAttempts++;
          const password = args[1] ?? '';
          this.recordCredential(session.sessionId, 'default', password, authAttempts >= 3);

          if (authAttempts >= 3) {
            this.addMitreTechnique(session.sessionId, 'T1078');
            respond(respSimple('OK'));
          } else {
            respond(respError('WRONGPASS invalid username-password pair'));
          }
          continue;
        }

        if (cmd === 'QUIT') {
          try {
            socket.write(respSimple('OK'));
          } catch {
            /* */
          }
          socket.end();
          return;
        }

        if (cmd === 'PING') {
          respond(args[1] ? respBulk(args[1]) : respSimple('PONG'));
          continue;
        }

        if (cmd === 'ECHO' && args[1]) {
          respond(respBulk(args[1]));
          continue;
        }

        if (cmd === 'INFO') {
          respond(respBulk(FAKE_INFO));
          continue;
        }

        if (cmd === 'DBSIZE') {
          respond(respInt(42));
          continue;
        }

        if (cmd === 'CONFIG') {
          const sub = args[1]?.toUpperCase();
          if (sub === 'SET') {
            respond(respError('ERR Insufficient permissions to modify config'));
          } else if (sub === 'GET') {
            const key = args[2] ?? '*';
            respond(respArray([key, '']));
          } else {
            respond(respSimple('OK'));
          }
          continue;
        }

        if (cmd === 'KEYS') {
          respond(respArray(['session:abc123', 'cache:homepage', 'user:1001', 'token:jwt_xyz']));
          continue;
        }

        if (cmd === 'GET') {
          respond(respNullBulk());
          continue;
        }

        if (cmd === 'SET' || cmd === 'DEL' || cmd === 'MSET' || cmd === 'HSET') {
          respond(respError("READONLY You can't write against a read only replica."));
          continue;
        }

        if (cmd === 'SLAVEOF' || cmd === 'REPLICAOF') {
          respond(respError('ERR SLAVEOF not allowed'));
          continue;
        }

        if (cmd === 'MODULE') {
          respond(respError('ERR MODULE command not allowed'));
          continue;
        }

        if (cmd === 'EVAL' || cmd === 'EVALSHA' || cmd === 'SCRIPT') {
          respond(respError('NOSCRIPT No matching script. Are you sure the script is loaded?'));
          continue;
        }

        if (cmd === 'FLUSHALL' || cmd === 'FLUSHDB') {
          respond(respError('ERR operation not permitted'));
          continue;
        }

        if (cmd === 'CLIENT') {
          const sub = args[1]?.toUpperCase();
          if (sub === 'SETNAME') {
            respond(respSimple('OK'));
          } else if (sub === 'GETNAME') {
            respond(respNullBulk());
          } else if (sub === 'LIST') {
            respond(
              respBulk(
                `id=1 addr=${remoteIP}:${remotePort} fd=8 name= age=0 idle=0 flags=N db=0 sub=0 psub=0 multi=-1 qbuf=0 qbuf-free=0 obl=0 oll=0 omem=0 events=r cmd=client`
              )
            );
          } else {
            respond(respSimple('OK'));
          }
          continue;
        }

        if (cmd === 'SELECT') {
          respond(respSimple('OK'));
          continue;
        }

        if (cmd === 'TYPE') {
          respond(respSimple('string'));
          continue;
        }

        if (cmd === 'TTL' || cmd === 'PTTL') {
          respond(respInt(-1));
          continue;
        }

        if (cmd === 'SCAN') {
          respond(
            `*2\r\n$1\r\n0\r\n${respArray(['session:abc123', 'cache:homepage', 'user:1001'])}`
          );
          continue;
        }

        respond(respError(`ERR unknown command '${cmd}'`));
      }
    });

    socket.on('timeout', () => {
      logger.info(`Redis session timeout: ${session.sessionId}`);
      socket.end();
    });

    socket.on('close', () => this.endSession(session.sessionId));
    socket.on('error', (err) => {
      logger.debug(`Redis socket error: ${err.message}`);
      this.endSession(session.sessionId);
    });
  }
}
