/**
 * MySQL Wire Protocol Honeypot
 * MySQL 線路協議蜜罐
 *
 * Speaks the real MySQL client-server protocol:
 * - Sends binary Server Greeting (handshake) packet
 * - Parses client HandshakeResponse to extract credentials
 * - Handles COM_QUERY with fake result sets
 *
 * @module @panguard-ai/panguard-trap/services/mysql-trap
 */

import { createLogger } from '@panguard-ai/core';
import type { TrapServiceConfig } from '../types.js';
import { BaseTrapService } from './base-service.js';

const logger = createLogger('panguard-trap:service:mysql');

// MySQL protocol constants
const MYSQL_PROTOCOL_VERSION = 10;
const SERVER_VERSION = '5.7.42-0ubuntu0.18.04.1';
const CHARSET_UTF8 = 0x21;
const STATUS_AUTOCOMMIT = 0x0002;

// Capability flags
const CLIENT_LONG_PASSWORD = 1;
const CLIENT_PROTOCOL_41 = 0x200;
const CLIENT_SECURE_CONNECTION = 0x8000;
const CLIENT_PLUGIN_AUTH = 0x00080000;
const SERVER_CAPABILITIES =
  CLIENT_LONG_PASSWORD | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH;

// COM types
const COM_QUIT = 0x01;
const COM_INIT_DB = 0x02;
const COM_QUERY = 0x03;
const COM_PING = 0x0e;

// ---------------------------------------------------------------------------
// Packet builders
// ---------------------------------------------------------------------------

function writeUint16LE(buf: Buffer, offset: number, value: number): void {
  buf[offset] = value & 0xff;
  buf[offset + 1] = (value >> 8) & 0xff;
}

function writeUint32LE(buf: Buffer, offset: number, value: number): void {
  buf[offset] = value & 0xff;
  buf[offset + 1] = (value >> 8) & 0xff;
  buf[offset + 2] = (value >> 16) & 0xff;
  buf[offset + 3] = (value >> 24) & 0xff;
}

/** Build a MySQL packet with length header and sequence id */
function buildPacket(sequenceId: number, payload: Buffer): Buffer {
  const header = Buffer.alloc(4);
  header[0] = payload.length & 0xff;
  header[1] = (payload.length >> 8) & 0xff;
  header[2] = (payload.length >> 16) & 0xff;
  header[3] = sequenceId;
  return Buffer.concat([header, payload]);
}

/** Build MySQL Server Greeting (Handshake v10) */
function buildServerGreeting(connectionId: number): Buffer {
  const scramble1 = Buffer.from('AAAAAAAAAA', 'ascii').subarray(0, 8);
  const scramble2 = Buffer.from('BBBBBBBBBBBB', 'ascii').subarray(0, 12);
  const pluginName = Buffer.from('mysql_native_password\0', 'ascii');
  const versionBuf = Buffer.from(SERVER_VERSION + '\0', 'ascii');

  const payloadLen =
    1 +                // protocol version
    versionBuf.length +
    4 +                // connection id
    8 + 1 +            // scramble1 + filler
    2 +                // capabilities lower
    1 +                // charset
    2 +                // status flags
    2 +                // capabilities upper
    1 +                // auth plugin data length
    10 +               // reserved
    12 + 1 +           // scramble2 + filler
    pluginName.length;

  const payload = Buffer.alloc(payloadLen);
  let pos = 0;

  payload[pos++] = MYSQL_PROTOCOL_VERSION;
  versionBuf.copy(payload, pos);
  pos += versionBuf.length;
  writeUint32LE(payload, pos, connectionId);
  pos += 4;
  scramble1.copy(payload, pos);
  pos += 8;
  payload[pos++] = 0x00; // filler
  writeUint16LE(payload, pos, SERVER_CAPABILITIES & 0xffff);
  pos += 2;
  payload[pos++] = CHARSET_UTF8;
  writeUint16LE(payload, pos, STATUS_AUTOCOMMIT);
  pos += 2;
  writeUint16LE(payload, pos, (SERVER_CAPABILITIES >> 16) & 0xffff);
  pos += 2;
  payload[pos++] = 21; // auth plugin data length
  payload.fill(0, pos, pos + 10); // reserved
  pos += 10;
  scramble2.copy(payload, pos);
  pos += 12;
  payload[pos++] = 0x00; // filler
  pluginName.copy(payload, pos);

  return buildPacket(0, payload);
}

/** Build OK packet */
function buildOKPacket(sequenceId: number): Buffer {
  const payload = Buffer.from([0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]);
  return buildPacket(sequenceId, payload);
}

/** Build ERR packet */
function buildERRPacket(sequenceId: number, code: number, message: string): Buffer {
  const msgBuf = Buffer.from(message, 'utf-8');
  const payload = Buffer.alloc(1 + 2 + 1 + 5 + msgBuf.length);
  let pos = 0;
  payload[pos++] = 0xff; // ERR marker
  writeUint16LE(payload, pos, code);
  pos += 2;
  payload[pos++] = 0x23; // '#'
  Buffer.from('28000').copy(payload, pos); // SQL state
  pos += 5;
  msgBuf.copy(payload, pos);
  return buildPacket(sequenceId, payload);
}

/** Build a simple text result set (for SHOW DATABASES etc.) */
function buildResultSet(
  sequenceId: number,
  columnName: string,
  rows: string[]
): Buffer[] {
  const packets: Buffer[] = [];
  let seq = sequenceId;

  // Column count
  packets.push(buildPacket(seq++, Buffer.from([rows.length > 0 ? 1 : 0])));

  // Column definition
  const colParts = [
    '\x03def', // catalog
    '', // schema
    '', // table
    '', // org_table
    columnName, // column name
    columnName, // org column name
  ];
  const colBufs: Buffer[] = [];
  for (const part of colParts) {
    const b = Buffer.from(part, 'utf-8');
    const len = Buffer.from([b.length]);
    colBufs.push(len, b);
  }
  colBufs.push(Buffer.from([
    0x0c,       // filler
    CHARSET_UTF8, 0x00, // charset
    0x40, 0x00, 0x00, 0x00, // column length
    0xfd,       // type: VARCHAR
    0x01, 0x00, // flags
    0x00,       // decimals
    0x00, 0x00, // filler
  ]));
  packets.push(buildPacket(seq++, Buffer.concat(colBufs)));

  // EOF
  packets.push(buildPacket(seq++, Buffer.from([0xfe, 0x00, 0x00, 0x02, 0x00])));

  // Rows
  for (const row of rows) {
    const rowBuf = Buffer.from(row, 'utf-8');
    const lenBuf = Buffer.from([rowBuf.length]);
    packets.push(buildPacket(seq++, Buffer.concat([lenBuf, rowBuf])));
  }

  // EOF
  packets.push(buildPacket(seq++, Buffer.from([0xfe, 0x00, 0x00, 0x02, 0x00])));

  return packets;
}

/** Parse username from client HandshakeResponse41 */
function parseHandshakeResponse(data: Buffer): { username: string } | null {
  if (data.length < 36) return null;

  try {
    // Skip: capabilities(4) + max_packet(4) + charset(1) + reserved(23) = 32
    let pos = 32;

    // Read null-terminated username
    const nullIdx = data.indexOf(0x00, pos);
    if (nullIdx < 0 || nullIdx > pos + 64) return null;
    const username = data.subarray(pos, nullIdx).toString('utf-8');
    return { username };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// MITRE detection patterns for SQL queries
// ---------------------------------------------------------------------------

const SQL_MITRE_PATTERNS: [RegExp, string][] = [
  [/UNION\s+(ALL\s+)?SELECT/i, 'T1190'], // SQL injection
  [/OR\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?/i, 'T1190'],
  [/LOAD_FILE\s*\(/i, 'T1005'], // Data from local system
  [/INTO\s+OUTFILE/i, 'T1567'], // Exfiltration
  [/INFORMATION_SCHEMA/i, 'T1083'], // File & directory discovery
  [/DROP\s+(TABLE|DATABASE)/i, 'T1485'], // Data destruction
  [/BENCHMARK\s*\(/i, 'T1499'], // Endpoint DoS
  [/SLEEP\s*\(/i, 'T1499'],
  [/xp_cmdshell/i, 'T1059'], // Command execution
  [/INTO\s+DUMPFILE/i, 'T1005'],
];

// ---------------------------------------------------------------------------
// MySQL Trap Service
// ---------------------------------------------------------------------------

export class MySQLTrapService extends BaseTrapService {
  private server: ReturnType<typeof import('node:net').createServer> | null = null;
  private connectionCounter = 0;

  constructor(config: TrapServiceConfig) {
    super({ ...config, type: 'mysql' });
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

    this.addMitreTechnique(session.sessionId, 'T1110'); // Brute force
    this.connectionCounter += 1;

    const connId = this.connectionCounter;
    let authenticated = false;
    let authAttempts = 0;
    let currentUser = '';

    // Send real MySQL greeting packet
    try {
      socket.write(buildServerGreeting(connId));
    } catch {
      return;
    }

    const timeout = this.config.sessionTimeoutMs ?? 30_000;
    socket.setTimeout(timeout);

    socket.on('data', (data: Buffer) => {
      if (data.length < 5) return;

      // Read sequence id from packet header
      const sequenceId = data[3]!;

      if (!authenticated) {
        // Expect HandshakeResponse
        const payload = data.subarray(4);
        const parsed = parseHandshakeResponse(payload);
        currentUser = parsed?.username ?? 'unknown';
        authAttempts += 1;

        this.recordCredential(session.sessionId, currentUser, '***', authAttempts >= 3);

        if (authAttempts >= 3) {
          authenticated = true;
          this.addMitreTechnique(session.sessionId, 'T1078'); // Valid accounts
          try {
            socket.write(buildOKPacket(sequenceId + 1));
          } catch { /* socket closed */ }
        } else {
          try {
            socket.write(
              buildERRPacket(sequenceId + 1, 1045, `Access denied for user '${currentUser}'@'${remoteIP}'`)
            );
          } catch { /* socket closed */ }
        }
        return;
      }

      // Authenticated - handle COM_* commands
      const comType = data[4];

      if (comType === COM_QUIT) {
        socket.end();
        return;
      }

      if (comType === COM_PING) {
        try { socket.write(buildOKPacket(1)); } catch { /* */ }
        return;
      }

      if (comType === COM_INIT_DB) {
        try { socket.write(buildOKPacket(1)); } catch { /* */ }
        return;
      }

      if (comType === COM_QUERY) {
        const query = data.subarray(5).toString('utf-8').trim();
        this.recordCommand(session.sessionId, query);

        // MITRE technique detection
        for (const [pattern, technique] of SQL_MITRE_PATTERNS) {
          if (pattern.test(query)) {
            this.addMitreTechnique(session.sessionId, technique);
            this.recordEvent(session.sessionId, 'exploit_attempt', query, { technique });
          }
        }

        const upper = query.toUpperCase().replace(/;$/, '');
        const delay = this.config.responseDelayMs ?? 80;

        setTimeout(() => {
          try {
            if (upper.startsWith('SHOW DATABASES')) {
              const packets = buildResultSet(1, 'Database', [
                'information_schema', 'mysql', 'performance_schema', 'webapp',
              ]);
              for (const p of packets) socket.write(p);
            } else if (upper.startsWith('SHOW TABLES')) {
              const packets = buildResultSet(1, 'Tables_in_webapp', [
                'users', 'sessions', 'orders', 'payments',
              ]);
              for (const p of packets) socket.write(p);
            } else if (upper.startsWith('SELECT')) {
              socket.write(
                buildERRPacket(1, 1142, `SELECT command denied to user '${currentUser}'@'${remoteIP}'`)
              );
            } else if (
              upper.startsWith('DROP') || upper.startsWith('DELETE') ||
              upper.startsWith('INSERT') || upper.startsWith('UPDATE')
            ) {
              socket.write(
                buildERRPacket(1, 1142, `command denied to user '${currentUser}'@'${remoteIP}'`)
              );
            } else {
              socket.write(
                buildERRPacket(1, 1064, `You have an error in your SQL syntax near '${query.slice(0, 30)}'`)
              );
            }
          } catch {
            // socket closed
          }
        }, delay);
        return;
      }

      // Unknown COM type
      try {
        socket.write(buildERRPacket(1, 1047, 'Unknown command'));
      } catch { /* */ }
    });

    socket.on('timeout', () => {
      logger.info(`MySQL session timeout: ${session.sessionId}`);
      socket.end();
    });

    socket.on('close', () => this.endSession(session.sessionId));
    socket.on('error', (err) => {
      logger.debug(`MySQL socket error: ${err.message}`);
      this.endSession(session.sessionId);
    });
  }
}
