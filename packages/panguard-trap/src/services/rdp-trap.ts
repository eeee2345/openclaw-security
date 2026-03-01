/**
 * RDP (X.224 + CredSSP) Protocol Honeypot
 * RDP (X.224 + CredSSP) 協議蜜罐
 *
 * Speaks real RDP initial negotiation:
 * - Parses X.224 Connection Request (CR) with cookie/username
 * - Sends X.224 Connection Confirm (CC) with NLA/CredSSP
 * - Captures TLS ClientHello / CredSSP auth attempts
 *
 * @module @panguard-ai/panguard-trap/services/rdp-trap
 */

import { createLogger } from '@panguard-ai/core';
import type { TrapServiceConfig } from '../types.js';
import { BaseTrapService } from './base-service.js';

const logger = createLogger('panguard-trap:service:rdp');

// TPKT header (RFC 1006)
const TPKT_VERSION = 3;

// X.224 types
const X224_CONNECTION_REQUEST = 0xe0;
const X224_CONNECTION_CONFIRM = 0xd0;

// RDP Negotiation types
const TYPE_RDP_NEG_REQ = 0x01;
const TYPE_RDP_NEG_RSP = 0x02;
const TYPE_RDP_NEG_FAILURE = 0x03;

// Negotiation protocols
const PROTOCOL_RDP = 0x00000000;
const PROTOCOL_SSL = 0x00000001;
const PROTOCOL_HYBRID = 0x00000002; // CredSSP (NLA)

// Failure codes
const SSL_REQUIRED_BY_SERVER = 0x00000001;

// ---------------------------------------------------------------------------
// Packet Builders
// ---------------------------------------------------------------------------

/**
 * Build TPKT + X.224 Connection Confirm with RDP Negotiation Response.
 *
 * The response tells the client which security protocol the server wants.
 * We respond with CredSSP/NLA to force the client to attempt authentication,
 * which reveals credentials in the TLS/CredSSP handshake.
 */
function buildConnectionConfirm(requestedProtocol: number): Buffer {
  // X.224 CC payload (without TPKT header)
  // X.224 header: length indicator (1), CC (1), DST-REF (2), SRC-REF (2), class (1) = 7 bytes
  // RDP Neg Response: type (1), flags (1), length (2), selectedProtocol (4) = 8 bytes

  const useNLA = (requestedProtocol & PROTOCOL_HYBRID) !== 0;
  const useSSL = (requestedProtocol & PROTOCOL_SSL) !== 0;

  let selectedProtocol: number;
  if (useNLA) {
    selectedProtocol = PROTOCOL_HYBRID;
  } else if (useSSL) {
    selectedProtocol = PROTOCOL_SSL;
  } else {
    selectedProtocol = PROTOCOL_RDP;
  }

  // Build X.224 CC + RDP Neg RSP
  const x224Len = 7 + 8; // 15 bytes
  const x224 = Buffer.alloc(x224Len);
  let pos = 0;

  // X.224 Connection Confirm
  x224[pos++] = x224Len - 1;         // Length indicator (excluding itself)
  x224[pos++] = X224_CONNECTION_CONFIRM; // CC
  x224[pos++] = 0x00; x224[pos++] = 0x00; // DST-REF
  x224[pos++] = 0x00; x224[pos++] = 0x00; // SRC-REF
  x224[pos++] = 0x00;                // Class/Options

  // RDP Negotiation Response
  x224[pos++] = TYPE_RDP_NEG_RSP;
  x224[pos++] = 0x00;                // Flags
  x224[pos++] = 0x08; x224[pos++] = 0x00; // Length (8)
  x224[pos++] = selectedProtocol & 0xff;
  x224[pos++] = (selectedProtocol >> 8) & 0xff;
  x224[pos++] = (selectedProtocol >> 16) & 0xff;
  x224[pos++] = (selectedProtocol >> 24) & 0xff;

  // TPKT header
  const tpktLen = 4 + x224Len;
  const tpkt = Buffer.alloc(4);
  tpkt[0] = TPKT_VERSION;
  tpkt[1] = 0x00; // Reserved
  tpkt[2] = (tpktLen >> 8) & 0xff;
  tpkt[3] = tpktLen & 0xff;

  return Buffer.concat([tpkt, x224]);
}

/** Build RDP Negotiation Failure response */
function buildNegFailure(failureCode: number): Buffer {
  const x224Len = 7 + 8;
  const x224 = Buffer.alloc(x224Len);
  let pos = 0;

  x224[pos++] = x224Len - 1;
  x224[pos++] = X224_CONNECTION_CONFIRM;
  x224[pos++] = 0x00; x224[pos++] = 0x00;
  x224[pos++] = 0x00; x224[pos++] = 0x00;
  x224[pos++] = 0x00;

  x224[pos++] = TYPE_RDP_NEG_FAILURE;
  x224[pos++] = 0x00;
  x224[pos++] = 0x08; x224[pos++] = 0x00;
  x224[pos++] = failureCode & 0xff;
  x224[pos++] = (failureCode >> 8) & 0xff;
  x224[pos++] = (failureCode >> 16) & 0xff;
  x224[pos++] = (failureCode >> 24) & 0xff;

  const tpktLen = 4 + x224Len;
  const tpkt = Buffer.alloc(4);
  tpkt[0] = TPKT_VERSION;
  tpkt[1] = 0x00;
  tpkt[2] = (tpktLen >> 8) & 0xff;
  tpkt[3] = tpktLen & 0xff;

  return Buffer.concat([tpkt, x224]);
}

/**
 * Parse X.224 Connection Request to extract:
 * - Cookie (mstshash=username)
 * - Requested security protocols
 */
function parseConnectionRequest(data: Buffer): {
  cookie: string | null;
  username: string | null;
  requestedProtocol: number;
} {
  const result = { cookie: null as string | null, username: null as string | null, requestedProtocol: 0 };

  if (data.length < 11) return result;

  // Skip TPKT (4 bytes) + X.224 length indicator (1) + CR code (1) + DST-REF (2) + SRC-REF (2) + class (1)
  let pos = 4 + 1 + 1 + 2 + 2 + 1; // = 11

  // Look for cookie and RDP Neg Req in the remaining data
  const remaining = data.subarray(pos);
  const str = remaining.toString('ascii');

  // Extract cookie (Cookie: mstshash=username\r\n)
  const cookieMatch = str.match(/Cookie:\s*mstshash=([^\r\n]+)/i);
  if (cookieMatch) {
    result.cookie = cookieMatch[1]!.trim();
    result.username = result.cookie;
  }

  // Look for RDP Negotiation Request at the end
  // Find TYPE_RDP_NEG_REQ byte
  for (let i = remaining.length - 8; i >= 0; i--) {
    if (remaining[i] === TYPE_RDP_NEG_REQ && remaining[i + 2] === 0x08 && remaining[i + 3] === 0x00) {
      result.requestedProtocol = remaining.readUInt32LE(i + 4);
      break;
    }
  }

  return result;
}

// ---------------------------------------------------------------------------
// RDP Trap Service
// ---------------------------------------------------------------------------

export class RDPTrapService extends BaseTrapService {
  private server: ReturnType<typeof import('node:net').createServer> | null = null;

  constructor(config: TrapServiceConfig) {
    super({ ...config, type: 'rdp' });
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

    this.addMitreTechnique(session.sessionId, 'T1021.001'); // RDP

    let phase: 'x224' | 'tls' | 'post_tls' = 'x224';
    let dataCount = 0;

    const timeout = this.config.sessionTimeoutMs ?? 60_000;
    socket.setTimeout(timeout);

    socket.on('data', (data: Buffer) => {
      dataCount++;

      if (phase === 'x224') {
        // Expect X.224 Connection Request
        if (data.length < 11) return;

        // Check TPKT header
        if (data[0] !== TPKT_VERSION) {
          // Not a valid TPKT, might be a scanner sending garbage
          this.recordEvent(session.sessionId, 'exploit_attempt', 'Non-TPKT data received', {
            rawHex: data.subarray(0, 32).toString('hex'),
          });
          return;
        }

        // Check X.224 CR
        const x224Type = data[5];
        if (x224Type !== X224_CONNECTION_REQUEST) {
          return;
        }

        const parsed = parseConnectionRequest(data);

        if (parsed.username) {
          this.recordCredential(session.sessionId, parsed.username, '***RDP_COOKIE***', false);
          this.recordEvent(session.sessionId, 'authentication_attempt', `RDP cookie: ${parsed.username}`, {
            cookie: parsed.cookie,
          });
        }

        this.recordCommand(session.sessionId, `X224_CR protocol=${parsed.requestedProtocol}`);

        // Send Connection Confirm
        const delay = this.config.responseDelayMs ?? 200;
        setTimeout(() => {
          try {
            if (parsed.requestedProtocol & PROTOCOL_HYBRID) {
              // Client supports NLA - send confirm, they'll attempt CredSSP/TLS
              socket.write(buildConnectionConfirm(parsed.requestedProtocol));
              phase = 'tls';
            } else if (parsed.requestedProtocol & PROTOCOL_SSL) {
              // Client wants SSL only - send confirm
              socket.write(buildConnectionConfirm(parsed.requestedProtocol));
              phase = 'tls';
            } else {
              // Plain RDP - send failure requiring SSL
              socket.write(buildNegFailure(SSL_REQUIRED_BY_SERVER));
              socket.end();
            }
          } catch {
            // socket closed
          }
        }, delay);
        return;
      }

      if (phase === 'tls') {
        // Client will send TLS ClientHello or CredSSP NTLM
        this.recordEvent(session.sessionId, 'authentication_attempt', 'TLS/CredSSP handshake data', {
          dataLength: data.length,
          firstBytes: data.subarray(0, 16).toString('hex'),
        });

        // Check for NTLMSSP in CredSSP
        const ntlmIdx = data.indexOf(Buffer.from('NTLMSSP\0', 'ascii'));
        if (ntlmIdx >= 0) {
          this.addMitreTechnique(session.sessionId, 'T1110');

          // Try to extract username from NTLMSSP Auth (type 3)
          const msgType = data.readUInt32LE(ntlmIdx + 8);
          if (msgType === 3) {
            // NTLMSSP Auth message
            try {
              const userLen = data.readUInt16LE(ntlmIdx + 36);
              const userOff = data.readUInt32LE(ntlmIdx + 40);
              const username = data.subarray(ntlmIdx + userOff, ntlmIdx + userOff + userLen).toString('utf16le');

              const domainLen = data.readUInt16LE(ntlmIdx + 28);
              const domainOff = data.readUInt32LE(ntlmIdx + 32);
              const domain = data.subarray(ntlmIdx + domainOff, ntlmIdx + domainOff + domainLen).toString('utf16le');

              const fullUser = domain ? `${domain}\\${username}` : username;
              this.recordCredential(session.sessionId, fullUser, '***NTLM_RDP***', false);
            } catch {
              // Malformed NTLMSSP
            }
          }
        }

        // After a few data exchanges, close with auth failure
        if (dataCount > 5) {
          phase = 'post_tls';
          setTimeout(() => {
            try { socket.end(); } catch { /* */ }
          }, 500);
        }
        return;
      }

      // post_tls - just record and close
      this.recordCommand(session.sessionId, `post_tls_data_len=${data.length}`);
    });

    socket.on('timeout', () => {
      logger.info(`RDP session timeout: ${session.sessionId}`);
      socket.end();
    });

    socket.on('close', () => this.endSession(session.sessionId));
    socket.on('error', (err) => {
      logger.debug(`RDP socket error: ${err.message}`);
      this.endSession(session.sessionId);
    });
  }
}
