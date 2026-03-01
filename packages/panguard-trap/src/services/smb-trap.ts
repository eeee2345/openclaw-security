/**
 * SMB2 Binary Protocol Honeypot
 * SMB2 二進位協議蜜罐
 *
 * Speaks real SMB2 binary protocol:
 * - Responds to SMB2 Negotiate with valid negotiate response
 * - Handles Session Setup (NTLMSSP) to capture credentials
 * - Tree Connect for share enumeration
 *
 * @module @panguard-ai/panguard-trap/services/smb-trap
 */

import { createLogger } from '@panguard-ai/core';
import type { TrapServiceConfig } from '../types.js';
import { BaseTrapService } from './base-service.js';

const logger = createLogger('panguard-trap:service:smb');

// SMB2 protocol constants
const SMB2_MAGIC = Buffer.from([0xfe, 0x53, 0x4d, 0x42]); // \xFESMB
const SMB1_MAGIC = Buffer.from([0xff, 0x53, 0x4d, 0x42]); // \xFFSMB

// SMB2 Commands
const SMB2_NEGOTIATE = 0x0000;
const SMB2_SESSION_SETUP = 0x0001;
const SMB2_TREE_CONNECT = 0x0003;
const SMB2_TREE_DISCONNECT = 0x0004;
const SMB2_LOGOFF = 0x0002;

// SMB2 Status codes
const STATUS_SUCCESS = 0x00000000;
const STATUS_MORE_PROCESSING = 0xc0000016;
const STATUS_LOGON_FAILURE = 0xc000006d;

// NTLMSSP signatures
const NTLMSSP_SIGNATURE = Buffer.from('NTLMSSP\0', 'ascii');
const NTLMSSP_NEGOTIATE = 1;
const NTLMSSP_CHALLENGE = 2;
const NTLMSSP_AUTH = 3;

// ---------------------------------------------------------------------------
// Packet Builders
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

/** Build NetBIOS Session Service wrapper (4-byte length header) */
function wrapNetBIOS(payload: Buffer): Buffer {
  const header = Buffer.alloc(4);
  header[0] = 0x00; // Session Message
  header[1] = (payload.length >> 16) & 0xff;
  header[2] = (payload.length >> 8) & 0xff;
  header[3] = payload.length & 0xff;
  return Buffer.concat([header, payload]);
}

/** Build minimal SMB2 header (64 bytes) */
function buildSMB2Header(
  command: number,
  status: number,
  messageId: bigint,
  sessionId: bigint
): Buffer {
  const header = Buffer.alloc(64);

  SMB2_MAGIC.copy(header, 0); // ProtocolId
  writeUint16LE(header, 4, 64); // StructureSize
  writeUint16LE(header, 6, 0); // CreditCharge
  writeUint32LE(header, 8, status); // Status
  writeUint16LE(header, 12, command); // Command
  writeUint16LE(header, 14, 1); // CreditResponse
  writeUint32LE(header, 16, 0); // Flags
  writeUint32LE(header, 20, 0); // NextCommand
  header.writeBigUInt64LE(messageId, 24); // MessageId
  writeUint32LE(header, 36, 0xfffffffe); // TreeId (0xFFFFFFFE for some cmds)
  header.writeBigUInt64LE(sessionId, 40); // SessionId

  return header;
}

/** Build SMB2 Negotiate Response */
function buildNegotiateResponse(messageId: bigint): Buffer {
  // Minimal Negotiate Response (65 bytes body)
  const body = Buffer.alloc(65);
  writeUint16LE(body, 0, 65); // StructureSize
  writeUint16LE(body, 2, 0); // SecurityMode (signing enabled)
  writeUint16LE(body, 4, 0x0311); // DialectRevision: SMB 3.1.1
  writeUint16LE(body, 6, 0); // NegotiateContextCount

  // Server GUID (16 bytes random-ish)
  const guid = Buffer.from('PANGUARD-AI-SMB2', 'ascii');
  guid.copy(body, 8);

  writeUint32LE(body, 24, 0x0000002f); // Capabilities
  writeUint32LE(body, 28, 0x00100000); // MaxTransactSize
  writeUint32LE(body, 32, 0x00100000); // MaxReadSize
  writeUint32LE(body, 36, 0x00100000); // MaxWriteSize

  // SystemTime (Windows FILETIME) - approximate current time
  const now = BigInt(Date.now()) * 10000n + 116444736000000000n;
  body.writeBigUInt64LE(now, 40); // SystemTime
  body.writeBigUInt64LE(now, 48); // ServerStartTime

  writeUint16LE(body, 56, 0); // SecurityBufferOffset
  writeUint16LE(body, 58, 0); // SecurityBufferLength

  const header = buildSMB2Header(SMB2_NEGOTIATE, STATUS_SUCCESS, messageId, 0n);
  return wrapNetBIOS(Buffer.concat([header, body]));
}

/** Build NTLMSSP Challenge message */
function buildNTLMSSPChallenge(): Buffer {
  const target = Buffer.from('PANGUARD', 'utf16le');
  const challenge = Buffer.alloc(32);

  // NTLMSSP header
  NTLMSSP_SIGNATURE.copy(challenge, 0);
  writeUint32LE(challenge, 8, NTLMSSP_CHALLENGE); // MessageType
  writeUint16LE(challenge, 12, target.length); // TargetNameLen
  writeUint16LE(challenge, 14, target.length); // TargetNameMaxLen
  writeUint32LE(challenge, 16, 32 + 24); // TargetNameOffset (after fixed fields)

  writeUint32LE(challenge, 20, 0x00028233); // NegotiateFlags

  // Server Challenge (8 bytes)
  const serverChallenge = Buffer.from('12345678', 'ascii');
  serverChallenge.copy(challenge, 24);

  // Minimal TargetInfo
  const targetInfo = Buffer.alloc(4); // MsvAvEOL
  writeUint16LE(targetInfo, 0, 0); // AvId: MsvAvEOL
  writeUint16LE(targetInfo, 2, 0); // AvLen

  return Buffer.concat([challenge, target, targetInfo]);
}

/** Build SMB2 Session Setup Response with NTLMSSP Challenge */
function buildSessionSetupChallengeResponse(messageId: bigint, sessionId: bigint): Buffer {
  const ntlmChallenge = buildNTLMSSPChallenge();

  // GSS-API / SPNEGO wrapper for NTLMSSP
  // Simplified: just send the NTLMSSP directly in the security buffer
  const securityBuffer = ntlmChallenge;

  const body = Buffer.alloc(9 + securityBuffer.length);
  writeUint16LE(body, 0, 9); // StructureSize
  writeUint16LE(body, 2, 0); // SessionFlags
  writeUint16LE(body, 4, 64 + 9); // SecurityBufferOffset (header + body start)
  writeUint16LE(body, 6, securityBuffer.length); // SecurityBufferLength
  securityBuffer.copy(body, 8);

  const header = buildSMB2Header(SMB2_SESSION_SETUP, STATUS_MORE_PROCESSING, messageId, sessionId);
  return wrapNetBIOS(Buffer.concat([header, body]));
}

/** Build SMB2 Session Setup failure response */
function buildSessionSetupFailure(messageId: bigint, sessionId: bigint): Buffer {
  const body = Buffer.alloc(9);
  writeUint16LE(body, 0, 9);

  const header = buildSMB2Header(SMB2_SESSION_SETUP, STATUS_LOGON_FAILURE, messageId, sessionId);
  return wrapNetBIOS(Buffer.concat([header, body]));
}

/** Extract username from NTLMSSP Auth message */
function parseNTLMSSPAuth(data: Buffer): { domain: string; username: string } | null {
  const ntlmIdx = data.indexOf(NTLMSSP_SIGNATURE);
  if (ntlmIdx < 0) return null;

  const msgType = data.readUInt32LE(ntlmIdx + 8);
  if (msgType !== NTLMSSP_AUTH) return null;

  try {
    // Domain name: offset at ntlmIdx+28 (4 bytes)
    const domainLen = data.readUInt16LE(ntlmIdx + 28);
    const domainOff = data.readUInt32LE(ntlmIdx + 32);
    const domain = data
      .subarray(ntlmIdx + domainOff, ntlmIdx + domainOff + domainLen)
      .toString('utf16le');

    // User name: offset at ntlmIdx+36
    const userLen = data.readUInt16LE(ntlmIdx + 36);
    const userOff = data.readUInt32LE(ntlmIdx + 40);
    const username = data
      .subarray(ntlmIdx + userOff, ntlmIdx + userOff + userLen)
      .toString('utf16le');

    return { domain, username };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// SMB Trap Service
// ---------------------------------------------------------------------------

export class SMBTrapService extends BaseTrapService {
  private server: ReturnType<typeof import('node:net').createServer> | null = null;

  constructor(config: TrapServiceConfig) {
    super({ ...config, type: 'smb' });
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

    this.addMitreTechnique(session.sessionId, 'T1021.002'); // SMB

    let authPhase: 'negotiate' | 'challenge_sent' | 'authenticated' | 'denied' = 'negotiate';
    let authAttempts = 0;
    const sessionIdSMB = BigInt(Math.floor(Math.random() * 0xffffffff));

    const timeout = this.config.sessionTimeoutMs ?? 30_000;
    socket.setTimeout(timeout);

    socket.on('data', (data: Buffer) => {
      if (data.length < 8) return;

      // Skip NetBIOS header (4 bytes)
      const payload = data.subarray(4);

      // Check for SMB1 Negotiate (initial clients may send SMB1 first)
      const isSMB1 = payload.subarray(0, 4).equals(SMB1_MAGIC);
      const isSMB2 = payload.subarray(0, 4).equals(SMB2_MAGIC);

      if (!isSMB1 && !isSMB2) {
        // Not SMB at all - text fallback for raw scanners
        const text = data.toString('utf-8').trim();
        if (text) {
          this.recordCommand(session.sessionId, text);
        }
        return;
      }

      if (isSMB1 || (isSMB2 && authPhase === 'negotiate')) {
        // Respond with SMB2 Negotiate Response regardless
        const msgId = isSMB2 ? payload.readBigUInt64LE(24) : 0n;
        try {
          socket.write(buildNegotiateResponse(msgId));
        } catch {
          /* */
        }
        authPhase = 'negotiate';

        // If it's an SMB2 Negotiate, wait for Session Setup
        if (isSMB2) {
          const command = payload.readUInt16LE(12);
          if (command === SMB2_NEGOTIATE) {
            authPhase = 'negotiate';
          }
        }
        return;
      }

      if (!isSMB2) return;

      const command = payload.readUInt16LE(12);
      const msgId = payload.readBigUInt64LE(24);

      if (command === SMB2_SESSION_SETUP) {
        // Check for NTLMSSP in the payload
        const ntlmIdx = data.indexOf(NTLMSSP_SIGNATURE);

        if (ntlmIdx >= 0) {
          const msgType = data.readUInt32LE(ntlmIdx + 8);

          if (msgType === NTLMSSP_NEGOTIATE) {
            // Send NTLMSSP Challenge
            try {
              socket.write(buildSessionSetupChallengeResponse(msgId, sessionIdSMB));
            } catch {
              /* */
            }
            authPhase = 'challenge_sent';
            return;
          }

          if (msgType === NTLMSSP_AUTH) {
            // Extract credentials
            const creds = parseNTLMSSPAuth(data);
            authAttempts++;

            const username = creds
              ? creds.domain
                ? `${creds.domain}\\${creds.username}`
                : creds.username
              : 'unknown';

            this.recordCredential(session.sessionId, username, '***NTLM***', authAttempts >= 3);
            this.addMitreTechnique(session.sessionId, 'T1110');

            if (authAttempts >= 3) {
              // Grant fake access
              authPhase = 'authenticated';
              this.addMitreTechnique(session.sessionId, 'T1078');
              // Send success (but limited access)
              const successHeader = buildSMB2Header(
                SMB2_SESSION_SETUP,
                STATUS_SUCCESS,
                msgId,
                sessionIdSMB
              );
              const successBody = Buffer.alloc(9);
              writeUint16LE(successBody, 0, 9);
              try {
                socket.write(wrapNetBIOS(Buffer.concat([successHeader, successBody])));
              } catch {
                /* */
              }
            } else {
              try {
                socket.write(buildSessionSetupFailure(msgId, sessionIdSMB));
              } catch {
                /* */
              }
              authPhase = 'denied';
            }
            return;
          }
        }

        // No NTLMSSP found - send challenge anyway
        try {
          socket.write(buildSessionSetupChallengeResponse(msgId, sessionIdSMB));
        } catch {
          /* */
        }
        authPhase = 'challenge_sent';
        return;
      }

      if (command === SMB2_TREE_CONNECT && authPhase === 'authenticated') {
        this.addMitreTechnique(session.sessionId, 'T1135'); // Network share discovery
        this.recordCommand(session.sessionId, 'TREE_CONNECT');

        // Minimal Tree Connect Response
        const treeBody = Buffer.alloc(16);
        writeUint16LE(treeBody, 0, 16); // StructureSize
        treeBody[2] = 0x01; // ShareType: Disk
        writeUint32LE(treeBody, 4, 0x00100081); // ShareFlags
        writeUint32LE(treeBody, 8, 0x001f01ff); // Capabilities

        const treeHeader = buildSMB2Header(SMB2_TREE_CONNECT, STATUS_SUCCESS, msgId, sessionIdSMB);
        try {
          socket.write(wrapNetBIOS(Buffer.concat([treeHeader, treeBody])));
        } catch {
          /* */
        }
        return;
      }

      if (command === SMB2_TREE_DISCONNECT || command === SMB2_LOGOFF) {
        const closeBody = Buffer.alloc(4);
        writeUint16LE(closeBody, 0, 4);
        const closeHeader = buildSMB2Header(command, STATUS_SUCCESS, msgId, sessionIdSMB);
        try {
          socket.write(wrapNetBIOS(Buffer.concat([closeHeader, closeBody])));
        } catch {
          /* */
        }
        if (command === SMB2_LOGOFF) {
          socket.end();
        }
        return;
      }

      // Any other command - return STATUS_ACCESS_DENIED
      const denyHeader = buildSMB2Header(command, 0xc0000022, msgId, sessionIdSMB);
      const denyBody = Buffer.alloc(9);
      writeUint16LE(denyBody, 0, 9);
      try {
        socket.write(wrapNetBIOS(Buffer.concat([denyHeader, denyBody])));
      } catch {
        /* */
      }
    });

    socket.on('timeout', () => {
      logger.info(`SMB session timeout: ${session.sessionId}`);
      socket.end();
    });

    socket.on('close', () => this.endSession(session.sessionId));
    socket.on('error', (err) => {
      logger.debug(`SMB socket error: ${err.message}`);
      this.endSession(session.sessionId);
    });
  }
}
