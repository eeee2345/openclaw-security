/**
 * TOTP (Time-based One-Time Password) implementation.
 * RFC 6238 compliant. Uses only node:crypto — zero external dependencies.
 *
 * @module @panguard-ai/panguard-auth/totp
 */

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const TOTP_PERIOD = 30; // seconds
const TOTP_DIGITS = 6;
const TOTP_ALGORITHM = 'sha1'; // RFC 6238 default, compatible with all authenticator apps

// ── Base32 Encoding ────────────────────────────────────────────

const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Encode a buffer to base32 (RFC 4648).
 */
export function base32Encode(buffer: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i]!;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_CHARS[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_CHARS[(value << (5 - bits)) & 31];
  }

  return output;
}

/**
 * Decode a base32 string to buffer.
 */
export function base32Decode(encoded: string): Buffer {
  const cleaned = encoded.replace(/[= ]/g, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const output: number[] = [];

  for (let i = 0; i < cleaned.length; i++) {
    const idx = BASE32_CHARS.indexOf(cleaned[i]!);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return Buffer.from(output);
}

// ── TOTP Core ──────────────────────────────────────────────────

/**
 * Generate a random TOTP secret (20 bytes = 160 bits, RFC recommended).
 * Returns the base32-encoded secret.
 */
export function generateTotpSecret(): string {
  return base32Encode(randomBytes(20));
}

/**
 * Generate 10 backup codes (8 hex chars each).
 */
export function generateBackupCodes(count = 10): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    codes.push(randomBytes(4).toString('hex'));
  }
  return codes;
}

/**
 * Generate a TOTP code for a given secret and time.
 */
export function generateTotp(secret: string, timeStep?: number): string {
  const key = base32Decode(secret);
  const step = timeStep ?? Math.floor(Date.now() / 1000 / TOTP_PERIOD);

  // Convert counter to 8-byte big-endian buffer
  const buffer = Buffer.alloc(8);
  let tmp = step;
  for (let i = 7; i >= 0; i--) {
    buffer[i] = tmp & 0xff;
    tmp = Math.floor(tmp / 256);
  }

  const hmac = createHmac(TOTP_ALGORITHM, key).update(buffer).digest();
  const offset = hmac[hmac.length - 1]! & 0x0f;

  const code =
    ((hmac[offset]! & 0x7f) << 24) |
    ((hmac[offset + 1]! & 0xff) << 16) |
    ((hmac[offset + 2]! & 0xff) << 8) |
    (hmac[offset + 3]! & 0xff);

  return String(code % 10 ** TOTP_DIGITS).padStart(TOTP_DIGITS, '0');
}

/**
 * Verify a TOTP code using timing-safe comparison.
 * Allows 1 time step drift in either direction.
 * Optionally enforces replay protection via lastUsedStep.
 *
 * Returns the matched time step on success (for replay tracking), or -1 on failure.
 */
export function verifyTotp(secret: string, code: string, lastUsedStep?: number): number {
  if (typeof code !== 'string' || code.length !== TOTP_DIGITS) return -1;

  const currentStep = Math.floor(Date.now() / 1000 / TOTP_PERIOD);

  // Check current step and +/- 1 (window of 90 seconds total)
  for (let i = -1; i <= 1; i++) {
    const step = currentStep + i;

    // Replay protection: reject codes from already-used time steps
    if (lastUsedStep !== undefined && step <= lastUsedStep) continue;

    const expected = generateTotp(secret, step);
    const a = Buffer.from(expected, 'utf8');
    const b = Buffer.from(code, 'utf8');
    if (a.length === b.length && timingSafeEqual(a, b)) {
      return step;
    }
  }

  return -1;
}

/**
 * Build an otpauth:// URI for QR code generation.
 * Compatible with Google Authenticator, Authy, 1Password, etc.
 */
export function buildOtpauthUri(secret: string, email: string, issuer = 'Panguard AI'): string {
  const encodedIssuer = encodeURIComponent(issuer);
  const encodedEmail = encodeURIComponent(email);
  return (
    `otpauth://totp/${encodedIssuer}:${encodedEmail}` +
    `?secret=${secret}&issuer=${encodedIssuer}&algorithm=SHA1&digits=${TOTP_DIGITS}&period=${TOTP_PERIOD}`
  );
}
