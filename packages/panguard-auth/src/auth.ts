/**
 * Authentication utilities: password hashing and token generation.
 * Uses only node:crypto — zero external dependencies.
 * @module @panguard-ai/panguard-auth/auth
 */

import { scrypt, randomBytes, randomUUID, timingSafeEqual, createHash } from 'node:crypto';

const SCRYPT_KEYLEN = 64;
const SCRYPT_COST_V1 = 16384; // Legacy N (pre-2026)
const SCRYPT_COST_V2 = 65536; // N (OWASP minimum recommendation)
const SCRYPT_BLOCK = 8; // r
const SCRYPT_PARALLEL = 1; // p
const SCRYPT_MAXMEM = 128 * 1024 * 1024; // 128 MB (N=65536 r=8 needs ~64 MB)
const CURRENT_HASH_VERSION = 2;

/**
 * Hash a password using scrypt with a random salt.
 * Returns `v2:salt:hash` in hex. New passwords always use the latest cost parameter.
 */
export function hashPassword(password: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const salt = randomBytes(16).toString('hex');
    scrypt(
      password,
      salt,
      SCRYPT_KEYLEN,
      { N: SCRYPT_COST_V2, r: SCRYPT_BLOCK, p: SCRYPT_PARALLEL, maxmem: SCRYPT_MAXMEM },
      (err, derived) => {
        if (err) return reject(err);
        resolve(`v${CURRENT_HASH_VERSION}:${salt}:${derived.toString('hex')}`);
      }
    );
  });
}

/**
 * Verify a password against a stored hash string.
 * Supports both legacy format (`salt:hash`, N=16384) and
 * versioned format (`v2:salt:hash`, N=65536).
 */
export function verifyPassword(password: string, stored: string): Promise<boolean> {
  return new Promise((resolve, reject) => {
    let salt: string | undefined;
    let hash: string | undefined;
    let cost: number;

    if (stored.startsWith('v2:')) {
      const parts = stored.slice(3).split(':');
      salt = parts[0];
      hash = parts[1];
      cost = SCRYPT_COST_V2;
    } else {
      // Legacy v1 format: salt:hash
      const parts = stored.split(':');
      salt = parts[0];
      hash = parts[1];
      cost = SCRYPT_COST_V1;
    }

    if (!salt || !hash) return resolve(false);

    scrypt(
      password,
      salt,
      SCRYPT_KEYLEN,
      { N: cost, r: SCRYPT_BLOCK, p: SCRYPT_PARALLEL, maxmem: SCRYPT_MAXMEM },
      (err, derived) => {
        if (err) return reject(err);
        const storedBuf = Buffer.from(hash!, 'hex');
        resolve(timingSafeEqual(derived, storedBuf));
      }
    );
  });
}

/**
 * Check if a stored password hash uses the latest scrypt parameters.
 * Returns false for legacy hashes that should be upgraded on next login.
 */
export function needsRehash(stored: string): boolean {
  return !stored.startsWith(`v${CURRENT_HASH_VERSION}:`);
}

/**
 * Generate a cryptographically secure session token (64 hex chars).
 */
export function generateSessionToken(): string {
  return randomBytes(32).toString('hex');
}

/**
 * Generate a verification token (UUID v4).
 */
export function generateVerifyToken(): string {
  return randomUUID();
}

/**
 * Hash a session token with SHA-256 for secure storage.
 * The plaintext token is sent to the client; only the hash is stored in DB.
 */
export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

/**
 * Calculate session expiry (24 hours from now).
 */
export function sessionExpiry(hours = 24): string {
  const d = new Date();
  d.setHours(d.getHours() + hours);
  return d.toISOString().replace('T', ' ').slice(0, 19);
}
