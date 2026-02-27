/**
 * Authentication utilities: password hashing and token generation.
 * Uses only node:crypto — zero external dependencies.
 * @module @panguard-ai/panguard-auth/auth
 */

import { scrypt, randomBytes, randomUUID, timingSafeEqual, createHash } from 'node:crypto';

const SCRYPT_KEYLEN = 64;
const SCRYPT_COST = 16384; // N
const SCRYPT_BLOCK = 8; // r
const SCRYPT_PARALLEL = 1; // p

/**
 * Hash a password using scrypt with a random salt.
 * Returns `salt:hash` in hex.
 */
export function hashPassword(password: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const salt = randomBytes(16).toString('hex');
    scrypt(
      password,
      salt,
      SCRYPT_KEYLEN,
      { N: SCRYPT_COST, r: SCRYPT_BLOCK, p: SCRYPT_PARALLEL },
      (err, derived) => {
        if (err) return reject(err);
        resolve(`${salt}:${derived.toString('hex')}`);
      }
    );
  });
}

/**
 * Verify a password against a stored `salt:hash` string.
 */
export function verifyPassword(password: string, stored: string): Promise<boolean> {
  return new Promise((resolve, reject) => {
    const [salt, hash] = stored.split(':');
    if (!salt || !hash) return resolve(false);

    scrypt(
      password,
      salt,
      SCRYPT_KEYLEN,
      { N: SCRYPT_COST, r: SCRYPT_BLOCK, p: SCRYPT_PARALLEL },
      (err, derived) => {
        if (err) return reject(err);
        const storedBuf = Buffer.from(hash, 'hex');
        resolve(timingSafeEqual(derived, storedBuf));
      }
    );
  });
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
