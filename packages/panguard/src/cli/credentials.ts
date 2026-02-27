/**
 * Local credential store for CLI authentication.
 * Stores session token at ~/.panguard/credentials.json with 0600 permissions.
 *
 * @module @panguard-ai/panguard/cli/credentials
 */

import { existsSync, readFileSync, writeFileSync, unlinkSync, mkdirSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { homedir, hostname, userInfo } from 'node:os';
import { createHash, createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

export const CREDENTIALS_DIR = join(homedir(), '.panguard');
export const CREDENTIALS_PATH = join(CREDENTIALS_DIR, 'credentials.enc');
/** Legacy plaintext path for migration */
const LEGACY_CREDENTIALS_PATH = join(CREDENTIALS_DIR, 'credentials.json');

// ── AES-256-GCM encryption ─────────────────────────────────────────

const ALGORITHM = 'aes-256-gcm' as const;
const IV_LENGTH = 16;

/** Derive a machine-locked encryption key from hostname + username */
function deriveKey(): Buffer {
  const machineId = `${hostname()}-${userInfo().username}-panguard-ai`;
  return createHash('sha256').update(machineId).digest();
}

function encryptData(plaintext: string): string {
  const key = deriveKey();
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return `${iv.toString('base64')}:${authTag.toString('base64')}:${encrypted.toString('base64')}`;
}

function decryptData(encryptedStr: string): string {
  const key = deriveKey();
  const parts = encryptedStr.split(':');
  if (parts.length !== 3) throw new Error('Invalid encrypted format');
  const iv = Buffer.from(parts[0]!, 'base64');
  const authTag = Buffer.from(parts[1]!, 'base64');
  const encrypted = Buffer.from(parts[2]!, 'base64');
  const decipher = createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

export type Tier = 'free' | 'solo' | 'pro' | 'enterprise' | 'starter' | 'team' | 'business';

export const TIER_LEVEL: Record<Tier, number> = {
  free: 0,
  solo: 1,
  starter: 2, // legacy
  pro: 2,
  team: 3, // legacy alias
  business: 4, // legacy
  enterprise: 5,
};

export interface StoredCredentials {
  /** Session token (Bearer token for API calls) */
  token: string;
  /** ISO timestamp of session expiry */
  expiresAt: string;
  /** User email */
  email: string;
  /** Subscription tier */
  tier: Tier;
  /** Display name */
  name: string;
  /** When credentials were saved */
  savedAt: string;
  /** Auth server base URL */
  apiUrl: string;
}

/**
 * Save credentials to disk with AES-256-GCM encryption.
 */
export function saveCredentials(creds: StoredCredentials): void {
  if (!existsSync(CREDENTIALS_DIR)) {
    mkdirSync(CREDENTIALS_DIR, { recursive: true, mode: 0o700 });
  }
  const json = JSON.stringify(creds);
  const encrypted = encryptData(json);
  writeFileSync(CREDENTIALS_PATH, encrypted, { encoding: 'utf-8', mode: 0o600 });
  try {
    chmodSync(CREDENTIALS_PATH, 0o600);
  } catch {
    /* best-effort */
  }

  // Remove legacy plaintext file if it exists
  if (existsSync(LEGACY_CREDENTIALS_PATH)) {
    try {
      unlinkSync(LEGACY_CREDENTIALS_PATH);
    } catch {
      /* best-effort */
    }
  }
}

/**
 * Load credentials from disk. Handles encrypted and legacy plaintext files.
 */
export function loadCredentials(): StoredCredentials | null {
  // Try encrypted file first
  if (existsSync(CREDENTIALS_PATH)) {
    try {
      const encrypted = readFileSync(CREDENTIALS_PATH, 'utf-8');
      const json = decryptData(encrypted);
      const data = JSON.parse(json) as StoredCredentials;
      if (!data.token || !data.expiresAt || !data.email) return null;
      return data;
    } catch {
      return null;
    }
  }

  // Fallback: migrate legacy plaintext credentials
  if (existsSync(LEGACY_CREDENTIALS_PATH)) {
    try {
      const json = readFileSync(LEGACY_CREDENTIALS_PATH, 'utf-8');
      const data = JSON.parse(json) as StoredCredentials;
      if (!data.token || !data.expiresAt || !data.email) return null;
      // Re-save as encrypted and remove plaintext
      saveCredentials(data);
      return data;
    } catch {
      return null;
    }
  }

  return null;
}

/**
 * Delete stored credentials. Returns true if file was removed.
 */
export function deleteCredentials(): boolean {
  let removed = false;
  if (existsSync(CREDENTIALS_PATH)) {
    try {
      unlinkSync(CREDENTIALS_PATH);
      removed = true;
    } catch {
      /* ignore */
    }
  }
  if (existsSync(LEGACY_CREDENTIALS_PATH)) {
    try {
      unlinkSync(LEGACY_CREDENTIALS_PATH);
      removed = true;
    } catch {
      /* ignore */
    }
  }
  return removed;
}

/**
 * Check if stored credentials have expired.
 */
export function isTokenExpired(creds: StoredCredentials): boolean {
  const expiry = new Date(creds.expiresAt);
  return expiry.getTime() <= Date.now();
}

/**
 * Get a human-readable tier display name.
 */
export function tierDisplayName(tier: Tier): string {
  const names: Record<Tier, string> = {
    free: 'Free',
    solo: 'Solo',
    pro: 'Pro',
    enterprise: 'Enterprise',
    starter: 'Starter', // legacy
    team: 'Pro', // legacy → Pro
    business: 'Pro', // legacy → Pro
  };
  return names[tier] ?? tier;
}
