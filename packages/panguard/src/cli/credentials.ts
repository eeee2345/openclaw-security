/**
 * Local credential store for CLI authentication.
 * Stores session token at ~/.panguard/credentials.json with 0600 permissions.
 *
 * @module @openclaw/panguard/cli/credentials
 */

import { existsSync, readFileSync, writeFileSync, unlinkSync, mkdirSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

export const CREDENTIALS_DIR = join(homedir(), '.panguard');
export const CREDENTIALS_PATH = join(CREDENTIALS_DIR, 'credentials.json');

export type Tier = 'free' | 'solo' | 'starter' | 'team' | 'business' | 'enterprise';

export const TIER_LEVEL: Record<Tier, number> = {
  free: 0,
  solo: 1,
  starter: 2,
  team: 3,
  business: 4,
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
 * Save credentials to disk with secure permissions.
 */
export function saveCredentials(creds: StoredCredentials): void {
  if (!existsSync(CREDENTIALS_DIR)) {
    mkdirSync(CREDENTIALS_DIR, { recursive: true });
  }
  const json = JSON.stringify(creds, null, 2);
  writeFileSync(CREDENTIALS_PATH, json, { encoding: 'utf-8', mode: 0o600 });
  // Ensure permissions even if file existed before
  try { chmodSync(CREDENTIALS_PATH, 0o600); } catch { /* best-effort */ }
}

/**
 * Load credentials from disk. Returns null if not found or invalid.
 */
export function loadCredentials(): StoredCredentials | null {
  if (!existsSync(CREDENTIALS_PATH)) return null;
  try {
    const json = readFileSync(CREDENTIALS_PATH, 'utf-8');
    const data = JSON.parse(json) as StoredCredentials;
    if (!data.token || !data.expiresAt || !data.email) return null;
    return data;
  } catch {
    return null;
  }
}

/**
 * Delete stored credentials. Returns true if file was removed.
 */
export function deleteCredentials(): boolean {
  if (!existsSync(CREDENTIALS_PATH)) return false;
  try {
    unlinkSync(CREDENTIALS_PATH);
    return true;
  } catch {
    return false;
  }
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
    free: 'Scan (Free)',
    solo: 'Solo',
    starter: 'Starter',
    team: 'Team',
    business: 'Business',
    enterprise: 'Enterprise',
  };
  return names[tier] ?? tier;
}
