/**
 * Manager utility functions
 * Manager 工具函式
 *
 * @module @panguard-ai/manager/utils
 */

import { randomBytes } from 'node:crypto';

/**
 * Generate a unique agent ID with a 'ag-' prefix.
 *
 * @returns A unique identifier string (e.g., 'ag-a1b2c3d4e5f6')
 */
export function generateAgentId(): string {
  return `ag-${randomBytes(6).toString('hex')}`;
}

/**
 * Generate a unique threat ID with a 'th-' prefix.
 *
 * @returns A unique identifier string (e.g., 'th-a1b2c3d4e5f6')
 */
export function generateThreatId(): string {
  return `th-${randomBytes(6).toString('hex')}`;
}

/**
 * Generate a unique policy ID with a 'pol-' prefix.
 *
 * @returns A unique identifier string (e.g., 'pol-a1b2c3d4')
 */
export function generatePolicyId(): string {
  return `pol-${randomBytes(4).toString('hex')}`;
}

/**
 * Generate a secure authentication token.
 *
 * @returns A 32-byte hex token string
 */
export function generateAuthToken(): string {
  return randomBytes(32).toString('hex');
}

/**
 * Extract source IP from a SecurityEvent's metadata.
 * Looks for common field names used across different event sources.
 *
 * @param metadata - The event metadata record
 * @returns The source IP string, or undefined if not found
 */
export function extractSourceIP(
  metadata: Record<string, unknown>
): string | undefined {
  const candidates = [
    'sourceIP',
    'remoteAddress',
    'src_ip',
    'source_ip',
    'attacker_ip',
    'client_ip',
  ];

  for (const key of candidates) {
    const value = metadata[key];
    if (typeof value === 'string' && value.length > 0) {
      return value;
    }
  }

  return undefined;
}

/**
 * Extract a file hash from a SecurityEvent's metadata.
 *
 * @param metadata - The event metadata record
 * @returns The hash string, or undefined if not found
 */
export function extractFileHash(
  metadata: Record<string, unknown>
): string | undefined {
  const candidates = [
    'sha256',
    'sha1',
    'md5',
    'fileHash',
    'hash',
    'malwareHash',
  ];

  for (const key of candidates) {
    const value = metadata[key];
    if (typeof value === 'string' && value.length > 0) {
      return value;
    }
  }

  return undefined;
}
