/**
 * Shared helpers, types, and the RouteContext interface for route modules.
 * @module @panguard-ai/panguard-auth/routes/shared
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AuthDB } from '../database.js';
import type { EmailConfig } from '../email-verify.js';
import type { GoogleOAuthConfig } from '../google-oauth.js';
import type { GoogleSheetsConfig } from '../google-sheets.js';
import type { LemonSqueezyConfig } from '../lemonsqueezy.js';
import { RateLimiter } from '../rate-limiter.js';
import type { UserPublic } from '../types.js';

// ── Constants ────────────────────────────────────────────────────────

export const MAX_BODY_SIZE = 1024 * 1024; // 1 MB

// ── Body reading helpers ─────────────────────────────────────────────

export type ReadBodyResult =
  | { ok: true; data: Record<string, unknown> }
  | { ok: false; status: 400 | 413 };

export function readBody(req: IncomingMessage): Promise<ReadBodyResult> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let totalSize = 0;
    let aborted = false;

    req.on('data', (chunk: Buffer) => {
      totalSize += chunk.length;
      if (totalSize > MAX_BODY_SIZE) {
        aborted = true;
        req.destroy();
        resolve({ ok: false, status: 413 });
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (aborted) return;
      try {
        const raw = Buffer.concat(chunks).toString('utf-8');
        resolve({ ok: true, data: JSON.parse(raw) as Record<string, unknown> });
      } catch {
        resolve({ ok: false, status: 400 });
      }
    });
    req.on('error', () => {
      if (!aborted) resolve({ ok: false, status: 400 });
    });
  });
}

export type ReadRawBodyResult = { ok: true; raw: string } | { ok: false; status: 400 | 413 };

export function readRawBody(req: IncomingMessage): Promise<ReadRawBodyResult> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let totalSize = 0;
    let aborted = false;

    req.on('data', (chunk: Buffer) => {
      totalSize += chunk.length;
      if (totalSize > MAX_BODY_SIZE) {
        aborted = true;
        req.destroy();
        resolve({ ok: false, status: 413 });
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (aborted) return;
      resolve({ ok: true, raw: Buffer.concat(chunks).toString('utf-8') });
    });
    req.on('error', () => {
      if (!aborted) resolve({ ok: false, status: 400 });
    });
  });
}

// ── Response helper ──────────────────────────────────────────────────

export function json(res: ServerResponse, status: number, data: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

// ── IP helper ────────────────────────────────────────────────────────

export function getClientIP(req: IncomingMessage): string {
  if (process.env['TRUST_PROXY'] === '1') {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string') {
      const first = forwarded.split(',')[0]?.trim();
      if (first) return first;
    }
  }
  return req.socket.remoteAddress ?? '127.0.0.1';
}

// ── Validation helpers ───────────────────────────────────────────────

export function isValidEmail(email: unknown): email is string {
  if (typeof email !== 'string') return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ── User projection ──────────────────────────────────────────────────

export function toPublicUser(u: {
  id: number;
  email: string;
  name: string;
  role: string;
  tier: string;
  createdAt: string;
  planExpiresAt?: string | null;
}): UserPublic {
  return {
    id: u.id,
    email: u.email,
    name: u.name,
    role: u.role,
    tier: u.tier,
    createdAt: u.createdAt,
    planExpiresAt: u.planExpiresAt,
  };
}

// ── AuthRouteConfig ──────────────────────────────────────────────────

export interface AuthRouteConfig {
  db: AuthDB;
  smtp?: EmailConfig;
  baseUrl?: string;
  google?: GoogleOAuthConfig;
  sheets?: GoogleSheetsConfig;
  lemonsqueezy?: LemonSqueezyConfig;
}

// ── RouteContext ─────────────────────────────────────────────────────

export interface RouteContext {
  db: AuthDB;
  config: AuthRouteConfig;
  loginLimiter: RateLimiter;
  registerLimiter: RateLimiter;
  resetLimiter: RateLimiter;
  waitlistLimiter: RateLimiter;
  pendingOAuthFlows: Map<string, { codeVerifier: string; createdAt: number }>;
  pendingCliFlows: Map<string, { callbackUrl: string; createdAt: number }>;
  oauthExchangeCodes: Map<string, { sessionToken: string; expiresAt: string; createdAt: number }>;
}
