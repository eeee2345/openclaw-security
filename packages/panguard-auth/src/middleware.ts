/**
 * Authentication middleware for raw node:http server.
 * Validates Bearer token from Authorization header.
 * @module @openclaw/panguard-auth/middleware
 */

import type { IncomingMessage } from 'node:http';
import type { AuthDB } from './database.js';
import type { User } from './types.js';

/**
 * Extract Bearer token from Authorization header.
 */
export function extractToken(req: IncomingMessage): string | null {
  const auth = req.headers.authorization;
  if (!auth) return null;
  const parts = auth.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return null;
  return parts[1] ?? null;
}

/**
 * Authenticate a request using session token.
 * Returns the user if valid, null otherwise.
 */
export function authenticateRequest(req: IncomingMessage, db: AuthDB): User | null {
  const token = extractToken(req);
  if (!token) return null;

  const session = db.getSession(token);
  if (!session) return null;

  return session.user;
}

/**
 * Check if the authenticated user has admin role.
 */
export function requireAdmin(user: User | null): boolean {
  return user?.role === 'admin';
}
