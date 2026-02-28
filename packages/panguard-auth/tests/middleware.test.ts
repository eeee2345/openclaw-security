import { describe, it, expect } from 'vitest';
import { extractToken, requireAdmin } from '../src/middleware.js';
import type { IncomingMessage } from 'node:http';
import type { User } from '../src/types.js';

function mockRequest(headers: Record<string, string> = {}): IncomingMessage {
  return { headers } as unknown as IncomingMessage;
}

describe('Middleware', () => {
  describe('extractToken', () => {
    it('should extract Bearer token', () => {
      const req = mockRequest({ authorization: 'Bearer abc123' });
      expect(extractToken(req)).toBe('abc123');
    });

    it('should return null for missing header', () => {
      const req = mockRequest({});
      expect(extractToken(req)).toBeNull();
    });

    it('should return null for non-Bearer scheme', () => {
      const req = mockRequest({ authorization: 'Basic abc123' });
      expect(extractToken(req)).toBeNull();
    });

    it('should return null for malformed header', () => {
      const req = mockRequest({ authorization: 'Bearer' });
      expect(extractToken(req)).toBeNull();
    });

    it('should return null for too many parts', () => {
      const req = mockRequest({ authorization: 'Bearer token extra' });
      expect(extractToken(req)).toBeNull();
    });

    it('should handle token with special characters', () => {
      const req = mockRequest({ authorization: 'Bearer a1b2c3-d4e5f6_g7h8' });
      expect(extractToken(req)).toBe('a1b2c3-d4e5f6_g7h8');
    });
  });

  describe('requireAdmin', () => {
    it('should return true for admin user', () => {
      const user = { role: 'admin' } as User;
      expect(requireAdmin(user)).toBe(true);
    });

    it('should return false for regular user', () => {
      const user = { role: 'user' } as User;
      expect(requireAdmin(user)).toBe(false);
    });

    it('should return false for null', () => {
      expect(requireAdmin(null)).toBe(false);
    });
  });
});
