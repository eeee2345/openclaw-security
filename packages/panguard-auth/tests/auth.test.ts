import { describe, it, expect } from 'vitest';
import {
  hashPassword,
  verifyPassword,
  generateSessionToken,
  generateVerifyToken,
  sessionExpiry,
} from '../src/auth.js';

describe('Auth utilities', () => {
  describe('hashPassword / verifyPassword', () => {
    it('should hash and verify a password', async () => {
      const hash = await hashPassword('mySecret123');
      expect(hash).toContain(':');
      expect(hash.split(':').length).toBe(2);

      const valid = await verifyPassword('mySecret123', hash);
      expect(valid).toBe(true);
    });

    it('should reject wrong password', async () => {
      const hash = await hashPassword('correct');
      const valid = await verifyPassword('wrong', hash);
      expect(valid).toBe(false);
    });

    it('should produce different hashes for same password (random salt)', async () => {
      const h1 = await hashPassword('same');
      const h2 = await hashPassword('same');
      expect(h1).not.toBe(h2);

      // Both should still verify
      expect(await verifyPassword('same', h1)).toBe(true);
      expect(await verifyPassword('same', h2)).toBe(true);
    });

    it('should return false for malformed hash', async () => {
      expect(await verifyPassword('test', 'nocolon')).toBe(false);
      expect(await verifyPassword('test', '')).toBe(false);
    });
  });

  describe('generateSessionToken', () => {
    it('should produce a 64-char hex string', () => {
      const token = generateSessionToken();
      expect(token).toMatch(/^[0-9a-f]{64}$/);
    });

    it('should be unique on each call', () => {
      const t1 = generateSessionToken();
      const t2 = generateSessionToken();
      expect(t1).not.toBe(t2);
    });
  });

  describe('generateVerifyToken', () => {
    it('should produce a valid UUID', () => {
      const token = generateVerifyToken();
      expect(token).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
      );
    });
  });

  describe('sessionExpiry', () => {
    it('should default to 24 hours from now', () => {
      const expiry = sessionExpiry();
      const expiryDate = new Date(expiry.replace(' ', 'T') + 'Z');
      const now = Date.now();
      const diff = expiryDate.getTime() - now;
      // Should be roughly 24 hours (with some tolerance)
      expect(diff).toBeGreaterThan(23 * 60 * 60 * 1000);
      expect(diff).toBeLessThan(25 * 60 * 60 * 1000);
    });

    it('should accept custom hours', () => {
      const expiry = sessionExpiry(1);
      const expiryDate = new Date(expiry.replace(' ', 'T') + 'Z');
      const now = Date.now();
      const diff = expiryDate.getTime() - now;
      expect(diff).toBeGreaterThan(0.9 * 60 * 60 * 1000);
      expect(diff).toBeLessThan(1.1 * 60 * 60 * 1000);
    });
  });
});
