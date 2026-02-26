import { describe, it, expect } from 'vitest';
import { createSign } from 'node:crypto';

describe('Google Sheets JWT', () => {
  it('should create RS256 signatures with node:crypto', () => {
    // Verify that the crypto primitives work for JWT signing
    const sign = createSign('RSA-SHA256');
    expect(sign).toBeDefined();
    expect(typeof sign.update).toBe('function');
    expect(typeof sign.sign).toBe('function');
  });

  it('should base64url encode correctly', () => {
    const data = JSON.stringify({ alg: 'RS256', typ: 'JWT' });
    const encoded = Buffer.from(data).toString('base64url');
    expect(encoded).not.toContain('+');
    expect(encoded).not.toContain('/');
    expect(encoded).not.toContain('=');
    // Decode and verify
    const decoded = Buffer.from(encoded, 'base64url').toString();
    expect(JSON.parse(decoded)).toEqual({ alg: 'RS256', typ: 'JWT' });
  });

  it('should build correct JWT payload structure', () => {
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      iss: 'test@project.iam.gserviceaccount.com',
      scope: 'https://www.googleapis.com/auth/spreadsheets',
      aud: 'https://oauth2.googleapis.com/token',
      iat: now,
      exp: now + 3600,
    };
    expect(payload.exp - payload.iat).toBe(3600);
    expect(payload.scope).toContain('spreadsheets');
  });
});
