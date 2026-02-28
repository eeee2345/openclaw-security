import { describe, it, expect } from 'vitest';
import {
  base32Encode,
  base32Decode,
  generateTotpSecret,
  generateBackupCodes,
  generateTotp,
  verifyTotp,
  buildOtpauthUri,
} from '../src/totp.js';

describe('TOTP', () => {
  describe('base32Encode / base32Decode', () => {
    it('should round-trip encode and decode', () => {
      const original = Buffer.from('Hello, World!');
      const encoded = base32Encode(original);
      const decoded = base32Decode(encoded);
      expect(decoded.toString()).toBe('Hello, World!');
    });

    it('should encode known values correctly', () => {
      // RFC 4648 test vectors
      expect(base32Encode(Buffer.from(''))).toBe('');
      expect(base32Encode(Buffer.from('f'))).toBe('MY');
      expect(base32Encode(Buffer.from('fo'))).toBe('MZXQ');
      expect(base32Encode(Buffer.from('foo'))).toBe('MZXW6');
      expect(base32Encode(Buffer.from('foob'))).toBe('MZXW6YQ');
      expect(base32Encode(Buffer.from('fooba'))).toBe('MZXW6YTB');
      expect(base32Encode(Buffer.from('foobar'))).toBe('MZXW6YTBOI');
    });

    it('should decode with padding and spaces', () => {
      const decoded = base32Decode('MZXW6=== ');
      expect(decoded.toString()).toBe('foo');
    });

    it('should handle 20-byte secrets', () => {
      const secret = Buffer.alloc(20, 0xab);
      const encoded = base32Encode(secret);
      const decoded = base32Decode(encoded);
      expect(Buffer.compare(decoded, secret)).toBe(0);
    });
  });

  describe('generateTotpSecret', () => {
    it('should return a base32 string', () => {
      const secret = generateTotpSecret();
      expect(typeof secret).toBe('string');
      expect(secret.length).toBeGreaterThan(0);
      // Should only contain valid base32 chars
      expect(/^[A-Z2-7]+$/.test(secret)).toBe(true);
    });

    it('should produce unique secrets', () => {
      const a = generateTotpSecret();
      const b = generateTotpSecret();
      expect(a).not.toBe(b);
    });

    it('should decode to 20 bytes', () => {
      const secret = generateTotpSecret();
      const decoded = base32Decode(secret);
      expect(decoded.length).toBe(20);
    });
  });

  describe('generateBackupCodes', () => {
    it('should generate 10 codes by default', () => {
      const codes = generateBackupCodes();
      expect(codes).toHaveLength(10);
    });

    it('should generate requested number of codes', () => {
      const codes = generateBackupCodes(5);
      expect(codes).toHaveLength(5);
    });

    it('should produce 8 hex character codes', () => {
      const codes = generateBackupCodes();
      for (const code of codes) {
        expect(code).toMatch(/^[0-9a-f]{8}$/);
      }
    });

    it('should produce unique codes', () => {
      const codes = generateBackupCodes(100);
      const unique = new Set(codes);
      // With 100 random 4-byte codes, collisions are astronomically unlikely
      expect(unique.size).toBe(100);
    });
  });

  describe('generateTotp', () => {
    it('should produce a 6-digit string', () => {
      const secret = generateTotpSecret();
      const code = generateTotp(secret, 1000000);
      expect(code).toMatch(/^\d{6}$/);
    });

    it('should produce consistent codes for the same time step', () => {
      const secret = generateTotpSecret();
      const a = generateTotp(secret, 12345);
      const b = generateTotp(secret, 12345);
      expect(a).toBe(b);
    });

    it('should produce different codes for different time steps', () => {
      const secret = generateTotpSecret();
      const a = generateTotp(secret, 12345);
      const b = generateTotp(secret, 12346);
      expect(a).not.toBe(b);
    });

    it('should produce different codes for different secrets', () => {
      const a = generateTotp(generateTotpSecret(), 12345);
      const b = generateTotp(generateTotpSecret(), 12345);
      // Extremely unlikely to be equal with different random secrets
      expect(a).not.toBe(b);
    });

    // RFC 6238 test vector (SHA1, 8 digits would be 94287082 at step 1, but we use 6 digits)
    it('should handle time step 0', () => {
      const secret = generateTotpSecret();
      const code = generateTotp(secret, 0);
      expect(code).toMatch(/^\d{6}$/);
    });
  });

  describe('verifyTotp', () => {
    it('should verify a valid code for the current time step', () => {
      const secret = generateTotpSecret();
      const currentStep = Math.floor(Date.now() / 1000 / 30);
      const code = generateTotp(secret, currentStep);
      expect(verifyTotp(secret, code)).toBe(true);
    });

    it('should allow 1 step drift (previous step)', () => {
      const secret = generateTotpSecret();
      const currentStep = Math.floor(Date.now() / 1000 / 30);
      const code = generateTotp(secret, currentStep - 1);
      expect(verifyTotp(secret, code)).toBe(true);
    });

    it('should allow 1 step drift (next step)', () => {
      const secret = generateTotpSecret();
      const currentStep = Math.floor(Date.now() / 1000 / 30);
      const code = generateTotp(secret, currentStep + 1);
      expect(verifyTotp(secret, code)).toBe(true);
    });

    it('should reject code from 2 steps ago', () => {
      const secret = generateTotpSecret();
      const currentStep = Math.floor(Date.now() / 1000 / 30);
      const code = generateTotp(secret, currentStep - 2);
      expect(verifyTotp(secret, code)).toBe(false);
    });

    it('should reject invalid format', () => {
      const secret = generateTotpSecret();
      expect(verifyTotp(secret, '12345')).toBe(false); // 5 digits
      expect(verifyTotp(secret, '1234567')).toBe(false); // 7 digits
      expect(verifyTotp(secret, 'abcdef')).toBe(false); // non-numeric
      expect(verifyTotp(secret, '')).toBe(false);
    });

    it('should reject wrong code', () => {
      const secret = generateTotpSecret();
      // Generate valid code, then modify it
      const currentStep = Math.floor(Date.now() / 1000 / 30);
      const code = generateTotp(secret, currentStep);
      const wrongCode = String((parseInt(code, 10) + 1) % 1000000).padStart(6, '0');
      expect(verifyTotp(secret, wrongCode)).toBe(false);
    });
  });

  describe('buildOtpauthUri', () => {
    it('should build a valid otpauth URI', () => {
      const secret = 'JBSWY3DPEHPK3PXP';
      const uri = buildOtpauthUri(secret, 'user@example.com');
      expect(uri).toContain('otpauth://totp/');
      expect(uri).toContain('secret=JBSWY3DPEHPK3PXP');
      expect(uri).toContain('issuer=Panguard%20AI');
      expect(uri).toContain('algorithm=SHA1');
      expect(uri).toContain('digits=6');
      expect(uri).toContain('period=30');
      expect(uri).toContain('user%40example.com');
    });

    it('should use custom issuer', () => {
      const uri = buildOtpauthUri('SECRET', 'a@b.com', 'My App');
      expect(uri).toContain('issuer=My%20App');
      expect(uri).toContain('My%20App:a%40b.com');
    });

    it('should encode special characters in email', () => {
      const uri = buildOtpauthUri('SECRET', 'test+tag@example.com');
      expect(uri).toContain('test%2Btag%40example.com');
    });
  });
});
