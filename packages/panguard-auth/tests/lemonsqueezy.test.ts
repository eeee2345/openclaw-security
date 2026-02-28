import { describe, it, expect } from 'vitest';
import { createHmac } from 'node:crypto';
import { verifyWebhookSignature } from '../src/lemonsqueezy.js';

describe('Lemon Squeezy', () => {
  describe('verifyWebhookSignature', () => {
    const secret = 'test-webhook-secret-123';

    function sign(body: string, signingSecret: string): string {
      return createHmac('sha256', signingSecret).update(body).digest('hex');
    }

    it('should verify a valid signature', () => {
      const body = '{"test": true}';
      const signature = sign(body, secret);
      expect(verifyWebhookSignature(body, signature, secret)).toBe(true);
    });

    it('should reject tampered body', () => {
      const body = '{"test": true}';
      const signature = sign(body, secret);
      expect(verifyWebhookSignature('{"test": false}', signature, secret)).toBe(false);
    });

    it('should reject wrong secret', () => {
      const body = '{"test": true}';
      const signature = sign(body, 'wrong-secret');
      expect(verifyWebhookSignature(body, signature, secret)).toBe(false);
    });

    it('should reject empty signature', () => {
      expect(verifyWebhookSignature('body', '', secret)).toBe(false);
    });

    it('should reject empty body', () => {
      expect(verifyWebhookSignature('', 'sig', secret)).toBe(false);
    });

    it('should reject empty secret', () => {
      expect(verifyWebhookSignature('body', 'sig', '')).toBe(false);
    });

    it('should handle non-hex signatures gracefully', () => {
      expect(verifyWebhookSignature('body', 'not-hex-at-all!!!', secret)).toBe(false);
    });

    it('should handle large payloads', () => {
      const largeBody = JSON.stringify({ data: 'x'.repeat(100000) });
      const signature = sign(largeBody, secret);
      expect(verifyWebhookSignature(largeBody, signature, secret)).toBe(true);
    });

    it('should be timing-safe (uses timingSafeEqual)', () => {
      // We can't directly test timing safety, but we verify it works
      // with valid and invalid signatures of the same length
      const body = '{"event": "subscription_created"}';
      const validSig = sign(body, secret);
      // Create a signature that's same length but different
      const fakeSig = validSig.replace(/./g, (c) => (c === 'a' ? 'b' : 'a'));
      expect(validSig.length).toBe(fakeSig.length);
      expect(verifyWebhookSignature(body, fakeSig, secret)).toBe(false);
    });
  });
});
