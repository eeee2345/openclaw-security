import { describe, it, expect, afterEach } from 'vitest';
import { RateLimiter } from '../src/rate-limiter.js';

describe('RateLimiter', () => {
  let limiter: RateLimiter;

  afterEach(() => {
    limiter?.destroy();
  });

  it('should allow requests under the limit', () => {
    limiter = new RateLimiter({ windowMs: 60000, maxRequests: 5 });
    const result = limiter.check('192.168.1.1');
    expect(result.allowed).toBe(true);
    expect(result.remaining).toBe(4);
    expect(result.retryAfterMs).toBe(0);
  });

  it('should count sequential requests', () => {
    limiter = new RateLimiter({ windowMs: 60000, maxRequests: 3 });
    expect(limiter.check('ip1').remaining).toBe(2);
    expect(limiter.check('ip1').remaining).toBe(1);
    expect(limiter.check('ip1').remaining).toBe(0);
  });

  it('should block after exceeding limit', () => {
    limiter = new RateLimiter({ windowMs: 60000, maxRequests: 2 });
    limiter.check('ip1');
    limiter.check('ip1');
    const result = limiter.check('ip1');
    expect(result.allowed).toBe(false);
    expect(result.remaining).toBe(0);
    expect(result.retryAfterMs).toBeGreaterThan(0);
  });

  it('should track different keys independently', () => {
    limiter = new RateLimiter({ windowMs: 60000, maxRequests: 1 });
    expect(limiter.check('ip1').allowed).toBe(true);
    expect(limiter.check('ip1').allowed).toBe(false);
    expect(limiter.check('ip2').allowed).toBe(true); // different key
    expect(limiter.check('ip2').allowed).toBe(false);
  });

  it('should reset after window expires', async () => {
    limiter = new RateLimiter({ windowMs: 50, maxRequests: 1 });
    expect(limiter.check('ip1').allowed).toBe(true);
    expect(limiter.check('ip1').allowed).toBe(false);

    await new Promise((r) => setTimeout(r, 60));

    expect(limiter.check('ip1').allowed).toBe(true);
  });

  it('should calculate retryAfterMs correctly', () => {
    limiter = new RateLimiter({ windowMs: 30000, maxRequests: 1 });
    limiter.check('ip1');
    const result = limiter.check('ip1');
    expect(result.retryAfterMs).toBeGreaterThan(0);
    expect(result.retryAfterMs).toBeLessThanOrEqual(30000);
  });

  it('should handle max=1 correctly', () => {
    limiter = new RateLimiter({ windowMs: 60000, maxRequests: 1 });
    const first = limiter.check('ip');
    expect(first.allowed).toBe(true);
    expect(first.remaining).toBe(0);

    const second = limiter.check('ip');
    expect(second.allowed).toBe(false);
  });

  it('should clean up after destroy', () => {
    limiter = new RateLimiter({ windowMs: 60000, maxRequests: 5 });
    limiter.check('ip1');
    limiter.check('ip2');
    limiter.destroy();
    // After destroy, new checks create fresh buckets
    const result = limiter.check('ip1');
    expect(result.allowed).toBe(true);
    expect(result.remaining).toBe(4);
  });
});
