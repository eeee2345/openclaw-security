import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('@/lib/sheets', () => ({
  appendToSheet: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('@/lib/rate-limit', () => ({
  checkRateLimit: vi.fn(() => true),
  getClientIP: vi.fn(() => '127.0.0.1'),
}));

import { POST } from '../../src/app/api/waitlist/route';
import { appendToSheet } from '@/lib/sheets';
import { checkRateLimit } from '@/lib/rate-limit';

function makeRequest(body: unknown) {
  return new Request('https://example.com/api/waitlist', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

describe('POST /api/waitlist', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(checkRateLimit).mockReturnValue(true);
  });

  it('returns 200 for valid email', async () => {
    const res = await POST(makeRequest({ email: 'test@example.com' }));
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.ok).toBe(true);
  });

  it('falls back to sheet storage', async () => {
    const res = await POST(makeRequest({ email: 'test@example.com' }));
    expect(res.status).toBe(200);
    expect(appendToSheet).toHaveBeenCalledWith(
      'waitlist',
      expect.arrayContaining(['test@example.com'])
    );
  });

  it('returns 400 for missing email', async () => {
    const res = await POST(makeRequest({ email: '' }));
    expect(res.status).toBe(400);
  });

  it('returns 400 for invalid email', async () => {
    const res = await POST(makeRequest({ email: 'not-an-email' }));
    expect(res.status).toBe(400);
  });

  it('returns 429 when rate limited', async () => {
    vi.mocked(checkRateLimit).mockReturnValue(false);
    const res = await POST(makeRequest({ email: 'test@example.com' }));
    expect(res.status).toBe(429);
  });

  it('returns 500 on server error', async () => {
    vi.mocked(appendToSheet).mockRejectedValueOnce(new Error('fail'));
    const res = await POST(makeRequest({ email: 'test@example.com' }));
    expect(res.status).toBe(500);
  });
});
