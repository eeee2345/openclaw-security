import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('@/lib/sheets', () => ({
  appendToSheet: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('@/lib/rate-limit', () => ({
  checkRateLimit: vi.fn(() => true),
  getClientIP: vi.fn(() => '127.0.0.1'),
}));

import { POST } from '../../src/app/api/contact/route';
import { appendToSheet } from '@/lib/sheets';
import { checkRateLimit } from '@/lib/rate-limit';

function makeRequest(body: unknown) {
  return new Request('https://example.com/api/contact', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

const validBody = {
  name: 'Alice',
  email: 'alice@example.com',
  company: 'ACME',
  type: 'General',
  message: 'Hello there',
};

describe('POST /api/contact', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(checkRateLimit).mockReturnValue(true);
  });

  it('returns 200 for valid contact form', async () => {
    const res = await POST(makeRequest(validBody));
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.ok).toBe(true);
    expect(appendToSheet).toHaveBeenCalledOnce();
  });

  it('returns 400 for missing fields', async () => {
    const res = await POST(makeRequest({ email: 'bad' }));
    expect(res.status).toBe(400);
  });

  it('returns 400 for invalid email', async () => {
    const res = await POST(makeRequest({ ...validBody, email: 'not-an-email' }));
    expect(res.status).toBe(400);
  });

  it('returns 429 when rate limited', async () => {
    vi.mocked(checkRateLimit).mockReturnValue(false);
    const res = await POST(makeRequest(validBody));
    expect(res.status).toBe(429);
  });

  it('returns 500 on server error', async () => {
    vi.mocked(appendToSheet).mockRejectedValueOnce(new Error('DB down'));
    const res = await POST(makeRequest(validBody));
    expect(res.status).toBe(500);
  });

  it('escapes XSS in name field', async () => {
    const res = await POST(makeRequest({ ...validBody, name: '<script>alert(1)</script>' }));
    expect(res.status).toBe(200);
    const call = vi.mocked(appendToSheet).mock.calls[0];
    const savedName = call[1][1];
    expect(savedName).not.toContain('<script>');
  });
});
