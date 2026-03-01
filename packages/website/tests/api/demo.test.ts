import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('@/lib/sheets', () => ({
  appendToSheet: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('@/lib/rate-limit', () => ({
  checkRateLimit: vi.fn(() => true),
  getClientIP: vi.fn(() => '127.0.0.1'),
}));

import { POST } from '../../src/app/api/demo/route';
import { appendToSheet } from '@/lib/sheets';
import { checkRateLimit } from '@/lib/rate-limit';

function makeRequest(body: unknown) {
  return new Request('https://example.com/api/demo', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

const validBody = {
  name: 'Bob',
  email: 'bob@corp.io',
  company: 'Corp Inc',
  teamSize: '11-50',
  stack: 'Node, React',
  message: 'Interested',
};

describe('POST /api/demo', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(checkRateLimit).mockReturnValue(true);
  });

  it('returns 200 for valid demo form', async () => {
    const res = await POST(makeRequest(validBody));
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.ok).toBe(true);
    expect(appendToSheet).toHaveBeenCalledOnce();
  });

  it('returns 400 for missing company', async () => {
    const res = await POST(makeRequest({ ...validBody, company: '' }));
    expect(res.status).toBe(400);
  });

  it('returns 400 for invalid email', async () => {
    const res = await POST(makeRequest({ ...validBody, email: 'bad' }));
    expect(res.status).toBe(400);
  });

  it('returns 429 when rate limited', async () => {
    vi.mocked(checkRateLimit).mockReturnValue(false);
    const res = await POST(makeRequest(validBody));
    expect(res.status).toBe(429);
  });

  it('returns 500 on server error', async () => {
    vi.mocked(appendToSheet).mockRejectedValueOnce(new Error('fail'));
    const res = await POST(makeRequest(validBody));
    expect(res.status).toBe(500);
  });

  it('allows empty optional fields', async () => {
    const res = await POST(makeRequest({ ...validBody, teamSize: '', stack: '', message: '' }));
    expect(res.status).toBe(200);
  });
});
