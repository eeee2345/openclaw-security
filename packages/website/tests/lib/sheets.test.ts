import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { promises as fs } from 'fs';

vi.mock('fs', () => {
  const fsMock = {
    mkdir: vi.fn().mockResolvedValue(undefined),
    readFile: vi.fn().mockRejectedValue(new Error('ENOENT')),
    writeFile: vi.fn().mockResolvedValue(undefined),
  };
  return { default: { promises: fsMock }, promises: fsMock };
});

describe('appendToSheet', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.unstubAllEnvs();
  });

  afterEach(() => {
    vi.resetModules();
  });

  it('sends to webhook when LEAD_WEBHOOK_URL is set', async () => {
    vi.stubEnv('LEAD_WEBHOOK_URL', 'https://hooks.example.com/test');
    const mockFetch = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', mockFetch);

    const { appendToSheet } = await import('../../src/lib/sheets');
    await appendToSheet('waitlist', ['2026-01-01', 'test@example.com']);

    expect(mockFetch).toHaveBeenCalledOnce();
    expect(mockFetch).toHaveBeenCalledWith(
      'https://hooks.example.com/test',
      expect.objectContaining({
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      })
    );

    vi.unstubAllGlobals();
  });

  it('writes to local file when no webhook URL', async () => {
    vi.stubEnv('LEAD_WEBHOOK_URL', '');

    const { appendToSheet } = await import('../../src/lib/sheets');
    await appendToSheet('contact', ['2026-01-01', 'Alice', 'alice@test.com']);

    expect(fs.mkdir).toHaveBeenCalled();
    expect(fs.writeFile).toHaveBeenCalled();
  });

  it('includes all row data in written file', async () => {
    vi.stubEnv('LEAD_WEBHOOK_URL', '');

    const { appendToSheet } = await import('../../src/lib/sheets');
    const row = ['2026-01-01', 'Bob', 'bob@test.com'];
    await appendToSheet('demo', row);

    const writeCall = vi.mocked(fs.writeFile).mock.calls[0];
    const written = JSON.parse(writeCall[1] as string);
    expect(written).toEqual([row]);
  });
});
