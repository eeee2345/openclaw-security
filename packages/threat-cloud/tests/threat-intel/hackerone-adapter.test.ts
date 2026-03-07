/**
 * HackerOne Adapter Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { HackerOneAdapter } from '../../src/threat-intel/hackerone-adapter.js';
import type { HackerOneHacktivityResponse } from '../../src/threat-intel/types.js';

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

function makeResponse(overrides: Record<string, unknown> = {}): HackerOneHacktivityResponse {
  return {
    data: [
      {
        id: 2701701,
        type: 'hacktivity_item',
        attributes: {
          title: 'Injection in path parameter of Ingress-nginx',
          substate: 'resolved',
          url: 'https://hackerone.com/reports/2701701',
          disclosed_at: '2026-03-07T05:10:30.190Z',
          vulnerability_information: null,
          cve_ids: ['CVE-2021-25748'],
          cwe: 'Code Injection',
          severity_rating: 'High',
          votes: 7,
          total_awarded_amount: null,
          latest_disclosable_action: 'Activities::ReportBecamePublic',
          latest_disclosable_activity_at: '2026-03-07T05:10:31.254Z',
          submitted_at: '2024-09-05T15:29:42.557Z',
          disclosed: true,
          ...overrides,
        },
        relationships: {
          report_generated_content: {
            data: {
              type: 'report_generated_content',
              attributes: {
                hacktivity_summary: 'A vulnerability was discovered in the Ingress-nginx controller.',
              },
            },
          },
          reporter: {
            data: {
              type: 'user',
              attributes: { name: 'Test User', username: 'testuser' },
            },
          },
          program: {
            data: {
              type: 'program',
              attributes: { handle: 'kubernetes', name: 'Kubernetes' },
            },
          },
        },
      },
    ],
    links: { self: 'https://api.hackerone.com/v1/hackers/hacktivity' },
  };
}

describe('HackerOneAdapter', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it('fetches and converts disclosed reports', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => makeResponse(),
    });

    const adapter = new HackerOneAdapter({ rateLimitPerMinute: 600 });
    const reports = await adapter.fetchReports();

    expect(reports).toHaveLength(1);
    expect(reports[0].id).toBe('2701701');
    expect(reports[0].title).toBe('Injection in path parameter of Ingress-nginx');
    expect(reports[0].severity).toBe('high');
    expect(reports[0].cweId).toBe('CWE-94');
    expect(reports[0].cweName).toBe('Code Injection');
    expect(reports[0].cveIds).toEqual(['CVE-2021-25748']);
    expect(reports[0].summary).toContain('Ingress-nginx');
    expect(reports[0].programHandle).toBe('kubernetes');
    expect(reports[0].programName).toBe('Kubernetes');
    expect(reports[0].reporterUsername).toBe('testuser');
    expect(reports[0].url).toBe('https://hackerone.com/reports/2701701');
  });

  it('filters by minimum severity', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => makeResponse({ severity_rating: 'Low' }),
    });

    const adapter = new HackerOneAdapter({
      minSeverity: 'medium',
      rateLimitPerMinute: 600,
    });
    const reports = await adapter.fetchReports();

    expect(reports).toHaveLength(0);
  });

  it('accepts reports meeting minimum severity', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => makeResponse({ severity_rating: 'Critical' }),
    });

    const adapter = new HackerOneAdapter({
      minSeverity: 'high',
      rateLimitPerMinute: 600,
    });
    const reports = await adapter.fetchReports();

    expect(reports).toHaveLength(1);
  });

  it('skips non-disclosed reports', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => makeResponse({ disclosed: false }),
    });

    const adapter = new HackerOneAdapter({ rateLimitPerMinute: 600 });
    const reports = await adapter.fetchReports();

    expect(reports).toHaveLength(0);
  });

  it('skips reports without title', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => makeResponse({ title: null }),
    });

    const adapter = new HackerOneAdapter({ rateLimitPerMinute: 600 });
    const reports = await adapter.fetchReports();

    expect(reports).toHaveLength(0);
  });

  it('handles pagination with next link', async () => {
    const page1: HackerOneHacktivityResponse = {
      ...makeResponse(),
      links: {
        self: 'https://api.hackerone.com/v1/hackers/hacktivity?page=1',
        next: 'https://api.hackerone.com/v1/hackers/hacktivity?page=2',
      },
    };
    const page2 = makeResponse({ title: 'XSS in search' });

    mockFetch
      .mockResolvedValueOnce({ ok: true, json: async () => page1 })
      .mockResolvedValueOnce({ ok: true, json: async () => page2 });

    const adapter = new HackerOneAdapter({
      maxReports: 50,
      rateLimitPerMinute: 600,
    });
    const reports = await adapter.fetchReports();

    expect(reports).toHaveLength(2);
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it('stops on rate limit (429)', async () => {
    const page1: HackerOneHacktivityResponse = {
      ...makeResponse(),
      links: {
        self: 'https://api.hackerone.com/v1/hackers/hacktivity?page=1',
        next: 'https://api.hackerone.com/v1/hackers/hacktivity?page=2',
      },
    };

    mockFetch
      .mockResolvedValueOnce({ ok: true, json: async () => page1 })
      .mockResolvedValueOnce({ ok: false, status: 429, statusText: 'Too Many Requests' });

    const adapter = new HackerOneAdapter({ rateLimitPerMinute: 600 });
    const reports = await adapter.fetchReports();

    expect(reports).toHaveLength(1);
  });

  it('supports incremental sync with since parameter', async () => {
    // Report disclosed before `since` should be skipped
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => makeResponse({ disclosed_at: '2026-01-01T00:00:00Z' }),
    });

    const adapter = new HackerOneAdapter({ rateLimitPerMinute: 600 });
    const reports = await adapter.fetchReports('2026-03-01T00:00:00Z');

    expect(reports).toHaveLength(0);
  });

  it('includes reports after since date', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => makeResponse({ disclosed_at: '2026-03-07T00:00:00Z' }),
    });

    const adapter = new HackerOneAdapter({ rateLimitPerMinute: 600 });
    const reports = await adapter.fetchReports('2026-03-01T00:00:00Z');

    expect(reports).toHaveLength(1);
  });

  it('handles API errors', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
      statusText: 'Internal Server Error',
    });

    const adapter = new HackerOneAdapter({ rateLimitPerMinute: 600 });

    await expect(adapter.fetchReports()).rejects.toThrow('HackerOne API error: 500');
  });

  it('handles missing CWE', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => makeResponse({ cwe: null }),
    });

    const adapter = new HackerOneAdapter({ rateLimitPerMinute: 600 });
    const reports = await adapter.fetchReports();

    expect(reports[0].cweId).toBeNull();
    expect(reports[0].cweName).toBeNull();
  });

  it('resolves CWE name to ID', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => makeResponse({ cwe: 'Cross-Site Scripting (XSS)' }),
    });

    const adapter = new HackerOneAdapter({ rateLimitPerMinute: 600 });
    const reports = await adapter.fetchReports();

    expect(reports[0].cweId).toBe('CWE-79');
    expect(reports[0].cweName).toBe('Cross-Site Scripting (XSS)');
  });

  it('sets User-Agent header', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => makeResponse(),
    });

    const adapter = new HackerOneAdapter({ rateLimitPerMinute: 600 });
    await adapter.fetchReports();

    const fetchOpts = mockFetch.mock.calls[0][1] as RequestInit;
    expect((fetchOpts.headers as Record<string, string>)['User-Agent']).toContain('Panguard');
  });

  it('respects maxReports limit', async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      json: async () => ({
        ...makeResponse(),
        links: { next: 'https://api.hackerone.com/v1/hackers/hacktivity?page=2' },
      }),
    });

    const adapter = new HackerOneAdapter({
      maxReports: 1,
      rateLimitPerMinute: 600,
    });
    const reports = await adapter.fetchReports();

    expect(reports).toHaveLength(1);
  });
});
