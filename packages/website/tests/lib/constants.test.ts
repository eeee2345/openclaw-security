import { describe, it, expect } from 'vitest';
import { LEGAL_LAST_UPDATED, GITHUB_URL } from '../../src/lib/constants';

describe('constants', () => {
  it('exports LEGAL_LAST_UPDATED as a non-empty string', () => {
    expect(typeof LEGAL_LAST_UPDATED).toBe('string');
    expect(LEGAL_LAST_UPDATED.length).toBeGreaterThan(0);
  });

  it('exports GITHUB_URL as a valid GitHub URL', () => {
    expect(GITHUB_URL).toMatch(/^https:\/\/github\.com\//);
  });
});
