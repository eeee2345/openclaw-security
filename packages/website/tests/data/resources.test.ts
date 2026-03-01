import { describe, it, expect } from 'vitest';
import { resources, resourceTypes, type Resource } from '../../src/data/resources';

describe('resources data', () => {
  it('exports a non-empty array', () => {
    expect(Array.isArray(resources)).toBe(true);
    expect(resources.length).toBeGreaterThan(0);
  });

  it('every resource has required fields', () => {
    for (const r of resources) {
      expect(r.slug).toBeTruthy();
      expect(r.title).toBeTruthy();
      expect(r.type).toBeTruthy();
      expect(r.description).toBeTruthy();
      expect(r.date).toBeTruthy();
    }
  });

  it('every resource type is in resourceTypes', () => {
    const validTypes = resourceTypes.filter((t) => t !== 'All');
    for (const r of resources) {
      expect(validTypes).toContain(r.type);
    }
  });

  it('slugs are unique', () => {
    const slugs = resources.map((r) => r.slug);
    expect(new Set(slugs).size).toBe(slugs.length);
  });

  it('resourceTypes includes All as first entry', () => {
    expect(resourceTypes[0]).toBe('All');
  });
});
