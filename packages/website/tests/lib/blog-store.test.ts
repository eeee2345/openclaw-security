import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('fs', () => {
  const fsMock = {
    mkdir: vi.fn().mockResolvedValue(undefined),
    readFile: vi.fn().mockRejectedValue(new Error('ENOENT')),
    writeFile: vi.fn().mockResolvedValue(undefined),
  };
  return { default: { promises: fsMock }, promises: fsMock };
});

describe('blog-store', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.resetModules();
  });

  it('getAllPosts returns static posts when no JSON file', async () => {
    const { getAllPosts } = await import('../../src/lib/blog-store');
    const posts = await getAllPosts();
    expect(posts.length).toBeGreaterThan(0);
    // Posts should be sorted by date descending
    for (let i = 1; i < posts.length; i++) {
      expect(posts[i - 1].date >= posts[i].date).toBe(true);
    }
  });

  it('isStaticPost returns true for known slugs', async () => {
    const { isStaticPost } = await import('../../src/lib/blog-store');
    expect(isStaticPost('why-99-percent-businesses-have-zero-security')).toBe(true);
    expect(isStaticPost('nonexistent-slug')).toBe(false);
  });

  it('savePost writes to JSON file', async () => {
    const { promises: fs } = await import('fs');
    const { savePost } = await import('../../src/lib/blog-store');

    const post = {
      slug: 'test-post',
      title: 'Test',
      excerpt: 'Test excerpt',
      category: 'Engineering',
      date: '2026-01-01',
      author: 'Test',
      readingTime: '3 min',
    };

    await savePost(post);
    expect(fs.writeFile).toHaveBeenCalled();
  });
});
