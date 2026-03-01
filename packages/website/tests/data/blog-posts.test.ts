import { describe, it, expect } from 'vitest';
import { blogPosts, categories } from '../../src/data/blog-posts';

describe('blog posts data', () => {
  it('exports a non-empty array', () => {
    expect(Array.isArray(blogPosts)).toBe(true);
    expect(blogPosts.length).toBeGreaterThan(0);
  });

  it('every post has required fields', () => {
    for (const post of blogPosts) {
      expect(post.slug).toBeTruthy();
      expect(post.title).toBeTruthy();
      expect(post.excerpt).toBeTruthy();
      expect(post.category).toBeTruthy();
      expect(post.date).toBeTruthy();
      expect(post.author).toBeTruthy();
      expect(post.readingTime).toBeTruthy();
    }
  });

  it('every category is in the categories list', () => {
    const validCategories = categories.filter((c) => c !== 'All');
    for (const post of blogPosts) {
      expect(validCategories).toContain(post.category);
    }
  });

  it('slugs are unique', () => {
    const slugs = blogPosts.map((p) => p.slug);
    expect(new Set(slugs).size).toBe(slugs.length);
  });

  it('categories includes All as first entry', () => {
    expect(categories[0]).toBe('All');
  });
});
