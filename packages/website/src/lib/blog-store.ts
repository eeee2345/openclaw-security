import { promises as fs } from 'fs';
import path from 'path';
import { blogPosts as staticPosts } from '@/data/blog-posts';
import type { BlogPost } from '@/data/blog-posts';

const JSON_PATH = path.join(process.cwd(), 'data', 'blog-posts.json');

async function readJsonPosts(): Promise<BlogPost[]> {
  try {
    const raw = await fs.readFile(JSON_PATH, 'utf-8');
    return JSON.parse(raw) as BlogPost[];
  } catch {
    return [];
  }
}

async function writeJsonPosts(posts: BlogPost[]): Promise<void> {
  const dir = path.dirname(JSON_PATH);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(JSON_PATH, JSON.stringify(posts, null, 2), 'utf-8');
}

/** Get only dynamically-created posts from JSON */
export async function getJsonPosts(): Promise<BlogPost[]> {
  return readJsonPosts();
}

/** Get all posts: static TS + dynamic JSON, sorted by date descending */
export async function getAllPosts(): Promise<BlogPost[]> {
  const jsonPosts = await readJsonPosts();
  const staticSlugs = new Set(staticPosts.map((p) => p.slug));

  // JSON posts override static posts with the same slug
  const merged = [
    ...jsonPosts,
    ...staticPosts.filter((p) => !jsonPosts.some((jp) => jp.slug === p.slug)),
  ];

  return merged.sort((a, b) => b.date.localeCompare(a.date));
}

/** Save or update a post in JSON storage */
export async function savePost(post: BlogPost): Promise<void> {
  const posts = await readJsonPosts();
  const idx = posts.findIndex((p) => p.slug === post.slug);
  if (idx >= 0) {
    posts[idx] = post;
  } else {
    posts.push(post);
  }
  await writeJsonPosts(posts);
}

/** Delete a post from JSON storage (cannot delete static posts) */
export async function deletePost(slug: string): Promise<boolean> {
  const posts = await readJsonPosts();
  const filtered = posts.filter((p) => p.slug !== slug);
  if (filtered.length === posts.length) return false;
  await writeJsonPosts(filtered);
  return true;
}

/** Check if a slug belongs to a static (hardcoded) post */
export function isStaticPost(slug: string): boolean {
  return staticPosts.some((p) => p.slug === slug);
}
