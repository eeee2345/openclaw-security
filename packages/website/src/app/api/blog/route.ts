import { NextResponse } from 'next/server';
import { getJsonPosts, savePost } from '@/lib/blog-store';
import type { BlogPost } from '@/data/blog-posts';

const AUTH_API = process.env.NEXT_PUBLIC_API_URL || 'https://panguard-api-production.up.railway.app';

async function verifyAdmin(req: Request): Promise<boolean> {
  const authHeader = req.headers.get('authorization');
  if (!authHeader?.startsWith('Bearer ')) return false;

  if (!AUTH_API) return false;

  try {
    const res = await fetch(`${AUTH_API}/api/auth/me`, {
      headers: { Authorization: authHeader },
    });
    if (!res.ok) return false;
    const data = (await res.json()) as { ok: boolean; data?: { user: { role: string } } };
    return data.ok && data.data?.user?.role === 'admin';
  } catch {
    return false;
  }
}

export async function GET() {
  try {
    const posts = await getJsonPosts();
    return NextResponse.json({ ok: true, data: posts });
  } catch {
    return NextResponse.json({ error: 'Failed to read posts' }, { status: 500 });
  }
}

export async function POST(req: Request) {
  if (!(await verifyAdmin(req))) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  try {
    const body = await req.json();
    const { title, slug, excerpt, category, date, author, readingTime, content } = body;

    if (!title || !slug || !excerpt || !category || !date || !author || !readingTime) {
      return NextResponse.json({ error: 'Missing required fields' }, { status: 400 });
    }

    const post: BlogPost = {
      slug,
      title,
      excerpt,
      category,
      date,
      author,
      readingTime,
    };

    if (content && typeof content === 'string' && content.trim()) {
      post.content = content.split('\n\n').filter((block: string) => block.trim());
    }

    await savePost(post);
    return NextResponse.json({ ok: true, data: post });
  } catch {
    return NextResponse.json({ error: 'Failed to save post' }, { status: 500 });
  }
}
