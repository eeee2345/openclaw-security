import { NextResponse } from 'next/server';
import { savePost, deletePost, isStaticPost } from '@/lib/blog-store';
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

export async function PUT(req: Request, { params }: { params: { slug: string } }) {
  if (!(await verifyAdmin(req))) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { slug } = params;

  if (isStaticPost(slug)) {
    return NextResponse.json({ error: 'Cannot edit static posts' }, { status: 403 });
  }

  try {
    const body = await req.json();
    const { title, excerpt, category, date, author, readingTime, content } = body;

    if (!title || !excerpt || !category || !date || !author || !readingTime) {
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
    return NextResponse.json({ error: 'Failed to update post' }, { status: 500 });
  }
}

export async function DELETE(req: Request, { params }: { params: { slug: string } }) {
  if (!(await verifyAdmin(req))) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { slug } = params;

  if (isStaticPost(slug)) {
    return NextResponse.json({ error: 'Cannot delete static posts' }, { status: 403 });
  }

  try {
    const deleted = await deletePost(slug);
    if (!deleted) {
      return NextResponse.json({ error: 'Post not found' }, { status: 404 });
    }
    return NextResponse.json({ ok: true });
  } catch {
    return NextResponse.json({ error: 'Failed to delete post' }, { status: 500 });
  }
}
