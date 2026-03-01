'use client';

import { useState, useEffect, useCallback } from 'react';
import { useAuth } from '@/lib/auth';
import { useRouter } from '@/navigation';
import { Link } from '@/navigation';
import {
  Plus,
  ArrowLeft,
  Loader2,
  LogOut,
  Pencil,
  Trash2,
  Save,
  X,
  FileText,
} from 'lucide-react';
import BrandLogo from '@/components/ui/BrandLogo';
import { blogPosts as staticPosts, categories } from '@/data/blog-posts';
import type { BlogPost } from '@/data/blog-posts';

/* ─── Slug Generator ─── */
function toSlug(title: string): string {
  return title
    .toLowerCase()
    .replace(/['']/g, '')
    .replace(/[^a-z0-9\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
}

/* ─── Today's date in YYYY-MM-DD ─── */
function today(): string {
  return new Date().toISOString().split('T')[0];
}

/* ─── Empty post template ─── */
function emptyPost(): BlogPost {
  return {
    slug: '',
    title: '',
    excerpt: '',
    category: 'Engineering',
    date: today(),
    author: 'Panguard Team',
    readingTime: '5 min',
  };
}

/* ─── Merge static + JSON posts ─── */
function mergePosts(jsonPosts: BlogPost[]): (BlogPost & { source: 'static' | 'dynamic' })[] {
  const jsonSlugs = new Set(jsonPosts.map((p) => p.slug));
  const merged = [
    ...jsonPosts.map((p) => ({ ...p, source: 'dynamic' as const })),
    ...staticPosts
      .filter((p) => !jsonSlugs.has(p.slug))
      .map((p) => ({ ...p, source: 'static' as const })),
  ];
  return merged.sort((a, b) => b.date.localeCompare(a.date));
}

/* ════════════════════════  Main Component  ═══════════════════════ */

export default function BlogAdminContent() {
  const { user, token, loading, logout } = useAuth();
  const router = useRouter();

  const [jsonPosts, setJsonPosts] = useState<BlogPost[]>([]);
  const [dataLoading, setDataLoading] = useState(true);
  const [view, setView] = useState<'list' | 'editor'>('list');
  const [editingPost, setEditingPost] = useState<BlogPost>(emptyPost());
  const [contentText, setContentText] = useState('');
  const [isNew, setIsNew] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  /* ─── Auth Guard ─── */
  useEffect(() => {
    if (!loading && !user) {
      router.push('/login?redirect=/dashboard/blog');
    }
  }, [loading, user, router]);

  /* ─── Fetch JSON Posts ─── */
  const fetchPosts = useCallback(async () => {
    try {
      const res = await fetch('/api/blog');
      const data = (await res.json()) as { ok: boolean; data?: BlogPost[] };
      if (data.ok && data.data) {
        setJsonPosts(data.data);
      }
    } catch {
      // Fallback to empty
    } finally {
      setDataLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchPosts();
  }, [fetchPosts]);

  /* ─── Handlers ─── */
  const openNewPost = () => {
    setEditingPost(emptyPost());
    setContentText('');
    setIsNew(true);
    setError('');
    setView('editor');
  };

  const openEditPost = (post: BlogPost) => {
    setEditingPost({ ...post });
    setContentText(post.content ? post.content.join('\n\n') : '');
    setIsNew(false);
    setError('');
    setView('editor');
  };

  const handleTitleChange = (title: string) => {
    setEditingPost((prev) => ({
      ...prev,
      title,
      slug: isNew ? toSlug(title) : prev.slug,
    }));
  };

  const handleSave = async () => {
    if (!token) return;
    setError('');
    setSaving(true);

    const { slug, title, excerpt, category, date, author, readingTime } = editingPost;
    if (!slug || !title || !excerpt) {
      setError('Title, slug, and excerpt are required.');
      setSaving(false);
      return;
    }

    try {
      const url = isNew ? '/api/blog' : `/api/blog/${slug}`;
      const method = isNew ? 'POST' : 'PUT';

      const res = await fetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          slug,
          title,
          excerpt,
          category,
          date,
          author,
          readingTime,
          content: contentText,
        }),
      });

      const data = (await res.json()) as { ok?: boolean; error?: string };
      if (!res.ok) {
        setError(data.error ?? 'Failed to save');
        setSaving(false);
        return;
      }

      await fetchPosts();
      setView('list');
    } catch {
      setError('Network error');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (slug: string) => {
    if (!token) return;
    if (!confirm('Delete this post?')) return;

    try {
      await fetch(`/api/blog/${slug}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });
      await fetchPosts();
    } catch {
      // Silent fail
    }
  };

  /* ─── Loading / Auth States ─── */
  if (loading || !user) {
    return (
      <div className="min-h-screen bg-surface-0 flex items-center justify-center">
        <Loader2 className="w-6 h-6 text-brand-sage animate-spin" />
      </div>
    );
  }

  const allPosts = mergePosts(jsonPosts);

  return (
    <div className="min-h-screen bg-surface-0">
      {/* ─── Header ─── */}
      <header className="border-b border-border bg-surface-1">
        <div className="max-w-6xl mx-auto px-6 h-14 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link href="/" className="flex items-center gap-1.5">
              <BrandLogo size={20} className="text-brand-sage" />
              <span className="font-semibold tracking-wider text-text-primary text-sm">PANGUARD</span>
            </Link>
            <span className="text-text-muted">/</span>
            <Link
              href={'/dashboard' as '/dashboard'}
              className="text-sm text-text-tertiary hover:text-text-secondary transition-colors"
            >
              Dashboard
            </Link>
            <span className="text-text-muted">/</span>
            <span className="text-sm text-text-primary font-medium">Blog</span>
          </div>
          <div className="flex items-center gap-4">
            <span className="text-sm text-text-secondary">{user.email}</span>
            <button
              onClick={() => { void logout(); router.push('/'); }}
              className="text-text-tertiary hover:text-text-secondary transition-colors"
              title="Log out"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </header>

      <div className="max-w-6xl mx-auto px-6 py-8">
        {view === 'list' ? (
          /* ═══════════════  LIST VIEW  ═══════════════ */
          <>
            <div className="flex items-center justify-between mb-6">
              <div>
                <h1 className="text-2xl font-bold text-text-primary">Blog Posts</h1>
                <p className="text-sm text-text-tertiary mt-1">
                  {allPosts.length} posts ({staticPosts.length} static, {jsonPosts.length} dynamic)
                </p>
              </div>
              <button
                onClick={openNewPost}
                className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold text-sm rounded-full px-5 py-2.5 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
              >
                <Plus className="w-4 h-4" />
                New Post
              </button>
            </div>

            {dataLoading ? (
              <div className="flex items-center justify-center py-16">
                <Loader2 className="w-5 h-5 text-text-tertiary animate-spin" />
              </div>
            ) : (
              <div className="bg-surface-1 border border-border rounded-xl overflow-hidden">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-border">
                      <th className="text-left text-xs uppercase tracking-wider text-text-muted font-semibold px-6 py-3">Title</th>
                      <th className="text-left text-xs uppercase tracking-wider text-text-muted font-semibold px-4 py-3 hidden md:table-cell">Category</th>
                      <th className="text-left text-xs uppercase tracking-wider text-text-muted font-semibold px-4 py-3 hidden md:table-cell">Date</th>
                      <th className="text-left text-xs uppercase tracking-wider text-text-muted font-semibold px-4 py-3 hidden sm:table-cell">Source</th>
                      <th className="text-right text-xs uppercase tracking-wider text-text-muted font-semibold px-6 py-3">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {allPosts.map((post) => (
                      <tr key={post.slug} className="border-b border-border/50 last:border-0 hover:bg-surface-2/50 transition-colors">
                        <td className="px-6 py-4">
                          <div className="flex items-start gap-3">
                            <FileText className="w-4 h-4 text-text-tertiary mt-0.5 shrink-0" />
                            <div className="min-w-0">
                              <p className="text-sm font-medium text-text-primary truncate max-w-[400px]">{post.title}</p>
                              <p className="text-xs text-text-muted mt-0.5">{post.author}</p>
                            </div>
                          </div>
                        </td>
                        <td className="px-4 py-4 hidden md:table-cell">
                          <span className="text-[10px] uppercase tracking-wider font-semibold px-2.5 py-1 rounded-full bg-brand-sage/10 text-brand-sage">
                            {post.category}
                          </span>
                        </td>
                        <td className="px-4 py-4 hidden md:table-cell">
                          <span className="text-sm text-text-secondary">{post.date}</span>
                        </td>
                        <td className="px-4 py-4 hidden sm:table-cell">
                          <span className={`text-[10px] uppercase tracking-wider font-semibold px-2 py-0.5 rounded-full ${
                            post.source === 'static'
                              ? 'bg-surface-3 text-text-tertiary'
                              : 'bg-[#60a5fa]/10 text-[#60a5fa]'
                          }`}>
                            {post.source}
                          </span>
                        </td>
                        <td className="px-6 py-4 text-right">
                          {post.source === 'dynamic' ? (
                            <div className="flex items-center justify-end gap-2">
                              <button
                                onClick={() => openEditPost(post)}
                                className="p-1.5 text-text-tertiary hover:text-brand-sage transition-colors rounded-lg hover:bg-surface-2"
                                title="Edit"
                              >
                                <Pencil className="w-3.5 h-3.5" />
                              </button>
                              <button
                                onClick={() => void handleDelete(post.slug)}
                                className="p-1.5 text-text-tertiary hover:text-[#ef4444] transition-colors rounded-lg hover:bg-surface-2"
                                title="Delete"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          ) : (
                            <span className="text-xs text-text-muted">Read-only</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        ) : (
          /* ═══════════════  EDITOR VIEW  ═══════════════ */
          <>
            <button
              onClick={() => setView('list')}
              className="inline-flex items-center gap-2 text-sm text-text-tertiary hover:text-text-secondary transition-colors mb-6"
            >
              <ArrowLeft className="w-4 h-4" />
              Back to list
            </button>

            <h1 className="text-2xl font-bold text-text-primary mb-6">
              {isNew ? 'New Post' : 'Edit Post'}
            </h1>

            {error && (
              <div className="bg-[#ef4444]/10 border border-[#ef4444]/20 rounded-lg px-4 py-3 mb-6">
                <p className="text-sm text-[#ef4444]">{error}</p>
              </div>
            )}

            <div className="grid lg:grid-cols-3 gap-6">
              {/* Main Content */}
              <div className="lg:col-span-2 space-y-5">
                {/* Title */}
                <div>
                  <label className="block text-xs uppercase tracking-wider text-text-muted font-semibold mb-2">Title</label>
                  <input
                    type="text"
                    value={editingPost.title}
                    onChange={(e) => handleTitleChange(e.target.value)}
                    placeholder="Post title..."
                    className="w-full bg-surface-2 border border-border rounded-lg px-4 py-3 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-brand-sage transition-colors"
                  />
                </div>

                {/* Slug */}
                <div>
                  <label className="block text-xs uppercase tracking-wider text-text-muted font-semibold mb-2">Slug</label>
                  <input
                    type="text"
                    value={editingPost.slug}
                    onChange={(e) => setEditingPost((prev) => ({ ...prev, slug: e.target.value }))}
                    placeholder="post-url-slug"
                    className="w-full bg-surface-2 border border-border rounded-lg px-4 py-3 text-sm text-text-primary font-mono placeholder:text-text-muted focus:outline-none focus:border-brand-sage transition-colors"
                  />
                </div>

                {/* Excerpt */}
                <div>
                  <label className="block text-xs uppercase tracking-wider text-text-muted font-semibold mb-2">Excerpt</label>
                  <textarea
                    value={editingPost.excerpt}
                    onChange={(e) => setEditingPost((prev) => ({ ...prev, excerpt: e.target.value }))}
                    placeholder="Brief summary shown on the blog listing page..."
                    rows={2}
                    className="w-full bg-surface-2 border border-border rounded-lg px-4 py-3 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-brand-sage transition-colors resize-none"
                  />
                </div>

                {/* Content */}
                <div>
                  <label className="block text-xs uppercase tracking-wider text-text-muted font-semibold mb-2">Content</label>
                  <p className="text-xs text-text-muted mb-2">
                    Use ## for headings. Use ``` for code blocks. Use ** for bold. Separate paragraphs with blank lines.
                  </p>
                  <textarea
                    value={contentText}
                    onChange={(e) => setContentText(e.target.value)}
                    placeholder={"## Introduction\n\nYour first paragraph here.\n\n## Next Section\n\nMore content..."}
                    rows={20}
                    className="w-full bg-surface-2 border border-border rounded-lg px-4 py-3 text-sm text-text-primary font-mono placeholder:text-text-muted focus:outline-none focus:border-brand-sage transition-colors resize-y leading-relaxed"
                  />
                </div>
              </div>

              {/* Sidebar */}
              <div className="space-y-5">
                {/* Category */}
                <div>
                  <label className="block text-xs uppercase tracking-wider text-text-muted font-semibold mb-2">Category</label>
                  <select
                    value={editingPost.category}
                    onChange={(e) => setEditingPost((prev) => ({ ...prev, category: e.target.value }))}
                    className="w-full bg-surface-2 border border-border rounded-lg px-4 py-3 text-sm text-text-primary focus:outline-none focus:border-brand-sage transition-colors"
                  >
                    {categories.filter((c) => c !== 'All').map((cat) => (
                      <option key={cat} value={cat}>{cat}</option>
                    ))}
                  </select>
                </div>

                {/* Date */}
                <div>
                  <label className="block text-xs uppercase tracking-wider text-text-muted font-semibold mb-2">Date</label>
                  <input
                    type="date"
                    value={editingPost.date}
                    onChange={(e) => setEditingPost((prev) => ({ ...prev, date: e.target.value }))}
                    className="w-full bg-surface-2 border border-border rounded-lg px-4 py-3 text-sm text-text-primary focus:outline-none focus:border-brand-sage transition-colors"
                  />
                </div>

                {/* Author */}
                <div>
                  <label className="block text-xs uppercase tracking-wider text-text-muted font-semibold mb-2">Author</label>
                  <input
                    type="text"
                    value={editingPost.author}
                    onChange={(e) => setEditingPost((prev) => ({ ...prev, author: e.target.value }))}
                    placeholder="Author name"
                    className="w-full bg-surface-2 border border-border rounded-lg px-4 py-3 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-brand-sage transition-colors"
                  />
                </div>

                {/* Reading Time */}
                <div>
                  <label className="block text-xs uppercase tracking-wider text-text-muted font-semibold mb-2">Reading Time</label>
                  <input
                    type="text"
                    value={editingPost.readingTime}
                    onChange={(e) => setEditingPost((prev) => ({ ...prev, readingTime: e.target.value }))}
                    placeholder="5 min"
                    className="w-full bg-surface-2 border border-border rounded-lg px-4 py-3 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-brand-sage transition-colors"
                  />
                </div>

                {/* Actions */}
                <div className="pt-4 border-t border-border space-y-3">
                  <button
                    onClick={() => void handleSave()}
                    disabled={saving}
                    className="w-full inline-flex items-center justify-center gap-2 bg-brand-sage text-surface-0 font-semibold text-sm rounded-lg px-5 py-3 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98] disabled:opacity-60"
                  >
                    {saving ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <Save className="w-4 h-4" />
                    )}
                    {saving ? 'Saving...' : isNew ? 'Publish' : 'Update'}
                  </button>
                  <button
                    onClick={() => setView('list')}
                    className="w-full inline-flex items-center justify-center gap-2 border border-border text-text-secondary font-semibold text-sm rounded-lg px-5 py-3 hover:text-text-primary hover:border-border-hover transition-all duration-200"
                  >
                    <X className="w-4 h-4" />
                    Cancel
                  </button>
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
