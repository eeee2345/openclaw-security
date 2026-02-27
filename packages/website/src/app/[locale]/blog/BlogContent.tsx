'use client';

import { useState } from 'react';
import { useTranslations, useLocale } from 'next-intl';
import { Link } from '@/navigation';
import { ArrowRight, Clock, User, Mail, Send } from 'lucide-react';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import SectionTitle from '@/components/ui/SectionTitle';
import { blogPosts, categories } from '@/data/blog-posts';

/* ─── Helpers ─── */

function formatDate(dateStr: string, locale: string): string {
  const date = new Date(dateStr + 'T00:00:00');
  return date.toLocaleDateString(locale === 'zh' ? 'zh-TW' : 'en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
}

/* ─── Category Badge ─── */

function CategoryBadge({ category }: { category: string }) {
  return (
    <span className="text-[10px] uppercase tracking-wider font-semibold px-2.5 py-1 rounded-full bg-brand-sage/10 text-brand-sage">
      {category}
    </span>
  );
}

/* ════════════════════════  Blog Content  ═══════════════════════ */

export default function BlogContent() {
  const t = useTranslations('blog');
  const tc = useTranslations('common');
  const locale = useLocale();

  const [activeCategory, setActiveCategory] = useState('All');
  const [nlEmail, setNlEmail] = useState('');
  const [nlStatus, setNlStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle');

  const featuredPost = blogPosts[0];
  const remainingPosts = blogPosts.slice(1);

  const filteredPosts =
    activeCategory === 'All'
      ? remainingPosts
      : remainingPosts.filter((post) => post.category === activeCategory);

  return (
    <>
      {/* ───────────── Hero ───────────── */}
      <SectionWrapper spacing="spacious">
        <SectionTitle overline={t('overline')} title={t('title')} subtitle={t('subtitle')} />
      </SectionWrapper>

      {/* ───────────── Featured Post ───────────── */}
      <SectionWrapper dark>
        <FadeInUp>
          <Link
            href={`/blog/${featuredPost.slug}`}
            className="block bg-surface-2 rounded-2xl border border-border p-8 md:p-10 hover:border-brand-sage/40 transition-all duration-200 card-glow group"
          >
            <div className="flex flex-col md:flex-row md:items-start gap-6 md:gap-10">
              {/* Left: Content */}
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-4">
                  <CategoryBadge category={featuredPost.category} />
                  <span className="text-[11px] uppercase tracking-wider font-semibold text-brand-sage">
                    {t('featured')}
                  </span>
                </div>
                <h2 className="text-[clamp(24px,3vw,36px)] font-bold text-text-primary leading-[1.15] group-hover:text-brand-sage transition-colors duration-200">
                  {featuredPost.title}
                </h2>
                <p className="text-text-secondary mt-4 leading-relaxed text-base md:text-lg">
                  {featuredPost.excerpt}
                </p>
                <div className="flex flex-wrap items-center gap-4 mt-6 text-sm text-text-tertiary">
                  <span className="flex items-center gap-1.5">
                    <User className="w-3.5 h-3.5" />
                    {featuredPost.author}
                  </span>
                  <span className="flex items-center gap-1.5">
                    <Clock className="w-3.5 h-3.5" />
                    {featuredPost.readingTime} read
                  </span>
                  <span>{formatDate(featuredPost.date, locale)}</span>
                </div>
              </div>

              {/* Right: Read More arrow */}
              <div className="flex items-center gap-2 text-brand-sage font-semibold text-sm shrink-0 md:mt-4 group-hover:gap-3 transition-all duration-200">
                {tc('readMore')}
                <ArrowRight className="w-4 h-4" />
              </div>
            </div>
          </Link>
        </FadeInUp>
      </SectionWrapper>

      {/* ───────────── Category Filter ───────────── */}
      <SectionWrapper spacing="tight">
        <FadeInUp>
          <div className="flex flex-wrap items-center gap-2 justify-center">
            {categories.map((cat) => (
              <button
                key={cat}
                onClick={() => setActiveCategory(cat)}
                className={`text-sm font-semibold rounded-full px-5 py-2 transition-all duration-200 ${
                  activeCategory === cat
                    ? 'bg-brand-sage text-surface-0'
                    : 'bg-surface-1 text-text-secondary border border-border hover:border-brand-sage/40 hover:text-text-primary'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>
        </FadeInUp>
      </SectionWrapper>

      {/* ───────────── Post Grid ───────────── */}
      <SectionWrapper>
        {filteredPosts.length === 0 ? (
          <FadeInUp>
            <div className="text-center py-16">
              <p className="text-text-tertiary text-lg">{t('noPosts')}</p>
            </div>
          </FadeInUp>
        ) : (
          <div className="grid md:grid-cols-2 gap-6">
            {filteredPosts.map((post, i) => (
              <FadeInUp key={post.slug} delay={i * 0.06}>
                <Link
                  href={`/blog/${post.slug}`}
                  className="block bg-surface-1 border border-border rounded-2xl p-6 hover:border-brand-sage/40 transition-all duration-200 card-glow h-full group"
                >
                  <div className="flex flex-col h-full">
                    <div className="flex items-center gap-3 mb-3">
                      <CategoryBadge category={post.category} />
                      <span className="text-xs text-text-muted">
                        {formatDate(post.date, locale)}
                      </span>
                    </div>

                    <h3 className="text-lg font-bold text-text-primary leading-snug group-hover:text-brand-sage transition-colors duration-200">
                      {post.title}
                    </h3>

                    <p className="text-sm text-text-secondary mt-3 leading-relaxed flex-1">
                      {post.excerpt}
                    </p>

                    <div className="flex items-center justify-between mt-5 pt-4 border-t border-border/50">
                      <div className="flex items-center gap-4 text-xs text-text-tertiary">
                        <span className="flex items-center gap-1">
                          <User className="w-3 h-3" />
                          {post.author}
                        </span>
                        <span className="flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          {post.readingTime}
                        </span>
                      </div>
                      <span className="flex items-center gap-1 text-brand-sage text-sm font-semibold group-hover:gap-2 transition-all duration-200">
                        Read
                        <ArrowRight className="w-3.5 h-3.5" />
                      </span>
                    </div>
                  </div>
                </Link>
              </FadeInUp>
            ))}
          </div>
        )}
      </SectionWrapper>

      {/* ───────────── Newsletter CTA ───────────── */}
      <SectionWrapper dark>
        <FadeInUp>
          <div className="text-center max-w-2xl mx-auto">
            <Mail className="w-8 h-8 text-brand-sage mx-auto mb-4" />
            <h2 className="text-[clamp(28px,3vw,40px)] font-bold text-text-primary">
              {t('digest.title')}
            </h2>
            <p className="text-text-secondary mt-4 leading-relaxed">{t('digest.desc')}</p>
          </div>
        </FadeInUp>
        <FadeInUp delay={0.1}>
          {nlStatus === 'success' ? (
            <p className="mt-8 text-sm text-status-safe font-medium text-center">
              {t('digest.success', { email: nlEmail })}
            </p>
          ) : (
            <form
              onSubmit={async (e) => {
                e.preventDefault();
                if (!nlEmail) return;
                setNlStatus('loading');
                try {
                  const res = await fetch('/api/waitlist', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: nlEmail, source: 'blog-newsletter' }),
                  });
                  if (!res.ok) throw new Error('fail');
                  setNlStatus('success');
                } catch {
                  setNlStatus('error');
                }
              }}
              className="flex flex-col sm:flex-row items-center gap-3 mt-8 max-w-md mx-auto"
            >
              <input
                type="email"
                placeholder={t('digest.placeholder')}
                value={nlEmail}
                onChange={(e) => setNlEmail(e.target.value)}
                className="w-full sm:flex-1 bg-surface-2 border border-border rounded-full px-5 py-3 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-brand-sage transition-colors"
                required
              />
              <button
                type="submit"
                disabled={nlStatus === 'loading'}
                className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold rounded-full px-6 py-3 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98] shrink-0 disabled:opacity-60"
              >
                {nlStatus === 'loading' ? '...' : t('digest.subscribe')}
                <Send className="w-4 h-4" />
              </button>
            </form>
          )}
          {nlStatus === 'error' && (
            <p className="text-sm text-status-alert text-center mt-3">{t('digest.error')}</p>
          )}
          <p className="text-xs text-text-muted text-center mt-3">{t('digest.note')}</p>
        </FadeInUp>
      </SectionWrapper>
    </>
  );
}
