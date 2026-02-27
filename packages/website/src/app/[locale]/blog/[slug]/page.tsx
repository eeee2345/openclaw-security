import { getTranslations } from 'next-intl/server';
import { Link } from '@/navigation';
import { ArrowLeft, Clock, User, Calendar } from 'lucide-react';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import { blogPosts } from '@/data/blog-posts';
import { notFound } from 'next/navigation';

/* ─── Static Params ─── */

export function generateStaticParams() {
  return blogPosts.map((post) => ({ slug: post.slug }));
}

/* ─── Metadata ─── */

export async function generateMetadata({ params }: { params: { slug: string; locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  const post = blogPosts.find((p) => p.slug === params.slug);
  if (!post) {
    return { title: t('blog.title'), description: t('blog.description') };
  }
  return {
    title: `${post.title} | Panguard AI Blog`,
    description: post.excerpt,
  };
}

/* ─── Helper ─── */

function formatDate(dateStr: string, locale: string): string {
  const date = new Date(dateStr + 'T00:00:00');
  return date.toLocaleDateString(locale === 'zh' ? 'zh-TW' : 'en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
}

/* ════════════════════════  Page Component  ═══════════════════════ */

export default async function BlogPostPage({
  params,
}: {
  params: { slug: string; locale: string };
}) {
  const t = await getTranslations({ locale: params.locale, namespace: 'blogPost' });
  const post = blogPosts.find((p) => p.slug === params.slug);

  if (!post) {
    notFound();
  }

  return (
    <>
      <NavBar />
      <main>
        {/* ───────────── Back Link ───────────── */}
        <section className="pt-24 pb-0 px-6">
          <div className="max-w-[800px] mx-auto">
            <FadeInUp>
              <Link
                href="/blog"
                className="inline-flex items-center gap-2 text-sm text-text-tertiary hover:text-brand-sage transition-colors duration-200"
              >
                <ArrowLeft className="w-4 h-4" />
                {t('backToBlog')}
              </Link>
            </FadeInUp>
          </div>
        </section>

        {/* ───────────── Post Header ───────────── */}
        <SectionWrapper spacing="default">
          <div className="max-w-[800px] mx-auto">
            <FadeInUp>
              <span className="text-[10px] uppercase tracking-wider font-semibold px-2.5 py-1 rounded-full bg-brand-sage/10 text-brand-sage">
                {post.category}
              </span>
            </FadeInUp>

            <FadeInUp delay={0.05}>
              <h1 className="text-[clamp(32px,4vw,48px)] font-bold text-text-primary leading-[1.1] mt-5">
                {post.title}
              </h1>
            </FadeInUp>

            <FadeInUp delay={0.1}>
              <div className="flex flex-wrap items-center gap-5 mt-6 text-sm text-text-tertiary">
                <span className="flex items-center gap-1.5">
                  <User className="w-4 h-4" />
                  {post.author}
                </span>
                <span className="flex items-center gap-1.5">
                  <Calendar className="w-4 h-4" />
                  {formatDate(post.date, params.locale)}
                </span>
                <span className="flex items-center gap-1.5">
                  <Clock className="w-4 h-4" />
                  {post.readingTime} read
                </span>
              </div>
            </FadeInUp>

            <FadeInUp delay={0.15}>
              <div className="border-t border-border mt-8 pt-8">
                <p className="text-lg text-text-secondary leading-relaxed">{post.excerpt}</p>
              </div>
            </FadeInUp>

            {/* ───────────── Article Content or Coming Soon ───────────── */}
            {post.content ? (
              <FadeInUp delay={0.2}>
                <div className="mt-12 prose-panguard space-y-5">
                  {post.content.map((block, i) => {
                    if (block.startsWith('## ')) {
                      return (
                        <h2 key={i} className="text-xl font-bold text-text-primary mt-10 mb-3">
                          {block.replace('## ', '')}
                        </h2>
                      );
                    }
                    if (block.startsWith('**') && block.includes('.**')) {
                      const parts = block.match(/^\*\*(.+?)\.\*\*\s*(.*)$/);
                      if (parts) {
                        return (
                          <p key={i} className="text-text-secondary leading-relaxed">
                            <strong className="text-text-primary">{parts[1]}.</strong> {parts[2]}
                          </p>
                        );
                      }
                    }
                    if (block.startsWith('```')) {
                      const code = block.replace(/^```\n?/, '').replace(/\n?```$/, '');
                      return (
                        <pre
                          key={i}
                          className="bg-surface-1 border border-border rounded-xl p-4 overflow-x-auto"
                        >
                          <code className="text-sm text-text-secondary font-mono">{code}</code>
                        </pre>
                      );
                    }
                    return (
                      <p key={i} className="text-text-secondary leading-relaxed">
                        {block}
                      </p>
                    );
                  })}
                </div>
              </FadeInUp>
            ) : (
              <FadeInUp delay={0.2}>
                <div className="mt-12 bg-surface-1 rounded-2xl border border-border p-8 text-center">
                  <p className="text-[11px] uppercase tracking-[0.12em] text-brand-sage font-semibold mb-3">
                    {t('comingSoon')}
                  </p>
                  <h2 className="text-xl font-bold text-text-primary">
                    {t('fullArticleInProgress')}
                  </h2>
                  <p className="text-sm text-text-secondary mt-3 max-w-md mx-auto leading-relaxed">
                    {t('fullArticleDesc')}
                  </p>
                  <Link
                    href="/blog"
                    className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold rounded-full px-6 py-3 mt-6 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
                  >
                    <ArrowLeft className="w-4 h-4" />
                    {t('browseAll')}
                  </Link>
                </div>
              </FadeInUp>
            )}
          </div>
        </SectionWrapper>
      </main>
      <Footer />
    </>
  );
}
