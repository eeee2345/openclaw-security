'use client';

import { useState } from 'react';
import { useTranslations, useLocale } from 'next-intl';
import {
  FileText,
  Video,
  Image as ImageIcon,
  Download,
  ArrowRight,
  Mail,
  Send,
} from 'lucide-react';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import SectionTitle from '@/components/ui/SectionTitle';
import { resources, resourceTypes, Resource } from '@/data/resources';

/* ─── Helpers ─── */

function formatDate(dateStr: string, locale: string): string {
  const [year, month] = dateStr.split('-');
  const date = new Date(Number(year), Number(month) - 1);
  return date.toLocaleDateString(locale === 'zh' ? 'zh-TW' : 'en-US', {
    year: 'numeric',
    month: 'long',
  });
}

/* ─── Type Badge Color Map ─── */

const typeBadgeStyles: Record<Resource['type'], string> = {
  Whitepaper: 'bg-brand-sage/10 text-brand-sage',
  Report: 'bg-blue-500/10 text-blue-400',
  Guide: 'bg-amber-500/10 text-amber-400',
  Webinar: 'bg-purple-500/10 text-purple-400',
  Infographic: 'bg-pink-500/10 text-pink-400',
};

/* ─── Type Icon Map ─── */

function TypeIcon({ type, className }: { type: Resource['type']; className?: string }) {
  switch (type) {
    case 'Webinar':
      return <Video className={className} />;
    case 'Infographic':
      return <ImageIcon className={className} />;
    default:
      return <FileText className={className} />;
  }
}

/* ─── Type Badge ─── */

function TypeBadge({ type }: { type: Resource['type'] }) {
  return (
    <span
      className={`text-[10px] uppercase tracking-wider font-semibold px-2.5 py-1 rounded-full ${typeBadgeStyles[type]}`}
    >
      {type}
    </span>
  );
}

/* ════════════════════════  Resources Content  ═══════════════════════ */

export default function ResourcesContent() {
  const t = useTranslations('resources');
  const locale = useLocale();

  const [activeType, setActiveType] = useState('All');

  const featuredResource = resources[0];
  const remainingResources = resources.slice(1);

  const filteredResources =
    activeType === 'All'
      ? remainingResources
      : remainingResources.filter((r) => r.type === activeType);

  function ctaLabel(type: Resource['type']): string {
    return type === 'Webinar' ? t('watch') : t('download');
  }

  return (
    <>
      {/* ───────────── Hero ───────────── */}
      <SectionWrapper spacing="spacious">
        <SectionTitle overline={t('overline')} title={t('title')} subtitle={t('subtitle')} />
      </SectionWrapper>

      {/* ───────────── Featured Resource ───────────── */}
      <SectionWrapper dark>
        <FadeInUp>
          <div className="bg-surface-1 border border-border rounded-2xl p-8 md:p-10 card-glow">
            <div className="flex flex-col md:flex-row md:items-start gap-6 md:gap-10">
              {/* Left: Icon */}
              <div className="flex items-center justify-center w-16 h-16 rounded-2xl bg-brand-sage/10 shrink-0">
                <TypeIcon type={featuredResource.type} className="w-8 h-8 text-brand-sage" />
              </div>

              {/* Center: Content */}
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-4">
                  <TypeBadge type={featuredResource.type} />
                  <span className="text-[11px] uppercase tracking-wider font-semibold text-brand-sage">
                    {t('featured')}
                  </span>
                </div>
                <h2 className="text-[clamp(24px,3vw,36px)] font-bold text-text-primary leading-[1.15]">
                  {featuredResource.title}
                </h2>
                <p className="text-text-secondary mt-4 leading-relaxed text-base md:text-lg">
                  {featuredResource.description}
                </p>
                <div className="flex flex-wrap items-center gap-4 mt-6">
                  <span className="text-xs text-text-tertiary">
                    {formatDate(featuredResource.date, locale)}
                  </span>
                </div>
              </div>

              {/* Right: CTA */}
              <div className="shrink-0 md:mt-4">
                <button className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold rounded-full px-6 py-3 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]">
                  <Download className="w-4 h-4" />
                  {ctaLabel(featuredResource.type)}
                </button>
              </div>
            </div>
          </div>
        </FadeInUp>
      </SectionWrapper>

      {/* ───────────── Type Filter ───────────── */}
      <SectionWrapper spacing="tight">
        <FadeInUp>
          <div className="flex flex-wrap items-center gap-2 justify-center">
            {resourceTypes.map((type) => (
              <button
                key={type}
                onClick={() => setActiveType(type)}
                className={`text-sm font-semibold rounded-full px-5 py-2 transition-all duration-200 ${
                  activeType === type
                    ? 'bg-brand-sage text-surface-0'
                    : 'bg-surface-1 text-text-secondary border border-border hover:border-brand-sage/40 hover:text-text-primary'
                }`}
              >
                {type}
              </button>
            ))}
          </div>
        </FadeInUp>
      </SectionWrapper>

      {/* ───────────── Resource Grid ───────────── */}
      <SectionWrapper>
        {filteredResources.length === 0 ? (
          <FadeInUp>
            <div className="text-center py-16">
              <p className="text-text-tertiary text-lg">{t('noResources')}</p>
            </div>
          </FadeInUp>
        ) : (
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
            {filteredResources.map((resource, i) => (
              <FadeInUp key={resource.slug} delay={i * 0.06}>
                <div className="bg-surface-1 border border-border rounded-2xl p-6 hover:border-brand-sage/40 transition-all duration-200 card-glow h-full flex flex-col group">
                  <div className="flex items-center gap-3 mb-3">
                    <TypeBadge type={resource.type} />
                    <span className="text-xs text-text-muted">
                      {formatDate(resource.date, locale)}
                    </span>
                  </div>

                  <h3 className="text-lg font-semibold text-text-primary leading-snug">
                    {resource.title}
                  </h3>

                  <p className="text-sm text-text-secondary mt-3 leading-relaxed flex-1">
                    {resource.description}
                  </p>

                  <div className="flex items-center justify-between mt-5 pt-4 border-t border-border/50">
                    <div className="flex items-center gap-2 text-xs text-text-tertiary">
                      <TypeIcon type={resource.type} className="w-3.5 h-3.5" />
                      <span>{resource.type}</span>
                    </div>
                    <button className="flex items-center gap-1 text-brand-sage text-sm font-semibold group-hover:gap-2 transition-all duration-200">
                      {ctaLabel(resource.type)}
                      <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
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
              {t('newsletter.title')}
            </h2>
            <p className="text-text-secondary mt-4 leading-relaxed">{t('newsletter.desc')}</p>
          </div>
        </FadeInUp>
        <FadeInUp delay={0.1}>
          <form
            onSubmit={(e) => e.preventDefault()}
            className="flex flex-col sm:flex-row items-center gap-3 mt-8 max-w-md mx-auto"
          >
            <input
              type="email"
              placeholder={t('newsletter.emailPlaceholder')}
              aria-label={t('newsletter.emailAriaLabel')}
              className="w-full sm:flex-1 bg-surface-2 border border-border rounded-full px-5 py-3 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-brand-sage transition-colors"
              required
            />
            <button
              type="submit"
              className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold rounded-full px-6 py-3 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98] shrink-0"
            >
              {t('newsletter.subscribe')}
              <Send className="w-4 h-4" />
            </button>
          </form>
          <p className="text-xs text-text-muted text-center mt-3">{t('newsletter.note')}</p>
        </FadeInUp>
      </SectionWrapper>
    </>
  );
}
