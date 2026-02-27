'use client';

import { useState } from 'react';
import { useTranslations, useLocale } from 'next-intl';
import { Rss } from 'lucide-react';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import SectionTitle from '@/components/ui/SectionTitle';
import { changelogEntries, type ChangelogEntry } from '@/data/changelog-entries';

/* ─── Types ─── */

type ChangeType = 'feature' | 'fix' | 'improvement' | 'security';

type FilterKey = 'all' | ChangeType;

/* ─── Badge styles per change type ─── */

const badgeStyles: Record<ChangeType, string> = {
  feature: 'bg-brand-sage/10 text-brand-sage',
  fix: 'bg-amber-500/10 text-amber-400',
  improvement: 'bg-blue-500/10 text-blue-400',
  security: 'bg-red-500/10 text-red-400',
};

/* ─── Helpers ─── */

function formatDate(dateStr: string, locale: string): string {
  const date = new Date(dateStr + 'T00:00:00');
  return date.toLocaleDateString(locale === 'zh' ? 'zh-TW' : 'en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
}

function filterEntries(entries: ChangelogEntry[], filter: FilterKey): ChangelogEntry[] {
  if (filter === 'all') return entries;

  return entries
    .map((entry) => ({
      ...entry,
      changes: entry.changes.filter((c) => c.type === filter),
    }))
    .filter((entry) => entry.changes.length > 0);
}

/* ─── Filter Config ─── */

const filterKeys: { key: FilterKey; labelKey: string }[] = [
  { key: 'all', labelKey: 'filters.all' },
  { key: 'feature', labelKey: 'filters.features' },
  { key: 'fix', labelKey: 'filters.fixes' },
  { key: 'improvement', labelKey: 'filters.improvements' },
  { key: 'security', labelKey: 'filters.security' },
];

/* ════════════════════════  Component  ═══════════════════════ */

export default function ChangelogContent() {
  const t = useTranslations('changelog');
  const locale = useLocale();

  const [activeFilter, setActiveFilter] = useState<FilterKey>('all');

  const filtered = filterEntries(changelogEntries, activeFilter);

  const badgeLabels: Record<ChangeType, string> = {
    feature: t('badges.feature'),
    fix: t('badges.fix'),
    improvement: t('badges.improvement'),
    security: t('badges.security'),
  };

  return (
    <>
      {/* ───────────── Hero ───────────── */}
      <SectionWrapper spacing="spacious">
        <SectionTitle overline={t('overline')} title={t('title')} subtitle={t('subtitle')} />
      </SectionWrapper>

      {/* ───────────── Filters ───────────── */}
      <SectionWrapper spacing="tight">
        <FadeInUp>
          <div className="flex flex-wrap items-center justify-center gap-3">
            {filterKeys.map((f) => (
              <button
                key={f.key}
                onClick={() => setActiveFilter(f.key)}
                className={`rounded-full px-5 py-2 text-sm font-medium transition-all duration-200 ${
                  activeFilter === f.key
                    ? 'bg-brand-sage text-surface-0'
                    : 'border border-border text-text-secondary hover:border-brand-sage hover:text-text-primary'
                }`}
              >
                {t(f.labelKey)}
              </button>
            ))}
          </div>
        </FadeInUp>
      </SectionWrapper>

      {/* ───────────── Timeline ───────────── */}
      <SectionWrapper>
        <div className="relative max-w-3xl mx-auto">
          {/* Vertical timeline line */}
          <div
            className="absolute left-[7.5rem] top-0 bottom-0 w-px bg-brand-sage/20 hidden md:block"
            aria-hidden="true"
          />

          <div className="space-y-12">
            {filtered.map((entry, idx) => (
              <FadeInUp key={entry.version} delay={idx * 0.05}>
                <article className="relative md:grid md:grid-cols-[7.5rem_1fr] md:gap-8">
                  {/* -- Left: version + date -- */}
                  <div className="mb-4 md:mb-0 md:text-right md:pt-1">
                    <span className="text-brand-sage font-mono font-semibold text-sm">
                      v{entry.version}
                    </span>
                    <p className="text-text-tertiary text-xs mt-1">
                      {formatDate(entry.date, locale)}
                    </p>
                  </div>

                  {/* -- Timeline dot -- */}
                  <div
                    className="absolute left-[7.25rem] top-1.5 hidden md:block"
                    aria-hidden="true"
                  >
                    <div className="w-2.5 h-2.5 rounded-full bg-brand-sage ring-4 ring-surface-0" />
                  </div>

                  {/* -- Right: content card -- */}
                  <div className="bg-surface-1 border border-border rounded-2xl p-6 md:ml-4">
                    <h3 className="text-lg font-semibold text-text-primary leading-snug">
                      {entry.title}
                    </h3>
                    <p className="text-text-secondary text-sm mt-2 leading-relaxed">
                      {entry.description}
                    </p>

                    <ul className="mt-5 space-y-3">
                      {entry.changes.map((change, cIdx) => (
                        <li key={cIdx} className="flex items-start gap-3 text-sm">
                          <span
                            className={`inline-block shrink-0 rounded-full px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide mt-0.5 ${badgeStyles[change.type]}`}
                          >
                            {badgeLabels[change.type]}
                          </span>
                          <span className="text-text-secondary leading-relaxed">{change.text}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </article>
              </FadeInUp>
            ))}
          </div>

          {/* Empty state */}
          {filtered.length === 0 && (
            <FadeInUp>
              <div className="text-center py-16">
                <p className="text-text-tertiary text-sm">{t('emptyFilter')}</p>
              </div>
            </FadeInUp>
          )}
        </div>
      </SectionWrapper>

      {/* ───────────── Subscribe CTA ───────────── */}
      <SectionWrapper dark>
        <FadeInUp>
          <div className="text-center max-w-xl mx-auto">
            <Rss className="w-8 h-8 text-brand-sage mx-auto mb-5" />
            <h2 className="text-[clamp(24px,3vw,36px)] font-bold text-text-primary leading-[1.1]">
              {t('notifyTitle')}
            </h2>
            <p className="text-text-secondary mt-3 leading-relaxed text-sm">
              {t('notifyDesc')} {t('noSpam')}
            </p>

            <form
              onSubmit={(e) => e.preventDefault()}
              className="mt-8 flex flex-col sm:flex-row items-center justify-center gap-3"
            >
              <input
                type="email"
                placeholder={t('emailPlaceholder')}
                aria-label={t('emailAriaLabel')}
                className="w-full sm:w-auto sm:min-w-[280px] rounded-full border border-border bg-surface-1 px-5 py-3 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-brand-sage transition-colors"
              />
              <button
                type="submit"
                className="bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3 text-sm hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98] whitespace-nowrap"
              >
                {t('subscribe')}
              </button>
            </form>
          </div>
        </FadeInUp>
      </SectionWrapper>
    </>
  );
}
