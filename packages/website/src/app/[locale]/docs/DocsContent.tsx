'use client';

import { useTranslations } from 'next-intl';
import { Link } from '@/navigation';
import { Search } from 'lucide-react';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import SectionTitle from '@/components/ui/SectionTitle';
import {
  TerminalIcon,
  DeployIcon,
  IntegrationIcon,
  ChatIcon,
  ScanIcon,
  ShieldIcon,
  TrapIcon,
  ReportIcon,
  AnalyticsIcon,
} from '@/components/ui/BrandIcons';

/* ────────────────────────  Config  ──────────────────────────────── */

const quickStartConfigs = [
  { key: 'item1' as const, icon: TerminalIcon },
  { key: 'item2' as const, icon: DeployIcon },
  { key: 'item3' as const, icon: IntegrationIcon },
];

const productDocConfigs = [
  { key: 'scan' as const, icon: ScanIcon },
  { key: 'guard' as const, icon: ShieldIcon },
  { key: 'chat' as const, icon: ChatIcon },
  { key: 'trap' as const, icon: TrapIcon },
  { key: 'report' as const, icon: ReportIcon },
  { key: 'dashboard' as const, icon: AnalyticsIcon },
];

const articleKeys = [
  'article1',
  'article2',
  'article3',
  'article4',
  'article5',
  'article6',
  'article7',
  'article8',
] as const;

/* ════════════════════════  Component  ═════════════════════════ */

export default function DocsContent() {
  const t = useTranslations('docs');

  return (
    <>
      {/* ───────────── Hero ───────────── */}
      <SectionWrapper spacing="spacious">
        <SectionTitle overline={t('overline')} title={t('title')} subtitle={t('subtitle')} />

        {/* Search bar (decorative) */}
        <FadeInUp delay={0.15}>
          <div className="mt-10 flex justify-center">
            <div className="bg-surface-1 border border-border rounded-full px-5 py-3 w-full max-w-lg mx-auto flex items-center gap-3">
              <Search className="w-5 h-5 text-text-muted shrink-0" />
              <span className="text-text-muted text-sm select-none">{t('searchPlaceholder')}</span>
            </div>
          </div>
        </FadeInUp>
      </SectionWrapper>

      {/* ───────────── Quick Start Cards ───────────── */}
      <SectionWrapper>
        <FadeInUp>
          <h3 className="text-xs uppercase tracking-[0.12em] text-brand-sage font-semibold mb-8 text-center">
            {t('quickStart.title')}
          </h3>
        </FadeInUp>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-5 max-w-3xl mx-auto">
          {quickStartConfigs.map((card, i) => {
            const isGettingStarted = card.key === 'item1';
            const inner = (
              <div className="bg-surface-1 border border-border rounded-2xl p-6 card-glow h-full flex flex-col">
                <div className="w-9 h-9 rounded-lg bg-surface-2 border border-border flex items-center justify-center mb-4">
                  <card.icon className="w-4 h-4 text-brand-sage" />
                </div>
                <h4 className="text-text-primary font-semibold">
                  {t(`quickStart.${card.key}.title`)}
                </h4>
                <p className="text-sm text-text-secondary mt-2 leading-relaxed flex-1">
                  {t(`quickStart.${card.key}.desc`)}
                </p>
                {isGettingStarted ? (
                  <span className="text-brand-sage text-xs font-medium flex items-center gap-1 mt-4">
                    {t('readGuide')} &rarr;
                  </span>
                ) : (
                  <span className="text-text-muted text-xs font-medium flex items-center gap-1 mt-4">
                    {t('comingSoon')}
                  </span>
                )}
              </div>
            );
            return (
              <FadeInUp key={card.key} delay={i * 0.06}>
                {isGettingStarted ? (
                  <Link href="/docs/getting-started" className="block h-full">
                    {inner}
                  </Link>
                ) : (
                  inner
                )}
              </FadeInUp>
            );
          })}
        </div>
      </SectionWrapper>

      {/* ───────────── Product Documentation Grid ───────────── */}
      <SectionWrapper dark>
        <FadeInUp>
          <h3 className="text-xs uppercase tracking-[0.12em] text-brand-sage font-semibold mb-2 text-center">
            {t('productDocs.title')}
          </h3>
          <p className="text-text-secondary text-center mb-10">{t('productDocs.subtitle')}</p>
        </FadeInUp>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
          {productDocConfigs.map((doc, i) => (
            <FadeInUp key={doc.key} delay={i * 0.06}>
              <div className="bg-surface-1 border border-border rounded-2xl p-6 h-full flex flex-col">
                <div className="w-9 h-9 rounded-lg bg-surface-2 border border-border flex items-center justify-center mb-4">
                  <doc.icon className="w-4 h-4 text-brand-sage" />
                </div>
                <h4 className="text-text-primary font-semibold">
                  {t(`productDocs.${doc.key}.title`)}
                </h4>
                <p className="text-sm text-text-secondary mt-2 leading-relaxed flex-1">
                  {t(`productDocs.${doc.key}.desc`)}
                </p>
                <span className="text-text-muted text-xs font-medium flex items-center gap-1 mt-4">
                  {t('comingSoon')}
                </span>
              </div>
            </FadeInUp>
          ))}
        </div>
      </SectionWrapper>

      {/* ───────────── Popular Articles ───────────── */}
      <SectionWrapper>
        <FadeInUp>
          <h3 className="text-xs uppercase tracking-[0.12em] text-brand-sage font-semibold mb-2 text-center">
            {t('popularArticles.title')}
          </h3>
          <p className="text-text-secondary text-center mb-10">{t('popularArticles.subtitle')}</p>
        </FadeInUp>

        <div className="max-w-2xl mx-auto divide-y divide-border">
          {articleKeys.map((key, i) => (
            <FadeInUp key={key} delay={i * 0.04}>
              <div className="flex items-center justify-between py-4 text-text-secondary">
                <span className="text-sm">{t(`popularArticles.${key}`)}</span>
                <span className="text-text-muted text-xs shrink-0 ml-4">{t('comingSoon')}</span>
              </div>
            </FadeInUp>
          ))}
        </div>
      </SectionWrapper>

      {/* ───────────── Help CTA ───────────── */}
      <SectionWrapper dark spacing="tight" fadeBorder>
        <FadeInUp>
          <div className="text-center">
            <h3 className="text-xl font-bold text-text-primary mb-3">{t('cantFind')}</h3>
            <p className="text-text-secondary text-sm mb-6 max-w-md mx-auto leading-relaxed">
              {t('cantFindDesc')}
            </p>
            <div className="flex flex-wrap items-center justify-center gap-4">
              <Link
                href="/contact"
                className="bg-brand-sage text-surface-0 rounded-full px-6 py-2.5 text-sm font-medium hover:bg-brand-sage-light transition-colors"
              >
                {t('contactSupport')}
              </Link>
              <Link
                href="/early-access"
                className="border border-border text-text-secondary rounded-full px-6 py-2.5 text-sm font-medium hover:text-text-primary hover:border-text-muted transition-colors"
              >
                {t('earlyAccess')}
              </Link>
            </div>
          </div>
        </FadeInUp>
      </SectionWrapper>
    </>
  );
}
