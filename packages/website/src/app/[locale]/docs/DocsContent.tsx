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
  { key: 'item1' as const, icon: TerminalIcon, href: '/docs/getting-started' },
  { key: 'cliRef' as const, icon: TerminalIcon, href: '/docs/cli' },
  { key: 'item3' as const, icon: IntegrationIcon, href: '/docs/api' },
  { key: 'benchmark' as const, icon: AnalyticsIcon, href: '/docs/benchmark' },
];

const productDocConfigs = [
  { key: 'scan' as const, icon: ScanIcon, href: '/docs/scan' },
  { key: 'guard' as const, icon: ShieldIcon, href: '/docs/guard' },
  { key: 'chat' as const, icon: ChatIcon, href: '/docs/chat' },
  { key: 'trap' as const, icon: TrapIcon, href: '/docs/trap' },
  { key: 'report' as const, icon: ReportIcon, href: '/docs/report' },
  { key: 'skillAuditor' as const, icon: AnalyticsIcon, href: '/docs/skill-auditor' },
];

const guideConfigs = [
  { key: 'deployment' as const, icon: DeployIcon, href: '/docs/deployment' },
  { key: 'advancedSetup' as const, icon: IntegrationIcon, href: '/docs/advanced-setup' },
];

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
          {quickStartConfigs.map((card, i) => (
            <FadeInUp key={card.key} delay={i * 0.06}>
              <Link href={card.href} className="block h-full">
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
                  <span className="text-brand-sage text-xs font-medium flex items-center gap-1 mt-4">
                    {t('readGuide')} &rarr;
                  </span>
                </div>
              </Link>
            </FadeInUp>
          ))}
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
              <Link href={doc.href} className="block h-full">
                <div className="bg-surface-1 border border-border rounded-2xl p-6 h-full flex flex-col card-glow">
                  <div className="w-9 h-9 rounded-lg bg-surface-2 border border-border flex items-center justify-center mb-4">
                    <doc.icon className="w-4 h-4 text-brand-sage" />
                  </div>
                  <h4 className="text-text-primary font-semibold">
                    {t(`productDocs.${doc.key}.title`)}
                  </h4>
                  <p className="text-sm text-text-secondary mt-2 leading-relaxed flex-1">
                    {t(`productDocs.${doc.key}.desc`)}
                  </p>
                  <span className="text-brand-sage text-xs font-medium flex items-center gap-1 mt-4">
                    {t('readGuide')} &rarr;
                  </span>
                </div>
              </Link>
            </FadeInUp>
          ))}
        </div>
      </SectionWrapper>

      {/* ───────────── Guides ───────────── */}
      <SectionWrapper>
        <FadeInUp>
          <h3 className="text-xs uppercase tracking-[0.12em] text-brand-sage font-semibold mb-2 text-center">
            {t('guides.title')}
          </h3>
          <p className="text-text-secondary text-center mb-10">{t('guides.subtitle')}</p>
        </FadeInUp>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-5 max-w-3xl mx-auto">
          {guideConfigs.map((guide, i) => (
            <FadeInUp key={guide.key} delay={i * 0.06}>
              <Link href={guide.href} className="block h-full">
                <div className="bg-surface-1 border border-border rounded-2xl p-6 card-glow h-full flex flex-col">
                  <div className="w-9 h-9 rounded-lg bg-surface-2 border border-border flex items-center justify-center mb-4">
                    <guide.icon className="w-4 h-4 text-brand-sage" />
                  </div>
                  <h4 className="text-text-primary font-semibold">
                    {t(`guides.${guide.key}.title`)}
                  </h4>
                  <p className="text-sm text-text-secondary mt-2 leading-relaxed flex-1">
                    {t(`guides.${guide.key}.desc`)}
                  </p>
                  <span className="text-brand-sage text-xs font-medium flex items-center gap-1 mt-4">
                    {t('readGuide')} &rarr;
                  </span>
                </div>
              </Link>
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
                href="/docs/getting-started"
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
