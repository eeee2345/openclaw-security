'use client';

import { useState } from 'react';
import { useTranslations, useLocale } from 'next-intl';
import { ArrowRight, ExternalLink, Download, Mail, FileText, Palette, Monitor } from 'lucide-react';
import BrandLogo from '@/components/ui/BrandLogo';
import { CertifiedSecureBadge, AIPoweredBadge } from '@/components/ui/BrandBadges';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import SectionTitle from '@/components/ui/SectionTitle';
import { pressItems, type PressItem } from '@/data/press-items';

/* ─── Helpers ─── */

function formatDate(dateStr: string, locale: string): string {
  const date = new Date(dateStr + 'T00:00:00');
  return date.toLocaleDateString(locale === 'zh' ? 'zh-TW' : 'en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
}

/* ─── Filter Tabs ─── */

type FilterTab = 'All' | 'Press Releases' | 'Coverage';

/* ─── Type Badge ─── */

function TypeBadge({ type }: { type: PressItem['type'] }) {
  const label = type === 'press-release' ? 'Press Release' : 'Coverage';
  return (
    <span className="text-[10px] uppercase tracking-wider font-semibold px-2.5 py-1 rounded-full bg-brand-sage/10 text-brand-sage">
      {label}
    </span>
  );
}

/* ─── Press Release Card ─── */

function PressReleaseCard({
  item,
  index,
  locale,
}: {
  item: PressItem;
  index: number;
  locale: string;
}) {
  return (
    <FadeInUp delay={index * 0.06}>
      <div className="bg-surface-1 border border-border rounded-2xl p-6 hover:border-brand-sage/40 transition-all duration-200 card-glow h-full flex flex-col group">
        <div className="flex items-center gap-3 mb-3">
          <TypeBadge type={item.type} />
          <span className="text-xs text-text-muted">{formatDate(item.date, locale)}</span>
        </div>

        <h3 className="text-lg font-semibold text-text-primary leading-snug group-hover:text-brand-sage transition-colors duration-200">
          {item.title}
        </h3>

        <p className="text-sm text-text-secondary mt-3 leading-relaxed flex-1">{item.excerpt}</p>

        <div className="flex items-center mt-5 pt-4 border-t border-border/50">
          <span className="flex items-center gap-1.5 text-brand-sage text-sm font-semibold group-hover:gap-2.5 transition-all duration-200 cursor-pointer">
            Read More
            <ArrowRight className="w-3.5 h-3.5" />
          </span>
        </div>
      </div>
    </FadeInUp>
  );
}

/* ─── Coverage Card ─── */

function CoverageCard({ item, index, locale }: { item: PressItem; index: number; locale: string }) {
  return (
    <FadeInUp delay={index * 0.06}>
      <div className="bg-surface-1 border border-border rounded-2xl p-6 hover:border-brand-sage/40 transition-all duration-200 card-glow h-full flex flex-col group">
        <div className="flex items-center gap-3 mb-3">
          <TypeBadge type={item.type} />
          <span className="text-xs text-text-muted">{formatDate(item.date, locale)}</span>
        </div>

        {item.source && (
          <p className="text-[11px] uppercase tracking-[0.12em] text-brand-sage font-semibold mb-2">
            {item.source}
          </p>
        )}

        <h3 className="text-lg font-semibold text-text-primary leading-snug group-hover:text-brand-sage transition-colors duration-200">
          {item.title}
        </h3>

        <p className="text-sm text-text-secondary mt-3 leading-relaxed flex-1">{item.excerpt}</p>

        <div className="flex items-center mt-5 pt-4 border-t border-border/50">
          <span className="flex items-center gap-1.5 text-brand-sage text-sm font-semibold group-hover:gap-2.5 transition-all duration-200 cursor-pointer">
            Read Article
            <ExternalLink className="w-3.5 h-3.5" />
          </span>
        </div>
      </div>
    </FadeInUp>
  );
}

/* ─── Brand Asset Card ─── */

const brandAssetIcons = [FileText, Palette, Monitor];
const brandAssetKeys = ['item1', 'item2', 'item3'] as const;

function BrandAssetCard({
  assetKey,
  icon: IconComponent,
  index,
  t,
}: {
  assetKey: string;
  icon: React.ComponentType<{ className?: string }>;
  index: number;
  t: ReturnType<typeof useTranslations>;
}) {
  return (
    <FadeInUp delay={index * 0.08}>
      <div className="bg-surface-1 border border-border rounded-2xl p-6 hover:border-brand-sage/40 transition-all duration-200 card-glow h-full flex flex-col">
        <div className="w-10 h-10 rounded-lg bg-brand-sage/10 flex items-center justify-center mb-4">
          <IconComponent className="w-5 h-5 text-brand-sage" />
        </div>

        {/* Brand asset preview */}
        <div className="flex items-center justify-center gap-4 py-4 mb-4 bg-surface-0 rounded-xl border border-border/50">
          {index === 0 && (
            <>
              <BrandLogo size={32} className="text-brand-sage" />
              <BrandLogo size={24} className="text-text-tertiary" />
              <BrandLogo size={16} className="text-text-muted" />
            </>
          )}
          {index === 1 && (
            <div className="flex gap-3">
              <div className="w-6 h-6 rounded bg-brand-sage" />
              <div className="w-6 h-6 rounded bg-[#1A1614]" />
              <div className="w-6 h-6 rounded bg-[#F5F1E8]" />
              <div className="w-6 h-6 rounded bg-[#2ED573]" />
              <div className="w-6 h-6 rounded bg-[#FBBF24]" />
              <div className="w-6 h-6 rounded bg-[#EF4444]" />
            </div>
          )}
          {index === 2 && (
            <div className="flex gap-3">
              <CertifiedSecureBadge size={36} className="opacity-50" />
              <AIPoweredBadge size={36} className="opacity-50" />
            </div>
          )}
        </div>

        <h3 className="text-lg font-semibold text-text-primary">
          {t(`brandAssets.${assetKey}.title`)}
        </h3>

        <p className="text-sm text-text-secondary mt-2 leading-relaxed flex-1">
          {t(`brandAssets.${assetKey}.desc`)}
        </p>

        <p className="text-xs text-text-muted mt-3 mb-4">
          Formats: {t(`brandAssets.${assetKey}.formats`)}
        </p>

        <a
          href="/contact"
          className="inline-flex items-center justify-center gap-2 bg-surface-2 border border-border text-text-secondary hover:text-text-primary hover:border-brand-sage/40 font-semibold rounded-full px-5 py-2.5 text-sm transition-all duration-200"
        >
          <Download className="w-4 h-4" />
          {t('requestAccess')}
        </a>
      </div>
    </FadeInUp>
  );
}

/* ════════════════════════  Press Content  ═══════════════════════ */

export default function PressContent() {
  const t = useTranslations('press');
  const locale = useLocale();

  const [activeTab, setActiveTab] = useState<FilterTab>('All');

  const filterTabs: { key: FilterTab; label: string }[] = [
    { key: 'All', label: t('filters.all') },
    { key: 'Press Releases', label: t('filters.pressReleases') },
    { key: 'Coverage', label: t('filters.coverage') },
  ];

  const filtered =
    activeTab === 'All'
      ? pressItems
      : activeTab === 'Press Releases'
        ? pressItems.filter((i) => i.type === 'press-release')
        : pressItems.filter((i) => i.type === 'coverage');

  const pressReleases = filtered.filter((i) => i.type === 'press-release');
  const coverage = filtered.filter((i) => i.type === 'coverage');

  return (
    <>
      {/* ───────────── Hero ───────────── */}
      <SectionWrapper spacing="spacious">
        <SectionTitle overline={t('overline')} title={t('title')} subtitle={t('subtitle')} />
      </SectionWrapper>

      {/* ───────────── Filter Tabs ───────────── */}
      <SectionWrapper spacing="tight">
        <FadeInUp>
          <div className="flex flex-wrap items-center gap-2 justify-center">
            {filterTabs.map((tab) => (
              <button
                key={tab.key}
                onClick={() => setActiveTab(tab.key)}
                className={`text-sm font-semibold rounded-full px-5 py-2 transition-all duration-200 ${
                  activeTab === tab.key
                    ? 'bg-brand-sage text-surface-0'
                    : 'bg-surface-1 text-text-secondary border border-border hover:border-brand-sage/40 hover:text-text-primary'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </FadeInUp>
      </SectionWrapper>

      {/* ───────────── Press Releases ───────────── */}
      {pressReleases.length > 0 && (
        <SectionWrapper>
          <FadeInUp>
            <h3 className="text-[11px] uppercase tracking-[0.12em] text-brand-sage font-semibold mb-8">
              {t('filters.pressReleases')}
            </h3>
          </FadeInUp>
          <div className="grid md:grid-cols-2 gap-6">
            {pressReleases.map((item, i) => (
              <PressReleaseCard key={item.slug} item={item} index={i} locale={locale} />
            ))}
          </div>
        </SectionWrapper>
      )}

      {/* ───────────── Media Coverage ───────────── */}
      {coverage.length > 0 && (
        <SectionWrapper dark>
          <FadeInUp>
            <h3 className="text-[11px] uppercase tracking-[0.12em] text-brand-sage font-semibold mb-8">
              {t('filters.coverage')}
            </h3>
          </FadeInUp>
          <div className="grid md:grid-cols-2 gap-6">
            {coverage.map((item, i) => (
              <CoverageCard key={item.slug} item={item} index={i} locale={locale} />
            ))}
          </div>
        </SectionWrapper>
      )}

      {/* ───────────── No Results ───────────── */}
      {filtered.length === 0 && (
        <SectionWrapper>
          <FadeInUp>
            <div className="text-center py-16">
              <p className="text-text-tertiary text-lg">
                No items in this category yet. Check back soon.
              </p>
            </div>
          </FadeInUp>
        </SectionWrapper>
      )}

      {/* ───────────── Brand Assets ───────────── */}
      <SectionWrapper dark={coverage.length === 0}>
        <SectionTitle
          overline={t('brandAssets.overline')}
          title={t('brandAssets.title')}
          subtitle={t('brandAssets.subtitle')}
        />
        <div className="grid sm:grid-cols-3 gap-6 mt-14">
          {brandAssetKeys.map((key, i) => (
            <BrandAssetCard key={key} assetKey={key} icon={brandAssetIcons[i]} index={i} t={t} />
          ))}
        </div>
      </SectionWrapper>

      {/* ───────────── Media Contact ───────────── */}
      <SectionWrapper dark={coverage.length > 0}>
        <FadeInUp>
          <div className="text-center max-w-2xl mx-auto">
            <Mail className="w-8 h-8 text-brand-sage mx-auto mb-4" />
            <h2 className="text-[clamp(28px,3vw,40px)] font-bold text-text-primary">
              {t('mediaInquiries.title')}
            </h2>
            <p className="text-text-secondary mt-4 leading-relaxed">{t('mediaInquiries.desc')}</p>
            <p className="text-brand-sage font-semibold mt-4">{t('mediaInquiries.email')}</p>
          </div>
        </FadeInUp>
        <FadeInUp delay={0.1}>
          <div className="flex justify-center mt-8">
            <a
              href={`mailto:${t('mediaInquiries.email')}`}
              className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3.5 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
            >
              <Mail className="w-4 h-4" />
              {t('mediaInquiries.cta')}
            </a>
          </div>
        </FadeInUp>
      </SectionWrapper>
    </>
  );
}
