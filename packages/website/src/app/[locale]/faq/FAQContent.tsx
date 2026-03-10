'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { ChevronDown } from 'lucide-react';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import SectionTitle from '@/components/ui/SectionTitle';
import {
  ShieldIcon,
  ScanIcon,
  LockIcon,
  DeployIcon,
  SupportIcon,
} from '@/components/ui/BrandIcons';

// ---------------------------------------------------------------------------
// FAQ Item
// ---------------------------------------------------------------------------

function FAQItem({ q, a, defaultOpen }: { q: string; a: string; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen ?? false);

  return (
    <div className="border-b border-border last:border-b-0">
      <button
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        className="w-full flex items-center justify-between py-5 text-left group focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-sage focus-visible:ring-offset-2 focus-visible:ring-offset-surface-0 rounded-lg"
      >
        <span className="text-text-primary font-medium pr-4 text-[15px]">{q}</span>
        <ChevronDown
          className={`w-5 h-5 text-text-tertiary shrink-0 transition-transform duration-300 ${
            open ? 'rotate-180' : ''
          }`}
        />
      </button>
      <div
        className={`overflow-hidden transition-all duration-300 ${
          open ? 'max-h-[600px] pb-6' : 'max-h-0'
        }`}
      >
        <p className="text-sm text-text-secondary leading-relaxed whitespace-pre-line">{a}</p>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Category Section
// ---------------------------------------------------------------------------

interface CategoryDef {
  key: string;
  icon: React.ReactNode;
  count: number;
  highlightFirst?: boolean;
}

function FAQCategory({
  categoryKey,
  icon,
  count,
  highlightFirst,
}: CategoryDef & { categoryKey: string }) {
  const t = useTranslations('faqPage');

  return (
    <FadeInUp>
      <div className="rounded-2xl border border-border bg-surface-1/50 p-6 md:p-8">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 rounded-xl bg-brand-sage/10 flex items-center justify-center">
            {icon}
          </div>
          <h3 className="text-lg font-semibold text-text-primary">
            {t(`${categoryKey}.title`)}
          </h3>
        </div>

        <div>
          {Array.from({ length: count }, (_, i) => (
            <FAQItem
              key={`${categoryKey}-${i}`}
              q={t(`${categoryKey}.q${i + 1}.q`)}
              a={t(`${categoryKey}.q${i + 1}.a`)}
              defaultOpen={highlightFirst && i === 0}
            />
          ))}
        </div>
      </div>
    </FadeInUp>
  );
}

// ---------------------------------------------------------------------------
// Main Content
// ---------------------------------------------------------------------------

const categories: CategoryDef[] = [
  { key: 'security', icon: <ShieldIcon size={20} className="text-brand-sage" />, count: 4, highlightFirst: true },
  { key: 'detection', icon: <ScanIcon size={20} className="text-brand-sage" />, count: 4 },
  { key: 'privacy', icon: <LockIcon size={20} className="text-brand-sage" />, count: 3 },
  { key: 'deployment', icon: <DeployIcon size={20} className="text-brand-sage" />, count: 3 },
  { key: 'general', icon: <SupportIcon size={20} className="text-brand-sage" />, count: 3 },
];

export default function FAQContent() {
  const t = useTranslations('faqPage');

  return (
    <>
      {/* Hero */}
      <section className="pt-24 pb-4 px-6 text-center">
        <FadeInUp>
          <p className="text-[11px] uppercase tracking-[0.12em] text-brand-sage font-semibold mb-4">
            {t('hero.overline')}
          </p>
          <h1 className="text-[clamp(30px,5vw,56px)] font-bold text-text-primary leading-[1.08] max-w-3xl mx-auto">
            {t('hero.title')}
          </h1>
          <p className="text-text-secondary mt-4 text-lg max-w-xl mx-auto leading-relaxed">
            {t('hero.subtitle')}
          </p>
        </FadeInUp>
      </section>

      {/* FAQ Categories */}
      <SectionWrapper>
        <div className="space-y-8">
          {categories.map((cat) => (
            <FAQCategory key={cat.key} categoryKey={cat.key} icon={cat.icon} count={cat.count} highlightFirst={cat.highlightFirst} />
          ))}
        </div>
      </SectionWrapper>

      {/* Still have questions */}
      <SectionWrapper dark spacing="tight">
        <SectionTitle
          title={t('cta.title')}
          subtitle={t('cta.subtitle')}
        />
        <FadeInUp>
          <div className="flex justify-center mt-8 gap-4">
            <a
              href="https://github.com/panguard-ai/panguard"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 px-6 py-3 rounded-full text-sm font-semibold hover:bg-sage-light transition-colors"
            >
              {t('cta.github')}
            </a>
            <a
              href="/contact"
              className="inline-flex items-center gap-2 border border-border text-text-primary px-6 py-3 rounded-full text-sm font-semibold hover:border-brand-sage hover:text-brand-sage transition-colors"
            >
              {t('cta.contact')}
            </a>
          </div>
        </FadeInUp>
      </SectionWrapper>
    </>
  );
}
