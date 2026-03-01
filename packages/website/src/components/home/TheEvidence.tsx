'use client';

import { useTranslations } from 'next-intl';
import { ExternalLink } from 'lucide-react';
import SectionWrapper from '../ui/SectionWrapper';
import SectionTitle from '../ui/SectionTitle';
import FadeInUp from '../FadeInUp';
import CountUp from '../animations/CountUp';

const statsGrid = [
  { target: 3149, suffix: '', key: 'sigmaRules' as const },
  { target: 4326, suffix: '', key: 'yaraRules' as const },
  { target: 50, suffix: '', key: 'controls' as const },
  { target: 1446, suffix: '', key: 'tests' as const },
  { target: 5, suffix: '', key: 'layers' as const },
  { target: 6, suffix: '', key: 'actions' as const },
  { target: 8, suffix: '', key: 'protocols' as const },
  { target: 0, suffix: '', key: 'mit' as const, isMIT: true },
];

const trustCards = ['openSource', 'security', 'privacy'] as const;

export default function TheEvidence() {
  const t = useTranslations('home.theEvidence');

  return (
    <SectionWrapper dark>
      <SectionTitle title={t('title')} subtitle={t('subtitle')} />

      {/* Part A: Stats grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-12 max-w-4xl mx-auto">
        {statsGrid.map((s, i) => (
          <FadeInUp key={s.key} delay={i * 0.05}>
            <div className="bg-surface-0 rounded-xl p-5 border border-border text-center">
              <div className="text-2xl lg:text-3xl font-extrabold text-text-primary">
                {s.isMIT ? (
                  <span>MIT</span>
                ) : (
                  <CountUp target={s.target} suffix={s.suffix} />
                )}
              </div>
              <p className="text-xs text-text-tertiary mt-1">{t(`stats.${s.key}`)}</p>
            </div>
          </FadeInUp>
        ))}
      </div>

      {/* GitHub CTA */}
      <FadeInUp delay={0.4}>
        <div className="text-center mt-8">
          <a
            href="https://github.com/panguard-ai/panguard-ai"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 text-sm text-brand-sage hover:text-brand-sage-light transition-colors font-medium"
          >
            {t('githubCta')} <ExternalLink className="w-3 h-3" />
          </a>
        </div>
      </FadeInUp>

      {/* Part B: Trust cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-14 max-w-4xl mx-auto">
        {trustCards.map((key, i) => (
          <FadeInUp key={key} delay={0.1 + i * 0.08}>
            <div className="bg-surface-0 rounded-xl p-6 border border-border card-glow">
              <h3 className="text-base font-bold text-text-primary mb-2">
                {t(`trust.${key}.title`)}
              </h3>
              <p className="text-sm text-text-secondary leading-relaxed">
                {t(`trust.${key}.desc`)}
              </p>
            </div>
          </FadeInUp>
        ))}
      </div>
    </SectionWrapper>
  );
}
