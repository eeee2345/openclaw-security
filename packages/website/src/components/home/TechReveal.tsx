'use client';

import { useTranslations } from 'next-intl';
import { Shield, Layers, Brain } from 'lucide-react';
import SectionWrapper from '../ui/SectionWrapper';
import SectionTitle from '../ui/SectionTitle';
import FadeInUp from '../FadeInUp';
import Card from '../ui/Card';
import CountUp from '../animations/CountUp';

export default function TechReveal() {
  const t = useTranslations('home.techReveal');

  return (
    <SectionWrapper>
      <SectionTitle overline={t('overline')} title={t('title')} subtitle={t('subtitle')} />

      <div className="grid md:grid-cols-3 gap-6 mt-14">
        {/* Detection Engine */}
        <FadeInUp delay={0}>
          <Card padding="lg" className="h-full">
            <Shield className="w-8 h-8 text-brand-sage mb-4" />
            <h3 className="text-lg font-bold text-text-primary mb-4">{t('detection.title')}</h3>
            <div className="space-y-4">
              <div>
                <p className="text-xl font-extrabold text-text-primary">
                  <CountUp target={3155} />
                </p>
                <p className="text-sm text-brand-sage font-medium">{t('detection.sigma')}</p>
                <p className="text-xs text-text-tertiary mt-1">{t('detection.sigmaDesc')}</p>
              </div>
              <div>
                <p className="text-xl font-extrabold text-text-primary">
                  <CountUp target={5895} />
                </p>
                <p className="text-sm text-brand-sage font-medium">{t('detection.yara')}</p>
                <p className="text-xs text-text-tertiary mt-1">{t('detection.yaraDesc')}</p>
              </div>
              <div>
                <p className="text-sm text-brand-sage font-medium">{t('detection.cve')}</p>
                <p className="text-xs text-text-tertiary mt-1">{t('detection.cveDesc')}</p>
              </div>
            </div>
          </Card>
        </FadeInUp>

        {/* Defense Architecture */}
        <FadeInUp delay={0.1}>
          <Card padding="lg" className="h-full">
            <Layers className="w-8 h-8 text-brand-sage mb-4" />
            <h3 className="text-lg font-bold text-text-primary mb-1">{t('defense.title')}</h3>
            <p className="text-xs text-text-tertiary mb-4">{t('defense.subtitle')}</p>
            <div className="space-y-4">
              <div>
                <p className="text-sm font-semibold text-text-primary">{t('defense.layer1')}</p>
                <p className="text-xs text-text-tertiary mt-1">{t('defense.layer1Desc')}</p>
              </div>
              <div>
                <p className="text-sm font-semibold text-text-primary">{t('defense.layer2')}</p>
                <p className="text-xs text-text-tertiary mt-1">{t('defense.layer2Desc')}</p>
              </div>
              <div>
                <p className="text-sm font-semibold text-text-primary">{t('defense.layer3')}</p>
                <p className="text-xs text-text-tertiary mt-1">{t('defense.layer3Desc')}</p>
              </div>
            </div>
          </Card>
        </FadeInUp>

        {/* AI Pipeline */}
        <FadeInUp delay={0.2}>
          <Card padding="lg" className="h-full">
            <Brain className="w-8 h-8 text-brand-sage mb-4" />
            <h3 className="text-lg font-bold text-text-primary mb-1">{t('pipeline.title')}</h3>
            <p className="text-xs text-text-tertiary mb-4">{t('pipeline.subtitle')}</p>
            <div className="space-y-2">
              {[0, 1, 2, 3, 4].map((i) => (
                <div key={i} className="flex items-center gap-3 bg-surface-0 rounded-lg px-3 py-2">
                  <span className="text-xs font-mono text-brand-sage w-4 text-right">{i + 1}</span>
                  <span className="text-sm text-text-secondary">{t(`pipeline.agents.${i}`)}</span>
                </div>
              ))}
            </div>
            <p className="text-xs text-text-tertiary mt-4">{t('pipeline.desc')}</p>
          </Card>
        </FadeInUp>
      </div>

      {/* GitHub CTA */}
      <FadeInUp delay={0.3}>
        <p className="text-center mt-10">
          <a
            href="https://github.com/panguard-ai/panguard-ai"
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm text-brand-sage hover:underline link-reveal"
          >
            {t('githubCta')}
          </a>
        </p>
      </FadeInUp>
    </SectionWrapper>
  );
}
