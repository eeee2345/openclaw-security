'use client';

import { useTranslations } from 'next-intl';
import { useScrollReveal } from '@/hooks/useScrollReveal';
import SectionWrapper from '../ui/SectionWrapper';
import SectionTitle from '../ui/SectionTitle';
import FadeInUp from '../FadeInUp';

export default function The3AMStory() {
  const t = useTranslations('home.the3amStory');

  const leftSteps = ['left1', 'left2', 'left3', 'left4', 'left5', 'left6', 'left7'] as const;

  const rightSteps = ['right1', 'right2', 'right3', 'right4', 'right5'] as const;

  const leftRef = useScrollReveal({ margin: '-60px' });
  const rightRef = useScrollReveal({ margin: '-60px' });

  return (
    <SectionWrapper bg="bg-[#0a0a0a]" spacing="tight">
      <SectionTitle title={t('title')} subtitle={t('subtitle')} />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mt-12 max-w-5xl mx-auto">
        {/* Left: Without Panguard (gray, slow reveal) */}
        <div ref={leftRef} className="stagger-group">
          <div className="flex items-center gap-2 mb-6">
            <div className="w-3 h-3 rounded-full bg-status-danger" />
            <h3 className="text-base sm:text-lg font-bold text-text-secondary">{t('leftTitle')}</h3>
          </div>

          <div className="space-y-4">
            {leftSteps.map((key, i) => (
              <div
                key={key}
                className="animate-on-scroll flex gap-3 items-start"
                style={{ transitionDelay: `${0.1 + i * 0.12}s` }}
              >
                <div className="shrink-0 w-10 sm:w-12 text-xs text-text-muted font-mono pt-0.5">
                  {t(`${key}.time`)}
                </div>
                <div className="flex-1 bg-surface-1/50 border border-border rounded-lg p-3">
                  <p className="text-sm text-text-secondary">{t(`${key}.text`)}</p>
                </div>
              </div>
            ))}
          </div>

          {/* Outcome */}
          <FadeInUp delay={0.9}>
            <div className="mt-6 p-4 bg-status-danger/10 border border-status-danger/20 rounded-xl">
              <p className="text-sm text-status-danger font-semibold">{t('leftOutcome')}</p>
            </div>
          </FadeInUp>
        </div>

        {/* Right: With Panguard (green terminal, fast reveal) */}
        <div ref={rightRef} className="stagger-group">
          <div className="flex items-center gap-2 mb-6">
            <div className="w-3 h-3 rounded-full bg-status-safe" />
            <h3 className="text-base sm:text-lg font-bold text-panguard-green">
              {t('rightTitle')}
            </h3>
          </div>

          <div className="space-y-4">
            {rightSteps.map((key, i) => (
              <div
                key={key}
                className="animate-on-scroll flex gap-3 items-start"
                style={{ transitionDelay: `${0.3 + i * 0.15}s` }}
              >
                <div className="shrink-0 w-10 sm:w-12 text-xs text-panguard-green font-mono pt-0.5">
                  {t(`${key}.time`)}
                </div>
                <div className="flex-1 bg-panguard-green/5 border border-panguard-green/20 rounded-lg p-3">
                  <p className="text-sm text-text-primary">{t(`${key}.text`)}</p>
                </div>
              </div>
            ))}
          </div>

          {/* Chat bubble mockup */}
          <FadeInUp delay={0.8}>
            <div className="mt-6 p-4 bg-surface-1 border border-border rounded-xl">
              <div className="flex items-start gap-3">
                <div className="shrink-0 w-8 h-8 rounded-full bg-panguard-green/20 flex items-center justify-center text-xs font-bold text-panguard-green">
                  P
                </div>
                <div className="flex-1">
                  <p className="text-xs text-text-muted">{t('lineLabel')}</p>
                  <p className="text-sm text-text-primary mt-1 bg-[#06C755]/10 border border-[#06C755]/20 rounded-lg px-3 py-2 inline-block">
                    {t('lineMessage')}
                  </p>
                </div>
              </div>
            </div>
          </FadeInUp>

          {/* Still sleeping */}
          <FadeInUp delay={1.0}>
            <p
              className="text-center text-lg font-bold text-panguard-green mt-6 animate-bounce"
              style={{ animationDuration: '3s' }}
            >
              {t('stillSleeping')}
            </p>
          </FadeInUp>
        </div>
      </div>
    </SectionWrapper>
  );
}
