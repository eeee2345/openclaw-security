'use client';

import { useTranslations } from 'next-intl';
import { Shield, EyeOff, Share2 } from 'lucide-react';
import SectionWrapper from '../ui/SectionWrapper';
import FadeInUp from '../FadeInUp';
import { useInViewport } from '@/hooks/useInViewport';

function FunnelBars() {
  const t = useTranslations('home.theShift');
  const [ref, inView] = useInViewport({ once: true, margin: '-80px' });

  const items = [
    { key: 'funnel1' as const, width: 90 },
    { key: 'funnel2' as const, width: 7 },
    { key: 'funnel3' as const, width: 3 },
  ];

  return (
    <div ref={ref} className="space-y-5">
      {items.map((item, i) => (
        <div key={item.key} className="group relative">
          <div className="flex justify-between items-baseline mb-2">
            <div>
              <span className="text-sm font-semibold text-text-primary">
                {t(`${item.key}.title`)}
              </span>
              <span className="text-xs text-text-tertiary ml-2">
                {t(`${item.key}.desc`)}
              </span>
            </div>
            <span className="text-lg font-extrabold text-brand-sage">
              {t(`${item.key}.percent`)}
            </span>
          </div>
          <div className="h-3 bg-surface-2 rounded-full overflow-hidden">
            <div
              className="h-full bg-brand-sage rounded-full"
              style={{
                width: inView ? `${Math.max(item.width, 4)}%` : '0%',
                transition: `width 1.2s cubic-bezier(0.25, 0.1, 0.25, 1) ${i * 0.2}s`,
              }}
            />
          </div>
          <div className="absolute left-0 right-0 top-full mt-2 px-3 py-2 bg-surface-3 border border-border rounded-lg text-xs text-text-secondary opacity-0 group-hover:opacity-100 transition-opacity duration-200 pointer-events-none z-10">
            {t(`${item.key}.tooltip`)}
          </div>
        </div>
      ))}
    </div>
  );
}

function ThreatCloudFlow() {
  const t = useTranslations('home.theShift');

  const steps = [
    { icon: Shield, label: 'Detect' },
    { icon: EyeOff, label: 'Anonymize' },
    { icon: Share2, label: 'Share' },
  ];

  return (
    <div>
      <h3 className="text-xl font-bold text-text-primary mb-3">{t('collectiveTitle')}</h3>
      <p className="text-text-secondary leading-relaxed mb-8">{t('collectiveDesc')}</p>

      {/* Flow diagram */}
      <div className="flex flex-col md:flex-row items-center justify-center gap-4 md:gap-0">
        {steps.map((step, i) => (
          <div key={step.label} className="flex flex-col md:flex-row items-center">
            {/* Node */}
            <div className="flex flex-col items-center gap-2">
              <div className="w-16 h-16 rounded-full bg-brand-sage/10 border-2 border-brand-sage/30 flex items-center justify-center">
                <step.icon className="w-7 h-7 text-brand-sage" />
              </div>
              <span className="text-sm font-semibold text-text-primary">{step.label}</span>
            </div>

            {/* Connector (not after last) */}
            {i < steps.length - 1 && (
              <>
                {/* Desktop: horizontal dashed line */}
                <div className="hidden md:block w-16 lg:w-24 mx-2">
                  <svg width="100%" height="20" viewBox="0 0 100 20" preserveAspectRatio="none">
                    <line
                      x1="0" y1="10" x2="80" y2="10"
                      stroke="rgba(139,154,142,0.4)"
                      strokeWidth="2"
                      strokeDasharray="6 4"
                      className="flow-line-dash"
                    />
                    <polygon
                      points="80,5 90,10 80,15"
                      fill="rgba(139,154,142,0.5)"
                    />
                  </svg>
                </div>
                {/* Mobile: vertical dashed line */}
                <div className="md:hidden h-8 my-1">
                  <svg width="20" height="32" viewBox="0 0 20 32">
                    <line
                      x1="10" y1="0" x2="10" y2="24"
                      stroke="rgba(139,154,142,0.4)"
                      strokeWidth="2"
                      strokeDasharray="6 4"
                      className="flow-line-dash"
                    />
                    <polygon
                      points="5,24 10,32 15,24"
                      fill="rgba(139,154,142,0.5)"
                    />
                  </svg>
                </div>
              </>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

export default function TheShift() {
  const t = useTranslations('home.theShift');

  const layers = [
    { key: 'layer1' as const },
    { key: 'layer2' as const },
    { key: 'layer3' as const },
    { key: 'layer4' as const },
    { key: 'layer5' as const },
  ];

  return (
    <SectionWrapper dark className="bg-gradient-to-b from-[#1F1C19] via-[#1D211C] to-[#1B261F]">
      {/* Blinking cursor top */}
      <FadeInUp>
        <div className="flex items-center gap-2 text-brand-sage font-mono text-sm mb-8">
          <span className="inline-block w-2 h-4 bg-brand-sage animate-pulse" />
          <span>{t('cursor')}</span>
        </div>
      </FadeInUp>

      {/* Philosophy manifesto */}
      <FadeInUp delay={0.1}>
        <div className="max-w-3xl">
          <h2 className="text-3xl lg:text-4xl font-extrabold text-text-primary leading-tight">
            {t('title')}
          </h2>
          <p className="text-xl text-text-secondary mt-6 leading-relaxed">
            {t('philosophy')}
          </p>
        </div>
      </FadeInUp>

      {/* Architecture block */}
      <FadeInUp delay={0.2}>
        <div className="mt-14 border-l-4 border-brand-sage pl-8 max-w-3xl">
          <h3 className="text-xl font-bold text-text-primary mb-6">{t('architectureTitle')}</h3>
          <div className="space-y-4">
            {layers.map((l, i) => (
              <div key={l.key} className="flex items-start gap-4">
                <div className="shrink-0 w-8 h-8 rounded-lg bg-brand-sage/10 border border-brand-sage/20 flex items-center justify-center text-sm font-bold text-brand-sage">
                  {i + 1}
                </div>
                <div>
                  <h4 className="text-text-primary font-semibold text-sm">
                    {t(`${l.key}.title`)}
                  </h4>
                  <p className="text-text-secondary text-sm mt-1 leading-relaxed">
                    {t(`${l.key}.desc`)}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </FadeInUp>

      {/* AI funnel — animated bars */}
      <FadeInUp delay={0.3}>
        <div className="mt-12 max-w-3xl">
          <h3 className="text-xl font-bold text-text-primary mb-6">{t('funnelTitle')}</h3>
          <FunnelBars />
        </div>
      </FadeInUp>

      {/* Collective defense — flow diagram */}
      <FadeInUp delay={0.35}>
        <div className="mt-12 max-w-3xl">
          <ThreatCloudFlow />
        </div>
      </FadeInUp>

      {/* Closing statement */}
      <FadeInUp delay={0.4}>
        <p className="text-2xl lg:text-3xl font-extrabold text-brand-sage text-center mt-16 text-glow-sage">
          {t('closing')}
        </p>
      </FadeInUp>
    </SectionWrapper>
  );
}
