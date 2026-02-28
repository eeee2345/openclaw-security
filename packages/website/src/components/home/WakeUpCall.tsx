'use client';

import { useTranslations } from 'next-intl';
import { AlertTriangle } from 'lucide-react';
import SectionWrapper from '../ui/SectionWrapper';
import FadeInUp from '../FadeInUp';
import CountUp from '../animations/CountUp';

export default function WakeUpCall() {
  const t = useTranslations('home.wakeUpCall');

  const scenarios = [
    { key: 'ransomware' as const },
    { key: 'dataBreach' as const },
  ];

  const stats = [
    { target: 39, suffix: 's', key: 'stat1' as const },
    { target: 60, suffix: '%', key: 'stat2' as const },
    { target: 197, suffix: '', key: 'stat3' as const },
    { target: 4350000, suffix: '', key: 'stat4' as const, prefix: '$' },
  ];

  return (
    <SectionWrapper dark className="bg-gradient-to-b from-[#1F1C19] to-[#261A18]">
      <FadeInUp>
        <h2 className="text-3xl lg:text-4xl font-extrabold text-text-primary text-center">
          {t('title')}
        </h2>
        <p className="text-text-secondary text-center mt-4 max-w-2xl mx-auto text-lg">
          {t('subtitle')}
        </p>
      </FadeInUp>

      {/* Scenario cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-12 max-w-4xl mx-auto">
        {scenarios.map((s, i) => (
          <FadeInUp key={s.key} delay={0.1 + i * 0.1}>
            <div className="bg-surface-0 border-l-4 border-status-danger rounded-xl p-6">
              <div className="flex items-center gap-3 mb-3">
                <AlertTriangle className="w-5 h-5 text-status-danger shrink-0" />
                <h3 className="text-lg font-bold text-text-primary">{t(`${s.key}.title`)}</h3>
              </div>
              <p className="text-sm text-text-secondary leading-relaxed">
                {t(`${s.key}.description`)}
              </p>
            </div>
          </FadeInUp>
        ))}
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-6 mt-14 max-w-4xl mx-auto">
        {stats.map((s, i) => (
          <FadeInUp key={s.key} delay={0.2 + i * 0.08}>
            <div className="text-center">
              <div className="text-3xl lg:text-4xl font-extrabold text-text-primary">
                {s.prefix && <span>{s.prefix}</span>}
                <CountUp target={s.target} suffix={s.suffix} />
              </div>
              <p className="text-xs text-text-tertiary mt-2">{t(`${s.key}.label`)}</p>
            </div>
          </FadeInUp>
        ))}
      </div>

      {/* Closing statement */}
      <FadeInUp delay={0.4}>
        <p className="text-xl text-status-danger text-center mt-14 max-w-2xl mx-auto leading-relaxed font-semibold animate-pulse-danger">
          {t('closing')}
        </p>
      </FadeInUp>
    </SectionWrapper>
  );
}
