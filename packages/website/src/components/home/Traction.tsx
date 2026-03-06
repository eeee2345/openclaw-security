'use client';

import { useTranslations } from 'next-intl';
import FadeInUp from '../FadeInUp';
import CountUp from '../animations/CountUp';
import { STATS } from '@/lib/stats';

interface MetricItem {
  label: string;
  value: number | string;
  suffix?: string;
}

export default function Traction() {
  const t = useTranslations('home');

  const metrics: readonly MetricItem[] = [
    { label: t('traction.tests'), value: STATS.testsPassing },
    { label: t('traction.rules'), value: STATS.totalRules },
    { label: t('traction.cli'), value: STATS.cliCommands },
    { label: t('traction.products'), value: STATS.products },
    { label: t('traction.mcp'), value: STATS.mcpTools },
    { label: t('traction.license'), value: STATS.license },
  ] as const;
  return (
    <section className="bg-[#080808] px-4 sm:px-6 py-16 sm:py-24">
      <div className="max-w-[1200px] mx-auto">
        {/* Title */}
        <FadeInUp>
          <div className="text-center mb-10">
            <h2 className="text-2xl sm:text-3xl md:text-4xl lg:text-5xl font-bold text-text-primary">
              {t('traction.title')}
            </h2>
            <p className="text-lg text-gray-400 mt-4 max-w-2xl mx-auto">
              {t('traction.subtitle')}
            </p>
          </div>
        </FadeInUp>

        {/* Metrics grid */}
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5 sm:gap-4 max-w-3xl mx-auto">
          {metrics.map((metric, i) => (
            <FadeInUp key={metric.label} delay={i * 0.08}>
              <div className="bg-surface-1/50 border border-border rounded-2xl p-4 sm:p-6 text-center">
                <div className="text-xl sm:text-3xl font-extrabold text-text-primary">
                  {typeof metric.value === 'number' ? (
                    <CountUp target={metric.value} suffix={metric.suffix ?? ''} />
                  ) : (
                    <span className="text-panguard-green">{metric.value}</span>
                  )}
                </div>
                <p className="text-sm text-gray-400 mt-2">{metric.label}</p>
              </div>
            </FadeInUp>
          ))}
        </div>

        {/* Note */}
        <FadeInUp delay={0.6}>
          <p className="text-center text-sm text-gray-500 mt-8 max-w-lg mx-auto">
            {t('traction.note')}
          </p>
        </FadeInUp>
      </div>
    </section>
  );
}
