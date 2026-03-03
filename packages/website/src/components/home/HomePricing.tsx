'use client';

import { useTranslations } from 'next-intl';
import { Link } from '@/navigation';
import { ArrowRight, Check, AlertTriangle } from 'lucide-react';
import { motion } from 'framer-motion';
import FadeInUp from '../FadeInUp';

const ease = [0.22, 1, 0.36, 1] as const;
const PLAN_COUNT = 4;
const FEATURE_COUNTS = [3, 4, 5, 5];
const REPORT_COUNT = 4;

export default function HomePricing() {
  const t = useTranslations('home.homePricing');

  return (
    <section id="pricing" className="bg-[#0a0a0a] px-4 sm:px-6 py-16 sm:py-24">
      <div className="max-w-[1200px] mx-auto">
        {/* Title */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-60px' }}
          transition={{ duration: 0.5, ease }}
          className="text-center mb-10"
        >
          <p className="text-xs uppercase tracking-[0.15em] text-panguard-green/70 font-semibold mb-3">
            {t('overline')}
          </p>
          <h2 className="text-2xl sm:text-3xl md:text-4xl lg:text-5xl font-bold text-text-primary">
            {t('title')}
          </h2>
          <p className="text-lg text-gray-400 mt-3">{t('subtitle')}</p>
        </motion.div>

        {/* Pricing cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
          {Array.from({ length: PLAN_COUNT }).map((_, i) => {
            const isRecommended = i === 2;
            return (
              <FadeInUp key={i} delay={i * 0.06}>
                <div
                  className={`rounded-2xl border p-6 h-full flex flex-col ${
                    isRecommended
                      ? 'border-panguard-green bg-surface-1 ring-1 ring-panguard-green/20'
                      : 'border-border bg-surface-1'
                  }`}
                >
                  {isRecommended && (
                    <span className="text-[10px] font-bold uppercase tracking-wider text-panguard-green bg-panguard-green/10 rounded-full px-2.5 py-0.5 self-start mb-3">
                      {t('recommended')}
                    </span>
                  )}
                  <h3 className="text-lg font-bold text-text-primary">{t(`plans.${i}.name`)}</h3>
                  <div className="mt-2 flex items-baseline gap-1">
                    <span className="text-3xl font-extrabold text-text-primary">
                      {t(`plans.${i}.price`)}
                    </span>
                    <span className="text-sm text-text-muted">{t(`plans.${i}.period`)}</span>
                  </div>
                  <p className="text-sm text-text-secondary mt-2">{t(`plans.${i}.desc`)}</p>
                  <ul className="mt-5 space-y-2.5 flex-1">
                    {Array.from({ length: FEATURE_COUNTS[i] }).map((_, fi) => (
                      <li key={fi} className="flex items-start gap-2 text-sm text-text-secondary">
                        <Check className="w-4 h-4 text-panguard-green shrink-0 mt-0.5" />
                        {t(`plans.${i}.features.${fi}`)}
                      </li>
                    ))}
                  </ul>
                  <Link
                    href={i === 0 ? '/docs/getting-started' : '/pricing'}
                    className={`mt-6 text-center font-semibold rounded-full px-6 py-3 transition-all duration-200 block ${
                      isRecommended
                        ? 'bg-panguard-green text-white hover:bg-panguard-green-light'
                        : 'border border-border text-text-secondary hover:text-text-primary hover:border-panguard-green'
                    }`}
                  >
                    {t(`plans.${i}.cta`)}
                  </Link>
                </div>
              </FadeInUp>
            );
          })}
        </div>

        {/* Compliance reports */}
        <FadeInUp delay={0.3}>
          <div className="mt-12 max-w-4xl mx-auto">
            <h3 className="text-lg font-bold text-text-primary text-center mb-6">
              {t('reportTitle')}
            </h3>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              {Array.from({ length: REPORT_COUNT }).map((_, i) => {
                const isBundle = i === 3;
                return (
                  <div
                    key={i}
                    className={`rounded-xl border p-5 text-center ${
                      isBundle
                        ? 'border-panguard-green/40 bg-panguard-green/5'
                        : 'border-border bg-surface-1/50'
                    }`}
                  >
                    {isBundle && t.has(`reports.${i}.badge`) && (
                      <span className="text-[10px] font-bold uppercase tracking-wider text-panguard-green bg-panguard-green/10 rounded-full px-2 py-0.5 inline-block mb-2">
                        {t(`reports.${i}.badge`)}
                      </span>
                    )}
                    <p className="text-sm font-semibold text-text-primary">
                      {t(`reports.${i}.name`)}
                    </p>
                    <p className="text-xs text-text-muted mt-1">{t(`reports.${i}.controls`)}</p>
                    <p className="text-2xl font-extrabold text-panguard-green mt-3">
                      {t(`reports.${i}.price`)}
                    </p>
                    <p className="text-xs text-panguard-red line-through opacity-70 mt-1">
                      {t(`reports.${i}.market`)}
                    </p>
                  </div>
                );
              })}
            </div>
            <p className="text-xs text-text-tertiary text-center mt-4">{t('reportNote')}</p>
            <div className="text-center mt-4">
              <Link
                href="/compliance"
                className="inline-flex items-center gap-2 text-panguard-green font-medium hover:gap-3 transition-all text-sm"
              >
                {t('reportCta')} <ArrowRight className="w-4 h-4" />
              </Link>
            </div>
          </div>
        </FadeInUp>

        {/* Disclaimer */}
        <FadeInUp delay={0.4}>
          <div className="flex items-start gap-2 justify-center mt-6">
            <AlertTriangle className="w-3.5 h-3.5 text-status-caution shrink-0 mt-0.5" />
            <p className="text-xs text-text-muted">{t('disclaimer')}</p>
          </div>
        </FadeInUp>
      </div>
    </section>
  );
}
