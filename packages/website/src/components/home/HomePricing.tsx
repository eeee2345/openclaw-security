'use client';

import { useTranslations } from 'next-intl';
import { Link } from '@/navigation';
import { ArrowRight, Check } from 'lucide-react';
import { motion } from 'framer-motion';
import FadeInUp from '../FadeInUp';
import { STATS } from '@/lib/stats';

const ease = [0.22, 1, 0.36, 1] as const;

const highlights = [
  `${(STATS.totalRules).toLocaleString()}+ detection rules`,
  `${STATS.atrRules} ATR rules`,
  'Unlimited machines',
  'Threat Cloud collective immunity',
  'All notifications (Telegram, Slack, Email, LINE)',
  'Compliance reports included',
  'Full source code (MIT)',
];

export default function HomePricing() {
  const t = useTranslations('home.homePricing');

  return (
    <section id="pricing" className="bg-[#0a0a0a] px-5 sm:px-6 py-16 sm:py-24">
      <div className="max-w-3xl mx-auto">
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

        <FadeInUp>
          <div className="bg-surface-1 rounded-2xl border border-panguard-green p-8 sm:p-10 text-center">
            <div className="mb-6">
              <span className="text-5xl font-extrabold text-text-primary">$0</span>
              <span className="text-xs uppercase tracking-wider text-brand-sage font-semibold ml-3">{t('badge')}</span>
            </div>
            <p className="text-text-secondary mb-8">{t('desc')}</p>

            <div className="grid sm:grid-cols-2 gap-3 text-left max-w-lg mx-auto mb-8">
              {highlights.map((h) => (
                <div key={h} className="flex items-start gap-2.5 text-sm text-text-secondary">
                  <Check className="w-4 h-4 text-panguard-green mt-0.5 shrink-0" />
                  {h}
                </div>
              ))}
            </div>

            <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
              <Link
                href="/docs/getting-started"
                className="inline-flex items-center gap-2 bg-panguard-green text-white font-semibold rounded-full px-8 py-3.5 hover:bg-panguard-green-light transition-all duration-200 active:scale-[0.98]"
              >
                {t('cta')} <ArrowRight className="w-4 h-4" />
              </Link>
              <Link
                href="/atr"
                className="border border-border text-text-secondary hover:text-text-primary hover:border-panguard-green font-semibold rounded-full px-8 py-3.5 transition-all duration-200"
              >
                {t('ctaSecondary')}
              </Link>
            </div>
          </div>
        </FadeInUp>
      </div>
    </section>
  );
}
