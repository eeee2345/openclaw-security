'use client';

import { useTranslations } from 'next-intl';
import { motion } from 'framer-motion';
import { Upload, Cpu, Send, Shield, Search, TrendingUp } from 'lucide-react';

const ease = [0.22, 1, 0.36, 1] as const;

const STEPS = [
  { key: 'installPanguard', icon: Shield },
  { key: 'detectThreats', icon: Search },
  { key: 'uploadToCloud', icon: Upload },
  { key: 'generateRules', icon: Cpu },
  { key: 'distribute', icon: Send },
  { key: 'betterProtection', icon: TrendingUp },
] as const;

export default function CommunityFlywheel() {
  const t = useTranslations('revolution.flywheel');

  return (
    <section className="bg-gradient-to-b from-[#0d2614] to-[#0a0a0a] px-5 sm:px-6 py-16 sm:py-24">
      <div className="max-w-4xl mx-auto">
        <motion.h2
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-60px' }}
          transition={{ duration: 0.5, ease }}
          className="text-2xl sm:text-3xl md:text-4xl font-bold text-text-primary text-center mb-12 sm:mb-16"
        >
          {t('title')}
        </motion.h2>

        {/* Pipeline grid */}
        <div className="grid grid-cols-3 sm:grid-cols-3 lg:grid-cols-6 gap-2.5 sm:gap-4">
          {STEPS.map(({ key, icon: Icon }, i) => (
            <motion.div
              key={key}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: '-40px' }}
              transition={{ duration: 0.4, delay: i * 0.08, ease }}
              className="relative flex flex-col items-center text-center bg-surface-1/30 border border-border rounded-xl p-4 sm:p-5"
            >
              <div className="flex items-center justify-center w-10 h-10 rounded-full bg-panguard-green/10 border border-panguard-green/20 mb-3">
                <Icon className="w-4 h-4 text-panguard-green" />
              </div>
              <span className="text-sm font-semibold text-text-primary leading-tight">
                {t(`nodes.${key}`)}
              </span>
              {/* Arrow indicator (hidden on last item) */}
              {i < STEPS.length - 1 && (
                <div className="hidden lg:block absolute -right-3 top-1/2 -translate-y-1/2 text-panguard-green/40 text-lg">
                  &rsaquo;
                </div>
              )}
            </motion.div>
          ))}
        </div>

        {/* Quote as 3 lines */}
        <motion.div
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5, delay: 0.3, ease }}
          className="mt-12 text-center max-w-2xl mx-auto space-y-2"
        >
          <p className="text-base sm:text-lg text-text-secondary leading-relaxed">
            {t('quoteLine1')}
          </p>
          <p className="text-base sm:text-lg text-text-secondary leading-relaxed">
            {t('quoteLine2')}
          </p>
          <p className="text-base sm:text-lg text-text-primary font-semibold leading-relaxed">
            {t('quoteLine3')}
          </p>
        </motion.div>
      </div>
    </section>
  );
}
