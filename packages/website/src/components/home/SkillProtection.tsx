'use client';

import { useTranslations } from 'next-intl';
import { motion } from 'framer-motion';
import { X, Check, Shield } from 'lucide-react';

const ease = [0.22, 1, 0.36, 1] as const;

export default function SkillProtection() {
  const t = useTranslations('revolution.skillProtection');

  const withoutItems = t.raw('without.items') as string[];
  const withItems = t.raw('with.items') as string[];

  return (
    <section className="bg-[#0a0a0a] px-5 sm:px-6 py-16 sm:py-24">
      <div className="max-w-5xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-60px' }}
          transition={{ duration: 0.5, ease }}
          className="text-center mb-12"
        >
          <div className="inline-flex items-center gap-2 bg-panguard-green/10 border border-panguard-green/20 rounded-full px-4 py-1.5 mb-6">
            <Shield className="w-4 h-4 text-panguard-green" />
            <span className="text-xs font-semibold text-panguard-green uppercase tracking-wider">
              Skill Security
            </span>
          </div>
          <h2 className="text-2xl sm:text-3xl md:text-4xl font-bold text-text-primary">
            {t('title')}
          </h2>
          <p className="text-base sm:text-lg text-gray-400 mt-4 max-w-2xl mx-auto leading-relaxed">
            {t('subtitle')}
          </p>
        </motion.div>

        {/* Comparison Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">
          {/* Without Panguard */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true, margin: '-60px' }}
            transition={{ duration: 0.5, delay: 0.1, ease }}
            className="bg-red-500/5 border border-red-500/15 rounded-2xl p-6 md:p-8"
          >
            <div className="flex items-center gap-2 mb-6">
              <X className="w-5 h-5 text-red-400" />
              <h3 className="text-lg font-bold text-red-400">
                {t('without.label')}
              </h3>
            </div>
            <ul className="space-y-4">
              {withoutItems.map((item, i) => (
                <li key={i} className="flex items-start gap-3">
                  <X className="w-4 h-4 text-red-400/60 mt-0.5 shrink-0" />
                  <span className="text-sm text-text-muted leading-relaxed">{item}</span>
                </li>
              ))}
            </ul>
          </motion.div>

          {/* With Panguard */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true, margin: '-60px' }}
            transition={{ duration: 0.5, delay: 0.2, ease }}
            className="bg-panguard-green/5 border border-panguard-green/20 rounded-2xl p-6 md:p-8"
          >
            <div className="flex items-center gap-2 mb-6">
              <Check className="w-5 h-5 text-panguard-green" />
              <h3 className="text-lg font-bold text-panguard-green">
                {t('with.label')}
              </h3>
            </div>
            <ul className="space-y-4">
              {withItems.map((item, i) => (
                <li key={i} className="flex items-start gap-3">
                  <Check className="w-4 h-4 text-panguard-green/60 mt-0.5 shrink-0" />
                  <span className="text-sm text-text-secondary leading-relaxed">{item}</span>
                </li>
              ))}
            </ul>
          </motion.div>
        </div>

        {/* Bottom line */}
        <motion.p
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5, delay: 0.4, ease }}
          className="text-center text-sm text-panguard-green font-semibold mt-8"
        >
          {t('bottomLine')}
        </motion.p>
      </div>
    </section>
  );
}
