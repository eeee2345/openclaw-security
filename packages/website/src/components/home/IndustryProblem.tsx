'use client';

import { useTranslations } from 'next-intl';
import { motion } from 'framer-motion';

const ease = [0.22, 1, 0.36, 1] as const;

export default function IndustryProblem() {
  const t = useTranslations('home.industryProblem');

  const paragraphs = ['p1', 'p2', 'p3', 'p4'] as const;

  return (
    <section className="bg-gradient-to-b from-[#0a0a0a] to-[#120808] px-6 py-12 sm:py-16">
      <div className="max-w-[1200px] mx-auto">
        <div className="max-w-3xl mx-auto">
          {/* Title */}
          <motion.h2
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: '-60px' }}
            transition={{ duration: 0.5, ease }}
            className="text-4xl md:text-5xl font-bold text-text-primary"
          >
            {t('title')}
          </motion.h2>

          {/* Paragraphs - staggered reveal */}
          <div className="mt-8 space-y-6">
            {paragraphs.map((key, i) => (
              <motion.p
                key={key}
                initial={{ opacity: 0, y: 16 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, margin: '-40px' }}
                transition={{ duration: 0.5, delay: i * 0.15, ease }}
                className="text-lg text-gray-400 leading-relaxed"
              >
                {t(key)}
              </motion.p>
            ))}
          </div>

          {/* Red emphasis */}
          <motion.p
            initial={{ opacity: 0, y: 16 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: '-40px' }}
            transition={{ duration: 0.6, delay: 0.6, ease }}
            className="mt-8 text-xl font-semibold text-panguard-red"
          >
            {t('emphasis')}
          </motion.p>

          {/* Stats bar */}
          <motion.div
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true, margin: '-40px' }}
            transition={{ duration: 0.5, delay: 0.8, ease }}
            className="mt-8 flex flex-wrap gap-4 text-sm text-gray-600"
          >
            <span>{t('stats.attacks')}</span>
            <span className="hidden sm:inline text-gray-700">&middot;</span>
            <span>{t('stats.smb')}</span>
            <span className="hidden sm:inline text-gray-700">&middot;</span>
            <span>{t('stats.cost')}</span>
          </motion.div>
        </div>
      </div>
    </section>
  );
}
