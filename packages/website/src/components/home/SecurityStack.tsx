'use client';

import { useTranslations } from 'next-intl';
import { motion } from 'framer-motion';
import { Check } from 'lucide-react';

const ease = [0.22, 1, 0.36, 1] as const;

export default function SecurityStack() {
  const t = useTranslations('revolution.securityStack');

  const preItems = t.raw('preDeployment.items') as string[];
  const postItems = t.raw('postDeployment.items') as string[];

  return (
    <section className="bg-[#0a0a0a] px-5 sm:px-6 py-16 sm:py-24">
      <div className="max-w-4xl mx-auto">
        <motion.h2
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-60px' }}
          transition={{ duration: 0.5, ease }}
          className="text-3xl md:text-4xl font-bold text-text-primary text-center"
        >
          {t('title')}
        </motion.h2>

        <div className="mt-10 max-w-3xl mx-auto text-center space-y-4">
          <motion.p
            initial={{ opacity: 0, y: 16 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: '-60px' }}
            transition={{ duration: 0.5, delay: 0.1, ease }}
            className="text-base sm:text-lg text-text-secondary leading-relaxed"
          >
            {t('intro')}
          </motion.p>

          <motion.p
            initial={{ opacity: 0, y: 16 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: '-60px' }}
            transition={{ duration: 0.5, delay: 0.2, ease }}
            className="text-base sm:text-lg text-text-primary leading-relaxed"
          >
            {t('but')}
          </motion.p>

          <motion.p
            initial={{ opacity: 0, y: 16 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: '-60px' }}
            transition={{ duration: 0.5, delay: 0.3, ease }}
            className="text-lg sm:text-xl text-text-primary font-semibold leading-relaxed"
          >
            {t('conclusion')}
          </motion.p>
        </div>

        <div className="mt-12 grid grid-cols-1 md:grid-cols-2 gap-6 max-w-4xl mx-auto">
          {/* Pre-deployment card */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true, margin: '-60px' }}
            transition={{ duration: 0.5, delay: 0.2, ease }}
            className="bg-surface-1/30 border border-border rounded-2xl p-6"
          >
            <span className="text-xs uppercase tracking-wider text-text-muted font-semibold">
              {t('preDeployment.label')}
            </span>
            <h3 className="text-lg font-semibold text-text-primary mt-2">
              {t('preDeployment.title')}
            </h3>
            <p className="text-sm text-panguard-green font-mono mt-1">
              {t('preDeployment.tools')}
            </p>
            <ul className="mt-4 space-y-3">
              {preItems.map((item, i) => (
                <li key={i} className="flex items-start gap-2">
                  <Check className="w-4 h-4 text-text-muted mt-0.5 shrink-0" />
                  <span className="text-base text-text-secondary leading-relaxed">{item}</span>
                </li>
              ))}
            </ul>
          </motion.div>

          {/* Post-deployment card */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true, margin: '-60px' }}
            transition={{ duration: 0.5, delay: 0.3, ease }}
            className="bg-panguard-green/5 border border-panguard-green/30 rounded-2xl p-6 card-glow"
          >
            <span className="text-xs uppercase tracking-wider text-panguard-green font-semibold">
              {t('postDeployment.label')}
            </span>
            <h3 className="text-lg font-semibold text-text-primary mt-2">
              {t('postDeployment.title')}
            </h3>
            <p className="text-sm text-panguard-green font-mono mt-1">
              {t('postDeployment.tools')}
            </p>
            <ul className="mt-4 space-y-3">
              {postItems.map((item, i) => (
                <li key={i} className="flex items-start gap-2">
                  <Check className="w-4 h-4 text-panguard-green mt-0.5 shrink-0" />
                  <span className="text-base text-text-secondary leading-relaxed">{item}</span>
                </li>
              ))}
            </ul>
          </motion.div>
        </div>

        <motion.p
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5, delay: 0.4, ease }}
          className="text-2xl font-bold text-center text-text-primary mt-8"
        >
          {t('bottomLine')}
        </motion.p>
      </div>
    </section>
  );
}
