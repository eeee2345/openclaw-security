'use client';

import { useTranslations } from 'next-intl';
import { motion } from 'framer-motion';
import { Terminal, Shield, Users } from 'lucide-react';

const ease = [0.22, 1, 0.36, 1] as const;

const STEPS = [
  { key: 'install', icon: Terminal },
  { key: 'protect', icon: Shield },
  { key: 'contribute', icon: Users },
] as const;

export default function HowItWorksNew() {
  const t = useTranslations('revolution.howItWorks');

  return (
    <section className="bg-[#0e0f0e] px-5 sm:px-6 py-16 sm:py-24">
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

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {STEPS.map(({ key, icon: Icon }, i) => (
            <motion.div
              key={key}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: '-60px' }}
              transition={{ duration: 0.5, delay: i * 0.1, ease }}
              className="bg-surface-1/20 border border-border rounded-2xl p-6 text-center"
            >
              <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-panguard-green/10 border border-panguard-green/20 mb-4">
                <Icon className="w-5 h-5 text-panguard-green" />
              </div>
              <h3 className="text-lg font-bold text-text-primary mb-2">
                {t(`steps.${key}.title`)}
              </h3>
              <p className="text-base text-text-secondary leading-relaxed">
                {t(`steps.${key}.desc`)}
              </p>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
