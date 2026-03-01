'use client';

import { useTranslations } from 'next-intl';
import { motion } from 'framer-motion';

const ease = [0.22, 1, 0.36, 1] as const;

export default function Redefine() {
  const t = useTranslations('home.redefine');

  return (
    <section className="bg-[#0a0a0a] px-6 py-16 sm:py-20">
      <div className="max-w-[900px] mx-auto text-center">
        {/* "Everyone asks" */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-60px' }}
          transition={{ duration: 0.5, ease }}
        >
          <p className="text-2xl md:text-3xl text-text-secondary leading-relaxed">
            {t('line1')}
          </p>
          <p className="text-2xl md:text-3xl text-text-primary font-medium leading-relaxed mt-2">
            {t('line2')}
          </p>
        </motion.div>

        {/* "We asked a different question" */}
        <motion.p
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-60px' }}
          transition={{ duration: 0.5, delay: 0.4, ease }}
          className="text-2xl md:text-3xl text-text-secondary leading-relaxed mt-10"
        >
          {t('line3')}
        </motion.p>

        {/* The green question */}
        <motion.p
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-60px' }}
          transition={{ duration: 0.6, delay: 0.8, ease }}
          className="text-3xl md:text-4xl font-bold text-panguard-green leading-normal mt-6"
        >
          {t('question')}
        </motion.p>
      </div>
    </section>
  );
}
