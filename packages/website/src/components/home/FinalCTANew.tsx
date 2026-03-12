'use client';

import { useTranslations } from 'next-intl';
import { motion } from 'framer-motion';
import { ArrowRight, Star } from 'lucide-react';
import { Link } from '@/navigation';

const ease = [0.22, 1, 0.36, 1] as const;

export default function FinalCTANew() {
  const t = useTranslations('revolution.finalCta');

  return (
    <section className="bg-gradient-to-b from-[#0a0a0a] to-[#0d2614] px-5 sm:px-6 py-16 sm:py-24">
      <div className="max-w-3xl mx-auto text-center">
        <motion.h2
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-60px' }}
          transition={{ duration: 0.5, ease }}
          className="text-2xl sm:text-3xl md:text-4xl lg:text-5xl font-bold text-text-primary"
        >
          {t('title')}
        </motion.h2>

        <motion.p
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true, margin: '-60px' }}
          transition={{ duration: 0.4, delay: 0.15, ease }}
          className="text-base sm:text-lg text-gray-400 mt-4 max-w-xl mx-auto leading-relaxed"
        >
          {t('subtitle')}
        </motion.p>

        {/* CTA Buttons */}
        <motion.div
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.4, delay: 0.3, ease }}
          className="flex flex-wrap justify-center gap-3 mt-8"
        >
          <a
            href="https://github.com/Agent-Threat-Rule/agent-threat-rules"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 bg-panguard-green text-white font-semibold rounded-full px-6 sm:px-8 py-3.5 text-sm sm:text-base hover:bg-panguard-green-light transition-all duration-200 active:scale-[0.98]"
          >
            {t('contributeATR')} <ArrowRight className="w-4 h-4" />
          </a>
          <Link
            href="/open-source"
            className="border border-border text-text-secondary hover:text-text-primary hover:border-panguard-green font-semibold rounded-full px-6 sm:px-8 py-3.5 text-sm sm:text-base transition-all duration-200"
          >
            {t('joinCommunity')}
          </Link>
          <a
            href="https://github.com/panguard-ai/panguard-ai"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 border border-border text-text-secondary hover:text-text-primary hover:border-text-tertiary font-semibold rounded-full px-6 sm:px-8 py-3.5 text-sm sm:text-base transition-all duration-200"
          >
            <Star className="w-4 h-4" /> Star on GitHub
          </a>
        </motion.div>

        {/* Bottom text */}
        <motion.p
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.4, delay: 0.4, ease }}
          className="text-sm text-text-muted mt-10 max-w-lg mx-auto leading-relaxed"
        >
          {t('bottomLine')}
        </motion.p>
      </div>
    </section>
  );
}
