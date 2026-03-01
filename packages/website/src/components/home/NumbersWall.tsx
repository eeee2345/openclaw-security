'use client';

import { useTranslations } from 'next-intl';
import { motion } from 'framer-motion';
import CountUp from '../animations/CountUp';
import FadeInUp from '../FadeInUp';
import {
  ShieldIcon,
  ScanIcon,
  CheckIcon,
  MonitorIcon,
  BlockIcon,
  NetworkIcon,
  LockIcon,
} from '@/components/ui/BrandIcons';

const ease = [0.22, 1, 0.36, 1] as const;

const statIcons = [ShieldIcon, ScanIcon, CheckIcon, MonitorIcon, ShieldIcon, BlockIcon, NetworkIcon, LockIcon];
const statValues = [3149, 4326, 50, 1446, 5, 6, 8, 'MIT'];
const statKeys = ['sigmaRules', 'yaraRules', 'controls', 'tests', 'layers', 'actions', 'protocols', 'mit'] as const;

export default function NumbersWall() {
  const t = useTranslations('home.numbersWall');

  return (
    <section className="bg-[#0c0d0c] px-6 py-12 sm:py-16">
      <div className="max-w-[1200px] mx-auto">
        {/* Title */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-60px' }}
          transition={{ duration: 0.5, ease }}
          className="text-center mb-10"
        >
          <h2 className="text-4xl md:text-5xl font-bold text-text-primary">
            {t('title')}
          </h2>
          <p className="text-lg text-gray-400 mt-4 max-w-2xl mx-auto">
            {t('subtitle')}
          </p>
        </motion.div>

        {/* Stats grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 max-w-4xl mx-auto">
          {statKeys.map((key, i) => {
            const Icon = statIcons[i];
            const val = statValues[i];
            return (
              <FadeInUp key={key} delay={i * 0.06}>
                <div className="bg-surface-1/50 border border-border rounded-xl p-4 text-center">
                  <Icon className="w-5 h-5 text-panguard-green mx-auto mb-2" />
                  <div className="text-2xl font-extrabold text-text-primary">
                    {typeof val === 'number' ? (
                      <CountUp target={val} suffix={val >= 1000 ? '' : ''} />
                    ) : (
                      val
                    )}
                  </div>
                  <p className="text-xs text-text-muted mt-1">{t(`stats.${key}`)}</p>
                </div>
              </FadeInUp>
            );
          })}
        </div>

        {/* GitHub CTA */}
        <FadeInUp delay={0.5}>
          <div className="text-center mt-8">
            <a
              href="https://github.com/panguard-ai/panguard-ai"
              target="_blank"
              rel="noopener noreferrer"
              className="text-panguard-green hover:text-panguard-green-light text-sm font-medium transition-colors"
            >
              {t('githubCta')} &rarr;
            </a>
          </div>
        </FadeInUp>

        {/* Trust cards */}
        <div className="grid sm:grid-cols-3 gap-5 mt-12 max-w-4xl mx-auto">
          {(['openSource', 'security', 'privacy'] as const).map((key, i) => (
            <FadeInUp key={key} delay={0.6 + i * 0.08}>
              <div className="bg-surface-1/50 border border-border rounded-2xl p-5">
                <h3 className="text-base font-bold text-text-primary mb-2">{t(`trust.${key}.title`)}</h3>
                <p className="text-sm text-gray-400 leading-relaxed">{t(`trust.${key}.desc`)}</p>
              </div>
            </FadeInUp>
          ))}
        </div>
      </div>
    </section>
  );
}
