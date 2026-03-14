'use client';

import { useTranslations } from 'next-intl';
import { motion } from 'framer-motion';
import CountUp from '../animations/CountUp';
import FadeInUp from '../FadeInUp';
import {
  ScanIcon,
  ShieldIcon,
  NetworkIcon,
  CheckIcon,
  BlockIcon,
} from '@/components/ui/BrandIcons';
import { STATS } from '@/lib/stats';

const ease = [0.22, 1, 0.36, 1] as const;

export default function EcosystemScanner() {
  const t = useTranslations('home.ecosystemScanner');
  const eco = STATS.ecosystem;

  return (
    <section className="bg-[#090a09] px-5 sm:px-6 py-16 sm:py-24 border-t border-border/30">
      <div className="max-w-[1100px] mx-auto">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-60px' }}
          transition={{ duration: 0.5, ease }}
          className="text-center mb-12"
        >
          <h2 className="text-2xl sm:text-3xl md:text-4xl font-bold text-text-primary">
            {t('title')}
          </h2>
          <p className="text-lg text-gray-400 mt-4 max-w-2xl mx-auto">
            {t('subtitle')}
          </p>
        </motion.div>

        {/* Main counter row */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 sm:gap-5 mb-8">
          {/* Discovered */}
          <FadeInUp delay={0}>
            <div className="bg-surface-1/60 border border-border rounded-2xl p-5 text-center">
              <NetworkIcon className="w-6 h-6 text-panguard-green mx-auto mb-3" />
              <div className="text-2xl sm:text-3xl font-extrabold text-text-primary">
                <CountUp target={eco.mcpSkillsDiscovered} />
              </div>
              <p className="text-xs text-text-muted mt-1">{t('discovered')}</p>
            </div>
          </FadeInUp>

          {/* Scanned */}
          <FadeInUp delay={0.08}>
            <div className="bg-surface-1/60 border border-border rounded-2xl p-5 text-center">
              <ScanIcon className="w-6 h-6 text-panguard-green mx-auto mb-3" />
              <div className="text-2xl sm:text-3xl font-extrabold text-text-primary">
                <CountUp target={eco.mcpSkillsScanned} />
              </div>
              <p className="text-xs text-text-muted mt-1">{t('scanned')}</p>
            </div>
          </FadeInUp>

          {/* Built-in Rules */}
          <FadeInUp delay={0.16}>
            <div className="bg-surface-1/60 border border-border rounded-2xl p-5 text-center">
              <ShieldIcon className="w-6 h-6 text-panguard-green mx-auto mb-3" />
              <div className="text-2xl sm:text-3xl font-extrabold text-text-primary">
                {STATS.integratedRulesDisplay}
              </div>
              <p className="text-xs text-text-muted mt-1">{t('builtInRules')}</p>
            </div>
          </FadeInUp>

          {/* ATR Rules */}
          <FadeInUp delay={0.24}>
            <div className="bg-surface-1/60 border border-border rounded-2xl p-5 text-center">
              <ShieldIcon className="w-6 h-6 text-[#DAA520] mx-auto mb-3" />
              <div className="text-2xl sm:text-3xl font-extrabold text-text-primary">
                <CountUp target={STATS.atrRules} />
              </div>
              <p className="text-xs text-text-muted mt-1">{t('atrRules')}</p>
            </div>
          </FadeInUp>
        </div>

        {/* Findings breakdown bar */}
        <FadeInUp delay={0.3}>
          <div className="bg-surface-1/40 border border-border rounded-2xl p-5 sm:p-6 max-w-3xl mx-auto">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-text-primary">{t('findingsTitle')}</h3>
              <span className="text-xs text-text-muted">
                {t('lastScan', { date: eco.lastCrawl })}
              </span>
            </div>

            {/* Stacked bar */}
            <div className="flex rounded-full overflow-hidden h-3 mb-4">
              {eco.findingsCritical > 0 && (
                <div
                  className="bg-red-500"
                  style={{ width: `${(eco.findingsCritical / eco.mcpSkillsScanned) * 100}%` }}
                  title={`CRITICAL: ${eco.findingsCritical}`}
                />
              )}
              {eco.findingsHigh > 0 && (
                <div
                  className="bg-orange-500"
                  style={{ width: `${(eco.findingsHigh / eco.mcpSkillsScanned) * 100}%` }}
                  title={`HIGH: ${eco.findingsHigh}`}
                />
              )}
              {eco.findingsMedium > 0 && (
                <div
                  className="bg-yellow-500"
                  style={{ width: `${(eco.findingsMedium / eco.mcpSkillsScanned) * 100}%` }}
                  title={`MEDIUM: ${eco.findingsMedium}`}
                />
              )}
              {eco.findingsClean > 0 && (
                <div
                  className="bg-emerald-500"
                  style={{ width: `${(eco.findingsClean / eco.mcpSkillsScanned) * 100}%` }}
                  title={`CLEAN: ${eco.findingsClean}`}
                />
              )}
            </div>

            {/* Legend */}
            <div className="flex flex-wrap gap-x-5 gap-y-1 text-xs">
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-red-500 inline-block" />
                <span className="text-text-muted">CRITICAL {eco.findingsCritical}</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-orange-500 inline-block" />
                <span className="text-text-muted">HIGH {eco.findingsHigh}</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-yellow-500 inline-block" />
                <span className="text-text-muted">MEDIUM {eco.findingsMedium}</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 inline-block" />
                <span className="text-text-muted">CLEAN {eco.findingsClean}</span>
              </span>
            </div>
          </div>
        </FadeInUp>

        {/* Rule breakdown */}
        <FadeInUp delay={0.4}>
          <div className="grid sm:grid-cols-3 gap-3 sm:gap-4 mt-6 max-w-3xl mx-auto">
            <div className="bg-surface-1/40 border border-border rounded-xl p-4 text-center">
              <div className="text-lg font-bold text-text-primary">
                <CountUp target={STATS.sigmaRules} />
              </div>
              <p className="text-xs text-text-muted mt-1">Sigma {t('rules')}</p>
            </div>
            <div className="bg-surface-1/40 border border-border rounded-xl p-4 text-center">
              <div className="text-lg font-bold text-text-primary">
                <CountUp target={STATS.yaraRules} />
              </div>
              <p className="text-xs text-text-muted mt-1">YARA {t('rules')}</p>
            </div>
            <div className="bg-surface-1/40 border border-border rounded-xl p-4 text-center">
              <div className="text-lg font-bold text-text-primary">
                <CountUp target={STATS.atrRules} />
              </div>
              <p className="text-xs text-text-muted mt-1">ATR {t('rules')}</p>
            </div>
          </div>
        </FadeInUp>

        {/* CTA */}
        <FadeInUp delay={0.5}>
          <p className="text-center text-sm text-gray-400 mt-8">
            {t('cta')}
          </p>
        </FadeInUp>
      </div>
    </section>
  );
}
