'use client';

import { useTranslations } from 'next-intl';
import { motion } from 'framer-motion';
import { LockIcon } from '@/components/ui/BrandIcons';

const ease = [0.22, 1, 0.36, 1] as const;

/* ============ 3-Step Flow ============ */

function FlowSteps() {
  const t = useTranslations('home.threatCloud');
  const steps = t.raw('steps') as Array<{ label: string; sub: string }>;

  return (
    <div className="flex flex-col md:flex-row items-center justify-center gap-4 md:gap-0 mt-10">
      {steps.map((step, i) => (
        <motion.div
          key={i}
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.4, delay: i * 0.2, ease }}
          className="flex items-center gap-4"
        >
          <div className="bg-panguard-green/10 border border-panguard-green/30 rounded-xl px-6 py-4 text-center">
            <p className="text-sm font-semibold text-panguard-green">{step.label}</p>
            <p className="text-xs text-gray-500 mt-1">{step.sub}</p>
          </div>
          {i < steps.length - 1 && (
            <div className="hidden md:block w-12 h-px border-t border-dashed border-panguard-green/40" />
          )}
        </motion.div>
      ))}
    </div>
  );
}

/* ============ Flywheel Diagram ============ */

function Flywheel() {
  const t = useTranslations('home.threatCloud.flywheel');
  const nodes = t.raw('nodes') as string[];

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      whileInView={{ opacity: 1, scale: 1 }}
      viewport={{ once: true, margin: '-60px' }}
      transition={{ duration: 0.6, ease }}
      className="mt-12 flex justify-center"
    >
      <div className="relative w-full max-w-[280px] aspect-square sm:max-w-[320px] md:max-w-[400px]">
        {/* Center text */}
        <div className="absolute inset-0 flex items-center justify-center z-10">
          <p className="text-sm sm:text-base font-bold text-panguard-green text-center max-w-[140px] leading-snug">
            {t('center')}
          </p>
        </div>

        {/* Circular ring */}
        <svg className="absolute inset-0 w-full h-full" viewBox="0 0 400 400">
          <circle
            cx="200"
            cy="200"
            r="160"
            fill="none"
            stroke="rgba(107,143,113,0.2)"
            strokeWidth="1"
            strokeDasharray="8 4"
          />
          {/* Arrow indicators */}
          {[0, 72, 144, 216, 288].map((angle) => {
            const rad = (angle * Math.PI) / 180;
            const x = 200 + 160 * Math.cos(rad);
            const y = 200 + 160 * Math.sin(rad);
            return <circle key={angle} cx={x} cy={y} r="4" fill="#6B8F71" opacity="0.5" />;
          })}
        </svg>

        {/* Node labels positioned around circle */}
        {nodes.map((label, i) => {
          const angle = (i * 72 - 90) * (Math.PI / 180);
          const radius = 52;
          const x = 50 + radius * Math.cos(angle);
          const y = 50 + radius * Math.sin(angle);
          return (
            <div
              key={i}
              className="absolute text-xs text-gray-400 text-center max-w-[100px] leading-tight"
              style={{
                left: `${x}%`,
                top: `${y}%`,
                transform: 'translate(-50%, -50%)',
              }}
            >
              {label}
            </div>
          );
        })}
      </div>
    </motion.div>
  );
}

/* ============ Open Source Section ============ */

function OpenSourceSpirit() {
  const t = useTranslations('home.threatCloud.openSource');

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-60px' }}
      transition={{ duration: 0.5, ease }}
      className="mt-16 max-w-3xl mx-auto"
    >
      <h3 className="text-2xl md:text-3xl font-bold text-text-primary text-center">{t('title')}</h3>
      <p className="text-xl text-panguard-green font-medium mt-2 text-center">{t('subtitle')}</p>
      <p className="text-gray-400 mt-6 leading-relaxed">{t('desc')}</p>
      <p className="text-gray-400 mt-4 leading-relaxed">{t('belief')}</p>
      <p className="text-sm text-gray-500 font-medium mt-6 text-center">{t('proof')}</p>
    </motion.div>
  );
}

/* ============ Main ThreatCloud Component ============ */

export default function ThreatCloudSection() {
  const t = useTranslations('home.threatCloud');

  return (
    <section className="bg-gradient-to-b from-[#0d2614] to-[#0a0a0a] px-4 sm:px-6 py-16 sm:py-24">
      <div className="max-w-[1200px] mx-auto">
        {/* Overline */}
        <motion.p
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true, margin: '-60px' }}
          transition={{ duration: 0.4, ease }}
          className="text-xs uppercase tracking-[0.2em] text-panguard-green/70 font-semibold mb-4 text-center"
        >
          {t('overline')}
        </motion.p>

        {/* Title */}
        <motion.h2
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-60px' }}
          transition={{ duration: 0.5, ease }}
          className="text-3xl md:text-4xl lg:text-5xl font-bold text-text-primary text-center"
        >
          {t('title')}
        </motion.h2>

        {/* Description */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-60px' }}
          transition={{ duration: 0.5, delay: 0.15, ease }}
          className="max-w-3xl mx-auto mt-6 text-center"
        >
          <p className="text-lg text-gray-400 leading-relaxed">{t('desc')}</p>
          <p className="text-lg text-text-primary font-semibold mt-4">{t('descHighlight')}</p>
        </motion.div>

        {/* 3-step flow */}
        <FlowSteps />

        {/* Privacy disclaimer */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5, delay: 0.3, ease }}
          className="max-w-2xl mx-auto mt-10 bg-[#0a0a0a]/50 border border-panguard-green/20 rounded-xl p-5"
        >
          <div className="flex items-start gap-3">
            <LockIcon size={16} className="text-panguard-green mt-0.5 shrink-0" />
            <div className="text-sm text-gray-400 leading-relaxed space-y-2">
              <p>{t('privacy1')}</p>
              <p>{t('privacy2')}</p>
            </div>
          </div>
        </motion.div>

        {/* Flywheel */}
        <Flywheel />

        {/* Open Source Spirit */}
        <OpenSourceSpirit />
      </div>
    </section>
  );
}
