'use client';

import { useTranslations } from 'next-intl';
import { motion } from 'framer-motion';
import { Shield, Search, ClipboardCheck, Crosshair, Globe } from 'lucide-react';

const ease = [0.22, 1, 0.36, 1] as const;

const roleIcons = [Shield, Search, ClipboardCheck, Crosshair, Globe];
const barColors = ['#6B8F71', '#8FB996', '#A8D5B0'];
const confidenceColors = {
  green: { bg: 'bg-panguard-green/10', border: 'border-panguard-green/40', dot: 'bg-panguard-green' },
  yellow: { bg: 'bg-status-caution/10', border: 'border-status-caution/40', dot: 'bg-status-caution' },
  gray: { bg: 'bg-gray-500/10', border: 'border-gray-500/40', dot: 'bg-gray-500' },
};

/* ============ S5A: 5-Person AI Security Team ============ */

function TeamSection() {
  const t = useTranslations('home.showMuscle.team');
  const roles = t.raw('roles') as Array<{ role: string; product: string; desc: string }>;

  return (
    <div>
      <motion.p
        initial={{ opacity: 0 }}
        whileInView={{ opacity: 1 }}
        viewport={{ once: true, margin: '-60px' }}
        transition={{ duration: 0.4, ease }}
        className="text-xs uppercase tracking-[0.2em] text-panguard-green/70 font-semibold mb-4"
      >
        {t('overline')}
      </motion.p>

      <motion.h2
        initial={{ opacity: 0, y: 20 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, margin: '-60px' }}
        transition={{ duration: 0.5, ease }}
        className="text-4xl md:text-5xl font-bold text-text-primary"
      >
        {t('title')}
      </motion.h2>

      <motion.p
        initial={{ opacity: 0 }}
        whileInView={{ opacity: 1 }}
        viewport={{ once: true, margin: '-60px' }}
        transition={{ duration: 0.4, delay: 0.15, ease }}
        className="text-lg text-gray-400 mt-4 max-w-2xl"
      >
        {t('subtitle')}
      </motion.p>

      {/* Role cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4 mt-10">
        {roles.map((role, i) => {
          const Icon = roleIcons[i];
          return (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 16 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.4, delay: i * 0.1, ease }}
              className="bg-surface-1/50 border border-gray-700 hover:border-[#6B8F71]/50 rounded-xl p-4 transition-all duration-200 hover:-translate-y-1"
            >
              <Icon className="w-6 h-6 text-panguard-green mb-3" />
              <p className="text-sm font-semibold text-text-primary">{role.role}</p>
              <p className="text-xs text-panguard-green mt-1">{role.product}</p>
              <p className="text-xs text-gray-500 mt-2">{role.desc}</p>
            </motion.div>
          );
        })}
      </div>

      <motion.p
        initial={{ opacity: 0 }}
        whileInView={{ opacity: 1 }}
        viewport={{ once: true }}
        transition={{ duration: 0.4, delay: 0.6, ease }}
        className="text-sm text-gray-500 mt-6"
      >
        {t('footer')}
      </motion.p>
    </div>
  );
}

/* ============ S5B: 90/7/3 AI Funnel ============ */

function FunnelSection() {
  const t = useTranslations('home.showMuscle.funnel');
  const layers = t.raw('layers') as Array<{ pct: number; label: string; sub: string; speed: string }>;

  return (
    <div className="mt-16 sm:mt-20">
      <motion.h3
        initial={{ opacity: 0, y: 20 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, margin: '-60px' }}
        transition={{ duration: 0.5, ease }}
        className="text-3xl md:text-4xl font-bold text-text-primary"
      >
        {t('title')}
      </motion.h3>

      <motion.p
        initial={{ opacity: 0 }}
        whileInView={{ opacity: 1 }}
        viewport={{ once: true, margin: '-60px' }}
        transition={{ duration: 0.4, delay: 0.15, ease }}
        className="text-lg text-gray-400 mt-4 max-w-3xl"
      >
        {t('desc')}
      </motion.p>

      {/* Bars */}
      <div className="mt-10 space-y-6">
        {layers.map((layer, i) => (
          <motion.div
            key={i}
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true, margin: '-40px' }}
            transition={{ duration: 0.4, delay: i * 0.15, ease }}
          >
            <div className="flex justify-between mb-2">
              <span className="font-medium text-text-primary">
                {layer.label}{' '}
                <span className="text-gray-500 text-sm ml-2">{layer.sub}</span>
              </span>
              <span className="font-bold text-xl text-text-primary">{layer.pct}%</span>
            </div>
            <div className="w-full h-3 bg-gray-800 rounded-full overflow-hidden">
              <motion.div
                className="h-full rounded-full"
                style={{ backgroundColor: barColors[i] }}
                initial={{ width: 0 }}
                whileInView={{ width: `${Math.max(layer.pct, 4)}%` }}
                viewport={{ once: true }}
                transition={{ duration: 0.8, delay: i * 0.2, ease }}
              />
            </div>
            <p className="text-xs text-gray-600 mt-1">{layer.speed}</p>
          </motion.div>
        ))}
      </div>

      {/* Fallback */}
      <motion.p
        initial={{ opacity: 0 }}
        whileInView={{ opacity: 1 }}
        viewport={{ once: true }}
        transition={{ duration: 0.4, delay: 0.7, ease }}
        className="text-sm text-panguard-green font-medium mt-6"
      >
        {t('fallback')}
      </motion.p>
    </div>
  );
}

/* ============ S5C: Confidence Threshold ============ */

function ConfidenceSection() {
  const t = useTranslations('home.showMuscle.confidence');
  const levels = t.raw('levels') as Array<{ threshold: string; color: string; action: string }>;

  return (
    <div className="mt-16 sm:mt-20">
      <motion.h3
        initial={{ opacity: 0, y: 20 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, margin: '-60px' }}
        transition={{ duration: 0.5, ease }}
        className="text-3xl md:text-4xl font-bold text-text-primary"
      >
        {t('title')}
      </motion.h3>

      <div className="mt-8 space-y-4">
        {levels.map((level, i) => {
          const colors = confidenceColors[level.color as keyof typeof confidenceColors];
          return (
            <motion.div
              key={i}
              initial={{ opacity: 0, x: -16 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.4, delay: i * 0.15, ease }}
              className={`flex items-start gap-4 ${colors.bg} border ${colors.border} rounded-xl p-4`}
            >
              <div className={`w-3 h-3 ${colors.dot} rounded-full mt-1.5 shrink-0`} />
              <div>
                <span className="text-sm font-bold text-text-primary">{level.threshold}</span>
                <p className="text-sm text-gray-400 mt-1">{level.action}</p>
              </div>
            </motion.div>
          );
        })}
      </div>

      <motion.p
        initial={{ opacity: 0 }}
        whileInView={{ opacity: 1 }}
        viewport={{ once: true }}
        transition={{ duration: 0.4, delay: 0.5, ease }}
        className="text-sm text-gray-500 mt-6"
      >
        {t('footer')}
      </motion.p>
    </div>
  );
}

/* ============ Main ShowMuscle Component ============ */

export default function ShowMuscle() {
  return (
    <section className="bg-gradient-to-b from-[#0a0a0a] via-[#081a0d] to-[#0d2614] px-6 py-12 sm:py-16">
      <div className="max-w-[1200px] mx-auto">
        <TeamSection />
        <FunnelSection />
        <ConfidenceSection />
      </div>
    </section>
  );
}
