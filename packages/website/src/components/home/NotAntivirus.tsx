'use client';

import { useTranslations } from 'next-intl';
import { motion } from 'framer-motion';
import { Shield, Activity, Radio, Brain, Users, Wrench } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

const ease = [0.22, 1, 0.36, 1] as const;

interface DiffRow {
  key: string;
  icon: LucideIcon;
}

const rows: DiffRow[] = [
  { key: 'detection', icon: Shield },
  { key: 'scope', icon: Activity },
  { key: 'defense', icon: Radio },
  { key: 'intelligence', icon: Brain },
  { key: 'response', icon: Wrench },
  { key: 'audience', icon: Users },
];

export default function NotAntivirus() {
  const t = useTranslations('home.notAntivirus');

  return (
    <section className="bg-gradient-to-b from-[#120808] to-[#0e0f0e] px-4 sm:px-6 py-16 sm:py-24">
      <div className="max-w-[1200px] mx-auto">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-60px' }}
          transition={{ duration: 0.5, ease }}
          className="max-w-3xl mx-auto text-center mb-10"
        >
          <p className="text-sm font-medium tracking-widest uppercase text-panguard-green mb-3">
            {t('overline')}
          </p>
          <h2 className="text-2xl sm:text-3xl md:text-4xl lg:text-5xl font-bold text-text-primary">
            {t('title')}
          </h2>
          <p className="text-base sm:text-lg text-gray-400 mt-4 leading-relaxed">{t('subtitle')}</p>
        </motion.div>

        {/* Comparison table - desktop */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-60px' }}
          transition={{ duration: 0.5, delay: 0.15, ease }}
          className="hidden md:block overflow-x-auto"
        >
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800">
                <th className="text-left py-4 px-4 text-gray-500 font-medium w-1/3" />
                <th className="text-center py-4 px-4 text-gray-400 font-medium w-1/3">
                  {t('columns.antivirus')}
                </th>
                <th className="text-center py-4 px-4 text-panguard-green font-semibold w-1/3 border-x border-[#6B8F71]/40 bg-[#6B8F71]/5 rounded-t-lg">
                  {t('columns.panguard')}
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ key, icon: Icon }) => (
                <tr
                  key={key}
                  className="border-b border-gray-800/50 hover:bg-white/[0.02] transition-colors"
                >
                  <td className="py-3.5 px-4 text-gray-400 font-medium">
                    <span className="inline-flex items-center gap-2">
                      <Icon className="w-4 h-4 text-gray-600 shrink-0" />
                      {t(`rows.${key}.label`)}
                    </span>
                  </td>
                  <td className="py-3.5 px-4 text-center text-gray-500">
                    {t(`rows.${key}.antivirus`)}
                  </td>
                  <td className="py-3.5 px-4 text-center text-text-primary font-medium border-x border-[#6B8F71]/40 bg-[#6B8F71]/5">
                    {t(`rows.${key}.panguard`)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </motion.div>

        {/* Mobile: card layout */}
        <div className="md:hidden space-y-3">
          {rows.map(({ key, icon: Icon }, i) => (
            <motion.div
              key={key}
              initial={{ opacity: 0, y: 12 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.4, delay: i * 0.05, ease }}
              className="bg-surface-1/50 border border-border rounded-xl p-4"
            >
              <p className="text-xs text-gray-500 font-medium mb-2 flex items-center gap-1.5">
                <Icon className="w-3.5 h-3.5" />
                {t(`rows.${key}.label`)}
              </p>
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div>
                  <p className="text-[11px] sm:text-xs text-gray-600 mb-1">
                    {t('columns.antivirus')}
                  </p>
                  <p className="text-gray-500">{t(`rows.${key}.antivirus`)}</p>
                </div>
                <div className="bg-[#6B8F71]/10 rounded-lg px-2 py-1">
                  <p className="text-[11px] sm:text-xs text-panguard-green mb-1">
                    {t('columns.panguard')}
                  </p>
                  <p className="text-text-primary font-medium">{t(`rows.${key}.panguard`)}</p>
                </div>
              </div>
            </motion.div>
          ))}
        </div>

        {/* Bottom note */}
        <motion.p
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.4, delay: 0.4, ease }}
          className="text-center mt-8 text-sm text-gray-500 max-w-2xl mx-auto leading-relaxed"
        >
          {t('footnote')}
        </motion.p>
      </div>
    </section>
  );
}
