'use client';

import { useTranslations } from 'next-intl';
import { motion } from 'framer-motion';
import { Check, X } from 'lucide-react';
import { Link } from '@/navigation';

const ease = [0.22, 1, 0.36, 1] as const;

const rowKeys = [
  'setup',
  'cost',
  'monitoring',
  'response',
  'learning',
  'compliance',
  'scales',
] as const;

function CellValue({ value }: { value: string }) {
  if (value === 'yes') return <Check className="w-4 h-4 text-panguard-green mx-auto" />;
  if (value === 'no') return <X className="w-4 h-4 text-gray-600 mx-auto" />;
  return <span>{value}</span>;
}

export default function ThreeRoads() {
  const t = useTranslations('home.threeRoads');

  return (
    <section className="bg-[#0e0f0e] px-4 sm:px-6 py-16 sm:py-24">
      <div className="max-w-[1200px] mx-auto">
        {/* Title */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-60px' }}
          transition={{ duration: 0.5, ease }}
          className="text-center mb-10"
        >
          <h2 className="text-2xl sm:text-4xl md:text-5xl font-bold text-text-primary">{t('title')}</h2>
          <p className="text-lg text-gray-400 mt-4 max-w-2xl mx-auto">{t('subtitle')}</p>
        </motion.div>

        {/* Comparison table - desktop */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-60px' }}
          transition={{ duration: 0.5, delay: 0.2, ease }}
          className="hidden md:block overflow-x-auto"
        >
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800">
                <th className="text-left py-4 px-4 text-gray-500 font-medium w-1/4" />
                <th className="text-center py-4 px-4 text-gray-400 font-medium w-1/4">
                  {t('columns.diy')}
                </th>
                <th className="text-center py-4 px-4 text-gray-400 font-medium w-1/4">
                  {t('columns.consultant')}
                </th>
                <th className="text-center py-4 px-4 text-panguard-green font-semibold w-1/4 border-x border-[#6B8F71]/40 bg-[#6B8F71]/5 rounded-t-lg">
                  {t('columns.panguard')}
                </th>
              </tr>
            </thead>
            <tbody>
              {rowKeys.map((key) => (
                <tr
                  key={key}
                  className="border-b border-gray-800/50 hover:bg-white/[0.02] transition-colors"
                >
                  <td className="py-3.5 px-4 text-gray-400 font-medium">
                    {t(`rows.${key}.label`)}
                  </td>
                  <td className="py-3.5 px-4 text-center text-gray-500">
                    <CellValue value={t(`rows.${key}.diy`)} />
                  </td>
                  <td className="py-3.5 px-4 text-center text-gray-500">
                    <CellValue value={t(`rows.${key}.consultant`)} />
                  </td>
                  <td className="py-3.5 px-4 text-center text-text-primary font-medium border-x border-[#6B8F71]/40 bg-[#6B8F71]/5">
                    <CellValue value={t(`rows.${key}.panguard`)} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </motion.div>

        {/* Mobile: card layout */}
        <div className="md:hidden space-y-3">
          {rowKeys.map((key, i) => (
            <motion.div
              key={key}
              initial={{ opacity: 0, y: 12 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.4, delay: i * 0.05, ease }}
              className="bg-surface-1/50 border border-border rounded-xl p-4"
            >
              <p className="text-xs text-gray-500 font-medium mb-2">{t(`rows.${key}.label`)}</p>
              <div className="grid grid-cols-3 gap-1 sm:gap-2 text-xs sm:text-sm">
                <div className="text-center px-1">
                  <p className="text-[10px] sm:text-xs text-gray-600 mb-1">{t('columns.diy')}</p>
                  <p className="text-gray-500">
                    <CellValue value={t(`rows.${key}.diy`)} />
                  </p>
                </div>
                <div className="text-center px-1">
                  <p className="text-[10px] sm:text-xs text-gray-600 mb-1">
                    {t('columns.consultant')}
                  </p>
                  <p className="text-gray-500">
                    <CellValue value={t(`rows.${key}.consultant`)} />
                  </p>
                </div>
                <div className="text-center bg-[#6B8F71]/10 rounded-lg py-1 px-1">
                  <p className="text-[10px] sm:text-xs text-panguard-green mb-1">
                    {t('columns.panguard')}
                  </p>
                  <p className="text-text-primary font-medium">
                    <CellValue value={t(`rows.${key}.panguard`)} />
                  </p>
                </div>
              </div>
            </motion.div>
          ))}
        </div>

        {/* Bottom CTA */}
        <motion.div
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.4, delay: 0.4, ease }}
          className="text-center mt-8"
        >
          <Link
            href="/docs/getting-started"
            className="text-panguard-green hover:text-panguard-green-light text-sm font-medium transition-colors"
          >
            {t('cta')} &rarr;
          </Link>
        </motion.div>
      </div>
    </section>
  );
}
