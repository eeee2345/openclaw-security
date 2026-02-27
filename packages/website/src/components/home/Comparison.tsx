'use client';
import { useTranslations } from 'next-intl';
import { X } from 'lucide-react';
import { CheckIcon } from '@/components/ui/BrandIcons';
import SectionWrapper from '../ui/SectionWrapper';
import SectionTitle from '../ui/SectionTitle';
import FadeInUp from '../FadeInUp';

function Cell({ val, highlight = false }: { val: string; highlight?: boolean }) {
  if (val === 'yes') return <CheckIcon size={16} className="text-status-safe mx-auto" />;
  if (val === 'no') return <X className="w-4 h-4 text-text-muted mx-auto" />;
  return (
    <span className={highlight ? 'text-text-primary font-medium' : 'text-text-tertiary'}>
      {val}
    </span>
  );
}

export default function Comparison() {
  const t = useTranslations('home.comparison');

  const rows = [
    { feature: t('price'), cs: t('csPrice'), def: t('defPrice'), pg: t('pgPrice') },
    { feature: t('afterDetection'), cs: t('csAfter'), def: t('defAfter'), pg: t('pgAfter') },
    { feature: t('reporting'), cs: t('csReporting'), def: t('defReporting'), pg: t('pgReporting') },
    { feature: t('developerPlan'), cs: 'no', def: 'no', pg: 'yes' },
    { feature: t('aiChat'), cs: 'no', def: 'no', pg: 'yes' },
  ];

  return (
    <SectionWrapper>
      <SectionTitle overline={t('overline')} title={t('title')} subtitle={t('subtitle')} />

      {/* Desktop table */}
      <FadeInUp delay={0.1} className="hidden md:block mt-12">
        <div className="bg-surface-1 rounded-2xl border border-border overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-surface-0">
                <th className="text-left p-4 text-text-tertiary font-medium text-xs uppercase tracking-wider">
                  {t('feature')}
                </th>
                <th className="p-4 text-text-tertiary font-medium text-xs uppercase tracking-wider">
                  {t('crowdstrike')}
                </th>
                <th className="p-4 text-text-tertiary font-medium text-xs uppercase tracking-wider">
                  {t('defender')}
                </th>
                <th className="p-4 text-text-primary font-semibold text-xs uppercase tracking-wider border-l-2 border-brand-sage">
                  {t('panguard')}
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.feature} className="border-t border-border hover:bg-surface-1/50">
                  <td className="p-4 text-text-secondary font-medium">{r.feature}</td>
                  <td className="p-4 text-center">
                    <Cell val={r.cs} />
                  </td>
                  <td className="p-4 text-center">
                    <Cell val={r.def} />
                  </td>
                  <td className="p-4 text-center border-l-2 border-brand-sage">
                    <Cell val={r.pg} highlight />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </FadeInUp>

      {/* Mobile cards */}
      <div className="md:hidden mt-12 space-y-3">
        {rows.map((r, i) => (
          <FadeInUp key={r.feature} delay={i * 0.04}>
            <div className="bg-surface-1 rounded-xl border border-border p-4">
              <p className="text-text-muted text-xs uppercase tracking-wide mb-3">{r.feature}</p>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-text-tertiary">CrowdStrike</span>
                  <span className="text-text-tertiary">
                    <Cell val={r.cs} />
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-text-tertiary">Defender</span>
                  <span className="text-text-tertiary">
                    <Cell val={r.def} />
                  </span>
                </div>
                <div className="flex justify-between pt-2 border-t border-border">
                  <span className="text-brand-sage font-medium">Panguard</span>
                  <span>
                    <Cell val={r.pg} highlight />
                  </span>
                </div>
              </div>
            </div>
          </FadeInUp>
        ))}
      </div>

      <FadeInUp delay={0.2}>
        <p className="text-text-tertiary text-sm italic mt-6 text-center max-w-2xl mx-auto">
          {t('quote')}
        </p>
      </FadeInUp>
    </SectionWrapper>
  );
}
