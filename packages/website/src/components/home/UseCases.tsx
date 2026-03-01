'use client';

import { useTranslations } from 'next-intl';
import { motion } from 'framer-motion';
import { Code, Rocket, Building2, ShoppingCart } from 'lucide-react';

const ease = [0.22, 1, 0.36, 1] as const;

const scenarioIcons = [Code, Rocket, Building2, ShoppingCart];

export default function UseCases() {
  const t = useTranslations('home.useCases');
  const scenarios = t.raw('scenarios') as Array<{
    type: string;
    detail: string;
    pain: string;
    result: string;
    products: string;
    cost: string;
    saved: string;
  }>;

  return (
    <section id="use-cases" className="bg-[#0e0f0e] px-4 sm:px-6 py-12 sm:py-16">
      <div className="max-w-[1200px] mx-auto">
        {/* Title */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-60px' }}
          transition={{ duration: 0.5, ease }}
          className="text-center mb-10"
        >
          <p className="text-xs uppercase tracking-[0.15em] text-panguard-green/70 font-semibold mb-3">
            {t('overline')}
          </p>
          <h2 className="text-2xl sm:text-3xl md:text-4xl lg:text-5xl font-bold text-text-primary">
            {t('title')}
          </h2>
        </motion.div>

        {/* 2x2 grid */}
        <div className="grid sm:grid-cols-2 gap-5 max-w-4xl mx-auto">
          {scenarios.map((s, i) => {
            const Icon = scenarioIcons[i];
            return (
              <motion.div
                key={i}
                initial={{ opacity: 0, y: 16 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.4, delay: i * 0.08, ease }}
                className="bg-surface-1/50 border border-border rounded-2xl p-6 h-full flex flex-col"
              >
                {/* Header */}
                <div className="flex items-center gap-3 mb-4">
                  <Icon className="w-5 h-5 text-panguard-green shrink-0" />
                  <span className="text-sm font-semibold text-text-primary">{s.type}</span>
                  <span className="text-xs text-text-muted">&middot; {s.detail}</span>
                </div>

                {/* Pain point */}
                <p className="text-sm text-gray-500 leading-relaxed">{s.pain}</p>

                {/* Result */}
                <p className="text-sm text-text-primary leading-relaxed mt-3 flex-1">{s.result}</p>

                {/* Tags */}
                <div className="flex flex-wrap gap-2 mt-4">
                  <span className="text-[10px] uppercase font-bold text-panguard-green bg-panguard-green/10 rounded-full px-2.5 py-1">
                    {s.products}
                  </span>
                  <span className="text-[10px] uppercase font-bold text-text-tertiary bg-surface-0 rounded-full px-2.5 py-1 border border-border">
                    {s.cost}
                  </span>
                  <span className="text-[10px] uppercase font-bold text-panguard-green bg-panguard-green/5 rounded-full px-2.5 py-1 border border-panguard-green/20">
                    {s.saved}
                  </span>
                </div>
              </motion.div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
