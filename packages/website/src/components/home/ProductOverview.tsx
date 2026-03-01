'use client';

import { useTranslations } from 'next-intl';
import { motion } from 'framer-motion';
import { Link } from '@/navigation';
import {
  ScanIcon,
  ShieldIcon,
  ChatIcon,
  TrapIcon,
  ReportIcon,
  GlobalIcon,
} from '@/components/ui/BrandIcons';

const ease = [0.22, 1, 0.36, 1] as const;

const productIcons = [ScanIcon, ShieldIcon, ChatIcon, TrapIcon, ReportIcon, GlobalIcon];

export default function ProductOverview() {
  const t = useTranslations('home.productOverview');
  const products = t.raw('products') as Array<{ name: string; desc: string }>;

  return (
    <section className="bg-[#0a0a0a] px-6 py-12 sm:py-16">
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

        {/* 6 product cards - 2x3 grid */}
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-5 max-w-5xl mx-auto">
          {products.map((product, i) => {
            const Icon = productIcons[i];
            const isThreatCloud = i === 5;
            return (
              <motion.div
                key={i}
                initial={{ opacity: 0, y: 16 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.4, delay: i * 0.06, ease }}
                className={`rounded-2xl border p-6 ${
                  isThreatCloud
                    ? 'border-panguard-green/40 bg-panguard-green/5'
                    : 'border-border bg-surface-1/50'
                }`}
              >
                <Icon className="w-6 h-6 text-panguard-green mb-3" />
                <h3 className="text-lg font-bold text-text-primary">{product.name}</h3>
                <p className="text-sm text-gray-400 mt-2 leading-relaxed">{product.desc}</p>
                <Link
                  href="#"
                  className="text-sm text-panguard-green hover:text-panguard-green-light font-medium mt-3 inline-block transition-colors"
                >
                  {t('learnMore')} &rarr;
                </Link>
              </motion.div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
