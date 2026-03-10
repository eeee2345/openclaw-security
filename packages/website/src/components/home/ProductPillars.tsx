'use client';

import { useTranslations } from 'next-intl';
import { motion } from 'framer-motion';
import { FileText, Globe, Shield, ArrowRight } from 'lucide-react';
import { Link } from '@/navigation';

const ease = [0.22, 1, 0.36, 1] as const;

const PILLARS = [
  { key: 'atrStandard', icon: FileText, href: '/atr' },
  { key: 'threatCloud', icon: Globe, href: '/threat-cloud' },
  { key: 'guard', icon: Shield, href: '/product/guard' },
] as const;

export default function ProductPillars() {
  const t = useTranslations('revolution.productPillars');

  return (
    <section className="bg-[#0a0a0a] px-5 sm:px-6 py-12 sm:py-16">
      <div className="max-w-5xl mx-auto">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 sm:gap-6">
          {PILLARS.map(({ key, icon: Icon, href }, i) => (
            <motion.div
              key={key}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: '-40px' }}
              transition={{ duration: 0.5, delay: i * 0.1, ease }}
            >
              <Link
                href={href}
                className="group block bg-surface-1/40 backdrop-blur-sm border border-border hover:border-panguard-green/40 rounded-2xl p-6 sm:p-8 transition-all duration-300 h-full"
              >
                <div className="flex items-center justify-center w-12 h-12 rounded-full bg-panguard-green/10 border border-panguard-green/20 mb-5">
                  <Icon className="w-5 h-5 text-panguard-green" />
                </div>
                <h3 className="text-lg font-bold text-text-primary mb-2">
                  {t(`${key}.title`)}
                </h3>
                <p className="text-sm text-text-secondary leading-relaxed mb-4">
                  {t(`${key}.desc`)}
                </p>
                <span className="inline-flex items-center gap-1.5 text-sm text-panguard-green font-medium group-hover:gap-2.5 transition-all duration-200">
                  {t(`${key}.link`)}
                  <ArrowRight className="w-3.5 h-3.5" />
                </span>
              </Link>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
