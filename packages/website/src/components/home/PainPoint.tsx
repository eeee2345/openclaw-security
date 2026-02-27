'use client';

import { useTranslations } from 'next-intl';
import { motion } from 'framer-motion';
import FadeInUp from '../FadeInUp';
import SectionWrapper from '../ui/SectionWrapper';
import BrandLogo from '../ui/BrandLogo';

/** Refined ambient brand logo — metallic 3D shield with subtle glow */
function AmbientLogo() {
  return (
    <motion.div
      className="relative hidden lg:flex items-center justify-center w-[280px] h-[320px]"
      initial={{ opacity: 0 }}
      whileInView={{ opacity: 1 }}
      viewport={{ once: true, margin: '-80px' }}
      transition={{ duration: 1.2, delay: 0.3 }}
      aria-hidden="true"
    >
      {/* Layered glow backdrop */}
      <div className="absolute w-[180px] h-[180px] rounded-full bg-brand-sage/[0.03] blur-[50px]" />
      <div className="absolute w-[120px] h-[120px] rounded-full bg-brand-sage/[0.05] blur-[30px]" />

      {/* Outer subtle ring */}
      <div className="absolute w-[240px] h-[240px] rounded-full border border-brand-sage/[0.06]" />

      {/* The shield logo — large, with metallic feel */}
      <div className="relative metallic-logo-float">
        <BrandLogo size={140} className="text-brand-sage/[0.14]" bg="transparent" />
      </div>
    </motion.div>
  );
}

export default function PainPoint() {
  const t = useTranslations('home.painPoint');

  return (
    <SectionWrapper>
      <div className="grid grid-cols-1 lg:grid-cols-[1fr_auto] gap-8 lg:gap-12 items-center">
        {/* Text content */}
        <div className="max-w-2xl tracking-tight">
          <FadeInUp>
            <p className="text-lg lg:text-xl text-text-secondary leading-relaxed">{t('line1')}</p>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <p className="text-lg lg:text-xl text-text-secondary leading-relaxed mt-5">
              {t('line2')}
            </p>
          </FadeInUp>
          <FadeInUp delay={0.2}>
            <p className="text-lg lg:text-xl text-text-secondary leading-relaxed mt-5">
              {t('line3')}
            </p>
          </FadeInUp>
          <FadeInUp delay={0.3}>
            <p className="text-lg lg:text-xl text-text-secondary leading-relaxed mt-5">
              {t('line4')}
            </p>
          </FadeInUp>
          <FadeInUp delay={0.4}>
            <p className="text-lg lg:text-xl text-status-alert font-semibold leading-relaxed mt-5">
              {t('line5')}
            </p>
          </FadeInUp>
        </div>

        {/* Ambient brand logo */}
        <AmbientLogo />
      </div>
    </SectionWrapper>
  );
}
