'use client';
import { motion } from 'framer-motion';
import { useTranslations } from 'next-intl';
import { Link } from '@/navigation';
import { ShieldIcon } from '@/components/ui/BrandIcons';
import {
  CertifiedSecureBadge,
  ZeroTrustBadge,
  ProtectedByBadge,
  AIPoweredBadge,
  MonitoringBadge,
} from '@/components/ui/BrandBadges';
import FadeInUp from '../FadeInUp';

export default function FinalCTA() {
  const t = useTranslations('home.finalCta');
  const tc = useTranslations('common');

  const badges = [
    { badge: CertifiedSecureBadge, label: t('iso') },
    { badge: CertifiedSecureBadge, label: t('soc2') },
    { badge: ProtectedByBadge, label: t('gdpr') },
    { badge: ZeroTrustBadge, label: t('zeroTrust') },
    { badge: AIPoweredBadge, label: t('aiPowered') },
    { badge: MonitoringBadge, label: t('monitoring') },
  ];

  return (
    <section className="bg-surface-0 py-24 sm:py-[120px] px-6 border-b border-border">
      <div className="max-w-[1200px] mx-auto text-center">
        <motion.div
          animate={{ opacity: [0.6, 1, 0.6] }}
          transition={{ duration: 4, repeat: Infinity, ease: 'easeInOut' }}
          className="mx-auto w-fit"
        >
          <ShieldIcon size={80} className="text-brand-sage mx-auto" />
        </motion.div>

        <FadeInUp>
          <h2 className="text-[clamp(36px,4vw,48px)] font-extrabold text-text-primary mt-8">
            {t('title')}
          </h2>
          <p className="text-text-secondary mt-3">{t('subtitle')}</p>
        </FadeInUp>

        <FadeInUp delay={0.1}>
          <div className="flex flex-wrap gap-3 justify-center mt-8">
            <Link
              href="/early-access"
              className="bg-brand-sage text-surface-0 font-semibold rounded-full px-10 py-4 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98] text-lg"
            >
              {tc('startFreeTrial')}
            </Link>
            <Link
              href="/demo"
              className="border border-text-tertiary/40 text-text-secondary hover:text-text-primary hover:border-text-secondary font-semibold rounded-full px-10 py-4 transition-all duration-200 text-lg"
            >
              {tc('scheduleDemo')}
            </Link>
          </div>
        </FadeInUp>

        <FadeInUp delay={0.2}>
          <div className="flex flex-wrap gap-6 justify-center mt-10">
            {badges.map((b) => (
              <div key={b.label} className="flex flex-col items-center gap-2">
                <b.badge size={56} className="opacity-60" />
                <span className="text-[10px] text-text-muted uppercase tracking-wider font-medium">
                  {b.label}
                </span>
              </div>
            ))}
          </div>
        </FadeInUp>
      </div>
    </section>
  );
}
