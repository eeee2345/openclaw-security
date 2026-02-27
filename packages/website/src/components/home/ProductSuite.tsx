'use client';
import { useTranslations } from 'next-intl';
import { Link } from '@/navigation';
import {
  ScanIcon,
  ShieldIcon,
  TerminalIcon,
  NetworkIcon,
  AnalyticsIcon,
} from '@/components/ui/BrandIcons';
import SectionWrapper from '../ui/SectionWrapper';
import SectionTitle from '../ui/SectionTitle';
import FadeInUp from '../FadeInUp';

export default function ProductSuite() {
  const t = useTranslations('home.productSuite');

  const products = [
    {
      icon: ScanIcon,
      name: t('scanName'),
      badge: t('scanBadge'),
      badgeColor: 'bg-status-safe/10 text-status-safe border-status-safe/20',
      desc: t('scanDesc'),
      href: '/product/scan',
    },
    {
      icon: ShieldIcon,
      name: t('guardName'),
      badge: t('guardBadge'),
      badgeColor: 'bg-status-safe/10 text-status-safe border-status-safe/20',
      desc: t('guardDesc'),
      href: '/product/guard',
    },
    {
      icon: TerminalIcon,
      name: t('chatName'),
      badge: t('chatBadge'),
      badgeColor: 'bg-status-safe/10 text-status-safe border-status-safe/20',
      desc: t('chatDesc'),
      href: '/product/chat',
    },
    {
      icon: NetworkIcon,
      name: t('trapName'),
      badge: t('trapBadge'),
      badgeColor: 'bg-status-caution/10 text-status-caution border-status-caution/20',
      desc: t('trapDesc'),
      href: '/product/trap',
    },
    {
      icon: AnalyticsIcon,
      name: t('reportName'),
      badge: t('reportBadge'),
      badgeColor: 'bg-status-info/10 text-status-info border-status-info/20',
      desc: t('reportDesc'),
      href: '/product/report',
    },
  ];

  return (
    <SectionWrapper dark>
      <SectionTitle overline={t('overline')} title={t('title')} subtitle={t('subtitle')} />

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mt-14">
        {products.map((p, i) => (
          <FadeInUp key={p.name} delay={i * 0.06}>
            <Link
              href={p.href}
              className="block bg-surface-0 rounded-2xl p-6 border border-border hover:border-border-hover transition-all group h-full card-glow"
            >
              <p.icon
                size={24}
                className="text-brand-sage mb-4 group-hover:scale-110 transition-transform"
              />
              <span
                className={`inline-block ${p.badgeColor} border text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded-full mb-3`}
              >
                {p.badge}
              </span>
              <p className="text-sm font-semibold text-text-primary">{p.name}</p>
              <p className="text-xs text-text-tertiary mt-1.5 leading-relaxed">{p.desc}</p>
            </Link>
          </FadeInUp>
        ))}
      </div>
    </SectionWrapper>
  );
}
