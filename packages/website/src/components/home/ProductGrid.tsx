'use client';
import { useTranslations } from 'next-intl';
import { Link } from '@/navigation';
import { ArrowRight } from 'lucide-react';
import SectionWrapper from '../ui/SectionWrapper';
import SectionTitle from '../ui/SectionTitle';
import FadeInUp from '../FadeInUp';
import Card from '../ui/Card';
import {
  ScanIcon,
  ShieldIcon,
  ChatIcon,
  TrapIcon,
  ReportIcon,
  GlobalIcon,
} from '@/components/ui/BrandIcons';

const products = [
  { icon: ScanIcon, href: '/product/scan', core: true },
  { icon: ShieldIcon, href: '/product/guard', core: true },
  { icon: ChatIcon, href: '/product/chat', core: true },
  { icon: TrapIcon, href: '/product/trap', core: false },
  { icon: ReportIcon, href: '/product/report', core: false },
  { icon: GlobalIcon, href: '/product', core: false },
];

export default function ProductGrid() {
  const t = useTranslations('home.productGrid');

  return (
    <SectionWrapper>
      <SectionTitle overline={t('overline')} title={t('title')} />

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5 mt-14">
        {products.map((p, i) => (
          <FadeInUp key={i} delay={i * 0.06}>
            <Link href={p.href} className="block h-full group">
              <Card
                padding="lg"
                className="h-full relative overflow-hidden transition-all duration-200 group-hover:border-brand-sage/40"
              >
                {p.core && (
                  <span className="absolute top-4 right-4 text-[10px] font-bold uppercase tracking-wider text-brand-sage bg-brand-sage/10 rounded-full px-2.5 py-0.5">
                    {t('coreBadge')}
                  </span>
                )}
                <p.icon size={28} className="text-brand-sage mb-4" />
                <h3 className="text-lg font-bold text-text-primary mb-2">
                  {t(`products.${i}.name`)}
                </h3>
                <p className="text-sm text-text-secondary leading-relaxed">
                  {t(`products.${i}.desc`)}
                </p>
                <span className="inline-flex items-center gap-1 text-sm text-brand-sage mt-4 group-hover:gap-2 transition-all">
                  {t('learnMore')} <ArrowRight className="w-3.5 h-3.5" />
                </span>
              </Card>
            </Link>
          </FadeInUp>
        ))}
      </div>
    </SectionWrapper>
  );
}
