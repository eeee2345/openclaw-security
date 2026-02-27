'use client';

import { useTranslations } from 'next-intl';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import SectionTitle from '@/components/ui/SectionTitle';
import { Link } from '@/navigation';
import { ArrowRight } from 'lucide-react';
import {
  ComplianceIcon,
  LockIcon,
  ShieldIcon,
  GlobalIcon,
  NetworkIcon,
  ScanIcon,
  CheckIcon,
  AlertIcon,
  MonitorIcon,
  HistoryIcon,
} from '@/components/ui/BrandIcons';
import {
  CertifiedSecureBadge,
  ProtectedByBadge,
  EnterpriseGradeBadge,
} from '@/components/ui/BrandBadges';

/* ─── Types ─── */
type StatusVariant = 'active' | 'in-progress' | 'planned';

/* ─── Status Badge Styles ─── */
const statusStyles: Record<StatusVariant, string> = {
  active: 'bg-[#22c55e]/10 text-[#22c55e] border-[#22c55e]/20',
  'in-progress': 'bg-[#f59e0b]/10 text-[#f59e0b] border-[#f59e0b]/20',
  planned: 'bg-text-muted/10 text-text-muted border-border',
};

/* ─── Compliance Card Config ─── */
const complianceCardConfigs = [
  { key: 'soc2' as const, variant: 'in-progress' as StatusVariant, badge: CertifiedSecureBadge },
  { key: 'iso27001' as const, variant: 'planned' as StatusVariant, badge: CertifiedSecureBadge },
  { key: 'gdpr' as const, variant: 'active' as StatusVariant, badge: ProtectedByBadge },
  { key: 'hipaa' as const, variant: 'in-progress' as StatusVariant, badge: EnterpriseGradeBadge },
];

/* ─── Security Architecture Icon Mapping ─── */
const layerConfigs = [
  { key: 'dataLayer' as const, icon: LockIcon },
  { key: 'applicationLayer' as const, icon: ShieldIcon },
  { key: 'infrastructureLayer' as const, icon: NetworkIcon },
];

/* ─── Data Handling Icon Mapping ─── */
const dataHandlingConfigs = [
  { key: 'item1' as const, icon: LockIcon },
  { key: 'item2' as const, icon: GlobalIcon },
  { key: 'item3' as const, icon: HistoryIcon },
  { key: 'item4' as const, icon: ShieldIcon },
  { key: 'item5' as const, icon: ScanIcon },
  { key: 'item6' as const, icon: AlertIcon },
];

/* ─── Subprocessors Config ─── */
const subprocessorKeys = ['aws', 'anthropic', 'cloudflare', 'stripe', 'sendgrid'] as const;

/* ═══════════════════════════════════════════════════════════════════
   Trust Center Content
   ═══════════════════════════════════════════════════════════════════ */
export default function TrustContent() {
  const t = useTranslations('trust');

  return (
    <>
      {/* -- Hero -- */}
      <section className="relative min-h-[50vh] flex items-center px-6 lg:px-[120px] py-24 border-b border-border overflow-hidden">
        <div className="absolute top-1/3 right-1/4 w-[600px] h-[400px] bg-brand-sage/5 rounded-full blur-[200px] pointer-events-none" />
        <div className="max-w-[1200px] mx-auto relative">
          <FadeInUp>
            <p className="text-[11px] uppercase tracking-[0.15em] text-brand-sage font-semibold mb-6">
              {t('overline')}
            </p>
          </FadeInUp>
          <FadeInUp delay={0.05}>
            <h1 className="text-[clamp(40px,5vw,64px)] font-extrabold leading-[1.08] tracking-tight text-text-primary max-w-3xl">
              {t('title')} <span className="text-brand-sage">{t('titleHighlight')}</span>
            </h1>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <p className="text-xl text-text-secondary max-w-2xl mt-6 leading-relaxed">
              {t('subtitle')}
            </p>
          </FadeInUp>
        </div>
      </section>

      {/* -- Compliance Status Cards -- */}
      <SectionWrapper>
        <SectionTitle
          overline={t('compliance.overline')}
          title={t('compliance.title')}
          subtitle={t('compliance.subtitle')}
        />
        <div className="grid sm:grid-cols-2 gap-4 mt-14">
          {complianceCardConfigs.map((card, i) => (
            <FadeInUp key={card.key} delay={i * 0.08}>
              <div className="bg-surface-1 rounded-xl border border-border p-6 h-full">
                <div className="flex items-start gap-4">
                  <div className="shrink-0">
                    {card.badge ? (
                      <card.badge size={36} className="opacity-50" />
                    ) : (
                      <ComplianceIcon className="w-5 h-5 text-brand-sage mt-0.5" />
                    )}
                  </div>
                  <div className="flex-1">
                    <div className="flex flex-wrap items-center gap-3 mb-3">
                      <span className="text-sm font-bold text-text-primary">
                        {t(`compliance.${card.key}.name`)}
                      </span>
                      <span
                        className={`text-[10px] font-semibold uppercase tracking-wider px-2.5 py-0.5 rounded-full border ${statusStyles[card.variant]}`}
                      >
                        {t(`compliance.${card.key}.status`)}
                      </span>
                    </div>
                    <p className="text-xs text-text-secondary leading-relaxed">
                      {t(`compliance.${card.key}.desc`)}
                    </p>
                  </div>
                </div>
              </div>
            </FadeInUp>
          ))}
        </div>
      </SectionWrapper>

      {/* -- Security Architecture -- */}
      <SectionWrapper dark>
        <SectionTitle
          overline={t('architecture.overline')}
          title={t('architecture.title')}
          subtitle={t('architecture.subtitle')}
        />
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-6 mt-14">
          {layerConfigs.map((layer, i) => {
            const items = t.raw(`architecture.${layer.key}.items`) as string[];
            return (
              <FadeInUp key={layer.key} delay={i * 0.1}>
                <div className="bg-surface-2 rounded-xl border border-border p-6 h-full">
                  <div className="flex items-center gap-3 mb-5">
                    <div className="w-10 h-10 rounded-lg bg-brand-sage/10 flex items-center justify-center">
                      <layer.icon className="w-5 h-5 text-brand-sage" />
                    </div>
                    <h3 className="text-sm font-bold text-text-primary">
                      {t(`architecture.${layer.key}.title`)}
                    </h3>
                  </div>
                  <ul className="space-y-2.5">
                    {items.map((item: string) => (
                      <li
                        key={item}
                        className="flex items-start gap-2 text-xs text-text-secondary leading-relaxed"
                      >
                        <CheckIcon className="w-3 h-3 text-brand-sage mt-0.5 shrink-0" />
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>
              </FadeInUp>
            );
          })}
        </div>
      </SectionWrapper>

      {/* -- Data Handling Practices -- */}
      <SectionWrapper>
        <SectionTitle
          overline={t('dataHandling.overline')}
          title={t('dataHandling.title')}
          subtitle={t('dataHandling.subtitle')}
        />
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4 mt-14">
          {dataHandlingConfigs.map((practice, i) => (
            <FadeInUp key={practice.key} delay={i * 0.08}>
              <div className="bg-surface-1 rounded-xl border border-border p-6 h-full">
                <practice.icon className="w-5 h-5 text-brand-sage mb-4" />
                <p className="text-sm font-bold text-text-primary mb-2">
                  {t(`dataHandling.${practice.key}.title`)}
                </p>
                <p className="text-xs text-text-secondary leading-relaxed">
                  {t(`dataHandling.${practice.key}.desc`)}
                </p>
              </div>
            </FadeInUp>
          ))}
        </div>
      </SectionWrapper>

      {/* -- Subprocessors -- */}
      <SectionWrapper dark>
        <SectionTitle
          overline={t('subprocessors.overline')}
          title={t('subprocessors.title')}
          subtitle={t('subprocessors.subtitle')}
        />
        <FadeInUp delay={0.1}>
          <div className="mt-14 max-w-3xl mx-auto">
            {/* Table header */}
            <div className="grid grid-cols-3 gap-4 px-6 pb-3 border-b border-border">
              <span className="text-[11px] uppercase tracking-wider text-text-muted font-semibold">
                {t('subprocessors.headers.name')}
              </span>
              <span className="text-[11px] uppercase tracking-wider text-text-muted font-semibold">
                {t('subprocessors.headers.purpose')}
              </span>
              <span className="text-[11px] uppercase tracking-wider text-text-muted font-semibold text-right">
                {t('subprocessors.headers.location')}
              </span>
            </div>
            {/* Table rows */}
            {subprocessorKeys.map((key, i) => (
              <FadeInUp key={key} delay={0.12 + i * 0.06}>
                <div className="grid grid-cols-3 gap-4 px-6 py-4 border-b border-border last:border-b-0 hover:bg-surface-2/50 transition-colors">
                  <span className="text-sm font-semibold text-text-primary">
                    {t(`subprocessors.${key}.name`)}
                  </span>
                  <span className="text-sm text-text-secondary">
                    {t(`subprocessors.${key}.purpose`)}
                  </span>
                  <span className="text-sm text-text-tertiary text-right">
                    {t(`subprocessors.${key}.location`)}
                  </span>
                </div>
              </FadeInUp>
            ))}
          </div>
        </FadeInUp>
        <FadeInUp delay={0.4}>
          <p className="text-xs text-text-muted text-center mt-6 max-w-lg mx-auto">
            {t('subprocessors.updateNote')}
          </p>
        </FadeInUp>
      </SectionWrapper>

      {/* -- Document Request CTA -- */}
      <SectionWrapper>
        <div className="text-center">
          <FadeInUp>
            <MonitorIcon className="w-8 h-8 text-brand-sage mx-auto mb-4" />
            <h2 className="text-[clamp(28px,3vw,40px)] font-bold text-text-primary">
              {t('cta.title')}
            </h2>
            <p className="text-text-secondary mt-4 max-w-xl mx-auto leading-relaxed">
              {t('cta.desc')}
            </p>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <div className="flex flex-wrap justify-center gap-3 mt-8">
              <Link
                href="/contact"
                className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3.5 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
              >
                {t('cta.cta1')} <ArrowRight className="w-4 h-4" />
              </Link>
              <Link
                href="/security"
                className="border border-border text-text-secondary hover:text-text-primary hover:border-brand-sage font-semibold rounded-full px-8 py-3.5 transition-all duration-200"
              >
                {t('cta.cta2')}
              </Link>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>
    </>
  );
}
