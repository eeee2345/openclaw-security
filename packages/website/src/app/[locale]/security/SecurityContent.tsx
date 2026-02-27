'use client';

import { useTranslations } from 'next-intl';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import SectionTitle from '@/components/ui/SectionTitle';
import { Link } from '@/navigation';
import { ArrowRight, ExternalLink } from 'lucide-react';
import {
  ShieldIcon,
  LockIcon,
  ScanIcon,
  NetworkIcon,
  AnalyticsIcon,
  CheckIcon,
  DeployIcon,
  GlobalIcon,
  AlertIcon,
  HistoryIcon,
} from '@/components/ui/BrandIcons';

/* ─── Security Practice Icons ─── */
const practiceConfigs = [
  { key: 'item1' as const, icon: NetworkIcon },
  { key: 'item2' as const, icon: LockIcon },
  { key: 'item3' as const, icon: ScanIcon },
  { key: 'item4' as const, icon: ScanIcon },
  { key: 'item5' as const, icon: ShieldIcon },
  { key: 'item6' as const, icon: HistoryIcon },
];

/* ─── Compliance Frameworks ─── */
const compliance = [
  {
    badge: 'SOC 2 Type II',
    status: 'In Progress',
    statusColor: 'text-[#f59e0b]',
    description:
      'We are actively pursuing SOC 2 Type II certification covering Security, Availability, and Confidentiality trust service criteria. Our audit is conducted by a Big Four firm. Expected completion: Q3 2026.',
  },
  {
    badge: 'ISO 27001',
    status: 'Planned',
    statusColor: 'text-[#60a5fa]',
    description:
      'ISO 27001 certification is on our roadmap for 2026. Our information security management system (ISMS) is being built to ISO 27001 standards from day one, making certification a formalization rather than a transformation.',
  },
  {
    badge: 'GDPR',
    status: 'Compliant',
    statusColor: 'text-[#22c55e]',
    description:
      'Panguard is designed for GDPR compliance by default. Data minimization, purpose limitation, and the right to erasure are built into the architecture. We offer Data Processing Agreements (DPA) to all customers.',
  },
  {
    badge: 'Taiwan Cybersecurity Management Act',
    status: 'Compliant',
    statusColor: 'text-[#22c55e]',
    description:
      "For customers operating under Taiwan's Cybersecurity Management Act, Panguard's reporting and audit capabilities are designed to meet regulatory requirements for critical infrastructure providers.",
  },
];

/* ─── Data Flow Zone Config ─── */
const dataFlowConfigs = [
  { key: 'onDevice' as const, icon: NetworkIcon, color: 'border-[#22c55e]' },
  { key: 'cloud' as const, icon: GlobalIcon, color: 'border-[#f59e0b]' },
  { key: 'neverTransmitted' as const, icon: ShieldIcon, color: 'border-[#ef4444]' },
];

/* ─── Trust Center Download Icons ─── */
const downloadConfigs = [
  { key: 'doc1' as const, icon: AnalyticsIcon },
  { key: 'doc2' as const, icon: ShieldIcon },
  { key: 'doc3' as const, icon: AnalyticsIcon },
  { key: 'doc4' as const, icon: AnalyticsIcon },
  { key: 'doc5' as const, icon: NetworkIcon },
  { key: 'doc6' as const, icon: AlertIcon },
];

export default function SecurityContent() {
  const t = useTranslations('security');

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
              {t('title')}
              <br className="hidden sm:block" />
              <span className="text-brand-sage">{t('titleHighlight')}</span> {t('titleSuffix')}
            </h1>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <p className="text-xl text-text-secondary max-w-2xl mt-6 leading-relaxed">
              {t('subtitle')}
            </p>
          </FadeInUp>
        </div>
      </section>

      {/* -- Security Practices -- */}
      <SectionWrapper>
        <SectionTitle
          overline={t('practices.overline')}
          title={t('practices.title')}
          subtitle={t('practices.subtitle')}
        />
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4 mt-14">
          {practiceConfigs.map((p, i) => (
            <FadeInUp key={p.key} delay={i * 0.08}>
              <div className="bg-surface-1 rounded-xl border border-border p-6 h-full">
                <p.icon className="w-5 h-5 text-brand-sage mb-4" />
                <p className="text-sm font-bold text-text-primary mb-2">
                  {t(`practices.${p.key}.title`)}
                </p>
                <p className="text-xs text-text-secondary leading-relaxed">
                  {t(`practices.${p.key}.desc`)}
                </p>
              </div>
            </FadeInUp>
          ))}
        </div>
      </SectionWrapper>

      {/* -- Compliance -- */}
      <SectionWrapper dark>
        <SectionTitle
          overline={t('compliance.overline')}
          title={t('compliance.title')}
          subtitle={t('compliance.subtitle')}
        />
        <div className="max-w-3xl mx-auto mt-14 space-y-4">
          {compliance.map((c, i) => (
            <FadeInUp key={c.badge} delay={i * 0.1}>
              <div className="bg-surface-2 rounded-xl border border-border p-6">
                <div className="flex flex-wrap items-center gap-3 mb-3">
                  <span className="text-sm font-bold text-text-primary">{c.badge}</span>
                  <span
                    className={`text-[11px] font-semibold uppercase tracking-wider ${c.statusColor}`}
                  >
                    {c.status}
                  </span>
                </div>
                <p className="text-sm text-text-secondary leading-relaxed">{c.description}</p>
              </div>
            </FadeInUp>
          ))}
        </div>
      </SectionWrapper>

      {/* -- Data Handling -- */}
      <SectionWrapper>
        <SectionTitle
          overline={t('dataHandling.overline')}
          title={t('dataHandling.title')}
          subtitle={t('dataHandling.subtitle')}
        />
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-6 mt-14">
          {dataFlowConfigs.map((zone, i) => {
            const items = t.raw(`dataHandling.${zone.key}.items`) as string[];
            return (
              <FadeInUp key={zone.key} delay={i * 0.1}>
                <div
                  className={`bg-surface-1 rounded-xl border-l-4 ${zone.color} border border-border p-6 h-full`}
                >
                  <div className="flex items-center gap-3 mb-4">
                    <zone.icon className="w-5 h-5 text-brand-sage" />
                    <p className="text-sm font-bold text-text-primary">
                      {t(`dataHandling.${zone.key}.zone`)}
                    </p>
                  </div>
                  <ul className="space-y-2">
                    {items.map((item: string) => (
                      <li
                        key={item}
                        className="flex items-start gap-2 text-xs text-text-secondary leading-relaxed"
                      >
                        <CheckIcon className="w-3 h-3 text-text-muted mt-0.5 shrink-0" />
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>
              </FadeInUp>
            );
          })}
        </div>

        {/* Anonymization note */}
        <FadeInUp delay={0.3}>
          <div className="mt-8 bg-surface-1 rounded-xl border border-border p-6 max-w-3xl mx-auto">
            <div className="flex items-start gap-4">
              <LockIcon className="w-5 h-5 text-brand-sage shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-bold text-text-primary mb-1">
                  {t('dataHandling.anonymization.title')}
                </p>
                <p className="text-xs text-text-secondary leading-relaxed">
                  {t('dataHandling.anonymization.desc')}
                </p>
              </div>
            </div>
          </div>
        </FadeInUp>
      </SectionWrapper>

      {/* -- Responsible Disclosure -- */}
      <SectionWrapper dark>
        <div className="max-w-3xl mx-auto text-center">
          <FadeInUp>
            <CheckIcon className="w-8 h-8 text-brand-sage mx-auto mb-4" />
            <h2 className="text-[clamp(28px,3vw,40px)] font-bold text-text-primary">
              {t('disclosure.title')}
            </h2>
            <p className="text-text-secondary mt-4 leading-relaxed max-w-xl mx-auto">
              {t('disclosure.desc')}
            </p>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <div className="flex flex-wrap justify-center gap-3 mt-8">
              <Link
                href="/legal/responsible-disclosure"
                className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3.5 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
              >
                {t('disclosure.cta1')} <ExternalLink className="w-4 h-4" />
              </Link>
              <Link
                href="mailto:security@panguard.ai"
                className="border border-border text-text-secondary hover:text-text-primary hover:border-brand-sage font-semibold rounded-full px-8 py-3.5 transition-all duration-200"
              >
                {t('disclosure.cta2')}
              </Link>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* -- Trust Center -- */}
      <SectionWrapper>
        <SectionTitle
          overline={t('trustCenter.overline')}
          title={t('trustCenter.title')}
          subtitle={t('trustCenter.subtitle')}
        />
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4 mt-14">
          {downloadConfigs.map((doc, i) => (
            <FadeInUp key={doc.key} delay={i * 0.08}>
              <div className="card-glow bg-surface-1 rounded-xl border border-border p-5 flex items-start gap-4 hover:border-border-hover transition-colors group">
                <doc.icon className="w-5 h-5 text-brand-sage shrink-0 mt-0.5" />
                <div className="flex-1">
                  <p className="text-sm font-semibold text-text-primary group-hover:text-brand-sage transition-colors">
                    {t(`trustCenter.${doc.key}.label`)}
                  </p>
                  <p className="text-xs text-text-tertiary mt-0.5">
                    {t(`trustCenter.${doc.key}.status`)}
                  </p>
                </div>
                <DeployIcon className="w-4 h-4 text-text-muted group-hover:text-text-secondary transition-colors shrink-0 mt-0.5" />
              </div>
            </FadeInUp>
          ))}
        </div>
      </SectionWrapper>

      {/* -- CTA -- */}
      <SectionWrapper dark>
        <div className="text-center">
          <FadeInUp>
            <h2 className="text-[clamp(28px,3vw,40px)] font-bold text-text-primary">
              {t('cta.title')}
            </h2>
            <p className="text-text-secondary mt-3 max-w-lg mx-auto">{t('cta.desc')}</p>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <div className="flex flex-wrap justify-center gap-3 mt-8">
              <Link
                href="/contact"
                className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3.5 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
              >
                {t('cta.cta1')} <ArrowRight className="w-4 h-4" />
              </Link>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>
    </>
  );
}
