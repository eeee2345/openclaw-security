'use client';

import { useTranslations } from 'next-intl';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import SectionTitle from '@/components/ui/SectionTitle';
import { Link } from '@/navigation';
import { ArrowRight } from 'lucide-react';
import {
  ShieldIcon,
  ScanIcon,
  ResponseIcon,
  AnalyticsIcon,
  TerminalIcon,
  NetworkIcon,
  CheckIcon,
  AlertIcon,
  SettingsIcon,
  MonitorIcon,
} from '@/components/ui/BrandIcons';

/* ─── Layer Config ─── */
const layerConfigs = [
  {
    key: 'layer1' as const,
    color: 'bg-brand-sage/10 text-brand-sage',
    width: '100%',
    icon: ScanIcon,
  },
  {
    key: 'layer2' as const,
    color: 'bg-brand-sage/10 text-brand-sage',
    width: '90%',
    icon: ShieldIcon,
  },
  {
    key: 'layer3' as const,
    color: 'bg-[#60a5fa]/10 text-[#60a5fa]',
    width: '75%',
    icon: AnalyticsIcon,
  },
  {
    key: 'layer4' as const,
    color: 'bg-[#f59e0b]/10 text-[#f59e0b]',
    width: '55%',
    icon: SettingsIcon,
  },
  {
    key: 'layer5' as const,
    color: 'bg-[#ef4444]/10 text-[#ef4444]',
    width: '40%',
    icon: ResponseIcon,
  },
];

/* ─── Agent Config ─── */
const agentConfigs = [
  { key: 'detect' as const, icon: ScanIcon },
  { key: 'analyze' as const, icon: SettingsIcon },
  { key: 'respond' as const, icon: ResponseIcon },
  { key: 'report' as const, icon: AnalyticsIcon },
  { key: 'investigate' as const, icon: NetworkIcon },
];

/* ─── Tier Config ─── */
const tierConfigs = [
  { key: 'tier1' as const, barColor: 'bg-brand-sage', barWidth: '100%' },
  { key: 'tier2' as const, barColor: 'bg-[#60a5fa]', barWidth: '70%' },
  { key: 'tier3' as const, barColor: 'bg-[#f59e0b]', barWidth: '40%' },
];

/* ─── Response Action Icons ─── */
const actionIcons = [ShieldIcon, TerminalIcon, AlertIcon, NetworkIcon, MonitorIcon, ResponseIcon];

/* ─── Degradation Config ─── */
const degradationConfigs = [
  { key: 'level1' as const, dot: 'bg-[#22c55e]' },
  { key: 'level2' as const, dot: 'bg-[#f59e0b]' },
  { key: 'level3' as const, dot: 'bg-[#f59e0b]' },
  { key: 'level4' as const, dot: 'bg-[#ef4444]' },
];

export default function HowItWorksContent() {
  const t = useTranslations('howItWorks');

  return (
    <>
      {/* ── Hero ── */}
      <section className="relative min-h-[60vh] flex items-center px-6 lg:px-[120px] py-24 border-b border-border overflow-hidden">
        <div className="absolute top-1/3 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-brand-sage/5 rounded-full blur-[200px] pointer-events-none" />
        <div className="max-w-[1200px] mx-auto relative text-center w-full">
          <FadeInUp>
            <div className="relative w-20 h-20 mx-auto mb-4 flex items-center justify-center">
              <div className="absolute inset-0 rounded-full border border-brand-sage/20 animate-[spin_12s_linear_infinite]" />
              <div className="absolute inset-2 rounded-full border border-brand-sage/10 animate-[spin_8s_linear_infinite_reverse]" />
              <ShieldIcon className="w-10 h-10 text-brand-sage relative" />
            </div>
          </FadeInUp>
          <FadeInUp delay={0.05}>
            <p className="text-[11px] uppercase tracking-[0.15em] text-brand-sage font-semibold mb-4">
              {t('overline')}
            </p>
            <h1 className="text-[clamp(36px,4.5vw,56px)] font-extrabold leading-[1.08] tracking-tight text-text-primary max-w-3xl mx-auto">
              {t('title')} <span className="text-brand-sage">{t('titleHighlight')}</span>
            </h1>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <p className="text-xl text-text-secondary max-w-xl mx-auto mt-6 leading-relaxed">
              {t('subtitle')}
            </p>
          </FadeInUp>
        </div>
      </section>

      {/* ── Overview Stats ── */}
      <SectionWrapper>
        <SectionTitle
          overline={t('overview.overline')}
          title={t('overview.title')}
          subtitle={t('overview.subtitle')}
        />
        <div className="grid sm:grid-cols-3 gap-6 mt-14">
          {(['stat1', 'stat2', 'stat3'] as const).map((key, i) => (
            <FadeInUp key={key} delay={i * 0.08}>
              <div className="bg-surface-1 rounded-xl border border-border p-8 text-center card-glow">
                <p className="text-[clamp(32px,4vw,48px)] font-extrabold text-brand-sage">
                  {t(`overview.${key}.value`)}
                </p>
                <p className="text-sm text-text-secondary mt-2">{t(`overview.${key}.label`)}</p>
              </div>
            </FadeInUp>
          ))}
        </div>
      </SectionWrapper>

      {/* ── Five Detection Layers (funnel) ── */}
      <SectionWrapper dark>
        <SectionTitle
          overline={t('layers.overline')}
          title={t('layers.title')}
          subtitle={t('layers.subtitle')}
        />
        <div className="max-w-3xl mx-auto mt-14 space-y-4">
          {layerConfigs.map((l, i) => {
            const Icon = l.icon;
            return (
              <FadeInUp key={l.key} delay={i * 0.08}>
                <div
                  className="bg-surface-2 rounded-xl p-6 border border-border mx-auto"
                  style={{ maxWidth: l.width }}
                >
                  <div className="flex items-start gap-4">
                    <div className="shrink-0">
                      <span
                        className={`${l.color} text-[10px] font-semibold uppercase tracking-wider px-2.5 py-1 rounded-full`}
                      >
                        {t(`layers.${l.key}.badge`)}
                      </span>
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <Icon className="w-4 h-4 text-text-tertiary shrink-0" />
                        <p className="text-sm font-semibold text-text-primary">
                          {t(`layers.${l.key}.name`)}
                        </p>
                      </div>
                      <p className="text-sm text-text-secondary leading-relaxed">
                        {t(`layers.${l.key}.desc`)}
                      </p>
                      <p className="text-xs text-text-tertiary mt-2 italic">
                        {t(`layers.${l.key}.detail`)}
                      </p>
                    </div>
                  </div>
                </div>
              </FadeInUp>
            );
          })}
        </div>
      </SectionWrapper>

      {/* ── AI Funnel (detailed) ── */}
      <SectionWrapper>
        <SectionTitle
          overline={t('aiFunnel.overline')}
          title={t('aiFunnel.title')}
          subtitle={t('aiFunnel.subtitle')}
        />
        <div className="max-w-3xl mx-auto mt-14 space-y-6">
          {tierConfigs.map((tier, i) => (
            <FadeInUp key={tier.key} delay={i * 0.1}>
              <div className="bg-surface-1 rounded-xl border border-border p-6">
                <div className="flex items-center justify-between mb-3">
                  <p className="text-sm font-semibold text-text-primary">
                    {t(`aiFunnel.${tier.key}.name`)}
                  </p>
                  <span className="text-lg font-extrabold text-brand-sage">
                    {t(`aiFunnel.${tier.key}.pct`)}
                  </span>
                </div>
                <div className="h-2 bg-surface-2 rounded-full mb-4 overflow-hidden">
                  <div
                    className={`h-full ${tier.barColor} rounded-full`}
                    style={{ width: tier.barWidth }}
                  />
                </div>
                <ul className="space-y-1.5">
                  {t(`aiFunnel.${tier.key}.items`)
                    .split('|')
                    .map((item, j) => (
                      <li key={j} className="flex items-start gap-2 text-sm text-text-secondary">
                        <CheckIcon className="w-3.5 h-3.5 text-brand-sage mt-0.5 shrink-0" />
                        <span>{item}</span>
                      </li>
                    ))}
                </ul>
                <p className="text-xs text-text-tertiary mt-3">{t(`aiFunnel.${tier.key}.speed`)}</p>
              </div>
            </FadeInUp>
          ))}
        </div>
      </SectionWrapper>

      {/* ── Agent Pipeline ── */}
      <SectionWrapper dark>
        <SectionTitle
          overline={t('agentPipeline.overline')}
          title={t('agentPipeline.title')}
          subtitle={t('agentPipeline.subtitle')}
        />
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4 mt-14">
          {agentConfigs.map((agent, i) => {
            const Icon = agent.icon;
            return (
              <FadeInUp key={agent.key} delay={i * 0.08}>
                <div className="bg-surface-2 rounded-xl border border-border p-6 h-full card-glow">
                  <Icon className="w-6 h-6 text-brand-sage mb-3" />
                  <p className="text-sm font-bold text-text-primary mb-1">
                    {t(`agentPipeline.${agent.key}.name`)}
                  </p>
                  <p className="text-sm text-text-secondary leading-relaxed">
                    {t(`agentPipeline.${agent.key}.desc`)}
                  </p>
                </div>
              </FadeInUp>
            );
          })}
        </div>
      </SectionWrapper>

      {/* ── Automated Response ── */}
      <SectionWrapper>
        <SectionTitle
          overline={t('response.overline')}
          title={t('response.title')}
          subtitle={t('response.subtitle')}
        />
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4 mt-14">
          {(t.raw('response.actions') as Array<{ name: string; desc: string }>).map((action, i) => {
            const Icon = actionIcons[i] || ShieldIcon;
            return (
              <FadeInUp key={action.name} delay={i * 0.06}>
                <div className="bg-surface-1 rounded-xl border border-border p-5 h-full">
                  <Icon className="w-5 h-5 text-brand-sage mb-2" />
                  <p className="text-sm font-semibold text-text-primary">{action.name}</p>
                  <p className="text-xs text-text-secondary mt-1">{action.desc}</p>
                </div>
              </FadeInUp>
            );
          })}
        </div>

        {/* Confidence thresholds */}
        <div className="max-w-2xl mx-auto mt-10 space-y-3">
          {(['high', 'medium', 'low'] as const).map((level, i) => {
            const colors = ['bg-[#22c55e]', 'bg-[#f59e0b]', 'bg-[#60a5fa]'];
            return (
              <FadeInUp key={level} delay={0.5 + i * 0.06}>
                <div className="flex items-center gap-4 bg-surface-1 rounded-lg border border-border px-5 py-3">
                  <div className={`w-2.5 h-2.5 rounded-full ${colors[i]} shrink-0`} />
                  <span className="text-sm font-semibold text-text-primary w-24">
                    {t(`response.confidence.${level}.threshold`)}
                  </span>
                  <span className="text-sm text-text-secondary">
                    {t(`response.confidence.${level}.action`)}
                  </span>
                </div>
              </FadeInUp>
            );
          })}
        </div>
      </SectionWrapper>

      {/* ── 7-Day Learning ── */}
      <SectionWrapper dark>
        <SectionTitle
          overline={t('learning.overline')}
          title={t('learning.title')}
          subtitle={t('learning.subtitle')}
        />
        <div className="max-w-3xl mx-auto mt-14">
          <div className="relative">
            {/* Timeline line */}
            <div className="absolute left-[18px] top-0 bottom-0 w-px bg-border hidden sm:block" />

            {(['phase1', 'phase2', 'phase3'] as const).map((phase, i) => (
              <FadeInUp key={phase} delay={i * 0.1}>
                <div className="flex gap-6 mb-8 last:mb-0">
                  <div className="relative shrink-0">
                    <div
                      className={`w-9 h-9 rounded-full border-2 flex items-center justify-center text-xs font-bold ${
                        i === 2
                          ? 'border-brand-sage bg-brand-sage/10 text-brand-sage'
                          : 'border-border bg-surface-2 text-text-tertiary'
                      }`}
                    >
                      {i + 1}
                    </div>
                  </div>
                  <div className="pb-2">
                    <p className="text-[11px] uppercase tracking-wider text-brand-sage font-semibold">
                      {t(`learning.${phase}.days`)}
                    </p>
                    <p className="text-base font-semibold text-text-primary mt-1">
                      {t(`learning.${phase}.title`)}
                    </p>
                    <p className="text-sm text-text-secondary mt-1 leading-relaxed">
                      {t(`learning.${phase}.desc`)}
                    </p>
                  </div>
                </div>
              </FadeInUp>
            ))}
          </div>
        </div>
      </SectionWrapper>

      {/* ── Graceful Degradation ── */}
      <SectionWrapper>
        <SectionTitle
          overline={t('degradation.overline')}
          title={t('degradation.title')}
          subtitle={t('degradation.subtitle')}
        />
        <div className="max-w-2xl mx-auto mt-14 space-y-3">
          {degradationConfigs.map((level, i) => (
            <FadeInUp key={level.key} delay={i * 0.08}>
              <div className="flex items-center gap-4 bg-surface-1 rounded-xl border border-border px-6 py-4">
                <div className={`w-3 h-3 rounded-full ${level.dot} shrink-0`} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-semibold text-text-primary">
                    {t(`degradation.${level.key}.name`)}
                  </p>
                  <p className="text-xs text-text-secondary mt-0.5">
                    {t(`degradation.${level.key}.desc`)}
                  </p>
                </div>
              </div>
            </FadeInUp>
          ))}
        </div>
      </SectionWrapper>

      {/* ── CTA ── */}
      <SectionWrapper dark>
        <div className="text-center max-w-2xl mx-auto">
          <FadeInUp>
            <h2 className="text-[clamp(28px,3.5vw,40px)] font-bold text-text-primary">
              {t('cta.title')}
            </h2>
            <p className="text-text-secondary mt-4 mb-8">{t('cta.desc')}</p>
            <code className="block text-sm bg-black/50 text-brand-sage px-6 py-3 rounded-lg mb-8 inline-block font-mono">
              $ curl -fsSL https://get.panguard.ai | bash
            </code>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <div className="flex flex-wrap justify-center gap-3">
              <Link
                href="/docs/getting-started"
                className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3.5 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
              >
                {t('cta.primary')} <ArrowRight className="w-4 h-4" />
              </Link>
              <Link
                href="/technology"
                className="border border-border text-text-secondary hover:text-text-primary hover:border-brand-sage font-semibold rounded-full px-8 py-3.5 transition-all duration-200"
              >
                {t('cta.secondary')}
              </Link>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>
    </>
  );
}
