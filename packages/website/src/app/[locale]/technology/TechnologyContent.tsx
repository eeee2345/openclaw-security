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
  TerminalIcon,
  AnalyticsIcon,
  ResponseIcon,
  AlertIcon,
  CheckIcon,
  NetworkIcon,
  SettingsIcon,
  GlobalIcon,
  HistoryIcon,
  LockIcon,
} from '@/components/ui/BrandIcons';

/* ─── Layer Config ─── */
const layerConfigs = [
  { key: 'layer1' as const, badgeColor: 'bg-brand-sage/10 text-brand-sage', width: '100%' },
  { key: 'layer2' as const, badgeColor: 'bg-[#60a5fa]/10 text-[#60a5fa]', width: '70%' },
  { key: 'layer3' as const, badgeColor: 'bg-[#f59e0b]/10 text-[#f59e0b]', width: '40%' },
];

/* ─── Agent Icons ─── */
const agentConfigs = [
  { key: 'detect' as const, icon: ScanIcon },
  { key: 'analyze' as const, icon: SettingsIcon },
  { key: 'respond' as const, icon: ResponseIcon },
  { key: 'report' as const, icon: AnalyticsIcon },
  { key: 'chat' as const, icon: TerminalIcon },
];

/* ─── Confidence Scoring ─── */
const confidenceConfigs = [
  { key: 'high' as const, color: 'bg-[#22c55e]' },
  { key: 'medium' as const, color: 'bg-[#f59e0b]' },
  { key: 'low' as const, color: 'bg-[#60a5fa]' },
];

const confidenceBarWidths: Record<string, string> = {
  high: '100%',
  medium: '84%',
  low: '49%',
};

/* ─── Collective Intelligence Icons ─── */
const collectiveConfigs = [
  { key: 'item1' as const, icon: ScanIcon },
  { key: 'item2' as const, icon: NetworkIcon },
  { key: 'item3' as const, icon: HistoryIcon },
  { key: 'item4' as const, icon: ShieldIcon },
];

/* ─── Resilience Levels ─── */
const resilienceConfigs = [
  { key: 'optimal' as const, color: 'bg-[#22c55e]', icon: CheckIcon },
  { key: 'cloudUnavailable' as const, color: 'bg-[#f59e0b]', icon: AlertIcon },
  { key: 'llmOffline' as const, color: 'bg-[#f59e0b]', icon: AlertIcon },
  { key: 'emergency' as const, color: 'bg-[#ef4444]', icon: AlertIcon },
];

/* ─── Tech Stack Icons ─── */
const stackConfigs = [
  { key: 'item1' as const, icon: TerminalIcon },
  { key: 'item2' as const, icon: ShieldIcon },
  { key: 'item3' as const, icon: LockIcon },
  { key: 'item4' as const, icon: SettingsIcon },
  { key: 'item5' as const, icon: SettingsIcon },
  { key: 'item6' as const, icon: TerminalIcon },
  { key: 'item7' as const, icon: NetworkIcon },
  { key: 'item8' as const, icon: NetworkIcon },
  { key: 'item9' as const, icon: GlobalIcon },
  { key: 'item10' as const, icon: AnalyticsIcon },
];

export default function TechnologyContent() {
  const t = useTranslations('technology');

  return (
    <>
      {/* -- Hero -- */}
      <section className="relative min-h-[60vh] flex items-center px-6 lg:px-[120px] py-24 border-b border-border overflow-hidden">
        <div className="absolute top-1/3 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-brand-sage/5 rounded-full blur-[200px] pointer-events-none" />
        <div className="max-w-[1200px] mx-auto relative">
          <FadeInUp>
            <p className="text-[11px] uppercase tracking-[0.15em] text-brand-sage font-semibold mb-6">
              {t('overline')}
            </p>
          </FadeInUp>
          <FadeInUp delay={0.05}>
            <h1 className="text-[clamp(40px,5vw,64px)] font-extrabold leading-[1.08] tracking-tight text-text-primary max-w-3xl">
              {t('title')} <span className="text-brand-sage">{t('titleHighlight')}</span>
              {t('titleSuffix')}
            </h1>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <p className="text-xl text-text-secondary max-w-2xl mt-6 leading-relaxed">
              {t('subtitle')}
            </p>
          </FadeInUp>
        </div>
      </section>

      {/* -- Three-Layer Funnel -- */}
      <SectionWrapper>
        <SectionTitle
          overline={t('defenseFunnel.overline')}
          title={t('defenseFunnel.title')}
          subtitle={t('defenseFunnel.subtitle')}
        />
        <div className="max-w-3xl mx-auto mt-14 space-y-6">
          {layerConfigs.map((l, i) => (
            <FadeInUp key={l.key} delay={i * 0.1}>
              <div
                className="bg-surface-1 rounded-xl p-6 border border-border mx-auto"
                style={{ maxWidth: l.width }}
              >
                <div className="flex flex-wrap items-center justify-between gap-4 mb-3">
                  <div className="flex items-center gap-3">
                    <span
                      className={`${l.badgeColor} text-[11px] font-semibold uppercase tracking-wider px-3 py-1 rounded-full`}
                    >
                      {t(`defenseFunnel.${l.key}.badge`)}
                    </span>
                    <div>
                      <p className="text-sm font-semibold text-text-primary">
                        {t(`defenseFunnel.${l.key}.name`)}
                      </p>
                      <p className="text-xs text-text-tertiary">
                        {t(`defenseFunnel.${l.key}.tech`)}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-6 text-sm">
                    <span className="text-text-secondary font-medium">
                      {t(`defenseFunnel.${l.key}.pct`)}
                    </span>
                    <span className="text-text-tertiary">
                      {t(`defenseFunnel.${l.key}.cost`)}/event
                    </span>
                  </div>
                </div>
                <p className="text-sm text-text-secondary leading-relaxed">
                  {t(`defenseFunnel.${l.key}.desc`)}
                </p>
              </div>
            </FadeInUp>
          ))}
        </div>
      </SectionWrapper>

      {/* -- Five Agent Architecture -- */}
      <SectionWrapper dark>
        <SectionTitle
          overline={t('agents.overline')}
          title={t('agents.title')}
          subtitle={t('agents.subtitle')}
        />
        <div className="mt-14 grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
          {agentConfigs.map((a, i) => (
            <FadeInUp key={a.key} delay={i * 0.08}>
              <div className="bg-surface-2 rounded-xl p-6 border border-border h-full flex flex-col">
                <a.icon className="w-6 h-6 text-brand-sage mb-4 shrink-0" />
                <p className="text-sm font-bold text-text-primary">{t(`agents.${a.key}.name`)}</p>
                <p className="text-[11px] uppercase tracking-wider text-brand-sage font-semibold mt-0.5 mb-3">
                  {t(`agents.${a.key}.role`)}
                </p>
                <p className="text-xs text-text-secondary leading-relaxed flex-1">
                  {t(`agents.${a.key}.desc`)}
                </p>
              </div>
            </FadeInUp>
          ))}
        </div>

        {/* Flow arrows (desktop) */}
        <FadeInUp delay={0.4}>
          <div className="hidden lg:flex items-center justify-center gap-2 mt-6 text-text-muted">
            {['Detect', 'Analyze', 'Respond', 'Report', 'Chat'].map((step, i) => (
              <span key={step} className="flex items-center gap-2">
                <span className="text-xs font-medium text-text-tertiary">{step}</span>
                {i < 4 && <ArrowRight className="w-3.5 h-3.5 text-text-muted" />}
              </span>
            ))}
          </div>
        </FadeInUp>
      </SectionWrapper>

      {/* -- Context Memory -- */}
      <SectionWrapper>
        <div className="grid lg:grid-cols-2 gap-12 items-center">
          <div>
            <FadeInUp>
              <p className="text-[11px] uppercase tracking-[0.12em] text-brand-sage font-semibold mb-4">
                {t('contextMemory.overline')}
              </p>
              <h2 className="text-[clamp(32px,3.5vw,44px)] font-bold text-text-primary leading-[1.1]">
                {t('contextMemory.title')}
              </h2>
            </FadeInUp>
            <FadeInUp delay={0.1}>
              <p className="text-text-secondary mt-5 leading-relaxed">{t('contextMemory.desc1')}</p>
              <p className="text-text-secondary mt-4 leading-relaxed">{t('contextMemory.desc2')}</p>
            </FadeInUp>
          </div>
          <FadeInUp delay={0.15}>
            <div className="bg-surface-1 rounded-xl border border-border p-6 space-y-4">
              {(['phase1', 'phase2', 'phase3', 'phase4'] as const).map((phase) => (
                <div key={phase} className="flex gap-4 items-start">
                  <div className="shrink-0 w-20">
                    <span className="text-xs font-semibold text-brand-sage">
                      {t(`contextMemory.${phase}.day`)}
                    </span>
                  </div>
                  <div>
                    <p className="text-sm font-semibold text-text-primary">
                      {t(`contextMemory.${phase}.label`)}
                    </p>
                    <p className="text-xs text-text-tertiary mt-0.5">
                      {t(`contextMemory.${phase}.desc`)}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* -- Confidence Scoring -- */}
      <SectionWrapper dark>
        <SectionTitle
          overline={t('confidenceScoring.overline')}
          title={t('confidenceScoring.title')}
          subtitle={t('confidenceScoring.subtitle')}
        />
        <div className="max-w-3xl mx-auto mt-14 space-y-6">
          {confidenceConfigs.map((band, i) => (
            <FadeInUp key={band.key} delay={i * 0.1}>
              <div className="bg-surface-2 rounded-xl border border-border p-6">
                <div className="flex flex-wrap items-center gap-4 mb-3">
                  <span className="text-lg font-bold text-text-primary font-mono">
                    {t(`confidenceScoring.${band.key}.range`)}
                  </span>
                  <span className="text-sm font-semibold text-text-secondary">
                    {t(`confidenceScoring.${band.key}.label`)}
                  </span>
                </div>
                <div className="w-full h-1.5 bg-surface-3 rounded-full mb-3">
                  <div
                    className={`h-full ${band.color} rounded-full`}
                    style={{ width: confidenceBarWidths[band.key] }}
                  />
                </div>
                <p className="text-sm text-text-secondary leading-relaxed">
                  {t(`confidenceScoring.${band.key}.desc`)}
                </p>
              </div>
            </FadeInUp>
          ))}
        </div>
      </SectionWrapper>

      {/* -- Collective Threat Intelligence -- */}
      <SectionWrapper>
        <div className="grid lg:grid-cols-2 gap-12 items-center">
          <FadeInUp>
            <div className="bg-surface-1 rounded-xl border border-border p-6">
              <div className="space-y-4">
                {collectiveConfigs.map((item) => (
                  <div key={item.key} className="flex gap-4 items-start">
                    <item.icon className="w-5 h-5 text-brand-sage shrink-0 mt-0.5" />
                    <div>
                      <p className="text-sm font-semibold text-text-primary">
                        {t(`collectiveIntelligence.${item.key}.label`)}
                      </p>
                      <p className="text-xs text-text-tertiary mt-0.5">
                        {t(`collectiveIntelligence.${item.key}.desc`)}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </FadeInUp>
          <div>
            <FadeInUp>
              <p className="text-[11px] uppercase tracking-[0.12em] text-brand-sage font-semibold mb-4">
                {t('collectiveIntelligence.overline')}
              </p>
              <h2 className="text-[clamp(32px,3.5vw,44px)] font-bold text-text-primary leading-[1.1]">
                {t('collectiveIntelligence.title')}
              </h2>
            </FadeInUp>
            <FadeInUp delay={0.1}>
              <p className="text-text-secondary mt-5 leading-relaxed">
                {t('collectiveIntelligence.desc1')}
              </p>
              <p className="text-text-secondary mt-4 leading-relaxed">
                {t('collectiveIntelligence.desc2')}
              </p>
            </FadeInUp>
          </div>
        </div>
      </SectionWrapper>

      {/* -- Graceful Degradation -- */}
      <SectionWrapper dark>
        <SectionTitle
          overline={t('resilience.overline')}
          title={t('resilience.title')}
          subtitle={t('resilience.subtitle')}
        />
        <div className="max-w-3xl mx-auto mt-14">
          <FadeInUp>
            <div className="bg-surface-2 rounded-xl border border-border overflow-hidden">
              {resilienceConfigs.map((level, i) => (
                <div
                  key={level.key}
                  className={`flex items-start gap-4 p-6 ${i < 3 ? 'border-b border-border' : ''}`}
                >
                  <div className={`w-2 h-2 rounded-full ${level.color} mt-1.5 shrink-0`} />
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <level.icon className="w-4 h-4 text-text-tertiary" />
                      <p className="text-sm font-semibold text-text-primary">
                        {t(`resilience.${level.key}.status`)}
                      </p>
                    </div>
                    <p className="text-sm text-text-secondary leading-relaxed">
                      {t(`resilience.${level.key}.desc`)}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* -- Tech Stack -- */}
      <SectionWrapper>
        <SectionTitle
          overline={t('stack.overline')}
          title={t('stack.title')}
          subtitle={t('stack.subtitle')}
        />
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4 mt-14">
          {stackConfigs.map((item, i) => (
            <FadeInUp key={item.key} delay={i * 0.05}>
              <div className="card-glow bg-surface-1 rounded-xl border border-border p-5 text-center hover:border-border-hover transition-colors">
                <item.icon className="w-5 h-5 text-brand-sage mx-auto mb-3" />
                <p className="text-sm font-semibold text-text-primary">
                  {t(`stack.${item.key}.name`)}
                </p>
                <p className="text-xs text-text-tertiary mt-1">{t(`stack.${item.key}.desc`)}</p>
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
                href="/early-access"
                className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3.5 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
              >
                {t('cta.cta1')} <ArrowRight className="w-4 h-4" />
              </Link>
              <Link
                href="/docs"
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
