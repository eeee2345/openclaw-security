'use client';

import { useTranslations } from 'next-intl';
import { Link } from '@/navigation';
import { ArrowRight } from 'lucide-react';
import {
  ShieldIcon,
  AnalyticsIcon,
  GlobalIcon,
} from '@/components/ui/BrandIcons';
import BrandLogo from '@/components/ui/BrandLogo';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import { STATS } from '@/lib/stats';

/* ────────────────────────────  Product config  ──────────────────────── */

const productConfigs = [
  /* ── Core Pillars ── */
  {
    key: 'atr' as const,
    icon: AnalyticsIcon,
    badgeColor: 'bg-brand-sage/10 text-brand-sage border-brand-sage/20',
    description:
      `ATR (Agent Threat Rules) is the first open standard for detecting AI agent threats. ${STATS.atrRules} YAML-based rules across 9 categories cover prompt injection, tool poisoning, skill compromise, unauthorized access, data exfiltration, and more. Like Sigma for network attacks, ATR gives the security community a shared language for AI agent threats. Rules are open-source, human-readable, and machine-enforceable.`,
    features: [
      `${STATS.atrRules} rules across 9 threat categories`,
      'YAML-based, human-readable rule format',
      'Covers prompt injection, tool poisoning, skill compromise, data exfiltration',
      'Open-source -- community-contributed and reviewed',
      'Machine-enforceable by Guard and any compatible engine',
      'Versioned rule lifecycle: draft, experimental, stable, deprecated',
    ],
    href: '/atr',
  },
  {
    key: 'threatCloud' as const,
    icon: GlobalIcon,
    badgeColor: 'bg-brand-sage/10 text-brand-sage border-brand-sage/20',
    description:
      `Threat Cloud is a self-hosted collective intelligence network. Every Panguard install contributes anonymized threat signals; the pipeline auto-generates Sigma, YARA, and ATR rules from real-world attacks. ${STATS.threatIntel.sources} threat intel sources, ${STATS.threatIntel.validatedRecords.toLocaleString()} validated IoC records, and ${STATS.threatIntel.promotedRules} community-promoted rules -- all synced every 6 hours. The more nodes participate, the stronger everyone's defense.`,
    features: [
      `${STATS.threatIntel.sources} threat intel sources with ${STATS.threatIntel.validatedRecords.toLocaleString()} validated records`,
      'Auto-generates Sigma, YARA, and ATR rules from collective data',
      `${STATS.threatIntel.promotedRules} community-promoted rules, synced every ${STATS.threatIntel.syncInterval}`,
      'Self-hosted -- your data never leaves your infrastructure',
      'Honeypot intelligence feeds from Trap deployments',
      'Confidence scoring and rule lifecycle management',
    ],
    href: '/threat-cloud',
  },
  {
    key: 'guard' as const,
    icon: ShieldIcon,
    badgeColor: 'bg-brand-sage/10 text-brand-sage border-brand-sage/20',
    description:
      `Panguard Guard is the enforcement engine. A 4-agent pipeline (Detect, Analyze, Respond, Report) processes OS-level events through ${STATS.sigmaRules.toLocaleString()} Sigma rules, ${STATS.yaraRules.toLocaleString()} YARA signatures, and ${STATS.atrRules} ATR rules. Built-in Skill Auditor runs ${STATS.skillAuditChecks} checks before any AI skill is installed. Three response modules auto-block IPs, kill processes, and quarantine files.`,
    features: [
      '4-agent AI pipeline: Detect, Analyze, Respond, Report',
      `${STATS.totalRules.toLocaleString()}+ detection rules (Sigma + YARA + ATR)`,
      `Skill Auditor: ${STATS.skillAuditChecks}-layer pre-install security gate`,
      '3 auto-response modules: IP Blocker, Process Killer, File Quarantine',
      'Works with Claude Code, Cursor, OpenClaw, WorkBuddy, and any AI agent',
      'Supports Linux, macOS, Windows, Docker, Kubernetes',
    ],
    href: '/product/guard',
  },
];

/* ════════════════════════  Component  ═══════════════════════ */

export default function ProductOverviewContent() {
  const t = useTranslations('product.overview');

  return (
    <>
      <p id="definition" className="sr-only">
        Panguard AI secures AI agents through three pillars: ATR (the open standard for agent threat
        rules), Threat Cloud (collective immunity network), and Guard (the enforcement engine with
        skill audit and auto-response).
      </p>

      {/* ───────────── Hero ───────────── */}
      <section className="pt-24 pb-4 px-6 text-center">
        <FadeInUp>
          <p className="text-[11px] uppercase tracking-[0.12em] text-brand-sage font-semibold mb-4">
            {t('overline')}
          </p>
          <h1 className="text-[clamp(40px,5vw,64px)] font-bold text-text-primary leading-[1.08] max-w-4xl mx-auto">
            {t('title')}
            <br />
            <span className="text-brand-sage">{t('titleHighlight')}</span>
          </h1>
          <p className="text-text-secondary mt-4 text-lg max-w-2xl mx-auto leading-relaxed">
            {t('subtitle')}
          </p>
        </FadeInUp>
        <FadeInUp delay={0.1}>
          <div className="mt-10 max-w-[240px] mx-auto">
            {/* CSS phone frame */}
            <div className="relative rounded-[36px] border-4 border-border bg-surface-1 p-2 shadow-2xl">
              {/* Notch */}
              <div className="absolute top-2 left-1/2 -translate-x-1/2 w-20 h-5 bg-surface-0 rounded-b-xl z-10" />
              {/* Screen */}
              <div className="rounded-[28px] bg-surface-0 overflow-hidden pt-6">
                {/* Status bar */}
                <div className="flex items-center justify-center gap-1.5 px-4 py-2">
                  <BrandLogo size={14} className="text-brand-sage" />
                  <span className="text-[10px] font-semibold text-text-primary">PANGUARD</span>
                </div>
                {/* Protected badge */}
                <div className="px-4 py-3 text-center">
                  <div className="w-10 h-10 rounded-full bg-status-safe/10 flex items-center justify-center mx-auto">
                    <BrandLogo size={18} className="text-status-safe" />
                  </div>
                  <p className="text-xs font-semibold text-status-safe mt-2">Protected</p>
                  <p className="text-[9px] text-text-muted mt-0.5">3 endpoints active</p>
                </div>
                {/* Mini stats */}
                <div className="grid grid-cols-3 gap-px bg-border mx-3">
                  {[
                    { v: '847', l: 'Blocked' },
                    { v: '99.9%', l: 'Uptime' },
                    { v: '0', l: 'Alerts' },
                  ].map((s) => (
                    <div key={s.l} className="bg-surface-0 py-2 text-center">
                      <p className="text-xs font-bold text-text-primary">{s.v}</p>
                      <p className="text-[8px] text-text-muted">{s.l}</p>
                    </div>
                  ))}
                </div>
                {/* Recent */}
                <div className="px-3 py-3 space-y-1.5">
                  {[
                    { t: 'SSH blocked', c: 'bg-status-caution' },
                    { t: 'Model updated', c: 'bg-status-safe' },
                    { t: 'Scan complete', c: 'bg-status-info' },
                  ].map((e) => (
                    <div key={e.t} className="flex items-center gap-2">
                      <span className={`w-1 h-1 rounded-full ${e.c} shrink-0`} />
                      <span className="text-[9px] text-text-tertiary">{e.t}</span>
                    </div>
                  ))}
                </div>
                {/* Bottom spacer for home indicator */}
                <div className="h-4" />
              </div>
            </div>
          </div>
        </FadeInUp>
      </section>

      {/* ───────────── Product Sections ───────────── */}
      {productConfigs.map((product, i) => (
        <SectionWrapper key={product.key} dark={i % 2 === 1}>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 lg:gap-16 items-start">
            {/* Left: Info */}
            <FadeInUp>
              <div>
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-10 h-10 rounded-xl bg-surface-2 border border-border flex items-center justify-center">
                    <product.icon className="w-5 h-5 text-brand-sage" />
                  </div>
                  <div>
                    <h2 className="text-2xl font-bold text-text-primary">
                      {t(`products.${product.key}.name`)}
                    </h2>
                    <span
                      className={`inline-block ${product.badgeColor} border text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded-full`}
                    >
                      {t(`products.${product.key}.badge`)}
                    </span>
                  </div>
                </div>

                <p className="text-xl text-text-primary font-medium mt-2 mb-4">
                  {t(`products.${product.key}.tagline`)}
                </p>

                <p className="text-text-secondary leading-relaxed">{product.description}</p>

                <Link
                  href={product.href}
                  className="inline-flex items-center gap-2 mt-6 text-brand-sage hover:text-brand-sage-light font-medium transition-colors group"
                >
                  Learn more about {t(`products.${product.key}.name`)}
                  <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                </Link>
              </div>
            </FadeInUp>

            {/* Right: Features */}
            <FadeInUp delay={0.1}>
              <div className="bg-surface-1 rounded-2xl border border-border p-8 card-glow">
                <p className="text-xs uppercase tracking-wider text-text-muted font-semibold mb-5">
                  {t('capabilities')}
                </p>
                <ul className="space-y-4">
                  {product.features.map((feature) => (
                    <li
                      key={feature}
                      className="flex items-start gap-3 text-sm text-text-secondary"
                    >
                      <div className="w-1.5 h-1.5 rounded-full bg-brand-sage mt-2 shrink-0" />
                      {feature}
                    </li>
                  ))}
                </ul>
              </div>
            </FadeInUp>
          </div>
        </SectionWrapper>
      ))}

      {/* ───────────── Bottom CTA ───────────── */}
      <SectionWrapper>
        <FadeInUp>
          <div className="text-center max-w-2xl mx-auto">
            <h2 className="text-[clamp(20px,3.5vw,40px)] font-bold text-text-primary leading-[1.1]">
              {t('cta.title')}
            </h2>
            <p className="text-text-secondary mt-4 leading-relaxed">{t('cta.subtitle')}</p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mt-8">
              <Link
                href="/docs/getting-started"
                className="bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3.5 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
              >
                {t('cta.cta1')}
              </Link>
              <Link
                href="/atr"
                className="border border-border text-text-secondary font-semibold rounded-full px-8 py-3.5 hover:border-brand-sage hover:text-text-primary transition-all duration-200"
              >
                {t('cta.cta2')}
              </Link>
            </div>
          </div>
        </FadeInUp>
      </SectionWrapper>
    </>
  );
}
