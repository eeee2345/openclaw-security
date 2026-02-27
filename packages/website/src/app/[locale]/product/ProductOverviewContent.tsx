'use client';

import { useTranslations } from 'next-intl';
import { Link } from '@/navigation';
import { ArrowRight } from 'lucide-react';
import {
  ScanIcon,
  ShieldIcon,
  TerminalIcon,
  NetworkIcon,
  AnalyticsIcon,
} from '@/components/ui/BrandIcons';
import BrandLogo from '@/components/ui/BrandLogo';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';

/* ────────────────────────────  Product config  ──────────────────────── */

const productConfigs = [
  {
    key: 'scan' as const,
    icon: ScanIcon,
    badgeColor: 'bg-status-safe/10 text-status-safe border-status-safe/20',
    description:
      'Run a comprehensive AI security audit on any endpoint with a single command. Panguard Scan analyzes open ports, running services, file permissions, network exposure, and known vulnerability databases. In under a minute, you receive a detailed PDF report with a risk score, prioritized findings, and actionable remediation steps -- no configuration, no agent installation required.',
    features: [
      'One-command execution -- no setup or agent needed',
      'AI-prioritized vulnerability ranking by real-world exploitability',
      'PDF report with risk score, findings, and fix instructions',
      'Covers ports, services, permissions, CVEs, and misconfigurations',
      'Unlimited scans on all plans, free forever',
      'API available for CI/CD pipeline integration',
    ],
    href: '/product/scan',
  },
  {
    key: 'guard' as const,
    icon: ShieldIcon,
    badgeColor: 'bg-status-safe/10 text-status-safe border-status-safe/20',
    description:
      'Panguard Guard is the always-on AI agent that monitors your endpoints 24/7. Using a three-layer detection engine -- signature matching, behavioral heuristics, and deep-learning anomaly detection -- Guard identifies threats in real time and responds automatically. Suspicious processes get quarantined. Lateral movement gets blocked. You get notified in plain language through your preferred channel.',
    features: [
      '3-layer AI detection: signatures, behavior, deep learning',
      'Automated threat response -- quarantine, block, isolate',
      'Sub-second detection with minimal resource overhead',
      'Cross-endpoint correlation for lateral movement detection',
      'Alerts via Slack, LINE, Telegram, email, or webhook',
      'Self-healing agent that auto-updates without downtime',
    ],
    href: '/product/guard',
  },
  {
    key: 'chat' as const,
    icon: TerminalIcon,
    badgeColor: 'bg-status-safe/10 text-status-safe border-status-safe/20',
    description:
      'Security alerts are useless if nobody understands them. Panguard Chat translates every detection, every log entry, and every recommendation into plain language. Ask it questions in natural English (or Chinese), get real-time explanations of what happened and what to do. Chat integrates into Slack, LINE, and Telegram so your team never has to leave their workflow.',
    features: [
      'Natural language explanations of every security event',
      'Interactive Q&A -- ask follow-ups, request deeper analysis',
      'Multi-language support including English and Traditional Chinese',
      'Slack, LINE, and Telegram integration',
      'Context-aware: understands your infrastructure topology',
      'Suggested remediation steps with copy-paste commands',
    ],
    href: '/product/chat',
  },
  {
    key: 'trap' as const,
    icon: NetworkIcon,
    badgeColor: 'bg-status-caution/10 text-status-caution border-status-caution/20',
    description:
      'Panguard Trap deploys lightweight, AI-generated honeypots across your network. These decoy services mimic real databases, SSH servers, admin panels, and API endpoints. When an attacker interacts with a trap, Panguard captures their techniques, tools, and intent -- then feeds that intelligence back into Guard to strengthen your defenses automatically.',
    features: [
      'AI-generated decoy services that look and respond like real systems',
      'Automatic deployment across your network topology',
      'Full attacker session recording and technique classification',
      'MITRE ATT&CK mapping for every captured interaction',
      'Intelligence feedback loop into Guard detection models',
      'Zero false positives -- legitimate users never touch honeypots',
    ],
    href: '/product/trap',
  },
  {
    key: 'report' as const,
    icon: AnalyticsIcon,
    badgeColor: 'bg-status-info/10 text-status-info border-status-info/20',
    description:
      'Generating compliance documentation used to take weeks and expensive consultants. Panguard Report continuously monitors your security posture against frameworks like ISO 27001, SOC 2, and GDPR, then auto-generates audit-ready reports with evidence. When gaps are detected, Report provides step-by-step remediation guides so you can close findings before auditors arrive.',
    features: [
      'Auto-generated ISO 27001, SOC 2, and GDPR reports',
      'Continuous compliance monitoring with real-time gap detection',
      'Evidence collection linked directly to controls',
      'Auditor-ready PDF exports with executive summaries',
      'Remediation guides with prioritized action items',
      'Scheduled reports -- weekly, monthly, or on-demand',
    ],
    href: '/product/report',
  },
];

/* ════════════════════════  Component  ═══════════════════════ */

export default function ProductOverviewContent() {
  const t = useTranslations('product.overview');

  return (
    <>
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
            <h2 className="text-[clamp(28px,3.5vw,40px)] font-bold text-text-primary leading-[1.1]">
              {t('cta.title')}
            </h2>
            <p className="text-text-secondary mt-4 leading-relaxed">{t('cta.subtitle')}</p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mt-8">
              <Link
                href="/early-access"
                className="bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3.5 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
              >
                {t('cta.cta1')}
              </Link>
              <Link
                href="/demo"
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
