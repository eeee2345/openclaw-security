'use client';

import { useTranslations } from 'next-intl';
import { Link } from '@/navigation';
import { CheckIcon } from '@/components/ui/BrandIcons';
import FadeInUp from '@/components/FadeInUp';
import { STATS } from '@/lib/stats';

/* ── All-inclusive feature list ── */

const features = [
  `${STATS.totalRules.toLocaleString()}+ detection rules (Sigma + YARA + ATR)`,
  '4-agent AI pipeline: Detect, Analyze, Respond, Report',
  `${STATS.atrRules} Agent Threat Rules across 9 categories`,
  'Threat Cloud collective intelligence network',
  `Skill Auditor with ${STATS.skillAuditChecks}-layer security checks`,
  `${STATS.honeypotProtocols} protocol honeypots (SSH, HTTP, MySQL, Redis, SMB, RDP, FTP, Telnet)`,
  'Auto-response: IP Blocker, Process Killer, File Quarantine',
  'Chat notifications: Telegram, Slack, Email, Webhook, LINE',
  `Compliance reports: ${STATS.complianceControls} controls (ISO 27001, SOC 2, TCSA)`,
  `${STATS.mcpTools} MCP tools for AI assistant integration`,
  'Unlimited machines, unlimited scans',
  'Full source code (MIT License)',
];

export default function PricingCards() {
  const t = useTranslations('pricingPage');

  return (
    <>
      <FadeInUp>
        <div className="max-w-2xl mx-auto">
          <div className="bg-surface-1 rounded-2xl border border-brand-sage p-8 sm:p-10 relative">
            <span className="absolute -top-3 left-1/2 -translate-x-1/2 bg-brand-sage text-surface-0 text-[10px] font-bold uppercase tracking-wider px-4 py-1 rounded-full whitespace-nowrap">
              {t('badge')}
            </span>

            <div className="text-center mb-8">
              <p className="text-xs uppercase tracking-wider text-text-muted font-semibold">
                {t('planName')}
              </p>
              <div className="mt-3">
                <span className="text-5xl font-extrabold text-text-primary">$0</span>
                <span className="text-xs uppercase tracking-wider text-brand-sage font-semibold ml-3">{t('badge')}</span>
              </div>
              <p className="text-sm text-text-secondary mt-2">{t('planDesc')}</p>
            </div>

            <div className="grid sm:grid-cols-2 gap-x-8 gap-y-3 mb-8">
              {features.map((f) => (
                <div key={f} className="flex items-start gap-2.5 text-sm text-text-secondary">
                  <CheckIcon className="w-4 h-4 text-brand-sage mt-0.5 shrink-0" />
                  {f}
                </div>
              ))}
            </div>

            <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
              <Link
                href="/docs/getting-started"
                className="bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3.5 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98] text-center w-full sm:w-auto"
              >
                {t('ctaInstall')}
              </Link>
              <a
                href="https://github.com/panguard-ai/panguard"
                target="_blank"
                rel="noopener noreferrer"
                className="border border-border text-text-secondary font-semibold rounded-full px-8 py-3.5 hover:border-brand-sage hover:text-text-primary transition-all duration-200 text-center w-full sm:w-auto"
              >
                {t('ctaGithub')}
              </a>
            </div>
          </div>
        </div>
      </FadeInUp>

      <FadeInUp delay={0.1}>
        <p className="text-sm text-text-tertiary text-center mt-8 max-w-xl mx-auto">
          {t('openSourceNote')}
        </p>
      </FadeInUp>
    </>
  );
}
