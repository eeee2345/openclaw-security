'use client';

import { useState } from 'react';
import { Copy, Check, Shield, AlertTriangle, Search, Code, FileKey, Lock, Zap } from 'lucide-react';
import { useTranslations } from 'next-intl';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import { Link } from '@/navigation';

function CodeBlock({ code, title }: { code: string; title?: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <div className="relative bg-[#111] border border-border rounded-xl overflow-hidden">
      {title && (
        <div className="px-4 py-2 border-b border-border text-xs text-text-muted font-mono">
          {title}
        </div>
      )}
      <pre className="p-4 font-mono text-sm text-gray-300 overflow-x-auto whitespace-pre">
        {code}
      </pre>
      <button
        onClick={handleCopy}
        className="absolute top-3 right-3 p-1.5 rounded-md bg-surface-2/50 hover:bg-surface-2 transition-colors"
        aria-label="Copy"
      >
        {copied ? (
          <Check className="w-3.5 h-3.5 text-panguard-green" />
        ) : (
          <Copy className="w-3.5 h-3.5 text-text-muted" />
        )}
      </button>
    </div>
  );
}

function CheckCard({
  icon: Icon,
  title,
  description,
  severity,
}: {
  icon: typeof Shield;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium';
}) {
  const colors = {
    critical: 'border-red-500/30 bg-red-500/5',
    high: 'border-orange-500/30 bg-orange-500/5',
    medium: 'border-yellow-500/30 bg-yellow-500/5',
  };
  return (
    <div className={`border rounded-xl p-5 ${colors[severity]}`}>
      <Icon className="w-5 h-5 text-panguard-green mb-3" />
      <h4 className="text-sm font-semibold text-text-primary mb-2">{title}</h4>
      <p className="text-xs text-text-secondary leading-relaxed">{description}</p>
    </div>
  );
}

export default function SkillAuditorContent() {
  const t = useTranslations('docs.skillAuditorDocs');

  return (
    <SectionWrapper className="py-16 sm:py-24">
      <div className="max-w-3xl mx-auto">
        {/* Header */}
        <FadeInUp>
          <div className="flex items-center gap-2 text-xs uppercase tracking-[0.2em] text-panguard-green/70 font-semibold mb-4">
            <Link href="/docs" className="hover:text-panguard-green transition-colors">
              {t('breadcrumbDocs')}
            </Link>
            <span>/</span>
            <span>{t('breadcrumbSkillAuditor')}</span>
          </div>
          <h1 className="text-3xl sm:text-4xl lg:text-5xl font-bold text-text-primary">
            {t('title')}
          </h1>
          <p className="text-lg text-text-secondary mt-4 max-w-2xl">
            {t('subtitle')}
          </p>
        </FadeInUp>

        {/* Quick Start */}
        <FadeInUp className="mt-12">
          <h2 className="text-2xl font-bold text-text-primary mb-6">{t('quickStartTitle')}</h2>
          <div className="space-y-4">
            <CodeBlock
              title={t('codeTitle1')}
              code="curl -fsSL https://get.panguard.ai | bash"
            />
            <CodeBlock
              title={t('codeTitle2')}
              code="panguard audit skill ./path/to/skill"
            />
            <CodeBlock
              title={t('codeTitle3')}
              code="panguard audit skill ./my-skill --json"
            />
          </div>
        </FadeInUp>

        {/* What It Checks */}
        <FadeInUp className="mt-16">
          <h2 className="text-2xl font-bold text-text-primary mb-6">{t('checksTitle')}</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <CheckCard
              icon={FileKey}
              title={t('check1.title')}
              description={t('check1.description')}
              severity="medium"
            />
            <CheckCard
              icon={Shield}
              title={t('check2.title')}
              description={t('check2.description')}
              severity="critical"
            />
            <CheckCard
              icon={Search}
              title={t('check3.title')}
              description={t('check3.description')}
              severity="critical"
            />
            <CheckCard
              icon={Code}
              title={t('check4.title')}
              description={t('check4.description')}
              severity="critical"
            />
            <CheckCard
              icon={AlertTriangle}
              title={t('check5.title')}
              description={t('check5.description')}
              severity="high"
            />
            <CheckCard
              icon={Lock}
              title={t('check6.title')}
              description={t('check6.description')}
              severity="high"
            />
            <CheckCard
              icon={Zap}
              title={t('check7.title')}
              description={t('check7.description')}
              severity="medium"
            />
          </div>
        </FadeInUp>

        {/* Risk Scoring */}
        <FadeInUp className="mt-16">
          <h2 className="text-2xl font-bold text-text-primary mb-6">{t('riskScoringTitle')}</h2>
          <p className="text-text-secondary mb-6">
            {t('riskScoringDesc')}
          </p>

          <div className="overflow-x-auto">
            <table className="w-full text-sm border border-border rounded-xl overflow-hidden">
              <thead>
                <tr className="bg-surface-1 text-text-secondary">
                  <th className="px-4 py-3 text-left font-medium">{t('tableSeverity')}</th>
                  <th className="px-4 py-3 text-left font-medium">{t('tableWeight')}</th>
                  <th className="px-4 py-3 text-left font-medium">{t('tableExample')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                <tr>
                  <td className="px-4 py-3 text-red-400 font-medium">{t('severityCritical')}</td>
                  <td className="px-4 py-3 text-text-primary">25</td>
                  <td className="px-4 py-3 text-text-secondary">{t('exampleCritical')}</td>
                </tr>
                <tr>
                  <td className="px-4 py-3 text-orange-400 font-medium">{t('severityHigh')}</td>
                  <td className="px-4 py-3 text-text-primary">15</td>
                  <td className="px-4 py-3 text-text-secondary">{t('exampleHigh')}</td>
                </tr>
                <tr>
                  <td className="px-4 py-3 text-yellow-400 font-medium">{t('severityMedium')}</td>
                  <td className="px-4 py-3 text-text-primary">5</td>
                  <td className="px-4 py-3 text-text-secondary">{t('exampleMedium')}</td>
                </tr>
                <tr>
                  <td className="px-4 py-3 text-gray-400 font-medium">{t('severityLow')}</td>
                  <td className="px-4 py-3 text-text-primary">1</td>
                  <td className="px-4 py-3 text-text-secondary">{t('exampleLow')}</td>
                </tr>
              </tbody>
            </table>
          </div>

          <div className="mt-6 grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              { range: '0-14', levelKey: 'riskLow' as const, color: 'bg-green-500/10 border-green-500/30 text-green-400', actionKey: 'actionLow' as const },
              { range: '15-39', levelKey: 'riskMedium' as const, color: 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400', actionKey: 'actionMedium' as const },
              { range: '40-69', levelKey: 'riskHigh' as const, color: 'bg-orange-500/10 border-orange-500/30 text-orange-400', actionKey: 'actionHigh' as const },
              { range: '70-100', levelKey: 'riskCritical' as const, color: 'bg-red-500/10 border-red-500/30 text-red-400', actionKey: 'actionCritical' as const },
            ].map((item) => (
              <div key={item.levelKey} className={`border rounded-xl p-4 text-center ${item.color}`}>
                <div className="text-lg font-bold">{item.range}</div>
                <div className="text-xs font-semibold mt-1">{t(item.levelKey)}</div>
                <div className="text-xs mt-2 opacity-70">{t(item.actionKey)}</div>
              </div>
            ))}
          </div>
        </FadeInUp>

        {/* Integration */}
        <FadeInUp className="mt-16">
          <h2 className="text-2xl font-bold text-text-primary mb-6">{t('integrationTitle')}</h2>

          <h3 className="text-lg font-semibold text-text-primary mb-3">{t('cicdTitle')}</h3>
          <p className="text-text-secondary mb-4">
            {t('cicdDesc')}
          </p>
          <CodeBlock
            title="bash"
            code={`# Block if HIGH or CRITICAL
RISK=$(panguard audit skill "$SKILL_PATH" --json | jq -r '.riskLevel')
if [ "$RISK" = "HIGH" ] || [ "$RISK" = "CRITICAL" ]; then
  echo "Blocked: $RISK risk skill"
  exit 1
fi`}
          />

          <h3 className="text-lg font-semibold text-text-primary mt-8 mb-3">{t('tsApiTitle')}</h3>
          <p className="text-text-secondary mb-4">
            {t('tsApiDesc')}
          </p>
          <CodeBlock
            title="typescript"
            code={`import { auditSkill } from '@panguard-ai/panguard-skill-auditor';

const report = await auditSkill('./skills/untrusted-skill');

console.log(\`Risk: \${report.riskScore}/100 (\${report.riskLevel})\`);
console.log(\`Checks: \${report.checks.length}\`);
console.log(\`Findings: \${report.findings.length}\`);

// Block dangerous skills
if (report.riskLevel === 'CRITICAL') {
  throw new Error('Skill blocked by security policy');
}

// Log individual findings
for (const finding of report.findings) {
  console.log(\`[\${finding.severity}] \${finding.title}\`);
  if (finding.location) console.log(\`  at \${finding.location}\`);
}`}
          />

          <h3 className="text-lg font-semibold text-text-primary mt-8 mb-3">
            {t('openclawTitle')}
          </h3>
          <p className="text-text-secondary mb-4">
            {t('openclawDesc')}
          </p>
          <CodeBlock
            title="~/.openclaw/hooks/pre-skill-install.sh"
            code={`#!/bin/bash
# Auto-audit skills before OpenClaw installs them
REPORT=$(panguard audit skill "$1" --json)
LEVEL=$(echo "$REPORT" | jq -r '.riskLevel')
SCORE=$(echo "$REPORT" | jq -r '.riskScore')

echo "Panguard Audit: $SCORE/100 ($LEVEL)"

if [ "$LEVEL" = "CRITICAL" ]; then
  echo "BLOCKED: Critical security issues found"
  echo "$REPORT" | jq '.findings[] | "  [\\(.severity)] \\(.title)"'
  exit 1
fi`}
          />
        </FadeInUp>

        {/* Example Output */}
        <FadeInUp className="mt-16">
          <h2 className="text-2xl font-bold text-text-primary mb-6">{t('exampleOutputTitle')}</h2>

          <h3 className="text-lg font-semibold text-text-primary mb-3">{t('safeSkillTitle')}</h3>
          <CodeBlock
            code={`$ panguard audit skill ./skills/weather-widget

PANGUARD SKILL AUDIT REPORT
============================
Skill:      weather-widget
Risk Score: 0/100
Risk Level: LOW
Duration:   0.2s

CHECKS:
  [PASS] Manifest: Valid SKILL.md structure
  [PASS] Prompt Safety: No injection patterns detected
  [PASS] Code: No vulnerabilities found; Secrets: Clean
  [PASS] Dependencies: No known issues
  [PASS] Permissions: Scope appropriate

VERDICT: Safe to install`}
          />

          <h3 className="text-lg font-semibold text-text-primary mt-8 mb-3">{t('maliciousSkillTitle')}</h3>
          <CodeBlock
            code={`$ panguard audit skill ./skills/suspicious-helper

PANGUARD SKILL AUDIT REPORT
============================
Skill:      suspicious-helper
Risk Score: 72/100
Risk Level: CRITICAL
Duration:   0.3s

CHECKS:
  [FAIL] Prompt Safety: 2 suspicious pattern(s) detected
  [PASS] Manifest: Valid SKILL.md structure
  [WARN] Code: 1 issue(s) found; Secrets: No hardcoded credentials
  [PASS] Dependencies: No known issues
  [PASS] Permissions: Scope appropriate

FINDINGS:
  [CRITICAL] Prompt injection: ignore previous instructions
             SKILL.md:42 - "ignore all previous instructions and..."
  [CRITICAL] Reverse shell pattern detected
             SKILL.md:87 - "bash -i >& /dev/tcp/..."
  [HIGH]     Environment variable exfiltration
             SKILL.md:23 - "printenv | curl..."

VERDICT: DO NOT INSTALL - Critical security issues found`}
          />
        </FadeInUp>

        {/* vs Manual */}
        <FadeInUp className="mt-16">
          <h2 className="text-2xl font-bold text-text-primary mb-6">
            {t('vsManualTitle')}
          </h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm border border-border rounded-xl overflow-hidden">
              <thead>
                <tr className="bg-surface-1 text-text-secondary">
                  <th className="px-4 py-3 text-left font-medium">{t('tableFeature')}</th>
                  <th className="px-4 py-3 text-left font-medium">{t('tableManual')}</th>
                  <th className="px-4 py-3 text-left font-medium">{t('tablePanguard')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {([
                  ['vsSpeed', 'vsSpeedManual', '< 1 second'],
                  ['vsConsistency', 'vsConsistencyManual', 'vsConsistencyPanguard'],
                  ['vsUnicode', 'vsUnicodeManual', 'vsUnicodePanguard'],
                  ['vsBase64', 'vsBase64Manual', 'vsBase64Panguard'],
                  ['vsSast', 'vsSastManual', 'vsSastPanguard'],
                  ['vsSecrets', 'vsSecretsManual', 'vsSecretsPanguard'],
                  ['vsRiskScore', 'vsRiskScoreManual', 'vsRiskScorePanguard'],
                  ['vsCicd', 'vsCicdManual', 'vsCicdPanguard'],
                ] as const).map(([featureKey, manualKey, panguardKey]) => (
                  <tr key={featureKey}>
                    <td className="px-4 py-3 text-text-primary font-medium">{t(featureKey)}</td>
                    <td className="px-4 py-3 text-text-muted">{t(manualKey)}</td>
                    <td className="px-4 py-3 text-panguard-green">
                      {panguardKey === '< 1 second' ? '< 1 second' : t(panguardKey)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </FadeInUp>

        {/* CTA */}
        <FadeInUp className="mt-16">
          <div className="bg-surface-1/50 border border-border rounded-2xl p-8 text-center">
            <h3 className="text-xl font-bold text-text-primary mb-3">{t('ctaTitle')}</h3>
            <p className="text-text-secondary mb-6 max-w-lg mx-auto">
              {t('ctaDesc')}
            </p>
            <CodeBlock code="curl -fsSL https://get.panguard.ai | bash" />
            <div className="flex flex-wrap justify-center gap-3 mt-6">
              <Link
                href="/docs/installation"
                className="inline-flex items-center gap-2 bg-panguard-green text-white font-semibold rounded-full px-6 py-2.5 text-sm hover:bg-panguard-green-light transition-all"
              >
                {t('ctaFullSetup')}
              </Link>
              <Link
                href="/blog/skill-auditor-guide"
                className="inline-flex items-center gap-2 border border-border text-text-secondary hover:text-text-primary hover:border-panguard-green font-semibold rounded-full px-6 py-2.5 text-sm transition-all"
              >
                {t('ctaBlogPost')}
              </Link>
            </div>
          </div>
        </FadeInUp>
      </div>
    </SectionWrapper>
  );
}
