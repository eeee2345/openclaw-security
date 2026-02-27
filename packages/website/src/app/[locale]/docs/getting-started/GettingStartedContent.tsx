'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { Copy, Check } from 'lucide-react';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import { Link } from '@/navigation';
import { CheckIcon as BrandCheck } from '@/components/ui/BrandIcons';

function CodeBlock({ code, label }: { code: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="bg-surface-1 border border-border rounded-xl overflow-hidden">
      {label && (
        <div className="px-4 py-2 border-b border-border flex items-center justify-between">
          <span className="text-xs text-text-muted">{label}</span>
          <button
            onClick={handleCopy}
            className="text-text-muted hover:text-text-secondary transition-colors p-1"
            aria-label="Copy code"
          >
            {copied ? (
              <Check className="w-3.5 h-3.5 text-status-safe" />
            ) : (
              <Copy className="w-3.5 h-3.5" />
            )}
          </button>
        </div>
      )}
      <pre className="p-4 text-sm font-mono text-text-secondary overflow-x-auto leading-relaxed">
        {code}
      </pre>
    </div>
  );
}

function TerminalOutput({ lines }: { lines: string[] }) {
  return (
    <div className="bg-surface-1 border border-border rounded-xl p-4 font-mono text-sm space-y-1">
      {lines.map((line, i) => {
        const isOk = line.startsWith('[OK]');
        return (
          <p key={i} className={isOk ? 'text-status-safe' : 'text-text-secondary'}>
            {line}
          </p>
        );
      })}
    </div>
  );
}

export default function GettingStartedContent() {
  const t = useTranslations('docs.gettingStarted');

  const requirements = [t('req1'), t('req2'), t('req3')];

  return (
    <>
      <SectionWrapper spacing="spacious">
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <Link
              href="/docs"
              className="text-sm text-text-muted hover:text-brand-sage transition-colors"
            >
              {t('backToDocs')}
            </Link>
            <h1 className="text-[clamp(32px,4vw,48px)] font-bold text-text-primary mt-4 leading-[1.1]">
              {t('title')}
            </h1>
            <p className="text-text-secondary mt-4 text-lg leading-relaxed">{t('subtitle')}</p>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Requirements */}
      <SectionWrapper>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-4">{t('requirementsTitle')}</h2>
            <ul className="space-y-2">
              {requirements.map((req) => (
                <li key={req} className="flex items-center gap-2 text-text-secondary">
                  <BrandCheck className="w-4 h-4 text-brand-sage shrink-0" />
                  {req}
                </li>
              ))}
            </ul>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Step 1: Install */}
      <SectionWrapper dark>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">{t('step1Title')}</h2>
            <p className="text-text-secondary mb-6">{t('step1Desc')}</p>
            <CodeBlock code="curl -fsSL https://get.panguard.ai | sh" label="Terminal" />
            <p className="text-xs text-text-muted mt-3">{t('step1Note')}</p>
            <TerminalOutput
              lines={[
                '[OK] Panguard v1.0.0 installed',
                '[OK] Rule engine loaded (3,155 Sigma + 423 YARA rules)',
                '[OK] Local LLM ready (Ollama)',
                '[OK] Monitoring started. Learning period: 7 days.',
              ]}
            />
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Step 2: Quick Scan */}
      <SectionWrapper>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">{t('step2Title')}</h2>
            <p className="text-text-secondary mb-6">{t('step2Desc')}</p>
            <CodeBlock code="panguard scan" label="Terminal" />
            <p className="text-text-secondary mt-4 mb-4">{t('step2Deep')}</p>
            <CodeBlock code="panguard scan --deep" label="Terminal" />
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Step 3: Guard */}
      <SectionWrapper dark>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">{t('step3Title')}</h2>
            <p className="text-text-secondary mb-6">{t('step3Desc')}</p>
            <CodeBlock code="panguard guard start" label="Terminal" />
            <TerminalOutput
              lines={[
                '[OK] Guard daemon started',
                '[OK] Watching 12 network interfaces',
                '[OK] Sigma rules: 3,155 loaded',
                '[OK] YARA rules: 423 loaded',
                '[OK] Baseline learning: active (7 days)',
              ]}
            />
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Step 4: Chat */}
      <SectionWrapper>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">{t('step4Title')}</h2>
            <p className="text-text-secondary mb-6">{t('step4Desc')}</p>
            <CodeBlock
              code={`panguard chat config\n# Follow the prompts to connect Slack, LINE, or Telegram`}
              label="Terminal"
            />
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Step 5: Understanding Scan Results */}
      <SectionWrapper dark>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">{t('step5Title')}</h2>
            <p className="text-text-secondary mb-6">{t('step5Desc')}</p>
            <div className="space-y-3">
              <div className="bg-surface-1 border border-border rounded-xl p-4">
                <p className="text-text-secondary text-sm leading-relaxed">
                  <span className="font-semibold text-text-primary">Score: </span>
                  {t('step5Score')}
                </p>
              </div>
              <div className="bg-surface-1 border border-border rounded-xl p-4">
                <p className="text-text-secondary text-sm leading-relaxed">
                  <span className="font-semibold text-text-primary">Grade: </span>
                  {t('step5Grade')}
                </p>
              </div>
              <div className="bg-surface-1 border border-border rounded-xl p-4">
                <p className="text-text-secondary text-sm leading-relaxed">
                  <span className="font-semibold text-text-primary">Findings: </span>
                  {t('step5Findings')}
                </p>
              </div>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Step 6: JSON Output for AI Agents */}
      <SectionWrapper>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">{t('step6Title')}</h2>
            <p className="text-text-secondary mb-6">{t('step6Desc')}</p>
            <CodeBlock code="panguard scan --json" label="Terminal" />
            <p className="text-xs text-text-muted mt-3 mb-4">{t('step6Note')}</p>
            <p className="text-text-secondary text-sm mb-3">{t('step6Output')}</p>
            <CodeBlock
              code={`{
  "version": "0.5.0",
  "target": "localhost",
  "risk_score": 35,
  "grade": "C",
  "findings_count": 8,
  "findings": [ ... ],
  "agent_friendly": true
}`}
              label="JSON"
            />
            <p className="text-text-secondary text-sm mt-4">{t('step6Integration')}</p>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Step 7: Remote Scanning */}
      <SectionWrapper dark>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">{t('step7Title')}</h2>
            <p className="text-text-secondary mb-6">{t('step7Desc')}</p>
            <CodeBlock
              code={`panguard scan --target example.com\npanguard scan --target 1.2.3.4 --json`}
              label="Terminal"
            />
            <p className="text-xs text-text-muted mt-3">{t('step7Note')}</p>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Step 8: Compliance Reports */}
      <SectionWrapper>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">{t('step8Title')}</h2>
            <p className="text-text-secondary mb-6">{t('step8Desc')}</p>
            <CodeBlock
              code={`panguard report generate --framework iso27001\npanguard report generate --framework soc2\npanguard report generate --framework tcsa`}
              label="Terminal"
            />
            <p className="text-text-secondary text-sm mt-4 mb-2">{t('step8Frameworks')}</p>
            <p className="text-xs text-text-muted">{t('step8Note')}</p>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Step 9: More CLI Commands */}
      <SectionWrapper dark>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">{t('step9Title')}</h2>
            <p className="text-text-secondary mb-6">{t('step9Desc')}</p>
            <div className="space-y-4">
              <div>
                <p className="text-text-secondary text-sm mb-2">{t('step9Whoami')}</p>
                <CodeBlock code="panguard whoami" label="Terminal" />
              </div>
              <div>
                <p className="text-text-secondary text-sm mb-2">{t('step9Chat')}</p>
                <CodeBlock code="panguard chat config" label="Terminal" />
              </div>
              <div>
                <p className="text-text-secondary text-sm mb-2">{t('step9Trap')}</p>
                <CodeBlock code="panguard trap deploy --services ssh,http" label="Terminal" />
              </div>
              <div>
                <p className="text-text-secondary text-sm mb-2">{t('step9Report')}</p>
                <CodeBlock code="panguard report list" label="Terminal" />
              </div>
              <div>
                <p className="text-text-secondary text-sm mb-2">{t('step9Status')}</p>
                <CodeBlock code="panguard guard status" label="Terminal" />
              </div>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Next steps CTA */}
      <SectionWrapper dark>
        <div className="max-w-3xl mx-auto text-center">
          <FadeInUp>
            <h2 className="text-2xl font-bold text-text-primary mb-3">{t('nextTitle')}</h2>
            <p className="text-text-secondary mb-8">{t('nextDesc')}</p>
            <div className="flex flex-wrap justify-center gap-3">
              <Link
                href="/docs"
                className="border border-border text-text-secondary hover:text-text-primary hover:border-brand-sage font-semibold rounded-full px-8 py-3.5 transition-all duration-200"
              >
                {t('nextDocs')}
              </Link>
              <a
                href="https://github.com/panguard-ai/panguard-ai"
                target="_blank"
                rel="noopener noreferrer"
                className="border border-border text-text-secondary hover:text-text-primary hover:border-brand-sage font-semibold rounded-full px-8 py-3.5 transition-all duration-200"
              >
                GitHub
              </a>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>
    </>
  );
}
