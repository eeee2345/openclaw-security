'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { Copy, Check } from 'lucide-react';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import { Link } from '@/navigation';

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

export default function AdvancedSetupContent() {
  const t = useTranslations('docs.advancedSetup');

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

      <SectionWrapper>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <p className="text-sm text-brand-sage font-semibold mb-2">{t('degradeNote')}</p>
            <p className="text-text-secondary text-sm leading-relaxed mb-8">{t('degradeDesc')}</p>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Ollama */}
      <SectionWrapper dark>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">{t('ollamaTitle')}</h2>
            <p className="text-text-secondary mb-6">{t('ollamaDesc')}</p>
            <CodeBlock
              code={`# Install Ollama\ncurl -fsSL https://ollama.ai/install.sh | sh\n\n# Pull a model\nollama pull llama3\n\n# Verify it's running\ncurl http://localhost:11434/api/tags`}
              label="Terminal"
            />
            <p className="text-xs text-text-muted mt-3">{t('ollamaNote')}</p>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Falco */}
      <SectionWrapper>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">{t('falcoTitle')}</h2>
            <p className="text-text-secondary mb-6">{t('falcoDesc')}</p>
            <CodeBlock
              code={`# Ubuntu/Debian\ncurl -fsSL https://falco.org/repo/falcosecurity-packages.asc | sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg\nsudo apt update && sudo apt install -y falco\n\n# Start Falco\nsudo systemctl enable falco && sudo systemctl start falco`}
              label="Terminal (Linux)"
            />
            <p className="text-xs text-text-muted mt-3">{t('falcoNote')}</p>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Suricata */}
      <SectionWrapper dark>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">{t('suricataTitle')}</h2>
            <p className="text-text-secondary mb-6">{t('suricataDesc')}</p>
            <CodeBlock
              code={`# Ubuntu/Debian\nsudo apt install -y suricata\n\n# Start Suricata\nsudo systemctl enable suricata && sudo systemctl start suricata`}
              label="Terminal (Linux)"
            />
            <p className="text-xs text-text-muted mt-3">{t('suricataNote')}</p>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Environment Variables */}
      <SectionWrapper>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">{t('envTitle')}</h2>
            <p className="text-text-secondary mb-6">{t('envDesc')}</p>
            <div className="bg-surface-1 border border-border rounded-xl overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border">
                    <th className="text-left py-3 px-4 text-text-muted font-medium">
                      {t('envVar')}
                    </th>
                    <th className="text-left py-3 px-4 text-text-muted font-medium">
                      {t('envPurpose')}
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {(['env1', 'env2', 'env3', 'env4'] as const).map((key) => (
                    <tr key={key} className="border-b border-border/50">
                      <td className="py-3 px-4 font-mono text-xs text-brand-sage">
                        {t(`${key}.var`)}
                      </td>
                      <td className="py-3 px-4 text-text-secondary text-xs">
                        {t(`${key}.purpose`)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Back to docs */}
      <SectionWrapper dark>
        <div className="max-w-3xl mx-auto text-center">
          <FadeInUp>
            <div className="flex flex-wrap justify-center gap-3">
              <Link
                href="/docs/getting-started"
                className="border border-border text-text-secondary hover:text-text-primary hover:border-brand-sage font-semibold rounded-full px-8 py-3.5 transition-all duration-200"
              >
                {t('backToGettingStarted')}
              </Link>
              <Link
                href="/docs/deployment"
                className="border border-border text-text-secondary hover:text-text-primary hover:border-brand-sage font-semibold rounded-full px-8 py-3.5 transition-all duration-200"
              >
                {t('goToDeployment')}
              </Link>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>
    </>
  );
}
