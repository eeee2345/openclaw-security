'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { Copy, Check } from 'lucide-react';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import { Link } from '@/navigation';
import { CheckIcon } from '@/components/ui/BrandIcons';

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

export default function DeploymentContent() {
  const t = useTranslations('docs.deployment');

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

      {/* SSH Batch Install */}
      <SectionWrapper dark>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">{t('sshTitle')}</h2>
            <p className="text-text-secondary mb-6">{t('sshDesc')}</p>
            <CodeBlock
              code={`#!/bin/bash
# servers.txt: one IP per line
SERVERS="servers.txt"

while IFS= read -r server; do
  echo "Installing on $server..."
  ssh "root@$server" 'curl -fsSL https://get.panguard.ai | bash'
  echo "Starting guard on $server..."
  ssh "root@$server" 'panguard guard start'
done < "$SERVERS"

echo "Done. All endpoints deployed."`}
              label="deploy.sh"
            />
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Ansible Playbook */}
      <SectionWrapper>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">{t('ansibleTitle')}</h2>
            <p className="text-text-secondary mb-6">{t('ansibleDesc')}</p>
            <CodeBlock
              code={`# panguard.yml
---
- name: Deploy Panguard
  hosts: all
  become: yes
  tasks:
    - name: Install Panguard
      shell: curl -fsSL https://get.panguard.ai | bash
      args:
        creates: /usr/local/bin/panguard

    - name: Start Guard
      shell: panguard guard start
      args:
        creates: /etc/systemd/system/panguard-guard.service

# Run: ansible-playbook -i inventory.ini panguard.yml`}
              label="panguard.yml"
            />
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Threat Cloud */}
      <SectionWrapper dark>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-2">{t('threatCloudTitle')}</h2>
            <p className="text-text-secondary mb-6">{t('threatCloudDesc')}</p>
            <CodeBlock
              code={`# On each endpoint, after install:
panguard login

# Verify connection
panguard status

# View all endpoints in Threat Cloud dashboard
# https://cloud.panguard.ai/endpoints`}
              label="Terminal"
            />
            <p className="text-xs text-text-muted mt-3">{t('threatCloudNote')}</p>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Tips */}
      <SectionWrapper>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <h2 className="text-xl font-bold text-text-primary mb-6">{t('tipsTitle')}</h2>
            <div className="space-y-3">
              {(['tip1', 'tip2', 'tip3', 'tip4'] as const).map((key) => (
                <div key={key} className="flex items-start gap-3">
                  <CheckIcon className="w-4 h-4 text-brand-sage shrink-0 mt-0.5" />
                  <p className="text-sm text-text-secondary leading-relaxed">{t(key)}</p>
                </div>
              ))}
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Back links */}
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
                href="/docs/advanced-setup"
                className="border border-border text-text-secondary hover:text-text-primary hover:border-brand-sage font-semibold rounded-full px-8 py-3.5 transition-all duration-200"
              >
                {t('goToAdvancedSetup')}
              </Link>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>
    </>
  );
}
