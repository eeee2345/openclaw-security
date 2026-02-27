'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { Copy, Check, ArrowRight } from 'lucide-react';
import { Link } from '@/navigation';
import FadeInUp from '../FadeInUp';
import SectionWrapper from '../ui/SectionWrapper';

const installCmd = 'curl -fsSL https://get.panguard.ai | sh';

export default function CallToAction() {
  const t = useTranslations('home.cta');
  const tc = useTranslations('common');
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(installCmd);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <SectionWrapper>
      <div className="max-w-2xl mx-auto text-center">
        <FadeInUp>
          <h2 className="text-[clamp(28px,3vw,40px)] font-bold text-text-primary">{t('title')}</h2>
          <p className="text-text-secondary mt-3">{t('subtitle')}</p>
        </FadeInUp>

        {/* Curl install */}
        <FadeInUp delay={0.1}>
          <p className="text-xs text-text-muted uppercase tracking-wider mt-10 mb-3">
            {t('curlLabel')}
          </p>
          <div className="relative flex items-center gap-3 bg-surface-1 border border-border rounded-xl px-5 py-3.5 font-mono text-sm">
            <span className="text-brand-sage select-none">$</span>
            <code className="text-text-secondary flex-1 select-all truncate text-left">
              {installCmd}
            </code>
            <button
              onClick={handleCopy}
              className="text-text-muted hover:text-text-secondary transition-colors p-1 shrink-0"
              aria-label="Copy install command"
            >
              {copied ? (
                <Check className="w-4 h-4 text-status-safe" />
              ) : (
                <Copy className="w-4 h-4" />
              )}
            </button>
            {copied && (
              <span className="toast-copied absolute -top-8 left-1/2 -translate-x-1/2 text-xs text-status-safe bg-surface-1 border border-border rounded px-2 py-1">
                {t('copied')}
              </span>
            )}
          </div>
        </FadeInUp>

        {/* CTA buttons */}
        <FadeInUp delay={0.2}>
          <div className="flex flex-wrap justify-center gap-3 mt-10">
            <Link
              href="/early-access"
              className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3.5 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
            >
              {tc('getStarted')} <ArrowRight className="w-4 h-4" />
            </Link>
            <Link
              href="/docs"
              className="border border-border text-text-secondary hover:text-text-primary hover:border-brand-sage font-semibold rounded-full px-8 py-3.5 transition-all duration-200"
            >
              {tc('learnMore')}
            </Link>
          </div>
        </FadeInUp>
      </div>
    </SectionWrapper>
  );
}
