'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { Copy, Check, ArrowRight } from 'lucide-react';
import { Link } from '@/navigation';
import FadeInUp from '../FadeInUp';
import SectionWrapper from '../ui/SectionWrapper';
import { CheckIcon } from '@/components/ui/BrandIcons';

const installCmd = 'curl -fsSL https://get.panguard.ai | sh';

export default function FinalCTA() {
  const t = useTranslations('home.finalCta');
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(installCmd);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <SectionWrapper dark spacing="spacious">
      <div className="max-w-3xl mx-auto text-center">
        {/* Title */}
        <FadeInUp>
          <h2 className="text-[clamp(32px,4vw,48px)] font-bold text-text-primary">{t('title')}</h2>
          <p className="text-text-secondary mt-3 text-lg">{t('subtitle')}</p>
        </FadeInUp>

        {/* Install command */}
        <FadeInUp delay={0.1}>
          <div className="relative flex items-center gap-3 bg-surface-0 border border-border rounded-xl px-5 py-3.5 font-mono text-sm max-w-md mx-auto mt-10">
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
                Copied!
              </span>
            )}
          </div>
        </FadeInUp>

        {/* CTA Buttons */}
        <FadeInUp delay={0.2}>
          <div className="flex flex-wrap justify-center gap-3 mt-8">
            <Link
              href="/docs/getting-started"
              className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3.5 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
            >
              {t('btnGetStarted')} <ArrowRight className="w-4 h-4" />
            </Link>
            <a
              href="https://github.com/panguard-ai/panguard-ai"
              target="_blank"
              rel="noopener noreferrer"
              className="border border-border text-text-secondary hover:text-text-primary hover:border-brand-sage font-semibold rounded-full px-8 py-3.5 transition-all duration-200"
            >
              {t('btnGithub')}
            </a>
            <Link
              href="/docs"
              className="border border-border text-text-secondary hover:text-text-primary hover:border-brand-sage font-semibold rounded-full px-8 py-3.5 transition-all duration-200"
            >
              {t('btnDocs')}
            </Link>
          </div>
        </FadeInUp>

        {/* Manifesto */}
        <FadeInUp delay={0.3}>
          <div className="mt-12 space-y-1">
            <p className="text-sm text-text-tertiary">{t('manifesto1')}</p>
            <p className="text-sm text-text-secondary font-medium">{t('manifesto2')}</p>
            <p className="text-sm text-brand-sage font-semibold">{t('manifesto3')}</p>
          </div>
        </FadeInUp>

        {/* Trust badges */}
        <FadeInUp delay={0.4}>
          <div className="flex flex-wrap justify-center gap-3 mt-8">
            {['MIT Open Source', '1,107 Tests Passing', 'Built in Taiwan'].map((badge) => (
              <span
                key={badge}
                className="flex items-center gap-2 text-xs text-text-tertiary bg-surface-2 border border-border rounded-full px-3 py-1.5"
              >
                <CheckIcon className="w-3 h-3 text-brand-sage" />
                {badge}
              </span>
            ))}
          </div>
        </FadeInUp>
      </div>
    </SectionWrapper>
  );
}
