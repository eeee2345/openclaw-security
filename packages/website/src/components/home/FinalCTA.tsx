'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { motion } from 'framer-motion';
import { Copy, Check, ArrowRight, CheckCircle } from 'lucide-react';
import { Link } from '@/navigation';
import { useOS } from '@/hooks/useOS';

const ease = [0.22, 1, 0.36, 1] as const;

export default function FinalCTA() {
  const t = useTranslations('home.finalCta');
  const { installCmd, prompt } = useOS();
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(installCmd);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <section className="bg-gradient-to-b from-[#0a0a0a] to-[#0d2614] px-6 py-12 sm:py-16">
      <div className="max-w-3xl mx-auto text-center">
        {/* Title */}
        <motion.h2
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-60px' }}
          transition={{ duration: 0.5, ease }}
          className="text-4xl md:text-5xl font-bold text-text-primary"
        >
          {t('title')}
        </motion.h2>

        <motion.p
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true, margin: '-60px' }}
          transition={{ duration: 0.4, delay: 0.15, ease }}
          className="text-lg text-gray-400 mt-4 max-w-xl mx-auto"
        >
          {t('subtitle')}
        </motion.p>

        {/* Install command */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.4, delay: 0.3, ease }}
          className="mt-8"
        >
          <div className="relative flex items-center gap-3 bg-[#0a0a0a] border border-border rounded-xl px-5 py-3.5 font-mono text-sm max-w-md mx-auto">
            <span className="text-panguard-green select-none">{prompt}</span>
            <code className="text-text-secondary flex-1 select-all truncate text-left">
              {installCmd}
            </code>
            <button
              onClick={handleCopy}
              className="text-text-muted hover:text-text-secondary transition-colors p-1 shrink-0"
              aria-label="Copy install command"
            >
              {copied ? <Check className="w-4 h-4 text-status-safe" /> : <Copy className="w-4 h-4" />}
            </button>
            {copied && (
              <span className="toast-copied absolute -top-8 left-1/2 -translate-x-1/2 text-xs text-status-safe bg-surface-1 border border-border rounded px-2 py-1">
                Copied!
              </span>
            )}
          </div>
        </motion.div>

        {/* CTA Buttons */}
        <motion.div
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.4, delay: 0.4, ease }}
          className="flex flex-wrap justify-center gap-3 mt-8"
        >
          <Link
            href="/docs/getting-started"
            className="inline-flex items-center gap-2 bg-panguard-green text-white font-semibold rounded-full px-8 py-3.5 hover:bg-panguard-green-light transition-all duration-200 active:scale-[0.98]"
          >
            {t('btnGetStarted')} <ArrowRight className="w-4 h-4" />
          </Link>
          <a
            href="https://github.com/panguard-ai/panguard-ai"
            target="_blank"
            rel="noopener noreferrer"
            className="border border-border text-text-secondary hover:text-text-primary hover:border-panguard-green font-semibold rounded-full px-8 py-3.5 transition-all duration-200"
          >
            {t('btnGithub')}
          </a>
          <Link
            href="/docs"
            className="border border-border text-text-secondary hover:text-text-primary hover:border-panguard-green font-semibold rounded-full px-8 py-3.5 transition-all duration-200"
          >
            {t('btnDocs')}
          </Link>
        </motion.div>

        {/* Manifesto */}
        <motion.p
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.4, delay: 0.5, ease }}
          className="text-sm text-text-secondary font-semibold mt-12 max-w-lg mx-auto leading-relaxed"
        >
          {t('manifesto')}
        </motion.p>

        {/* Trust badges */}
        <motion.div
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.4, delay: 0.6, ease }}
          className="flex flex-wrap justify-center gap-3 mt-8"
        >
          {(['badge1', 'badge2', 'badge3'] as const).map((key) => (
            <span
              key={key}
              className="flex items-center gap-2 text-xs text-text-tertiary bg-surface-2/50 border border-border rounded-full px-3 py-1.5"
            >
              <CheckCircle className="w-3 h-3 text-panguard-green" />
              {t(key)}
            </span>
          ))}
        </motion.div>
      </div>
    </section>
  );
}
