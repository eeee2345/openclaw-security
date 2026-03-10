'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { motion } from 'framer-motion';
import { Copy, Check, ArrowRight, KeyRound, MessageSquareOff, Bot, ShieldAlert } from 'lucide-react';
import { Link } from '@/navigation';
import BrandLogo from '@/components/ui/BrandLogo';
import { CheckIcon } from '@/components/ui/BrandIcons';

const INSTALL_CMD = 'npx panguard guard --watch';

function InstallBar() {
  const t = useTranslations('revolution.hero');
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(INSTALL_CMD);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="max-w-md mx-auto">
      <div className="relative flex items-center gap-2 sm:gap-3 bg-surface-1/80 backdrop-blur-sm border border-border rounded-xl px-4 sm:px-5 py-3 sm:py-3.5 font-mono text-sm">
        <span className="text-panguard-green select-none shrink-0">$</span>
        <code className="text-text-secondary flex-1 select-all min-w-0 overflow-x-auto whitespace-nowrap scrollbar-none break-all">
          {INSTALL_CMD}
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
            {t('copied')}
          </span>
        )}
      </div>
    </div>
  );
}

const ease = [0.22, 1, 0.36, 1] as const;

const threatIcons = [KeyRound, MessageSquareOff, Bot, ShieldAlert];

export default function RevolutionHero() {
  const t = useTranslations('revolution.hero');

  return (
    <section className="relative min-h-screen flex items-center justify-center overflow-hidden bg-[#0a0a0a]">
      {/* Grid background */}
      <div
        className="absolute inset-0 pointer-events-none opacity-[0.03]"
        style={{
          backgroundImage:
            'linear-gradient(rgba(107,143,113,1) 1px, transparent 1px), linear-gradient(90deg, rgba(107,143,113,1) 1px, transparent 1px)',
          backgroundSize: '80px 80px',
        }}
      />

      {/* Central glow orb */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[min(700px,200vw)] h-[min(700px,200vw)] rounded-full pointer-events-none hero-orb" />

      {/* Content */}
      <div className="relative z-10 text-center px-5 sm:px-6 pt-20 pb-12 max-w-4xl mx-auto">
        {/* Brand Logo */}
        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.5, ease }}
          className="mb-6"
        >
          <BrandLogo size={36} className="text-panguard-green mx-auto sm:w-12 sm:h-12" />
        </motion.div>

        {/* Overline */}
        <motion.p
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.5, delay: 0.1, ease }}
          className="text-xs uppercase tracking-[0.2em] text-panguard-green font-semibold mb-6"
        >
          {t('eyebrow')}
        </motion.p>

        {/* Title */}
        <motion.h1
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.1, ease }}
          className="text-[clamp(22px,6vw,64px)] font-bold leading-[1.12] tracking-tight text-text-primary max-w-3xl mx-auto"
        >
          {t('title')}
        </motion.h1>

        {/* Subtitle line 1 — the problem */}
        <motion.p
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.3, ease }}
          className="mt-8 max-w-2xl mx-auto text-lg sm:text-xl text-text-secondary leading-relaxed"
        >
          {t('subtitleLine1')}
        </motion.p>

        {/* Threat cards */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.5, ease }}
          className="mt-8 max-w-2xl mx-auto"
        >
          <p className="text-sm font-semibold text-red-400 uppercase tracking-wider mb-4">
            {t('threats.title')}
          </p>
          <div className="grid grid-cols-2 gap-3">
            {[0, 1, 2, 3].map((i) => {
              const Icon = threatIcons[i];
              return (
                <div
                  key={i}
                  className="border border-red-500/20 bg-red-500/5 rounded-lg px-4 py-3 text-left"
                >
                  <div className="flex items-center gap-2 mb-1">
                    <Icon className="w-4 h-4 text-red-400 shrink-0" />
                    <span className="text-sm font-semibold text-text-primary">
                      {t(`threats.items.${i}.label`)}
                    </span>
                  </div>
                  <p className="text-xs text-text-muted leading-relaxed">
                    {t(`threats.items.${i}.detail`)}
                  </p>
                </div>
              );
            })}
          </div>
        </motion.div>

        {/* Subtitle line 2 + 3 — the solution */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.7, ease }}
          className="mt-8 max-w-2xl mx-auto space-y-3"
        >
          <p className="text-lg sm:text-xl text-text-primary font-medium leading-relaxed">
            {t('subtitleLine2')}
          </p>
          <p className="text-lg sm:text-xl text-panguard-green font-semibold leading-relaxed">
            {t('subtitleLine3')}
          </p>
        </motion.div>

        {/* Install command */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 1.0, ease }}
          className="mt-10"
        >
          <InstallBar />
        </motion.div>

        {/* CTA Buttons */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.5, delay: 1.2, ease }}
          className="flex flex-wrap gap-3 justify-center mt-8"
        >
          <a
            href="https://github.com/Agent-Threat-Rule/agent-threat-rules"
            target="_blank"
            rel="noopener noreferrer"
            className="border border-border text-text-secondary hover:text-text-primary hover:border-panguard-green font-semibold rounded-full px-6 sm:px-8 py-3.5 text-sm sm:text-base transition-all duration-200"
          >
            {t('viewATR')}
          </a>
          <Link
            href="/docs/installation"
            className="inline-flex items-center gap-2 bg-panguard-green text-white font-semibold rounded-full px-6 sm:px-8 py-3.5 text-sm sm:text-base hover:bg-panguard-green-light transition-all duration-200 active:scale-[0.98]"
          >
            {t('install')} <ArrowRight className="w-4 h-4" />
          </Link>
        </motion.div>

        {/* Trust line */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.5, delay: 1.3, ease }}
          className="flex flex-wrap gap-3 justify-center mt-6"
        >
          {(['mit', 'rules', 'tests', 'taiwan'] as const).map((key) => (
            <span
              key={key}
              className="inline-flex items-center gap-1.5 text-xs text-text-tertiary bg-surface-1/50 border border-border/50 rounded-full px-3 py-1.5"
            >
              <CheckIcon size={12} className="text-panguard-green" />
              {t(`badges.${key}`)}
            </span>
          ))}
        </motion.div>
      </div>

      {/* Bottom gradient fade */}
      <div className="absolute bottom-0 left-0 right-0 h-32 bg-gradient-to-t from-[#0e0f0e] to-transparent pointer-events-none" />
    </section>
  );
}
