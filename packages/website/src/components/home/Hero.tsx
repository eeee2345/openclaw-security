'use client';
import { useState, useEffect, useRef } from 'react';
import { useTranslations } from 'next-intl';
import { Copy, Check, ArrowRight, CheckCircle } from 'lucide-react';
import { Link } from '@/navigation';
import { useOS } from '@/hooks/useOS';

function InstallBar() {
  const t = useTranslations('home.hero');
  const { installCmd, prompt } = useOS();
  const [copied, setCopied] = useState(false);
  const [typedLen, setTypedLen] = useState(0);
  const [typing, setTyping] = useState(false);
  const [done, setDone] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const started = useRef(false);

  useEffect(() => {
    if (started.current || !ref.current) return;
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting && !started.current) {
          started.current = true;
          setTimeout(() => setTyping(true), 600);
        }
      },
      { threshold: 0.5 }
    );
    observer.observe(ref.current);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    if (!typing || done) return;
    if (typedLen >= installCmd.length) {
      setDone(true);
      return;
    }
    const timeout = setTimeout(() => setTypedLen((l) => l + 1), 35);
    return () => clearTimeout(timeout);
  }, [typing, typedLen, installCmd, done]);

  const handleCopy = () => {
    navigator.clipboard.writeText(installCmd);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <div className="max-w-md mx-auto" ref={ref}>
      <div className="relative flex items-center gap-3 bg-surface-1/80 backdrop-blur-sm border border-border rounded-xl px-5 py-3.5 font-mono text-sm">
        <span className="text-brand-sage select-none">{prompt}</span>
        <code className="text-text-secondary flex-1 truncate">
          {done ? installCmd : installCmd.slice(0, typedLen)}
          {!done && typing && <span className="cursor-blink text-brand-sage">_</span>}
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

/* ===========================  Hero Component  =========================== */

export default function Hero() {
  const t = useTranslations('home.hero');

  return (
    <section className="relative min-h-screen flex items-center justify-center overflow-hidden">
      {/* -- Background: pure CSS, no JS animation overhead -- */}

      {/* Grid */}
      <div
        className="absolute inset-0 pointer-events-none opacity-[0.03]"
        style={{
          backgroundImage:
            'linear-gradient(rgba(139,154,142,1) 1px, transparent 1px), linear-gradient(90deg, rgba(139,154,142,1) 1px, transparent 1px)',
          backgroundSize: '80px 80px',
        }}
      />

      {/* Central glow orb -- CSS animation */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[700px] rounded-full pointer-events-none hero-orb" />

      {/* Scan line -- CSS animation */}
      <div className="absolute left-0 right-0 pointer-events-none hero-scanline" />

      {/* -- Content -- */}
      <div className="relative z-10 text-center px-6 py-24 max-w-4xl mx-auto">
        {/* Eyebrow */}
        <div className="hero-entrance" style={{ animationDelay: '0s' }}>
          <p className="text-[11px] uppercase tracking-[0.12em] text-brand-sage font-semibold mb-6">
            {t('eyebrow')}
          </p>
        </div>

        {/* Title */}
        <div className="hero-entrance" style={{ animationDelay: '0.1s' }}>
          <h1 className="text-[clamp(36px,6vw,72px)] font-extrabold leading-[1.1] tracking-tight text-text-primary">
            {t('title')}
          </h1>
          <p className="text-[clamp(36px,6vw,72px)] font-extrabold leading-[1.1] tracking-tight text-brand-sage mt-2">
            {t('titleLine2')}
          </p>
        </div>

        {/* Subtitle */}
        <div className="mt-8 max-w-2xl mx-auto hero-entrance" style={{ animationDelay: '0.25s' }}>
          <p className="text-lg lg:text-xl text-text-secondary leading-relaxed">
            {t('subtitle1')}
          </p>
          <p className="text-lg lg:text-xl text-text-secondary leading-relaxed mt-4">
            {t('subtitle2')}
          </p>
          <p className="text-base lg:text-lg text-text-primary leading-relaxed mt-4 font-semibold">
            {t('subtitle3')}
          </p>
        </div>

        {/* Install command */}
        <div className="mt-10 hero-entrance" style={{ animationDelay: '0.4s' }}>
          <InstallBar />
        </div>

        {/* Buttons */}
        <div
          className="flex flex-wrap gap-3 justify-center mt-8 hero-entrance-fade"
          style={{ animationDelay: '0.55s' }}
        >
          <Link
            href="/early-access"
            className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3.5 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
          >
            {t('getStarted')} <ArrowRight className="w-4 h-4" />
          </Link>
          <a
            href="https://github.com/panguard-ai/panguard-ai"
            target="_blank"
            rel="noopener noreferrer"
            className="border border-border text-text-secondary hover:text-text-primary hover:border-brand-sage font-semibold rounded-full px-8 py-3.5 transition-all duration-200"
          >
            {t('github')}
          </a>
        </div>

        {/* Social proof badges */}
        <div
          className="flex flex-wrap gap-3 justify-center mt-6 hero-entrance-fade"
          style={{ animationDelay: '0.7s' }}
        >
          {(['mit', 'tests', 'taiwan'] as const).map((key) => (
            <span
              key={key}
              className="inline-flex items-center gap-1.5 text-xs text-text-tertiary bg-surface-1/50 border border-border/50 rounded-full px-3 py-1.5"
            >
              <CheckCircle className="w-3 h-3 text-brand-sage" />
              {t(`badges.${key}`)}
            </span>
          ))}
        </div>
      </div>

      {/* Bottom gradient fade */}
      <div className="absolute bottom-0 left-0 right-0 h-32 bg-gradient-to-t from-surface-0 to-transparent pointer-events-none" />
    </section>
  );
}
