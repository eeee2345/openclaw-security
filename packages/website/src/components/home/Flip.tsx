'use client';

import { useTranslations } from 'next-intl';
import { motion } from 'framer-motion';
import FadeInUp from '../FadeInUp';
import SectionWrapper from '../ui/SectionWrapper';
import BrandLogo from '../ui/BrandLogo';

/** Visual separator: crossed-out dashboard vs auto-fix */
function FlipVisual({ t }: { t: ReturnType<typeof useTranslations> }) {
  return (
    <FadeInUp delay={0.1}>
      <div className="flex items-center gap-6 py-2" aria-hidden="true">
        <div className="flex items-center gap-2 opacity-40">
          <svg
            width="20"
            height="20"
            viewBox="0 0 24 24"
            fill="none"
            stroke="#F5F1E8"
            strokeWidth="1.5"
          >
            <rect x="3" y="3" width="18" height="14" rx="2" />
            <line x1="3" y1="21" x2="21" y2="21" />
            <line x1="12" y1="17" x2="12" y2="21" />
          </svg>
          <span className="text-sm text-text-tertiary line-through">{t('dashboard')}</span>
        </div>
        <svg width="24" height="12" viewBox="0 0 24 12" fill="none" className="opacity-30">
          <path d="M0 6h20m0 0l-4-4m4 4l-4 4" stroke="#8B9A8E" strokeWidth="1.5" />
        </svg>
        <div className="flex items-center gap-2">
          <svg
            width="20"
            height="20"
            viewBox="0 0 24 24"
            fill="none"
            stroke="#8B9A8E"
            strokeWidth="1.5"
          >
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            <polyline points="9 12 11 14 15 10" />
          </svg>
          <span className="text-sm text-brand-sage font-medium">{t('autoFixed')}</span>
        </div>
      </div>
    </FadeInUp>
  );
}

/** Compact radar visualization */
function AgentProtection({ t }: { t: ReturnType<typeof useTranslations> }) {
  const orbitDots = [
    { left: '88%', top: '14%' },
    { left: '8%', top: '10%' },
    { left: '84%', top: '54%' },
    { left: '50%', top: '1%' },
    { left: '14%', top: '50%' },
    { left: '94%', top: '34%' },
  ];

  return (
    <motion.div
      className="relative w-[260px] h-[260px] shrink-0"
      initial={{ opacity: 0, scale: 0.95 }}
      whileInView={{ opacity: 1, scale: 1 }}
      viewport={{ once: true, margin: '-60px' }}
      transition={{ duration: 0.8, delay: 0.3 }}
      aria-hidden="true"
    >
      {/* Glow */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[160px] h-[160px] rounded-full bg-brand-sage/[0.04] blur-[50px]" />

      {/* Rings */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[240px] h-[240px] rounded-full border border-brand-sage/[0.06]" />
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[180px] h-[180px] rounded-full border border-dashed border-brand-sage/[0.10]" />
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2">
        <div className="w-[120px] h-[120px] rounded-full border border-brand-sage/[0.15] shield-inner-pulse" />
      </div>

      {/* Radar sweep */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[240px] h-[240px] rounded-full overflow-hidden pointer-events-none">
        <div className="absolute inset-0 scanning-radar" />
      </div>

      {/* Dots */}
      {orbitDots.map((pos, i) => (
        <div key={i} className="absolute w-1 h-1 rounded-full bg-brand-sage/25" style={pos} />
      ))}

      {/* Center shield */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-10 flex flex-col items-center">
        <div className="w-[72px] h-[72px] rounded-2xl bg-surface-2 border border-brand-sage/20 flex items-center justify-center shadow-[0_0_30px_rgba(139,154,142,0.1)]">
          <BrandLogo size={42} className="text-brand-sage/70" bg="#272320" />
        </div>
      </div>

      {/* Connection + particles */}
      <svg
        className="absolute inset-0 w-full h-full pointer-events-none"
        viewBox="0 0 260 260"
        fill="none"
      >
        <defs>
          <filter id="ap-glow2">
            <feGaussianBlur in="SourceGraphic" stdDeviation="2" result="blur" />
            <feColorMatrix
              in="blur"
              type="matrix"
              values="0 0 0 0 0.545 0 0 0 0 0.604 0 0 0 0 0.557 0 0 0 0.5 0"
            />
            <feMerge>
              <feMergeNode />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        <path
          d="M48,220 Q90,180 130,140"
          stroke="#8B9A8E"
          strokeWidth="0.8"
          strokeDasharray="4 4"
          opacity="0.15"
          className="flow-line-dash"
        />
        <circle r="2" fill="#8B9A8E" filter="url(#ap-glow2)">
          <animateMotion dur="2s" repeatCount="indefinite" path="M48,220 Q90,180 130,140" />
        </circle>
        <circle r="1.5" fill="#B8C4BA" filter="url(#ap-glow2)">
          <animateMotion
            dur="2s"
            repeatCount="indefinite"
            path="M48,220 Q90,180 130,140"
            begin="0.7s"
          />
        </circle>
      </svg>

      {/* Agent node bottom-left */}
      <div className="absolute bottom-[10px] left-[8px] z-10 flex flex-col items-center gap-1">
        <div className="relative">
          <div className="w-[48px] h-[38px] bg-surface-2 border border-border rounded-lg flex items-center justify-center">
            <span className="text-text-secondary font-mono text-xs font-bold">&gt;_</span>
          </div>
          <div className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-brand-sage border-2 border-surface-1" />
        </div>
        <span className="text-[9px] text-text-muted">{t('yourAgent')}</span>
      </div>
    </motion.div>
  );
}

export default function Flip() {
  const t = useTranslations('home.flip');

  return (
    <SectionWrapper dark spacing="tight">
      <div className="relative">
        <div
          className="absolute inset-0 bg-grid opacity-50 pointer-events-none"
          aria-hidden="true"
        />

        <div className="relative max-w-5xl mx-auto">
          {/* Top: text left + radar right */}
          <div className="grid grid-cols-1 lg:grid-cols-[1fr_auto] gap-6 lg:gap-12 items-center">
            {/* Text content */}
            <div className="space-y-5">
              <FadeInUp>
                <p className="text-xl lg:text-2xl text-text-secondary leading-relaxed whitespace-pre-line">
                  {t('part1')}
                </p>
              </FadeInUp>

              <FlipVisual t={t} />

              <FadeInUp delay={0.15}>
                <div>
                  <p className="text-xl lg:text-2xl text-text-secondary leading-relaxed">
                    {t('part2a')}
                  </p>
                  <p className="text-[clamp(36px,4.5vw,54px)] font-extrabold text-brand-sage leading-[1.1] mt-2 text-glow-sage">
                    {t('part2b')}
                  </p>
                  <p className="text-lg text-text-secondary leading-relaxed mt-3">{t('part2c')}</p>
                </div>
              </FadeInUp>

              <FadeInUp delay={0.25}>
                <div>
                  <p className="text-text-tertiary leading-relaxed">{t('part3a')}</p>
                  <p className="text-text-secondary leading-relaxed mt-2">{t('part3b')}</p>
                </div>
              </FadeInUp>
            </div>

            {/* Radar visualization (right side, desktop only) */}
            <div className="hidden lg:block self-center">
              <AgentProtection t={t} />
            </div>
          </div>

          {/* Bottom: tagline centered */}
          <FadeInUp delay={0.35}>
            <p className="text-[clamp(2rem,4vw,2.5rem)] font-extrabold text-brand-sage tracking-normal text-glow-sage text-center mt-10">
              {t('tagline')}
            </p>
          </FadeInUp>
        </div>
      </div>
    </SectionWrapper>
  );
}
