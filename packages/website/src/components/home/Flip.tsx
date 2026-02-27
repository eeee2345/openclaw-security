"use client";

import { useTranslations } from "next-intl";
import FadeInUp from "../FadeInUp";
import SectionWrapper from "../ui/SectionWrapper";
import { BRAND_LOGO_PATHS } from "../ui/BrandLogo";

/** Animated flow: Your Agent ---> Panguard Agent */
function AgentFlowDiagram() {
  return (
    <FadeInUp delay={0.2}>
      <div className="relative w-full max-w-xl mx-auto py-8" aria-hidden="true">
        <svg
          viewBox="0 0 600 120"
          fill="none"
          className="w-full h-auto"
        >
          <defs>
            {/* Animated dash for the connection line */}
            <linearGradient id="flow-grad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#8B9A8E" stopOpacity="0.1" />
              <stop offset="30%" stopColor="#8B9A8E" stopOpacity="0.6" />
              <stop offset="70%" stopColor="#8B9A8E" stopOpacity="0.6" />
              <stop offset="100%" stopColor="#8B9A8E" stopOpacity="0.1" />
            </linearGradient>

            {/* Data packet glow */}
            <filter id="packet-glow">
              <feGaussianBlur in="SourceGraphic" stdDeviation="3" result="blur" />
              <feColorMatrix
                in="blur"
                type="matrix"
                values="0 0 0 0 0.545  0 0 0 0 0.604  0 0 0 0 0.557  0 0 0 0.6 0"
              />
              <feMerge>
                <feMergeNode />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>

            {/* Metallic gradient for shield */}
            <linearGradient id="flow-metallic" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#6B7B6E" />
              <stop offset="40%" stopColor="#B8C4BA" />
              <stop offset="60%" stopColor="#D4DDD6" />
              <stop offset="100%" stopColor="#8B9A8E" />
            </linearGradient>
          </defs>

          {/* Left node: Your Agent (terminal icon) */}
          <g>
            {/* Node background */}
            <rect x="20" y="25" width="70" height="70" rx="16" fill="#1A1614" stroke="#8B9A8E" strokeWidth="1" strokeOpacity="0.3" />
            {/* Terminal prompt icon */}
            <text x="55" y="68" textAnchor="middle" fill="#8B9A8E" fontSize="26" fontFamily="monospace" fontWeight="bold">&gt;_</text>
            {/* Outer pulse ring */}
            <rect x="20" y="25" width="70" height="70" rx="16" fill="none" stroke="#8B9A8E" strokeWidth="1" opacity="0.2" className="agent-pulse-left" />
          </g>

          {/* Connection line */}
          <line x1="100" y1="60" x2="500" y2="60" stroke="url(#flow-grad)" strokeWidth="1" strokeDasharray="6 4" className="flow-line-dash" />

          {/* Data packets flowing */}
          <g filter="url(#packet-glow)">
            <circle r="3" fill="#8B9A8E" className="flow-packet-1">
              <animateMotion dur="3s" repeatCount="indefinite" path="M100,60 L500,60" />
            </circle>
            <circle r="2.5" fill="#B8C4BA" className="flow-packet-2">
              <animateMotion dur="3s" repeatCount="indefinite" path="M100,60 L500,60" begin="1s" />
            </circle>
            <circle r="2" fill="#8B9A8E" className="flow-packet-3">
              <animateMotion dur="3s" repeatCount="indefinite" path="M100,60 L500,60" begin="2s" />
            </circle>
          </g>

          {/* Center label */}
          <text x="300" y="45" textAnchor="middle" fill="#8B9A8E" fontSize="9" fontFamily="monospace" opacity="0.5" letterSpacing="2">ENCRYPTED</text>

          {/* Right node: Panguard Shield */}
          <g>
            <rect x="510" y="25" width="70" height="70" rx="16" fill="#1A1614" stroke="#8B9A8E" strokeWidth="1" strokeOpacity="0.3" />
            {/* Mini brand logo */}
            <g transform="translate(525, 32) scale(0.038)">
              {BRAND_LOGO_PATHS.map((p, i) => (
                <path
                  key={i}
                  d={p.d}
                  fill={p.role === "bg" ? "#1A1614" : "url(#flow-metallic)"}
                />
              ))}
            </g>
            {/* Outer pulse ring */}
            <rect x="510" y="25" width="70" height="70" rx="16" fill="none" stroke="#8B9A8E" strokeWidth="1" opacity="0.2" className="agent-pulse-right" />
          </g>

          {/* Labels below nodes */}
          <text x="55" y="112" textAnchor="middle" fill="#F5F1E8" fontSize="10" opacity="0.5" fontFamily="sans-serif">Your Agent</text>
          <text x="545" y="112" textAnchor="middle" fill="#F5F1E8" fontSize="10" opacity="0.5" fontFamily="sans-serif">Panguard</text>
        </svg>
      </div>
    </FadeInUp>
  );
}

/** Visual separator: crossed-out dashboard vs auto-fix */
function FlipVisual() {
  return (
    <FadeInUp delay={0.1}>
      <div className="flex items-center gap-6 py-4" aria-hidden="true">
        {/* Dashboard crossed out */}
        <div className="flex items-center gap-2 opacity-40">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#F5F1E8" strokeWidth="1.5">
            <rect x="3" y="3" width="18" height="14" rx="2" />
            <line x1="3" y1="21" x2="21" y2="21" />
            <line x1="12" y1="17" x2="12" y2="21" />
          </svg>
          <span className="text-sm text-text-tertiary line-through">Dashboard</span>
        </div>

        {/* Arrow */}
        <svg width="24" height="12" viewBox="0 0 24 12" fill="none" className="opacity-30">
          <path d="M0 6h20m0 0l-4-4m4 4l-4 4" stroke="#8B9A8E" strokeWidth="1.5" />
        </svg>

        {/* Auto-fix */}
        <div className="flex items-center gap-2">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#8B9A8E" strokeWidth="1.5">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            <polyline points="9 12 11 14 15 10" />
          </svg>
          <span className="text-sm text-brand-sage font-medium">Auto-fixed</span>
        </div>
      </div>
    </FadeInUp>
  );
}

export default function Flip() {
  const t = useTranslations("home.flip");

  return (
    <SectionWrapper dark>
      {/* Subtle background grid for this section */}
      <div className="relative">
        <div className="absolute inset-0 bg-grid opacity-50 pointer-events-none" aria-hidden="true" />

        <div className="relative max-w-3xl mx-auto space-y-16">
          {/* Part 1: The status quo */}
          <FadeInUp>
            <p className="text-xl lg:text-2xl text-text-secondary leading-relaxed whitespace-pre-line">
              {t("part1")}
            </p>
          </FadeInUp>

          {/* Visual: dashboard → auto-fix */}
          <FlipVisual />

          {/* Part 2: The flip */}
          <FadeInUp delay={0.15}>
            <div>
              <p className="text-xl lg:text-2xl text-text-secondary leading-relaxed">
                {t("part2a")}
              </p>
              <p className="text-[clamp(36px,4.5vw,54px)] font-extrabold text-brand-sage leading-[1.1] mt-2 text-glow-sage">
                {t("part2b")}
              </p>
              <p className="text-lg text-text-secondary leading-relaxed mt-4">
                {t("part2c")}
              </p>
            </div>
          </FadeInUp>

          {/* Part 3: The mechanism */}
          <FadeInUp delay={0.25}>
            <div>
              <p className="text-text-tertiary leading-relaxed">
                {t("part3a")}
              </p>
              <p className="text-text-secondary leading-relaxed mt-3">
                {t("part3b")}
              </p>
            </div>
          </FadeInUp>

          {/* Agent-to-Agent flow diagram */}
          <AgentFlowDiagram />

          {/* Tagline */}
          <FadeInUp delay={0.35}>
            <p className="text-[2.5rem] font-extrabold text-brand-sage tracking-[0.05em] text-glow-sage text-center">
              {t("tagline")}
            </p>
          </FadeInUp>
        </div>
      </div>
    </SectionWrapper>
  );
}
