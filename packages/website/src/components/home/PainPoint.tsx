"use client";

import { useTranslations } from "next-intl";
import FadeInUp from "../FadeInUp";
import SectionWrapper from "../ui/SectionWrapper";
import { BRAND_LOGO_PATHS, BRAND_LOGO_VIEWBOX } from "../ui/BrandLogo";

/** Large ambient background logo — faded, blurred, part of the atmosphere */
function BackgroundLogo() {
  return (
    <div
      className="absolute right-[-5%] top-1/2 -translate-y-1/2 pointer-events-none select-none hidden md:block"
      aria-hidden="true"
    >
      <div className="metallic-logo-wrapper opacity-[0.07]">
        <div className="metallic-logo-inner">
          <svg
            width="500"
            height="500"
            viewBox={BRAND_LOGO_VIEWBOX}
            fill="none"
            className="lg:w-[600px] lg:h-[600px]"
          >
            <defs>
              <linearGradient id="bg-metallic" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#6B7B6E" />
                <stop offset="30%" stopColor="#B8C4BA" />
                <stop offset="50%" stopColor="#D4DDD6" />
                <stop offset="70%" stopColor="#9BA99E" />
                <stop offset="100%" stopColor="#7A8A7D" />
              </linearGradient>
              <filter id="bg-blur" x="-30%" y="-30%" width="160%" height="160%">
                <feGaussianBlur in="SourceGraphic" stdDeviation="6" />
              </filter>
            </defs>
            <g filter="url(#bg-blur)">
              {BRAND_LOGO_PATHS.map((p, i) => (
                <path
                  key={i}
                  d={p.d}
                  fill={p.role === "bg" ? "none" : "url(#bg-metallic)"}
                />
              ))}
            </g>
          </svg>
        </div>
      </div>
    </div>
  );
}

export default function PainPoint() {
  const t = useTranslations("home.painPoint");

  return (
    <SectionWrapper>
      <div className="relative">
        {/* Background ambient logo */}
        <BackgroundLogo />

        {/* Foreground text */}
        <div className="relative z-10 max-w-2xl">
          <FadeInUp>
            <p className="text-lg lg:text-xl text-text-secondary leading-relaxed">
              {t("line1")}
            </p>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <p className="text-lg lg:text-xl text-text-secondary leading-relaxed mt-6">
              {t("line2")}
            </p>
          </FadeInUp>
          <FadeInUp delay={0.2}>
            <p className="text-lg lg:text-xl text-text-secondary leading-relaxed mt-6">
              {t("line3")}
            </p>
          </FadeInUp>
          <FadeInUp delay={0.3}>
            <p className="text-lg lg:text-xl text-text-secondary leading-relaxed mt-6">
              {t("line4")}
            </p>
          </FadeInUp>
          <FadeInUp delay={0.4}>
            <p className="text-lg lg:text-xl text-status-alert font-semibold leading-relaxed mt-6">
              {t("line5")}
            </p>
          </FadeInUp>
        </div>
      </div>
    </SectionWrapper>
  );
}
