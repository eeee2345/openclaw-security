"use client";

import { useTranslations } from "next-intl";
import FadeInUp from "../FadeInUp";
import SectionWrapper from "../ui/SectionWrapper";

export default function Flip() {
  const t = useTranslations("home.flip");

  return (
    <SectionWrapper dark>
      <div className="max-w-3xl mx-auto space-y-20">
        {/* Part 1: The status quo */}
        <FadeInUp>
          <p className="text-xl lg:text-2xl text-text-secondary leading-relaxed whitespace-pre-line">
            {t("part1")}
          </p>
        </FadeInUp>

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

        {/* Tagline */}
        <FadeInUp delay={0.35}>
          <p className="text-[2.5rem] font-extrabold text-brand-sage tracking-[0.05em] text-glow-sage">
            {t("tagline")}
          </p>
        </FadeInUp>
      </div>
    </SectionWrapper>
  );
}
