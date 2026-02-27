"use client";

import { useTranslations } from "next-intl";
import FadeInUp from "../FadeInUp";
import SectionWrapper from "../ui/SectionWrapper";
import { Link } from "@/navigation";
import { CheckIcon } from "@/components/ui/BrandIcons";

export default function Vision() {
  const t = useTranslations("home.vision");

  const badges = [
    t("badge1"),
    t("badge2"),
    t("badge3"),
  ];

  return (
    <SectionWrapper dark>
      <div className="max-w-3xl mx-auto text-center">
        <FadeInUp>
          <p className="text-lg text-text-tertiary">
            {t("line1")}
          </p>
        </FadeInUp>
        <FadeInUp delay={0.1}>
          <p className="text-[clamp(24px,3vw,36px)] font-bold text-text-primary leading-[1.2] mt-6">
            {t("line2")}
          </p>
          <p className="text-[clamp(24px,3vw,36px)] font-bold text-brand-sage leading-[1.2] mt-2">
            {t("line3")}
          </p>
        </FadeInUp>
        <FadeInUp delay={0.2}>
          <p className="text-text-secondary mt-8 leading-relaxed">
            {t("line4")}
          </p>
          <p className="text-text-secondary mt-2 leading-relaxed">
            {t("line5")}
          </p>
        </FadeInUp>

        {/* Trust badges */}
        <FadeInUp delay={0.3}>
          <div className="flex flex-wrap justify-center gap-4 mt-12">
            {badges.map((badge) => (
              <span
                key={badge}
                className="flex items-center gap-2 text-sm text-text-tertiary bg-surface-2 border border-border rounded-full px-4 py-2"
              >
                <CheckIcon className="w-3.5 h-3.5 text-brand-sage" />
                {badge}
              </span>
            ))}
          </div>
        </FadeInUp>

        {/* Buttons */}
        <FadeInUp delay={0.4}>
          <div className="flex flex-wrap justify-center gap-3 mt-10">
            <a
              href="https://github.com/panguard-ai/panguard-ai"
              target="_blank"
              rel="noopener noreferrer"
              className="border border-border text-text-secondary hover:text-text-primary hover:border-brand-sage font-semibold rounded-full px-8 py-3.5 transition-all duration-200"
            >
              {t("btnGithub")}
            </a>
            <Link
              href="/docs"
              className="border border-border text-text-secondary hover:text-text-primary hover:border-brand-sage font-semibold rounded-full px-8 py-3.5 transition-all duration-200"
            >
              {t("btnDocs")}
            </Link>
            <Link
              href="/scan"
              className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3.5 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
            >
              {t("btnScan")}
            </Link>
          </div>
        </FadeInUp>
      </div>
    </SectionWrapper>
  );
}
