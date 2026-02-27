"use client";
import { useTranslations } from "next-intl";
import SectionWrapper from "../ui/SectionWrapper";
import SectionTitle from "../ui/SectionTitle";
import FadeInUp from "../FadeInUp";
import CountUp from "../animations/CountUp";
import {
  ShieldIcon, NetworkIcon, TerminalIcon, ScanIcon, LockIcon, AnalyticsIcon,
} from "@/components/ui/BrandIcons";

export default function SocialProof() {
  const t = useTranslations("home.socialProof");

  const stats: Array<{
    numericValue?: number;
    textValue?: string;
    suffix?: string;
    label: string;
    icon: typeof ShieldIcon;
  }> = [
    { numericValue: 1068, label: t("stat1Label"), icon: ShieldIcon },
    { numericValue: 3155, label: t("stat2Label"), icon: ScanIcon },
    { numericValue: 8, label: t("stat3Label"), icon: NetworkIcon },
    { numericValue: 423, label: t("stat4Label"), icon: TerminalIcon },
    { numericValue: 5, label: t("stat5Label"), icon: AnalyticsIcon },
    { textValue: "MIT", label: t("stat6Label"), icon: LockIcon },
  ];

  return (
    <SectionWrapper>
      <SectionTitle
        overline={t("overline")}
        title={t("title")}
        subtitle={t("subtitle")}
      />

      <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 mt-14 max-w-3xl mx-auto">
        {stats.map((s, i) => (
          <FadeInUp key={s.label} delay={i * 0.06}>
            <div className="bg-surface-1 rounded-xl border border-border p-6 text-center card-glow">
              <s.icon size={20} className="text-brand-sage mx-auto mb-3" />
              <p className="text-2xl sm:text-3xl font-extrabold text-text-primary">
                {s.numericValue !== null && s.numericValue !== undefined ? (
                  <CountUp target={s.numericValue} suffix={s.suffix} />
                ) : (
                  s.textValue
                )}
              </p>
              <p className="text-xs text-text-tertiary mt-2">{s.label}</p>
            </div>
          </FadeInUp>
        ))}
      </div>

      <FadeInUp delay={0.4}>
        <p className="text-xs text-text-muted text-center mt-8 max-w-xl mx-auto leading-relaxed">
          {t("footnote")}{" "}
          <a
            href="https://github.com/panguard-ai/panguard-ai"
            target="_blank"
            rel="noopener noreferrer"
            className="text-brand-sage hover:underline"
          >
            {t("githubLink")}
          </a>
        </p>
      </FadeInUp>
    </SectionWrapper>
  );
}
