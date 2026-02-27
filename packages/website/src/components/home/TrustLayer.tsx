"use client";

import { useTranslations } from "next-intl";
import { Lock, Shield, Eye } from "lucide-react";
import SectionWrapper from "../ui/SectionWrapper";
import SectionTitle from "../ui/SectionTitle";
import FadeInUp from "../FadeInUp";
import Card from "../ui/Card";

const columns = [
  { key: "openSource", icon: Lock, href: "https://github.com/eeee2345/openclaw-security" },
  { key: "security", icon: Shield, href: "https://github.com/eeee2345/openclaw-security/actions" },
  { key: "privacy", icon: Eye, href: "/privacy" },
] as const;

export default function TrustLayer() {
  const t = useTranslations("home.trustLayer");

  return (
    <SectionWrapper dark>
      <SectionTitle
        overline={t("overline")}
        title={t("title")}
      />

      <div className="grid md:grid-cols-3 gap-6 mt-14">
        {columns.map((col, i) => (
          <FadeInUp key={col.key} delay={i * 0.08}>
            <Card padding="lg" className="h-full">
              <col.icon className="w-7 h-7 text-brand-sage mb-4" />
              <h3 className="text-lg font-bold text-text-primary mb-3">
                {t(`${col.key}.title`)}
              </h3>
              <p className="text-sm text-text-secondary leading-relaxed whitespace-pre-line">
                {t(`${col.key}.desc`)}
              </p>
              <a
                href={col.href}
                target={col.href.startsWith("http") ? "_blank" : undefined}
                rel={col.href.startsWith("http") ? "noopener noreferrer" : undefined}
                className="inline-block mt-4 text-sm text-brand-sage hover:text-brand-sage-light transition-colors link-reveal"
              >
                {t(`${col.key}.link`)}
              </a>
            </Card>
          </FadeInUp>
        ))}
      </div>
    </SectionWrapper>
  );
}
