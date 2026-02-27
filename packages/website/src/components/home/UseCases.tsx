"use client";

import { useTranslations } from "next-intl";
import { Rocket, ShoppingCart, Building2, User } from "lucide-react";
import SectionWrapper from "../ui/SectionWrapper";
import SectionTitle from "../ui/SectionTitle";
import FadeInUp from "../FadeInUp";
import Card from "../ui/Card";

const cases = [
  { key: "saas", icon: Rocket },
  { key: "ecommerce", icon: ShoppingCart },
  { key: "taiwan", icon: Building2 },
  { key: "freelance", icon: User },
] as const;

export default function UseCases() {
  const t = useTranslations("home.useCases");

  return (
    <SectionWrapper id="use-cases">
      <SectionTitle
        overline={t("overline")}
        title={t("title")}
      />

      <div className="grid sm:grid-cols-2 gap-6 mt-14 max-w-4xl mx-auto">
        {cases.map((c, i) => (
          <FadeInUp key={c.key} delay={i * 0.08}>
            <Card padding="lg" className="h-full">
              <div className="flex items-center gap-3 mb-4">
                <c.icon className="w-5 h-5 text-brand-sage shrink-0" />
                <span className="text-xs uppercase tracking-wider text-text-muted font-semibold">
                  {t(`cases.${c.key}.persona`)}
                </span>
              </div>
              <p className="text-text-secondary text-sm leading-relaxed italic">
                &ldquo;{t(`cases.${c.key}.quote`)}&rdquo;
              </p>
              <div className="mt-4 flex flex-wrap gap-2">
                <span className="text-[10px] uppercase font-bold text-brand-sage bg-brand-sage/10 rounded-full px-2.5 py-1">
                  {t(`cases.${c.key}.used`)}
                </span>
                <span className="text-[10px] uppercase font-bold text-text-tertiary bg-surface-0 rounded-full px-2.5 py-1 border border-border">
                  {t(`cases.${c.key}.saved`)}
                </span>
              </div>
            </Card>
          </FadeInUp>
        ))}
      </div>
    </SectionWrapper>
  );
}
