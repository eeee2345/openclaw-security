"use client";

import { useState } from "react";
import { useTranslations } from "next-intl";
import { motion, AnimatePresence } from "framer-motion";
import { ArrowRight } from "lucide-react";
import { Link } from "@/navigation";
import SectionWrapper from "../ui/SectionWrapper";
import SectionTitle from "../ui/SectionTitle";
import FadeInUp from "../FadeInUp";

const tabKeys = ["website", "developer", "business"] as const;
type TabKey = (typeof tabKeys)[number];

export default function ThreeSteps() {
  const t = useTranslations("home.threeSteps");
  const [activeTab, setActiveTab] = useState<TabKey>("website");

  const ctaHrefs: Record<TabKey, string> = {
    website: "/scan",
    developer: "/docs",
    business: "/scan",
  };

  return (
    <SectionWrapper dark>
      <SectionTitle
        overline={t("overline")}
        title={t("title")}
      />

      {/* Tab bar */}
      <FadeInUp delay={0.1}>
        <div className="flex justify-center gap-2 mt-10 flex-wrap">
          {tabKeys.map((key) => (
            <button
              key={key}
              onClick={() => setActiveTab(key)}
              className={`relative px-5 py-2.5 text-sm font-medium rounded-full transition-colors ${
                activeTab === key
                  ? "bg-brand-sage text-surface-0"
                  : "bg-surface-0/5 text-text-secondary hover:text-text-primary border border-border"
              }`}
            >
              {t(`tabs.${key}`)}
            </button>
          ))}
        </div>
      </FadeInUp>

      {/* Tab content */}
      <div className="mt-10 max-w-3xl mx-auto">
        <AnimatePresence mode="wait">
          <motion.div
            key={activeTab}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.2 }}
          >
            <div className="grid md:grid-cols-2 gap-8">
              {/* Steps */}
              <div className="space-y-6">
                {([1, 2, 3] as const).map((step) => (
                  <div key={step} className="flex gap-4">
                    <div className="shrink-0 w-8 h-8 rounded-full bg-brand-sage/10 border border-brand-sage/20 flex items-center justify-center text-sm font-bold text-brand-sage">
                      {step}
                    </div>
                    <div>
                      <h4 className="text-text-primary font-semibold">
                        {t(`${activeTab}.step${step}Title`)}
                      </h4>
                      <p className="text-sm text-text-secondary mt-1 leading-relaxed whitespace-pre-line">
                        {t(`${activeTab}.step${step}Desc`)}
                      </p>
                    </div>
                  </div>
                ))}
              </div>

              {/* Visual mockup */}
              <div className="bg-surface-0 rounded-xl border border-border p-5 font-mono text-xs leading-relaxed min-h-[200px]">
                {activeTab === "website" && (
                  <div className="space-y-2 text-text-secondary">
                    <p className="text-brand-sage">$ Enter domain: example.com</p>
                    <p>Scanning example.com...</p>
                    <p className="text-[#2ED573]">{"████████████████████████ 100%"}</p>
                    <p className="text-text-primary mt-2">Score: 72/100 (C)</p>
                    <p className="text-[#FBBF24]">3 issues found</p>
                    <p className="text-text-muted mt-1">Report saved: example-report.pdf</p>
                  </div>
                )}
                {activeTab === "developer" && (
                  <div className="space-y-2 text-text-secondary">
                    <p className="text-brand-sage">$ curl -fsSL https://get.panguard.ai | sh</p>
                    <p className="text-[#2ED573]">Installed in 12s</p>
                    <p className="text-brand-sage mt-2">$ panguard scan --deep</p>
                    <p>Scanning... 5 issues found</p>
                    <p className="text-brand-sage mt-2">$ panguard guard start</p>
                    <p className="text-[#2ED573]">Guard active. Monitoring...</p>
                    <p className="text-brand-sage mt-2">$ panguard chat</p>
                    <p className="text-text-muted">You: Any threats today?</p>
                    <p className="text-text-secondary">Panguard: All clear. Score: 94/100.</p>
                  </div>
                )}
                {activeTab === "business" && (
                  <div className="space-y-2 text-text-secondary">
                    <p className="text-brand-sage">$ panguard scan --target company.com</p>
                    <p>Enterprise scan complete</p>
                    <p className="text-text-primary mt-2">Risk Score: 34/100 (B)</p>
                    <p className="text-brand-sage mt-2">$ panguard report --framework iso27001</p>
                    <p className="text-[#2ED573]">Coverage: 94% (107/114 controls)</p>
                    <p className="text-text-muted mt-1">Report: iso27001-report.pdf</p>
                    <p className="text-text-muted">Evidence: iso27001-evidence.zip</p>
                  </div>
                )}
              </div>
            </div>

            {/* CTA */}
            <div className="text-center mt-8">
              <Link
                href={ctaHrefs[activeTab]}
                className="inline-flex items-center gap-2 text-sm text-brand-sage hover:text-brand-sage-light transition-colors font-medium"
              >
                {t(`${activeTab}.cta`)} <ArrowRight className="w-4 h-4" />
              </Link>
            </div>
          </motion.div>
        </AnimatePresence>
      </div>
    </SectionWrapper>
  );
}
