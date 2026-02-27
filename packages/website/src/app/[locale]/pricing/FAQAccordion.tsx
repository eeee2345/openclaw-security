"use client";

import { useState } from "react";
import { useTranslations } from "next-intl";
import { ChevronDown } from "lucide-react";
import FadeInUp from "@/components/FadeInUp";

const faqKeys = ["faq1", "faq2", "faq3", "faq4", "faq5", "faq6", "faq7", "faq8"] as const;

function FAQItem({ q, a }: { q: string; a: string }) {
  const [open, setOpen] = useState(false);

  return (
    <div className="border-b border-border">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between py-5 text-left group"
      >
        <span className="text-text-primary font-medium pr-4">{q}</span>
        <ChevronDown
          className={`w-5 h-5 text-text-tertiary shrink-0 transition-transform duration-300 ${
            open ? "rotate-180" : ""
          }`}
        />
      </button>
      <div
        className={`overflow-hidden transition-all duration-300 ${
          open ? "max-h-[400px] pb-5" : "max-h-0"
        }`}
      >
        <p className="text-sm text-text-secondary leading-relaxed">{a}</p>
      </div>
    </div>
  );
}

export default function FAQAccordion() {
  const t = useTranslations("pricingPage");

  return (
    <FadeInUp>
      <div>
        {faqKeys.map((key) => (
          <FAQItem
            key={key}
            q={t(`faq.${key}q`)}
            a={t(`faq.${key}a`)}
          />
        ))}
      </div>
    </FadeInUp>
  );
}
