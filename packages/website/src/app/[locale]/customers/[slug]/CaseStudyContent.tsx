'use client';

import { useTranslations } from 'next-intl';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import { Link } from '@/navigation';
import { ArrowLeft, ArrowRight } from 'lucide-react';
import type { CaseStudy } from '@/data/case-studies';

export default function CaseStudyContent({ study }: { study: CaseStudy }) {
  const t = useTranslations('caseStudy');

  return (
    <>
      {/* -- Back Link + Hero -- */}
      <SectionWrapper spacing="spacious">
        <FadeInUp>
          <Link
            href="/customers"
            className="inline-flex items-center gap-1.5 text-sm text-text-tertiary hover:text-brand-sage transition-colors mb-8"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            {t('allStories')}
          </Link>
        </FadeInUp>

        <FadeInUp delay={0.05}>
          <div className="flex flex-wrap items-center gap-3 mb-4">
            <span className="text-[10px] uppercase tracking-wider font-semibold px-2.5 py-1 rounded-full bg-brand-sage/10 text-brand-sage">
              {study.industry}
            </span>
            <span className="text-sm font-semibold text-text-primary">{study.company}</span>
            <span className="text-xs text-text-muted">{study.companySize}</span>
          </div>
        </FadeInUp>

        <FadeInUp delay={0.1}>
          <h1 className="text-[clamp(32px,4vw,52px)] font-extrabold leading-[1.1] tracking-tight text-text-primary max-w-4xl">
            {study.headline}
          </h1>
        </FadeInUp>

        <FadeInUp delay={0.15}>
          <p className="text-xl text-text-secondary max-w-3xl mt-6 leading-relaxed">
            {study.excerpt}
          </p>
        </FadeInUp>
      </SectionWrapper>

      {/* -- Results Metrics -- */}
      <SectionWrapper dark spacing="tight">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {study.results.map((r, i) => (
            <FadeInUp key={r.metric} delay={i * 0.06}>
              <div className="bg-surface-2 rounded-xl border border-border p-5 text-center">
                <p className="text-[clamp(24px,3vw,36px)] font-extrabold text-brand-sage leading-none">
                  {r.value}
                </p>
                <p className="text-xs text-text-tertiary mt-2">{r.metric}</p>
              </div>
            </FadeInUp>
          ))}
        </div>
      </SectionWrapper>

      {/* -- Challenge -- */}
      <SectionWrapper>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <p className="text-[11px] uppercase tracking-[0.12em] text-brand-sage font-semibold mb-4">
              {t('challenge')}
            </p>
            <p className="text-lg text-text-secondary leading-relaxed">{study.challenge}</p>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* -- Solution -- */}
      <SectionWrapper dark>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <p className="text-[11px] uppercase tracking-[0.12em] text-brand-sage font-semibold mb-4">
              {t('solution')}
            </p>
            <p className="text-lg text-text-secondary leading-relaxed">{study.solution}</p>
          </FadeInUp>

          {/* Products used */}
          <FadeInUp delay={0.05}>
            <div className="flex flex-wrap gap-2 mt-6">
              {study.productsUsed.map((product) => (
                <span
                  key={product}
                  className="text-[10px] uppercase tracking-wider font-medium px-2.5 py-1 rounded-full border border-border text-text-tertiary"
                >
                  Panguard {product}
                </span>
              ))}
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* -- Quote -- */}
      <SectionWrapper>
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <blockquote className="border-l-4 border-brand-sage pl-6 md:pl-8">
              <p className="text-xl md:text-2xl font-semibold text-text-primary leading-relaxed italic">
                &ldquo;{study.quote}&rdquo;
              </p>
              <footer className="mt-4">
                <p className="text-sm font-semibold text-text-primary">{study.quoteName}</p>
                <p className="text-sm text-text-tertiary">{study.quoteRole}</p>
              </footer>
            </blockquote>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* -- CTA -- */}
      <SectionWrapper dark>
        <div className="text-center">
          <FadeInUp>
            <h2 className="text-[clamp(28px,3vw,40px)] font-bold text-text-primary">
              {t('similarResults')}
            </h2>
            <p className="text-text-secondary mt-4 max-w-xl mx-auto leading-relaxed">
              Join {study.company} and other growing teams that trust Panguard AI to protect their
              infrastructure.
            </p>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <div className="flex flex-wrap justify-center gap-3 mt-8">
              <Link
                href="/early-access"
                className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3.5 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
              >
                Get Early Access <ArrowRight className="w-4 h-4" />
              </Link>
              <Link
                href="/customers"
                className="border border-border text-text-secondary hover:text-text-primary hover:border-brand-sage font-semibold rounded-full px-8 py-3.5 transition-all duration-200"
              >
                {t('moreStories')}
              </Link>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>
    </>
  );
}
