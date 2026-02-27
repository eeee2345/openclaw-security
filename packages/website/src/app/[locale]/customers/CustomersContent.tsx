'use client';

import { useTranslations } from 'next-intl';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import SectionTitle from '@/components/ui/SectionTitle';
import { Link } from '@/navigation';
import { ArrowRight } from 'lucide-react';
import { caseStudies } from '@/data/case-studies';

/* ─── Stats Keys ─── */
const statKeys = ['stat1', 'stat2', 'stat3', 'stat4'] as const;

export default function CustomersContent() {
  const t = useTranslations('customers');

  const featured = caseStudies[0];
  const remaining = caseStudies.slice(1);

  return (
    <>
      {/* -- Hero -- */}
      <SectionWrapper spacing="spacious">
        <SectionTitle overline={t('overline')} title={t('title')} subtitle={t('subtitle')} />
      </SectionWrapper>

      {/* -- Stats Bar -- */}
      <SectionWrapper dark spacing="tight">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-6 md:gap-8">
          {statKeys.map((key, i) => (
            <FadeInUp key={key} delay={i * 0.06}>
              <div className="text-center">
                <p className="text-[clamp(28px,3.5vw,40px)] font-extrabold text-brand-sage leading-none">
                  {t(`stats.${key}.value`)}
                </p>
                <p className="text-sm text-text-secondary mt-2">{t(`stats.${key}.label`)}</p>
              </div>
            </FadeInUp>
          ))}
        </div>
      </SectionWrapper>

      {/* -- Featured Case Study -- */}
      <SectionWrapper>
        <FadeInUp>
          <p className="text-[11px] uppercase tracking-[0.12em] text-brand-sage font-semibold mb-6">
            {t('featured')}
          </p>
        </FadeInUp>
        <FadeInUp delay={0.05}>
          <div className="bg-surface-1 border border-border rounded-2xl p-8 md:p-10 hover:border-brand-sage/40 transition-all card-glow">
            <div className="flex flex-wrap items-center gap-3 mb-4">
              <span className="text-[10px] uppercase tracking-wider font-semibold px-2.5 py-1 rounded-full bg-brand-sage/10 text-brand-sage">
                {featured.industry}
              </span>
              <span className="text-sm text-text-tertiary">{featured.company}</span>
              <span className="text-xs text-text-muted">{featured.companySize}</span>
            </div>

            <h3 className="text-[clamp(24px,3vw,32px)] font-bold text-text-primary leading-tight max-w-3xl">
              {featured.headline}
            </h3>

            <p className="text-text-secondary mt-4 leading-relaxed max-w-3xl">{featured.excerpt}</p>

            {/* Results grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-8">
              {featured.results.map((r) => (
                <div key={r.metric} className="bg-surface-2 rounded-xl border border-border p-4">
                  <p className="text-xl font-bold text-brand-sage">{r.value}</p>
                  <p className="text-xs text-text-tertiary mt-1">{r.metric}</p>
                </div>
              ))}
            </div>

            <div className="mt-8">
              <Link
                href={`/customers/${featured.slug}`}
                className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3.5 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
              >
                Read Full Scenario <ArrowRight className="w-4 h-4" />
              </Link>
            </div>
          </div>
        </FadeInUp>
      </SectionWrapper>

      {/* -- All Case Studies Grid -- */}
      <SectionWrapper dark>
        <SectionTitle
          overline={t('allScenarios.overline')}
          title={t('allScenarios.title')}
          subtitle={t('allScenarios.subtitle')}
        />
        <div className="grid md:grid-cols-2 gap-6 mt-14">
          {remaining.map((cs, i) => (
            <FadeInUp key={cs.slug} delay={i * 0.08}>
              <Link
                href={`/customers/${cs.slug}`}
                className="group bg-surface-1 border border-border rounded-2xl p-6 hover:border-brand-sage/40 transition-all card-glow flex flex-col h-full"
              >
                <div className="flex flex-wrap items-center gap-2 mb-3">
                  <span className="text-[10px] uppercase tracking-wider font-semibold px-2.5 py-1 rounded-full bg-brand-sage/10 text-brand-sage">
                    {cs.industry}
                  </span>
                  <span className="text-sm font-semibold text-text-primary">{cs.company}</span>
                </div>

                <h3 className="text-lg font-bold text-text-primary leading-snug group-hover:text-brand-sage transition-colors">
                  {cs.headline}
                </h3>

                <p className="text-sm text-text-secondary mt-3 leading-relaxed flex-1">
                  {cs.excerpt}
                </p>

                {/* Products used */}
                <div className="flex flex-wrap gap-2 mt-4">
                  {cs.productsUsed.map((product) => (
                    <span
                      key={product}
                      className="text-[10px] uppercase tracking-wider font-medium px-2 py-0.5 rounded-full border border-border text-text-tertiary"
                    >
                      {product}
                    </span>
                  ))}
                </div>

                <span className="inline-flex items-center gap-1.5 text-sm font-semibold text-brand-sage mt-4 group-hover:gap-2.5 transition-all">
                  {t('readScenario')} <ArrowRight className="w-3.5 h-3.5" />
                </span>
              </Link>
            </FadeInUp>
          ))}
        </div>
      </SectionWrapper>

      {/* -- CTA -- */}
      <SectionWrapper dark>
        <div className="text-center">
          <FadeInUp>
            <h2 className="text-[clamp(28px,3vw,40px)] font-bold text-text-primary">
              {t('cta.title')}
            </h2>
            <p className="text-text-secondary mt-4 max-w-xl mx-auto leading-relaxed">
              {t('cta.desc')}
            </p>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <div className="flex flex-wrap justify-center gap-3 mt-8">
              <Link
                href="/early-access"
                className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3.5 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
              >
                {t('cta.cta1')} <ArrowRight className="w-4 h-4" />
              </Link>
              <Link
                href="/contact"
                className="border border-border text-text-secondary hover:text-text-primary hover:border-brand-sage font-semibold rounded-full px-8 py-3.5 transition-all duration-200"
              >
                {t('cta.cta2')}
              </Link>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>
    </>
  );
}
