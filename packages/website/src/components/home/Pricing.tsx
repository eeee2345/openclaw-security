'use client';
import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { Link } from '@/navigation';
import { CheckIcon } from '@/components/ui/BrandIcons';
import SectionWrapper from '../ui/SectionWrapper';
import SectionTitle from '../ui/SectionTitle';
import FadeInUp from '../FadeInUp';

export default function Pricing() {
  const t = useTranslations('home.pricing');
  const tc = useTranslations('common');
  const [annual, setAnnual] = useState(false);

  const plans = [
    {
      name: t('freeName'),
      price: 0,
      unit: '',
      features: t.raw('freeFeatures') as string[],
      cta: tc('scanFree'),
      ctaHref: '/early-access',
      popular: false,
    },
    {
      name: t('soloName'),
      price: 9,
      unit: '/mo',
      features: t.raw('soloFeatures') as string[],
      cta: tc('startFreeTrial'),
      ctaHref: '/early-access',
      popular: false,
    },
    {
      name: t('teamName'),
      price: 14,
      unit: '/endpoint/mo',
      features: t.raw('teamFeatures') as string[],
      cta: tc('startFreeTrial'),
      ctaHref: '/early-access',
      popular: true,
    },
    {
      name: t('enterpriseName'),
      price: null,
      unit: '',
      features: t.raw('enterpriseFeatures') as string[],
      cta: tc('contactSales'),
      ctaHref: '/contact',
      popular: false,
    },
  ];

  const displayPrice = (price: number | null) => {
    if (price === null) return null;
    if (price === 0) return '$0';
    const effective = annual ? Math.round(price * 0.8 * 100) / 100 : price;
    return `$${effective % 1 === 0 ? effective : effective.toFixed(2)}`;
  };

  return (
    <SectionWrapper id="pricing" dark>
      <SectionTitle overline={t('overline')} title={t('title')} subtitle={t('subtitle')} />

      {/* Annual toggle */}
      <FadeInUp delay={0.05}>
        <div className="flex items-center justify-center gap-3 mt-8">
          <span
            className={`text-sm ${!annual ? 'text-text-primary font-medium' : 'text-text-tertiary'}`}
          >
            {tc('monthly')}
          </span>
          <button
            onClick={() => setAnnual(!annual)}
            className={`relative w-12 h-6 rounded-full transition-colors duration-200 ${
              annual ? 'bg-brand-sage' : 'bg-surface-3'
            }`}
            aria-label="Toggle annual billing"
          >
            <div
              className={`absolute top-0.5 w-5 h-5 rounded-full bg-surface-0 transition-transform duration-200 ${
                annual ? 'translate-x-6' : 'translate-x-0.5'
              }`}
            />
          </button>
          <span
            className={`text-sm ${annual ? 'text-text-primary font-medium' : 'text-text-tertiary'}`}
          >
            {tc('annual')}
          </span>
          {annual && (
            <span className="text-xs text-brand-sage font-semibold bg-brand-sage/10 px-2 py-0.5 rounded-full">
              {tc('save20')}
            </span>
          )}
        </div>
      </FadeInUp>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mt-10 max-w-5xl mx-auto">
        {plans.map((plan, i) => (
          <FadeInUp key={plan.name} delay={i * 0.06}>
            <div
              className={`relative bg-surface-0 rounded-2xl p-7 border h-full flex flex-col ${
                plan.popular ? 'border-brand-sage card-glow' : 'border-border'
              }`}
            >
              {plan.popular && (
                <span className="absolute -top-3 left-1/2 -translate-x-1/2 bg-brand-sage text-surface-0 text-[10px] font-bold uppercase tracking-wider px-3 py-1 rounded-full whitespace-nowrap">
                  {tc('mostPopular')}
                </span>
              )}

              <p className="text-xs uppercase tracking-wider text-text-muted font-semibold mb-3">
                {plan.name}
              </p>

              <div className="mb-5">
                {plan.price === null ? (
                  <>
                    <span className="text-3xl font-extrabold text-text-primary">
                      {tc('custom')}
                    </span>
                    <p className="text-sm text-text-tertiary mt-1">{tc('contactUs')}</p>
                  </>
                ) : (
                  <>
                    <span className="text-3xl font-extrabold text-text-primary">
                      {displayPrice(plan.price)}
                    </span>
                    {plan.unit && <span className="text-sm text-text-tertiary">{plan.unit}</span>}
                    {annual && plan.price > 0 && (
                      <p className="text-[11px] text-text-muted mt-1">{tc('billedAnnually')}</p>
                    )}
                  </>
                )}
              </div>

              <ul className="space-y-2.5 flex-1">
                {plan.features.map((f) => (
                  <li key={f} className="flex items-start gap-2 text-xs text-text-secondary">
                    <CheckIcon size={14} className="text-brand-sage mt-0.5 shrink-0" />
                    {f}
                  </li>
                ))}
              </ul>

              <Link
                href={plan.ctaHref}
                className={`mt-6 block text-center font-semibold rounded-full px-5 py-3 text-sm transition-all duration-200 active:scale-[0.98] ${
                  plan.popular
                    ? 'bg-brand-sage text-surface-0 hover:bg-brand-sage-light'
                    : 'border border-text-tertiary/40 text-text-secondary hover:text-text-primary hover:border-text-secondary'
                }`}
              >
                {plan.cta}
              </Link>
            </div>
          </FadeInUp>
        ))}
      </div>

      <FadeInUp delay={0.3}>
        <p className="text-sm text-text-tertiary text-center mt-8">
          <Link
            href="/pricing"
            className="text-brand-sage hover:text-brand-sage-light underline underline-offset-2"
          >
            {t('seeAllPlans')}
          </Link>
        </p>
      </FadeInUp>
    </SectionWrapper>
  );
}
