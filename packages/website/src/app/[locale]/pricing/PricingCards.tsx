'use client';

import { useState, useCallback, Fragment } from 'react';
import { useTranslations } from 'next-intl';
import { Link } from '@/navigation';
import { X } from 'lucide-react';
import { CheckIcon } from '@/components/ui/BrandIcons';
import FadeInUp from '@/components/FadeInUp';
import SectionTitle from '@/components/ui/SectionTitle';

/* ── Plan keys and pricing data (4 tiers) ── */

const planKeys = ['community', 'solo', 'pro', 'business'] as const;

type PlanKey = (typeof planKeys)[number];

interface PlanMeta {
  price: number;
  unit: string;
  ctaHref: string;
  popular: boolean;
  machines: string;
  /** If set, clicking CTA triggers checkout for this tier */
  checkoutTier?: string;
}

const planMeta: Record<PlanKey, PlanMeta> = {
  community: {
    price: 0,
    unit: '',
    ctaHref: '/docs/getting-started',
    popular: false,
    machines: '1',
  },
  solo: {
    price: 9,
    unit: '/mo',
    ctaHref: '/early-access',
    popular: false,
    machines: '3',
    checkoutTier: 'solo',
  },
  pro: {
    price: 29,
    unit: '/mo',
    ctaHref: '/early-access',
    popular: true,
    machines: '10',
    checkoutTier: 'pro',
  },
  business: {
    price: 79,
    unit: '/mo',
    ctaHref: '/early-access',
    popular: false,
    machines: '25',
    checkoutTier: 'business',
  },
};

/* ── Feature comparison (4 columns) ── */

type FeatureValue = boolean | string;
type TierKey = 'community' | 'solo' | 'pro' | 'business';

interface FeatureRow {
  feature: string;
  community: FeatureValue;
  solo: FeatureValue;
  pro: FeatureValue;
  business: FeatureValue;
}

const comparisonCategories: { categoryKey: string; rows: FeatureRow[] }[] = [
  {
    categoryKey: 'productsIncluded',
    rows: [
      {
        feature: 'Panguard Scan',
        community: 'Full',
        solo: 'Full',
        pro: 'Full',
        business: 'Full + custom',
      },
      {
        feature: 'Guard detection',
        community: 'Layer 1',
        solo: 'Layer 1+2+3',
        pro: 'Layer 1+2+3',
        business: 'Layer 1+2+3',
      },
      {
        feature: 'Auto-block attacks',
        community: 'Known patterns',
        solo: 'All threats',
        pro: 'All threats',
        business: 'All threats',
      },
      {
        feature: 'Auto-fix vulnerabilities',
        community: 'Manual guide',
        solo: 'One-click',
        pro: 'One-click',
        business: 'One-click',
      },
      {
        feature: 'AI analysis',
        community: false,
        solo: true,
        pro: true,
        business: 'Custom models',
      },
      {
        feature: 'Panguard Chat',
        community: false,
        solo: 'Basic',
        pro: 'Advanced',
        business: 'Advanced + API',
      },
      {
        feature: 'Panguard Report',
        community: false,
        solo: false,
        pro: 'Full',
        business: 'Full + custom',
      },
      { feature: 'Panguard Trap', community: false, solo: false, pro: true, business: true },
    ],
  },
  {
    categoryKey: 'alertsIntegrations',
    rows: [
      { feature: 'Email alerts', community: false, solo: true, pro: true, business: true },
      { feature: 'LINE / Telegram', community: false, solo: true, pro: true, business: true },
      { feature: 'Slack', community: false, solo: false, pro: true, business: true },
      { feature: 'Webhook / API', community: false, solo: false, pro: false, business: true },
      { feature: 'SIEM integration', community: false, solo: false, pro: false, business: true },
    ],
  },
  {
    categoryKey: 'supportInfra',
    rows: [
      { feature: 'Community support', community: true, solo: true, pro: true, business: true },
      { feature: 'Priority support', community: false, solo: false, pro: true, business: true },
      { feature: 'Dedicated manager', community: false, solo: false, pro: false, business: true },
      {
        feature: 'Log retention',
        community: 'Session only',
        solo: '7 days',
        pro: '30 days',
        business: '90 days+',
      },
      { feature: 'SSO & RBAC', community: false, solo: false, pro: false, business: true },
      { feature: 'On-premise option', community: false, solo: false, pro: false, business: true },
      {
        feature: 'Machines',
        community: '1',
        solo: '3',
        pro: '10',
        business: '25',
      },
    ],
  },
];

const tierKeys: TierKey[] = ['community', 'solo', 'pro', 'business'];

function ComparisonCell({ value }: { value: FeatureValue }) {
  if (value === true) return <CheckIcon className="w-4 h-4 text-status-safe mx-auto" />;
  if (value === false) return <X className="w-4 h-4 text-text-muted mx-auto" />;
  return <span className="text-xs text-text-secondary text-center block">{value}</span>;
}

/* ── Main component ── */

export default function PricingCards() {
  const t = useTranslations('pricingPage');
  const tc = useTranslations('common');
  const [annual, setAnnual] = useState(false);
  const [loading, setLoading] = useState<string | null>(null);

  const displayPrice = (price: number) => {
    if (price === 0) return '$0';
    const effective = annual ? Math.round(price * 0.8 * 100) / 100 : price;
    return `$${effective % 1 === 0 ? effective : effective.toFixed(2)}`;
  };

  const handleCheckout = useCallback(async (tier: string) => {
    setLoading(tier);
    try {
      const res = await fetch('/api/billing/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tier }),
        credentials: 'include',
      });
      const data = await res.json();
      if (data.ok && data.data?.url) {
        window.location.href = data.data.url;
      } else if (res.status === 401) {
        // Not logged in — redirect to login, then come back
        window.location.href = `/login?redirect=/pricing`;
      } else {
        // Fallback to early access
        window.location.href = '/early-access';
      }
    } catch {
      window.location.href = '/early-access';
    } finally {
      setLoading(null);
    }
  }, []);

  return (
    <>
      {/* Annual toggle */}
      <FadeInUp>
        <div className="flex items-center justify-center gap-3 mb-10">
          <span
            className={`text-sm ${!annual ? 'text-text-primary font-medium' : 'text-text-tertiary'}`}
          >
            {tc('monthly')}
          </span>
          <button
            onClick={() => setAnnual(!annual)}
            className={`relative w-12 h-6 rounded-full transition-colors duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-sage focus-visible:ring-offset-2 focus-visible:ring-offset-surface-0 ${
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

      {/* Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 max-w-5xl mx-auto">
        {planKeys.map((key, i) => {
          const meta = planMeta[key];
          const features = t.raw(`plans.${key}.features`) as string[];
          return (
            <FadeInUp key={key} delay={i * 0.05}>
              <div
                className={`relative bg-surface-1 rounded-2xl p-7 border h-full flex flex-col ${
                  meta.popular ? 'border-brand-sage' : 'border-border'
                }`}
              >
                {meta.popular && (
                  <span className="absolute -top-3 left-1/2 -translate-x-1/2 bg-brand-sage text-surface-0 text-[10px] font-bold uppercase tracking-wider px-3 py-1 rounded-full whitespace-nowrap">
                    {tc('mostPopular')}
                  </span>
                )}

                <p className="text-xs uppercase tracking-wider text-text-muted font-semibold">
                  {t(`plans.${key}.name`)}
                </p>
                <p className="text-xs text-text-tertiary mt-0.5 mb-3">
                  {t(`plans.${key}.audience`)}
                </p>

                <div className="mb-1">
                  <span className="text-3xl font-extrabold text-text-primary">
                    {displayPrice(meta.price)}
                  </span>
                  {meta.unit && <span className="text-sm text-text-tertiary">{meta.unit}</span>}
                </div>
                <p className="text-xs text-text-muted mb-4">{t(`plans.${key}.machines`)}</p>
                {annual && meta.price > 0 && (
                  <p className="text-[11px] text-text-muted -mt-3 mb-4">{tc('billedAnnually')}</p>
                )}

                <ul className="space-y-2 flex-1">
                  {features.map((f: string) => (
                    <li key={f} className="flex items-start gap-2 text-xs text-text-secondary">
                      <CheckIcon className="w-3.5 h-3.5 text-brand-sage mt-0.5 shrink-0" />
                      {f}
                    </li>
                  ))}
                </ul>

                {meta.checkoutTier ? (
                  <button
                    onClick={() => handleCheckout(meta.checkoutTier!)}
                    disabled={loading === meta.checkoutTier}
                    className={`mt-6 block w-full text-center font-semibold rounded-full px-5 py-3 text-sm transition-all duration-200 active:scale-[0.98] disabled:opacity-50 ${
                      meta.popular
                        ? 'bg-brand-sage text-surface-0 hover:bg-brand-sage-light'
                        : 'border border-border text-text-secondary hover:border-brand-sage hover:text-text-primary'
                    }`}
                  >
                    {loading === meta.checkoutTier ? '...' : t(`plans.${key}.cta`)}
                  </button>
                ) : (
                  <Link
                    href={meta.ctaHref}
                    className={`mt-6 block text-center font-semibold rounded-full px-5 py-3 text-sm transition-all duration-200 active:scale-[0.98] ${
                      meta.popular
                        ? 'bg-brand-sage text-surface-0 hover:bg-brand-sage-light'
                        : 'border border-border text-text-secondary hover:border-brand-sage hover:text-text-primary'
                    }`}
                  >
                    {t(`plans.${key}.cta`)}
                  </Link>
                )}
              </div>
            </FadeInUp>
          );
        })}
      </div>

      <FadeInUp>
        <p className="text-sm text-text-tertiary text-center mt-8">{t('allPaidPlansNote')}</p>
      </FadeInUp>

      {/* Feature Comparison */}
      <div className="mt-20">
        <SectionTitle
          overline={t('comparison.overline')}
          title={t('comparison.title')}
          subtitle={t('comparison.subtitle')}
        />
        <FadeInUp>
          <div className="mt-12 overflow-x-auto">
            <table className="w-full min-w-[600px]">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left text-sm text-text-tertiary font-normal py-4 pr-4 w-[30%]" />
                  {tierKeys.map((key) => (
                    <th
                      key={key}
                      className={`text-center text-xs font-semibold uppercase tracking-wider py-4 ${
                        key === 'pro' ? 'text-brand-sage' : 'text-text-muted'
                      }`}
                      style={{ width: `${70 / 4}%` }}
                    >
                      {t(`tierLabels.${key}`)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {comparisonCategories.map((cat) => (
                  <Fragment key={cat.categoryKey}>
                    <tr>
                      <td
                        colSpan={5}
                        className="pt-8 pb-3 text-xs uppercase tracking-wider text-brand-sage font-semibold"
                      >
                        {t(`comparisonCategories.${cat.categoryKey}`)}
                      </td>
                    </tr>
                    {cat.rows.map((row) => (
                      <tr key={row.feature} className="border-b border-border/50">
                        <td className="py-3 pr-4 text-sm text-text-secondary">{row.feature}</td>
                        {tierKeys.map((key) => (
                          <td
                            key={key}
                            className={`py-3 text-center ${key === 'pro' ? 'bg-brand-sage/[0.03]' : ''}`}
                          >
                            <ComparisonCell value={row[key]} />
                          </td>
                        ))}
                      </tr>
                    ))}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        </FadeInUp>
      </div>
    </>
  );
}
