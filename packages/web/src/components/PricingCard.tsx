import { Link } from 'react-router-dom';
import type { PricingPlanDetails } from '@openclaw/panguard-web';
import { useLanguage } from '../context/LanguageContext';

interface PricingCardProps {
  plan: PricingPlanDetails;
}

export default function PricingCard({ plan }: PricingCardProps) {
  const { language, t } = useLanguage();
  const name = language === 'en' ? plan.nameEn : plan.nameZh;
  const tagline = language === 'en' ? plan.taglineEn : plan.taglineZh;
  const priceDisplay = language === 'en' ? plan.priceDisplayEn : plan.priceDisplayZh;

  const isPerEndpoint = plan.plan === 'team' || plan.plan === 'business';

  return (
    <div className={plan.highlighted ? 'card-highlighted relative flex flex-col' : 'card flex flex-col'}>
      {plan.highlighted && (
        <div className="absolute -top-3 left-1/2 -translate-x-1/2 rounded-full bg-brand-cyan px-4 py-0.5 text-xs font-bold text-brand-dark">
          {t('Most Popular', '最受歡迎')}
        </div>
      )}

      <div className="mb-4">
        <h3 className="text-xl font-bold">{name}</h3>
        <p className="text-sm text-brand-muted">{tagline}</p>
      </div>

      <div className="mb-6">
        <span className="text-3xl font-extrabold">{priceDisplay}</span>
        {isPerEndpoint && (
          <span className="ml-1 text-xs text-brand-muted">
            {t('per endpoint', '/端點')}
          </span>
        )}
      </div>

      <ul className="mb-6 flex-1 space-y-2">
        {plan.features.map((feature, i) => (
          <li key={i} className="flex items-start gap-2 text-sm">
            <span className={feature.included ? 'text-brand-cyan' : 'text-brand-muted/40'}>
              {feature.included ? '+' : '-'}
            </span>
            <span className={feature.included ? 'text-brand-muted' : 'text-brand-muted/40 line-through'}>
              {language === 'en' ? feature.nameEn : feature.nameZh}
              {feature.limit ? ` (${feature.limit})` : ''}
            </span>
          </li>
        ))}
      </ul>

      <Link
        to="/guide"
        className={plan.highlighted ? 'btn-primary w-full justify-center' : 'btn-secondary w-full justify-center'}
      >
        {plan.priceUsd === 0
          ? t('Try Free', '免費試用')
          : t('Get Started', '立即開始')}
      </Link>
    </div>
  );
}
