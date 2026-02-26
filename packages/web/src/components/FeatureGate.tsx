import { Link } from 'react-router-dom';
import { useAuth, hasTierAccess } from '../context/AuthContext';
import { useLanguage } from '../context/LanguageContext';
import type { ReactNode } from 'react';

interface FeatureGateProps {
  /** Minimum tier required to access this feature */
  requiredTier: string;
  /** Feature name (English) */
  featureNameEn: string;
  /** Feature name (Chinese) */
  featureNameZh: string;
  /** Description of what the feature does (English) */
  descriptionEn: string;
  /** Description of what the feature does (Chinese) */
  descriptionZh: string;
  /** Tier to suggest upgrading to */
  suggestedTier?: string;
  /** Suggested tier display price */
  suggestedPriceEn?: string;
  suggestedPriceZh?: string;
  children: ReactNode;
}

const TIER_DISPLAY: Record<string, [string, string]> = {
  solo: ['Solo $9/mo', 'Solo US$9/月'],
  starter: ['Starter $19/mo', 'Starter US$19/月'],
  team: ['Team $14/endpoint/mo', 'Team US$14/端點/月'],
  business: ['Business $10/endpoint/mo', 'Business US$10/端點/月'],
};

export default function FeatureGate({
  requiredTier,
  featureNameEn,
  featureNameZh,
  descriptionEn,
  descriptionZh,
  suggestedTier,
  suggestedPriceEn,
  suggestedPriceZh,
  children,
}: FeatureGateProps) {
  const { tier } = useAuth();
  const { t } = useLanguage();

  if (hasTierAccess(tier, requiredTier)) {
    return <>{children}</>;
  }

  const upgradeTier = suggestedTier ?? requiredTier;
  const tierDisplay = TIER_DISPLAY[upgradeTier];
  const priceEn = suggestedPriceEn ?? tierDisplay?.[0] ?? upgradeTier;
  const priceZh = suggestedPriceZh ?? tierDisplay?.[1] ?? upgradeTier;

  return (
    <div className="p-6">
      <div className="mx-auto max-w-lg rounded-xl border border-brand-border bg-brand-card p-8 text-center">
        <div className="mb-4 text-4xl text-brand-muted/50">
          <svg className="mx-auto h-12 w-12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
            <path d="M7 11V7a5 5 0 0110 0v4" />
          </svg>
        </div>
        <h2 className="mb-2 text-xl font-bold">
          {t(featureNameEn, featureNameZh)}
        </h2>
        <p className="mb-6 text-sm text-brand-muted">
          {t(descriptionEn, descriptionZh)}
        </p>
        <p className="mb-4 text-sm text-brand-muted">
          {t(
            `This feature requires the ${upgradeTier.charAt(0).toUpperCase() + upgradeTier.slice(1)} plan or above.`,
            `此功能需要 ${upgradeTier.charAt(0).toUpperCase() + upgradeTier.slice(1)} 方案以上。`,
          )}
        </p>
        <p className="mb-6 text-xs text-brand-muted">
          {t(`You are currently on the ${tier} plan.`, `你目前是 ${tier} 方案。`)}
        </p>
        <Link to="/pricing" className="btn-primary">
          {t(`Upgrade to ${priceEn}`, `升級到 ${priceZh}`)}
        </Link>
      </div>
    </div>
  );
}
