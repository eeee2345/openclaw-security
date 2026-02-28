'use client';

import { useState, useEffect } from 'react';
import { useAuth } from '@/lib/auth';
import { useRouter, Link } from '@/navigation';
import { CreditCard, ExternalLink, Loader2, ArrowLeft, ArrowUpRight, Check } from 'lucide-react';
import BrandLogo from '@/components/ui/BrandLogo';

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? '';

interface BillingData {
  tier: string;
  subscription?: {
    status: string;
    renewsAt?: string;
    endsAt?: string;
  };
}

const TIER_FEATURES: Record<string, string[]> = {
  free: ['100 scans/month', '1 endpoint', '1,000 API calls'],
  solo: ['Unlimited scans', '3 endpoints', '10,000 API calls', '1 honeypot'],
  pro: ['Unlimited scans', '10 endpoints', '50,000 API calls', '5 reports', '3 honeypots'],
  business: ['Unlimited scans', '25 endpoints', 'Unlimited API calls', '20 reports', '8 honeypots'],
  enterprise: ['Everything unlimited', 'Priority support', 'Custom SLA'],
};

export default function BillingContent() {
  const { user, token, loading } = useAuth();
  const router = useRouter();
  const [billing, setBilling] = useState<BillingData | null>(null);
  const [billingLoading, setBillingLoading] = useState(true);
  const [portalLoading, setPortalLoading] = useState(false);

  useEffect(() => {
    if (!loading && !user) {
      router.push('/login?redirect=/account/billing');
    }
  }, [loading, user, router]);

  useEffect(() => {
    if (!token) return;
    async function fetchBilling() {
      try {
        const res = await fetch(`${API_URL}/api/billing/status`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        const data = (await res.json()) as { ok: boolean; data?: BillingData };
        if (data.ok && data.data) {
          setBilling(data.data);
        }
      } catch {
        // ignore
      } finally {
        setBillingLoading(false);
      }
    }
    void fetchBilling();
  }, [token]);

  async function openPortal() {
    if (!token) return;
    setPortalLoading(true);
    try {
      const res = await fetch(`${API_URL}/api/billing/portal`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = (await res.json()) as { ok: boolean; data?: { url: string } };
      if (data.ok && data.data?.url) {
        window.open(data.data.url, '_blank');
      }
    } catch {
      // ignore
    } finally {
      setPortalLoading(false);
    }
  }

  if (loading || !user) {
    return (
      <div className="min-h-screen bg-surface-0 flex items-center justify-center">
        <Loader2 className="w-6 h-6 text-brand-sage animate-spin" />
      </div>
    );
  }

  const tier = billing?.tier ?? user.tier;
  const tierDisplay = tier.charAt(0).toUpperCase() + tier.slice(1);
  const features = TIER_FEATURES[tier] ?? TIER_FEATURES['free']!;
  const sub = billing?.subscription;
  const statusColor =
    sub?.status === 'active'
      ? 'text-status-safe'
      : sub?.status === 'cancelled'
        ? 'text-status-caution'
        : 'text-text-tertiary';

  return (
    <div className="min-h-screen bg-surface-0">
      {/* Header */}
      <header className="border-b border-border bg-surface-1">
        <div className="max-w-3xl mx-auto px-6 h-14 flex items-center gap-4">
          <Link href="/dashboard" className="text-text-tertiary hover:text-text-secondary">
            <ArrowLeft className="w-4 h-4" />
          </Link>
          <BrandLogo size={20} className="text-brand-sage" />
          <span className="font-semibold text-text-primary text-sm">Billing</span>
        </div>
      </header>

      <div className="max-w-3xl mx-auto px-6 py-8 space-y-6">
        {/* Current Plan */}
        <div className="bg-surface-1 border border-border rounded-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-text-primary flex items-center gap-2">
              <CreditCard className="w-5 h-5 text-brand-sage" />
              Current Plan
            </h2>
            {tier !== 'free' && sub && (
              <button
                onClick={openPortal}
                disabled={portalLoading}
                className="flex items-center gap-1.5 text-sm text-brand-sage hover:text-brand-sage-light transition-colors"
              >
                {portalLoading ? (
                  <Loader2 className="w-3 h-3 animate-spin" />
                ) : (
                  <ExternalLink className="w-3 h-3" />
                )}
                Manage Subscription
              </button>
            )}
          </div>

          {billingLoading ? (
            <Loader2 className="w-4 h-4 text-text-tertiary animate-spin" />
          ) : (
            <div className="space-y-4">
              <div className="flex items-baseline gap-3">
                <span className="text-3xl font-bold text-text-primary">{tierDisplay}</span>
                {sub && (
                  <span className={`text-sm font-medium ${statusColor}`}>
                    {sub.status.charAt(0).toUpperCase() + sub.status.slice(1)}
                  </span>
                )}
              </div>

              {sub?.renewsAt && (
                <p className="text-sm text-text-secondary">
                  Renews on {new Date(sub.renewsAt).toLocaleDateString()}
                </p>
              )}
              {sub?.endsAt && (
                <p className="text-sm text-status-caution">
                  Ends on {new Date(sub.endsAt).toLocaleDateString()}
                </p>
              )}
              {!sub && tier === 'free' && (
                <p className="text-sm text-text-tertiary">Free tier — no subscription</p>
              )}

              <div className="pt-4 border-t border-border">
                <p className="text-xs text-text-tertiary uppercase tracking-wider mb-2">
                  Plan includes
                </p>
                <ul className="space-y-1.5">
                  {features.map((f) => (
                    <li key={f} className="flex items-center gap-2 text-sm text-text-secondary">
                      <Check className="w-3.5 h-3.5 text-brand-sage shrink-0" />
                      {f}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          )}
        </div>

        {/* Upgrade CTA */}
        {tier === 'free' && (
          <div className="bg-brand-sage-wash border border-brand-sage/20 rounded-xl p-6">
            <h3 className="font-semibold text-text-primary mb-2">Upgrade your plan</h3>
            <p className="text-sm text-text-secondary mb-4">
              Get more scans, endpoints, and advanced features.
            </p>
            <Link
              href="/pricing"
              className="inline-flex items-center gap-1.5 bg-brand-sage text-surface-0 font-semibold text-sm rounded-lg px-5 py-2.5 hover:bg-brand-sage-light transition-all"
            >
              View Plans
              <ArrowUpRight className="w-4 h-4" />
            </Link>
          </div>
        )}
      </div>
    </div>
  );
}
