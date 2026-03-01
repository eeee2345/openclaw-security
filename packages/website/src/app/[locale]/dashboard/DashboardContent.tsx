'use client';

import { useState, useEffect } from 'react';
import { useTranslations } from 'next-intl';
import { useAuth } from '@/lib/auth';
import { useRouter } from '@/navigation';
import { Link } from '@/navigation';
import {
  Shield,
  Activity,
  BarChart3,
  Settings,
  CreditCard,
  LogOut,
  Loader2,
  Terminal,
} from 'lucide-react';
import BrandLogo from '@/components/ui/BrandLogo';

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? '';

interface UsageItem {
  resource: string;
  current: number;
  limit: number;
  percentage: number;
}

export default function DashboardContent() {
  const t = useTranslations('dashboard');
  const { user, token, loading, logout } = useAuth();
  const router = useRouter();
  const [usage, setUsage] = useState<UsageItem[]>([]);
  const [usageLoading, setUsageLoading] = useState(true);
  const [usageError, setUsageError] = useState('');

  useEffect(() => {
    if (!loading && !user) {
      router.push('/login?redirect=/dashboard');
    }
  }, [loading, user, router]);

  useEffect(() => {
    if (!token) return;
    async function fetchUsage() {
      try {
        const res = await fetch(`${API_URL}/api/usage`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        const data = (await res.json()) as { ok: boolean; data?: { usage: UsageItem[] } };
        if (data.ok && data.data?.usage) {
          setUsage(data.data.usage);
        }
      } catch {
        setUsageError(t('usageError'));
      } finally {
        setUsageLoading(false);
      }
    }
    void fetchUsage();
  }, [token, t]);

  if (loading || !user) {
    return (
      <div className="min-h-screen bg-surface-0 flex items-center justify-center">
        <Loader2 className="w-6 h-6 text-brand-sage animate-spin" />
      </div>
    );
  }

  const tierDisplay = user.tier.charAt(0).toUpperCase() + user.tier.slice(1);

  return (
    <div className="min-h-screen bg-surface-0">
      {/* Header */}
      <header className="border-b border-border bg-surface-1">
        <div className="max-w-6xl mx-auto px-6 h-14 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-1.5">
            <BrandLogo size={20} className="text-brand-sage" />
            <span className="font-semibold tracking-wider text-text-primary text-sm">PANGUARD</span>
          </Link>
          <div className="flex items-center gap-4">
            <span className="text-sm text-text-secondary">{user.email}</span>
            <button
              onClick={() => {
                void logout();
                router.push('/');
              }}
              className="text-text-tertiary hover:text-text-secondary transition-colors"
              aria-label={t('logOut')}
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </header>

      <div className="max-w-6xl mx-auto px-6 py-8">
        {/* Welcome */}
        <div className="mb-8">
          <h1 className="text-2xl font-bold text-text-primary">
            {t('welcome', { name: user.name })}
          </h1>
          <p className="text-sm text-text-secondary mt-1">
            {t('planLabel')} <span className="text-brand-sage font-medium">{tierDisplay}</span>
            {user.planExpiresAt && (
              <span className="text-text-tertiary">
                {' '}
                {t('planExpires', { date: new Date(user.planExpiresAt).toLocaleDateString() })}
              </span>
            )}
          </p>
        </div>

        {/* Quick Actions */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
          <QuickAction
            icon={<Terminal className="w-5 h-5" />}
            title={t('quickActions.installCLI.title')}
            description={t('quickActions.installCLI.description')}
            href="/docs/getting-started"
          />
          <QuickAction
            icon={<Settings className="w-5 h-5" />}
            title={t('quickActions.accountSettings.title')}
            description={t('quickActions.accountSettings.description')}
            href="/account/settings"
          />
          <QuickAction
            icon={<CreditCard className="w-5 h-5" />}
            title={t('quickActions.billing.title')}
            description={t('quickActions.billing.description')}
            href="/account/billing"
          />
          <QuickAction
            icon={<BarChart3 className="w-5 h-5" />}
            title={t('quickActions.apiDocs.title')}
            description={t('quickActions.apiDocs.description')}
            href="/docs/api"
          />
        </div>

        {/* Usage Meters */}
        <div className="bg-surface-1 border border-border rounded-xl p-6">
          <h2 className="text-lg font-semibold text-text-primary mb-4 flex items-center gap-2">
            <Activity className="w-5 h-5 text-brand-sage" />
            {t('usageHeading')}
          </h2>

          {usageLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="w-5 h-5 text-text-tertiary animate-spin" />
            </div>
          ) : usageError ? (
            <p className="text-sm text-status-caution py-4">{usageError}</p>
          ) : usage.length === 0 ? (
            <p className="text-sm text-text-tertiary py-4">{t('usageEmpty')}</p>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {usage.map((item) => (
                <UsageMeter
                  key={item.resource}
                  item={item}
                  unlimitedLabel={t('unlimited')}
                  resourceLabel={t(`resources.${item.resource}` as 'resources.scan')}
                />
              ))}
            </div>
          )}
        </div>

        {/* CLI Install Banner */}
        <div className="mt-8 bg-surface-2 border border-border rounded-xl p-6">
          <div className="flex items-start gap-4">
            <Shield className="w-8 h-8 text-brand-sage shrink-0 mt-0.5" />
            <div>
              <h3 className="font-semibold text-text-primary">{t('quickStartHeading')}</h3>
              <p className="text-sm text-text-secondary mt-1">{t('quickStartDescription')}</p>
              <code className="inline-block mt-3 bg-surface-0 border border-border rounded-lg px-4 py-2 font-mono text-sm text-brand-sage">
                curl -fsSL https://panguard.ai/install | bash
              </code>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function QuickAction({
  icon,
  title,
  description,
  href,
}: {
  icon: React.ReactNode;
  title: string;
  description: string;
  href: string;
}) {
  return (
    <Link
      href={href as '/docs/getting-started'}
      className="bg-surface-1 border border-border rounded-xl p-4 hover:border-border-hover transition-colors group"
    >
      <div className="text-brand-sage mb-2 group-hover:text-brand-sage-light transition-colors">
        {icon}
      </div>
      <h3 className="text-sm font-medium text-text-primary">{title}</h3>
      <p className="text-xs text-text-tertiary mt-0.5">{description}</p>
    </Link>
  );
}

function UsageMeter({
  item,
  unlimitedLabel,
  resourceLabel,
}: {
  item: UsageItem;
  unlimitedLabel: string;
  resourceLabel: string;
}) {
  const isUnlimited = item.limit === -1;
  const percentage = isUnlimited ? 0 : item.percentage;
  const barColor =
    percentage >= 90
      ? 'bg-status-danger'
      : percentage >= 70
        ? 'bg-status-caution'
        : 'bg-brand-sage';

  return (
    <div className="bg-surface-0 border border-border rounded-lg p-4">
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm font-medium text-text-primary">{resourceLabel}</span>
        <span className="text-xs text-text-tertiary">
          {item.current.toLocaleString()} /{' '}
          {isUnlimited ? unlimitedLabel : item.limit.toLocaleString()}
        </span>
      </div>
      <div className="h-2 bg-surface-2 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-500 ${barColor}`}
          style={{ width: isUnlimited ? '0%' : `${Math.min(100, percentage)}%` }}
        />
      </div>
    </div>
  );
}
