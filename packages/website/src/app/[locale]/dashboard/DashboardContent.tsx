'use client';

import { useState, useEffect, useCallback } from 'react';
import { useTranslations } from 'next-intl';
import { useAuth } from '@/lib/auth';
import { useRouter } from '@/navigation';
import { Link } from '@/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield,
  Activity,
  BarChart3,
  Settings,
  CreditCard,
  LogOut,
  Loader2,
  Terminal,
  Copy,
  Check,
  ArrowUpRight,
  Eye,
  Bell,
  Download,
  CircleCheck,
  Circle,
  X,
} from 'lucide-react';
import BrandLogo from '@/components/ui/BrandLogo';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'https://api.panguard.ai';
const REQUEST_TIMEOUT = 15_000;

const ONBOARDING_STORAGE_KEY = 'panguard_onboarding_checklist';
const ONBOARDING_DISMISSED_KEY = 'panguard_onboarding_dismissed';

interface UsageItem {
  resource: string;
  current: number;
  limit: number;
  percentage: number;
}

interface OnboardingState {
  installCLI: boolean;
  firstScan: boolean;
  guardActive: boolean;
  notificationsConfigured: boolean;
}

const DEFAULT_ONBOARDING: OnboardingState = {
  installCLI: false,
  firstScan: false,
  guardActive: false,
  notificationsConfigured: false,
};

function getOnboardingState(): OnboardingState {
  if (typeof window === 'undefined') return DEFAULT_ONBOARDING;
  try {
    const stored = localStorage.getItem(ONBOARDING_STORAGE_KEY);
    if (stored) {
      const parsed = JSON.parse(stored) as Partial<OnboardingState>;
      return { ...DEFAULT_ONBOARDING, ...parsed };
    }
  } catch {
    // Malformed data
  }
  return DEFAULT_ONBOARDING;
}

function saveOnboardingState(state: OnboardingState): void {
  if (typeof window === 'undefined') return;
  localStorage.setItem(ONBOARDING_STORAGE_KEY, JSON.stringify(state));
}

function getOnboardingDismissed(): boolean {
  if (typeof window === 'undefined') return false;
  return localStorage.getItem(ONBOARDING_DISMISSED_KEY) === 'true';
}

function setOnboardingDismissed(dismissed: boolean): void {
  if (typeof window === 'undefined') return;
  if (dismissed) {
    localStorage.setItem(ONBOARDING_DISMISSED_KEY, 'true');
  } else {
    localStorage.removeItem(ONBOARDING_DISMISSED_KEY);
  }
}

const ease = [0.22, 1, 0.36, 1] as const;

const fadeInUp = {
  initial: { opacity: 0, y: 16 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.5, ease },
};

const staggerContainer = {
  animate: {
    transition: {
      staggerChildren: 0.08,
    },
  },
};

/* ── Tier plan limits ── */

interface TierLimits {
  machines: string;
  scans: string;
  guard: string;
}

const TIER_LIMITS: Record<string, TierLimits> = {
  community: { machines: 'communityMachines', scans: 'communityScans', guard: 'communityGuard' },
  solo: { machines: 'soloMachines', scans: 'soloScans', guard: 'soloGuard' },
  pro: { machines: 'proMachines', scans: 'proScans', guard: 'proGuard' },
  business: { machines: 'businessMachines', scans: 'businessScans', guard: 'businessGuard' },
};

const TIER_PRICE: Record<string, string> = {
  community: '$0',
  solo: '$9/mo',
  pro: '$29/mo',
  business: '$79/mo',
};

export default function DashboardContent() {
  const t = useTranslations('dashboard');
  const { user, token, loading, logout } = useAuth();
  const router = useRouter();
  const [usage, setUsage] = useState<UsageItem[]>([]);
  const [usageLoading, setUsageLoading] = useState(true);
  const [usageError, setUsageError] = useState('');
  const [onboarding, setOnboarding] = useState<OnboardingState>(DEFAULT_ONBOARDING);
  const [dismissed, setDismissed] = useState(true);

  useEffect(() => {
    if (!loading && !user) {
      router.push('/login?redirect=/dashboard');
    }
  }, [loading, user, router]);

  useEffect(() => {
    setOnboarding(getOnboardingState());
    setDismissed(getOnboardingDismissed());
  }, []);

  useEffect(() => {
    if (!token) return;
    async function fetchUsage() {
      try {
        const res = await fetch(`${API_URL}/api/usage`, {
          headers: { Authorization: `Bearer ${token}` },
          signal: AbortSignal.timeout(REQUEST_TIMEOUT),
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

  const toggleChecklistItem = useCallback((key: keyof OnboardingState) => {
    setOnboarding((prev) => {
      const updated = { ...prev, [key]: !prev[key] };
      saveOnboardingState(updated);
      return updated;
    });
  }, []);

  const handleDismiss = useCallback(() => {
    setDismissed(true);
    setOnboardingDismissed(true);
  }, []);

  const handleShowGuide = useCallback(() => {
    setDismissed(false);
    setOnboardingDismissed(false);
  }, []);

  if (loading || !user) {
    return (
      <div className="min-h-screen bg-surface-0 flex items-center justify-center">
        <Loader2 className="w-6 h-6 text-brand-sage animate-spin" />
      </div>
    );
  }

  const tierDisplay = user.tier.charAt(0).toUpperCase() + user.tier.slice(1);
  const tierKey = user.tier.toLowerCase();
  const isCommunity = tierKey === 'community';
  const completedCount = Object.values(onboarding).filter(Boolean).length;
  const totalChecklist = Object.keys(onboarding).length;
  const allComplete = completedCount === totalChecklist;

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
        <motion.div
          className="mb-8"
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, ease }}
        >
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
        </motion.div>

        {/* Quick Actions */}
        <motion.div
          className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8"
          variants={staggerContainer}
          initial="initial"
          animate="animate"
        >
          <QuickAction
            icon={<Terminal className="w-5 h-5" />}
            title={t('quickActions.installCLI.title')}
            description={t('quickActions.installCLI.description')}
            href="/docs/getting-started"
            index={0}
          />
          <QuickAction
            icon={<Settings className="w-5 h-5" />}
            title={t('quickActions.accountSettings.title')}
            description={t('quickActions.accountSettings.description')}
            href="/account/settings"
            index={1}
          />
          <QuickAction
            icon={<CreditCard className="w-5 h-5" />}
            title={t('quickActions.billing.title')}
            description={t('quickActions.billing.description')}
            href="/account/billing"
            index={2}
          />
          <QuickAction
            icon={<BarChart3 className="w-5 h-5" />}
            title={t('quickActions.apiDocs.title')}
            description={t('quickActions.apiDocs.description')}
            href="/docs/api"
            index={3}
          />
        </motion.div>

        {/* Current Plan + Onboarding Checklist Row */}
        <motion.div
          className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8"
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.15, ease }}
        >
          {/* Current Plan Card */}
          <div className="lg:col-span-1 bg-surface-1 border border-border rounded-xl p-6 card-glow">
            <div className="flex items-center gap-2 mb-4">
              <Shield className="w-5 h-5 text-brand-sage" />
              <h2 className="text-lg font-semibold text-text-primary">
                {t('currentPlan.heading')}
              </h2>
            </div>

            <div className="flex items-baseline gap-3 mb-4">
              <span className="text-2xl font-bold text-text-primary">{tierDisplay}</span>
              <span className="text-sm text-brand-sage font-medium px-2.5 py-0.5 rounded-full bg-brand-sage/10 border border-brand-sage/20">
                {isCommunity ? t('currentPlan.freeTier') : (TIER_PRICE[tierKey] ?? tierDisplay)}
              </span>
            </div>

            {/* Tier Limits */}
            {TIER_LIMITS[tierKey] && (
              <div className="space-y-2.5 mb-5">
                <TierLimitRow
                  label={t('currentPlan.machines')}
                  value={t(`currentPlan.${TIER_LIMITS[tierKey].machines}` as 'currentPlan.communityMachines')}
                />
                <TierLimitRow
                  label={t('currentPlan.scansPerMonth')}
                  value={t(`currentPlan.${TIER_LIMITS[tierKey].scans}` as 'currentPlan.communityScans')}
                />
                <TierLimitRow
                  label={t('currentPlan.guardEndpoints')}
                  value={t(`currentPlan.${TIER_LIMITS[tierKey].guard}` as 'currentPlan.communityGuard')}
                />
              </div>
            )}

            {isCommunity && (
              <div className="pt-3 border-t border-border">
                <p className="text-xs text-text-tertiary mb-3">
                  {t('currentPlan.upgradeMessage')}
                </p>
                <Link
                  href="/pricing"
                  className="inline-flex items-center gap-1.5 px-4 py-2 rounded-full bg-brand-sage text-surface-0 text-sm font-medium hover:bg-brand-sage/90 transition-colors"
                >
                  {t('currentPlan.upgradeButton')}
                  <ArrowUpRight className="w-3.5 h-3.5" />
                </Link>
              </div>
            )}
          </div>

          {/* Onboarding Checklist */}
          <div className="lg:col-span-2 bg-surface-1 border border-border rounded-xl p-6 card-glow">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Activity className="w-5 h-5 text-brand-sage" />
                <h2 className="text-lg font-semibold text-text-primary">
                  {t('onboarding.checklist.heading')}
                </h2>
              </div>
              <span className="text-xs text-text-tertiary">
                {t('onboarding.checklist.progress', {
                  completed: String(completedCount),
                  total: String(totalChecklist),
                })}
              </span>
            </div>

            {/* Progress bar */}
            <div className="h-2 bg-surface-2 rounded-full overflow-hidden mb-5">
              <motion.div
                className="h-full rounded-full bg-brand-sage"
                initial={{ width: 0 }}
                animate={{ width: `${(completedCount / totalChecklist) * 100}%` }}
                transition={{ duration: 0.6, ease }}
              />
            </div>

            {allComplete && (
              <motion.p
                className="text-sm text-brand-sage font-medium mb-4 flex items-center gap-2"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.3 }}
              >
                <CircleCheck className="w-4 h-4" />
                {t('onboarding.checklist.complete')}
              </motion.p>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <ChecklistItem
                checked={onboarding.installCLI}
                label={t('onboarding.checklist.installCLI')}
                icon={<Download className="w-4 h-4" />}
                onToggle={() => toggleChecklistItem('installCLI')}
              />
              <ChecklistItem
                checked={onboarding.firstScan}
                label={t('onboarding.checklist.firstScan')}
                icon={<Eye className="w-4 h-4" />}
                onToggle={() => toggleChecklistItem('firstScan')}
              />
              <ChecklistItem
                checked={onboarding.guardActive}
                label={t('onboarding.checklist.guardActive')}
                icon={<Shield className="w-4 h-4" />}
                onToggle={() => toggleChecklistItem('guardActive')}
              />
              <ChecklistItem
                checked={onboarding.notificationsConfigured}
                label={t('onboarding.checklist.notificationsConfigured')}
                icon={<Bell className="w-4 h-4" />}
                onToggle={() => toggleChecklistItem('notificationsConfigured')}
              />
            </div>
          </div>
        </motion.div>

        {/* Quick Start Guide (dismissible) */}
        <AnimatePresence mode="wait">
          {!dismissed ? (
            <motion.div
              key="quick-start-guide"
              className="mb-8"
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              transition={{ duration: 0.4, ease }}
            >
              <QuickStartGuide
                token={token}
                onDismiss={handleDismiss}
              />
            </motion.div>
          ) : (
            <motion.div
              key="show-guide-button"
              className="mb-8"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.3, ease }}
            >
              <button
                onClick={handleShowGuide}
                className="text-xs text-text-tertiary hover:text-text-secondary transition-colors flex items-center gap-1.5"
              >
                <Terminal className="w-3.5 h-3.5" />
                {t('onboarding.showGuide')}
              </button>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Usage Meters */}
        <motion.div
          className="bg-surface-1 border border-border rounded-xl p-6"
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.25, ease }}
        >
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
        </motion.div>
      </div>
    </div>
  );
}

/* ── Quick Start Guide Section ── */

function QuickStartGuide({
  token,
  onDismiss,
}: {
  token: string | null;
  onDismiss: () => void;
}) {
  const t = useTranslations('dashboard');

  const steps = [
    {
      num: 1,
      title: t('onboarding.step1Title'),
      desc: t('onboarding.step1Desc'),
      commands: [
        { label: t('onboarding.step1CurlLabel'), cmd: 'curl -fsSL https://get.panguard.ai | bash' },
        { label: t('onboarding.step1NpmLabel'), cmd: 'npm install -g @panguard-ai/panguard' },
      ],
    },
    {
      num: 2,
      title: t('onboarding.step2Title'),
      desc: t('onboarding.step2Desc'),
      commands: [{ label: null, cmd: 'panguard login' }],
    },
    {
      num: 3,
      title: t('onboarding.step3Title'),
      desc: t('onboarding.step3Desc'),
      commands: [{ label: null, cmd: 'panguard scan' }],
    },
    {
      num: 4,
      title: t('onboarding.step4Title'),
      desc: t('onboarding.step4Desc'),
      commands: [{ label: null, cmd: 'panguard guard start' }],
    },
    {
      num: 5,
      title: t('onboarding.step5Title'),
      desc: t('onboarding.step5Desc'),
      commands: [{ label: null, cmd: 'panguard chat setup' }],
      optional: t('onboarding.step5Optional'),
    },
  ];

  return (
    <div className="bg-surface-1 border border-border rounded-xl p-6 card-glow">
      <div className="flex items-start justify-between mb-6">
        <div className="flex items-start gap-3">
          <div className="w-10 h-10 rounded-xl bg-brand-sage/10 border border-brand-sage/20 flex items-center justify-center shrink-0">
            <Terminal className="w-5 h-5 text-brand-sage" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-text-primary">
              {t('onboarding.heading')}
            </h2>
            <p className="text-sm text-text-secondary mt-0.5">
              {t('onboarding.subtitle')}
            </p>
          </div>
        </div>
        <button
          onClick={onDismiss}
          className="text-text-tertiary hover:text-text-secondary transition-colors p-1 -mr-1 -mt-1"
          aria-label={t('onboarding.dismiss')}
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="space-y-5">
        {steps.map((step, idx) => (
          <motion.div
            key={step.num}
            className="relative"
            initial={{ opacity: 0, x: -12 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.4, delay: idx * 0.06, ease }}
          >
            <div className="flex gap-4">
              {/* Step indicator with connecting line */}
              <div className="flex flex-col items-center">
                <div className="w-8 h-8 rounded-full bg-brand-sage/15 border border-brand-sage/30 flex items-center justify-center shrink-0">
                  <span className="text-xs font-bold text-brand-sage">{step.num}</span>
                </div>
                {idx < steps.length - 1 && (
                  <div className="w-px flex-1 bg-border mt-2" />
                )}
              </div>

              <div className="flex-1 min-w-0 pb-2">
                <div className="flex items-center gap-2 mb-1">
                  <h3 className="text-sm font-semibold text-text-primary">{step.title}</h3>
                  {step.optional && (
                    <span className="text-[10px] uppercase tracking-wider text-text-tertiary bg-surface-2 px-1.5 py-0.5 rounded">
                      {step.optional}
                    </span>
                  )}
                </div>
                <p className="text-xs text-text-tertiary mb-2.5">{step.desc}</p>

                <div className="space-y-2">
                  {step.commands.map((c) => (
                    <div key={c.cmd}>
                      {c.label && (
                        <span className="text-[10px] uppercase tracking-wider text-text-tertiary mb-1 block">
                          {c.label}
                        </span>
                      )}
                      <CommandBlock command={c.cmd} />
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  );
}

/* ── Sub-components ── */

function QuickAction({
  icon,
  title,
  description,
  href,
  index,
}: {
  icon: React.ReactNode;
  title: string;
  description: string;
  href: string;
  index: number;
}) {
  return (
    <motion.div
      variants={fadeInUp}
      custom={index}
    >
      <Link
        href={href as '/docs/getting-started'}
        className="block bg-surface-1 border border-border rounded-xl p-4 hover:border-border-hover transition-colors group h-full"
      >
        <div className="text-brand-sage mb-2 group-hover:text-brand-sage-light transition-colors">
          {icon}
        </div>
        <h3 className="text-sm font-medium text-text-primary">{title}</h3>
        <p className="text-xs text-text-tertiary mt-0.5">{description}</p>
      </Link>
    </motion.div>
  );
}

function CommandBlock({
  command,
  copyValue,
}: {
  command: string;
  copyValue?: string;
}) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(copyValue ?? command);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard not available
    }
  }, [command, copyValue]);

  return (
    <div className="flex items-center gap-2 bg-surface-0 border border-border rounded-lg px-3 py-2">
      <code className="font-mono text-xs text-brand-sage truncate flex-1">{command}</code>
      <button
        onClick={handleCopy}
        className="text-text-tertiary hover:text-text-secondary transition-colors shrink-0"
        aria-label="Copy command"
      >
        {copied ? (
          <Check className="w-3.5 h-3.5 text-status-safe" />
        ) : (
          <Copy className="w-3.5 h-3.5" />
        )}
      </button>
    </div>
  );
}

function ChecklistItem({
  checked,
  label,
  icon,
  onToggle,
}: {
  checked: boolean;
  label: string;
  icon: React.ReactNode;
  onToggle: () => void;
}) {
  return (
    <button
      onClick={onToggle}
      className={`flex items-center gap-3 p-3 rounded-lg border transition-all text-left w-full ${
        checked
          ? 'bg-brand-sage/5 border-brand-sage/20'
          : 'bg-surface-0 border-border hover:border-border-hover'
      }`}
    >
      <div className={`shrink-0 transition-colors ${checked ? 'text-brand-sage' : 'text-text-tertiary'}`}>
        {checked ? <CircleCheck className="w-5 h-5" /> : <Circle className="w-5 h-5" />}
      </div>
      <div className={`shrink-0 transition-colors ${checked ? 'text-brand-sage' : 'text-text-tertiary'}`}>
        {icon}
      </div>
      <span className={`text-sm transition-colors ${checked ? 'text-brand-sage font-medium' : 'text-text-secondary'}`}>
        {label}
      </span>
    </button>
  );
}

function TierLimitRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between text-sm">
      <span className="text-text-tertiary">{label}</span>
      <span className="text-text-primary font-medium">{value}</span>
    </div>
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
