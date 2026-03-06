'use client';

import { useState, useEffect } from 'react';
import { useTranslations } from 'next-intl';
import { useAuth } from '@/lib/auth';
import { useRouter, Link } from '@/navigation';
import {
  Shield,
  Key,
  Trash2,
  Download,
  Loader2,
  ArrowLeft,
  Check,
  AlertTriangle,
} from 'lucide-react';
import BrandLogo from '@/components/ui/BrandLogo';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'https://panguard-api-production.up.railway.app';

export default function AccountSettings() {
  const t = useTranslations('accountSettings');
  const { user, token, loading, logout } = useAuth();
  const router = useRouter();

  const [totpEnabled, setTotpEnabled] = useState(false);
  const [totpLoading, setTotpLoading] = useState(true);
  const [setupData, setSetupData] = useState<{
    secret: string;
    uri: string;
    backupCodes: string[];
  } | null>(null);
  const [totpCode, setTotpCode] = useState('');
  const [totpError, setTotpError] = useState('');
  const [totpSuccess, setTotpSuccess] = useState('');

  const [deleteConfirm, setDeleteConfirm] = useState(false);
  const [deletePassword, setDeletePassword] = useState('');
  const [deleteError, setDeleteError] = useState('');
  const [deleteLoading, setDeleteLoading] = useState(false);

  const [exportLoading, setExportLoading] = useState(false);

  useEffect(() => {
    if (!loading && !user) {
      router.push('/login?redirect=/account/settings');
    }
  }, [loading, user, router]);

  useEffect(() => {
    if (!token) return;
    async function checkTotp() {
      try {
        const res = await fetch(`${API_URL}/api/auth/totp/status`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        const data = (await res.json()) as { ok: boolean; data?: { enabled: boolean } };
        if (data.ok) setTotpEnabled(data.data?.enabled ?? false);
      } catch {
        setTotpError(t('twoFA.errorCheckStatus'));
      } finally {
        setTotpLoading(false);
      }
    }
    void checkTotp();
  }, [token, t]);

  async function handleTotpSetup() {
    if (!token) return;
    setTotpError('');
    try {
      const res = await fetch(`${API_URL}/api/auth/totp/setup`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = (await res.json()) as {
        ok: boolean;
        data?: { secret: string; uri: string; backupCodes: string[] };
      };
      if (data.ok && data.data) {
        setSetupData(data.data);
      }
    } catch {
      setTotpError(t('twoFA.errorSetupFailed'));
    }
  }

  async function handleTotpVerify() {
    if (!token || !totpCode) return;
    setTotpError('');
    try {
      const res = await fetch(`${API_URL}/api/auth/totp/verify`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ code: totpCode }),
      });
      const data = (await res.json()) as { ok: boolean; error?: string };
      if (data.ok) {
        setTotpEnabled(true);
        setSetupData(null);
        setTotpCode('');
        setTotpSuccess(t('twoFA.successEnabled'));
      } else {
        setTotpError(data.error ?? t('twoFA.errorInvalidCode'));
      }
    } catch {
      setTotpError(t('twoFA.errorVerifyFailed'));
    }
  }

  async function handleTotpDisable() {
    if (!token) return;
    setTotpError('');
    try {
      const res = await fetch(`${API_URL}/api/auth/totp/disable`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ password: deletePassword || 'confirm' }),
      });
      const data = (await res.json()) as { ok: boolean; error?: string };
      if (data.ok) {
        setTotpEnabled(false);
        setTotpSuccess(t('twoFA.successDisabled'));
      } else {
        setTotpError(data.error ?? t('twoFA.errorDisableFailed'));
      }
    } catch {
      setTotpError(t('twoFA.errorDisableFailed'));
    }
  }

  async function handleExportData() {
    if (!token) return;
    setExportLoading(true);
    try {
      const res = await fetch(`${API_URL}/api/auth/export-data`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'panguard-data-export.json';
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      // ignore
    } finally {
      setExportLoading(false);
    }
  }

  async function handleDeleteAccount() {
    if (!token || !deletePassword) return;
    setDeleteError('');
    setDeleteLoading(true);
    try {
      const res = await fetch(`${API_URL}/api/auth/delete-account`, {
        method: 'DELETE',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ password: deletePassword }),
      });
      const data = (await res.json()) as { ok: boolean; error?: string };
      if (data.ok) {
        await logout();
        router.push('/');
      } else {
        setDeleteError(data.error ?? t('deleteAccount.errorFailed'));
      }
    } catch {
      setDeleteError(t('deleteAccount.errorNetwork'));
    } finally {
      setDeleteLoading(false);
    }
  }

  if (loading || !user) {
    return (
      <div className="min-h-screen bg-surface-0 flex items-center justify-center">
        <Loader2 className="w-6 h-6 text-brand-sage animate-spin" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-surface-0">
      {/* Header */}
      <header className="border-b border-border bg-surface-1">
        <div className="max-w-3xl mx-auto px-6 h-14 flex items-center gap-4">
          <Link
            href="/dashboard"
            className="text-text-tertiary hover:text-text-secondary"
            aria-label={t('backToDashboard')}
          >
            <ArrowLeft className="w-4 h-4" />
          </Link>
          <BrandLogo size={20} className="text-brand-sage" />
          <span className="font-semibold text-text-primary text-sm">{t('headerTitle')}</span>
        </div>
      </header>

      <div className="max-w-3xl mx-auto px-6 py-8 space-y-6">
        {/* Profile */}
        <Section title={t('profile.sectionTitle')} icon={<Shield className="w-5 h-5" />}>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-text-tertiary">{t('profile.nameLabel')}</span>
              <p className="text-text-primary font-medium">{user.name}</p>
            </div>
            <div>
              <span className="text-text-tertiary">{t('profile.emailLabel')}</span>
              <p className="text-text-primary font-medium">{user.email}</p>
            </div>
            <div>
              <span className="text-text-tertiary">{t('profile.planLabel')}</span>
              <p className="text-brand-sage font-medium">
                {user.tier.charAt(0).toUpperCase() + user.tier.slice(1)}
              </p>
            </div>
            <div>
              <span className="text-text-tertiary">{t('profile.memberSinceLabel')}</span>
              <p className="text-text-primary font-medium">
                {new Date(user.createdAt).toLocaleDateString()}
              </p>
            </div>
          </div>
        </Section>

        {/* 2FA */}
        <Section title={t('twoFA.sectionTitle')} icon={<Key className="w-5 h-5" />}>
          {totpLoading ? (
            <Loader2 className="w-4 h-4 text-text-tertiary animate-spin" />
          ) : totpEnabled ? (
            <div>
              <div className="flex items-center gap-2 mb-3">
                <Check className="w-4 h-4 text-status-safe" />
                <span className="text-sm text-status-safe font-medium">
                  {t('twoFA.statusEnabled')}
                </span>
              </div>
              <button
                onClick={handleTotpDisable}
                className="text-sm text-status-danger hover:underline"
              >
                {t('twoFA.disableButton')}
              </button>
            </div>
          ) : setupData ? (
            <div className="space-y-4">
              <p className="text-sm text-text-secondary">{t('twoFA.qrInstruction')}</p>
              <code className="block bg-surface-0 border border-border rounded-lg p-3 font-mono text-xs text-brand-sage break-all">
                {setupData.secret}
              </code>
              <div>
                <label className="block text-sm text-text-secondary mb-1.5">
                  {t('twoFA.codeLabel')}
                </label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    inputMode="numeric"
                    pattern="\d{6}"
                    maxLength={6}
                    value={totpCode}
                    onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                    className="bg-surface-0 border border-border rounded-lg px-4 py-2 text-text-primary font-mono text-center tracking-[0.3em] text-sm focus:outline-none focus:border-brand-sage w-40"
                    placeholder="000000"
                  />
                  <button
                    onClick={handleTotpVerify}
                    className="bg-brand-sage text-surface-0 font-medium text-sm rounded-lg px-4 py-2 hover:bg-brand-sage-light"
                  >
                    {t('twoFA.verifyButton')}
                  </button>
                </div>
              </div>
              {setupData.backupCodes.length > 0 && (
                <div>
                  <p className="text-sm text-text-secondary mb-2">
                    {t('twoFA.backupCodesInstruction')}
                  </p>
                  <div className="bg-surface-0 border border-border rounded-lg p-3 grid grid-cols-2 gap-1">
                    {setupData.backupCodes.map((code) => (
                      <code key={code} className="font-mono text-xs text-text-primary">
                        {code}
                      </code>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div>
              <p className="text-sm text-text-secondary mb-3">{t('twoFA.description')}</p>
              <button
                onClick={handleTotpSetup}
                className="bg-brand-sage text-surface-0 font-medium text-sm rounded-lg px-4 py-2 hover:bg-brand-sage-light"
              >
                {t('twoFA.setupButton')}
              </button>
            </div>
          )}
          {totpError && <p className="text-sm text-status-danger mt-2">{totpError}</p>}
          {totpSuccess && <p className="text-sm text-status-safe mt-2">{totpSuccess}</p>}
        </Section>

        {/* Data Export */}
        <Section title={t('exportData.sectionTitle')} icon={<Download className="w-5 h-5" />}>
          <p className="text-sm text-text-secondary mb-3">{t('exportData.description')}</p>
          <button
            onClick={handleExportData}
            disabled={exportLoading}
            className="border border-border rounded-lg px-4 py-2 text-sm text-text-secondary hover:text-text-primary hover:border-border-hover transition-colors flex items-center gap-2"
          >
            {exportLoading ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Download className="w-4 h-4" />
            )}
            {t('exportData.exportButton')}
          </button>
        </Section>

        {/* Danger Zone */}
        <Section
          title={t('deleteAccount.sectionTitle')}
          icon={<Trash2 className="w-5 h-5" />}
          danger
        >
          {!deleteConfirm ? (
            <div>
              <p className="text-sm text-text-secondary mb-3">{t('deleteAccount.description')}</p>
              <button
                onClick={() => setDeleteConfirm(true)}
                className="border border-status-danger/30 text-status-danger rounded-lg px-4 py-2 text-sm hover:bg-status-danger/10 transition-colors"
              >
                {t('deleteAccount.sectionTitle')}
              </button>
            </div>
          ) : (
            <div className="space-y-3">
              <div className="flex items-start gap-2 bg-status-danger/10 border border-status-danger/20 rounded-lg p-3">
                <AlertTriangle className="w-4 h-4 text-status-danger shrink-0 mt-0.5" />
                <p className="text-sm text-status-danger">{t('deleteAccount.warning')}</p>
              </div>
              <div>
                <label className="block text-sm text-text-secondary mb-1.5">
                  {t('deleteAccount.passwordLabel')}
                </label>
                <input
                  type="password"
                  value={deletePassword}
                  onChange={(e) => setDeletePassword(e.target.value)}
                  className="w-full bg-surface-0 border border-border rounded-lg px-4 py-2 text-text-primary text-sm focus:outline-none focus:border-status-danger"
                  placeholder={t('deleteAccount.passwordPlaceholder')}
                />
              </div>
              {deleteError && <p className="text-sm text-status-danger">{deleteError}</p>}
              <div className="flex gap-2">
                <button
                  onClick={() => {
                    setDeleteConfirm(false);
                    setDeletePassword('');
                    setDeleteError('');
                  }}
                  className="border border-border rounded-lg px-4 py-2 text-sm text-text-secondary hover:text-text-primary"
                >
                  {t('deleteAccount.cancelButton')}
                </button>
                <button
                  onClick={handleDeleteAccount}
                  disabled={deleteLoading || !deletePassword}
                  className="bg-status-danger text-white rounded-lg px-4 py-2 text-sm font-medium hover:bg-status-danger/90 disabled:opacity-50 flex items-center gap-2"
                >
                  {deleteLoading && <Loader2 className="w-4 h-4 animate-spin" />}
                  {t('deleteAccount.confirmButton')}
                </button>
              </div>
            </div>
          )}
        </Section>
      </div>
    </div>
  );
}

function Section({
  title,
  icon,
  danger,
  children,
}: {
  title: string;
  icon: React.ReactNode;
  danger?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div
      className={`bg-surface-1 border rounded-xl p-6 ${danger ? 'border-status-danger/20' : 'border-border'}`}
    >
      <h2
        className={`text-base font-semibold mb-4 flex items-center gap-2 ${danger ? 'text-status-danger' : 'text-text-primary'}`}
      >
        <span className={danger ? 'text-status-danger' : 'text-brand-sage'}>{icon}</span>
        {title}
      </h2>
      {children}
    </div>
  );
}
