'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { Link } from '@/navigation';
import { useAuth } from '@/lib/auth';
import { useRouter } from '@/navigation';
import { Check, Eye, EyeOff, Loader2 } from 'lucide-react';
import BrandLogo from '@/components/ui/BrandLogo';

export default function RegisterForm() {
  const t = useTranslations('auth.register');
  const { register } = useAuth();
  const router = useRouter();

  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError('');

    if (password.length < 8) {
      setError(t('errorPasswordLength'));
      return;
    }

    setLoading(true);
    const result = await register(email, name, password);

    if (result.ok) {
      setSuccess(true);
    } else {
      setError(result.error ?? t('errorFallback'));
    }
    setLoading(false);
  }

  if (success) {
    return (
      <div className="min-h-screen bg-surface-0 flex items-center justify-center px-4">
        <div className="w-full max-w-md text-center">
          <div className="bg-surface-1 border border-border rounded-xl p-8">
            <div className="w-12 h-12 bg-status-safe/10 rounded-full flex items-center justify-center mx-auto mb-4">
              <Check className="w-6 h-6 text-status-safe" />
            </div>
            <h2 className="text-xl font-bold text-text-primary">{t('successTitle')}</h2>
            <p className="text-sm text-text-secondary mt-2">
              {t('successMessage')}
            </p>
            <button
              onClick={() => router.push('/login')}
              className="mt-6 bg-brand-sage text-surface-0 font-semibold text-sm rounded-lg px-6 py-2.5 hover:bg-brand-sage-light transition-all"
            >
              {t('goToLogin')}
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-surface-0 flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <Link href="/" className="inline-flex items-center gap-2 mb-6">
            <BrandLogo size={28} className="text-brand-sage" />
            <span className="font-semibold tracking-wider text-text-primary text-lg">
              PANGUARD AI
            </span>
          </Link>
          <h1 className="text-2xl font-bold text-text-primary">{t('title')}</h1>
          <p className="text-sm text-text-secondary mt-2">{t('subtitle')}</p>
        </div>

        <div className="bg-surface-1 border border-border rounded-xl p-6">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="register-name" className="block text-sm font-medium text-text-secondary mb-1.5">{t('nameLabel')}</label>
              <input
                id="register-name"
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                autoComplete="name"
                className="w-full bg-surface-0 border border-border rounded-lg px-4 py-2.5 text-text-primary placeholder-text-muted text-sm focus:outline-none focus:border-brand-sage transition-colors"
                placeholder={t('namePlaceholder')}
              />
            </div>
            <div>
              <label htmlFor="register-email" className="block text-sm font-medium text-text-secondary mb-1.5">{t('emailLabel')}</label>
              <input
                id="register-email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoComplete="email"
                className="w-full bg-surface-0 border border-border rounded-lg px-4 py-2.5 text-text-primary placeholder-text-muted text-sm focus:outline-none focus:border-brand-sage transition-colors"
                placeholder={t('emailPlaceholder')}
              />
            </div>
            <div>
              <label htmlFor="register-password" className="block text-sm font-medium text-text-secondary mb-1.5">
                {t('passwordLabel')}
              </label>
              <div className="relative">
                <input
                  id="register-password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  minLength={8}
                  autoComplete="new-password"
                  className="w-full bg-surface-0 border border-border rounded-lg px-4 py-2.5 pr-10 text-text-primary placeholder-text-muted text-sm focus:outline-none focus:border-brand-sage transition-colors"
                  placeholder={t('passwordPlaceholder')}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-text-tertiary hover:text-text-secondary"
                  aria-label={showPassword ? t('hidePassword') : t('showPassword')}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {error && (
              <div role="alert" className="bg-status-danger/10 border border-status-danger/20 rounded-lg px-4 py-2.5 text-sm text-status-danger">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-brand-sage text-surface-0 font-semibold text-sm rounded-lg px-4 py-2.5 hover:bg-brand-sage-light transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              {loading && <Loader2 className="w-4 h-4 animate-spin" />}
              {t('createButton')}
            </button>

            <p className="text-center text-sm text-text-tertiary">
              {t('alreadyHaveAccount')}{' '}
              <Link
                href="/login"
                className="text-brand-sage hover:text-brand-sage-light transition-colors"
              >
                {t('loginLink')}
              </Link>
            </p>
          </form>
        </div>

        <p className="text-center text-xs text-text-muted mt-6">
          {t('legalPrefix')}{' '}
          <Link href="/legal/terms" className="underline hover:text-text-tertiary">
            {t('termsLink')}
          </Link>{' '}
          {t('legalAnd')}{' '}
          <Link href="/legal/privacy" className="underline hover:text-text-tertiary">
            {t('privacyLink')}
          </Link>
          .
        </p>
      </div>
    </div>
  );
}
