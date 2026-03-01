'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { Check, ArrowRight, Users } from 'lucide-react';
import FadeInUp from '@/components/FadeInUp';

export default function WaitlistForm() {
  const t = useTranslations('waitlistForm');
  const te = useTranslations('errorValidation');

  const [email, setEmail] = useState('');
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState('');

  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError('');

    if (!email.trim()) {
      setError(te('emailRequired'));
      return;
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      setError(te('emailInvalid'));
      return;
    }

    setLoading(true);
    try {
      const res = await fetch('/api/waitlist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });
      if (!res.ok) throw new Error('Submit failed');
      setSubmitted(true);
    } catch {
      setError(te('submitFailed'));
    } finally {
      setLoading(false);
    }
  }

  return (
    <FadeInUp>
      <div className="max-w-xl mx-auto text-center">
        {!submitted ? (
          <div>
            <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-3">
              <input
                type="email"
                value={email}
                onChange={(e) => {
                  setEmail(e.target.value);
                  if (error) setError('');
                }}
                placeholder={t('placeholder')}
                aria-label="Email address"
                className="flex-1 bg-surface-1 border border-border rounded-full px-5 py-3.5 text-text-primary placeholder:text-text-muted focus:outline-none focus:border-brand-sage transition-colors text-sm"
                autoFocus
              />
              <button
                type="submit"
                className="bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3.5 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98] flex items-center justify-center gap-2 text-sm shrink-0"
              >
                {loading ? t('joining') : t('joinWaitlist')}
                {!loading && <ArrowRight className="w-4 h-4" />}
              </button>
            </form>

            {error && <p role="alert" className="text-sm text-status-alert mt-3">{error}</p>}

            {/* Checkmarks */}
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4 sm:gap-6 mt-6">
              {(['priority', 'feedback', 'founding'] as const).map((key) => (
                <div key={key} className="flex items-center gap-2 text-sm text-text-secondary">
                  <Check className="w-4 h-4 text-brand-sage shrink-0" />
                  {t(`checks.${key}`)}
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className="py-4 form-state-enter">
            <div className="w-12 h-12 rounded-full bg-status-safe/10 border border-status-safe/20 flex items-center justify-center mx-auto mb-4">
              <Check className="w-6 h-6 text-status-safe" />
            </div>
            <h3 className="text-xl font-bold text-text-primary">{t('successTitle')}</h3>
            <p className="text-text-secondary mt-2 leading-relaxed">
              {t('successDesc', { email })}
            </p>
          </div>
        )}

        {/* Note */}
        <div className="mt-10 flex items-center justify-center gap-2 text-sm text-text-tertiary">
          <Users className="w-4 h-4" />
          <span>{t('betaNote')}</span>
        </div>
      </div>
    </FadeInUp>
  );
}
