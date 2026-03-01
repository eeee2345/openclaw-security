'use client';

import { useState, useEffect } from 'react';
import { useTranslations } from 'next-intl';
import { Link } from '@/navigation';

const COOKIE_NAME = 'pg_consent';

export default function CookieBanner() {
  const t = useTranslations('cookieBanner');
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const consent = document.cookie.split('; ').find((row) => row.startsWith(`${COOKIE_NAME}=`));
    if (!consent) {
      setVisible(true);
    }
  }, []);

  const setConsent = (value: 'all' | 'essential') => {
    const maxAge = 365 * 24 * 60 * 60; // 1 year
    document.cookie = `${COOKIE_NAME}=${value}; path=/; max-age=${maxAge}; SameSite=Lax`;
    setVisible(false);
  };

  if (!visible) return null;

  return (
    <div
      role="dialog"
      aria-label={t('ariaLabel')}
      className="fixed bottom-0 inset-x-0 z-50 p-4 sm:p-6"
    >
      <div className="max-w-2xl mx-auto bg-surface-1 border border-border rounded-2xl shadow-xl p-5 sm:p-6">
        <p className="text-sm text-text-secondary leading-relaxed">
          {t('message')}{' '}
          <Link
            href="/legal/cookies"
            className="text-brand-sage hover:text-brand-sage-light underline"
          >
            {t('learnMore')}
          </Link>
        </p>
        <div className="flex flex-wrap gap-3 mt-4">
          <button
            onClick={() => setConsent('all')}
            className="bg-brand-sage text-surface-0 font-semibold text-sm rounded-full px-5 py-2.5 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
          >
            {t('acceptAll')}
          </button>
          <button
            onClick={() => setConsent('essential')}
            className="border border-border text-text-secondary hover:text-text-primary hover:border-brand-sage font-semibold text-sm rounded-full px-5 py-2.5 transition-all duration-200"
          >
            {t('essentialOnly')}
          </button>
        </div>
      </div>
    </div>
  );
}
