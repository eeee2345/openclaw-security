'use client';

import { useState } from 'react';
import { Link } from '@/navigation';
import { ArrowLeft } from 'lucide-react';
import { ShieldIcon } from '@/components/ui/BrandIcons';
import { useTranslations } from 'next-intl';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';

export default function ComingSoon({ title }: { title: string }) {
  const t = useTranslations('comingSoon');
  const [email, setEmail] = useState('');
  const [status, setStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle');

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!email) return;
    setStatus('loading');
    try {
      const res = await fetch('/api/waitlist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, source: title }),
      });
      if (!res.ok) throw new Error('Submit failed');
      setStatus('success');
    } catch {
      setStatus('error');
    }
  }

  return (
    <div className="min-h-screen bg-surface-0 flex flex-col">
      <NavBar />
      <main className="flex-1 flex items-center justify-center px-6 py-24">
        <div className="max-w-md w-full text-center">
          <div className="flex justify-center mb-8">
            <div className="relative">
              <ShieldIcon className="w-16 h-16 text-brand-sage animate-[breathe_3s_ease-in-out_infinite]" />
              <div className="absolute inset-0 w-16 h-16 rounded-full bg-brand-sage/10 animate-[breathe_3s_ease-in-out_infinite]" />
            </div>
          </div>

          <h1 className="text-3xl font-bold text-text-primary mb-2">{title}</h1>
          <p className="text-lg text-brand-sage font-medium mb-4">{t('badge')}</p>
          <p className="text-text-secondary text-sm leading-relaxed mb-8">{t('description')}</p>

          {status === 'success' ? (
            <p className="text-sm text-status-safe font-medium mb-8">{t('success')}</p>
          ) : (
            <form onSubmit={handleSubmit} className="flex gap-2 max-w-sm mx-auto mb-8">
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder={t('emailPlaceholder')}
                className="flex-1 bg-surface-1 border border-border rounded-full px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-brand-sage/50 focus:ring-1 focus:ring-brand-sage/25 transition-colors"
              />
              <button
                type="submit"
                disabled={status === 'loading'}
                className="bg-brand-sage text-surface-0 font-semibold text-sm rounded-full px-5 py-2.5 hover:bg-brand-sage-light transition-colors active:scale-[0.98] shrink-0 disabled:opacity-60"
              >
                {status === 'loading' ? '...' : t('notifyMe')}
              </button>
            </form>
          )}
          {status === 'error' && <p className="text-sm text-status-alert mb-4">{t('error')}</p>}

          <Link
            href="/"
            className="inline-flex items-center gap-2 text-sm text-text-tertiary hover:text-text-secondary transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            {t('backHome')}
          </Link>
        </div>
      </main>
      <Footer />
    </div>
  );
}
