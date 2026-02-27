'use client';

import { Link } from '@/navigation';
import { ArrowLeft } from 'lucide-react';
import { ShieldIcon } from '@/components/ui/BrandIcons';
import { useTranslations } from 'next-intl';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';

export default function NotFound() {
  const t = useTranslations('notFound');

  return (
    <div className="min-h-screen bg-surface-0 flex flex-col">
      <NavBar />
      <main className="flex-1 flex items-center justify-center px-6 py-24">
        <div className="max-w-md w-full text-center">
          <div className="flex justify-center mb-6">
            <ShieldIcon className="w-12 h-12 text-text-muted" />
          </div>

          <p className="text-7xl font-bold text-text-muted mb-4">404</p>
          <h1 className="text-2xl font-bold text-text-primary mb-3">{t('title')}</h1>
          <p className="text-text-secondary text-sm leading-relaxed mb-8">{t('description')}</p>

          <Link
            href="/"
            className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold text-sm rounded-full px-6 py-3 hover:bg-brand-sage-light transition-colors active:scale-[0.98]"
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
