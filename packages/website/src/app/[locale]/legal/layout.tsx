'use client';

import { Link, usePathname } from '@/navigation';
import { useTranslations } from 'next-intl';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';

export default function LegalLayout({ children }: { children: React.ReactNode }) {
  const t = useTranslations('legalNav');
  const pathname = usePathname();

  const legalPages = [
    { href: '/legal/privacy', label: t('privacy') },
    { href: '/legal/terms', label: t('terms') },
    { href: '/legal/dpa', label: t('dpa') },
    { href: '/legal/cookies', label: t('cookies') },
    { href: '/legal/acceptable-use', label: t('acceptableUse') },
    { href: '/legal/responsible-disclosure', label: t('responsibleDisclosure') },
    { href: '/legal/sla', label: t('sla') },
    { href: '/legal/security', label: t('securityWhitepaper') },
  ];

  return (
    <div className="min-h-screen bg-surface-0 flex flex-col">
      <NavBar />
      <div className="flex-1 max-w-4xl mx-auto w-full px-6 py-12 lg:py-16">
        <div className="flex gap-12">
          {/* Sidebar TOC */}
          <aside className="hidden lg:block w-56 shrink-0">
            <nav className="sticky top-24">
              <p className="text-xs uppercase tracking-wider text-text-muted font-semibold mb-4">
                {t('heading')}
              </p>
              <ul className="space-y-1">
                {legalPages.map((page) => (
                  <li key={page.href}>
                    <Link
                      href={page.href}
                      className={`block text-sm py-1.5 px-3 rounded-md transition-colors duration-150 ${
                        pathname === page.href
                          ? 'text-text-primary bg-surface-2 font-medium'
                          : 'text-text-tertiary hover:text-text-secondary hover:bg-surface-1'
                      }`}
                    >
                      {page.label}
                    </Link>
                  </li>
                ))}
              </ul>
            </nav>
          </aside>

          {/* Main content */}
          <main className="flex-1 min-w-0 max-w-prose">{children}</main>
        </div>
      </div>
      <Footer />
    </div>
  );
}
