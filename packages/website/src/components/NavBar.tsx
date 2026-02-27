'use client';
import { useState, useEffect } from 'react';
import { useLocale, useTranslations } from 'next-intl';
import { Menu, X } from 'lucide-react';
import { Link, usePathname, useRouter } from '@/navigation';
import type { Locale } from '@/navigation';
import BrandLogo from './ui/BrandLogo';

/* ─── Locale Switcher ─── */
function LocaleSwitcher() {
  const locale = useLocale() as Locale;
  const pathname = usePathname();
  const router = useRouter();

  const switchTo = (target: Locale) => {
    router.replace(pathname, { locale: target });
  };

  return (
    <div className="inline-flex items-center bg-surface-1 border border-border rounded-full p-0.5">
      <button
        onClick={() => switchTo('en')}
        className={`relative px-3 py-1 text-xs font-medium rounded-full transition-all duration-300 ${
          locale === 'en'
            ? 'text-surface-0 bg-brand-sage'
            : 'text-text-tertiary hover:text-text-secondary'
        }`}
      >
        EN
      </button>
      <button
        onClick={() => switchTo('zh')}
        className={`relative px-3 py-1 text-xs font-medium rounded-full transition-all duration-300 ${
          locale === 'zh'
            ? 'text-surface-0 bg-brand-sage'
            : 'text-text-tertiary hover:text-text-secondary'
        }`}
      >
        中文
      </button>
    </div>
  );
}

/* ─── Logo ─── */
function Logo() {
  return (
    <Link href="/" className="flex items-center gap-1.5 shrink-0">
      <span className="font-semibold tracking-wider text-text-primary text-[15px]">PANGUARD</span>
      <BrandLogo size={22} className="text-brand-sage" />
      <span className="font-semibold tracking-wider text-text-primary text-[15px]">AI</span>
    </Link>
  );
}

export default function NavBar() {
  const t = useTranslations('nav');
  const [mobileOpen, setMobileOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  const navLinks = [
    { label: t('docs'), href: '/docs' },
    { label: t('useCases'), href: '/#use-cases' },
    { label: t('pricing'), href: '/pricing' },
  ];

  return (
    <nav
      className={`sticky top-0 z-50 h-16 flex items-center justify-between px-6 lg:px-[120px] transition-all duration-300 ${
        scrolled
          ? 'bg-surface-0/80 backdrop-blur-xl border-b border-border'
          : 'bg-transparent border-b border-transparent'
      }`}
    >
      <Logo />

      {/* Desktop nav */}
      <div className="hidden lg:flex items-center gap-1">
        {navLinks.map((link) =>
          link.href.startsWith('/#') ? (
            <a
              key={link.href}
              href={link.href}
              className="px-3 py-2 text-sm text-text-secondary hover:text-text-primary transition-colors"
            >
              {link.label}
            </a>
          ) : (
            <Link
              key={link.href}
              href={link.href}
              className="px-3 py-2 text-sm text-text-secondary hover:text-text-primary transition-colors"
            >
              {link.label}
            </Link>
          )
        )}
        <a
          href="https://github.com/panguard-ai/panguard-ai"
          target="_blank"
          rel="noopener noreferrer"
          className="px-3 py-2 text-sm text-text-secondary hover:text-text-primary transition-colors"
        >
          GitHub
        </a>
      </div>

      {/* Desktop CTA + Locale Switcher */}
      <div className="hidden lg:flex items-center gap-4">
        <LocaleSwitcher />
        <Link
          href="/early-access"
          className="bg-brand-sage text-surface-0 font-semibold text-sm rounded-full px-5 py-2.5 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
        >
          {t('getStarted')}
        </Link>
      </div>

      {/* Mobile hamburger */}
      <button
        className="lg:hidden text-text-secondary"
        onClick={() => setMobileOpen(!mobileOpen)}
        aria-label="Toggle menu"
      >
        {mobileOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
      </button>

      {/* Mobile menu */}
      {mobileOpen && (
        <div className="fixed inset-0 top-16 bg-surface-0/98 backdrop-blur-xl z-40 overflow-y-auto lg:hidden">
          <div className="p-6 space-y-4">
            <div className="flex justify-center">
              <LocaleSwitcher />
            </div>
            {navLinks.map((link) =>
              link.href.startsWith('/#') ? (
                <a
                  key={link.href}
                  href={link.href}
                  className="block py-2 text-sm text-text-secondary hover:text-text-primary"
                  onClick={() => setMobileOpen(false)}
                >
                  {link.label}
                </a>
              ) : (
                <Link
                  key={link.href}
                  href={link.href}
                  className="block py-2 text-sm text-text-secondary hover:text-text-primary"
                  onClick={() => setMobileOpen(false)}
                >
                  {link.label}
                </Link>
              )
            )}
            <a
              href="https://github.com/panguard-ai/panguard-ai"
              target="_blank"
              rel="noopener noreferrer"
              className="block py-2 text-sm text-text-secondary hover:text-text-primary"
              onClick={() => setMobileOpen(false)}
            >
              GitHub
            </a>
            <div className="pt-4 border-t border-border">
              <Link
                href="/early-access"
                className="block text-center bg-brand-sage text-surface-0 font-semibold text-sm rounded-full px-5 py-3"
                onClick={() => setMobileOpen(false)}
              >
                {t('getStarted')}
              </Link>
            </div>
          </div>
        </div>
      )}
    </nav>
  );
}
