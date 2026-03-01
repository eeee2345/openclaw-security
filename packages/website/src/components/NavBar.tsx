'use client';
import { useState, useEffect, useRef } from 'react';
import { useLocale, useTranslations } from 'next-intl';
import { Menu, X, User, LogOut, ChevronDown } from 'lucide-react';
import { Link, usePathname, useRouter } from '@/navigation';
import type { Locale } from '@/navigation';
import BrandLogo from './ui/BrandLogo';
import { useAuth } from '@/lib/auth';

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

/* ─── Desktop Dropdown ─── */
type DropdownItem = { label: string; desc: string; href: string };

function NavDropdown({ label, items }: { label: string; items: DropdownItem[] }) {
  const [open, setOpen] = useState(false);
  const closeTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const handleEnter = () => {
    if (closeTimer.current) clearTimeout(closeTimer.current);
    setOpen(true);
  };

  const handleLeave = () => {
    closeTimer.current = setTimeout(() => setOpen(false), 150);
  };

  return (
    <div className="relative" onMouseEnter={handleEnter} onMouseLeave={handleLeave}>
      <button className="flex items-center gap-1 px-3 py-2 text-sm text-text-secondary hover:text-text-primary transition-colors">
        {label}
        <ChevronDown className={`w-3.5 h-3.5 transition-transform duration-200 ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && (
        <div className="absolute top-full left-0 pt-2 z-50">
          <div className="bg-surface-1 border border-border rounded-xl shadow-xl p-1.5 min-w-[260px]">
            {items.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                className="flex flex-col px-4 py-2.5 rounded-lg hover:bg-surface-2 transition-colors group"
                onClick={() => setOpen(false)}
              >
                <span className="text-sm font-semibold text-text-primary group-hover:text-brand-sage transition-colors">
                  {item.label}
                </span>
                <span className="text-xs text-text-muted mt-0.5">{item.desc}</span>
              </Link>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default function NavBar() {
  const t = useTranslations('nav');
  const { user, loading: authLoading, logout } = useAuth();
  const navRouter = useRouter();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [mobileProductsOpen, setMobileProductsOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  const productItems: DropdownItem[] = [
    { label: t('productLinks.overview'), desc: t('productLinks.overviewDesc'), href: '/product' },
    { label: t('productLinks.scan'), desc: t('productLinks.scanDesc'), href: '/product/scan' },
    { label: t('productLinks.guard'), desc: t('productLinks.guardDesc'), href: '/product/guard' },
    { label: t('productLinks.chat'), desc: t('productLinks.chatDesc'), href: '/product/chat' },
    { label: t('productLinks.trap'), desc: t('productLinks.trapDesc'), href: '/product/trap' },
    { label: t('productLinks.report'), desc: t('productLinks.reportDesc'), href: '/product/report' },
  ];

  const topLinks = [
    { label: t('howItWorks'), href: '/how-it-works' },
    { label: t('threatCloud'), href: '/threat-cloud' },
    { label: t('pricing'), href: '/pricing' },
    { label: t('about'), href: '/about' },
    { label: t('blog'), href: '/blog' },
  ];

  return (
    <nav
      aria-label="Main navigation"
      className={`sticky top-0 z-50 transition-all duration-300 ${
        scrolled
          ? 'bg-surface-0/80 backdrop-blur-xl border-b border-border'
          : 'bg-transparent border-b border-transparent'
      }`}
    >
      {/* Brand accent line */}
      <div className="h-[2px] bg-gradient-to-r from-transparent via-brand-sage/60 to-transparent" />

      <div className="h-16 flex items-center justify-between px-6 lg:px-[120px]">
        <Logo />

        {/* Desktop nav */}
        <div className="hidden lg:flex items-center gap-0.5">
          <NavDropdown label={t('product')} items={productItems} />
          {topLinks.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              className="px-3 py-2 text-sm text-text-secondary hover:text-text-primary transition-colors"
            >
              {link.label}
            </Link>
          ))}
        </div>

        {/* Desktop CTA + Locale Switcher */}
        <div className="hidden lg:flex items-center gap-4">
          <LocaleSwitcher />
          {!authLoading && user ? (
            <>
              <Link
                href="/dashboard"
                className="flex items-center gap-1.5 px-3 py-2 text-sm text-text-secondary hover:text-text-primary transition-colors"
              >
                <User className="w-4 h-4" />
                Dashboard
              </Link>
              <button
                onClick={() => {
                  void logout();
                  navRouter.push('/');
                }}
                className="text-text-tertiary hover:text-text-secondary transition-colors"
                aria-label="Log out"
              >
                <LogOut className="w-4 h-4" />
              </button>
            </>
          ) : (
            <>
              <Link
                href="/login"
                className="px-3 py-2 text-sm text-text-secondary hover:text-text-primary transition-colors"
              >
                {t('login')}
              </Link>
              <Link
                href="/register"
                className="bg-brand-sage text-surface-0 font-semibold text-sm rounded-full px-5 py-2.5 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
              >
                {t('getStarted')}
              </Link>
            </>
          )}
        </div>

        {/* Mobile hamburger */}
        <button
          className="lg:hidden p-2 -mr-2 text-text-secondary"
          onClick={() => setMobileOpen(!mobileOpen)}
          aria-label="Toggle menu"
        >
          {mobileOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
        </button>
      </div>

      {/* Mobile menu */}
      {mobileOpen && (
        <div role="dialog" aria-label="Navigation menu" className="fixed inset-0 top-[66px] bg-surface-0/98 backdrop-blur-xl z-40 overflow-y-auto lg:hidden">
          <div className="p-6 space-y-1">
            <div className="flex justify-center mb-4">
              <LocaleSwitcher />
            </div>

            {/* Products accordion */}
            <button
              onClick={() => setMobileProductsOpen(!mobileProductsOpen)}
              className="flex items-center justify-between w-full py-3 text-sm text-text-secondary hover:text-text-primary"
              aria-expanded={mobileProductsOpen}
            >
              {t('product')}
              <ChevronDown className={`w-4 h-4 transition-transform duration-200 ${mobileProductsOpen ? 'rotate-180' : ''}`} />
            </button>
            {mobileProductsOpen && (
              <div className="pl-4 pb-2 space-y-1">
                {productItems.map((item) => (
                  <Link
                    key={item.href}
                    href={item.href}
                    className="block py-3 text-sm text-text-tertiary hover:text-text-primary"
                    onClick={() => setMobileOpen(false)}
                  >
                    {item.label}
                  </Link>
                ))}
              </div>
            )}

            {/* Top links */}
            {topLinks.map((link) => (
              <Link
                key={link.href}
                href={link.href}
                className="block py-3 text-sm text-text-secondary hover:text-text-primary"
                onClick={() => setMobileOpen(false)}
              >
                {link.label}
              </Link>
            ))}

            <a
              href="https://github.com/panguard-ai/panguard-ai"
              target="_blank"
              rel="noopener noreferrer"
              className="block py-3 text-sm text-text-secondary hover:text-text-primary"
              onClick={() => setMobileOpen(false)}
            >
              GitHub
            </a>

            <div className="pt-4 border-t border-border space-y-3">
              {!authLoading && user ? (
                <>
                  <Link
                    href="/dashboard"
                    className="block text-center bg-brand-sage text-surface-0 font-semibold text-sm rounded-full px-5 py-3"
                    onClick={() => setMobileOpen(false)}
                  >
                    Dashboard
                  </Link>
                  <button
                    onClick={() => {
                      void logout();
                      navRouter.push('/');
                      setMobileOpen(false);
                    }}
                    className="block w-full text-center text-sm text-text-secondary py-2"
                  >
                    Log out
                  </button>
                </>
              ) : (
                <>
                  <Link
                    href="/login"
                    className="block text-center border border-border text-text-secondary font-semibold text-sm rounded-full px-5 py-3"
                    onClick={() => setMobileOpen(false)}
                  >
                    {t('login')}
                  </Link>
                  <Link
                    href="/register"
                    className="block text-center bg-brand-sage text-surface-0 font-semibold text-sm rounded-full px-5 py-3"
                    onClick={() => setMobileOpen(false)}
                  >
                    {t('getStarted')}
                  </Link>
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </nav>
  );
}
