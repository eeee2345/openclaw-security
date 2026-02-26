import { useState, useEffect, useCallback } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { getNavItems } from '@openclaw/panguard-web';
import { useLanguage } from '../context/LanguageContext';

/** Read auth state from localStorage */
function getAuthState(): { token: string; email: string } | null {
  const token = localStorage.getItem('panguard_token');
  const email = localStorage.getItem('panguard_email');
  if (token && email) return { token, email };
  return null;
}

export default function Navbar() {
  const { language, toggleLanguage, t } = useLanguage();
  const location = useLocation();
  const navigate = useNavigate();
  const navItems = getNavItems();
  const [auth, setAuth] = useState(getAuthState);

  // Re-check auth on route change (e.g. after login redirect)
  useEffect(() => {
    setAuth(getAuthState());
  }, [location.pathname]);

  const handleLogout = useCallback(async () => {
    const token = localStorage.getItem('panguard_token');
    if (token) {
      try {
        await fetch('/api/auth/logout', {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}` },
        });
      } catch { /* ignore */ }
    }
    localStorage.removeItem('panguard_token');
    localStorage.removeItem('panguard_email');
    setAuth(null);
    navigate('/');
  }, [navigate]);

  return (
    <nav className="sticky top-0 z-50 border-b border-brand-border bg-brand-dark/95 backdrop-blur-sm">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-4 sm:px-6">
        <Link to="/" className="flex items-center gap-2 text-xl font-bold">
          <span className="text-brand-cyan">&gt;_</span>
          <span>Panguard AI</span>
        </Link>

        <div className="hidden items-center gap-6 md:flex">
          {navItems.map((page) => (
            <Link
              key={page.id}
              to={page.path}
              className={`text-sm transition-colors ${
                location.pathname === page.path
                  ? 'text-brand-cyan'
                  : 'text-brand-muted hover:text-brand-text'
              }`}
            >
              {language === 'en' ? page.titleEn : page.titleZh}
            </Link>
          ))}
        </div>

        <div className="flex items-center gap-3">
          <Link
            to="/dashboard"
            className="rounded-md border border-brand-cyan/30 bg-brand-cyan/10 px-3 py-1.5 text-xs text-brand-cyan transition-colors hover:bg-brand-cyan/20"
          >
            Dashboard
          </Link>
          <button
            onClick={toggleLanguage}
            className="rounded-md border border-brand-border px-3 py-1.5 text-xs text-brand-muted transition-colors hover:border-brand-cyan hover:text-brand-cyan"
          >
            {language === 'zh-TW' ? 'EN' : 'ZH'}
          </button>

          {auth ? (
            <>
              <span className="text-xs text-brand-muted">{auth.email}</span>
              <button
                onClick={handleLogout}
                className="rounded-md border border-brand-border px-3 py-1.5 text-xs text-brand-muted transition-colors hover:border-red-500 hover:text-red-400"
              >
                {t('Logout', '登出')}
              </button>
            </>
          ) : (
            <>
              <Link
                to="/login"
                className="rounded-md border border-brand-border px-3 py-1.5 text-xs text-brand-muted transition-colors hover:border-brand-cyan hover:text-brand-cyan"
              >
                {t('Login', '登入')}
              </Link>
              <Link to="/register" className="btn-primary text-sm">
                {t('Sign Up', '註冊')}
              </Link>
            </>
          )}
        </div>
      </div>
    </nav>
  );
}
