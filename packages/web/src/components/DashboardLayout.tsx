import { Link, Outlet, useLocation } from 'react-router-dom';
import { useLanguage } from '../context/LanguageContext';
import { useAuth, hasTierAccess } from '../context/AuthContext';

interface NavItem {
  path: string;
  labelEn: string;
  labelZh: string;
  icon: string;
  /** Minimum tier required — undefined means all tiers */
  requiredTier?: string;
}

const navItems: NavItem[] = [
  { path: '/dashboard', labelEn: 'Overview', labelZh: '總覽', icon: 'grid' },
  { path: '/dashboard/scan', labelEn: 'Scan', labelZh: '掃描', icon: 'shield' },
  { path: '/dashboard/report', labelEn: 'Reports', labelZh: '報告', icon: 'file' },
  { path: '/dashboard/threat', labelEn: 'Threats', labelZh: '威脅', icon: 'alert', requiredTier: 'solo' },
  { path: '/dashboard/guard', labelEn: 'Guard', labelZh: '守護', icon: 'eye', requiredTier: 'solo' },
  { path: '/dashboard/trap', labelEn: 'Trap', labelZh: '蜜罐', icon: 'target', requiredTier: 'team' },
  { path: '/dashboard/chat', labelEn: 'Notify', labelZh: '通知', icon: 'bell', requiredTier: 'solo' },
];

const iconMap: Record<string, string> = {
  grid: 'M4 5a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1H5a1 1 0 01-1-1V5zm10 0a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1h-4a1 1 0 01-1-1V5zM4 15a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1H5a1 1 0 01-1-1v-4zm10 0a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1h-4a1 1 0 01-1-1v-4z',
  shield: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z',
  file: 'M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z M14 2v6h6 M16 13H8 M16 17H8 M10 9H8',
  alert: 'M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z M12 9v4 M12 17h.01',
  eye: 'M1 12s4-8 11-8 11 8-4 8-11 8-11-8z M12 9a3 3 0 100 6 3 3 0 000-6z',
  target: 'M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10z M12 18a6 6 0 100-12 6 6 0 000 12z M12 14a2 2 0 100-4 2 2 0 000 4z',
  bell: 'M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9 M13.73 21a2 2 0 01-3.46 0',
  lock: 'M19 11H5a2 2 0 00-2 2v7a2 2 0 002 2h14a2 2 0 002-2v-7a2 2 0 00-2-2z M7 11V7a5 5 0 0110 0v4',
};

export default function DashboardLayout() {
  const { language, toggleLanguage, t } = useLanguage();
  const { tier } = useAuth();
  const location = useLocation();

  return (
    <div className="flex min-h-screen bg-brand-dark">
      {/* Sidebar */}
      <aside className="flex w-60 flex-col border-r border-brand-border bg-brand-card/50">
        {/* Logo */}
        <div className="border-b border-brand-border p-4">
          <Link to="/" className="flex items-center gap-2 text-lg font-bold">
            <span className="text-brand-cyan">&gt;_</span>
            <span>Panguard AI</span>
          </Link>
          <div className="mt-1 text-xs text-brand-muted">
            {t('Security Dashboard', '安全儀表板')}
          </div>
        </div>

        {/* Nav items */}
        <nav className="flex-1 p-3">
          {navItems.map((item) => {
            const isActive = location.pathname === item.path;
            const locked = item.requiredTier ? !hasTierAccess(tier, item.requiredTier) : false;

            return (
              <Link
                key={item.path}
                to={item.path}
                className={`mb-1 flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition-colors ${
                  isActive
                    ? 'bg-brand-cyan/10 text-brand-cyan'
                    : locked
                      ? 'text-brand-muted/40 hover:bg-brand-card hover:text-brand-muted/60'
                      : 'text-brand-muted hover:bg-brand-card hover:text-brand-text'
                }`}
              >
                <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d={iconMap[item.icon] ?? ''} />
                </svg>
                <span className="flex-1">
                  {language === 'en' ? item.labelEn : item.labelZh}
                </span>
                {locked && (
                  <svg className="h-3 w-3 text-brand-muted/40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d={iconMap['lock']} />
                  </svg>
                )}
              </Link>
            );
          })}
        </nav>

        {/* Bottom controls */}
        <div className="border-t border-brand-border p-3">
          <Link
            to="/pricing"
            className="mb-2 block w-full rounded-lg bg-brand-cyan/10 px-3 py-2 text-center text-xs font-semibold text-brand-cyan transition-colors hover:bg-brand-cyan/20"
          >
            {t('Upgrade Plan', '升級方案')}
          </Link>
          <button
            onClick={toggleLanguage}
            className="w-full rounded-lg border border-brand-border px-3 py-2 text-xs text-brand-muted transition-colors hover:border-brand-cyan hover:text-brand-cyan"
          >
            {language === 'zh-TW' ? 'EN' : 'ZH'}
          </button>
          <Link
            to="/"
            className="mt-2 block text-center text-xs text-brand-muted hover:text-brand-cyan"
          >
            {t('Back to Website', '回到官網')}
          </Link>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}
