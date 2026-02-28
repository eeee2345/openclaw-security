/**
 * Panguard Admin - Shared Utilities
 * Provides: auth, API helpers, formatting, navigation, pagination, toast
 */
window.PG = (() => {
  const API = window.location.origin;

  // ── Auth ─────────────────────────────────────────────────────────

  function getToken() {
    return localStorage.getItem('panguard_admin_token');
  }

  function getUser() {
    try { return JSON.parse(localStorage.getItem('panguard_admin_user') || '{}'); }
    catch { return {}; }
  }

  function logout() {
    const token = getToken();
    if (token) {
      fetch(`${API}/api/auth/logout`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` },
      }).catch(() => { /* best-effort session invalidation */ });
    }
    localStorage.removeItem('panguard_admin_token');
    localStorage.removeItem('panguard_admin_user');
    window.location.href = '/admin/login';
  }

  function requireAuth() {
    if (!getToken()) {
      window.location.href = '/admin/login';
      return false;
    }
    return true;
  }

  // ── API ──────────────────────────────────────────────────────────

  async function apiFetch(path) {
    const res = await fetch(`${API}${path}`, {
      headers: { 'Authorization': `Bearer ${getToken()}` },
    });
    if (res.status === 401 || res.status === 403) { logout(); return null; }
    return res.json();
  }

  async function apiPost(path, body) {
    const res = await fetch(`${API}${path}`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${getToken()}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (res.status === 401 || res.status === 403) { logout(); return null; }
    return res.json();
  }

  async function apiPatch(path, body) {
    const res = await fetch(`${API}${path}`, {
      method: 'PATCH',
      headers: { 'Authorization': `Bearer ${getToken()}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (res.status === 401 || res.status === 403) { logout(); return null; }
    return res.json();
  }

  async function apiDelete(path) {
    const res = await fetch(`${API}${path}`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${getToken()}` },
    });
    if (res.status === 401 || res.status === 403) { logout(); return null; }
    return res.json();
  }

  // ── Formatting ───────────────────────────────────────────────────

  function escapeHtml(s) {
    const d = document.createElement('div');
    d.textContent = s || '';
    return d.innerHTML;
  }

  function formatDate(d) {
    if (!d) return '-';
    return new Date(d + 'Z').toLocaleDateString('en-US', {
      month: 'short', day: 'numeric', year: 'numeric',
    });
  }

  function formatRelativeTime(d) {
    if (!d) return '-';
    const now = Date.now();
    const then = new Date(d + 'Z').getTime();
    const diff = now - then;

    if (diff < 0) return 'just now';
    if (diff < 60_000) return 'just now';
    if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
    if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
    if (diff < 604_800_000) return `${Math.floor(diff / 86_400_000)}d ago`;
    return formatDate(d);
  }

  function formatNumber(n) {
    if (n == null) return '0';
    return n.toLocaleString('en-US');
  }

  // ── Navigation ───────────────────────────────────────────────────

  const NAV_ITEMS = [
    { id: 'dashboard', label: 'Dashboard', href: '/admin', icon: 'barChart' },
    { id: 'users', label: 'Users', href: '/admin/users', icon: 'users' },
    { id: 'waitlist', label: 'Waitlist', href: '/admin/waitlist', icon: 'list' },
    { id: 'sessions', label: 'Sessions', href: '/admin/sessions', icon: 'key' },
    { id: 'audit', label: 'Audit Log', href: '/admin/audit', icon: 'fileText' },
    { id: 'usage', label: 'Usage', href: '/admin/usage', icon: 'activity' },
  ];

  function renderNav(activePage) {
    const user = getUser();
    const navLinks = NAV_ITEMS.map(item => {
      const isActive = item.id === activePage;
      const cls = isActive
        ? 'bg-sage/10 text-sage'
        : 'text-text-tertiary hover:text-text-secondary hover:bg-surface-2/50';
      return `<a href="${item.href}" class="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-md transition-colors ${cls}">
        ${Icons[item.icon](14)}
        <span>${item.label}</span>
      </a>`;
    }).join('');

    return `<nav class="border-b border-border px-6 py-3 flex items-center justify-between">
      <div class="flex items-center gap-4">
        <a href="/admin" class="flex items-center gap-2">
          ${Icons.shieldCheck(22, '#8B9A8E')}
          <span class="font-bold text-sage tracking-wide">PANGUARD</span>
        </a>
        <span class="text-text-muted text-[10px] uppercase tracking-widest">Admin</span>
        <div class="flex gap-1 ml-2">${navLinks}</div>
      </div>
      <div class="flex items-center gap-3">
        <span class="text-xs text-text-tertiary">${escapeHtml(user.name || user.email || '')}</span>
        <button onclick="PG.logout()" class="flex items-center gap-1 text-xs text-text-muted hover:text-danger transition-colors">
          ${Icons.logOut(14)}
          <span>Logout</span>
        </button>
      </div>
    </nav>`;
  }

  // ── Pagination ───────────────────────────────────────────────────

  function paginate(items, page, perPage) {
    const totalPages = Math.ceil(items.length / perPage) || 1;
    const safePage = Math.max(1, Math.min(page, totalPages));
    const start = (safePage - 1) * perPage;
    return {
      items: items.slice(start, start + perPage),
      page: safePage,
      totalPages,
      total: items.length,
      start: start + 1,
      end: Math.min(start + perPage, items.length),
    };
  }

  function renderPagination(p, onPageChange) {
    if (p.totalPages <= 1) return '';

    let buttons = '';
    // Prev
    buttons += `<button ${p.page <= 1 ? 'disabled' : ''} data-page="${p.page - 1}"
      class="px-2 py-1 text-xs rounded border border-border ${p.page <= 1 ? 'text-text-muted cursor-not-allowed' : 'text-text-secondary hover:border-sage hover:text-sage'}">${Icons.chevronLeft(14)}</button>`;

    // Page numbers
    const maxVisible = 5;
    let startPage = Math.max(1, p.page - Math.floor(maxVisible / 2));
    let endPage = Math.min(p.totalPages, startPage + maxVisible - 1);
    if (endPage - startPage < maxVisible - 1) startPage = Math.max(1, endPage - maxVisible + 1);

    if (startPage > 1) buttons += `<button data-page="1" class="px-2 py-1 text-xs rounded border border-border text-text-secondary hover:border-sage">1</button>`;
    if (startPage > 2) buttons += `<span class="text-text-muted text-xs px-1">...</span>`;

    for (let i = startPage; i <= endPage; i++) {
      const isActive = i === p.page;
      buttons += `<button data-page="${i}" class="px-2 py-1 text-xs rounded border ${isActive ? 'border-sage text-sage bg-sage/10' : 'border-border text-text-secondary hover:border-sage'}">${i}</button>`;
    }

    if (endPage < p.totalPages - 1) buttons += `<span class="text-text-muted text-xs px-1">...</span>`;
    if (endPage < p.totalPages) buttons += `<button data-page="${p.totalPages}" class="px-2 py-1 text-xs rounded border border-border text-text-secondary hover:border-sage">${p.totalPages}</button>`;

    // Next
    buttons += `<button ${p.page >= p.totalPages ? 'disabled' : ''} data-page="${p.page + 1}"
      class="px-2 py-1 text-xs rounded border border-border ${p.page >= p.totalPages ? 'text-text-muted cursor-not-allowed' : 'text-text-secondary hover:border-sage hover:text-sage'}">${Icons.chevronRight(14)}</button>`;

    const id = 'pg-pagination-' + Math.random().toString(36).slice(2, 8);
    setTimeout(() => {
      const el = document.getElementById(id);
      if (!el) return;
      el.querySelectorAll('button[data-page]').forEach(btn => {
        btn.addEventListener('click', () => {
          const pg = parseInt(btn.dataset.page);
          if (pg >= 1 && pg <= p.totalPages) onPageChange(pg);
        });
      });
    }, 0);

    return `<div id="${id}" class="flex items-center justify-between mt-4">
      <span class="text-xs text-text-tertiary">Showing ${p.start}-${p.end} of ${p.total}</span>
      <div class="flex items-center gap-1">${buttons}</div>
    </div>`;
  }

  // ── Toast ────────────────────────────────────────────────────────

  function showToast(message, type = 'info') {
    const colors = {
      success: 'border-safe/50 bg-safe/10 text-safe',
      error: 'border-danger/50 bg-danger/10 text-danger',
      warning: 'border-caution/50 bg-caution/10 text-caution',
      info: 'border-sage/50 bg-sage/10 text-sage',
    };
    const iconMap = {
      success: Icons.check(16),
      error: Icons.xMark(16),
      warning: Icons.activity(16),
      info: Icons.shieldCheck(16),
    };

    let container = document.getElementById('pg-toast-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'pg-toast-container';
      container.className = 'fixed top-4 right-4 z-50 flex flex-col gap-2';
      document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `flex items-center gap-2 px-4 py-2.5 rounded-lg border text-sm ${colors[type] || colors.info} shadow-lg transition-all duration-300 translate-x-full opacity-0`;
    toast.innerHTML = `${iconMap[type] || iconMap.info}<span>${escapeHtml(message)}</span>`;
    container.appendChild(toast);

    requestAnimationFrame(() => {
      toast.classList.remove('translate-x-full', 'opacity-0');
    });

    setTimeout(() => {
      toast.classList.add('translate-x-full', 'opacity-0');
      setTimeout(() => toast.remove(), 300);
    }, 3000);
  }

  // ── Skeleton ─────────────────────────────────────────────────────

  function skeleton(w, h) {
    return `<div class="animate-pulse bg-surface-2 rounded" style="width:${w};height:${h}"></div>`;
  }

  // ── Tailwind Config ──────────────────────────────────────────────

  const TAILWIND_CONFIG = {
    theme: {
      extend: {
        colors: {
          surface: { 0: '#1A1614', 1: '#1F1C19', 2: '#272320', 3: '#302B27' },
          border: '#2E2A27',
          sage: '#8B9A8E',
          'sage-light': '#A3B0A6',
          'text-primary': '#F5F1E8',
          'text-secondary': '#A09890',
          'text-tertiary': '#706860',
          'text-muted': '#4A4540',
          safe: '#2ED573',
          caution: '#FBBF24',
          danger: '#EF4444',
        }
      }
    }
  };

  // ── Status Badges ────────────────────────────────────────────────

  const STATUS_BADGE = {
    pending: 'bg-caution/10 text-caution border-caution/20',
    approved: 'bg-safe/10 text-safe border-safe/20',
    rejected: 'bg-danger/10 text-danger border-danger/20',
  };

  const TIER_COLORS = {
    free: 'text-text-secondary',
    solo: 'text-caution',
    starter: 'text-caution',
    pro: 'text-sage',
    team: 'text-sage',
    business: 'text-sage-light',
    enterprise: 'text-danger',
  };

  // ── CSV Export ───────────────────────────────────────────────────

  function generateCsv(columns, rows) {
    const header = columns.map(c => `"${c.label}"`).join(',');
    const lines = rows.map(row =>
      columns.map(c => {
        const val = row[c.key];
        if (val == null) return '""';
        const str = String(val).replace(/"/g, '""');
        return `"${str}"`;
      }).join(',')
    );
    return [header, ...lines].join('\n');
  }

  function downloadCsv(filename, csv) {
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  // ── Server-side Pagination ─────────────────────────────────────

  function renderServerPagination(page, perPage, total, onPageChange) {
    const totalPages = Math.ceil(total / perPage) || 1;
    const safePage = Math.max(1, Math.min(page, totalPages));
    const start = (safePage - 1) * perPage + 1;
    const end = Math.min(safePage * perPage, total);
    const p = { page: safePage, totalPages, total, start, end };
    return renderPagination(p, onPageChange);
  }

  // ── Exports ──────────────────────────────────────────────────────

  return {
    // Auth
    getToken, getUser, logout, requireAuth,
    // API
    apiFetch, apiPost, apiPatch, apiDelete,
    // Formatting
    escapeHtml, formatDate, formatRelativeTime, formatNumber,
    // Navigation
    renderNav, NAV_ITEMS,
    // Pagination
    paginate, renderPagination, renderServerPagination,
    // Toast
    showToast,
    // CSV
    generateCsv, downloadCsv,
    // Skeleton
    skeleton,
    // Config
    TAILWIND_CONFIG, STATUS_BADGE, TIER_COLORS,
  };
})();
