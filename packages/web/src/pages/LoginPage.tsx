import { useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { useLanguage } from '../context/LanguageContext';

export default function LoginPage() {
  const { t } = useLanguage();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [status, setStatus] = useState<'idle' | 'loading' | 'error'>('idle');
  const [error, setError] = useState('');

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    setStatus('loading');
    setError('');

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      const data = await res.json();

      if (data.ok) {
        localStorage.setItem('panguard_token', data.data.token);
        window.location.href = '/dashboard';
      } else {
        setStatus('error');
        setError(data.error ?? t('Login failed.', '\u767B\u5165\u5931\u6557\u3002'));
      }
    } catch {
      setStatus('error');
      setError(t('Network error.', '\u7DB2\u8DEF\u932F\u8AA4\u3002'));
    }
  }, [email, password, t]);

  return (
    <div className="flex min-h-[60vh] items-center justify-center px-4">
      <div className="w-full max-w-md rounded-xl border border-brand-border bg-brand-card p-8">
        <h2 className="mb-6 text-center text-2xl font-bold text-brand-text">
          {t('Sign In', '\u767B\u5165')}
        </h2>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder={t('Email', 'Email')}
            required
            className="w-full rounded-lg border border-brand-border bg-brand-dark px-4 py-3 text-brand-text placeholder-brand-muted outline-none transition focus:border-brand-cyan"
          />
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder={t('Password', '\u5BC6\u78BC')}
            required
            className="w-full rounded-lg border border-brand-border bg-brand-dark px-4 py-3 text-brand-text placeholder-brand-muted outline-none transition focus:border-brand-cyan"
          />
          <button
            type="submit"
            disabled={status === 'loading'}
            className="btn-primary w-full py-3 text-base disabled:opacity-50"
          >
            {status === 'loading'
              ? t('Signing in...', '\u767B\u5165\u4E2D...')
              : t('Sign In', '\u767B\u5165')}
          </button>
        </form>

        {status === 'error' && (
          <p className="mt-4 text-center text-sm text-red-400">{error}</p>
        )}

        <p className="mt-6 text-center text-sm text-brand-muted">
          {t("Don't have an account?", '\u9084\u6C92\u6709\u5E33\u865F\uFF1F')}{' '}
          <Link to="/register" className="text-brand-cyan hover:underline">
            {t('Register', '\u8A3B\u518A')}
          </Link>
        </p>
      </div>
    </div>
  );
}
