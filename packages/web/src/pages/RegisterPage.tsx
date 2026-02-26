import { useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { useLanguage } from '../context/LanguageContext';

export default function RegisterPage() {
  const { t } = useLanguage();
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [status, setStatus] = useState<'idle' | 'loading' | 'error'>('idle');
  const [error, setError] = useState('');

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    setStatus('loading');
    setError('');

    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, name, password }),
      });
      const data = await res.json();

      if (data.ok) {
        localStorage.setItem('panguard_token', data.data.token);
        window.location.href = '/dashboard';
      } else {
        setStatus('error');
        setError(data.error ?? t('Registration failed.', '\u8A3B\u518A\u5931\u6557\u3002'));
      }
    } catch {
      setStatus('error');
      setError(t('Network error.', '\u7DB2\u8DEF\u932F\u8AA4\u3002'));
    }
  }, [email, name, password, t]);

  return (
    <div className="flex min-h-[60vh] items-center justify-center px-4">
      <div className="w-full max-w-md rounded-xl border border-brand-border bg-brand-card p-8">
        <h2 className="mb-6 text-center text-2xl font-bold text-brand-text">
          {t('Create Account', '\u5EFA\u7ACB\u5E33\u865F')}
        </h2>

        {/* Google OAuth button */}
        <a
          href="/api/auth/google"
          className="mb-4 flex w-full items-center justify-center gap-3 rounded-lg border border-brand-border bg-brand-dark px-4 py-3 text-brand-text transition hover:border-brand-cyan"
        >
          <svg width="18" height="18" viewBox="0 0 48 48">
            <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>
            <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>
            <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/>
            <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
          </svg>
          {t('Sign up with Google', '\u4F7F\u7528 Google \u8A3B\u518A')}
        </a>

        <div className="mb-4 flex items-center gap-3">
          <div className="h-px flex-1 bg-brand-border" />
          <span className="text-sm text-brand-muted">{t('or', '\u6216')}</span>
          <div className="h-px flex-1 bg-brand-border" />
        </div>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={t('Your name', '\u59D3\u540D')}
            required
            className="w-full rounded-lg border border-brand-border bg-brand-dark px-4 py-3 text-brand-text placeholder-brand-muted outline-none transition focus:border-brand-cyan"
          />
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
            placeholder={t('Password (min 8 characters)', '\u5BC6\u78BC\uFF08\u81F3\u5C11 8 \u5B57\u5143\uFF09')}
            required
            minLength={8}
            className="w-full rounded-lg border border-brand-border bg-brand-dark px-4 py-3 text-brand-text placeholder-brand-muted outline-none transition focus:border-brand-cyan"
          />
          <button
            type="submit"
            disabled={status === 'loading'}
            className="btn-primary w-full py-3 text-base disabled:opacity-50"
          >
            {status === 'loading'
              ? t('Creating account...', '\u5EFA\u7ACB\u4E2D...')
              : t('Create Account', '\u5EFA\u7ACB\u5E33\u865F')}
          </button>
        </form>

        {status === 'error' && (
          <p className="mt-4 text-center text-sm text-red-400">{error}</p>
        )}

        <p className="mt-6 text-center text-sm text-brand-muted">
          {t('Already have an account?', '\u5DF2\u6709\u5E33\u865F\uFF1F')}{' '}
          <Link to="/login" className="text-brand-cyan hover:underline">
            {t('Sign In', '\u767B\u5165')}
          </Link>
        </p>
      </div>
    </div>
  );
}
