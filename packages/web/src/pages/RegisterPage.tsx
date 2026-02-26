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
