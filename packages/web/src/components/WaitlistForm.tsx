import { useState, useCallback } from 'react';
import { useLanguage } from '../context/LanguageContext';

interface WaitlistFormProps {
  className?: string;
}

export default function WaitlistForm({ className = '' }: WaitlistFormProps) {
  const { t } = useLanguage();
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [status, setStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle');
  const [message, setMessage] = useState('');

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim()) return;

    setStatus('loading');
    try {
      const res = await fetch('/api/waitlist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email.trim(), name: name.trim() || undefined }),
      });
      const data = await res.json();

      if (data.ok) {
        setStatus('success');
        setMessage(t('You\'re on the list! Check your email to verify.', '\u5DF2\u52A0\u5165\u767D\u540D\u55AE\uFF01\u8ACB\u67E5\u770B Email \u9A57\u8B49\u3002'));
        setEmail('');
        setName('');
      } else {
        setStatus('error');
        setMessage(data.error ?? t('Something went wrong.', '\u767C\u751F\u932F\u8AA4\uFF0C\u8ACB\u7A0D\u5F8C\u518D\u8A66\u3002'));
      }
    } catch {
      setStatus('error');
      setMessage(t('Network error. Please try again.', '\u7DB2\u8DEF\u932F\u8AA4\uFF0C\u8ACB\u7A0D\u5F8C\u518D\u8A66\u3002'));
    }
  }, [email, name, t]);

  if (status === 'success') {
    return (
      <div className={`rounded-lg border border-brand-cyan/30 bg-brand-card p-6 text-center ${className}`}>
        <p className="text-lg text-brand-cyan">{message}</p>
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit} className={`mx-auto max-w-md ${className}`}>
      <div className="flex flex-col gap-3">
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder={t('Your email address', '\u4F60\u7684 Email \u5730\u5740')}
          required
          className="w-full rounded-lg border border-brand-border bg-brand-card px-4 py-3 text-brand-text placeholder-brand-muted outline-none transition focus:border-brand-cyan"
        />
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder={t('Your name (optional)', '\u59D3\u540D\uFF08\u53EF\u9078\uFF09')}
          className="w-full rounded-lg border border-brand-border bg-brand-card px-4 py-3 text-brand-text placeholder-brand-muted outline-none transition focus:border-brand-cyan"
        />
        <button
          type="submit"
          disabled={status === 'loading'}
          className="btn-primary w-full py-3 text-base disabled:opacity-50"
        >
          {status === 'loading'
            ? t('Joining...', '\u52A0\u5165\u4E2D...')
            : t('Join the Waitlist', '\u52A0\u5165\u767D\u540D\u55AE')}
        </button>
      </div>
      {status === 'error' && (
        <p className="mt-3 text-center text-sm text-red-400">{message}</p>
      )}
    </form>
  );
}
