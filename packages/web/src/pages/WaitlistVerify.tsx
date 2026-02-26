import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useLanguage } from '../context/LanguageContext';

export default function WaitlistVerify() {
  const { token } = useParams<{ token: string }>();
  const { t } = useLanguage();
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading');
  const [message, setMessage] = useState('');

  useEffect(() => {
    if (!token) {
      setStatus('error');
      setMessage(t('Invalid verification link.', '\u7121\u6548\u7684\u9A57\u8B49\u9023\u7D50\u3002'));
      return;
    }

    fetch(`/api/waitlist/verify/${token}`)
      .then((res) => res.json())
      .then((data) => {
        if (data.ok) {
          setStatus('success');
          setMessage(t('Email verified successfully!', 'Email \u9A57\u8B49\u6210\u529F\uFF01'));
        } else {
          setStatus('error');
          setMessage(data.error ?? t('Verification failed.', '\u9A57\u8B49\u5931\u6557\u3002'));
        }
      })
      .catch(() => {
        setStatus('error');
        setMessage(t('Network error.', '\u7DB2\u8DEF\u932F\u8AA4\u3002'));
      });
  }, [token, t]);

  return (
    <div className="flex min-h-[60vh] items-center justify-center px-4">
      <div className="w-full max-w-md rounded-xl border border-brand-border bg-brand-card p-8 text-center">
        {status === 'loading' && (
          <p className="text-brand-muted">{t('Verifying...', '\u9A57\u8B49\u4E2D...')}</p>
        )}
        {status === 'success' && (
          <>
            <h2 className="mb-4 text-2xl font-bold text-brand-cyan">
              {t('Verified!', '\u9A57\u8B49\u6210\u529F\uFF01')}
            </h2>
            <p className="mb-6 text-brand-muted">{message}</p>
            <Link to="/" className="btn-primary">
              {t('Back to Home', '\u56DE\u5230\u9996\u9801')}
            </Link>
          </>
        )}
        {status === 'error' && (
          <>
            <h2 className="mb-4 text-2xl font-bold text-red-400">
              {t('Verification Failed', '\u9A57\u8B49\u5931\u6557')}
            </h2>
            <p className="mb-6 text-brand-muted">{message}</p>
            <Link to="/" className="btn-secondary">
              {t('Back to Home', '\u56DE\u5230\u9996\u9801')}
            </Link>
          </>
        )}
      </div>
    </div>
  );
}
