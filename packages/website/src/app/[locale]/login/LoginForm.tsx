'use client';

import { useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { Link } from '@/navigation';
import { useAuth } from '@/lib/auth';
import { useRouter } from '@/navigation';
import { Shield, Eye, EyeOff, Loader2 } from 'lucide-react';
import BrandLogo from '@/components/ui/BrandLogo';

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? '';

export default function LoginForm() {
  const { login } = useAuth();
  const router = useRouter();
  const searchParams = useSearchParams();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [needs2FA, setNeeds2FA] = useState(false);
  const [forgotSent, setForgotSent] = useState(false);

  const redirect = searchParams.get('redirect') ?? '/dashboard';

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setLoading(true);

    const result = await login(email, password, needs2FA ? totpCode : undefined);

    if (result.ok) {
      router.push(redirect as '/dashboard');
      return;
    }

    if (result.requiresTwoFactor) {
      setNeeds2FA(true);
      setLoading(false);
      return;
    }

    setError(result.error ?? 'Login failed');
    setLoading(false);
  }

  async function handleForgotPassword() {
    if (!email.trim()) {
      setError('Please enter your email first');
      return;
    }
    setLoading(true);
    try {
      await fetch(`${API_URL}/api/auth/forgot-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });
      setForgotSent(true);
      setError('');
    } catch {
      setError('Failed to send reset email');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-surface-0 flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <Link href="/" className="inline-flex items-center gap-2 mb-6">
            <BrandLogo size={28} className="text-brand-sage" />
            <span className="font-semibold tracking-wider text-text-primary text-lg">
              PANGUARD AI
            </span>
          </Link>
          <h1 className="text-2xl font-bold text-text-primary">
            {needs2FA ? 'Two-Factor Authentication' : 'Welcome back'}
          </h1>
          <p className="text-sm text-text-secondary mt-2">
            {needs2FA
              ? 'Enter the 6-digit code from your authenticator app'
              : 'Log in to your account'}
          </p>
        </div>

        <div className="bg-surface-1 border border-border rounded-xl p-6">
          {forgotSent ? (
            <div className="text-center py-4">
              <Shield className="w-10 h-10 text-brand-sage mx-auto mb-3" />
              <p className="text-text-primary font-medium">Check your email</p>
              <p className="text-sm text-text-secondary mt-1">
                If an account exists for {email}, we sent a password reset link.
              </p>
              <button
                onClick={() => setForgotSent(false)}
                className="text-brand-sage text-sm mt-4 hover:underline"
              >
                Back to login
              </button>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-4">
              {!needs2FA && (
                <>
                  <div>
                    <label className="block text-sm font-medium text-text-secondary mb-1.5">
                      Email
                    </label>
                    <input
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      required
                      autoComplete="email"
                      className="w-full bg-surface-0 border border-border rounded-lg px-4 py-2.5 text-text-primary placeholder-text-muted text-sm focus:outline-none focus:border-brand-sage transition-colors"
                      placeholder="you@example.com"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-text-secondary mb-1.5">
                      Password
                    </label>
                    <div className="relative">
                      <input
                        type={showPassword ? 'text' : 'password'}
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        required
                        autoComplete="current-password"
                        className="w-full bg-surface-0 border border-border rounded-lg px-4 py-2.5 pr-10 text-text-primary placeholder-text-muted text-sm focus:outline-none focus:border-brand-sage transition-colors"
                        placeholder="Your password"
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-text-tertiary hover:text-text-secondary"
                      >
                        {showPassword ? (
                          <EyeOff className="w-4 h-4" />
                        ) : (
                          <Eye className="w-4 h-4" />
                        )}
                      </button>
                    </div>
                  </div>
                </>
              )}

              {needs2FA && (
                <div>
                  <label className="block text-sm font-medium text-text-secondary mb-1.5">
                    Authentication Code
                  </label>
                  <input
                    type="text"
                    inputMode="numeric"
                    pattern="\d{6}"
                    maxLength={6}
                    value={totpCode}
                    onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                    autoFocus
                    required
                    className="w-full bg-surface-0 border border-border rounded-lg px-4 py-2.5 text-text-primary text-center text-lg font-mono tracking-[0.3em] focus:outline-none focus:border-brand-sage transition-colors"
                    placeholder="000000"
                  />
                </div>
              )}

              {error && (
                <div className="bg-status-danger/10 border border-status-danger/20 rounded-lg px-4 py-2.5 text-sm text-status-danger">
                  {error}
                </div>
              )}

              <button
                type="submit"
                disabled={loading}
                className="w-full bg-brand-sage text-surface-0 font-semibold text-sm rounded-lg px-4 py-2.5 hover:bg-brand-sage-light transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              >
                {loading && <Loader2 className="w-4 h-4 animate-spin" />}
                {needs2FA ? 'Verify' : 'Log In'}
              </button>

              {!needs2FA && (
                <div className="flex items-center justify-between text-sm">
                  <button
                    type="button"
                    onClick={handleForgotPassword}
                    className="text-text-tertiary hover:text-brand-sage transition-colors"
                  >
                    Forgot password?
                  </button>
                  <Link
                    href="/register"
                    className="text-brand-sage hover:text-brand-sage-light transition-colors"
                  >
                    Create account
                  </Link>
                </div>
              )}

              {!needs2FA && (
                <>
                  <div className="relative my-4">
                    <div className="absolute inset-0 flex items-center">
                      <div className="w-full border-t border-border" />
                    </div>
                    <div className="relative flex justify-center text-xs">
                      <span className="bg-surface-1 px-3 text-text-tertiary">or</span>
                    </div>
                  </div>

                  <a
                    href={`${API_URL}/api/auth/google`}
                    className="w-full flex items-center justify-center gap-2 border border-border rounded-lg px-4 py-2.5 text-sm text-text-secondary hover:text-text-primary hover:border-border-hover transition-colors"
                  >
                    <svg className="w-4 h-4" viewBox="0 0 24 24">
                      <path
                        d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z"
                        fill="#4285F4"
                      />
                      <path
                        d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                        fill="#34A853"
                      />
                      <path
                        d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
                        fill="#FBBC05"
                      />
                      <path
                        d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
                        fill="#EA4335"
                      />
                    </svg>
                    Continue with Google
                  </a>
                </>
              )}
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
