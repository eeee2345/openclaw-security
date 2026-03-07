'use client';

import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import type { ReactNode } from 'react';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'https://panguard-api-production.up.railway.app';
const REQUEST_TIMEOUT = 15_000;

export interface AuthUser {
  id: number;
  email: string;
  name: string;
  role: string;
  tier: string;
  verified: number;
  createdAt: string;
  planExpiresAt: string | null;
}

interface AuthContextValue {
  user: AuthUser | null;
  token: string | null;
  loading: boolean;
  login: (email: string, password: string, totpCode?: string) => Promise<LoginResult>;
  register: (
    email: string,
    name: string,
    password: string
  ) => Promise<{ ok: boolean; error?: string }>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
}

interface LoginResult {
  ok: boolean;
  requiresTwoFactor?: boolean;
  error?: string;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}

const TOKEN_KEY = 'panguard_token';

function getStoredToken(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem(TOKEN_KEY);
}

function storeToken(token: string | null) {
  if (typeof window === 'undefined') return;
  if (token) {
    localStorage.setItem(TOKEN_KEY, token);
  } else {
    localStorage.removeItem(TOKEN_KEY);
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    const stored = token ?? getStoredToken();
    if (!stored) {
      setUser(null);
      setLoading(false);
      return;
    }

    try {
      const res = await fetch(`${API_URL}/api/auth/me`, {
        headers: { Authorization: `Bearer ${stored}` },
        signal: AbortSignal.timeout(REQUEST_TIMEOUT),
      });
      if (res.ok) {
        const data = (await res.json()) as { ok: boolean; data?: { user: AuthUser } };
        if (data.ok && data.data?.user) {
          setUser(data.data.user);
          setToken(stored);
          storeToken(stored);
        } else {
          setUser(null);
          setToken(null);
          storeToken(null);
        }
      } else {
        setUser(null);
        setToken(null);
        storeToken(null);
      }
    } catch {
      setUser(null);
      setToken(null);
      storeToken(null);
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    // Check for OAuth exchange code in URL
    if (typeof window !== 'undefined') {
      const params = new URLSearchParams(window.location.search);
      const code = params.get('code');
      const cliState = params.get('cli_state');
      const cliCallback = params.get('cli_callback');
      if (code) {
        // Clean URL immediately
        const url = new URL(window.location.href);
        url.searchParams.delete('code');
        url.searchParams.delete('cli_state');
        url.searchParams.delete('cli_callback');
        window.history.replaceState({}, '', url.toString());

        // Exchange code for token
        fetch(`${API_URL}/api/auth/oauth/exchange`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code }),
        })
          .then((res) => res.json() as Promise<{ ok: boolean; data?: { token: string } }>)
          .then(async (data) => {
            if (data.ok && data.data?.token) {
              storeToken(data.data.token);
              setToken(data.data.token);

              // CLI login flow: redirect token back to CLI's localhost callback
              if (cliState && cliCallback) {
                try {
                  const parsed = new URL(cliCallback);
                  if (['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname)) {
                    const meRes = await fetch(`${API_URL}/api/auth/me`, {
                      headers: { Authorization: `Bearer ${data.data.token}` },
                      signal: AbortSignal.timeout(10_000),
                    });
                    if (meRes.ok) {
                      const meData = (await meRes.json()) as {
                        ok: boolean;
                        data?: { user: { email: string; name: string; tier: string } };
                      };
                      if (meData.ok && meData.data?.user) {
                        const { email, name, tier } = meData.data.user;
                        const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
                        const cbParams = new URLSearchParams({
                          token: data.data.token,
                          email,
                          name,
                          tier,
                          state: cliState,
                          expires,
                        });
                        window.location.href = `${cliCallback}?${cbParams.toString()}`;
                        return;
                      }
                    }
                  }
                } catch {
                  // Fall through to normal flow
                }
              }
            }
          })
          .catch(() => {
            // Exchange failed — user can log in manually
          })
          .finally(() => void refresh());
        return;
      }
    }
    void refresh();
  }, []);

  const login = useCallback(
    async (email: string, password: string, totpCode?: string): Promise<LoginResult> => {
      try {
        const body: Record<string, string> = { email, password };
        if (totpCode) body['totpCode'] = totpCode;

        const res = await fetch(`${API_URL}/api/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(REQUEST_TIMEOUT),
        });

        const data = (await res.json()) as {
          ok: boolean;
          data?: { token: string; requiresTwoFactor?: boolean };
          error?: string;
        };

        if (data.data?.requiresTwoFactor) {
          return { ok: false, requiresTwoFactor: true };
        }

        if (!data.ok || !data.data?.token) {
          return { ok: false, error: data.error ?? 'Login failed' };
        }

        storeToken(data.data.token);
        setToken(data.data.token);
        await refresh();
        return { ok: true };
      } catch {
        return { ok: false, error: 'Network error' };
      }
    },
    [refresh]
  );

  const register = useCallback(
    async (
      email: string,
      name: string,
      password: string
    ): Promise<{ ok: boolean; error?: string }> => {
      try {
        const res = await fetch(`${API_URL}/api/auth/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, name, password }),
          signal: AbortSignal.timeout(REQUEST_TIMEOUT),
        });

        const data = (await res.json()) as { ok: boolean; error?: string };
        return { ok: data.ok, error: data.error };
      } catch {
        return { ok: false, error: 'Network error' };
      }
    },
    []
  );

  const logout = useCallback(async () => {
    const stored = token ?? getStoredToken();
    if (stored) {
      try {
        await fetch(`${API_URL}/api/auth/logout`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${stored}` },
          signal: AbortSignal.timeout(REQUEST_TIMEOUT),
        });
      } catch {
        // Best effort
      }
    }
    storeToken(null);
    setToken(null);
    setUser(null);
  }, [token]);

  return (
    <AuthContext.Provider value={{ user, token, loading, login, register, logout, refresh }}>
      {children}
    </AuthContext.Provider>
  );
}
