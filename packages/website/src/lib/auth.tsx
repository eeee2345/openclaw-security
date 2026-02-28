'use client';

import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import type { ReactNode } from 'react';

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? '';

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
    // Check for token in URL (from OAuth callback)
    if (typeof window !== 'undefined') {
      const params = new URLSearchParams(window.location.search);
      const urlToken = params.get('token');
      if (urlToken) {
        storeToken(urlToken);
        setToken(urlToken);
        // Clean URL
        const url = new URL(window.location.href);
        url.searchParams.delete('token');
        window.history.replaceState({}, '', url.toString());
      }
    }
    void refresh();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const login = useCallback(
    async (email: string, password: string, totpCode?: string): Promise<LoginResult> => {
      try {
        const body: Record<string, string> = { email, password };
        if (totpCode) body['totpCode'] = totpCode;

        const res = await fetch(`${API_URL}/api/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
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
