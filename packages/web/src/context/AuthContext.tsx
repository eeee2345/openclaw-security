import { createContext, useContext, useState, useEffect, type ReactNode } from 'react';

export interface AuthUser {
  id: number;
  email: string;
  name: string;
  role: string;
  tier: string;
  createdAt: string;
}

interface AuthContextValue {
  user: AuthUser | null;
  loading: boolean;
  tier: string;
}

const AuthContext = createContext<AuthContextValue>({
  user: null,
  loading: true,
  tier: 'free',
});

const TIER_LEVEL: Record<string, number> = {
  free: 0,
  solo: 1,
  starter: 2,
  team: 3,
  business: 4,
  enterprise: 5,
};

export function tierLevel(tier: string): number {
  return TIER_LEVEL[tier] ?? 0;
}

export function hasTierAccess(userTier: string, requiredTier: string): boolean {
  return tierLevel(userTier) >= tierLevel(requiredTier);
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('panguard_token');
    if (!token) {
      setLoading(false);
      return;
    }

    fetch('/api/auth/me', {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then(res => {
        if (!res.ok) throw new Error('Unauthorized');
        return res.json();
      })
      .then((json: { ok: boolean; data?: { user: AuthUser } }) => {
        if (json.ok && json.data?.user) {
          setUser(json.data.user);
        }
      })
      .catch(() => {
        // Token invalid — clear silently
        localStorage.removeItem('panguard_token');
        localStorage.removeItem('panguard_email');
      })
      .finally(() => setLoading(false));
  }, []);

  const tier = user?.tier ?? 'free';

  return (
    <AuthContext.Provider value={{ user, loading, tier }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  return useContext(AuthContext);
}
