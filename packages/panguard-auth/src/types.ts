/**
 * Type definitions for Panguard Auth
 * @module @openclaw/panguard-auth/types
 */

export interface WaitlistEntry {
  id: number;
  email: string;
  name: string | null;
  company: string | null;
  role: string | null;
  source: string;
  status: 'pending' | 'approved' | 'rejected';
  verified: number;
  verifyToken: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface WaitlistInput {
  email: string;
  name?: string;
  company?: string;
  role?: string;
  source?: string;
}

export interface User {
  id: number;
  email: string;
  name: string;
  passwordHash: string;
  role: 'user' | 'admin';
  tier: 'free' | 'solo' | 'starter' | 'team' | 'business' | 'enterprise';
  verified: number;
  createdAt: string;
  lastLogin: string | null;
}

export interface UserPublic {
  id: number;
  email: string;
  name: string;
  role: string;
  tier: string;
  createdAt: string;
}

export interface RegisterInput {
  email: string;
  name: string;
  password: string;
}

export interface LoginInput {
  email: string;
  password: string;
}

export interface Session {
  id: number;
  userId: number;
  token: string;
  expiresAt: string;
  createdAt: string;
}

export interface WaitlistStats {
  total: number;
  pending: number;
  approved: number;
  verified: number;
  todaySignups: number;
}

export interface AuthResult {
  ok: boolean;
  error?: string;
  data?: unknown;
}
