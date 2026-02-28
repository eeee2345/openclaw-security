/**
 * Type definitions for Panguard Auth
 * @module @panguard-ai/panguard-auth/types
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
  suspended: number;
  createdAt: string;
  lastLogin: string | null;
  planExpiresAt: string | null;
}

export interface UserPublic {
  id: number;
  email: string;
  name: string;
  role: string;
  tier: string;
  createdAt: string;
  planExpiresAt?: string | null;
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
  rejected: number;
  verified: number;
  todaySignups: number;
  bySource: Record<string, number>;
}

export interface UserAdmin {
  id: number;
  email: string;
  name: string;
  role: string;
  tier: string;
  verified: number;
  suspended: number;
  createdAt: string;
  lastLogin: string | null;
  planExpiresAt: string | null;
}

export interface SessionAdmin {
  id: number;
  userId: number;
  userEmail: string;
  userName: string;
  expiresAt: string;
  createdAt: string;
}

export interface ActivityItem {
  type: string;
  description: string;
  timestamp: string;
}

export interface AuthResult {
  ok: boolean;
  error?: string;
  data?: unknown;
}

// ── Admin Detail Types ───────────────────────────────────────

export interface AuditLogFilter {
  action?: string;
  actorId?: number;
  dateFrom?: string;
  dateTo?: string;
  page?: number;
  perPage?: number;
}

export interface UserDetailAdmin {
  user: UserAdmin;
  subscription: {
    status: string;
    tier: string;
    renewsAt: string | null;
    endsAt: string | null;
  } | null;
  usage: Array<{ resource: string; current: number; limit: number; percentage: number }>;
  sessions: Array<{ id: number; expiresAt: string; createdAt: string }>;
  recentAudit: Array<{
    id: number;
    action: string;
    actorId: number | null;
    targetId: number | null;
    details: string | null;
    createdAt: string;
  }>;
  twoFactor: { enabled: boolean };
}

export interface BulkActionRequest {
  userIds: number[];
  action: 'change_tier' | 'change_role' | 'suspend' | 'unsuspend';
  value?: string;
}

export interface BulkActionResult {
  processed: number;
  failed: number;
  results: Array<{ userId: number; success: boolean; error?: string }>;
}
