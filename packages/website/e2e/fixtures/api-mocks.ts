/**
 * E2E Mock Response Factories
 *
 * Centralizes all API response shapes for Playwright route interception.
 * Matches the exact JSON contract the frontend expects.
 */

export const MOCK_TOKEN = 'e2e-test-token-panguard-12345';

export const MOCK_USER = {
  id: 1,
  email: 'user@example.com',
  name: 'Test User',
  role: 'user',
  tier: 'community',
  verified: 1,
  createdAt: '2026-01-15T00:00:00Z',
  planExpiresAt: null,
} as const;

export const MOCK_ADMIN = {
  id: 2,
  email: 'admin@panguard.ai',
  name: 'Admin User',
  role: 'admin',
  tier: 'pro',
  verified: 1,
  createdAt: '2026-01-01T00:00:00Z',
  planExpiresAt: '2027-01-01T00:00:00Z',
} as const;

export const MOCK_PRO_USER = {
  id: 3,
  email: 'pro@example.com',
  name: 'Pro User',
  role: 'user',
  tier: 'pro',
  verified: 1,
  createdAt: '2026-02-01T00:00:00Z',
  planExpiresAt: '2027-02-01T00:00:00Z',
} as const;

export const MOCK_USAGE: readonly { resource: string; current: number; limit: number; percentage: number }[] = [
  { resource: 'machines', current: 1, limit: 3, percentage: 33 },
  { resource: 'scans', current: 12, limit: 50, percentage: 24 },
  { resource: 'guard_endpoints', current: 1, limit: 3, percentage: 33 },
  { resource: 'reports', current: 2, limit: 10, percentage: 20 },
] as const;

// --- Auth responses ---

export function authMeSuccess(overrides?: Record<string, unknown>) {
  const user = { ...MOCK_USER, ...overrides };
  return { ok: true, data: { user } };
}

export function authMeAdmin() {
  return { ok: true, data: { user: MOCK_ADMIN } };
}

export function authMeUnauthorized() {
  return { ok: false, error: 'Unauthorized' };
}

export function loginSuccess(token = MOCK_TOKEN) {
  return { ok: true, data: { token } };
}

export function loginRequires2FA() {
  return { ok: false, data: { requiresTwoFactor: true } };
}

export function loginError(message = 'Invalid credentials') {
  return { ok: false, error: message };
}

export function registerSuccess() {
  return { ok: true, data: { message: 'Account created' } };
}

export function registerError(message = 'Email already registered') {
  return { ok: false, error: message };
}

export function forgotPasswordSuccess() {
  return { ok: true, data: { message: 'Reset email sent' } };
}

export function resetPasswordSuccess() {
  return { ok: true, data: { message: 'Password reset' } };
}

export function resetPasswordError(message = 'Token expired') {
  return { ok: false, error: message };
}

// --- Usage responses ---

export function usageSuccess(items = MOCK_USAGE) {
  return { ok: true, data: { usage: items } };
}

// --- Billing responses ---

export function billingStatusFree() {
  return { ok: true, data: { tier: 'community', status: null, renewsAt: null } };
}

export function billingStatusPro() {
  return {
    ok: true,
    data: {
      tier: 'pro',
      status: 'active',
      renewsAt: '2027-02-01T00:00:00Z',
      customerPortalUrl: 'https://billing.lemonsqueezy.com/portal/test',
    },
  };
}

export function billingPortalUrl(url = 'https://billing.lemonsqueezy.com/portal/test') {
  return { ok: true, data: { url } };
}

// --- TOTP responses ---

export function totpStatusDisabled() {
  return { ok: true, data: { enabled: false } };
}

export function totpStatusEnabled() {
  return { ok: true, data: { enabled: true } };
}

export function totpSetupSuccess() {
  return {
    ok: true,
    data: {
      secret: 'JBSWY3DPEHPK3PXP',
      qrUrl: 'otpauth://totp/Panguard:user@example.com?secret=JBSWY3DPEHPK3PXP',
      backupCodes: ['12345678', '23456789', '34567890', '45678901', '56789012'],
    },
  };
}

// --- Form responses ---

export function formSuccess() {
  return { ok: true };
}

export function formError(message = 'Submission failed') {
  return { ok: false, error: message };
}
