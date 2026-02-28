/**
 * Panguard Auth - Authentication and waitlist system
 * @module @panguard-ai/panguard-auth
 */

export { AuthDB } from './database.js';
export type { ReportPurchase, AuditLogEntry, Subscription } from './database.js';
export {
  hashPassword,
  verifyPassword,
  generateSessionToken,
  generateVerifyToken,
  sessionExpiry,
  hashToken,
} from './auth.js';
export { extractToken, authenticateRequest, requireAdmin } from './middleware.js';
export { createAuthHandlers } from './routes.js';
export { RateLimiter } from './rate-limiter.js';
export type { RateLimitConfig, RateLimitResult } from './rate-limiter.js';
export {
  sendVerificationEmail,
  sendWelcomeEmail,
  sendResetEmail,
  sendExpirationWarningEmail,
} from './email-verify.js';
export type { SmtpConfig } from './email-verify.js';
export {
  getGoogleAuthUrl,
  exchangeCodeForTokens,
  getGoogleUserInfo,
  generateCodeVerifier,
  generateCodeChallenge,
  generateOAuthState,
} from './google-oauth.js';
export type { GoogleOAuthConfig, GoogleUserInfo } from './google-oauth.js';
export { syncWaitlistEntry, appendRow, ensureSheetHeaders } from './google-sheets.js';
export type { GoogleSheetsConfig } from './google-sheets.js';
export type { AuthRouteConfig } from './routes.js';
export {
  verifyWebhookSignature,
  handleWebhookEvent,
  createCheckoutUrl,
  getCustomerPortalUrl,
} from './lemonsqueezy.js';
export type { LemonSqueezyConfig, WebhookResult } from './lemonsqueezy.js';
export type {
  WaitlistEntry,
  WaitlistInput,
  WaitlistStats,
  User,
  UserPublic,
  RegisterInput,
  LoginInput,
  Session,
  AuthResult,
  UserAdmin,
  SessionAdmin,
  ActivityItem,
} from './types.js';
