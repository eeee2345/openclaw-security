/**
 * Panguard Auth - Authentication and waitlist system
 * @module @panguard-ai/panguard-auth
 */

export { AuthDB } from './database.js';
export type { ReportPurchase, AuditLogEntry, Subscription, TotpSecret } from './database.js';
export {
  generateTotpSecret,
  generateBackupCodes,
  buildOtpauthUri,
  verifyTotp,
  base32Encode,
  base32Decode,
} from './totp.js';
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
export {
  checkQuota,
  recordUsage,
  setUsage,
  getUsageSummary,
  getQuotaLimits,
  currentPeriod,
} from './usage-meter.js';
export type { MeterableResource, QuotaCheck, UsageSummary } from './usage-meter.js';
export { initErrorTracking, captureException, captureRequestError } from './error-tracker.js';
export { generateOpenApiSpec, generateSwaggerHtml } from './openapi.js';
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
  AuditLogFilter,
  UserDetailAdmin,
  BulkActionRequest,
  BulkActionResult,
} from './types.js';
