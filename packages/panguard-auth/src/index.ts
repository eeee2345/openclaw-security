/**
 * Panguard Auth - Authentication and waitlist system
 * @module @openclaw/panguard-auth
 */

export { AuthDB } from './database.js';
export { hashPassword, verifyPassword, generateSessionToken, generateVerifyToken, sessionExpiry } from './auth.js';
export { extractToken, authenticateRequest, requireAdmin } from './middleware.js';
export { createAuthHandlers } from './routes.js';
export { sendVerificationEmail, sendWelcomeEmail } from './email-verify.js';
export type { SmtpConfig } from './email-verify.js';
export type { AuthRouteConfig } from './routes.js';
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
} from './types.js';
