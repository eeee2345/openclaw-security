/**
 * Panguard AI Hardening Library
 * Panguard 安全強化函式庫
 *
 * Provides security fixes and hardening for Panguard AI Agent framework.
 * Addresses CVE-2026-25253, credential storage, skill sandboxing,
 * permission minimization, and audit logging.
 * 為 Panguard AI Agent 框架提供安全修復和強化。
 * 處理 CVE-2026-25253、憑證儲存、技能沙盒、權限最小化和稽核日誌。
 *
 * @module @panguard-ai/security-hardening
 */

// Types
export type {
  SecurityPolicy,
  CsrfToken,
  OriginConfig,
  AuditAction,
  AuditEvent,
  CredentialStore,
  VulnerabilityFinding,
  SecurityAuditReport,
  MigrationReport,
} from './types.js';

// WebSocket Security (CVE-2026-25253)
export { validateOrigin, createOriginValidator } from './websocket/index.js';
export { CsrfTokenManager } from './websocket/index.js';
export { validateGatewayUrl, sanitizeWebSocketUrl } from './websocket/index.js';

// Credential Security
export { InMemoryCredentialStore, EncryptedFileCredentialStore } from './credentials/index.js';
export { scanPlaintextCredentials, migrateCredentials } from './credentials/index.js';

// Skill Sandbox
export { isPathAllowed, createFilesystemGuard } from './sandbox/index.js';
export {
  isCommandAllowed,
  createCommandValidator,
  DEFAULT_ALLOWED_COMMANDS,
} from './sandbox/index.js';

// Permissions
export {
  loadSecurityPolicy,
  isOperationAllowed,
  DEFAULT_SECURITY_POLICY,
} from './permissions/index.js';
export type { OperationType } from './permissions/index.js';

// Audit Logging
export {
  logAuditEvent,
  logWebSocketConnect,
  logCredentialAccess,
  logFileAccess,
  logCommandExecution,
  logPolicyCheck,
} from './audit/index.js';
export { SyslogAdapter, formatSyslogMessage } from './audit/index.js';

// Security Scanner
export { runSecurityAudit } from './scanner/index.js';

/** Security hardening library version / 安全強化函式庫版本 */
export const HARDENING_VERSION = '0.1.0';
