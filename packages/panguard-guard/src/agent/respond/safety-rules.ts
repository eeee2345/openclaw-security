/**
 * Safety rules for auto-response actions
 * @module @panguard-ai/panguard-guard/agent/respond/safety-rules
 */

export const SAFETY_RULES = {
  whitelistedIPs: new Set(['127.0.0.1', '::1', 'localhost', '0.0.0.0']),

  protectedProcesses: new Set([
    'sshd',
    'systemd',
    'init',
    'launchd',
    'loginwindow',
    'explorer.exe',
    'svchost.exe',
    'csrss.exe',
    'lsass.exe',
    'services.exe',
    'winlogon.exe',
    'wininit.exe',
    'panguard-guard',
    'node',
  ]),

  protectedAccounts: new Set(['root', 'Administrator', 'admin', 'SYSTEM', 'LocalSystem']),

  /** Default auto-unblock duration: 1 hour */
  defaultBlockDurationMs: 60 * 60 * 1000,

  /** Extended block duration for repeat offenders: 24 hours */
  repeatOffenderBlockDurationMs: 24 * 60 * 60 * 1000,

  /** SIGKILL timeout after SIGTERM: 5 seconds */
  sigkillTimeoutMs: 5000,

  /** Network isolation requires confidence >= 95 */
  networkIsolationMinConfidence: 95,

  /** Violations before escalation */
  escalationThreshold: 3,
} as const;
