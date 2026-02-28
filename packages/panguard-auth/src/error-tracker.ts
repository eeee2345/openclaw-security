/**
 * Lightweight error tracking with optional Sentry integration.
 *
 * If SENTRY_DSN is configured and @sentry/node is installed, errors are
 * reported to Sentry. Otherwise, falls back to structured console logging.
 *
 * @module @panguard-ai/panguard-auth/error-tracker
 */

interface SentryLike {
  init(opts: { dsn: string; environment: string; tracesSampleRate: number }): void;
  captureException(err: unknown, context?: { extra?: Record<string, unknown> }): void;
  setTag(key: string, value: string): void;
}

let sentry: SentryLike | null = null;
let initialized = false;

/**
 * Initialize error tracking.
 * - Installs global handlers for uncaughtException and unhandledRejection.
 * - If SENTRY_DSN env var is set, attempts to load @sentry/node.
 * - Falls back to console.error if Sentry is unavailable.
 */
export async function initErrorTracking(): Promise<void> {
  if (initialized) return;
  initialized = true;

  const dsn = process.env['SENTRY_DSN'];

  if (dsn) {
    try {
      // Dynamic import — only loads if @sentry/node is installed
      const sentryModule = (await import('@sentry/node')) as unknown as SentryLike;
      sentryModule.init({
        dsn,
        environment: process.env['NODE_ENV'] ?? 'production',
        tracesSampleRate: 0.1,
      });
      sentry = sentryModule;
      console.log('  [Sentry] Error tracking initialized');
    } catch {
      console.log('  [Sentry] @sentry/node not installed, using console fallback');
    }
  }

  // Global error handlers
  process.on('uncaughtException', (err) => {
    captureException(err, { source: 'uncaughtException' });
    console.error('[FATAL] Uncaught exception:', err);
  });

  process.on('unhandledRejection', (reason) => {
    const err = reason instanceof Error ? reason : new Error(String(reason));
    captureException(err, { source: 'unhandledRejection' });
    console.error('[FATAL] Unhandled rejection:', reason);
  });
}

/**
 * Capture an exception for tracking.
 */
export function captureException(err: unknown, context?: Record<string, unknown>): void {
  if (sentry) {
    sentry.captureException(err, context ? { extra: context } : undefined);
  }

  // Always log to stderr for observability
  const timestamp = new Date().toISOString();
  const message = err instanceof Error ? err.message : String(err);
  const stack = err instanceof Error ? err.stack : undefined;
  const logEntry = {
    timestamp,
    level: 'error',
    message,
    ...(stack ? { stack } : {}),
    ...(context ?? {}),
  };
  console.error(JSON.stringify(logEntry));
}

/**
 * Capture a request-level error with HTTP context.
 */
export function captureRequestError(err: unknown, method: string, path: string): void {
  captureException(err, {
    source: 'request',
    method,
    path,
  });
}
