/**
 * Rate limiter for response actions -- prevents runaway auto-responses
 * from causing self-DoS if DetectAgent produces false-positive loops.
 *
 * @module @panguard-ai/panguard-guard/agent/respond/action-rate-limiter
 */

import { createLogger } from '@panguard-ai/core';
import type { ResponseAction } from '../../types.js';

const logger = createLogger('panguard-guard:action-rate-limiter');

export class ActionRateLimiter {
  private readonly windows = new Map<ResponseAction, number[]>();
  private consecutiveFailures = 0;
  private circuitBreakerUntil = 0;

  /** Per-action limits: max invocations per 60-second window */
  private readonly limits: Record<string, number> = {
    block_ip: 10,
    kill_process: 5,
    disable_account: 2,
    isolate_file: 5,
    notify: 30,
    log_only: Infinity,
    // ATR agent-specific actions
    block_tool: 10,
    kill_agent: 3,
    quarantine_session: 5,
    revoke_skill: 10,
    reduce_permissions: 5,
  };

  /** Circuit breaker: pause all actions after N consecutive failures */
  private readonly maxConsecutiveFailures = 5;
  /** Circuit breaker cooldown: 60 seconds */
  private readonly circuitBreakerCooldownMs = 60_000;
  /** Sliding window size: 60 seconds */
  private readonly windowMs = 60_000;

  /**
   * Check whether the given action is allowed under rate limits.
   * Returns true if allowed, false if rate-limited or circuit-broken.
   */
  allow(action: ResponseAction): boolean {
    const now = Date.now();

    // Circuit breaker check
    if (now < this.circuitBreakerUntil) {
      return false;
    }

    const limit = this.limits[action] ?? 10;
    if (limit === Infinity) return true;

    // Sliding window: prune old entries, count recent
    const timestamps = this.windows.get(action) ?? [];
    const cutoff = now - this.windowMs;
    const recent = timestamps.filter((t) => t > cutoff);
    this.windows.set(action, recent);

    return recent.length < limit;
  }

  /** Record that an action was executed (adds to sliding window) */
  record(action: ResponseAction): void {
    const timestamps = this.windows.get(action) ?? [];
    timestamps.push(Date.now());
    this.windows.set(action, timestamps);
  }

  /** Record a successful action -- resets consecutive failure counter */
  recordSuccess(): void {
    this.consecutiveFailures = 0;
  }

  /** Record a failed action execution. Trips circuit breaker after threshold. */
  recordFailure(): void {
    this.consecutiveFailures++;
    if (this.consecutiveFailures >= this.maxConsecutiveFailures) {
      this.circuitBreakerUntil = Date.now() + this.circuitBreakerCooldownMs;
      logger.error(
        `Circuit breaker tripped: ${this.consecutiveFailures} consecutive failures. ` +
          `All auto-responses paused for ${this.circuitBreakerCooldownMs / 1000}s.`
      );
      this.consecutiveFailures = 0;
    }
  }

  /** Check if circuit breaker is currently active */
  isCircuitBroken(): boolean {
    return Date.now() < this.circuitBreakerUntil;
  }

  /** Get current rate limit status for monitoring */
  getStatus(): {
    circuitBroken: boolean;
    consecutiveFailures: number;
    windowCounts: Record<string, number>;
  } {
    const now = Date.now();
    const cutoff = now - this.windowMs;
    const windowCounts: Record<string, number> = {};
    for (const [action, timestamps] of this.windows) {
      windowCounts[action] = timestamps.filter((t) => t > cutoff).length;
    }
    return {
      circuitBroken: this.isCircuitBroken(),
      consecutiveFailures: this.consecutiveFailures,
      windowCounts,
    };
  }
}
