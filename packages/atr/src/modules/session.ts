/**
 * ATR Session Module - Built-in behavioral detection module
 *
 * Provides cross-event analysis using SessionTracker.
 * This is the reference implementation for ATR modules.
 *
 * Functions:
 * - call_frequency: Count tool calls within a time window
 * - pattern_frequency: Count pattern occurrences within a window
 * - event_count: Total events in a session within a window
 * - session_age: Time since first event in session (seconds)
 *
 * @module agent-threat-rules/modules/session
 */

import type { AgentEvent } from '../types.js';
import { SessionTracker } from '../session-tracker.js';
import type { ATRModule, ModuleCondition, ModuleResult } from './index.js';

export class SessionModule implements ATRModule {
  readonly name = 'session';
  readonly description = 'Cross-event behavioral analysis using session state tracking';
  readonly version = '0.1.0';

  readonly functions = [
    {
      name: 'call_frequency',
      description: 'Count how many times a specific tool was called within a time window',
      args: [
        { name: 'tool_name', type: 'string' as const, required: true, description: 'Tool name to count' },
        { name: 'window', type: 'string' as const, required: false, description: 'Time window (e.g., "5m", "1h"). Default: 5m' },
      ],
    },
    {
      name: 'pattern_frequency',
      description: 'Count how many times a pattern was matched within a time window',
      args: [
        { name: 'pattern', type: 'string' as const, required: true, description: 'Pattern string to count' },
        { name: 'window', type: 'string' as const, required: false, description: 'Time window. Default: 5m' },
      ],
    },
    {
      name: 'event_count',
      description: 'Total number of events in the current session within a time window',
      args: [
        { name: 'window', type: 'string' as const, required: false, description: 'Time window. Default: 5m' },
      ],
    },
    {
      name: 'session_age',
      description: 'Time in seconds since the first event in this session',
      args: [],
    },
  ] as const;

  private tracker: SessionTracker;

  constructor(tracker?: SessionTracker) {
    this.tracker = tracker ?? new SessionTracker();
  }

  async initialize(): Promise<void> {
    // SessionTracker is ready immediately, no async setup needed
  }

  async evaluate(event: AgentEvent, condition: ModuleCondition): Promise<ModuleResult> {
    const sessionId = event.sessionId ?? 'default';
    const fn = condition.function;
    const args = condition.args;

    let value = 0;
    let description = '';

    switch (fn) {
      case 'call_frequency': {
        const toolName = String(args['tool_name'] ?? '');
        const window = String(args['window'] ?? '5m');
        const windowMs = parseWindow(window);
        value = this.tracker.getCallFrequency(sessionId, toolName, windowMs);
        description = `Tool "${toolName}" called ${value} times in ${window}`;
        break;
      }

      case 'pattern_frequency': {
        const pattern = String(args['pattern'] ?? '');
        const window = String(args['window'] ?? '5m');
        const windowMs = parseWindow(window);
        value = this.tracker.getPatternFrequency(sessionId, pattern, windowMs);
        description = `Pattern "${pattern}" seen ${value} times in ${window}`;
        break;
      }

      case 'event_count': {
        const window = String(args['window'] ?? '5m');
        const windowMs = parseWindow(window);
        value = this.tracker.getEventCount(sessionId, windowMs);
        description = `${value} events in session within ${window}`;
        break;
      }

      case 'session_age': {
        const snapshot = this.tracker.getSessionSnapshot(sessionId);
        if (snapshot && snapshot.oldestEventTimestamp) {
          value = Math.floor((Date.now() - snapshot.oldestEventTimestamp) / 1000);
        }
        description = `Session age: ${value} seconds`;
        break;
      }

      default:
        return { matched: false, value: 0, description: `Unknown function: ${fn}` };
    }

    const matched = compare(value, condition.operator, condition.threshold);

    return { matched, value, description };
  }

  async destroy(): Promise<void> {
    // No cleanup needed
  }
}

function compare(value: number, operator: string, threshold: number): boolean {
  switch (operator) {
    case 'gt': return value > threshold;
    case 'lt': return value < threshold;
    case 'eq': return value === threshold;
    case 'gte': return value >= threshold;
    case 'lte': return value <= threshold;
    default: return false;
  }
}

function parseWindow(window: string): number {
  const match = window.match(/^(\d+)(s|m|h)$/);
  if (!match) return 300_000; // default 5m
  const [, num, unit] = match;
  const n = parseInt(num, 10);
  switch (unit) {
    case 's': return n * 1000;
    case 'm': return n * 60_000;
    case 'h': return n * 3_600_000;
    default: return 300_000;
  }
}
