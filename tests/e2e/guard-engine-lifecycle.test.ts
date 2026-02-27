/**
 * E2E: GuardEngine lifecycle test
 * Tests the complete startup -> event processing -> shutdown cycle
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import { join } from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { GuardEngine } from '@panguard-ai/panguard-guard/guard-engine.js';
import type { GuardConfig } from '@panguard-ai/panguard-guard/types.js';
import { DEFAULT_ACTION_POLICY } from '@panguard-ai/panguard-guard/types.js';

// Suppress logger output during tests
vi.spyOn(process.stderr, 'write').mockImplementation(() => true);

function createTempDir(): string {
  return mkdtempSync(join(tmpdir(), 'guard-e2e-'));
}

function createTestConfig(dataDir: string): GuardConfig {
  return {
    lang: 'en',
    mode: 'learning',
    learningDays: 1,
    actionPolicy: DEFAULT_ACTION_POLICY,
    notifications: {},
    dataDir,
    dashboardPort: 0, // random port
    dashboardEnabled: false, // disable for faster tests
    verbose: false,
    monitors: {
      logMonitor: false,
      networkMonitor: false,
      processMonitor: false,
      fileMonitor: false,
      networkPollInterval: 60000,
      processPollInterval: 60000,
    },
    watchdogEnabled: false,
    watchdogInterval: 60000,
  };
}

describe('GuardEngine Lifecycle', () => {
  let tempDir: string;
  let engine: GuardEngine | null = null;

  afterEach(async () => {
    if (engine) {
      try {
        await engine.stop();
      } catch {
        /* ignore */
      }
      engine = null;
    }
    if (tempDir) {
      try {
        rmSync(tempDir, { recursive: true, force: true });
      } catch {
        /* ignore */
      }
    }
  });

  it('should initialize in learning mode', () => {
    tempDir = createTempDir();
    const config = createTestConfig(tempDir);
    engine = new GuardEngine(config);

    const status = engine.getStatus();
    expect(status.mode).toBe('learning');
    expect(status.running).toBe(false);
    expect(status.eventsProcessed).toBe(0);
    expect(status.threatsDetected).toBe(0);
  });

  it('should start and stop cleanly', async () => {
    tempDir = createTempDir();
    const config = createTestConfig(tempDir);
    engine = new GuardEngine(config);

    await engine.start();
    const statusAfterStart = engine.getStatus();
    expect(statusAfterStart.running).toBe(true);

    await engine.stop();
    const statusAfterStop = engine.getStatus();
    expect(statusAfterStop.running).toBe(false);
    engine = null;
  });

  it('should initialize in protection mode', () => {
    tempDir = createTempDir();
    const config = createTestConfig(tempDir);
    config.mode = 'protection';
    engine = new GuardEngine(config);

    const status = engine.getStatus();
    expect(status.mode).toBe('protection');
  });

  it('should handle double start gracefully', async () => {
    tempDir = createTempDir();
    const config = createTestConfig(tempDir);
    engine = new GuardEngine(config);

    await engine.start();
    // Second start should not throw
    await engine.start();
    expect(engine.getStatus().running).toBe(true);

    await engine.stop();
    engine = null;
  });

  it('should handle double stop gracefully', async () => {
    tempDir = createTempDir();
    const config = createTestConfig(tempDir);
    engine = new GuardEngine(config);

    await engine.start();
    await engine.stop();
    // Second stop should not throw
    await engine.stop();
    engine = null;
  });
});
