import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execSync } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync, mkdirSync, writeFileSync, chmodSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';

const PROJECT_ROOT = resolve(__dirname, '../..');
const INSTALL_SCRIPT = join(PROJECT_ROOT, 'scripts/installer/install.sh');

/** 10 minutes -- source builds are slow */
const TIMEOUT = 600_000;

describe('Installer E2E', { timeout: TIMEOUT }, () => {
  // -------------------------------------------------------------------
  // Full source build on macOS
  // -------------------------------------------------------------------
  describe('Full source build on macOS', () => {
    let fakeHome: string;

    beforeAll(() => {
      fakeHome = mkdtempSync(join(tmpdir(), 'panguard-e2e-'));
      // Create shell profile files so PATH-fallback logic can work
      writeFileSync(join(fakeHome, '.bashrc'), '# test\n');
      writeFileSync(join(fakeHome, '.zshrc'), '# test\n');
      writeFileSync(join(fakeHome, '.profile'), '# test\n');
    }, TIMEOUT);

    afterAll(() => {
      rmSync(fakeHome, { recursive: true, force: true });
    });

    it(
      'should install successfully',
      () => {
        const result = execSync(`bash "${INSTALL_SCRIPT}" 2>&1`, {
          env: {
            ...process.env,
            HOME: fakeHome,
            // Keep the real PATH so git, node, and pnpm remain available
          },
          encoding: 'utf-8',
          timeout: TIMEOUT,
          maxBuffer: 10 * 1024 * 1024, // 10 MB output buffer
        });

        // The installer should report success
        expect(result).toContain('Installation complete');

        // Either binary install (.panguard/bin/) or source build (.panguard/source/) should exist
        const hasBinaryInstall = existsSync(join(fakeHome, '.panguard', 'bin'));
        const hasSourceBuild = existsSync(join(fakeHome, '.panguard', 'source'));
        expect(hasBinaryInstall || hasSourceBuild).toBe(true);
      },
      TIMEOUT
    );

    it('should have a working panguard binary after install', () => {
      // Binary download path: .panguard/bin/panguard
      const binaryBinPath = join(fakeHome, '.panguard', 'bin', 'panguard');
      // Source build path: .panguard/source/bin/panguard
      const sourceBinPath = join(fakeHome, '.panguard', 'source', 'bin', 'panguard');
      // PATH fallback: .local/bin/panguard
      const localBinPath = join(fakeHome, '.local', 'bin', 'panguard');
      // CLI entry (binary download): .panguard/dist/cli/index.js
      const binaryCli = join(fakeHome, '.panguard', 'dist', 'cli', 'index.js');
      // CLI entry (source build): .panguard/source/packages/panguard/dist/cli/index.js
      const sourceCli = join(
        fakeHome,
        '.panguard',
        'source',
        'packages',
        'panguard',
        'dist',
        'cli',
        'index.js'
      );

      const hasBinary =
        existsSync(binaryBinPath) || existsSync(sourceBinPath) || existsSync(localBinPath);
      const hasCli = existsSync(binaryCli) || existsSync(sourceCli);
      expect(hasBinary || hasCli).toBe(true);

      // Try running --version via whichever CLI entry exists
      const cliEntry = existsSync(binaryCli) ? binaryCli : sourceCli;
      if (existsSync(cliEntry)) {
        const version = execSync(`node "${cliEntry}" --version 2>&1 || true`, {
          env: { ...process.env, HOME: fakeHome },
          encoding: 'utf-8',
          timeout: 30_000,
        });
        expect(version.trim()).toMatch(/\d+\.\d+/);
      }
    }, 30_000);
  });

  // -------------------------------------------------------------------
  // Backup existing installation
  // -------------------------------------------------------------------
  describe('Backup existing installation', () => {
    let fakeHome: string;

    beforeAll(() => {
      fakeHome = mkdtempSync(join(tmpdir(), 'panguard-backup-'));
      writeFileSync(join(fakeHome, '.bashrc'), '# test\n');
      writeFileSync(join(fakeHome, '.zshrc'), '# test\n');
      writeFileSync(join(fakeHome, '.profile'), '# test\n');

      // Create a fake existing installation to trigger backup logic
      const fakeInstall = join(fakeHome, '.panguard', 'bin');
      mkdirSync(fakeInstall, { recursive: true });
      const fakeBin = join(fakeInstall, 'panguard');
      writeFileSync(fakeBin, '#!/bin/bash\necho "0.1.0-old"');
      chmodSync(fakeBin, 0o755);
    });

    afterAll(() => {
      rmSync(fakeHome, { recursive: true, force: true });
    });

    it(
      'should backup existing installation before installing',
      () => {
        let output = '';
        try {
          output = execSync(`bash "${INSTALL_SCRIPT}" 2>&1`, {
            env: { ...process.env, HOME: fakeHome },
            encoding: 'utf-8',
            timeout: TIMEOUT,
            maxBuffer: 10 * 1024 * 1024,
          });
        } catch (error: unknown) {
          const e = error as { stdout?: Buffer | string; stderr?: Buffer | string };
          output = (e.stdout?.toString() || '') + (e.stderr?.toString() || '');
        }

        // Installer output should mention a backup
        expect(output.toLowerCase()).toContain('backup');

        // A .panguard.backup.* directory should now exist
        const backupDirs = execSync(
          `ls -d "${fakeHome}/.panguard.backup."* 2>/dev/null || echo ""`,
          { encoding: 'utf-8' }
        ).trim();
        expect(backupDirs.length).toBeGreaterThan(0);
      },
      TIMEOUT
    );
  });

  // -------------------------------------------------------------------
  // Node version gate
  // -------------------------------------------------------------------
  describe('Node version gate', () => {
    it('should reject Node 18', () => {
      const tmpDir = mkdtempSync(join(tmpdir(), 'node-gate-'));
      try {
        // Create a mock node binary that reports v18.19.0
        const mockNode = join(tmpDir, 'node');
        writeFileSync(mockNode, '#!/bin/bash\necho "v18.19.0"');
        chmodSync(mockNode, 0o755);

        let exitCode = 0;
        let output = '';
        try {
          output = execSync(`bash "${INSTALL_SCRIPT}" 2>&1`, {
            env: {
              ...process.env,
              HOME: tmpDir,
              // Replace PATH: only mock-node dir + essential system utilities
              PATH: `${tmpDir}:/usr/bin:/bin`,
            },
            encoding: 'utf-8',
            timeout: 30_000,
          });
        } catch (error: unknown) {
          const e = error as {
            status?: number;
            stdout?: Buffer | string;
            stderr?: Buffer | string;
          };
          exitCode = e.status ?? 1;
          output = (e.stdout?.toString() || '') + (e.stderr?.toString() || '');
        }

        expect(exitCode).not.toBe(0);
        // Installer should complain about minimum version requirement
        expect(output).toContain('v20');
      } finally {
        rmSync(tmpDir, { recursive: true, force: true });
      }
    }, 30_000);

    it('should reject when node is not found at all', () => {
      const tmpDir = mkdtempSync(join(tmpdir(), 'no-node-'));
      try {
        // Shell profiles
        writeFileSync(join(tmpDir, '.bashrc'), '# test\n');

        let exitCode = 0;
        try {
          execSync(`bash "${INSTALL_SCRIPT}" 2>&1`, {
            env: {
              ...process.env,
              HOME: tmpDir,
              // PATH with no node at all
              PATH: `${tmpDir}:/usr/bin:/bin`,
            },
            encoding: 'utf-8',
            timeout: 30_000,
          });
        } catch (error: unknown) {
          const e = error as {
            status?: number;
          };
          exitCode = e.status ?? 1;
        }

        expect(exitCode).not.toBe(0);
      } finally {
        rmSync(tmpDir, { recursive: true, force: true });
      }
    }, 30_000);
  });
});
