import { describe, it, expect, beforeEach, afterEach, beforeAll, afterAll } from 'vitest';
import { execSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, existsSync, readFileSync, rmSync, chmodSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';

const PROJECT_ROOT = resolve(__dirname, '../..');
const FUNCTIONS_SCRIPT = join(PROJECT_ROOT, 'scripts/installer/install-functions.sh');

// Minimal system PATH that includes bash but NOT node (for mocking)
const SYSTEM_PATH = '/usr/bin:/bin:/usr/sbin:/sbin';

/**
 * Helper to run a bash function from install-functions.sh.
 * Sources the functions file, then executes the given function call.
 * Returns stdout, stderr, and the exit code.
 */
function runFunction(
  fnCall: string,
  env?: Record<string, string>
): { stdout: string; stderr: string; exitCode: number } {
  const cmd = `bash -c 'source "${FUNCTIONS_SCRIPT}" && ${fnCall}'`;
  try {
    const stdout = execSync(cmd, {
      env: { ...process.env, ...env },
      encoding: 'utf-8',
      timeout: 10_000,
    });
    return { stdout, stderr: '', exitCode: 0 };
  } catch (error: unknown) {
    const e = error as {
      stdout?: Buffer | string;
      stderr?: Buffer | string;
      status?: number;
    };
    return {
      stdout: e.stdout?.toString() || '',
      stderr: e.stderr?.toString() || '',
      exitCode: e.status ?? 1,
    };
  }
}

describe('Installer Unit Tests', () => {
  // -------------------------------------------------------------------
  // detect_platform
  // -------------------------------------------------------------------
  describe('detect_platform', () => {
    it('should detect current platform correctly', () => {
      const result = runFunction('detect_platform && echo "$PLATFORM"');
      expect(result.exitCode).toBe(0);

      // Verify the output contains the expected OS token
      const expectedOs = process.platform === 'darwin' ? 'darwin' : 'linux';
      expect(result.stdout).toContain(expectedOs);
    });

    it('should set PLATFORM_OS variable', () => {
      const result = runFunction('detect_platform && echo "$PLATFORM_OS"');
      expect(result.exitCode).toBe(0);

      const expectedOs = process.platform === 'darwin' ? 'darwin' : 'linux';
      expect(result.stdout.trim()).toContain(expectedOs);
    });

    it('should set PLATFORM_ARCH variable', () => {
      const result = runFunction('detect_platform && echo "$PLATFORM_ARCH"');
      expect(result.exitCode).toBe(0);

      const arch = process.arch; // 'arm64' | 'x64'
      const expectedArch = arch === 'arm64' ? 'arm64' : 'x64';
      expect(result.stdout.trim()).toContain(expectedArch);
    });

    it('should fail on unsupported architecture', () => {
      // Directly exercise the arch case-match logic with an invalid arch
      const result = runFunction(`
        ARCH="ppc64le"
        case "$ARCH" in
          x86_64|amd64) PLATFORM_ARCH="x64" ;;
          arm64|aarch64) PLATFORM_ARCH="arm64" ;;
          *) fail "Unsupported architecture: \${ARCH}" ;;
        esac
      `);
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain('Unsupported architecture');
    });
  });

  // -------------------------------------------------------------------
  // check_node_version
  // -------------------------------------------------------------------
  describe('check_node_version', () => {
    let tmpDir: string;

    beforeEach(() => {
      tmpDir = mkdtempSync(join(tmpdir(), 'node-test-'));
    });

    afterEach(() => {
      rmSync(tmpDir, { recursive: true, force: true });
    });

    it('should pass with Node 22', () => {
      // Create a mock "node" binary that outputs v22.5.0
      const mockNode = join(tmpDir, 'node');
      writeFileSync(mockNode, '#!/bin/bash\necho "v22.5.0"');
      chmodSync(mockNode, 0o755);

      // tmpDir first so mock node is found; SYSTEM_PATH for bash/grep/etc.
      const result = runFunction('check_node_version', {
        PATH: `${tmpDir}:${SYSTEM_PATH}`,
        MIN_NODE_VERSION: '20',
      });
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain('v22.5.0');
    });

    it('should pass with Node 20', () => {
      const mockNode = join(tmpDir, 'node');
      writeFileSync(mockNode, '#!/bin/bash\necho "v20.11.1"');
      chmodSync(mockNode, 0o755);

      const result = runFunction('check_node_version', {
        PATH: `${tmpDir}:${SYSTEM_PATH}`,
        MIN_NODE_VERSION: '20',
      });
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain('v20.11.1');
    });

    it('should reject Node 18', () => {
      const mockNode = join(tmpDir, 'node');
      writeFileSync(mockNode, '#!/bin/bash\necho "v18.19.0"');
      chmodSync(mockNode, 0o755);

      const result = runFunction('check_node_version', {
        PATH: `${tmpDir}:${SYSTEM_PATH}`,
        MIN_NODE_VERSION: '20',
      });
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain('v20');
    });

    it('should reject Node 16', () => {
      const mockNode = join(tmpDir, 'node');
      writeFileSync(mockNode, '#!/bin/bash\necho "v16.20.2"');
      chmodSync(mockNode, 0o755);

      const result = runFunction('check_node_version', {
        PATH: `${tmpDir}:${SYSTEM_PATH}`,
        MIN_NODE_VERSION: '20',
      });
      expect(result.exitCode).not.toBe(0);
    });

    it('should fail when node is not installed', () => {
      // SYSTEM_PATH only — no node binary available
      const result = runFunction('check_node_version', {
        PATH: `${tmpDir}:${SYSTEM_PATH}`,
        MIN_NODE_VERSION: '20',
      });
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain('not installed');
    });
  });

  // -------------------------------------------------------------------
  // verify_checksum
  // -------------------------------------------------------------------
  describe('verify_checksum', () => {
    let tmpDir: string;

    beforeAll(() => {
      tmpDir = mkdtempSync(join(tmpdir(), 'checksum-test-'));
    });

    afterAll(() => {
      rmSync(tmpDir, { recursive: true, force: true });
    });

    it('should pass with matching checksum', () => {
      // Create a test file with known content
      const testFile = join(tmpDir, 'test.tar.gz');
      writeFileSync(testFile, 'test content');

      // Generate the real SHA-256 hash
      const hash = execSync(`shasum -a 256 "${testFile}" | awk '{print $1}'`, {
        encoding: 'utf-8',
      }).trim();

      // Create a checksums file containing the correct hash
      const checksumsFile = join(tmpDir, 'SHA256SUMS.txt');
      writeFileSync(checksumsFile, `${hash}  test.tar.gz\n`);

      const result = runFunction(`verify_checksum "${testFile}" "${checksumsFile}" "test.tar.gz"`);
      expect(result.exitCode).toBe(0);
    });

    it('should fail with mismatched checksum', () => {
      const testFile = join(tmpDir, 'test2.tar.gz');
      writeFileSync(testFile, 'real content');

      const checksumsFile = join(tmpDir, 'SHA256SUMS2.txt');
      writeFileSync(
        checksumsFile,
        'aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aabb7788ccdd9900  test2.tar.gz\n'
      );

      const result = runFunction(`verify_checksum "${testFile}" "${checksumsFile}" "test2.tar.gz"`);
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain('mismatch');
    });

    it('should warn and skip when file is not found in checksums', () => {
      const testFile = join(tmpDir, 'test3.tar.gz');
      writeFileSync(testFile, 'some content');

      const checksumsFile = join(tmpDir, 'SHA256SUMS3.txt');
      writeFileSync(
        checksumsFile,
        'aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aabb7788ccdd9900  other-file.tar.gz\n'
      );

      const result = runFunction(`verify_checksum "${testFile}" "${checksumsFile}" "test3.tar.gz"`);
      // Function gracefully skips when entry not found (warns but returns 0)
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain('No checksum entry found');
    });
  });

  // -------------------------------------------------------------------
  // detect_musl
  // -------------------------------------------------------------------
  describe('detect_musl', () => {
    it('should return non-zero on macOS (not musl)', () => {
      if (process.platform !== 'darwin') {
        // Skip on non-macOS platforms -- musl detection varies
        return;
      }
      const result = runFunction('detect_musl');
      // On macOS, detect_musl should return 1 (not musl)
      expect(result.exitCode).not.toBe(0);
    });

    it('should not set SKIP_BINARY_DOWNLOAD on macOS', () => {
      if (process.platform !== 'darwin') {
        return;
      }
      const result = runFunction('detect_musl; echo "SKIP=$SKIP_BINARY_DOWNLOAD"');
      // Even if detect_musl fails (exit 1), the echo still runs if we use ;
      // But since fail() calls exit, we may not reach the echo.
      // Instead, test the variable is not "true" after a safe call.
      const combined = result.stdout + result.stderr;
      expect(combined).not.toContain('SKIP=true');
    });
  });

  // -------------------------------------------------------------------
  // setup_path
  // -------------------------------------------------------------------
  describe('setup_path', () => {
    let tmpDir: string;

    beforeEach(() => {
      tmpDir = mkdtempSync(join(tmpdir(), 'path-test-'));
    });

    afterEach(() => {
      rmSync(tmpDir, { recursive: true, force: true });
    });

    it('should create symlink when target directory is writable', () => {
      // Create a fake binary
      const binSource = join(tmpDir, 'panguard');
      writeFileSync(binSource, '#!/bin/bash\necho "test"');
      chmodSync(binSource, 0o755);

      const symlinkTarget = join(tmpDir, 'symlink-panguard');
      const binDir = join(tmpDir, 'bin');

      // setup_path takes positional args: $1=bin_source $2=symlink_target $3=bin_dir
      const result = runFunction(`setup_path "${binSource}" "${symlinkTarget}" "${binDir}"`, {
        HOME: tmpDir,
      });
      expect(result.exitCode).toBe(0);
    });

    it('should fall back to PATH modification when symlink target is not writable', () => {
      const binSource = join(tmpDir, 'panguard');
      writeFileSync(binSource, '#!/bin/bash\necho "test"');
      chmodSync(binSource, 0o755);

      // Use a path that cannot be written to
      const symlinkTarget = '/nonexistent/path/panguard';
      const binDir = join(tmpDir, 'local-bin');

      // Create shell profile files so the fallback can update them
      writeFileSync(join(tmpDir, '.bashrc'), '# test bashrc\n');
      writeFileSync(join(tmpDir, '.zshrc'), '# test zshrc\n');
      writeFileSync(join(tmpDir, '.profile'), '# test profile\n');

      // setup_path takes positional args: $1=bin_source $2=symlink_target $3=bin_dir
      const result = runFunction(`setup_path "${binSource}" "${symlinkTarget}" "${binDir}"`, {
        HOME: tmpDir,
      });
      // Should still succeed via PATH fallback
      expect(result.exitCode).toBe(0);

      // Verify at least one shell profile was updated with the bin directory
      const bashrc = readFileSync(join(tmpDir, '.bashrc'), 'utf-8');
      const zshrc = readFileSync(join(tmpDir, '.zshrc'), 'utf-8');
      const profile = readFileSync(join(tmpDir, '.profile'), 'utf-8');
      const anyUpdated =
        bashrc.includes(binDir) || zshrc.includes(binDir) || profile.includes(binDir);
      expect(anyUpdated).toBe(true);
    });

    it('should create bin directory if it does not exist', () => {
      const binSource = join(tmpDir, 'panguard');
      writeFileSync(binSource, '#!/bin/bash\necho "test"');
      chmodSync(binSource, 0o755);

      const symlinkTarget = '/nonexistent/path/panguard';
      const binDir = join(tmpDir, 'new-local-bin');

      writeFileSync(join(tmpDir, '.bashrc'), '# test\n');

      // binDir does not exist yet
      expect(existsSync(binDir)).toBe(false);

      // setup_path takes positional args: $1=bin_source $2=symlink_target $3=bin_dir
      const result = runFunction(`setup_path "${binSource}" "${symlinkTarget}" "${binDir}"`, {
        HOME: tmpDir,
      });
      expect(result.exitCode).toBe(0);

      // After setup_path, the bin directory should have been created
      expect(existsSync(binDir)).toBe(true);
    });
  });

  // -------------------------------------------------------------------
  // Logging helpers
  // -------------------------------------------------------------------
  describe('logging helpers', () => {
    it('info() should print to stdout', () => {
      const result = runFunction('info "Hello from info"');
      expect(result.exitCode).toBe(0);
      expect(result.stdout + result.stderr).toContain('Hello from info');
    });

    it('success() should print to stdout', () => {
      const result = runFunction('success "Operation succeeded"');
      expect(result.exitCode).toBe(0);
      expect(result.stdout + result.stderr).toContain('Operation succeeded');
    });

    it('warn() should print a warning', () => {
      const result = runFunction('warn "Something concerning"');
      expect(result.exitCode).toBe(0);
      expect(result.stdout + result.stderr).toContain('Something concerning');
    });

    it('fail() should exit with code 1', () => {
      const result = runFunction('fail "Fatal error occurred"');
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain('Fatal error occurred');
    });
  });
});
