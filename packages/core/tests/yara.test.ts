import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { YaraScanner } from '../src/rules/yara-scanner.js';
import { join } from 'node:path';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';

describe('YaraScanner', () => {
  let scanner: YaraScanner;
  let tempDir: string;
  let rulesDir: string;
  let testFilesDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'yara-test-'));
    rulesDir = join(tempDir, 'rules');
    testFilesDir = join(tempDir, 'files');
    mkdirSync(rulesDir, { recursive: true });
    mkdirSync(testFilesDir, { recursive: true });
    scanner = new YaraScanner();

    // Write a test YARA rule
    writeFileSync(
      join(rulesDir, 'test-webshell.yar'),
      `
rule PHP_Webshell_Generic {
  meta:
    description = "Detects generic PHP webshell patterns"
    severity = "high"
    mitre = "T1505.003"
  strings:
    $eval = "eval("
    $exec = "exec("
    $system = "system("
    $passthru = "passthru("
    $shell_exec = "shell_exec("
  condition:
    any of them
}

rule Suspicious_Base64 {
  meta:
    description = "Detects base64 encoded content"
    severity = "medium"
  strings:
    $b64 = "base64_decode("
    $b64_encode = "base64_encode("
  condition:
    any of them
}
`
    );
  });

  afterEach(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  });

  it('should load YARA rules from directory', async () => {
    const count = await scanner.loadRules(rulesDir);
    expect(count).toBe(1); // 1 .yar file
    expect(scanner.getRuleCount()).toBe(1);
  });

  it('should return 0 for empty directory', async () => {
    const emptyDir = join(tempDir, 'empty');
    mkdirSync(emptyDir);
    const count = await scanner.loadRules(emptyDir);
    expect(count).toBe(0);
  });

  it('should handle non-existent directory', async () => {
    const count = await scanner.loadRules(join(tempDir, 'nonexistent'));
    expect(count).toBe(0);
  });

  it('should detect webshell pattern in PHP file', async () => {
    await scanner.loadRules(rulesDir);

    const phpFile = join(testFilesDir, 'backdoor.php');
    writeFileSync(phpFile, '<?php eval($_POST["cmd"]); system("ls"); ?>');

    const result = await scanner.scanFile(phpFile);
    expect(result.matches.length).toBeGreaterThan(0);
    expect(result.matches[0].rule).toBe('PHP_Webshell_Generic');
    expect(result.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(result.fileSize).toBeGreaterThan(0);
  });

  it('should detect base64 pattern', async () => {
    await scanner.loadRules(rulesDir);

    const suspiciousFile = join(testFilesDir, 'encoded.php');
    writeFileSync(suspiciousFile, '<?php $data = base64_decode($input); ?>');

    const result = await scanner.scanFile(suspiciousFile);
    expect(result.matches.length).toBeGreaterThan(0);
    expect(result.matches.some((m) => m.rule === 'Suspicious_Base64')).toBe(true);
  });

  it('should return no matches for clean file', async () => {
    await scanner.loadRules(rulesDir);

    const cleanFile = join(testFilesDir, 'clean.txt');
    writeFileSync(cleanFile, 'This is a perfectly normal text file with no suspicious content.');

    const result = await scanner.scanFile(cleanFile);
    expect(result.matches.length).toBe(0);
    expect(result.sha256).toMatch(/^[a-f0-9]{64}$/);
  });

  it('should scan directory and find infected files', async () => {
    await scanner.loadRules(rulesDir);

    // Write mix of clean and infected
    writeFileSync(join(testFilesDir, 'clean.txt'), 'normal file');
    writeFileSync(join(testFilesDir, 'shell.php'), '<?php eval($_REQUEST["x"]); ?>');
    writeFileSync(join(testFilesDir, 'readme.md'), '# README');

    const results = await scanner.scanDirectory(testFilesDir);
    expect(results.length).toBe(1); // Only shell.php should match
    expect(results[0].filePath).toContain('shell.php');
  });

  it('should convert scan result to SecurityEvent', async () => {
    await scanner.loadRules(rulesDir);

    const malFile = join(testFilesDir, 'mal.php');
    writeFileSync(malFile, '<?php system("cat /etc/passwd"); ?>');

    const result = await scanner.scanFile(malFile);
    const event = scanner.toSecurityEvent(result);

    expect(event).not.toBeNull();
    expect(event!.source).toBe('file');
    expect(event!.category).toBe('malware_detection');
    expect(event!.severity).toBe('high');
    expect(event!.description).toContain('YARA match');
    const rawData = event!.raw as Record<string, unknown>;
    expect(rawData?.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(rawData?.mitreTechnique).toBe('T1505.003');
  });

  it('should return null SecurityEvent for clean file', async () => {
    await scanner.loadRules(rulesDir);

    const cleanFile = join(testFilesDir, 'clean.txt');
    writeFileSync(cleanFile, 'clean');

    const result = await scanner.scanFile(cleanFile);
    const event = scanner.toSecurityEvent(result);
    expect(event).toBeNull();
  });

  it('should include scan timing info', async () => {
    await scanner.loadRules(rulesDir);

    const file = join(testFilesDir, 'test.txt');
    writeFileSync(file, 'test content');

    const result = await scanner.scanFile(file);
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
    expect(result.scannedAt).toBeTruthy();
  });

  it('should skip node_modules and .git directories', async () => {
    await scanner.loadRules(rulesDir);

    const nmDir = join(testFilesDir, 'node_modules');
    mkdirSync(nmDir);
    writeFileSync(join(nmDir, 'evil.php'), '<?php eval("hack"); ?>');
    writeFileSync(join(testFilesDir, 'safe.txt'), 'clean');

    const results = await scanner.scanDirectory(testFilesDir);
    // node_modules should be skipped, so evil.php won't be found
    expect(results.every((r) => !r.filePath.includes('node_modules'))).toBe(true);
  });

  it('should loadAllRules from custom and community dirs', async () => {
    const communityDir = join(tempDir, 'community-rules');
    mkdirSync(communityDir, { recursive: true });

    writeFileSync(
      join(communityDir, 'community.yar'),
      `
rule Community_Ransomware {
  meta:
    description = "Community ransomware detection"
    severity = "critical"
  strings:
    $ransom = "Your files have been encrypted"
    $bitcoin = "bitcoin"
  condition:
    any of them
}
`
    );

    const total = await scanner.loadAllRules(rulesDir, communityDir);
    expect(total).toBe(2); // 1 custom + 1 community
    expect(scanner.getRuleCount()).toBe(2);
  });

  it('should loadAllRules with nested community subdirectories', async () => {
    const communityDir = join(tempDir, 'community-nested');
    mkdirSync(join(communityDir, 'apt'), { recursive: true });
    mkdirSync(join(communityDir, 'malware'), { recursive: true });

    writeFileSync(
      join(communityDir, 'apt', 'apt.yar'),
      `
rule APT_Tool {
  meta:
    description = "APT tool detection"
    severity = "critical"
  strings:
    $tool = "mimikatz"
  condition:
    any of them
}
`
    );

    writeFileSync(
      join(communityDir, 'malware', 'trojan.yar'),
      `
rule Trojan_Generic {
  meta:
    description = "Trojan detection"
    severity = "high"
  strings:
    $trojan = "CreateRemoteThread"
  condition:
    any of them
}
`
    );

    const total = await scanner.loadAllRules(rulesDir, communityDir);
    expect(total).toBe(3); // 1 custom + 2 community
  });

  it('should gracefully handle missing community directory in loadAllRules', async () => {
    const total = await scanner.loadAllRules(rulesDir, join(tempDir, 'nonexistent'));
    expect(total).toBe(1); // Only custom rules loaded
  });

  it('should include ruleSource in SecurityEvent from loadAllRules', async () => {
    const total = await scanner.loadAllRules(rulesDir);
    expect(total).toBe(1);

    const malFile = join(testFilesDir, 'mal.php');
    writeFileSync(malFile, '<?php system("cat /etc/passwd"); ?>');

    const result = await scanner.scanFile(malFile);
    const event = scanner.toSecurityEvent(result);
    expect(event).not.toBeNull();
    const rawData = event!.raw as Record<string, unknown>;
    expect(rawData?.ruleSource).toBe('custom');
  });
});
