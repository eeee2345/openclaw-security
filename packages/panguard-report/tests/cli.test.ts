/**
 * PanguardReport CLI tests
 * PanguardReport CLI 測試
 */

import { describe, it, expect } from 'vitest';
import {
  parseCliArgs,
  buildConfigFromOptions,
  formatConfig,
  formatFrameworkList,
  getHelpText,
} from '../src/cli/index.js';

describe('PanguardReport CLI', () => {
  describe('parseCliArgs', () => {
    it('should default to help command', () => {
      const options = parseCliArgs([]);
      expect(options.command).toBe('help');
    });

    it('should parse generate command', () => {
      const options = parseCliArgs(['generate']);
      expect(options.command).toBe('generate');
    });

    it('should parse list-frameworks command', () => {
      const options = parseCliArgs(['list-frameworks']);
      expect(options.command).toBe('list-frameworks');
    });

    it('should parse validate command', () => {
      const options = parseCliArgs(['validate']);
      expect(options.command).toBe('validate');
    });

    it('should parse summary command', () => {
      const options = parseCliArgs(['summary']);
      expect(options.command).toBe('summary');
    });

    it('should parse config command', () => {
      const options = parseCliArgs(['config']);
      expect(options.command).toBe('config');
    });

    it('should parse --framework option', () => {
      const options = parseCliArgs(['generate', '--framework', 'iso27001']);
      expect(options.framework).toBe('iso27001');
    });

    it('should parse --language option', () => {
      const options = parseCliArgs(['generate', '--language', 'en']);
      expect(options.language).toBe('en');
    });

    it('should parse --format option', () => {
      const options = parseCliArgs(['generate', '--format', 'pdf']);
      expect(options.format).toBe('pdf');
    });

    it('should parse --output-dir option', () => {
      const options = parseCliArgs(['generate', '--output-dir', '/tmp/reports']);
      expect(options.outputDir).toBe('/tmp/reports');
    });

    it('should parse --org option', () => {
      const options = parseCliArgs(['generate', '--org', 'ACME Corp']);
      expect(options.organizationName).toBe('ACME Corp');
    });

    it('should parse --input option', () => {
      const options = parseCliArgs(['generate', '--input', 'findings.json']);
      expect(options.inputFile).toBe('findings.json');
    });

    it('should parse --verbose flag', () => {
      const options = parseCliArgs(['generate', '--verbose']);
      expect(options.verbose).toBe(true);
    });

    it('should parse -v flag', () => {
      const options = parseCliArgs(['generate', '-v']);
      expect(options.verbose).toBe(true);
    });

    it('should parse multiple options', () => {
      const options = parseCliArgs([
        'generate',
        '--framework',
        'soc2',
        '--language',
        'zh-TW',
        '--format',
        'json',
        '--org',
        'TestCo',
        '--input',
        'scan.json',
        '-v',
      ]);
      expect(options.command).toBe('generate');
      expect(options.framework).toBe('soc2');
      expect(options.language).toBe('zh-TW');
      expect(options.format).toBe('json');
      expect(options.organizationName).toBe('TestCo');
      expect(options.inputFile).toBe('scan.json');
      expect(options.verbose).toBe(true);
    });
  });

  describe('buildConfigFromOptions', () => {
    it('should use defaults when no options provided', () => {
      const config = buildConfigFromOptions({ command: 'generate' });
      expect(config.language).toBe('zh-TW');
      expect(config.framework).toBe('tw_cyber_security_act');
      expect(config.format).toBe('json');
    });

    it('should override framework', () => {
      const config = buildConfigFromOptions({
        command: 'generate',
        framework: 'iso27001',
      });
      expect(config.framework).toBe('iso27001');
    });

    it('should override language', () => {
      const config = buildConfigFromOptions({
        command: 'generate',
        language: 'en',
      });
      expect(config.language).toBe('en');
    });

    it('should override format', () => {
      const config = buildConfigFromOptions({
        command: 'generate',
        format: 'pdf',
      });
      expect(config.format).toBe('pdf');
    });

    it('should override output directory', () => {
      const config = buildConfigFromOptions({
        command: 'generate',
        outputDir: '/custom/path',
      });
      expect(config.outputDir).toBe('/custom/path');
    });

    it('should set organization name', () => {
      const config = buildConfigFromOptions({
        command: 'generate',
        organizationName: 'Test Corp',
      });
      expect(config.organizationName).toBe('Test Corp');
    });
  });

  describe('formatConfig', () => {
    it('should format config with all fields', () => {
      const config = buildConfigFromOptions({
        command: 'config',
        framework: 'iso27001',
        language: 'en',
        organizationName: 'ACME',
      });
      const output = formatConfig(config);
      expect(output).toContain('PanguardReport Configuration');
      expect(output).toContain('iso27001');
      expect(output).toContain('en');
      expect(output).toContain('ACME');
    });

    it('should omit organization when not set', () => {
      const config = buildConfigFromOptions({ command: 'config' });
      const output = formatConfig(config);
      expect(output).not.toContain('Organization');
    });
  });

  describe('formatFrameworkList', () => {
    it('should list all frameworks', () => {
      const output = formatFrameworkList();
      expect(output).toContain('tw_cyber_security_act');
      expect(output).toContain('iso27001');
      expect(output).toContain('soc2');
    });

    it('should include bilingual names', () => {
      const output = formatFrameworkList();
      expect(output).toContain('資通安全管理法');
      expect(output).toContain('ISO/IEC 27001');
      expect(output).toContain('Trust Services Criteria');
    });
  });

  describe('getHelpText', () => {
    it('should include product name', () => {
      const help = getHelpText();
      expect(help).toContain('PanguardReport');
      expect(help).toContain('Panguard AI');
    });

    it('should list all commands', () => {
      const help = getHelpText();
      expect(help).toContain('generate');
      expect(help).toContain('list-frameworks');
      expect(help).toContain('validate');
      expect(help).toContain('summary');
      expect(help).toContain('config');
      expect(help).toContain('help');
    });

    it('should list all options', () => {
      const help = getHelpText();
      expect(help).toContain('--framework');
      expect(help).toContain('--language');
      expect(help).toContain('--format');
      expect(help).toContain('--output-dir');
      expect(help).toContain('--org');
      expect(help).toContain('--input');
      expect(help).toContain('--verbose');
    });

    it('should include examples', () => {
      const help = getHelpText();
      expect(help).toContain('panguard-report generate');
    });

    it('should include bilingual descriptions', () => {
      const help = getHelpText();
      expect(help).toContain('產生合規報告');
    });
  });
});
