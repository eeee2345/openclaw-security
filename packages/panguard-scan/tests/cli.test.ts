/**
 * CLI module unit tests for PanguardScan
 * PanguardScan CLI 模組單元測試
 *
 * Validates package exports, constant values, type structures,
 * and the severity sorting utility without executing the actual CLI.
 * 驗證套件匯出、常數值、型別結構，以及嚴重度排序工具函式，
 * 不會實際執行 CLI。
 *
 * @module @panguard-ai/panguard-scan/tests/cli
 */

import { describe, it, expect } from 'vitest';
import {
  PANGUARD_SCAN_VERSION,
  CLAWSCAN_NAME,
  sortBySeverity,
  SEVERITY_ORDER,
  runScan,
  generatePdfReport,
} from '../src/index.js';
import type { ScanConfig, Finding } from '../src/scanners/types.js';

// ---------------------------------------------------------------------------
// Helpers / 輔助工具
// ---------------------------------------------------------------------------

/**
 * Create a minimal Finding stub for testing sort logic.
 * 建立最小的 Finding 測試替身以測試排序邏輯。
 *
 * @param id - Unique identifier / 唯一識別碼
 * @param severity - Severity level string / 嚴重等級字串
 * @returns A Finding object with only the fields required for sorting /
 *          僅包含排序所需欄位的 Finding 物件
 */
function makeFinding(id: string, severity: string): Finding {
  return {
    id,
    title: `Finding ${id}`,
    description: `Description for ${id}`,
    severity: severity as Finding['severity'],
    category: 'test',
    remediation: 'N/A',
  };
}

// ---------------------------------------------------------------------------
// Tests / 測試
// ---------------------------------------------------------------------------

describe('PanguardScan index exports', () => {
  /**
   * Verify the published version string matches the expected value.
   * 驗證發佈的版本字串符合預期值。
   */
  it('PANGUARD_SCAN_VERSION should be a semver string', () => {
    expect(PANGUARD_SCAN_VERSION).toMatch(/^\d+\.\d+\.\d+/);
  });

  /**
   * Verify the product name constant is correct.
   * 驗證產品名稱常數正確。
   */
  it('CLAWSCAN_NAME should be PanguardScan', () => {
    expect(CLAWSCAN_NAME).toBe('PanguardScan');
  });
});

describe('ScanConfig type validation', () => {
  /**
   * A minimal ScanConfig with depth 'quick' and lang 'en' should be valid.
   * 具有 depth 'quick' 和 lang 'en' 的最小 ScanConfig 應為有效。
   */
  it('should accept a valid quick/en config', () => {
    const config: ScanConfig = {
      depth: 'quick',
      lang: 'en',
    };

    expect(config.depth).toBe('quick');
    expect(config.lang).toBe('en');
    expect(config.output).toBeUndefined();
    expect(config.verbose).toBeUndefined();
  });

  /**
   * A fully-populated ScanConfig with all optional fields should be valid.
   * 包含所有可選欄位的完整 ScanConfig 應為有效。
   */
  it('should accept a full config with depth full, lang zh-TW, output, and verbose', () => {
    const config: ScanConfig = {
      depth: 'full',
      lang: 'zh-TW',
      output: '/tmp/report.pdf',
      verbose: true,
    };

    expect(config.depth).toBe('full');
    expect(config.lang).toBe('zh-TW');
    expect(config.output).toBe('/tmp/report.pdf');
    expect(config.verbose).toBe(true);
  });
});

describe('SEVERITY_ORDER constant', () => {
  /**
   * SEVERITY_ORDER must contain exactly 5 entries covering all severity levels.
   * SEVERITY_ORDER 必須包含恰好 5 個條目，涵蓋所有嚴重等級。
   */
  it('should have exactly 5 entries', () => {
    expect(Object.keys(SEVERITY_ORDER)).toHaveLength(5);
  });

  /**
   * All expected severity keys must be present with correct relative ordering.
   * 所有預期的嚴重等級鍵必須存在，且具有正確的相對排序。
   */
  it('should contain critical, high, medium, low, and info in ascending order', () => {
    expect(SEVERITY_ORDER).toHaveProperty('critical');
    expect(SEVERITY_ORDER).toHaveProperty('high');
    expect(SEVERITY_ORDER).toHaveProperty('medium');
    expect(SEVERITY_ORDER).toHaveProperty('low');
    expect(SEVERITY_ORDER).toHaveProperty('info');

    expect(SEVERITY_ORDER['critical']).toBeLessThan(SEVERITY_ORDER['high']);
    expect(SEVERITY_ORDER['high']).toBeLessThan(SEVERITY_ORDER['medium']);
    expect(SEVERITY_ORDER['medium']).toBeLessThan(SEVERITY_ORDER['low']);
    expect(SEVERITY_ORDER['low']).toBeLessThan(SEVERITY_ORDER['info']);
  });
});

describe('sortBySeverity', () => {
  /**
   * Sorting an array of findings should place critical items before low items.
   * 對發現陣列排序時，嚴重項目應排在低嚴重度項目之前。
   */
  it('should sort findings from most severe to least severe', () => {
    const findings: Finding[] = [
      makeFinding('F-LOW', 'low'),
      makeFinding('F-CRITICAL', 'critical'),
      makeFinding('F-MEDIUM', 'medium'),
      makeFinding('F-INFO', 'info'),
      makeFinding('F-HIGH', 'high'),
    ];

    const sorted = [...findings].sort(sortBySeverity);

    expect(sorted[0].id).toBe('F-CRITICAL');
    expect(sorted[1].id).toBe('F-HIGH');
    expect(sorted[2].id).toBe('F-MEDIUM');
    expect(sorted[3].id).toBe('F-LOW');
    expect(sorted[4].id).toBe('F-INFO');
  });

  /**
   * Findings with an unrecognised severity should be placed after known levels.
   * 具有無法辨識嚴重等級的發現應排在已知等級之後。
   */
  it('should place unknown severity after info', () => {
    const known = makeFinding('F-INFO', 'info');
    const unknown = makeFinding('F-UNKNOWN', 'alien');

    const result = sortBySeverity(known, unknown);
    expect(result).toBeLessThan(0);
  });
});

describe('Module exports completeness', () => {
  /**
   * The main index module should export all key public symbols as the
   * correct types (functions, constants).
   * 主要 index 模組應以正確型別（函式、常數）匯出所有關鍵公開符號。
   */
  it('should export runScan as a function', () => {
    expect(typeof runScan).toBe('function');
  });

  it('should export generatePdfReport as a function', () => {
    expect(typeof generatePdfReport).toBe('function');
  });

  it('should export sortBySeverity as a function', () => {
    expect(typeof sortBySeverity).toBe('function');
  });

  it('should export SEVERITY_ORDER as an object', () => {
    expect(typeof SEVERITY_ORDER).toBe('object');
    expect(SEVERITY_ORDER).not.toBeNull();
  });
});
