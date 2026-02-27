/**
 * Report module unit tests for PanguardScan
 * PanguardScan 報告模組單元測試
 *
 * Validates styling constants, severity color mapping, compliance
 * framework helpers, and report module exports. Does NOT generate
 * actual PDF documents (pdfkit requires writable streams).
 * 驗證樣式常數、嚴重度顏色對應、合規框架輔助函式，以及報告模組匯出。
 * 不會產生實際的 PDF 文件（pdfkit 需要可寫入串流）。
 *
 * @module @panguard-ai/panguard-scan/tests/report
 */

import { describe, it, expect } from 'vitest';
import { COLORS, FONTS, LAYOUT, severityColor } from '../src/report/styles.js';
import { getComplianceEntries, mapFindingsToCompliance } from '../src/report/compliance-map.js';
import { generatePdfReport } from '../src/report/index.js';
import type { Finding } from '../src/scanners/types.js';

// ---------------------------------------------------------------------------
// styles.ts / 樣式常數
// ---------------------------------------------------------------------------

describe('COLORS constant', () => {
  /**
   * COLORS must expose the primary brand color.
   * COLORS 必須暴露主要品牌顏色。
   */
  it('should have a primary color property', () => {
    expect(COLORS).toHaveProperty('primary');
    expect(typeof COLORS.primary).toBe('string');
    expect(COLORS.primary).toMatch(/^#[0-9a-fA-F]{6}$/);
  });

  /**
   * COLORS must expose an accent color.
   * COLORS 必須暴露強調色。
   */
  it('should have an accent color property', () => {
    expect(COLORS).toHaveProperty('accent');
    expect(typeof COLORS.accent).toBe('string');
    expect(COLORS.accent).toMatch(/^#[0-9a-fA-F]{6}$/);
  });

  /**
   * COLORS must include all five severity-level colors (critical through info).
   * COLORS 必須包含所有五個嚴重等級顏色（critical 到 info）。
   */
  it('should include severity colors for critical, high, medium, low, and info', () => {
    expect(COLORS).toHaveProperty('critical');
    expect(COLORS).toHaveProperty('high');
    expect(COLORS).toHaveProperty('medium');
    expect(COLORS).toHaveProperty('low');
    expect(COLORS).toHaveProperty('info');
  });
});

describe('FONTS constant', () => {
  /**
   * FONTS must define heading, body, and mono font families.
   * FONTS 必須定義 heading、body 和 mono 字型家族。
   */
  it('should have heading, body, and mono properties', () => {
    expect(FONTS).toHaveProperty('heading');
    expect(FONTS).toHaveProperty('body');
    expect(FONTS).toHaveProperty('mono');

    expect(typeof FONTS.heading).toBe('string');
    expect(typeof FONTS.body).toBe('string');
    expect(typeof FONTS.mono).toBe('string');
  });
});

describe('LAYOUT constant', () => {
  /**
   * LAYOUT must define page width, page height, and margin for A4 format.
   * LAYOUT 必須定義 A4 格式的頁面寬度、頁面高度和邊距。
   */
  it('should have pageWidth, pageHeight, and margin properties', () => {
    expect(LAYOUT).toHaveProperty('pageWidth');
    expect(LAYOUT).toHaveProperty('pageHeight');
    expect(LAYOUT).toHaveProperty('margin');

    expect(typeof LAYOUT.pageWidth).toBe('number');
    expect(typeof LAYOUT.pageHeight).toBe('number');
    expect(typeof LAYOUT.margin).toBe('number');
  });

  /**
   * LAYOUT dimensions should be positive and margin smaller than page size.
   * LAYOUT 尺寸應為正數，且邊距小於頁面尺寸。
   */
  it('should have positive dimensions with margin smaller than page size', () => {
    expect(LAYOUT.pageWidth).toBeGreaterThan(0);
    expect(LAYOUT.pageHeight).toBeGreaterThan(0);
    expect(LAYOUT.margin).toBeGreaterThan(0);
    expect(LAYOUT.margin).toBeLessThan(LAYOUT.pageWidth);
    expect(LAYOUT.margin).toBeLessThan(LAYOUT.pageHeight);
  });
});

// ---------------------------------------------------------------------------
// severityColor helper / 嚴重度顏色輔助函式
// ---------------------------------------------------------------------------

describe('severityColor', () => {
  /**
   * Known severity levels should return the corresponding color from COLORS.
   * 已知嚴重等級應回傳 COLORS 中對應的顏色。
   */
  it('should return the correct color for critical severity', () => {
    expect(severityColor('critical')).toBe(COLORS.critical);
  });

  /**
   * An unrecognised severity string should return a fallback color.
   * 無法辨識的嚴重等級字串應回傳備用顏色。
   */
  it('should return a fallback color for unknown severity', () => {
    const fallback = severityColor('unknown');
    expect(typeof fallback).toBe('string');
    expect(fallback).toMatch(/^#[0-9a-fA-F]{6}$/);
    expect(fallback).toBe(COLORS.lightText);
  });
});

// ---------------------------------------------------------------------------
// compliance-map.ts / 合規對照
// ---------------------------------------------------------------------------

describe('getComplianceEntries', () => {
  /**
   * getComplianceEntries should return a non-empty array of entries.
   * getComplianceEntries 應回傳非空的條目陣列。
   */
  it('should return an array of compliance entries', () => {
    const entries = getComplianceEntries();

    expect(Array.isArray(entries)).toBe(true);
    expect(entries.length).toBeGreaterThan(0);
  });

  /**
   * Each entry should have the required shape (ref, titleEn, titleZh, categories).
   * 每個條目應具有必要的結構（ref、titleEn、titleZh、categories）。
   */
  it('should return entries with the expected shape', () => {
    const entries = getComplianceEntries();

    for (const entry of entries) {
      expect(entry).toHaveProperty('ref');
      expect(entry).toHaveProperty('titleEn');
      expect(entry).toHaveProperty('titleZh');
      expect(entry).toHaveProperty('categories');
      expect(Array.isArray(entry.categories)).toBe(true);
    }
  });
});

describe('mapFindingsToCompliance', () => {
  /**
   * When called with an empty findings array, every entry should be
   * marked as not_applicable because no categories were scanned.
   * 當以空的發現陣列呼叫時，每個條目都應標記為 not_applicable，
   * 因為沒有任何分類被掃描到。
   */
  it('should return 10 entries all marked not_applicable for empty findings', () => {
    const statuses = mapFindingsToCompliance([]);

    expect(statuses).toHaveLength(10);

    for (const status of statuses) {
      expect(status.status).toBe('not_applicable');
      expect(status.relatedFindings).toHaveLength(0);
    }
  });

  /**
   * A critical finding in the 'password' category should cause the
   * Access Control (4.1) and Authentication (4.5) articles to become
   * non_compliant while unrelated articles remain not_applicable.
   * 'password' 分類中的嚴重發現應導致存取控制（4.1）和身分驗證（4.5）
   * 條文變為不合規，而無關條文仍為不適用。
   */
  it('should mark related articles as non_compliant for critical findings', () => {
    const criticalPasswordFinding: Finding = {
      id: 'TEST-001',
      title: 'Weak password policy',
      description: 'Password policy does not meet minimum requirements.',
      severity: 'critical',
      category: 'password',
      remediation: 'Enforce stronger password policy.',
    };

    const statuses = mapFindingsToCompliance([criticalPasswordFinding]);

    const accessControl = statuses.find((s) => s.ref === '4.1');
    const authentication = statuses.find((s) => s.ref === '4.5');

    expect(accessControl).toBeDefined();
    expect(accessControl!.status).toBe('non_compliant');
    expect(accessControl!.relatedFindings.length).toBeGreaterThan(0);

    expect(authentication).toBeDefined();
    expect(authentication!.status).toBe('non_compliant');
  });
});

// ---------------------------------------------------------------------------
// report/index.ts exports / 報告模組匯出
// ---------------------------------------------------------------------------

describe('Report module exports', () => {
  /**
   * generatePdfReport should be exported as a function.
   * generatePdfReport 應以函式型別匯出。
   */
  it('should export generatePdfReport as a function', () => {
    expect(typeof generatePdfReport).toBe('function');
  });

  /**
   * getComplianceEntries should be exported as a function.
   * getComplianceEntries 應以函式型別匯出。
   */
  it('should export getComplianceEntries as a function', () => {
    expect(typeof getComplianceEntries).toBe('function');
  });

  /**
   * mapFindingsToCompliance should be exported as a function.
   * mapFindingsToCompliance 應以函式型別匯出。
   */
  it('should export mapFindingsToCompliance as a function', () => {
    expect(typeof mapFindingsToCompliance).toBe('function');
  });
});
