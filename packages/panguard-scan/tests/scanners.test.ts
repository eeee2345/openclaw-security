/**
 * PanguardScan scanner module unit tests
 * PanguardScan 掃描器模組單元測試
 *
 * Tests for scanner types, open-ports checker, scanner orchestrator exports,
 * and compliance mapping logic.
 * 測試掃描器型別、開放埠檢查器、掃描器編排器匯出和合規對照邏輯。
 *
 * @module @panguard-ai/panguard-scan/tests/scanners
 */

import { describe, it, expect } from 'vitest';
import { sortBySeverity, SEVERITY_ORDER } from '../src/scanners/types.js';
import type { Finding } from '../src/scanners/types.js';
import { checkUnnecessaryPorts } from '../src/scanners/open-ports.js';
import {
  SCANNERS_VERSION,
  checkUnnecessaryPorts as reExportedCheckPorts,
} from '../src/scanners/index.js';
import { getComplianceEntries, mapFindingsToCompliance } from '../src/report/compliance-map.js';
import type { PortInfo } from '@panguard-ai/core';

// ---------------------------------------------------------------------------
// Helper: create a minimal Finding for testing
// 輔助函式：建立用於測試的最小 Finding 物件
// ---------------------------------------------------------------------------

/**
 * Create a Finding with sensible defaults for test purposes
 * 為測試目的建立具有合理預設值的 Finding
 *
 * @param overrides - Partial fields to override / 要覆寫的部分欄位
 * @returns A complete Finding object / 完整的 Finding 物件
 */
function makeFinding(overrides: Partial<Finding> & { severity: Finding['severity'] }): Finding {
  return {
    id: overrides.id ?? 'TEST-001',
    title: overrides.title ?? 'Test finding',
    description: overrides.description ?? 'A test finding for unit tests',
    severity: overrides.severity,
    category: overrides.category ?? 'system',
    remediation: overrides.remediation ?? 'Fix the issue',
    complianceRef: overrides.complianceRef,
    details: overrides.details,
  };
}

/**
 * Create a PortInfo with sensible defaults for test purposes
 * 為測試目的建立具有合理預設值的 PortInfo
 *
 * @param port - Port number / 埠號
 * @param overrides - Partial fields to override / 要覆寫的部分欄位
 * @returns A complete PortInfo object / 完整的 PortInfo 物件
 */
function makePort(port: number, overrides?: Partial<PortInfo>): PortInfo {
  return {
    port,
    protocol: overrides?.protocol ?? 'tcp',
    state: overrides?.state ?? 'LISTEN',
    pid: overrides?.pid ?? undefined,
    process: overrides?.process ?? '',
    service: overrides?.service ?? '',
  };
}

// ===========================================================================
// types.ts - sortBySeverity / SEVERITY_ORDER
// types.ts - 按嚴重度排序 / 嚴重度順序
// ===========================================================================

describe('types.ts - sortBySeverity and SEVERITY_ORDER', () => {
  /**
   * Verify that sortBySeverity places critical findings before high and
   * high before medium when used with Array.prototype.sort.
   * 驗證 sortBySeverity 將嚴重發現排在高之前，高排在中之前。
   */
  it('should sort critical before high before medium', () => {
    const findings: Finding[] = [
      makeFinding({ severity: 'medium', id: 'F-MED' }),
      makeFinding({ severity: 'critical', id: 'F-CRIT' }),
      makeFinding({ severity: 'high', id: 'F-HIGH' }),
    ];

    const sorted = [...findings].sort(sortBySeverity);

    expect(sorted[0].severity).toBe('critical');
    expect(sorted[1].severity).toBe('high');
    expect(sorted[2].severity).toBe('medium');
  });

  /**
   * Verify the numeric values in SEVERITY_ORDER match the expected
   * mapping: critical=0, high=1, medium=2, low=3, info=4.
   * 驗證 SEVERITY_ORDER 中的數值對應：critical=0、high=1、medium=2、low=3、info=4。
   */
  it('should have correct SEVERITY_ORDER values (0-4)', () => {
    expect(SEVERITY_ORDER['critical']).toBe(0);
    expect(SEVERITY_ORDER['high']).toBe(1);
    expect(SEVERITY_ORDER['medium']).toBe(2);
    expect(SEVERITY_ORDER['low']).toBe(3);
    expect(SEVERITY_ORDER['info']).toBe(4);
  });

  /**
   * Verify that an unknown severity string defaults to order value 5,
   * placing it after all known severities.
   * 驗證未知的嚴重度字串預設為順序值 5，排在所有已知嚴重度之後。
   */
  it('should default unknown severity to 5', () => {
    const known = makeFinding({ severity: 'info', id: 'F-INFO' });
    const unknown = makeFinding({ severity: 'unknown' as Finding['severity'], id: 'F-UNK' });

    const result = sortBySeverity(unknown, known);

    // unknown (5) - info (4) = 1 => unknown sorts after info
    expect(result).toBeGreaterThan(0);
  });
});

// ===========================================================================
// open-ports.ts - checkUnnecessaryPorts
// open-ports.ts - 檢查不必要的開放埠
// ===========================================================================

describe('open-ports.ts - checkUnnecessaryPorts', () => {
  /**
   * An empty port list should produce zero findings.
   * 空的埠列表應該產生零個發現。
   */
  it('should return empty array for no ports', () => {
    const findings = checkUnnecessaryPorts([]);
    expect(findings).toEqual([]);
  });

  /**
   * FTP (port 21) is an unencrypted file transfer protocol and should
   * be flagged as a risky finding.
   * FTP（埠 21）是未加密的檔案傳輸協定，應被標記為風險發現。
   */
  it('should detect FTP port 21 as risky', () => {
    const findings = checkUnnecessaryPorts([makePort(21)]);

    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('SCAN-PORT-21');
    expect(findings[0].severity).toBe('critical');
  });

  /**
   * Telnet (port 23) is an unencrypted remote access protocol and should
   * be flagged as a risky finding.
   * Telnet（埠 23）是未加密的遠端存取協定，應被標記為風險發現。
   */
  it('should detect Telnet port 23 as risky', () => {
    const findings = checkUnnecessaryPorts([makePort(23)]);

    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('SCAN-PORT-23');
    expect(findings[0].severity).toBe('critical');
  });

  /**
   * RDP (port 3389) should be flagged as high severity due to brute force
   * and BlueKeep vulnerability risks.
   * RDP（埠 3389）因暴力破解和 BlueKeep 弱點風險應被標記為高嚴重度。
   */
  it('should detect RDP port 3389 as risky', () => {
    const findings = checkUnnecessaryPorts([makePort(3389)]);

    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('SCAN-PORT-3389');
    expect(findings[0].severity).toBe('high');
  });

  /**
   * HTTPS (port 443) is a standard safe port and should not produce
   * any findings.
   * HTTPS（埠 443）是標準安全埠，不應產生任何發現。
   */
  it('should not flag safe ports like 443', () => {
    const findings = checkUnnecessaryPorts([makePort(443)]);
    expect(findings).toHaveLength(0);
  });

  /**
   * Each returned Finding should have the complete structure with
   * all required fields populated correctly.
   * 每個回傳的 Finding 應具有完整結構，所有必要欄位正確填入。
   */
  it('should return proper Finding structure with correct fields', () => {
    const findings = checkUnnecessaryPorts([makePort(21, { process: 'vsftpd', pid: 1234 })]);

    expect(findings).toHaveLength(1);
    const f = findings[0];

    expect(f).toHaveProperty('id');
    expect(f).toHaveProperty('title');
    expect(f).toHaveProperty('description');
    expect(f).toHaveProperty('severity');
    expect(f).toHaveProperty('category');
    expect(f).toHaveProperty('remediation');
    expect(f).toHaveProperty('complianceRef');
    expect(f).toHaveProperty('details');

    expect(f.id).toBe('SCAN-PORT-21');
    expect(f.category).toBe('network');
    expect(f.complianceRef).toBe('4.3');
    expect(f.title).toContain('FTP');
    expect(f.details).toContain('1234');
  });
});

// ===========================================================================
// scanners/index.ts - Orchestrator exports
// scanners/index.ts - 編排器匯出
// ===========================================================================

describe('scanners/index.ts - orchestrator exports', () => {
  /**
   * SCANNERS_VERSION should be a defined, non-empty string indicating
   * the current scanner modules version.
   * SCANNERS_VERSION 應為已定義的非空字串，表示目前掃描器模組版本。
   */
  it('should have SCANNERS_VERSION defined as a non-empty string', () => {
    expect(SCANNERS_VERSION).toBeDefined();
    expect(typeof SCANNERS_VERSION).toBe('string');
    expect(SCANNERS_VERSION.length).toBeGreaterThan(0);
  });

  /**
   * The scanners/index.ts barrel should re-export checkUnnecessaryPorts
   * so consumers can import it from the orchestrator module.
   * scanners/index.ts 桶檔案應重新匯出 checkUnnecessaryPorts，
   * 以便使用者可以從編排器模組匯入。
   */
  it('should re-export checkUnnecessaryPorts', () => {
    expect(reExportedCheckPorts).toBeDefined();
    expect(typeof reExportedCheckPorts).toBe('function');
  });
});

// ===========================================================================
// compliance-map.ts - getComplianceEntries / mapFindingsToCompliance
// compliance-map.ts - 取得合規條目 / 將發現對應至合規
// ===========================================================================

describe('compliance-map.ts - getComplianceEntries', () => {
  /**
   * The compliance framework should contain exactly 10 entries
   * covering articles 4.1 through 4.10.
   * 合規框架應包含恰好 10 個條目，涵蓋條文 4.1 至 4.10。
   */
  it('should return exactly 10 compliance entries', () => {
    const entries = getComplianceEntries();
    expect(entries).toHaveLength(10);
  });

  /**
   * Every compliance entry must have the required structural fields:
   * ref, titleEn, titleZh, descriptionEn, descriptionZh, and categories.
   * 每個合規條目必須具有必要的結構欄位：
   * ref、titleEn、titleZh、descriptionEn、descriptionZh 和 categories。
   */
  it('should have all required fields on each entry', () => {
    const entries = getComplianceEntries();

    for (const entry of entries) {
      expect(entry).toHaveProperty('ref');
      expect(entry).toHaveProperty('titleEn');
      expect(entry).toHaveProperty('titleZh');
      expect(entry).toHaveProperty('descriptionEn');
      expect(entry).toHaveProperty('descriptionZh');
      expect(entry).toHaveProperty('categories');
      expect(Array.isArray(entry.categories)).toBe(true);
    }
  });

  /**
   * All article reference numbers should begin with "4." per the
   * Taiwan ISMS framework numbering convention.
   * 所有條文參照編號應以 "4." 開頭，符合台灣資通安全管理法編號慣例。
   */
  it('should have all refs starting with "4."', () => {
    const entries = getComplianceEntries();

    for (const entry of entries) {
      expect(entry.ref).toMatch(/^4\./);
    }
  });

  /**
   * Both English and Traditional Chinese title/description fields
   * must be non-empty strings to support bilingual output.
   * 英文和繁體中文的標題/描述欄位都必須是非空字串，以支援雙語輸出。
   */
  it('should have non-empty en and zh string fields', () => {
    const entries = getComplianceEntries();

    for (const entry of entries) {
      expect(typeof entry.titleEn).toBe('string');
      expect(entry.titleEn.length).toBeGreaterThan(0);
      expect(typeof entry.titleZh).toBe('string');
      expect(entry.titleZh.length).toBeGreaterThan(0);
      expect(typeof entry.descriptionEn).toBe('string');
      expect(entry.descriptionEn.length).toBeGreaterThan(0);
      expect(typeof entry.descriptionZh).toBe('string');
      expect(entry.descriptionZh.length).toBeGreaterThan(0);
    }
  });
});

describe('compliance-map.ts - mapFindingsToCompliance', () => {
  /**
   * When no findings are provided, every compliance article should
   * have a status of 'not_applicable' since no scan categories matched.
   * 當沒有提供發現時，每個合規條文的狀態應為 'not_applicable'，
   * 因為沒有掃描分類匹配。
   */
  it('should mark all entries as not_applicable when no findings exist', () => {
    const statuses = mapFindingsToCompliance([]);

    expect(statuses).toHaveLength(10);
    for (const status of statuses) {
      expect(status.status).toBe('not_applicable');
    }
  });

  /**
   * A critical-severity finding in the 'password' category should cause
   * articles 4.1 (Access Control) and 4.5 (Authentication) to be
   * marked as non_compliant, since both map to the 'password' category.
   * 'password' 分類中的嚴重等級發現應使條文 4.1（存取控制）和
   * 4.5（身分驗證）被標記為 non_compliant，因為兩者都對應到 'password' 分類。
   */
  it('should mark 4.1 and 4.5 as non_compliant for critical password finding', () => {
    const findings: Finding[] = [
      makeFinding({
        severity: 'critical',
        category: 'password',
        id: 'PWD-001',
        title: 'Weak password policy detected',
      }),
    ];

    const statuses = mapFindingsToCompliance(findings);
    const status41 = statuses.find((s) => s.ref === '4.1');
    const status45 = statuses.find((s) => s.ref === '4.5');

    expect(status41).toBeDefined();
    expect(status41!.status).toBe('non_compliant');
    expect(status41!.relatedFindings).toHaveLength(1);

    expect(status45).toBeDefined();
    expect(status45!.status).toBe('non_compliant');
    expect(status45!.relatedFindings).toHaveLength(1);
  });

  /**
   * A medium-severity finding in the 'network' category should cause
   * article 4.3 (Network Security) to be marked as 'partial' compliance.
   * 'network' 分類中的中等嚴重度發現應使條文 4.3（網路安全）
   * 被標記為 'partial'（部分合規）。
   */
  it('should mark 4.3 as partial for medium network finding', () => {
    const findings: Finding[] = [
      makeFinding({
        severity: 'medium',
        category: 'network',
        id: 'NET-001',
        title: 'Open port detected',
      }),
    ];

    const statuses = mapFindingsToCompliance(findings);
    const status43 = statuses.find((s) => s.ref === '4.3');

    expect(status43).toBeDefined();
    expect(status43!.status).toBe('partial');
    expect(status43!.relatedFindings).toHaveLength(1);
  });

  /**
   * An info-severity finding in a matched category should result in
   * 'compliant' status, since info-level issues do not indicate
   * non-compliance.
   * 匹配分類中的資訊嚴重度發現應導致 'compliant' 狀態，
   * 因為資訊等級問題不表示不合規。
   */
  it('should mark as compliant for info-only finding in matching category', () => {
    const findings: Finding[] = [
      makeFinding({
        severity: 'info',
        category: 'network',
        id: 'NET-INFO-001',
        title: 'Network scan completed',
      }),
    ];

    const statuses = mapFindingsToCompliance(findings);
    const status43 = statuses.find((s) => s.ref === '4.3');

    expect(status43).toBeDefined();
    expect(status43!.status).toBe('compliant');
    expect(status43!.relatedFindings).toHaveLength(1);
  });
});
