/**
 * Taiwan Information Security Management Act compliance mapping
 * 台灣資通安全管理法合規對照
 *
 * Maps security findings to relevant articles of the Taiwan ISMS
 * (Information Security Management System) framework.
 * 將安全發現對應到台灣資通安全管理法（ISMS）框架的相關條文。
 *
 * @module @panguard-ai/panguard-scan/report/compliance-map
 */

import type { Finding } from '../scanners/types.js';

/**
 * A single compliance framework entry
 * 單一合規框架條目
 */
export interface ComplianceEntry {
  /**
   * Article reference number (e.g. "4.1")
   * 條文參照編號（例如 "4.1"）
   */
  ref: string;

  /**
   * Article title in English
   * 條文標題（英文）
   */
  titleEn: string;

  /**
   * Article title in Traditional Chinese
   * 條文標題（繁體中文）
   */
  titleZh: string;

  /**
   * Article description in English
   * 條文描述（英文）
   */
  descriptionEn: string;

  /**
   * Article description in Traditional Chinese
   * 條文描述（繁體中文）
   */
  descriptionZh: string;

  /**
   * Finding categories that map to this article
   * 對應到此條文的發現分類
   */
  categories: string[];
}

/**
 * Compliance status for a single article with related findings
 * 單一條文的合規狀態及相關發現
 */
export interface ComplianceStatus extends ComplianceEntry {
  /**
   * Compliance status assessment
   * 合規狀態評估
   */
  status: 'compliant' | 'non_compliant' | 'partial' | 'not_applicable';

  /**
   * Security findings related to this article
   * 與此條文相關的安全發現
   */
  relatedFindings: Finding[];
}

/**
 * Taiwan ISMS compliance entries
 * 台灣資通安全管理法合規條目
 */
const COMPLIANCE_ENTRIES: ComplianceEntry[] = [
  {
    ref: '4.1',
    titleEn: 'Access Control',
    titleZh: '存取控制',
    descriptionEn:
      'Establish and enforce access control policies to restrict unauthorized access to information systems and data.',
    descriptionZh: '建立並執行存取控制政策，限制對資訊系統和資料的未經授權存取。',
    categories: ['password', 'access'],
  },
  {
    ref: '4.2',
    titleEn: 'System Protection',
    titleZh: '系統保護',
    descriptionEn:
      'Implement system-level protections including firewalls, intrusion detection, and endpoint security measures.',
    descriptionZh: '實施系統層級保護措施，包括防火牆、入侵偵測和端點安全措施。',
    categories: ['system', 'firewall'],
  },
  {
    ref: '4.3',
    titleEn: 'Network Security',
    titleZh: '網路安全',
    descriptionEn:
      'Secure network infrastructure through segmentation, monitoring, and traffic analysis.',
    descriptionZh: '透過網路分段、監控和流量分析來保護網路基礎設施。',
    categories: ['network'],
  },
  {
    ref: '4.4',
    titleEn: 'Encryption Management',
    titleZh: '加密管理',
    descriptionEn:
      'Apply appropriate encryption standards for data in transit and at rest, and manage certificates properly.',
    descriptionZh: '對傳輸中和靜態資料套用適當的加密標準，並妥善管理憑證。',
    categories: ['certificate'],
  },
  {
    ref: '4.5',
    titleEn: 'Authentication',
    titleZh: '身分驗證',
    descriptionEn:
      'Enforce strong authentication mechanisms including password policies and multi-factor authentication.',
    descriptionZh: '強制執行強健的身分驗證機制，包括密碼政策和多因素身分驗證。',
    categories: ['password', 'authentication'],
  },
  {
    ref: '4.6',
    titleEn: 'Monitoring',
    titleZh: '監控管理',
    descriptionEn:
      'Continuously monitor systems for security events, anomalies, and policy violations.',
    descriptionZh: '持續監控系統的安全事件、異常行為和政策違規。',
    categories: ['system', 'monitoring'],
  },
  {
    ref: '4.7',
    titleEn: 'Incident Response',
    titleZh: '事件應變',
    descriptionEn:
      'Establish procedures for detecting, reporting, and responding to security incidents.',
    descriptionZh: '建立偵測、報告和回應安全事件的程序。',
    categories: ['incident'],
  },
  {
    ref: '4.8',
    titleEn: 'Asset Management',
    titleZh: '資產管理',
    descriptionEn: 'Identify, classify, and manage information assets throughout their lifecycle.',
    descriptionZh: '在資訊資產的整個生命週期中進行識別、分類和管理。',
    categories: ['system', 'access'],
  },
  {
    ref: '4.9',
    titleEn: 'Update Management',
    titleZh: '更新管理',
    descriptionEn:
      'Maintain systems with timely security patches and software updates to address known vulnerabilities.',
    descriptionZh: '透過及時的安全修補和軟體更新來維護系統，以解決已知弱點。',
    categories: ['updates', 'system'],
  },
  {
    ref: '4.10',
    titleEn: 'Audit',
    titleZh: '稽核管理',
    descriptionEn:
      'Conduct regular security audits and maintain comprehensive audit logs for accountability.',
    descriptionZh: '定期進行安全稽核並維護完整的稽核日誌以確保可追溯性。',
    categories: ['audit', 'logging'],
  },
];

/**
 * Retrieve all compliance framework entries
 * 取得所有合規框架條目
 *
 * @returns Array of compliance entries / 合規條目陣列
 */
export function getComplianceEntries(): ComplianceEntry[] {
  return [...COMPLIANCE_ENTRIES];
}

/**
 * Map security findings to compliance framework articles
 * 將安全發現對應到合規框架條文
 *
 * Evaluates each compliance article against the provided findings to
 * determine compliance status. Articles with critical or high severity
 * findings are marked non-compliant; those with medium or low findings
 * are marked partial; articles with no related findings are marked
 * compliant; articles whose categories have no matching findings are
 * marked not-applicable when there are no findings at all in any
 * related category.
 *
 * 根據提供的發現評估每個合規條文以判定合規狀態。具有嚴重或高嚴重度發現的
 * 條文標記為不合規；具有中等或低嚴重度發現的標記為部分合規；沒有相關發現
 * 的條文標記為合規；當完全沒有任何相關分類的發現時標記為不適用。
 *
 * @param findings - Array of security findings / 安全發現陣列
 * @returns Array of compliance statuses / 合規狀態陣列
 */
export function mapFindingsToCompliance(findings: Finding[]): ComplianceStatus[] {
  return COMPLIANCE_ENTRIES.map((entry) => {
    const relatedFindings = findings.filter((f) => entry.categories.includes(f.category));

    let status: ComplianceStatus['status'];

    if (relatedFindings.length === 0) {
      // If no findings exist at all for these categories, mark as not applicable
      // when the scan did not cover them; otherwise compliant
      const hasAnyFindingInCategory = findings.some((f) => entry.categories.includes(f.category));
      status = hasAnyFindingInCategory ? 'compliant' : 'not_applicable';
    } else {
      const hasCriticalOrHigh = relatedFindings.some(
        (f) => f.severity === 'critical' || f.severity === 'high'
      );
      const hasMediumOrLow = relatedFindings.some(
        (f) => f.severity === 'medium' || f.severity === 'low'
      );

      if (hasCriticalOrHigh) {
        status = 'non_compliant';
      } else if (hasMediumOrLow) {
        status = 'partial';
      } else {
        // Only info-level findings
        status = 'compliant';
      }
    }

    return {
      ...entry,
      status,
      relatedFindings,
    };
  });
}
