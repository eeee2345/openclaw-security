/**
 * SOC 2 Trust Services Criteria Framework
 * SOC 2 信任服務準則合規框架
 *
 * Based on AICPA SOC 2 Trust Services Criteria.
 * 基於 AICPA SOC 2 信任服務準則。
 *
 * @module @panguard-ai/panguard-report/frameworks/soc2
 */

import type { ComplianceControl } from '../types.js';

/**
 * SOC 2 Trust Services Criteria controls
 * SOC 2 信任服務準則控制項
 */
export const SOC2_CONTROLS: ComplianceControl[] = [
  {
    controlId: 'CC6.1',
    category: 'logical_access',
    titleEn: 'Logical and Physical Access Controls',
    titleZh: '邏輯及實體存取控制',
    descriptionEn:
      'The entity implements logical access security software, infrastructure, and architectures over protected information assets.',
    descriptionZh: '組織在受保護的資訊資產上實施邏輯存取安全軟體、基礎設施及架構。',
    relatedCategories: ['access', 'authentication', 'password'],
  },
  {
    controlId: 'CC6.2',
    category: 'credentials',
    titleEn: 'User Registration and Authorization',
    titleZh: '使用者註冊及授權',
    descriptionEn:
      'Prior to issuing system credentials, the entity registers and authorizes new users.',
    descriptionZh: '在發放系統憑證前，組織註冊並授權新使用者。',
    relatedCategories: ['access', 'authentication', 'personnel'],
  },
  {
    controlId: 'CC6.3',
    category: 'access_management',
    titleEn: 'Access Removal and Modification',
    titleZh: '存取移除及修改',
    descriptionEn:
      'The entity removes access when no longer needed and reviews access periodically.',
    descriptionZh: '組織在不再需要時移除存取權限，並定期審查存取。',
    relatedCategories: ['access', 'audit'],
  },
  {
    controlId: 'CC6.6',
    category: 'boundary_protection',
    titleEn: 'System Boundary Protection',
    titleZh: '系統邊界保護',
    descriptionEn:
      'The entity implements boundary protection mechanisms to protect against threats at system boundaries.',
    descriptionZh: '組織實施邊界保護機制，以防範系統邊界的威脅。',
    relatedCategories: ['firewall', 'network', 'system'],
  },
  {
    controlId: 'CC6.7',
    category: 'data_transmission',
    titleEn: 'Transmission Encryption',
    titleZh: '傳輸加密',
    descriptionEn:
      'The entity restricts transmission, movement, and removal of information to authorized channels.',
    descriptionZh: '組織將資訊的傳輸、移動及移除限制在經授權的管道。',
    relatedCategories: ['encryption', 'certificate', 'tls', 'network'],
  },
  {
    controlId: 'CC7.1',
    category: 'monitoring',
    titleEn: 'Infrastructure and Software Monitoring',
    titleZh: '基礎設施及軟體監控',
    descriptionEn:
      'The entity monitors infrastructure and software to identify vulnerabilities and detect anomalies.',
    descriptionZh: '組織監控基礎設施及軟體以識別弱點並偵測異常。',
    relatedCategories: ['monitoring', 'vulnerability', 'system'],
  },
  {
    controlId: 'CC7.2',
    category: 'anomaly_detection',
    titleEn: 'Anomaly Detection',
    titleZh: '異常偵測',
    descriptionEn:
      'The entity monitors system components for anomalies indicating malicious acts or natural disasters.',
    descriptionZh: '組織監控系統元件的異常，指示惡意行為或自然災害。',
    relatedCategories: ['monitoring', 'incident', 'network'],
  },
  {
    controlId: 'CC7.3',
    category: 'incident_evaluation',
    titleEn: 'Security Event Evaluation',
    titleZh: '安全事件評估',
    descriptionEn:
      'The entity evaluates security events to determine if they constitute incidents.',
    descriptionZh: '組織評估安全事件以判定是否構成資安事件。',
    relatedCategories: ['incident', 'response', 'logging'],
  },
  {
    controlId: 'CC7.4',
    category: 'incident_response',
    titleEn: 'Incident Response',
    titleZh: '事件應變',
    descriptionEn:
      'The entity responds to identified security incidents by executing defined response program.',
    descriptionZh: '組織透過執行既定應變計畫回應已識別的安全事件。',
    relatedCategories: ['incident', 'response', 'notification'],
  },
  {
    controlId: 'CC8.1',
    category: 'change_management',
    titleEn: 'Change Management',
    titleZh: '變更管理',
    descriptionEn:
      'The entity authorizes, designs, develops, configures, documents, tests, approves and implements changes.',
    descriptionZh: '組織授權、設計、開發、配置、記錄、測試、核准並實施變更。',
    relatedCategories: ['system', 'updates', 'patch'],
  },
];
