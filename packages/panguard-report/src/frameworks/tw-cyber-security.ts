/**
 * Taiwan Cyber Security Management Act Framework
 * 台灣資通安全管理法合規框架
 *
 * Based on the Cyber Security Management Act (資通安全管理法)
 * and its enforcement rules.
 * 基於資通安全管理法及其施行細則。
 *
 * @module @panguard-ai/panguard-report/frameworks/tw-cyber-security
 */

import type { ComplianceControl } from '../types.js';

/**
 * Taiwan Cyber Security Management Act controls
 * 資通安全管理法控制項
 */
export const TW_CYBER_SECURITY_CONTROLS: ComplianceControl[] = [
  {
    controlId: 'TWCS-4.1',
    category: 'access_control',
    titleEn: 'Access Control and Identity Management',
    titleZh: '存取控制及身分管理',
    descriptionEn:
      'Establish access control mechanisms to ensure only authorized personnel can access information systems.',
    descriptionZh: '建立存取控制機制，確保僅經授權人員得存取資通系統。',
    relatedCategories: ['password', 'access', 'authentication'],
  },
  {
    controlId: 'TWCS-4.2',
    category: 'system_protection',
    titleEn: 'System and Communication Protection',
    titleZh: '系統與通訊保護',
    descriptionEn:
      'Implement system protection measures including firewall, intrusion detection, and secure communication.',
    descriptionZh: '實施系統保護措施，包括防火牆、入侵偵測及安全通訊。',
    relatedCategories: ['firewall', 'network', 'system'],
  },
  {
    controlId: 'TWCS-4.3',
    category: 'network_security',
    titleEn: 'Network Security Management',
    titleZh: '網路安全管理',
    descriptionEn:
      'Manage network security including network segmentation, monitoring, and access restrictions.',
    descriptionZh: '管理網路安全，包括網路分段、監控及存取限制。',
    relatedCategories: ['network', 'monitoring'],
  },
  {
    controlId: 'TWCS-4.4',
    category: 'encryption',
    titleEn: 'Encryption and Key Management',
    titleZh: '加密及金鑰管理',
    descriptionEn:
      'Implement appropriate encryption for data in transit and at rest, with proper key management.',
    descriptionZh: '針對傳輸中及靜態資料實施適當加密，並妥善管理金鑰。',
    relatedCategories: ['certificate', 'encryption', 'tls'],
  },
  {
    controlId: 'TWCS-4.5',
    category: 'authentication',
    titleEn: 'Multi-Factor Authentication',
    titleZh: '多因子驗證',
    descriptionEn:
      'Implement multi-factor authentication for critical systems and privileged accounts.',
    descriptionZh: '針對關鍵系統及特權帳號實施多因子驗證。',
    relatedCategories: ['password', 'authentication', 'access'],
  },
  {
    controlId: 'TWCS-4.6',
    category: 'monitoring',
    titleEn: 'Security Monitoring and Log Management',
    titleZh: '安全監控及日誌管理',
    descriptionEn:
      'Establish continuous security monitoring and maintain audit logs for at least 6 months.',
    descriptionZh: '建立持續安全監控，並保留稽核日誌至少六個月。',
    relatedCategories: ['monitoring', 'logging', 'audit'],
  },
  {
    controlId: 'TWCS-4.7',
    category: 'incident_response',
    titleEn: 'Security Incident Response',
    titleZh: '資安事件應變',
    descriptionEn:
      'Establish incident response procedures, including notification within specified timeframes.',
    descriptionZh: '建立資安事件應變程序，包括於規定時限內通報。',
    relatedCategories: ['incident', 'response', 'notification'],
  },
  {
    controlId: 'TWCS-4.8',
    category: 'asset_management',
    titleEn: 'Information Asset Management',
    titleZh: '資訊資產管理',
    descriptionEn: 'Maintain inventory of information assets and classify by sensitivity level.',
    descriptionZh: '維護資訊資產清冊，並依敏感程度分級分類。',
    relatedCategories: ['system', 'access', 'inventory'],
  },
  {
    controlId: 'TWCS-4.9',
    category: 'patch_management',
    titleEn: 'Vulnerability and Patch Management',
    titleZh: '弱點及修補管理',
    descriptionEn: 'Regular vulnerability scanning and timely application of security patches.',
    descriptionZh: '定期弱點掃描並及時套用安全修補。',
    relatedCategories: ['vulnerability', 'updates', 'system'],
  },
  {
    controlId: 'TWCS-4.10',
    category: 'audit',
    titleEn: 'Security Audit and Assessment',
    titleZh: '安全稽核及評估',
    descriptionEn: 'Conduct regular security audits and risk assessments at least annually.',
    descriptionZh: '至少每年進行定期安全稽核及風險評估。',
    relatedCategories: ['audit', 'assessment', 'compliance'],
  },
];
