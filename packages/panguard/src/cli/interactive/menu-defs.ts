/**
 * Menu definitions for interactive CLI
 * @module @panguard-ai/panguard/cli/interactive/menu-defs
 */

export interface MenuDef {
  key: string;
  icon: string;
  number: number;
  en: string;
  zh: string;
  enDesc: string;
  zhDesc: string;
  tierBadge: string;
  featureKey: string;
}

export const MENU_DEFS: MenuDef[] = [
  {
    key: 'setup',
    icon: '>',
    number: 0,
    en: 'Setup Wizard',
    zh: '\u521D\u59CB\u8A2D\u5B9A',
    enDesc: 'Configure all modules with guided setup',
    zhDesc: '\u958B\u555F\u6B64\u5F15\u64CE\uFF0C\u81EA\u52D5\u914D\u7F6E\u6240\u6709\u6A21\u7D44',
    tierBadge: '',
    featureKey: 'setup',
  },
  {
    key: 'scan',
    icon: '\u26A1',
    number: 1,
    en: 'Security Scan',
    zh: '\u5B89\u5168\u6383\u63CF',
    enDesc: 'Scan system security and analyze risks',
    zhDesc: '\u6383\u63CF\u7CFB\u7D71\u5B89\u5168\u72C0\u614B\uFF0C\u5206\u6790\u6240\u6709\u98A8\u96AA',
    tierBadge: '',
    featureKey: 'scan',
  },
  {
    key: 'report',
    icon: '\u25A0',
    number: 2,
    en: 'Compliance Report [Coming Soon]',
    zh: '\u5408\u898F\u5831\u544A [\u5373\u5C07\u63A8\u51FA]',
    enDesc: 'ISO 27001, SOC 2, TW Cyber Security Act — under development',
    zhDesc: 'ISO 27001\u3001SOC 2\u3001\u8CC7\u5B89\u7BA1\u7406\u6CD5 \u2014 \u958B\u767C\u4E2D',
    tierBadge: '',
    featureKey: 'report',
  },
  {
    key: 'guard',
    icon: '\u2713',
    number: 3,
    en: 'Guard Engine',
    zh: '\u5B88\u8B77\u5F15\u64CE',
    enDesc: 'Real-time monitoring and continuous protection',
    zhDesc: '\u5373\u6642\u76E3\u63A7\u9023\u7E8C\u9632\u8B77\u7CFB\u7D71',
    tierBadge: '',
    featureKey: 'guard',
  },
  {
    key: 'trap',
    icon: '\u00B7',
    number: 4,
    en: 'Honeypot System [Coming Soon]',
    zh: '\u871C\u7F50\u7CFB\u7D71 [\u5373\u5C07\u63A8\u51FA]',
    enDesc: 'Decoy services to detect attackers — under development',
    zhDesc: '\u8A98\u990C\u670D\u52D9\u5075\u6E2C\u653B\u64CA\u8005 \u2014 \u958B\u767C\u4E2D',
    tierBadge: '',
    featureKey: 'trap',
  },
  {
    key: 'notify',
    icon: '\u00B7',
    number: 5,
    en: 'Notifications',
    zh: '\u901A\u77E5\u7CFB\u7D71',
    enDesc: 'LINE, Telegram, Slack, Email, Webhook channels',
    zhDesc: 'LINE\u3001Telegram\u3001Slack\u3001Email\u3001Webhook \u901A\u77E5\u7BA1\u9053',
    tierBadge: '',
    featureKey: 'notify',
  },
  {
    key: 'threat-cloud',
    icon: '\u00B7',
    number: 6,
    en: 'Threat Cloud',
    zh: '\u5A01\u8105\u60C5\u5831',
    enDesc: 'Threat intelligence REST API server',
    zhDesc: '\u5A01\u8105\u60C5\u5831 REST API \u4F3A\u670D\u5668',
    tierBadge: '',
    featureKey: 'threat-cloud',
  },
  {
    key: 'demo',
    icon: '\u00B7',
    number: 7,
    en: 'Auto Demo',
    zh: '\u81EA\u52D5\u5C55\u793A',
    enDesc: 'Run through all security modules',
    zhDesc: '\u81EA\u52D5\u57F7\u884C\u7D9C\u5408\u529F\u80FD\u5C55\u793A',
    tierBadge: '',
    featureKey: 'demo',
  },
  {
    key: 'audit',
    icon: '\u25A0',
    number: 8,
    en: 'Skill Auditor',
    zh: '\u6280\u80FD\u5BE9\u8A08',
    enDesc: 'Audit AI agent skills for security issues',
    zhDesc: '\u5BE9\u8A08 AI \u4EE3\u7406\u6280\u80FD\u7684\u5B89\u5168\u554F\u984C',
    tierBadge: '',
    featureKey: 'audit',
  },
];
