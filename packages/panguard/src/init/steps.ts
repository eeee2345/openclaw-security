/**
 * Init Wizard Step Definitions
 * 初始設定精靈步驟定義
 *
 * All steps are bilingual (en + zh-TW).
 *
 * @module @panguard-ai/panguard/init/steps
 */

import type { WizardStep } from '@panguard-ai/core';
import { detectEnvironment } from './environment.js';

/**
 * All wizard steps in order.
 * Step 1 (language) is always shown in both languages.
 */
export function getWizardSteps(): WizardStep[] {
  return [
    // ── Step 1: Language ──────────────────────────────────────
    {
      id: 'language',
      title: { en: 'Language / \u8A9E\u8A00', 'zh-TW': '\u8A9E\u8A00 / Language' },
      description: {
        en: 'Choose your preferred language / \u9078\u64C7\u4F60\u504F\u597D\u7684\u8A9E\u8A00',
        'zh-TW':
          '\u9078\u64C7\u4F60\u504F\u597D\u7684\u8A9E\u8A00 / Choose your preferred language',
      },
      inputType: 'select',
      options: [
        {
          value: 'zh-TW',
          label: { en: '\u7E41\u9AD4\u4E2D\u6587', 'zh-TW': '\u7E41\u9AD4\u4E2D\u6587' },
        },
        { value: 'en', label: { en: 'English', 'zh-TW': 'English' } },
      ],
    },

    // ── Step 2: Organization Name ─────────────────────────────
    {
      id: 'orgName',
      title: { en: 'Organization Name', 'zh-TW': '\u7D44\u7E54\u540D\u7A31' },
      description: {
        en: 'What is your organization or project called?',
        'zh-TW': '\u4F60\u7684\u7D44\u7E54\u6216\u5C08\u6848\u53EB\u4EC0\u9EBC\u540D\u5B57\uFF1F',
      },
      inputType: 'text',
      validate: (v: string) => (v.trim().length > 0 ? null : 'Required / \u5FC5\u586B'),
    },

    // ── Step 3: Organization Size ─────────────────────────────
    {
      id: 'orgSize',
      title: { en: 'Organization Size', 'zh-TW': '\u7D44\u7E54\u898F\u6A21' },
      description: {
        en: 'This affects default protection settings',
        'zh-TW': '\u9019\u6703\u5F71\u97FF\u9810\u8A2D\u7684\u9632\u8B77\u8A2D\u5B9A',
      },
      inputType: 'select',
      options: [
        {
          value: 'individual',
          label: { en: 'Individual Developer', 'zh-TW': '\u500B\u4EBA\u958B\u767C\u8005' },
          description: {
            en: 'Solo developer with VPS or servers',
            'zh-TW': '\u6709 VPS/\u4F3A\u670D\u5668\u7684\u7368\u7ACB\u958B\u767C\u8005',
          },
        },
        {
          value: 'small',
          label: { en: 'Small Business (5-50)', 'zh-TW': '\u5C0F\u578B\u4F01\u696D (5-50\u4EBA)' },
          description: {
            en: 'No dedicated IT department',
            'zh-TW': '\u6C92\u6709\u5C08\u9580\u7684 IT \u90E8\u9580',
          },
        },
        {
          value: 'medium',
          label: {
            en: 'Medium Business (50-500)',
            'zh-TW': '\u4E2D\u578B\u4F01\u696D (50-500\u4EBA)',
          },
          description: {
            en: 'IT team but no security team',
            'zh-TW': '\u6709 IT \u5718\u968A\u4F46\u6C92\u6709\u8CC7\u5B89\u5718\u968A',
          },
        },
        {
          value: 'large',
          label: { en: 'Enterprise (500+)', 'zh-TW': '\u5927\u578B\u4F01\u696D (500+\u4EBA)' },
          description: {
            en: 'Dedicated security team',
            'zh-TW': '\u6709\u5C08\u9580\u7684\u8CC7\u5B89\u5718\u968A',
          },
        },
      ],
    },

    // ── Step 4: Industry ──────────────────────────────────────
    {
      id: 'industry',
      title: { en: 'Industry', 'zh-TW': '\u884C\u696D' },
      description: {
        en: 'Helps tailor compliance recommendations',
        'zh-TW': '\u5354\u52A9\u5236\u5B9A\u5408\u898F\u5EFA\u8B70',
      },
      inputType: 'select',
      options: [
        { value: 'tech', label: { en: 'Technology / SaaS', 'zh-TW': '\u79D1\u6280 / SaaS' } },
        {
          value: 'finance',
          label: { en: 'Finance / Banking', 'zh-TW': '\u91D1\u878D / \u9280\u884C' },
        },
        { value: 'healthcare', label: { en: 'Healthcare', 'zh-TW': '\u91AB\u7642' } },
        { value: 'education', label: { en: 'Education', 'zh-TW': '\u6559\u80B2' } },
        { value: 'government', label: { en: 'Government', 'zh-TW': '\u653F\u5E9C' } },
        {
          value: 'retail',
          label: { en: 'Retail / E-commerce', 'zh-TW': '\u96F6\u552E / \u96FB\u5546' },
        },
        { value: 'manufacturing', label: { en: 'Manufacturing', 'zh-TW': '\u88FD\u9020\u696D' } },
        { value: 'other', label: { en: 'Other', 'zh-TW': '\u5176\u4ED6' } },
      ],
    },

    // ── Step 5: Environment (auto-detect) ─────────────────────
    {
      id: 'environment_os',
      title: { en: 'System Environment', 'zh-TW': '\u7CFB\u7D71\u74B0\u5883' },
      description: {
        en: 'Auto-detecting your system...',
        'zh-TW': '\u6B63\u5728\u81EA\u52D5\u5075\u6E2C\u4F60\u7684\u7CFB\u7D71...',
      },
      inputType: 'auto',
      autoDetect: detectEnvironment,
    },

    // ── Step 5b: Deploy type ──────────────────────────────────
    {
      id: 'deployType',
      title: { en: 'Deployment Type', 'zh-TW': '\u90E8\u7F72\u65B9\u5F0F' },
      description: {
        en: 'Where does your infrastructure run?',
        'zh-TW': '\u4F60\u7684\u57FA\u790E\u8A2D\u65BD\u5728\u54EA\u88E1\u904B\u884C\uFF1F',
      },
      inputType: 'select',
      options: [
        {
          value: 'cloud',
          label: { en: 'Cloud (AWS/GCP/Azure/VPS)', 'zh-TW': '\u96F2\u7AEF (AWS/GCP/Azure/VPS)' },
        },
        {
          value: 'on-prem',
          label: { en: 'On-Premises', 'zh-TW': '\u81EA\u5EFA\u6A5F\u623F' },
        },
        {
          value: 'hybrid',
          label: { en: 'Hybrid', 'zh-TW': '\u6DF7\u5408\u90E8\u7F72' },
        },
      ],
    },

    // ── Step 6: Security Goals ────────────────────────────────
    {
      id: 'securityGoals',
      title: { en: 'Security Priorities', 'zh-TW': '\u5B89\u5168\u91CD\u9EDE' },
      description: {
        en: 'What matters most to you?',
        'zh-TW': '\u4EC0\u9EBC\u5C0D\u4F60\u6700\u91CD\u8981\uFF1F',
      },
      inputType: 'select',
      options: [
        {
          value: 'realtime',
          label: { en: 'Real-time Protection', 'zh-TW': '\u5373\u6642\u9632\u8B77' },
          description: {
            en: 'Monitor and block threats 24/7',
            'zh-TW': '24/7 \u76E3\u63A7\u548C\u963B\u64CB\u5A01\u8105',
          },
        },
        {
          value: 'compliance',
          label: { en: 'Compliance Reports', 'zh-TW': '\u5408\u898F\u5831\u544A' },
          description: {
            en: 'ISO 27001, SOC 2, regulatory',
            'zh-TW': 'ISO 27001, SOC 2, \u6CD5\u898F',
          },
        },
        {
          value: 'vulnerability',
          label: { en: 'Vulnerability Scanning', 'zh-TW': '\u5F31\u9EDE\u6383\u63CF' },
          description: {
            en: 'Find misconfigurations and CVEs',
            'zh-TW': '\u627E\u51FA\u914D\u7F6E\u932F\u8AA4\u548C CVE',
          },
        },
        {
          value: 'honeypot',
          label: { en: 'Honeypot / Deception', 'zh-TW': '\u871C\u7F50 / \u8A98\u6355' },
          description: {
            en: 'Detect and profile attackers',
            'zh-TW': '\u5075\u6E2C\u548C\u5206\u6790\u653B\u64CA\u8005',
          },
        },
        {
          value: 'all',
          label: {
            en: 'All of the Above (Recommended)',
            'zh-TW': '\u4EE5\u4E0A\u5168\u90E8 (\u63A8\u85A6)',
          },
          description: {
            en: 'Maximum protection',
            'zh-TW': '\u6700\u5927\u5316\u9632\u8B77',
          },
        },
      ],
    },

    // ── Step 7: Compliance Frameworks ─────────────────────────
    {
      id: 'compliance',
      title: { en: 'Compliance Frameworks', 'zh-TW': '\u5408\u898F\u6846\u67B6' },
      description: {
        en: 'Which compliance standards apply to you?',
        'zh-TW': '\u4F60\u9700\u8981\u7B26\u5408\u54EA\u4E9B\u5408\u898F\u6A19\u6E96\uFF1F',
      },
      inputType: 'select',
      dependsOn: { stepId: 'securityGoals', values: ['compliance', 'all'] },
      options: [
        { value: 'iso27001', label: { en: 'ISO 27001', 'zh-TW': 'ISO 27001' } },
        { value: 'soc2', label: { en: 'SOC 2', 'zh-TW': 'SOC 2' } },
        {
          value: 'tw_cyber',
          label: {
            en: 'Taiwan Cyber Security Act',
            'zh-TW': '\u8CC7\u901A\u5B89\u5168\u7BA1\u7406\u6CD5',
          },
        },
        {
          value: 'none',
          label: { en: 'None / Not Sure', 'zh-TW': '\u6C92\u6709 / \u4E0D\u78BA\u5B9A' },
        },
      ],
    },

    // ── Step 8: Notification Channel ──────────────────────────
    {
      id: 'notification',
      title: { en: 'Notification Channel', 'zh-TW': '\u901A\u77E5\u7BA1\u9053' },
      description: {
        en: 'How should we alert you about threats?',
        'zh-TW':
          '\u6211\u5011\u61C9\u8A72\u5982\u4F55\u901A\u77E5\u4F60\u6709\u95DC\u5A01\u8105\uFF1F',
      },
      inputType: 'select',
      options: [
        {
          value: 'line',
          label: { en: 'LINE', 'zh-TW': 'LINE' },
          description: {
            en: 'Most popular in Taiwan',
            'zh-TW': '\u53F0\u7063\u6700\u5E38\u7528\u7684\u901A\u8A0A\u8EDF\u9AD4',
          },
        },
        {
          value: 'telegram',
          label: { en: 'Telegram', 'zh-TW': 'Telegram' },
          description: {
            en: 'Global messaging, strong privacy',
            'zh-TW': '\u5168\u7403\u901A\u7528\uFF0C\u96B1\u79C1\u5F37',
          },
        },
        {
          value: 'slack',
          label: { en: 'Slack', 'zh-TW': 'Slack' },
          description: {
            en: 'Best for teams and workflows',
            'zh-TW': '\u6700\u9069\u5408\u5718\u968A\u548C\u5DE5\u4F5C\u6D41\u7A0B',
          },
        },
        {
          value: 'email',
          label: { en: 'Email', 'zh-TW': 'Email' },
          description: {
            en: 'Traditional, good for archives',
            'zh-TW': '\u50B3\u7D71\u65B9\u5F0F\uFF0C\u9069\u5408\u5B58\u6A94',
          },
        },
        {
          value: 'webhook',
          label: { en: 'Webhook (Enterprise)', 'zh-TW': 'Webhook (\u4F01\u696D\u7D1A)' },
          description: {
            en: 'SIEM / ticketing integration',
            'zh-TW': '\u6574\u5408 SIEM / \u5DE5\u55AE\u7CFB\u7D71',
          },
        },
        {
          value: 'none',
          label: { en: 'Skip for now', 'zh-TW': '\u5148\u8DF3\u904E' },
          description: {
            en: 'Configure later with: panguard chat setup',
            'zh-TW': '\u7A0D\u5F8C\u7528 panguard chat setup \u8A2D\u5B9A',
          },
        },
      ],
    },

    // ── Step 9: AI Preference ─────────────────────────────────
    {
      id: 'aiPreference',
      title: { en: 'AI Engine', 'zh-TW': 'AI \u5F15\u64CE' },
      description: {
        en: 'How should Panguard analyze threats?',
        'zh-TW': 'Panguard \u61C9\u5982\u4F55\u5206\u6790\u5A01\u8105\uFF1F',
      },
      inputType: 'select',
      options: [
        {
          value: 'cloud_ai',
          label: { en: 'Cloud AI (Claude/OpenAI)', 'zh-TW': '\u96F2\u7AEF AI (Claude/OpenAI)' },
          description: {
            en: 'Best accuracy, requires API key',
            'zh-TW': '\u6700\u4F73\u6E96\u78BA\u5EA6\uFF0C\u9700\u8981 API \u91D1\u9470',
          },
        },
        {
          value: 'local_ai',
          label: { en: 'Local AI (Ollama)', 'zh-TW': '\u672C\u5730 AI (Ollama)' },
          description: {
            en: 'Privacy-first, runs on your server',
            'zh-TW':
              '\u96B1\u79C1\u512A\u5148\uFF0C\u5728\u4F60\u7684\u4F3A\u670D\u5668\u4E0A\u904B\u884C',
          },
        },
        {
          value: 'rules_only',
          label: { en: 'Rules Only (No AI)', 'zh-TW': '\u50C5\u898F\u5247 (\u4E0D\u7528 AI)' },
          description: {
            en: 'Zero cost, Sigma + YARA rules',
            'zh-TW': '\u96F6\u6210\u672C\uFF0CSigma + YARA \u898F\u5247',
          },
        },
      ],
    },

    // ── Step 10: Protection Level ─────────────────────────────
    {
      id: 'protectionLevel',
      title: { en: 'Protection Mode', 'zh-TW': '\u9632\u8B77\u6A21\u5F0F' },
      description: {
        en: 'How aggressively should Panguard respond to threats?',
        'zh-TW': 'Panguard \u61C9\u8A72\u591A\u7A4D\u6975\u5730\u56DE\u61C9\u5A01\u8105\uFF1F',
      },
      inputType: 'select',
      options: [
        {
          value: 'aggressive',
          label: { en: 'Aggressive', 'zh-TW': '\u7A4D\u6975' },
          description: {
            en: 'Auto-block threats immediately',
            'zh-TW': '\u7ACB\u5373\u81EA\u52D5\u963B\u64CB\u5A01\u8105',
          },
        },
        {
          value: 'balanced',
          label: { en: 'Balanced (Recommended)', 'zh-TW': '\u5747\u8861 (\u63A8\u85A6)' },
          description: {
            en: 'Learn first, then protect. Notify before blocking.',
            'zh-TW':
              '\u5148\u5B78\u7FD2\u518D\u9632\u8B77\u3002\u963B\u64CB\u524D\u5148\u901A\u77E5\u3002',
          },
        },
        {
          value: 'learning',
          label: { en: 'Learning Only', 'zh-TW': '\u50C5\u5B78\u7FD2' },
          description: {
            en: 'Monitor and learn for 7 days, no auto-actions',
            'zh-TW':
              '\u89C0\u5BDF\u5B78\u7FD2 7 \u5929\uFF0C\u4E0D\u81EA\u52D5\u57F7\u884C\u4EFB\u4F55\u52D5\u4F5C',
          },
        },
      ],
    },
  ];
}
