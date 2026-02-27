/**
 * Website page definitions and metadata
 * 網站頁面定義與元資料
 *
 * @module @panguard-ai/panguard-web/pages
 */

import type { PageId, PageMeta, WebLanguage } from '../types.js';

// ---------------------------------------------------------------------------
// Page registry
// 頁面註冊表
// ---------------------------------------------------------------------------

export const PAGES: PageMeta[] = [
  {
    id: 'home',
    titleEn: 'Panguard AI - AI-Driven Endpoint Protection',
    titleZh: 'Panguard AI - AI 驅動的端點防護',
    descriptionEn:
      'One command to install. AI protects your machines automatically. It tells you when something happens. You do nothing when all is well.',
    descriptionZh: '一行指令安裝，AI 全自動保護你的機器。有事它會告訴你，沒事你什麼都不用做。',
    path: '/',
  },
  {
    id: 'features',
    titleEn: 'Features - How Panguard AI Protects You',
    titleZh: '功能 - Panguard AI 如何保護你',
    descriptionEn:
      'Panguard Scan, Panguard Guard, Panguard Chat, Panguard Trap, Panguard Report - complete security in plain language.',
    descriptionZh:
      'Panguard Scan、Panguard Guard、Panguard Chat、Panguard Trap、Panguard Report - 用人話做資安。',
    path: '/features',
  },
  {
    id: 'pricing',
    titleEn: 'Pricing - Plans for Every Size',
    titleZh: '定價 - 各種規模都有方案',
    descriptionEn:
      'From free security scans to enterprise compliance. Start protecting in 60 seconds.',
    descriptionZh: '從免費資安掃描到企業合規。60 秒內開始防護。',
    path: '/pricing',
  },
  {
    id: 'docs',
    titleEn: 'Documentation - Getting Started',
    titleZh: '文件 - 快速開始',
    descriptionEn: 'Installation guide, configuration, API reference, and FAQ.',
    descriptionZh: '安裝指南、配置、API 參考和常見問題。',
    path: '/docs',
  },
  {
    id: 'guide',
    titleEn: 'Online Guide - Find Your Security Solution',
    titleZh: '線上引導 - 找到你的資安方案',
    descriptionEn: "Answer a few questions and we'll recommend the perfect security setup for you.",
    descriptionZh: '回答幾個問題，我們就推薦最適合你的資安方案。',
    path: '/guide',
  },
  {
    id: 'about',
    titleEn: 'About Panguard AI',
    titleZh: '關於 Panguard AI',
    descriptionEn: 'Our mission: make enterprise-grade security accessible to everyone.',
    descriptionZh: '我們的使命：讓每個人都能享有企業級資安防護。',
    path: '/about',
  },
];

/**
 * Get page by ID
 * 根據 ID 取得頁面
 */
export function getPage(id: PageId): PageMeta | undefined {
  return PAGES.find((p) => p.id === id);
}

/**
 * Get page title in specified language
 * 取得指定語言的頁面標題
 */
export function getPageTitle(id: PageId, language: WebLanguage): string {
  const page = getPage(id);
  if (!page) return id;
  return language === 'zh-TW' ? page.titleZh : page.titleEn;
}

/**
 * Get all pages
 * 取得所有頁面
 */
export function getAllPages(): PageMeta[] {
  return PAGES;
}

/**
 * Get navigation items (exclude guide)
 * 取得導覽項目（排除引導頁）
 */
export function getNavItems(): PageMeta[] {
  return PAGES.filter((p) => p.id !== 'guide');
}

// ---------------------------------------------------------------------------
// Product features for the features page
// 功能頁的產品特色
// ---------------------------------------------------------------------------

/** Product feature definition / 產品特色定義 */
export interface ProductFeature {
  product: string;
  tagEn: string;
  tagZh: string;
  headlineEn: string;
  headlineZh: string;
  descriptionEn: string;
  descriptionZh: string;
  highlightsEn: string[];
  highlightsZh: string[];
}

export const PRODUCT_FEATURES: ProductFeature[] = [
  {
    product: 'Panguard Scan',
    tagEn: 'Free',
    tagZh: '免費',
    headlineEn: '60-Second Security Health Check',
    headlineZh: '60 秒資安健檢',
    descriptionEn:
      'One command scans your system and generates a professional PDF report with remediation steps.',
    descriptionZh: '一行指令掃描你的系統，產生專業 PDF 報告和修復步驟。',
    highlightsEn: [
      'Password policy audit',
      'Open port detection',
      'SSL certificate check',
      'Scheduled task analysis',
      'Shared folder inspection',
      'Risk score with remediation guide',
    ],
    highlightsZh: [
      '密碼政策稽核',
      '開放埠偵測',
      'SSL 憑證檢查',
      '排程任務分析',
      '共享資料夾檢查',
      '風險評分 + 修復指南',
    ],
  },
  {
    product: 'Panguard Guard',
    tagEn: 'Core',
    tagZh: '核心',
    headlineEn: 'AI Watches. AI Acts. You Sleep.',
    headlineZh: 'AI 監控。AI 行動。你安心睡。',
    descriptionEn:
      'Continuous monitoring with multi-agent AI. Detects, analyzes, and responds to threats automatically.',
    descriptionZh: '多 Agent AI 持續監控。自動偵測、分析、回應威脅。',
    highlightsEn: [
      'Multi-agent pipeline: Detect > Analyze > Respond > Report',
      '3-layer funnel: Rules (90%) > Local AI (7%) > Cloud AI (3%)',
      '7-day learning period - zero false positives',
      'Auto-block, auto-isolate, auto-notify',
      'Context Memory - gets smarter over time',
      'Panguard Threat Cloud - collective intelligence',
    ],
    highlightsZh: [
      '多 Agent 管線：偵測 > 分析 > 回應 > 報告',
      '三層漏斗：規則 (90%) > 本地 AI (7%) > 雲端 AI (3%)',
      '7 天學習期 - 零誤報',
      '自動封鎖、自動隔離、自動通知',
      'Context Memory - 越用越準',
      'Panguard Threat Cloud - 集體威脅智慧',
    ],
  },
  {
    product: 'Panguard Chat',
    tagEn: 'P0',
    tagZh: 'P0',
    headlineEn: 'Your AI Security Co-pilot',
    headlineZh: '你的 AI 資安副駕駛',
    descriptionEn:
      'Talks to you in plain language through LINE, Telegram, or Slack. No jargon, just clear answers.',
    descriptionZh: '透過 LINE、Telegram 或 Slack 用人話跟你溝通。不講術語，只給清楚的答案。',
    highlightsEn: [
      'LINE / Telegram / Slack / Email / Webhook',
      'Adapts language to your role (developer/boss/IT admin)',
      'Ask follow-up questions naturally',
      'Approve or reject AI recommendations via chat',
      'Daily/weekly security summaries',
      '"All clear" notifications - peace of mind',
    ],
    highlightsZh: [
      'LINE / Telegram / Slack / Email / Webhook',
      '根據你的角色調整語氣（開發者/老闆/IT 管理員）',
      '自然地追問問題',
      '透過聊天確認或駁回 AI 的建議',
      '每日/每週資安摘要',
      '「太平無事」通知 - 安心',
    ],
  },
  {
    product: 'Panguard Trap',
    tagEn: 'Advanced',
    tagZh: '進階',
    headlineEn: 'Smart Honeypots That Learn',
    headlineZh: '會學習的智慧蜜罐',
    descriptionEn:
      'Deploy fake services that attract and profile attackers. Feeds intelligence back to protect everyone.',
    descriptionZh: '部署假服務，吸引並分析攻擊者。將情報回饋保護所有人。',
    highlightsEn: [
      '8 service types: SSH, HTTP, FTP, MySQL, Redis, and more',
      'Attacker profiling: skill level, intent, tools used',
      'MITRE ATT&CK technique tracking',
      'Anonymous intelligence sharing via Threat Cloud',
      'Zero-config deployment',
    ],
    highlightsZh: [
      '8 種服務類型：SSH、HTTP、FTP、MySQL、Redis 等',
      '攻擊者分析：技術水準、意圖、使用工具',
      'MITRE ATT&CK 技術追蹤',
      '透過 Threat Cloud 匿名分享情報',
      '零配置部署',
    ],
  },
  {
    product: 'Panguard Report',
    tagEn: 'Compliance',
    tagZh: '合規',
    headlineEn: 'Audit-Ready in 5 Minutes',
    headlineZh: '5 分鐘準備好稽核',
    descriptionEn:
      'AI generates compliance reports mapped to real frameworks. No security expertise required.',
    descriptionZh: 'AI 產生對應真實框架的合規報告。不需要資安專業知識。',
    highlightsEn: [
      'Taiwan Cyber Security Management Act (10 controls)',
      'ISO/IEC 27001:2022 (12 controls)',
      'SOC 2 Trust Services Criteria (10 controls)',
      'Automatic finding-to-control mapping',
      'Bilingual reports (Chinese/English)',
      'Recommendations with priority and effort estimates',
    ],
    highlightsZh: [
      '資通安全管理法（10 個控制項）',
      'ISO/IEC 27001:2022（12 個控制項）',
      'SOC 2 信任服務準則（10 個控制項）',
      '自動映射發現到控制項',
      '雙語報告（中文/英文）',
      '建議含優先級和工作量預估',
    ],
  },
];

/**
 * Get product feature by name
 * 根據名稱取得產品特色
 */
export function getProductFeature(product: string): ProductFeature | undefined {
  return PRODUCT_FEATURES.find((f) => f.product === product);
}
