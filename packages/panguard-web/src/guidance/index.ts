/**
 * Online Guidance Wizard Engine
 * 線上引導精靈引擎
 *
 * Implements the interactive onboarding flow that helps users
 * find the right security solution based on their profile.
 * 實作互動式引導流程，幫助用戶根據自身條件找到合適的資安方案。
 *
 * @module @openclaw/panguard-web/guidance
 */

import type {
  GuidanceStep,
  GuidanceAnswers,
  GuidanceResult,
  GuidanceStepType,
  PersonaType,
  PricingPlan,
  WebLanguage,
} from '../types.js';

// ---------------------------------------------------------------------------
// Step definitions
// 步驟定義
// ---------------------------------------------------------------------------

/** All guidance steps / 所有引導步驟 */
export const GUIDANCE_STEPS: GuidanceStep[] = [
  {
    type: 'welcome',
    stepNumber: 1,
    titleEn: 'Welcome to Panguard AI',
    titleZh: '歡迎來到 Panguard AI',
    descriptionEn: 'Answer a few quick questions and we\'ll recommend the perfect security setup for you. Takes less than 2 minutes.',
    descriptionZh: '回答幾個簡單的問題，我們就推薦最適合你的資安方案。不到 2 分鐘。',
  },
  {
    type: 'persona_select',
    stepNumber: 2,
    titleEn: 'Tell us about you',
    titleZh: '告訴我們你的身份',
    descriptionEn: 'Which best describes you?',
    descriptionZh: '哪一個最符合你的狀況？',
    options: [
      {
        id: 'developer',
        labelEn: 'Developer',
        labelZh: '開發者',
        descriptionEn: 'I have servers/VPS and build software. AI-generated code is part of my workflow.',
        descriptionZh: '我有伺服器/VPS，寫軟體。AI 生成的 code 是我工作流程的一部分。',
      },
      {
        id: 'small_business',
        labelEn: 'Small Business',
        labelZh: '小型企業',
        descriptionEn: '5-50 employees. No dedicated IT department. Worried about ransomware.',
        descriptionZh: '5-50 人。沒有專職 IT 部門。擔心勒索軟體。',
      },
      {
        id: 'mid_enterprise',
        labelEn: 'Mid-size Enterprise',
        labelZh: '中型企業',
        descriptionEn: '50-500 employees. Have IT but no security team. Need compliance reports.',
        descriptionZh: '50-500 人。有 IT 但沒有資安團隊。需要合規報告。',
      },
    ],
  },
  {
    type: 'threat_assessment',
    stepNumber: 3,
    titleEn: 'What do you have?',
    titleZh: '你有什麼？',
    descriptionEn: 'Help us understand your environment to give better recommendations.',
    descriptionZh: '幫助我們了解你的環境，以便給出更好的建議。',
    options: [
      {
        id: 'has_server',
        labelEn: 'Servers / VPS',
        labelZh: '伺服器 / VPS',
        descriptionEn: 'I have servers exposed to the internet.',
        descriptionZh: '我有暴露在公網的伺服器。',
      },
      {
        id: 'has_webapp',
        labelEn: 'Web Applications',
        labelZh: '網站應用程式',
        descriptionEn: 'I run web applications or APIs.',
        descriptionZh: '我有運行網站應用程式或 API。',
      },
      {
        id: 'has_database',
        labelEn: 'Databases',
        labelZh: '資料庫',
        descriptionEn: 'I have databases with important data.',
        descriptionZh: '我有存放重要資料的資料庫。',
      },
    ],
  },
  {
    type: 'product_recommendation',
    stepNumber: 4,
    titleEn: 'Your Recommended Setup',
    titleZh: '你的推薦方案',
    descriptionEn: 'Based on your answers, here\'s what we recommend.',
    descriptionZh: '根據你的回答，我們推薦以下方案。',
  },
  {
    type: 'notification_setup',
    stepNumber: 5,
    titleEn: 'Stay Notified',
    titleZh: '保持聯繫',
    descriptionEn: 'Choose how you want to receive security notifications.',
    descriptionZh: '選擇你要如何接收資安通知。',
    options: [
      {
        id: 'line',
        labelEn: 'LINE',
        labelZh: 'LINE',
        descriptionEn: 'Best for personal use in Taiwan/Japan.',
        descriptionZh: '適合台灣/日本的個人使用。',
      },
      {
        id: 'telegram',
        labelEn: 'Telegram',
        labelZh: 'Telegram',
        descriptionEn: 'Best for developers and tech-savvy users.',
        descriptionZh: '適合開發者和科技愛好者。',
      },
      {
        id: 'slack',
        labelEn: 'Slack',
        labelZh: 'Slack',
        descriptionEn: 'Best for teams and businesses.',
        descriptionZh: '適合團隊和企業。',
      },
      {
        id: 'email',
        labelEn: 'Email',
        labelZh: 'Email',
        descriptionEn: 'Universal, works everywhere.',
        descriptionZh: '通用，隨處可用。',
      },
    ],
  },
  {
    type: 'installation',
    stepNumber: 6,
    titleEn: 'Install in One Command',
    titleZh: '一行指令安裝',
    descriptionEn: 'Copy and paste this command to get started.',
    descriptionZh: '複製貼上這行指令就能開始。',
  },
  {
    type: 'complete',
    stepNumber: 7,
    titleEn: 'You\'re Protected!',
    titleZh: '你已受到保護！',
    descriptionEn: 'Panguard AI is now learning your environment. You\'ll receive your first security summary in 24 hours.',
    descriptionZh: 'Panguard AI 正在學習你的環境。你會在 24 小時內收到第一份資安摘要。',
  },
];

/**
 * Get guidance step by type
 * 根據類型取得引導步驟
 */
export function getGuidanceStep(type: GuidanceStepType): GuidanceStep | undefined {
  return GUIDANCE_STEPS.find((s) => s.type === type);
}

/**
 * Get the next step in the guidance flow
 * 取得引導流程的下一步
 */
export function getNextStep(currentType: GuidanceStepType): GuidanceStep | undefined {
  const currentIndex = GUIDANCE_STEPS.findIndex((s) => s.type === currentType);
  if (currentIndex < 0 || currentIndex >= GUIDANCE_STEPS.length - 1) {
    return undefined;
  }
  return GUIDANCE_STEPS[currentIndex + 1];
}

/**
 * Get the previous step in the guidance flow
 * 取得引導流程的上一步
 */
export function getPreviousStep(currentType: GuidanceStepType): GuidanceStep | undefined {
  const currentIndex = GUIDANCE_STEPS.findIndex((s) => s.type === currentType);
  if (currentIndex <= 0) {
    return undefined;
  }
  return GUIDANCE_STEPS[currentIndex - 1];
}

/**
 * Get total step count
 * 取得總步驟數
 */
export function getTotalSteps(): number {
  return GUIDANCE_STEPS.length;
}

// ---------------------------------------------------------------------------
// Recommendation engine
// 推薦引擎
// ---------------------------------------------------------------------------

/**
 * Determine recommended plan based on persona
 * 根據角色判斷推薦方案
 */
function determinePlan(persona: PersonaType | undefined): PricingPlan {
  switch (persona) {
    case 'developer':
      return 'solo';
    case 'small_business':
      return 'team';
    case 'mid_enterprise':
      return 'business';
    default:
      return 'free';
  }
}

/**
 * Determine recommended products based on answers
 * 根據回答判斷推薦產品
 */
function determineProducts(answers: GuidanceAnswers): string[] {
  const products: string[] = ['Panguard Scan']; // Always recommend scan

  if (answers.persona !== undefined) {
    products.push('Panguard Guard');
    products.push('Panguard Chat');
  }

  if (answers.hasServer) {
    products.push('Panguard Trap');
  }

  if (answers.persona === 'mid_enterprise') {
    products.push('Panguard Report');
  }

  return products;
}

/**
 * Generate installation command based on answers
 * 根據回答產生安裝指令
 */
function generateInstallCommand(answers: GuidanceAnswers): string {
  const plan = determinePlan(answers.persona);

  if (plan === 'free') {
    return 'curl -fsSL https://get.panguard.ai | sh';
  }

  const channelFlag = answers.notificationChannel
    ? ` --notify ${answers.notificationChannel}`
    : '';

  return `curl -fsSL https://get.panguard.ai | sh -s -- --plan ${plan}${channelFlag}`;
}

/**
 * Generate configuration steps based on answers
 * 根據回答產生配置步驟
 */
function generateConfigSteps(answers: GuidanceAnswers, language: WebLanguage): string[] {
  const steps: string[] = [];
  const isZh = language === 'zh-TW';

  steps.push(isZh
    ? '1. 執行安裝指令（自動偵測你的環境）'
    : '1. Run the install command (auto-detects your environment)');

  steps.push(isZh
    ? '2. 等待 7 天學習期完成（已知攻擊仍會立即處理）'
    : '2. Wait for the 7-day learning period (known attacks are still handled immediately)');

  if (answers.notificationChannel) {
    const channelName = answers.notificationChannel.charAt(0).toUpperCase()
      + answers.notificationChannel.slice(1);
    steps.push(isZh
      ? `3. 設定 ${channelName} 通知管道`
      : `3. Set up ${channelName} notification channel`);
  }

  if (answers.persona === 'mid_enterprise') {
    steps.push(isZh
      ? '4. 設定合規報告排程（Panguard Report）'
      : '4. Configure compliance report scheduling (Panguard Report)');
  }

  if (answers.hasServer) {
    steps.push(isZh
      ? `${steps.length + 1}. 部署蜜罐服務（Panguard Trap）`
      : `${steps.length + 1}. Deploy honeypot services (Panguard Trap)`);
  }

  return steps;
}

/**
 * Generate guidance result from user answers
 * 從用戶回答產生引導結果
 */
export function generateGuidanceResult(
  answers: GuidanceAnswers,
  language: WebLanguage = 'zh-TW',
): GuidanceResult {
  const recommendedPlan = determinePlan(answers.persona);
  const recommendedProducts = determineProducts(answers);
  const installCommand = generateInstallCommand(answers);
  const configSteps = generateConfigSteps(answers, language);

  let estimatedSetupTime: string;
  if (recommendedPlan === 'free') {
    estimatedSetupTime = language === 'zh-TW' ? '60 秒' : '60 seconds';
  } else if (recommendedPlan === 'business') {
    estimatedSetupTime = language === 'zh-TW' ? '10 分鐘' : '10 minutes';
  } else {
    estimatedSetupTime = language === 'zh-TW' ? '5 分鐘' : '5 minutes';
  }

  return {
    recommendedPlan,
    recommendedProducts,
    installCommand,
    configSteps,
    estimatedSetupTime,
  };
}
