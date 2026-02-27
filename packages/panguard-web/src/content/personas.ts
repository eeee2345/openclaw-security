/**
 * Target audience persona definitions
 * 目標用戶角色定義
 *
 * Based on README TA: individual developers, small businesses (5-50), mid enterprises (50-500)
 * 根據 README TA：個人開發者、小型企業 (5-50 人)、中型企業 (50-500 人)
 *
 * @module @panguard-ai/panguard-web/content/personas
 */

import type { PersonaProfile, ScenarioStory } from '../types.js';

// ---------------------------------------------------------------------------
// Scenario stories per persona
// 各角色的場景故事
// ---------------------------------------------------------------------------

const DEVELOPER_SCENARIOS: ScenarioStory[] = [
  {
    id: 'dev-ssh-brute',
    threatType: 'SSH Brute Force',
    beforeEn:
      'Your VPS is getting hammered by SSH brute force attacks from bots. You have no idea because you never check auth.log.',
    beforeZh:
      '你的 VPS 正在被機器人的 SSH 暴力破解攻擊轟炸。你完全不知道，因為你從來不看 auth.log。',
    afterEn:
      'Panguard AI detects 500 failed login attempts from China, automatically blocks the IP, and tells you on LINE.',
    afterZh: 'Panguard AI 偵測到來自中國的 500 次登入失敗，自動封鎖 IP，並在 LINE 上告訴你。',
    notificationEn:
      "Someone was trying to guess your password to log in. Source: Hebei, China. 500 attempts, all failed. I've added this IP to the blocklist.",
    notificationZh:
      '有人正在嘗試猜你的密碼登入。來源：中國河北。已嘗試 500 次，全部失敗。我已把這個 IP 加入黑名單。',
  },
  {
    id: 'dev-ai-code-vuln',
    threatType: 'Vulnerable AI-Generated Code',
    beforeEn:
      'AI-generated code deployed a web server with an exposed .env file containing your database credentials.',
    beforeZh: 'AI 生成的程式碼部署了一個 Web Server，其中 .env 檔案暴露了你的資料庫密碼。',
    afterEn:
      'Panguard Scan detects the exposed configuration within 60 seconds and alerts you immediately.',
    afterZh: 'Panguard Scan 在 60 秒內偵測到暴露的配置檔，並立即通知你。',
    notificationEn:
      'Found a security issue: your database password is publicly accessible through .env file. I recommend moving it to environment variables immediately.',
    notificationZh:
      '發現一個安全問題：你的資料庫密碼透過 .env 檔案公開了。建議立即將它移到環境變數中。',
  },
];

const SMALL_BIZ_SCENARIOS: ScenarioStory[] = [
  {
    id: 'biz-ransomware',
    threatType: 'Ransomware',
    beforeEn:
      'An employee clicks a phishing email attachment. Ransomware encrypts the company NAS within 15 minutes. The company goes bankrupt.',
    beforeZh: '員工點了釣魚信件的附件。勒索軟體在 15 分鐘內加密了公司 NAS。公司倒閉。',
    afterEn:
      'Panguard AI detects the ransomware within 3 seconds of execution, isolates the file before encryption begins, and notifies the boss.',
    afterZh: 'Panguard AI 在勒索軟體執行的 3 秒內偵測到它，在加密開始前隔離檔案，並通知老闆。',
    notificationEn:
      "Found a ransomware (LockBit type) on Ms. Wang's computer. Already intercepted and isolated before it could encrypt any files.",
    notificationZh:
      '在王小姐的電腦上發現一個勒索病毒（LockBit 類型）。已在它加密檔案之前攔截並隔離。',
  },
  {
    id: 'biz-weak-password',
    threatType: 'Weak Passwords',
    beforeEn:
      'Your employees use "123456" and "password" for everything. You have no password policy because no one knows how to set one up.',
    beforeZh:
      '你的員工所有帳號都用「123456」和「password」。你沒有密碼政策，因為沒人知道怎麼設定。',
    afterEn:
      'Panguard Scan identifies all weak password policies and explains what to do in plain language.',
    afterZh: 'Panguard Scan 找出所有弱密碼政策，用白話文告訴你該怎麼做。',
    notificationEn:
      'Your system allows passwords as short as 1 character. I recommend requiring at least 12 characters with a mix of letters, numbers, and symbols.',
    notificationZh:
      '你的系統允許只有 1 個字元的密碼。建議要求至少 12 個字元，混合英文、數字和符號。',
  },
];

const ENTERPRISE_SCENARIOS: ScenarioStory[] = [
  {
    id: 'ent-compliance',
    threatType: 'Compliance Gap',
    beforeEn:
      'An audit is coming in 2 weeks. You need to prove compliance with the Cyber Security Management Act but have no documentation.',
    beforeZh: '稽核 2 週後就來了。你需要證明符合資通安全管理法但沒有任何文件。',
    afterEn:
      'Panguard Report generates a complete compliance report in 5 minutes, mapping your security posture to all 10 control requirements.',
    afterZh:
      'Panguard Report 在 5 分鐘內產生完整的合規報告，將你的資安狀態對應到全部 10 個控制項。',
    notificationEn:
      'Your compliance report is ready. Overall score: 72%. 2 controls need immediate attention. Report has been sent to your email.',
    notificationZh:
      '你的合規報告已經產生。整體分數：72%。2 個控制項需要立即處理。報告已寄到你的信箱。',
  },
  {
    id: 'ent-lateral-movement',
    threatType: 'Lateral Movement',
    beforeEn:
      'An attacker gained access to one workstation and is silently moving across your network to reach the database server.',
    beforeZh: '攻擊者取得了一台工作站的存取權限，正在悄悄地在你的網路中移動，目標是資料庫伺服器。',
    afterEn:
      'Panguard Guard detects abnormal internal connections, blocks the lateral movement, and notifies the IT admin with full investigation results.',
    afterZh: 'Panguard Guard 偵測到異常的內部連線，封鎖橫向移動，並將完整調查結果通知 IT 管理員。',
    notificationEn:
      'Your server is trying to connect to an address it has never connected to before. This is abnormal. I have blocked this connection and am investigating.',
    notificationZh:
      '你的伺服器正在嘗試連線到一個它從來沒連過的可疑地址。這不正常。我已阻止這個連線並在調查中。',
  },
];

// ---------------------------------------------------------------------------
// Persona definitions
// 角色定義
// ---------------------------------------------------------------------------

export const PERSONAS: Record<string, PersonaProfile> = {
  developer: {
    type: 'developer',
    nameEn: 'Individual Developer / AI Developer',
    nameZh: '個人開發者 / AI 開發者',
    descriptionEn:
      'Has a VPS exposed to the internet. AI-generated code quality varies. No time for security.',
    descriptionZh: '有 VPS 暴露在公網上。AI 生成的 code 品質不穩定。沒時間管資安。',
    painPointsEn: [
      'Server exposed to public internet with no protection',
      'AI-generated code may have security vulnerabilities',
      'Too busy building product to think about security',
      'No idea what attacks are happening right now',
    ],
    painPointsZh: [
      '伺服器暴露在公網上沒有任何防護',
      'AI 生成的程式碼可能有安全漏洞',
      '忙著做產品，沒時間想資安',
      '完全不知道現在正在發生什麼攻擊',
    ],
    recommendedPlan: 'solo',
    scenarios: DEVELOPER_SCENARIOS,
  },

  small_business: {
    type: 'small_business',
    nameEn: 'Small Business (5-50 employees)',
    nameZh: '小型企業（5-50 人）',
    descriptionEn:
      'No IT department. Employees click on phishing emails. One ransomware attack could shut down the company.',
    descriptionZh: '沒有 IT 部門。員工會亂點附件。一次勒索軟體攻擊就可能倒閉。',
    painPointsEn: [
      'No dedicated IT or security team',
      'Employees lack security awareness training',
      'One ransomware attack could bankrupt the company',
      'Cannot afford enterprise security solutions',
    ],
    painPointsZh: [
      '沒有專職的 IT 或資安團隊',
      '員工缺乏資安意識訓練',
      '一次勒索軟體攻擊就可能讓公司倒閉',
      '負擔不起企業級資安解決方案',
    ],
    recommendedPlan: 'team',
    scenarios: SMALL_BIZ_SCENARIOS,
  },

  mid_enterprise: {
    type: 'mid_enterprise',
    nameEn: 'Mid-size Enterprise (50-500 employees)',
    nameZh: '中型企業（50-500 人）',
    descriptionEn: 'Has IT but no security team. Needs compliance reports for audits.',
    descriptionZh: '有 IT 沒有資安。需要合規報告來通過稽核。',
    painPointsEn: [
      'IT team is stretched thin, no dedicated security staff',
      'Compliance requirements (Cyber Security Act, ISO 27001)',
      'Need audit-ready reports on short notice',
      'Multiple offices/servers to protect',
    ],
    painPointsZh: [
      'IT 團隊人手不足，沒有專職資安人員',
      '合規要求（資通安全管理法、ISO 27001）',
      '需要隨時能拿出稽核用的報告',
      '多個辦公室 / 伺服器需要防護',
    ],
    recommendedPlan: 'business',
    scenarios: ENTERPRISE_SCENARIOS,
  },
};

/**
 * Get persona by type
 * 根據類型取得角色
 */
export function getPersona(type: string): PersonaProfile | undefined {
  return PERSONAS[type];
}

/**
 * Get all personas
 * 取得所有角色
 */
export function getAllPersonas(): PersonaProfile[] {
  return Object.values(PERSONAS);
}
