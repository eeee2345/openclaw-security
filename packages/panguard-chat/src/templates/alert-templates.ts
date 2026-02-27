/**
 * Alert Message Templates
 * 告警訊息模板
 *
 * Pre-built templates for common security alert scenarios.
 * Each template provides human-friendly descriptions for common attacks.
 * 常見安全告警場景的預建模板。
 * 每個模板提供常見攻擊的人性化描述。
 *
 * @module @panguard-ai/panguard-chat/templates/alert-templates
 */

import type { MessageLanguage } from '../types.js';

// ---------------------------------------------------------------------------
// Template Types
// 模板類型
// ---------------------------------------------------------------------------

/** Alert template for a specific attack type / 特定攻擊類型的告警模板 */
export interface AlertTemplate {
  readonly attackType: string;
  readonly humanSummary: Record<MessageLanguage, string>;
  readonly analogy: Record<MessageLanguage, string>;
  readonly recommendedAction: Record<MessageLanguage, string>;
}

// ---------------------------------------------------------------------------
// Alert Templates
// 告警模板
// ---------------------------------------------------------------------------

/** Built-in alert templates for common attack scenarios / 常見攻擊場景的內建告警模板 */
export const ALERT_TEMPLATES: readonly AlertTemplate[] = [
  {
    attackType: 'ssh_brute_force',
    humanSummary: {
      'zh-TW': '有人正在嘗試猜你的密碼登入。已嘗試 {{count}} 次，全部失敗。',
      en: 'Someone is trying to guess your login password. {{count}} attempts, all failed.',
    },
    analogy: {
      'zh-TW': '就像有人在嘗試所有鑰匙組合來開你家的門',
      en: "It's like someone trying every key combination to open your front door",
    },
    recommendedAction: {
      'zh-TW': '建議啟用雙因素認證，並檢查所有帳號密碼強度。',
      en: 'We recommend enabling two-factor authentication and checking all account password strength.',
    },
  },
  {
    attackType: 'ransomware_detected',
    humanSummary: {
      'zh-TW': '發現一個勒索病毒（{{variant}} 類型）。已在它加密檔案之前攔截並隔離。',
      en: 'A ransomware variant ({{variant}} type) was detected. It was intercepted and quarantined before encrypting files.',
    },
    analogy: {
      'zh-TW': '就像在小偷把你的檔案鎖進保險箱之前抓到了他',
      en: 'Like catching a thief before they could lock your files in a safe',
    },
    recommendedAction: {
      'zh-TW': '建議檢查最近的備份是否完整，確保所有系統已更新到最新版本。',
      en: 'We recommend verifying your recent backups are complete and ensuring all systems are up to date.',
    },
  },
  {
    attackType: 'sql_injection',
    humanSummary: {
      'zh-TW': '有人試圖透過你的網站竊取資料庫中的資料。已成功阻擋。',
      en: 'Someone attempted to steal data from your database through your website. Successfully blocked.',
    },
    analogy: {
      'zh-TW': '就像有人試圖用特殊技巧讓你的網站說出不該說的秘密',
      en: "Like someone trying to trick your website into revealing secrets it shouldn't",
    },
    recommendedAction: {
      'zh-TW': '建議更新網站應用程式，並檢查是否有未修復的安全漏洞。',
      en: 'We recommend updating your web application and checking for unpatched security vulnerabilities.',
    },
  },
  {
    attackType: 'suspicious_outbound',
    humanSummary: {
      'zh-TW': '你的伺服器正在嘗試連線到一個它從來沒連過的可疑地址。這不正常。已阻止此連線。',
      en: 'Your server is trying to connect to a suspicious address it has never contacted before. This is unusual. Connection blocked.',
    },
    analogy: {
      'zh-TW': '就像發現你家的電話半夜自動撥打一個陌生號碼',
      en: 'Like discovering your phone is making calls to an unknown number in the middle of the night',
    },
    recommendedAction: {
      'zh-TW': '建議檢查伺服器上最近安裝的軟體和正在執行的程序。',
      en: 'We recommend checking recently installed software and running processes on the server.',
    },
  },
  {
    attackType: 'encoded_command',
    humanSummary: {
      'zh-TW': '有個程式試圖在背景執行一段加密的指令。這通常是駭客在做的事。已阻止執行。',
      en: 'A program tried to execute an encoded command in the background. This is typically attacker behavior. Execution blocked.',
    },
    analogy: {
      'zh-TW': '就像有人在你的電腦上偷偷執行一段用密碼寫的指令',
      en: 'Like someone secretly running coded instructions on your computer',
    },
    recommendedAction: {
      'zh-TW': '建議掃描整台電腦，檢查是否有其他可疑程式。',
      en: 'We recommend scanning the entire system for other suspicious programs.',
    },
  },
  {
    attackType: 'privilege_escalation',
    humanSummary: {
      'zh-TW': '一個普通程式試圖取得系統最高權限。這可能是攻擊者在嘗試控制你的電腦。已阻止。',
      en: 'A regular program tried to gain system administrator privileges. This could be an attacker trying to take control. Blocked.',
    },
    analogy: {
      'zh-TW': '就像一個普通員工試圖偷走公司保險箱的鑰匙',
      en: 'Like a regular employee trying to steal the keys to the company safe',
    },
    recommendedAction: {
      'zh-TW': '建議檢查該程式的來源，並確認系統上的帳號權限設定是否正確。',
      en: "We recommend checking the program's origin and verifying account permission settings on the system.",
    },
  },
  {
    attackType: 'data_exfiltration',
    humanSummary: {
      'zh-TW': '偵測到大量資料正在被傳送到外部。已暫停傳輸並等待您的確認。',
      en: 'Large amounts of data were being transmitted externally. Transfer suspended pending your confirmation.',
    },
    analogy: {
      'zh-TW': '就像發現有人正在把你辦公室的文件一箱一箱搬出去',
      en: 'Like discovering someone is carrying boxes of your office documents out the back door',
    },
    recommendedAction: {
      'zh-TW': '請確認這是否為正常的資料傳輸。如果不是，建議立即調查資料外洩的範圍。',
      en: 'Please confirm whether this is a legitimate data transfer. If not, we recommend immediately investigating the scope of data exposure.',
    },
  },
];

// ---------------------------------------------------------------------------
// Template Lookup
// 模板查詢
// ---------------------------------------------------------------------------

/**
 * Find an alert template by attack type
 * 依攻擊類型查找告警模板
 *
 * @param attackType - The attack type identifier / 攻擊類型識別碼
 * @returns Alert template or undefined / 告警模板或 undefined
 */
export function findAlertTemplate(attackType: string): AlertTemplate | undefined {
  return ALERT_TEMPLATES.find((t) => t.attackType === attackType);
}

/**
 * Get the human-friendly summary for an attack type
 * 取得攻擊類型的人性化摘要
 *
 * @param attackType - The attack type / 攻擊類型
 * @param language - Target language / 目標語言
 * @param params - Template parameters / 模板參數
 * @returns Human-friendly summary or undefined / 人性化摘要或 undefined
 */
export function getHumanSummary(
  attackType: string,
  language: MessageLanguage,
  params?: Record<string, string | number>
): string | undefined {
  const template = findAlertTemplate(attackType);
  if (!template) return undefined;

  let text = template.humanSummary[language];
  if (params) {
    for (const [key, value] of Object.entries(params)) {
      text = text.replace(`{{${key}}}`, String(value));
    }
  }
  return text;
}
