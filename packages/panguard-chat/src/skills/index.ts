/**
 * Panguard Skill Definitions for PanguardChat
 * PanguardChat 的 Panguard Skill 定義
 *
 * Skills are structured commands that the Chat Agent can invoke
 * in response to user requests via messaging channels.
 * Skills 是 Chat Agent 可以在回應用戶訊息時調用的結構化指令。
 *
 * @module @panguard-ai/panguard-chat/skills
 */

export const SKILLS_VERSION = '0.1.0';

// ---------------------------------------------------------------------------
// Skill type definitions
// ---------------------------------------------------------------------------

/** Skill parameter definition */
export interface SkillParam {
  readonly name: string;
  readonly description: string;
  readonly descriptionZh: string;
  readonly required: boolean;
  readonly type: 'string' | 'number' | 'boolean';
  readonly defaultValue?: string | number | boolean;
}

/** Skill definition */
export interface Skill {
  readonly id: string;
  readonly name: string;
  readonly nameZh: string;
  readonly description: string;
  readonly descriptionZh: string;
  readonly category: 'scan' | 'guard' | 'trap' | 'report' | 'system' | 'info';
  readonly params: readonly SkillParam[];
  readonly examples: readonly string[];
}

// ---------------------------------------------------------------------------
// Skill registry
// ---------------------------------------------------------------------------

export const SKILLS: readonly Skill[] = [
  // ── Scan ──────────────────────────────────────────────────────────────
  {
    id: 'scan_quick',
    name: 'Quick Scan',
    nameZh: '快速掃描',
    description: 'Run a quick security scan on the system',
    descriptionZh: '對系統執行快速安全掃描',
    category: 'scan',
    params: [
      {
        name: 'target',
        description: 'Target path or "system" for full scan',
        descriptionZh: '目標路徑或 "system" 執行完整掃描',
        required: false,
        type: 'string',
        defaultValue: 'system',
      },
    ],
    examples: ['scan my system', 'run a quick scan', '掃描系統'],
  },
  {
    id: 'scan_compliance',
    name: 'Compliance Scan',
    nameZh: '合規掃描',
    description: 'Run a compliance assessment against a framework',
    descriptionZh: '依照框架執行合規評估',
    category: 'scan',
    params: [
      {
        name: 'framework',
        description: 'Compliance framework (iso27001, soc2, tw_cyber_security_act)',
        descriptionZh: '合規框架（iso27001, soc2, tw_cyber_security_act）',
        required: false,
        type: 'string',
        defaultValue: 'iso27001',
      },
    ],
    examples: ['check ISO 27001 compliance', '執行 SOC 2 合規檢查'],
  },

  // ── Guard ─────────────────────────────────────────────────────────────
  {
    id: 'guard_status',
    name: 'Guard Status',
    nameZh: '防護狀態',
    description: 'Show current Guard engine status and recent verdicts',
    descriptionZh: '顯示目前 Guard 引擎狀態和最近的判定',
    category: 'guard',
    params: [],
    examples: ['guard status', 'is the guard running?', '防護狀態'],
  },
  {
    id: 'guard_block_ip',
    name: 'Block IP',
    nameZh: '封鎖 IP',
    description: 'Block an IP address via the Guard respond agent',
    descriptionZh: '透過 Guard 回應代理封鎖 IP',
    category: 'guard',
    params: [
      {
        name: 'ip',
        description: 'IP address to block',
        descriptionZh: '要封鎖的 IP 位址',
        required: true,
        type: 'string',
      },
      {
        name: 'duration',
        description: 'Block duration in hours (0 = permanent)',
        descriptionZh: '封鎖時長（小時，0 = 永久）',
        required: false,
        type: 'number',
        defaultValue: 1,
      },
    ],
    examples: ['block 192.168.1.100', '封鎖 10.0.0.5 持續 24 小時'],
  },
  {
    id: 'guard_unblock_ip',
    name: 'Unblock IP',
    nameZh: '解除封鎖 IP',
    description: 'Unblock a previously blocked IP address',
    descriptionZh: '解除先前封鎖的 IP',
    category: 'guard',
    params: [
      {
        name: 'ip',
        description: 'IP address to unblock',
        descriptionZh: '要解除封鎖的 IP 位址',
        required: true,
        type: 'string',
      },
    ],
    examples: ['unblock 192.168.1.100', '解除封鎖 10.0.0.5'],
  },

  // ── Trap ──────────────────────────────────────────────────────────────
  {
    id: 'trap_status',
    name: 'Trap Status',
    nameZh: '蜜罐狀態',
    description: 'Show honeypot service status and recent catch statistics',
    descriptionZh: '顯示蜜罐服務狀態和最近的捕獲統計',
    category: 'trap',
    params: [],
    examples: ['honeypot status', 'any catches today?', '蜜罐狀態'],
  },
  {
    id: 'trap_top_attackers',
    name: 'Top Attackers',
    nameZh: '攻擊者排行',
    description: 'Show the top attacker IPs from honeypot data',
    descriptionZh: '顯示蜜罐資料中的攻擊者排行',
    category: 'trap',
    params: [
      {
        name: 'limit',
        description: 'Number of top attackers to show',
        descriptionZh: '顯示前幾名攻擊者',
        required: false,
        type: 'number',
        defaultValue: 10,
      },
    ],
    examples: ['show top attackers', '前 5 名攻擊者'],
  },

  // ── Report ────────────────────────────────────────────────────────────
  {
    id: 'report_generate',
    name: 'Generate Report',
    nameZh: '產生報告',
    description: 'Generate a compliance report with live assessment',
    descriptionZh: '使用即時評估產生合規報告',
    category: 'report',
    params: [
      {
        name: 'framework',
        description: 'Compliance framework',
        descriptionZh: '合規框架',
        required: false,
        type: 'string',
        defaultValue: 'iso27001',
      },
      {
        name: 'language',
        description: 'Report language (en or zh-TW)',
        descriptionZh: '報告語言（en 或 zh-TW）',
        required: false,
        type: 'string',
        defaultValue: 'zh-TW',
      },
    ],
    examples: ['generate ISO 27001 report', '產生 SOC 2 報告'],
  },
  {
    id: 'report_summary',
    name: 'Report Summary',
    nameZh: '報告摘要',
    description: 'Show a brief compliance summary without generating a full report',
    descriptionZh: '顯示簡短合規摘要',
    category: 'report',
    params: [],
    examples: ['compliance summary', '合規摘要'],
  },

  // ── System ────────────────────────────────────────────────────────────
  {
    id: 'system_health',
    name: 'System Health',
    nameZh: '系統健康',
    description: 'Show overall Panguard system health (all modules)',
    descriptionZh: '顯示 Panguard 系統整體健康狀態（所有模組）',
    category: 'system',
    params: [],
    examples: ['system health', 'how is everything?', '系統狀態'],
  },
  {
    id: 'system_config',
    name: 'Show Config',
    nameZh: '顯示設定',
    description: 'Show current Panguard configuration',
    descriptionZh: '顯示目前 Panguard 設定',
    category: 'system',
    params: [],
    examples: ['show config', '目前設定'],
  },

  // ── Info ──────────────────────────────────────────────────────────────
  {
    id: 'info_explain',
    name: 'Explain Event',
    nameZh: '解釋事件',
    description: 'Explain a security event or MITRE technique in plain language',
    descriptionZh: '用白話解釋安全事件或 MITRE 技術',
    category: 'info',
    params: [
      {
        name: 'topic',
        description: 'Event ID, MITRE technique (e.g. T1059), or keyword',
        descriptionZh: '事件 ID、MITRE 技術（如 T1059）或關鍵字',
        required: true,
        type: 'string',
      },
    ],
    examples: ['what is T1059?', 'explain brute force', '什麼是 SQL injection'],
  },
  {
    id: 'info_help',
    name: 'Help',
    nameZh: '幫助',
    description: 'List available commands and how to use them',
    descriptionZh: '列出可用指令和使用方法',
    category: 'info',
    params: [],
    examples: ['help', 'what can you do?', '你能做什麼'],
  },
] as const;

// ---------------------------------------------------------------------------
// Skill lookup helpers
// ---------------------------------------------------------------------------

/** Find a skill by ID */
export function getSkillById(id: string): Skill | undefined {
  return SKILLS.find((s) => s.id === id);
}

/** Find skills by category */
export function getSkillsByCategory(category: Skill['category']): readonly Skill[] {
  return SKILLS.filter((s) => s.category === category);
}

/**
 * Match a user message to the most likely skill.
 * Returns null if no skill matches above the confidence threshold.
 */
export function matchSkill(message: string): { skill: Skill; confidence: number } | null {
  const lower = message.toLowerCase().trim();
  let bestMatch: { skill: Skill; confidence: number } | null = null;

  for (const skill of SKILLS) {
    let score = 0;

    // Check example phrases
    for (const example of skill.examples) {
      const exLower = example.toLowerCase();
      if (lower === exLower) {
        score = Math.max(score, 100);
      } else if (lower.includes(exLower) || exLower.includes(lower)) {
        score = Math.max(score, 70);
      }
    }

    // Check skill name keywords
    const nameWords = skill.name.toLowerCase().split(/\s+/);
    const nameZhChars = skill.nameZh;
    for (const word of nameWords) {
      if (lower.includes(word)) {
        score = Math.max(score, 50);
      }
    }
    if (lower.includes(nameZhChars)) {
      score = Math.max(score, 60);
    }

    // Check skill ID keywords
    const idParts = skill.id.split('_');
    if (idParts.every((part) => lower.includes(part))) {
      score = Math.max(score, 55);
    }

    if (score > 0 && (!bestMatch || score > bestMatch.confidence)) {
      bestMatch = { skill, confidence: score };
    }
  }

  // Only return matches above threshold
  return bestMatch && bestMatch.confidence >= 40 ? bestMatch : null;
}

/** Format skills as a help message for a given language */
export function formatSkillsHelp(language: 'en' | 'zh-TW'): string {
  const isZh = language === 'zh-TW';
  const lines: string[] = [];

  lines.push(isZh ? '=== 可用指令 ===' : '=== Available Commands ===');
  lines.push('');

  const categories: Skill['category'][] = ['scan', 'guard', 'trap', 'report', 'system', 'info'];
  const categoryLabels: Record<Skill['category'], { en: string; zh: string }> = {
    scan: { en: 'Scanning', zh: '掃描' },
    guard: { en: 'Guard', zh: '防護' },
    trap: { en: 'Honeypot', zh: '蜜罐' },
    report: { en: 'Report', zh: '報告' },
    system: { en: 'System', zh: '系統' },
    info: { en: 'Information', zh: '資訊' },
  };

  for (const cat of categories) {
    const skills = getSkillsByCategory(cat);
    if (skills.length === 0) continue;

    const label = isZh ? categoryLabels[cat].zh : categoryLabels[cat].en;
    lines.push(`[${label}]`);

    for (const skill of skills) {
      const name = isZh ? skill.nameZh : skill.name;
      const desc = isZh ? skill.descriptionZh : skill.description;
      lines.push(`  ${name} - ${desc}`);
      lines.push(`    ${isZh ? '範例' : 'Examples'}: ${skill.examples.slice(0, 2).join(', ')}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}
