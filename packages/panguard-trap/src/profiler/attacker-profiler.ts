/**
 * Attacker Profiling Engine
 * 攻擊者分析引擎
 *
 * Analyzes trap sessions to build attacker profiles:
 * - Skill level estimation
 * - Intent classification
 * - Tool detection
 * - Credential pattern analysis
 * - MITRE ATT&CK technique mapping
 *
 * 分析蜜罐連線以建立攻擊者 profile：
 * - 技術水準估計
 * - 意圖分類
 * - 工具偵測
 * - 認證模式分析
 * - MITRE ATT&CK 技術映射
 *
 * @module @panguard-ai/panguard-trap/profiler/attacker-profiler
 */

import { createLogger } from '@panguard-ai/core';
import type { TrapSession, AttackerProfile, AttackerSkillLevel, AttackerIntent } from '../types.js';

const logger = createLogger('panguard-trap:profiler');

// ---------------------------------------------------------------------------
// Skill Level Estimation
// 技術水準估計
// ---------------------------------------------------------------------------

/** Known tool signatures / 已知工具特徵 */
const TOOL_SIGNATURES: { pattern: RegExp; tool: string; skillBoost: number }[] = [
  { pattern: /nmap/i, tool: 'nmap', skillBoost: 10 },
  { pattern: /metasploit|msfconsole|meterpreter/i, tool: 'Metasploit', skillBoost: 20 },
  { pattern: /hydra/i, tool: 'Hydra', skillBoost: 15 },
  { pattern: /sqlmap/i, tool: 'sqlmap', skillBoost: 15 },
  { pattern: /nikto/i, tool: 'Nikto', skillBoost: 10 },
  { pattern: /gobuster|dirbuster|dirb/i, tool: 'Directory Buster', skillBoost: 10 },
  { pattern: /burp/i, tool: 'Burp Suite', skillBoost: 20 },
  { pattern: /cobalt\s*strike|beacon/i, tool: 'Cobalt Strike', skillBoost: 40 },
  { pattern: /mimikatz/i, tool: 'Mimikatz', skillBoost: 30 },
  { pattern: /bloodhound/i, tool: 'BloodHound', skillBoost: 30 },
  { pattern: /empire|stager/i, tool: 'Empire', skillBoost: 25 },
  { pattern: /xmrig|minergate|cryptonight/i, tool: 'Cryptominer', skillBoost: 5 },
  { pattern: /masscan/i, tool: 'Masscan', skillBoost: 10 },
  { pattern: /wpscan/i, tool: 'WPScan', skillBoost: 10 },
];

/** Advanced command patterns that indicate higher skill / 表示較高技術的進階指令模式 */
const ADVANCED_PATTERNS: RegExp[] = [
  /base64\s+-d/i,
  /python\s+-c/i,
  /perl\s+-e/i,
  /awk\s+'{/i,
  /sed\s+-[ie]/i,
  /\/proc\/self/i,
  /ld_preload/i,
  /ptrace/i,
  /ebpf|bpf/i,
  /\.\.\/\.\.\/\.\.\/etc/i,
  /reverse.*shell/i,
  /bind.*shell/i,
];

/**
 * Estimate attacker skill level based on behavior
 * 根據行為估計攻擊者技術水準
 */
export function estimateSkillLevel(
  commands: string[],
  mitreTechniques: string[],
  toolsDetected: string[]
): { level: AttackerSkillLevel; score: number } {
  let score = 0;

  // Base score from technique count
  score += mitreTechniques.length * 5;

  // Tool-based scoring
  score += toolsDetected.length * 8;

  // Advanced command patterns
  for (const cmd of commands) {
    for (const pattern of ADVANCED_PATTERNS) {
      if (pattern.test(cmd)) {
        score += 10;
        break;
      }
    }
  }

  // Command diversity
  const uniqueCommands = new Set(commands.map((c) => c.split(' ')[0]?.toLowerCase()));
  if (uniqueCommands.size > 10) score += 15;
  else if (uniqueCommands.size > 5) score += 8;

  // MITRE technique diversity
  if (mitreTechniques.length > 5) score += 20;
  else if (mitreTechniques.length > 3) score += 10;

  // Classify
  let level: AttackerSkillLevel;
  if (score >= 60) level = 'apt';
  else if (score >= 35) level = 'advanced';
  else if (score >= 15) level = 'intermediate';
  else level = 'script_kiddie';

  return { level, score: Math.min(score, 100) };
}

// ---------------------------------------------------------------------------
// Intent Classification
// 意圖分類
// ---------------------------------------------------------------------------

/** Intent indicators / 意圖指標 */
const INTENT_INDICATORS: { pattern: RegExp; intent: AttackerIntent; weight: number }[] = [
  {
    pattern: /whoami|id\s|uname|hostname|ifconfig|ip\s+addr|cat\s+\/etc\/passwd/i,
    intent: 'reconnaissance',
    weight: 3,
  },
  {
    pattern: /shadow|passwd|credential|hash|dump|mimikatz/i,
    intent: 'credential_harvesting',
    weight: 5,
  },
  {
    pattern: /encrypt|ransom|lockbit|cryptolocker|\.locked|\.crypt/i,
    intent: 'ransomware_deployment',
    weight: 8,
  },
  { pattern: /xmrig|miner|cryptonight|stratum|pool\./i, intent: 'cryptomining', weight: 8 },
  {
    pattern: /tar\s+.*\.gz|zip\s+|scp\s+|rsync|curl.*upload|wget.*post/i,
    intent: 'data_theft',
    weight: 5,
  },
  { pattern: /irc\s|c2\s|beacon|callback|botnet|zombie/i, intent: 'botnet_recruitment', weight: 6 },
  { pattern: /ssh\s+\w+@|psexec|wmic|net\s+use|smbclient/i, intent: 'lateral_movement', weight: 5 },
];

/**
 * Classify attacker intent based on behavior
 * 根據行為分類攻擊者意圖
 */
export function classifyIntent(commands: string[], mitreTechniques: string[]): AttackerIntent {
  const scores: Partial<Record<AttackerIntent, number>> = {};

  for (const cmd of commands) {
    for (const indicator of INTENT_INDICATORS) {
      if (indicator.pattern.test(cmd)) {
        scores[indicator.intent] = (scores[indicator.intent] ?? 0) + indicator.weight;
      }
    }
  }

  const techniqueToIntent: Record<string, AttackerIntent> = {
    T1082: 'reconnaissance',
    T1016: 'reconnaissance',
    T1057: 'reconnaissance',
    T1003: 'credential_harvesting',
    T1110: 'credential_harvesting',
    T1486: 'ransomware_deployment',
    T1496: 'cryptomining',
    T1005: 'data_theft',
    T1041: 'data_theft',
    T1021: 'lateral_movement',
    T1570: 'lateral_movement',
  };

  for (const tech of mitreTechniques) {
    const intent = techniqueToIntent[tech];
    if (intent) {
      scores[intent] = (scores[intent] ?? 0) + 3;
    }
  }

  let maxScore = 0;
  let maxIntent: AttackerIntent = 'unknown';

  for (const [intent, score] of Object.entries(scores)) {
    if (score > maxScore) {
      maxScore = score;
      maxIntent = intent as AttackerIntent;
    }
  }

  return maxIntent;
}

// ---------------------------------------------------------------------------
// Tool Detection
// 工具偵測
// ---------------------------------------------------------------------------

/**
 * Detect tools used by attacker
 * 偵測攻擊者使用的工具
 */
export function detectTools(commands: string[], userAgents?: string[]): string[] {
  const tools: Set<string> = new Set();

  const allInputs = [...commands, ...(userAgents ?? [])];

  for (const input of allInputs) {
    for (const sig of TOOL_SIGNATURES) {
      if (sig.pattern.test(input)) {
        tools.add(sig.tool);
      }
    }
  }

  return Array.from(tools);
}

// ---------------------------------------------------------------------------
// Attacker Profiler
// 攻擊者分析器
// ---------------------------------------------------------------------------

/**
 * AttackerProfiler - builds and maintains attacker profiles
 * AttackerProfiler - 建立和維護攻擊者 profile
 */
export class AttackerProfiler {
  private profiles: Map<string, AttackerProfile> = new Map();
  private ipToProfile: Map<string, string> = new Map();
  private profileCounter = 0;

  /**
   * Process a completed trap session and update/create attacker profile
   * 處理已完成的蜜罐連線並更新/建立攻擊者 profile
   */
  processSession(session: TrapSession): AttackerProfile {
    const existingProfileId = this.ipToProfile.get(session.sourceIP);
    let profile: AttackerProfile;

    if (existingProfileId) {
      profile = this.profiles.get(existingProfileId)!;
      this.updateProfile(profile, session);
    } else {
      profile = this.createProfile(session);
      this.profiles.set(profile.profileId, profile);
      this.ipToProfile.set(session.sourceIP, profile.profileId);
    }

    session.attackerProfileId = profile.profileId;

    logger.info(
      `Attacker profile updated: ${profile.profileId} (skill=${profile.skillLevel}, intent=${profile.intent}) / 攻擊者 profile 已更新`
    );

    return profile;
  }

  /** Get a profile by ID / 依 ID 取得 profile */
  getProfile(profileId: string): AttackerProfile | undefined {
    return this.profiles.get(profileId);
  }

  /** Get profile by IP / 依 IP 取得 profile */
  getProfileByIP(ip: string): AttackerProfile | undefined {
    const profileId = this.ipToProfile.get(ip);
    return profileId ? this.profiles.get(profileId) : undefined;
  }

  /** Get all profiles / 取得所有 profiles */
  getAllProfiles(): AttackerProfile[] {
    return Array.from(this.profiles.values());
  }

  /** Get top attackers by risk score / 依風險分數取得前幾名攻擊者 */
  getTopAttackers(limit = 10): AttackerProfile[] {
    return this.getAllProfiles()
      .sort((a, b) => b.riskScore - a.riskScore)
      .slice(0, limit);
  }

  /** Get profile count / 取得 profile 數量 */
  getProfileCount(): number {
    return this.profiles.size;
  }

  /** Clear all profiles / 清除所有 profiles */
  clear(): void {
    this.profiles.clear();
    this.ipToProfile.clear();
  }

  // -------------------------------------------------------------------------
  // Internal
  // -------------------------------------------------------------------------

  private createProfile(session: TrapSession): AttackerProfile {
    this.profileCounter += 1;
    const profileId = `atk-${Date.now().toString(36)}-${this.profileCounter.toString(36).padStart(3, '0')}`;

    const tools = detectTools(session.commands);
    const { level, score } = estimateSkillLevel(session.commands, session.mitreTechniques, tools);
    const intent = classifyIntent(session.commands, session.mitreTechniques);

    return {
      profileId,
      sourceIPs: [session.sourceIP],
      firstSeen: session.startTime,
      lastSeen: session.endTime ?? session.startTime,
      totalSessions: 1,
      skillLevel: level,
      intent,
      toolsDetected: tools,
      mitreTechniques: [...session.mitreTechniques],
      credentialPatterns: {
        commonUsernames: session.credentials.map((c) => c.username).filter(Boolean),
        commonPasswords: session.credentials.map((c) => c.password).filter(Boolean),
        totalAttempts: session.credentials.length,
      },
      geoHints: {},
      riskScore: score,
    };
  }

  private updateProfile(profile: AttackerProfile, session: TrapSession): void {
    if (!profile.sourceIPs.includes(session.sourceIP)) {
      profile.sourceIPs.push(session.sourceIP);
    }

    profile.lastSeen = session.endTime ?? session.startTime;
    profile.totalSessions += 1;

    for (const tech of session.mitreTechniques) {
      if (!profile.mitreTechniques.includes(tech)) {
        profile.mitreTechniques.push(tech);
      }
    }

    const newTools = detectTools(session.commands);
    for (const tool of newTools) {
      if (!profile.toolsDetected.includes(tool)) {
        profile.toolsDetected.push(tool);
      }
    }

    for (const cred of session.credentials) {
      if (cred.username && !profile.credentialPatterns.commonUsernames.includes(cred.username)) {
        profile.credentialPatterns.commonUsernames.push(cred.username);
      }
      if (cred.password && !profile.credentialPatterns.commonPasswords.includes(cred.password)) {
        profile.credentialPatterns.commonPasswords.push(cred.password);
      }
    }
    profile.credentialPatterns.totalAttempts += session.credentials.length;

    const { level, score } = estimateSkillLevel(
      session.commands,
      profile.mitreTechniques,
      profile.toolsDetected
    );

    const SKILL_ORDER: AttackerSkillLevel[] = ['script_kiddie', 'intermediate', 'advanced', 'apt'];
    if (SKILL_ORDER.indexOf(level) > SKILL_ORDER.indexOf(profile.skillLevel)) {
      profile.skillLevel = level;
    }

    profile.riskScore = Math.max(profile.riskScore, score);
    profile.intent = classifyIntent(session.commands, profile.mitreTechniques);
  }
}
