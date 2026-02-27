/**
 * Achievement System - Security gamification with badges and milestones
 * 成就系統 - 安全遊戲化（徽章與里程碑）
 *
 * Tracks user progress and awards achievements for security best practices.
 * Designed to encourage continuous security improvement.
 *
 * @module @panguard-ai/core/scoring/achievements
 */

import { createLogger } from '../utils/logger.js';

const logger = createLogger('achievements');

/** Achievement definition / 成就定義 */
export interface Achievement {
  id: string;
  name: string;
  nameZhTW: string;
  description: string;
  descriptionZhTW: string;
  category: 'scan' | 'guard' | 'response' | 'compliance' | 'streak';
  icon: string; // ASCII icon for CLI
  condition: (stats: AchievementStats) => boolean;
}

/** User stats for achievement checking / 成就檢查的用戶統計 */
export interface AchievementStats {
  totalScans: number;
  consecutiveSafeDays: number;
  threatsBlocked: number;
  vulnsFixedWithin24h: number;
  totalVulnsFixed: number;
  complianceScore: number;
  securityScore: number;
  allRecommendationsEnabled: boolean;
  firstScanCompleted: boolean;
  guardRunningDays: number;
  rulesActive: number;
  chatChannelsConfigured: number;
}

/** Earned achievement / 已獲得的成就 */
export interface EarnedAchievement {
  achievement: Achievement;
  earnedAt: string;
  notified: boolean;
}

/** All defined achievements / 所有已定義的成就 */
export const ACHIEVEMENTS: Achievement[] = [
  // Scan achievements
  {
    id: 'first_scan',
    name: 'First Scan',
    nameZhTW: 'First Scan',
    description: 'Complete your first security scan',
    descriptionZhTW: 'Complete your first security scan',
    category: 'scan',
    icon: '[SCAN]',
    condition: (s) => s.firstScanCompleted,
  },
  {
    id: 'scan_10',
    name: 'Scan Veteran',
    nameZhTW: 'Scan Veteran',
    description: 'Complete 10 security scans',
    descriptionZhTW: 'Complete 10 security scans',
    category: 'scan',
    icon: '[SCAN+]',
    condition: (s) => s.totalScans >= 10,
  },

  // Streak achievements
  {
    id: 'safe_7_days',
    name: '7 Day Clean Streak',
    nameZhTW: '7 Day Clean Streak',
    description: '7 consecutive days with zero threats',
    descriptionZhTW: '7 consecutive days with zero threats',
    category: 'streak',
    icon: '[7DAY]',
    condition: (s) => s.consecutiveSafeDays >= 7,
  },
  {
    id: 'safe_30_days',
    name: '30 Day Fortress',
    nameZhTW: '30 Day Fortress',
    description: '30 consecutive days with zero threats',
    descriptionZhTW: '30 consecutive days with zero threats',
    category: 'streak',
    icon: '[30DAY]',
    condition: (s) => s.consecutiveSafeDays >= 30,
  },

  // Response achievements
  {
    id: 'quick_fix',
    name: 'Patch Champion',
    nameZhTW: 'Patch Champion',
    description: 'Fix all vulnerabilities within 24 hours',
    descriptionZhTW: 'Fix all vulnerabilities within 24 hours',
    category: 'response',
    icon: '[FIX]',
    condition: (s) => s.vulnsFixedWithin24h >= 5,
  },
  {
    id: 'threat_hunter',
    name: 'Threat Hunter',
    nameZhTW: 'Threat Hunter',
    description: 'Block 50 threats',
    descriptionZhTW: 'Block 50 threats',
    category: 'response',
    icon: '[HUNT]',
    condition: (s) => s.threatsBlocked >= 50,
  },
  {
    id: 'first_block',
    name: 'First Defense',
    nameZhTW: 'First Defense',
    description: 'Block your first threat',
    descriptionZhTW: 'Block your first threat',
    category: 'response',
    icon: '[DEF]',
    condition: (s) => s.threatsBlocked >= 1,
  },

  // Compliance achievements
  {
    id: 'compliance_80',
    name: 'Compliance Ready',
    nameZhTW: 'Compliance Ready',
    description: 'Reach 80% compliance score',
    descriptionZhTW: 'Reach 80% compliance score',
    category: 'compliance',
    icon: '[COMP]',
    condition: (s) => s.complianceScore >= 80,
  },

  // Guard achievements
  {
    id: 'fully_armed',
    name: 'Fully Armed',
    nameZhTW: 'Fully Armed',
    description: 'Enable all recommended security settings',
    descriptionZhTW: 'Enable all recommended security settings',
    category: 'guard',
    icon: '[ARM]',
    condition: (s) => s.allRecommendationsEnabled,
  },
  {
    id: 'guard_7_days',
    name: 'Vigilant Guardian',
    nameZhTW: 'Vigilant Guardian',
    description: 'Run Guard continuously for 7 days',
    descriptionZhTW: 'Run Guard continuously for 7 days',
    category: 'guard',
    icon: '[GUARD]',
    condition: (s) => s.guardRunningDays >= 7,
  },
  {
    id: 'score_90',
    name: 'Grade A Security',
    nameZhTW: 'Grade A Security',
    description: 'Achieve a security score of 90 or higher',
    descriptionZhTW: 'Achieve a security score of 90 or higher',
    category: 'guard',
    icon: '[A+]',
    condition: (s) => s.securityScore >= 90,
  },
  {
    id: 'chat_connected',
    name: 'Connected',
    nameZhTW: 'Connected',
    description: 'Configure at least one notification channel',
    descriptionZhTW: 'Configure at least one notification channel',
    category: 'guard',
    icon: '[CHAT]',
    condition: (s) => s.chatChannelsConfigured >= 1,
  },
];

/**
 * Achievement Tracker - manages earned achievements
 * 成就追蹤器 - 管理已獲得的成就
 */
export class AchievementTracker {
  private earned: Map<string, EarnedAchievement> = new Map();

  /**
   * Check stats against all achievements, return newly earned ones
   * 檢查統計數據，回傳新獲得的成就
   */
  check(stats: AchievementStats): EarnedAchievement[] {
    const newlyEarned: EarnedAchievement[] = [];

    for (const achievement of ACHIEVEMENTS) {
      if (this.earned.has(achievement.id)) continue;

      if (achievement.condition(stats)) {
        const earned: EarnedAchievement = {
          achievement,
          earnedAt: new Date().toISOString(),
          notified: false,
        };
        this.earned.set(achievement.id, earned);
        newlyEarned.push(earned);
        logger.info(`Achievement unlocked: ${achievement.name} (${achievement.id})`);
      }
    }

    return newlyEarned;
  }

  /** Get all earned achievements / 取得所有已獲得的成就 */
  getEarned(): EarnedAchievement[] {
    return Array.from(this.earned.values());
  }

  /** Get count of earned achievements / 取得已獲得成就數量 */
  getEarnedCount(): number {
    return this.earned.size;
  }

  /** Get total available achievements / 取得所有可用成就數量 */
  getTotalCount(): number {
    return ACHIEVEMENTS.length;
  }

  /** Mark an achievement as notified / 標記成就已通知 */
  markNotified(id: string): void {
    const earned = this.earned.get(id);
    if (earned) earned.notified = true;
  }

  /** Get un-notified achievements / 取得未通知的成就 */
  getUnnotified(): EarnedAchievement[] {
    return Array.from(this.earned.values()).filter((e) => !e.notified);
  }

  /** Load earned achievements from serialized data / 從序列化資料載入 */
  load(data: Array<{ id: string; earnedAt: string }>): void {
    for (const item of data) {
      const achievement = ACHIEVEMENTS.find((a) => a.id === item.id);
      if (achievement) {
        this.earned.set(item.id, {
          achievement,
          earnedAt: item.earnedAt,
          notified: true,
        });
      }
    }
  }

  /** Serialize earned achievements / 序列化已獲得的成就 */
  serialize(): Array<{ id: string; earnedAt: string }> {
    return Array.from(this.earned.values()).map((e) => ({
      id: e.achievement.id,
      earnedAt: e.earnedAt,
    }));
  }
}
