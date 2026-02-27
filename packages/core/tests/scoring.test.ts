import { describe, it, expect, beforeEach } from 'vitest';
import {
  calculateSecurityScore,
  scoreToGrade,
  scoreToColor,
  generateScoreSummary,
  type ScoreInput,
} from '../src/scoring/security-score.js';
import {
  AchievementTracker,
  ACHIEVEMENTS,
  type AchievementStats,
} from '../src/scoring/achievements.js';

describe('Security Score', () => {
  const perfectInput: ScoreInput = {
    firewallEnabled: true,
    openPorts: [
      { port: 80, service: 'http' },
      { port: 443, service: 'https' },
    ],
    dangerousPorts: [],
    passwordPolicyStrength: 95,
    pendingUpdates: 0,
    securityToolsRunning: ['panguard-guard', 'firewall', 'antivirus'],
    recentThreats24h: 0,
    recentThreats7d: 0,
    complianceProgress: 90,
    avgResponseTimeMs: 30000,
  };

  const terribleInput: ScoreInput = {
    firewallEnabled: false,
    openPorts: [
      { port: 22 },
      { port: 23 },
      { port: 445 },
      { port: 3389 },
      { port: 3306 },
      { port: 6379 },
    ],
    dangerousPorts: [22, 23, 445, 3389, 3306, 6379],
    passwordPolicyStrength: 10,
    pendingUpdates: 50,
    securityToolsRunning: [],
    recentThreats24h: 20,
    recentThreats7d: 100,
    complianceProgress: 10,
    avgResponseTimeMs: 7200000,
  };

  it('should score perfect system close to 100', () => {
    const result = calculateSecurityScore(perfectInput);
    expect(result.totalScore).toBeGreaterThanOrEqual(90);
    expect(result.grade).toBe('A');
  });

  it('should score terrible system close to 0', () => {
    const result = calculateSecurityScore(terribleInput);
    expect(result.totalScore).toBeLessThan(20);
    expect(result.grade).toBe('F');
  });

  it('should include all 8 factors', () => {
    const result = calculateSecurityScore(perfectInput);
    expect(result.factors.length).toBe(8);
    expect(result.factors.map((f) => f.name)).toEqual([
      'firewall',
      'open_ports',
      'password_policy',
      'system_updates',
      'security_tools',
      'recent_threats',
      'compliance',
      'response_speed',
    ]);
  });

  it('should weights sum to 1.0', () => {
    const result = calculateSecurityScore(perfectInput);
    const totalWeight = result.factors.reduce((sum, f) => sum + f.weight, 0);
    expect(totalWeight).toBeCloseTo(1.0, 5);
  });

  it('should detect improving trend', () => {
    const result = calculateSecurityScore(perfectInput, 50);
    expect(result.trend).toBe('improving');
  });

  it('should detect declining trend', () => {
    const result = calculateSecurityScore(terribleInput, 80);
    expect(result.trend).toBe('declining');
  });

  it('should detect stable trend', () => {
    // First calculate the actual score, then use it as previousScore for stable trend
    const baseline = calculateSecurityScore(perfectInput);
    const result = calculateSecurityScore(perfectInput, baseline.totalScore);
    expect(result.trend).toBe('stable');
  });

  it('should penalize disabled firewall', () => {
    const withFirewall = calculateSecurityScore(perfectInput);
    const withoutFirewall = calculateSecurityScore({ ...perfectInput, firewallEnabled: false });
    expect(withFirewall.totalScore).toBeGreaterThan(withoutFirewall.totalScore);
  });

  it('should penalize dangerous open ports', () => {
    const safe = calculateSecurityScore(perfectInput);
    const unsafe = calculateSecurityScore({
      ...perfectInput,
      openPorts: [{ port: 22 }, { port: 23 }, { port: 445 }, { port: 3389 }],
      dangerousPorts: [22, 23, 445, 3389],
    });
    expect(safe.totalScore).toBeGreaterThan(unsafe.totalScore);
  });
});

describe('scoreToGrade', () => {
  it('should return A for 90+', () => expect(scoreToGrade(95)).toBe('A'));
  it('should return B for 75-89', () => expect(scoreToGrade(80)).toBe('B'));
  it('should return C for 60-74', () => expect(scoreToGrade(65)).toBe('C'));
  it('should return D for 40-59', () => expect(scoreToGrade(45)).toBe('D'));
  it('should return F for <40', () => expect(scoreToGrade(20)).toBe('F'));
});

describe('scoreToColor', () => {
  it('should return green for 80+', () => expect(scoreToColor(85)).toBe('green'));
  it('should return yellow for 60-79', () => expect(scoreToColor(65)).toBe('yellow'));
  it('should return orange for 40-59', () => expect(scoreToColor(45)).toBe('orange'));
  it('should return red for <40', () => expect(scoreToColor(20)).toBe('red'));
});

describe('generateScoreSummary', () => {
  it('should include score and grade', () => {
    const snapshot = calculateSecurityScore({
      firewallEnabled: true,
      openPorts: [],
      dangerousPorts: [],
      passwordPolicyStrength: 80,
      pendingUpdates: 2,
      securityToolsRunning: ['guard'],
      recentThreats24h: 0,
      recentThreats7d: 0,
      complianceProgress: 70,
      avgResponseTimeMs: 60000,
    });
    const summary = generateScoreSummary(snapshot);
    expect(summary).toContain('/100');
    expect(summary).toMatch(/[ABCDF]/);
  });
});

describe('AchievementTracker', () => {
  let tracker: AchievementTracker;

  const baseStats: AchievementStats = {
    totalScans: 0,
    consecutiveSafeDays: 0,
    threatsBlocked: 0,
    vulnsFixedWithin24h: 0,
    totalVulnsFixed: 0,
    complianceScore: 0,
    securityScore: 0,
    allRecommendationsEnabled: false,
    firstScanCompleted: false,
    guardRunningDays: 0,
    rulesActive: 0,
    chatChannelsConfigured: 0,
  };

  beforeEach(() => {
    tracker = new AchievementTracker();
  });

  it('should have at least 10 achievements defined', () => {
    expect(ACHIEVEMENTS.length).toBeGreaterThanOrEqual(10);
  });

  it('should start with no earned achievements', () => {
    expect(tracker.getEarnedCount()).toBe(0);
    expect(tracker.getEarned()).toEqual([]);
  });

  it('should earn first_scan achievement', () => {
    const earned = tracker.check({ ...baseStats, firstScanCompleted: true });
    expect(earned.length).toBe(1);
    expect(earned[0].achievement.id).toBe('first_scan');
  });

  it('should earn 7-day streak achievement', () => {
    const earned = tracker.check({ ...baseStats, consecutiveSafeDays: 7 });
    expect(earned.some((e) => e.achievement.id === 'safe_7_days')).toBe(true);
  });

  it('should earn 30-day streak and 7-day streak together', () => {
    const earned = tracker.check({ ...baseStats, consecutiveSafeDays: 30 });
    expect(earned.some((e) => e.achievement.id === 'safe_7_days')).toBe(true);
    expect(earned.some((e) => e.achievement.id === 'safe_30_days')).toBe(true);
  });

  it('should not earn same achievement twice', () => {
    tracker.check({ ...baseStats, firstScanCompleted: true });
    const earned2 = tracker.check({ ...baseStats, firstScanCompleted: true });
    expect(earned2.length).toBe(0);
    expect(tracker.getEarnedCount()).toBe(1);
  });

  it('should track multiple achievements across checks', () => {
    tracker.check({ ...baseStats, firstScanCompleted: true });
    tracker.check({ ...baseStats, firstScanCompleted: true, threatsBlocked: 1 });
    expect(tracker.getEarnedCount()).toBe(2); // first_scan + first_block
  });

  it('should earn fully_armed achievement', () => {
    const earned = tracker.check({ ...baseStats, allRecommendationsEnabled: true });
    expect(earned.some((e) => e.achievement.id === 'fully_armed')).toBe(true);
  });

  it('should mark achievements as notified', () => {
    tracker.check({ ...baseStats, firstScanCompleted: true });
    expect(tracker.getUnnotified().length).toBe(1);

    tracker.markNotified('first_scan');
    expect(tracker.getUnnotified().length).toBe(0);
  });

  it('should serialize and load achievements', () => {
    tracker.check({ ...baseStats, firstScanCompleted: true, consecutiveSafeDays: 7 });
    const serialized = tracker.serialize();
    expect(serialized.length).toBe(2);

    const tracker2 = new AchievementTracker();
    tracker2.load(serialized);
    expect(tracker2.getEarnedCount()).toBe(2);
  });

  it('should show progress (earned vs total)', () => {
    tracker.check({ ...baseStats, firstScanCompleted: true });
    expect(tracker.getEarnedCount()).toBe(1);
    expect(tracker.getTotalCount()).toBe(ACHIEVEMENTS.length);
  });
});
