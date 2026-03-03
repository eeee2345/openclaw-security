/**
 * SOAR Playbook Engine - Match verdicts to playbooks and handle escalation
 * SOAR 劇本引擎 - 將判定匹配到劇本並處理升級
 *
 * The engine is the runtime component that evaluates threat verdicts
 * against loaded playbooks, returns the appropriate actions, and
 * tracks occurrence counts for escalation logic.
 *
 * @module @panguard-ai/panguard-guard/playbook/engine
 */

import { createLogger } from '@panguard-ai/core';
import type { ThreatVerdict } from '../types.js';
import type {
  Playbook,
  PlaybookAction,
  CorrelationPatternType,
} from './schema.js';
import { SEVERITY_ORDER } from './schema.js';
import { loadPlaybooksFromDir, validatePlaybook } from './parser.js';

const logger = createLogger('panguard-guard:playbook-engine');

/** Occurrence tracking entry for escalation / 用於升級的發生次數追蹤條目 */
interface OccurrenceEntry {
  count: number;
  firstSeen: number;
}

/**
 * Lightweight correlation data passed alongside a verdict for playbook matching.
 * 與判定一起傳遞的輕量關聯資料，用於劇本匹配。
 */
export interface PlaybookCorrelationMatch {
  /** Pattern type identifier / 模式類型識別碼 */
  type: CorrelationPatternType;
  /** Confidence score 0-100 / 信心分數 */
  confidence: number;
  /** Source information / 來源資訊 */
  sourceIP?: string;
  /** Event category / 事件分類 */
  category?: string;
}

/** Cleanup interval: 1 hour / 清理間隔：1 小時 */
const CLEANUP_INTERVAL_MS = 60 * 60 * 1000;

/**
 * Parse a duration string (e.g., "1h", "30m", "7d") into milliseconds.
 * 解析持續時間字串為毫秒。
 *
 * @param duration - Duration string / 持續時間字串
 * @returns Milliseconds / 毫秒
 */
export function parseDuration(duration: string): number {
  const match = /^(\d+)([smhd])$/.exec(duration);
  if (!match) {
    throw new Error(`Invalid duration string: "${duration}"`);
  }

  const value = parseInt(match[1]!, 10);
  const unit = match[2]!;

  switch (unit) {
    case 's':
      return value * 1000;
    case 'm':
      return value * 60 * 1000;
    case 'h':
      return value * 60 * 60 * 1000;
    case 'd':
      return value * 24 * 60 * 60 * 1000;
    default:
      throw new Error(`Unknown duration unit: "${unit}"`);
  }
}

/**
 * SOAR Playbook Engine.
 * Matches threat verdicts to playbooks and manages escalation state.
 *
 * SOAR 劇本引擎。
 * 將威脅判定匹配到劇本並管理升級狀態。
 */
export class PlaybookEngine {
  private playbooks: Playbook[];
  private readonly occurrenceCounts: Map<string, OccurrenceEntry>;
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  constructor(playbooks?: Playbook[]) {
    this.playbooks = playbooks ? [...playbooks] : [];
    this.occurrenceCounts = new Map();
    this.startCleanupTimer();
  }

  /**
   * Load playbooks from a directory.
   * 從目錄載入劇本。
   *
   * @param dir - Path to directory containing YAML playbooks / 包含 YAML 劇本的目錄路徑
   */
  loadFromDir(dir: string): void {
    const loaded = loadPlaybooksFromDir(dir);
    this.playbooks = [...this.playbooks, ...loaded];
    logger.info(`PlaybookEngine: loaded ${loaded.length} playbooks from ${dir} (total: ${this.playbooks.length})`);
  }

  /**
   * Add a playbook at runtime.
   * 在執行時新增劇本。
   *
   * @param playbook - Playbook to add / 要新增的劇本
   * @throws Error if playbook is invalid / 劇本無效時拋出錯誤
   */
  addPlaybook(playbook: Playbook): void {
    const validation = validatePlaybook(playbook);
    if (!validation.valid) {
      throw new Error(
        `Invalid playbook "${playbook.name}": ${validation.errors.join('; ')}`
      );
    }
    this.playbooks = [...this.playbooks, playbook];
    logger.info(`PlaybookEngine: added playbook "${playbook.name}" (total: ${this.playbooks.length})`);
  }

  /**
   * Find the highest-priority matching playbook for a verdict.
   * 為判定找到最高優先級的匹配劇本。
   *
   * Match logic:
   * 1. Sort playbooks by priority (descending)
   * 2. For each enabled playbook, check ALL trigger conditions (AND logic)
   * 3. Return first match or null
   *
   * @param verdict - The threat verdict to match / 要匹配的威脅判定
   * @param patterns - Optional correlation patterns / 選用的關聯模式
   * @returns Matching playbook or null / 匹配的劇本或 null
   */
  match(
    verdict: ThreatVerdict,
    patterns?: PlaybookCorrelationMatch[]
  ): Playbook | null {
    // Sort by priority descending (higher priority first)
    const sorted = [...this.playbooks].sort(
      (a, b) => (b.priority ?? 0) - (a.priority ?? 0)
    );

    for (const playbook of sorted) {
      // Skip disabled playbooks / 跳過停用的劇本
      if (playbook.enabled === false) {
        continue;
      }

      if (this.matchesTrigger(playbook, verdict, patterns)) {
        return playbook;
      }
    }

    return null;
  }

  /**
   * Get the actions to execute for a matched playbook (considering escalation).
   * 取得匹配劇本要執行的動作（考慮升級）。
   *
   * Escalation logic:
   * 1. Check occurrence count for sourceKey
   * 2. If count >= escalation.after within time window -> return escalation actions
   * 3. Otherwise -> return normal actions
   *
   * @param playbook - The matched playbook / 匹配的劇本
   * @param sourceKey - Unique key for tracking occurrences / 用於追蹤發生次數的唯一鍵
   * @returns Actions to execute / 要執行的動作
   */
  getActions(playbook: Playbook, sourceKey: string): PlaybookAction[] {
    if (!playbook.escalation) {
      return playbook.actions;
    }

    const compositeKey = `${playbook.name}:${sourceKey}`;
    const entry = this.occurrenceCounts.get(compositeKey);

    if (!entry) {
      return playbook.actions;
    }

    // Check if within time window / 檢查是否在時間窗口內
    if (playbook.escalation.within) {
      const windowMs = parseDuration(playbook.escalation.within);
      const elapsed = Date.now() - entry.firstSeen;
      if (elapsed > windowMs) {
        // Window expired, reset and return normal actions
        // 窗口已過期，重置並返回正常動作
        this.occurrenceCounts.delete(compositeKey);
        return playbook.actions;
      }
    }

    // Check threshold / 檢查閾值
    if (entry.count >= playbook.escalation.after) {
      logger.info(
        `Escalation triggered for "${playbook.name}" (key: ${sourceKey}, ` +
          `count: ${entry.count} >= threshold: ${playbook.escalation.after})`
      );
      return playbook.escalation.actions;
    }

    return playbook.actions;
  }

  /**
   * Record an occurrence for escalation tracking.
   * 記錄一次發生以追蹤升級。
   *
   * @param sourceKey - Unique key identifying the source / 識別來源的唯一鍵
   */
  recordOccurrence(sourceKey: string): void {
    const existing = this.occurrenceCounts.get(sourceKey);
    if (existing) {
      this.occurrenceCounts.set(sourceKey, {
        ...existing,
        count: existing.count + 1,
      });
    } else {
      this.occurrenceCounts.set(sourceKey, {
        count: 1,
        firstSeen: Date.now(),
      });
    }
  }

  /**
   * Get number of loaded playbooks.
   * 取得已載入劇本數量。
   */
  get count(): number {
    return this.playbooks.length;
  }

  /**
   * Get all loaded playbooks (read-only copy).
   * 取得所有已載入的劇本（唯讀副本）。
   */
  getPlaybooks(): readonly Playbook[] {
    return [...this.playbooks];
  }

  /**
   * Cleanup resources (timers).
   * 清理資源（計時器）。
   */
  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
  }

  // ---------------------------------------------------------------------------
  // Private methods / 私有方法
  // ---------------------------------------------------------------------------

  /**
   * Check if a playbook's trigger matches the given verdict and patterns.
   * All specified conditions must be satisfied (AND logic).
   *
   * 檢查劇本的觸發條件是否匹配給定的判定和模式。
   * 所有指定的條件都必須滿足（AND 邏輯）。
   */
  private matchesTrigger(
    playbook: Playbook,
    verdict: ThreatVerdict,
    patterns?: PlaybookCorrelationMatch[]
  ): boolean {
    const { trigger } = playbook;

    // Pattern match / 模式匹配
    if (trigger.pattern !== undefined) {
      const matched = patterns?.some((p) => p.type === trigger.pattern);
      if (!matched) {
        return false;
      }
    }

    // Confidence check / 信心度檢查
    if (trigger.minConfidence !== undefined) {
      // Use the verdict confidence, or max pattern confidence if patterns provided
      let effectiveConfidence = verdict.confidence;
      if (patterns && patterns.length > 0 && trigger.pattern) {
        const matchingPattern = patterns.find((p) => p.type === trigger.pattern);
        if (matchingPattern) {
          effectiveConfidence = Math.max(effectiveConfidence, matchingPattern.confidence);
        }
      }

      if (effectiveConfidence < trigger.minConfidence) {
        return false;
      }
    }

    // Severity check / 嚴重度檢查
    if (trigger.minSeverity !== undefined) {
      const verdictSeverity = this.inferSeverity(verdict);
      const requiredLevel = SEVERITY_ORDER[trigger.minSeverity] ?? 0;
      const actualLevel = SEVERITY_ORDER[verdictSeverity] ?? 0;

      if (actualLevel < requiredLevel) {
        return false;
      }
    }

    // Category match / 分類匹配
    if (trigger.category !== undefined) {
      const matchesCategory = patterns?.some(
        (p) => p.category === trigger.category
      );
      if (!matchesCategory) {
        return false;
      }
    }

    // MITRE ATT&CK technique match / MITRE ATT&CK 技術匹配
    if (trigger.mitreTechnique !== undefined) {
      if (verdict.mitreTechnique !== trigger.mitreTechnique) {
        return false;
      }
    }

    return true;
  }

  /**
   * Infer severity from a verdict's confidence level.
   * 從判定的信心度推斷嚴重度。
   */
  private inferSeverity(verdict: ThreatVerdict): string {
    if (verdict.confidence >= 90) return 'critical';
    if (verdict.confidence >= 70) return 'high';
    if (verdict.confidence >= 40) return 'medium';
    return 'low';
  }

  /**
   * Start periodic cleanup of expired occurrence entries.
   * 啟動過期發生次數條目的定期清理。
   */
  private startCleanupTimer(): void {
    this.cleanupTimer = setInterval(() => {
      this.cleanupExpiredEntries();
    }, CLEANUP_INTERVAL_MS);

    // Don't hold the process open for cleanup / 不要為了清理而保持程序運行
    if (this.cleanupTimer.unref) {
      this.cleanupTimer.unref();
    }
  }

  /**
   * Remove expired occurrence entries (entries older than max window of any playbook).
   * 移除過期的發生次數條目。
   */
  private cleanupExpiredEntries(): void {
    // Find the maximum escalation window across all playbooks
    // 找到所有劇本中最大的升級時間窗口
    let maxWindowMs = 24 * 60 * 60 * 1000; // Default: 24h

    for (const playbook of this.playbooks) {
      if (playbook.escalation?.within) {
        try {
          const windowMs = parseDuration(playbook.escalation.within);
          if (windowMs > maxWindowMs) {
            maxWindowMs = windowMs;
          }
        } catch {
          // Skip invalid durations
        }
      }
    }

    const now = Date.now();
    const keysToDelete: string[] = [];

    for (const [key, entry] of this.occurrenceCounts.entries()) {
      if (now - entry.firstSeen > maxWindowMs) {
        keysToDelete.push(key);
      }
    }

    for (const key of keysToDelete) {
      this.occurrenceCounts.delete(key);
    }

    if (keysToDelete.length > 0) {
      logger.info(`Cleaned up ${keysToDelete.length} expired occurrence entries`);
    }
  }
}
