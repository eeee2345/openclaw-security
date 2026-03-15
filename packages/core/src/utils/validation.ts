/**
 * Input validation utilities using Zod
 * 使用 Zod 的輸入驗證工具
 *
 * @module @panguard-ai/core/utils/validation
 */

import { z } from 'zod';

/**
 * Validate input data against a Zod schema
 * 使用 Zod schema 驗證輸入資料
 *
 * @param schema - Zod validation schema / Zod 驗證 schema
 * @param data - Data to validate / 要驗證的資料
 * @returns Validated and typed data / 驗證後的型別化資料
 * @throws Error if validation fails / 驗證失敗時拋出錯誤
 */
export function validateInput<T>(schema: z.ZodSchema<T>, data: unknown): T {
  const result = schema.safeParse(data);
  if (!result.success) {
    const messages = result.error.errors.map((e) => `${e.path.join('.')}: ${e.message}`).join('; ');
    throw new Error(`Validation failed: ${messages}`);
  }
  return result.data;
}

/**
 * Try to validate input, returning a result object instead of throwing.
 * 嘗試驗證輸入，回傳結果物件而非拋出錯誤。
 */
export function tryValidateInput<T>(
  schema: z.ZodSchema<T>,
  data: unknown
): { ok: true; data: T } | { ok: false; error: string } {
  const result = schema.safeParse(data);
  if (!result.success) {
    const messages = result.error.errors.map((e) => `${e.path.join('.')}: ${e.message}`).join('; ');
    return { ok: false, error: messages };
  }
  return { ok: true, data: result.data };
}

// -- Common field schemas --

/** Client ID from x-panguard-client-id header (alphanumeric + dash/underscore, 1-64 chars) */
export const ClientIdSchema = z
  .string()
  .regex(/^[a-zA-Z0-9_-]{1,64}$/, 'Client ID must be 1-64 alphanumeric/dash/underscore characters');

/** ISO 8601 date string (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS) */
export const ISODateSchema = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2})?/, 'Must be ISO 8601 format');

/** Pagination limit (positive integer, clamped to max) */
export const PaginationLimitSchema = z.coerce
  .number()
  .int()
  .min(1)
  .max(5000)
  .default(1000);

/** Reputation score for blocklist feeds */
export const ReputationSchema = z.coerce
  .number()
  .min(0)
  .max(100)
  .default(70);

/** Risk level enum */
export const RiskLevelSchema = z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);

// -- API request body schemas --

/** POST /api/threats */
export const ThreatDataSchema = z.object({
  attackSourceIP: z.string().min(1, 'attackSourceIP is required'),
  attackType: z.string().min(1, 'attackType is required'),
  mitreTechnique: z.string().min(1, 'mitreTechnique is required'),
  sigmaRuleMatched: z.string().min(1, 'sigmaRuleMatched is required'),
  timestamp: z.string().min(1, 'timestamp is required'),
  industry: z.string().optional(),
  region: z.string().min(1, 'region is required'),
});
export type ThreatDataInput = z.infer<typeof ThreatDataSchema>;

/** POST /api/rules */
export const RulePublishSchema = z.object({
  ruleId: z.string().min(1, 'ruleId is required').max(256, 'ruleId exceeds maximum length of 256'),
  ruleContent: z.string().min(1, 'ruleContent is required').max(65_536, 'ruleContent exceeds maximum size of 64KB'),
  source: z.string().min(1, 'source is required'),
  publishedAt: z.string().optional(),
  category: z.string().optional(),
  severity: z.string().optional(),
  mitreTechniques: z.string().optional(),
  tags: z.string().optional(),
});
export type RulePublishInput = z.infer<typeof RulePublishSchema>;

/** POST /api/atr-proposals */
export const ATRProposalSchema = z.object({
  patternHash: z.string().min(1, 'patternHash is required'),
  ruleContent: z.string().min(1, 'ruleContent is required'),
  llmProvider: z.string().min(1, 'llmProvider is required'),
  llmModel: z.string().min(1, 'llmModel is required'),
  selfReviewVerdict: z.string().min(1, 'selfReviewVerdict is required'),
});
export type ATRProposalInput = z.infer<typeof ATRProposalSchema>;

/** POST /api/atr-feedback */
export const ATRFeedbackSchema = z.object({
  ruleId: z.string().min(1, 'ruleId is required'),
  isTruePositive: z.boolean({ required_error: 'isTruePositive must be a boolean' }),
});
export type ATRFeedbackInput = z.infer<typeof ATRFeedbackSchema>;

/** POST /api/skill-threats */
export const SkillThreatSchema = z.object({
  skillHash: z.string().min(1, 'skillHash is required'),
  skillName: z.string().min(1, 'skillName is required'),
  riskScore: z.number().min(0).max(100, 'riskScore must be between 0 and 100'),
  riskLevel: RiskLevelSchema,
  findingSummaries: z
    .array(
      z.object({
        id: z.string(),
        category: z.string(),
        severity: z.string(),
        title: z.string(),
      })
    )
    .optional(),
});
export type SkillThreatInput = z.infer<typeof SkillThreatSchema>;

/** POST /api/skill-whitelist (single or batch) */
export const SkillWhitelistItemSchema = z.object({
  skillName: z.string().min(1, 'skillName is required'),
  fingerprintHash: z.string().optional(),
});

export const SkillWhitelistSchema = z.object({
  skillName: z.string().min(1).optional(),
  fingerprintHash: z.string().optional(),
  skills: z.array(SkillWhitelistItemSchema).optional(),
});
export type SkillWhitelistInput = z.infer<typeof SkillWhitelistSchema>;

/**
 * Sanitize a string by removing potentially dangerous characters
 * 清理字串，移除潛在危險字元
 *
 * @param input - Raw string input / 原始字串輸入
 * @returns Sanitized string / 清理後的字串
 */
export function sanitizeString(input: string): string {
  return input
    .replace(/[<>]/g, '')
    .replace(/javascript:/gi, '')
    .replace(/on\w+=/gi, '')
    .trim();
}

/**
 * Validate and sanitize a file path to prevent directory traversal
 * 驗證並清理檔案路徑以防止目錄遍歷攻擊
 *
 * @param filePath - File path to validate / 要驗證的檔案路徑
 * @returns Sanitized file path / 清理後的檔案路徑
 * @throws Error if path contains traversal patterns / 路徑包含遍歷模式時拋出錯誤
 */
export function validateFilePath(filePath: string): string {
  const normalized = filePath.replace(/\\/g, '/');
  if (normalized.includes('..')) {
    throw new Error('Directory traversal detected in file path / 偵測到檔案路徑中的目錄遍歷');
  }
  if (normalized.includes('\0')) {
    throw new Error('Null byte detected in file path / 偵測到檔案路徑中的空位元組');
  }
  return normalized;
}

/**
 * Sanitize a filename to prevent path traversal attacks.
 * Strips path separators and allows only safe characters.
 * 清理檔案名稱以防止路徑穿越攻擊。
 *
 * @param filename - Raw filename (potentially from external source)
 * @returns Safe filename with only alphanumeric, dash, underscore, and dot characters
 */
export function sanitizeFilename(filename: string): string {
  // Extract basename (strip any directory components)
  const base = filename.split(/[/\\]/).pop() ?? 'unknown';
  // Allow only safe characters: alphanumeric, dash, underscore, dot
  const sanitized = base.replace(/[^a-zA-Z0-9_.-]/g, '_');
  // Prevent empty or dot-only filenames
  if (!sanitized || sanitized === '.' || sanitized === '..') {
    return 'unknown';
  }
  return sanitized;
}

/**
 * Validate that a resolved file path stays within a given base directory.
 * 驗證解析後的檔案路徑仍在指定基準目錄內。
 *
 * @param filePath - The file path to check
 * @param baseDir - The directory it must stay within
 * @returns true if path is within baseDir
 */
export function isPathWithinDir(filePath: string, baseDir: string): boolean {
  const { resolve } = require('node:path') as { resolve: (...args: string[]) => string };
  const resolved = resolve(filePath);
  const resolvedBase = resolve(baseDir);
  return resolved.startsWith(resolvedBase + '/') || resolved === resolvedBase;
}
