/**
 * License Key Validation and Feature Gating
 * 授權金鑰驗證與功能閘
 *
 * Validates license keys in the format CLAW-TIER-XXXX-XXXX-XXXX,
 * determines tier (Free/Pro/Enterprise), and gates features accordingly.
 * 驗證格式為 CLAW-TIER-XXXX-XXXX-XXXX 的授權金鑰，
 * 判定等級（Free/Pro/Enterprise），並據此控制功能閘。
 *
 * @module @panguard-ai/panguard-guard/license
 */

import { createLogger } from '@panguard-ai/core';
import type { LicenseTier, LicenseInfo } from '../types.js';
import { TIER_FEATURES } from '../types.js';

const logger = createLogger('panguard-guard:license');

/** License key format: CLAW-TIER-XXXX-XXXX-XXXX / 授權金鑰格式 */
const LICENSE_PATTERN = /^CLAW-(FREE|PRO|ENT)-([A-Z0-9]{4})-([A-Z0-9]{4})-([A-Z0-9]{4})$/;

/** Tier mapping from key prefix / 從金鑰前綴映射等級 */
const TIER_MAP: Record<string, LicenseTier> = {
  FREE: 'free',
  PRO: 'pro',
  ENT: 'enterprise',
};

/**
 * Validate a license key and return license information
 * 驗證授權金鑰並回傳授權資訊
 *
 * Key format: CLAW-{TIER}-{XXXX}-{XXXX}-{XXXX}
 * - TIER: FREE, PRO, or ENT
 * - X: Alphanumeric characters
 * - Last 4 characters contain a checksum
 *
 * @param key - The license key to validate / 要驗證的授權金鑰
 * @returns License information / 授權資訊
 */
export function validateLicense(key: string | undefined): LicenseInfo {
  // No key = free tier / 無金鑰 = 免費等級
  if (!key || key.trim() === '') {
    logger.info('No license key provided, using Free tier / 未提供授權金鑰，使用免費等級');
    return {
      key: '',
      tier: 'free',
      isValid: true,
      features: TIER_FEATURES.free,
    };
  }

  const normalizedKey = key.trim().toUpperCase();
  const match = normalizedKey.match(LICENSE_PATTERN);

  if (!match) {
    logger.warn(`Invalid license key format: ${maskKey(normalizedKey)} / 無效的授權金鑰格式`);
    return {
      key: normalizedKey,
      tier: 'free',
      isValid: false,
      features: TIER_FEATURES.free,
    };
  }

  const tierCode = match[1]!;
  const segment2 = match[2]!;
  const segment3 = match[3]!;
  const segment4 = match[4]!;

  // Validate checksum: last character of segment4 should equal
  // sum of all alphanumeric values mod 36 converted to base36
  // 驗證校驗碼
  const checksumValid = validateChecksum(tierCode, segment2, segment3, segment4);

  if (!checksumValid) {
    logger.warn(`License key checksum failed: ${maskKey(normalizedKey)} / 授權金鑰校驗碼失敗`);
    return {
      key: normalizedKey,
      tier: 'free',
      isValid: false,
      features: TIER_FEATURES.free,
    };
  }

  const tier: LicenseTier = TIER_MAP[tierCode] ?? 'free';
  const features = TIER_FEATURES[tier];

  logger.info(`License validated: ${tier} tier / 授權已驗證: ${tier} 等級`);

  return {
    key: normalizedKey,
    tier,
    isValid: true,
    features,
    maxEndpoints: tier === 'enterprise' ? 1000 : tier === 'pro' ? 10 : 1,
  };
}

/**
 * Check if a feature is available for the given license
 * 檢查功能是否適用於給定的授權
 *
 * @param license - License information / 授權資訊
 * @param feature - Feature name to check / 要檢查的功能名稱
 * @returns True if feature is available / 功能可用時回傳 true
 */
export function hasFeature(license: LicenseInfo, feature: string): boolean {
  return license.features.includes(feature);
}

/**
 * Get all features for a tier / 取得等級的所有功能
 */
export function getTierFeatures(tier: LicenseTier): string[] {
  return TIER_FEATURES[tier];
}

/**
 * Generate a license key for testing / 產生測試用授權金鑰
 *
 * @param tier - The tier to generate for / 要產生的等級
 * @returns A valid license key / 有效的授權金鑰
 */
export function generateTestLicenseKey(tier: LicenseTier): string {
  const tierCode = tier === 'enterprise' ? 'ENT' : tier === 'pro' ? 'PRO' : 'FREE';

  // Generate random segments / 產生隨機段落
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const randomChar = () => chars.charAt(Math.floor(Math.random() * chars.length));

  const seg2 = randomChar() + randomChar() + randomChar() + randomChar();
  const seg3 = randomChar() + randomChar() + randomChar() + randomChar();

  // Calculate checksum for segment 4 / 計算段落 4 的校驗碼
  const seg4base = randomChar() + randomChar() + randomChar();
  const checkChar = calculateCheckChar(tierCode, seg2, seg3, seg4base);

  return `CLAW-${tierCode}-${seg2}-${seg3}-${seg4base}${checkChar}`;
}

// ---------------------------------------------------------------------------
// Internal / 內部函數
// ---------------------------------------------------------------------------

/** Validate checksum of license key segments / 驗證授權金鑰段落的校驗碼 */
function validateChecksum(tierCode: string, seg2: string, seg3: string, seg4: string): boolean {
  const seg4base = seg4.slice(0, 3);
  const checkChar = seg4[3];
  const expected = calculateCheckChar(tierCode, seg2, seg3, seg4base);
  return checkChar === expected;
}

/** Calculate the check character / 計算校驗字元 */
function calculateCheckChar(
  tierCode: string,
  seg2: string,
  seg3: string,
  seg4base: string
): string {
  const allChars = tierCode + seg2 + seg3 + seg4base;
  let sum = 0;
  for (const ch of allChars) {
    sum += parseInt(ch, 36);
  }
  return (sum % 36).toString(36).toUpperCase();
}

/** Mask a license key for logging (show first 8 and last 4 chars) / 遮罩授權金鑰 */
function maskKey(key: string): string {
  if (key.length <= 12) return '****';
  return key.slice(0, 8) + '****' + key.slice(-4);
}
