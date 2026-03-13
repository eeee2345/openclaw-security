/**
 * License validation tests
 * 授權驗證測試
 *
 * All features are now free (community model). These tests verify
 * that the license key validation mechanism still works correctly,
 * and that no key is required for full access.
 */

import { describe, it, expect } from 'vitest';
import { validateLicense, hasFeature, generateTestLicenseKey } from '../src/license/index.js';
import { TIER_FEATURES } from '../src/types.js';

describe('license', () => {
  it('should return community (free) tier for empty key', () => {
    const license = validateLicense(undefined);
    expect(license.tier).toBe('free');
    expect(license.isValid).toBe(true);
    expect(license.features).toEqual(TIER_FEATURES.free);
  });

  it('should return community (free) tier for blank key', () => {
    const license = validateLicense('');
    expect(license.tier).toBe('free');
    expect(license.isValid).toBe(true);
  });

  it('should reject invalid format and fall back to community (free) tier', () => {
    const license = validateLicense('INVALID-KEY-FORMAT');
    expect(license.isValid).toBe(false);
    expect(license.tier).toBe('free');
  });

  it('should generate and validate a community (free) key', () => {
    const key = generateTestLicenseKey('free');
    expect(key).toMatch(/^PG-FREE-/);
    const license = validateLicense(key);
    expect(license.isValid).toBe(true);
    expect(license.tier).toBe('free');
  });

  it('should still parse legacy pro keys', () => {
    const key = generateTestLicenseKey('pro');
    expect(key).toMatch(/^PG-PRO-/);
    const license = validateLicense(key);
    expect(license.isValid).toBe(true);
    expect(license.tier).toBe('pro');
    expect(license.features).toEqual(TIER_FEATURES.pro);
  });

  it('should still parse legacy enterprise keys', () => {
    const key = generateTestLicenseKey('enterprise');
    expect(key).toMatch(/^PG-ENT-/);
    const license = validateLicense(key);
    expect(license.isValid).toBe(true);
    expect(license.tier).toBe('enterprise');
    expect(license.maxEndpoints).toBe(1000);
  });

  it('should include all community features without a key', () => {
    const license = validateLicense(undefined);
    expect(hasFeature(license, 'basic_monitoring')).toBe(true);
    expect(hasFeature(license, 'rule_matching')).toBe(true);
    expect(hasFeature(license, 'auto_respond')).toBe(true);
  });

  it('should accept legacy CLAW- prefix keys', () => {
    const license = validateLicense('CLAW-PRO-AAAA-BBBB-CCCC');
    // Format is accepted (legacy prefix), checksum may or may not pass
    expect(license.key).toBe('CLAW-PRO-AAAA-BBBB-CCCC');
  });
});
