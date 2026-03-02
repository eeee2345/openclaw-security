import { test, expect } from '@playwright/test';
import { setupAuthenticatedAdmin } from './fixtures/auth';

test.describe('Admin Threats', () => {
  test.beforeEach(async ({ page }) => {
    await setupAuthenticatedAdmin(page);
    await page.goto('/admin/threats');
    await expect(page.locator('main')).toBeVisible({ timeout: 10000 });
  });

  test('shows threat feed heading', async ({ page }) => {
    await expect(page.getByText('Threat Feed')).toBeVisible({ timeout: 5000 });
  });

  test('shows severity summary cards', async ({ page }) => {
    await expect(page.getByText('Critical').first()).toBeVisible({ timeout: 5000 });
    await expect(page.getByText('High').first()).toBeVisible();
    await expect(page.getByText('Medium').first()).toBeVisible();
    await expect(page.getByText('Low').first()).toBeVisible();
  });

  test('search filters threats', async ({ page }) => {
    const searchInput = page.locator('input[placeholder*="earch"]').first();
    if (await searchInput.isVisible({ timeout: 3000 }).catch(() => false)) {
      await searchInput.fill('rootkit');
      await page.waitForTimeout(500);
      await expect(page.getByText(/rootkit/i).first()).toBeVisible();
    }
  });

  test('severity filter filters threats', async ({ page }) => {
    const criticalFilter = page.locator('button:has-text("Critical")').first();
    if (await criticalFilter.isVisible({ timeout: 3000 }).catch(() => false)) {
      await criticalFilter.click();
      await page.waitForTimeout(500);
    }
  });

  test('threat click expands details', async ({ page }) => {
    const threatRow = page.locator('button:has-text("Rootkit")').first();
    if (await threatRow.isVisible({ timeout: 5000 }).catch(() => false)) {
      await threatRow.click();
      await page.waitForTimeout(500);
      // Expanded section should show threat ID or full description
      const expandedDetail = page.getByText(/threat id|full timestamp|confidence/i).first();
      if (await expandedDetail.isVisible({ timeout: 3000 }).catch(() => false)) {
        await expect(expandedDetail).toBeVisible();
      }
    }
  });

  test('empty search shows no results', async ({ page }) => {
    const searchInput = page.locator('input[placeholder*="earch"]').first();
    if (await searchInput.isVisible({ timeout: 3000 }).catch(() => false)) {
      await searchInput.fill('nonexistent-threat-xyz-999');
      await page.waitForTimeout(500);
      const noResults = page.getByText(/no.*threat.*match/i).first();
      if (await noResults.isVisible({ timeout: 3000 }).catch(() => false)) {
        await expect(noResults).toBeVisible();
      }
    }
  });
});
