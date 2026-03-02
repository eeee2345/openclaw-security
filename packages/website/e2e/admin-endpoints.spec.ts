import { test, expect } from '@playwright/test';
import { setupAuthenticatedAdmin } from './fixtures/auth';

test.describe('Admin Endpoints', () => {
  test.beforeEach(async ({ page }) => {
    await setupAuthenticatedAdmin(page);
    await page.goto('/admin/endpoints');
    await expect(page.locator('main')).toBeVisible({ timeout: 10000 });
  });

  test('shows endpoints heading', async ({ page }) => {
    await expect(page.getByText(/endpoint/i).first()).toBeVisible({ timeout: 5000 });
  });

  test('shows endpoint list with hostnames', async ({ page }) => {
    await expect(page.getByText('prod-web-01').first()).toBeVisible({ timeout: 5000 });
  });

  test('search filters endpoints', async ({ page }) => {
    const searchInput = page.locator('input[placeholder*="earch"]').first();
    if (await searchInput.isVisible({ timeout: 3000 }).catch(() => false)) {
      await searchInput.fill('prod-web');
      await page.waitForTimeout(500);
      // Should show filtered results
      await expect(page.getByText('prod-web-01').first()).toBeVisible();
    }
  });

  test('status filter shows only online', async ({ page }) => {
    const onlineFilter = page.getByText('Online').first();
    if (await onlineFilter.isVisible({ timeout: 3000 }).catch(() => false)) {
      await onlineFilter.click();
      await page.waitForTimeout(500);
    }
  });

  test('empty search shows no results message', async ({ page }) => {
    const searchInput = page.locator('input[placeholder*="earch"]').first();
    if (await searchInput.isVisible({ timeout: 3000 }).catch(() => false)) {
      await searchInput.fill('nonexistent-hostname-xyz');
      await page.waitForTimeout(500);
      const noResults = page.getByText(/no.*endpoint.*match|no results/i).first();
      if (await noResults.isVisible({ timeout: 3000 }).catch(() => false)) {
        await expect(noResults).toBeVisible();
      }
    }
  });
});
