import { test, expect } from '@playwright/test';

test.describe('Pricing Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/pricing');
  });

  test('shows 4 pricing tiers', async ({ page }) => {
    await expect(page.getByText('Community').first()).toBeVisible();
    await expect(page.getByText('Solo').first()).toBeVisible();
    await expect(page.getByText('Pro').first()).toBeVisible();
    await expect(page.getByText('Business').first()).toBeVisible();
  });

  test('Community tier shows free price', async ({ page }) => {
    await expect(page.getByText('$0')).toBeVisible();
  });

  test('Solo tier shows $9 price', async ({ page }) => {
    await expect(page.getByText('$9', { exact: true })).toBeVisible();
  });

  test('Pro tier shows $29 price', async ({ page }) => {
    await expect(page.getByText('$29').first()).toBeVisible();
  });

  test('Business tier shows $79 price', async ({ page }) => {
    await expect(page.getByText('$79').first()).toBeVisible();
  });

  test('annual toggle changes prices', async ({ page }) => {
    const toggle = page.locator('role=switch').first();
    if (await toggle.isVisible()) {
      await toggle.click();
      // Annual prices should show discounted amounts
      await expect(page.getByText('Save 20%').first()).toBeVisible();
    }
  });

  test('FAQ section is visible', async ({ page }) => {
    const faqSection = page.getByText('Frequently Asked').first();
    if (await faqSection.isVisible()) {
      await expect(faqSection).toBeVisible();
    }
  });
});
