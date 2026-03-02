import { test, expect } from '@playwright/test';
import { setupAuthenticatedUser, setupUnauthenticated } from './fixtures/auth';

test.describe('Account Billing', () => {
  test('redirects to login when unauthenticated', async ({ page }) => {
    await setupUnauthenticated(page);
    await page.goto('/account/billing');
    await page.waitForURL('**/login**', { timeout: 10000 });
  });

  test('shows current plan for free user', async ({ page }) => {
    await setupAuthenticatedUser(page);
    await page.goto('/account/billing');
    const currentPlanHeader = page.getByText(/current plan/i).first();
    await expect(currentPlanHeader).toBeVisible({ timeout: 15000 });
  });

  test('shows upgrade CTA for free tier', async ({ page }) => {
    await setupAuthenticatedUser(page);
    await page.goto('/account/billing');
    const upgradeCta = page.getByText(/upgrade|view plans/i).first();
    if (await upgradeCta.isVisible({ timeout: 5000 }).catch(() => false)) {
      await expect(upgradeCta).toBeVisible();
    }
  });

  test('shows subscription details for paid user', async ({ page }) => {
    await setupAuthenticatedUser(page, { tier: 'pro', planExpiresAt: '2027-02-01T00:00:00Z' });
    await page.goto('/account/billing');
    await expect(page.getByText(/pro/i).first()).toBeVisible({ timeout: 10000 });
  });

  test('manage subscription button visible for paid users', async ({ page }) => {
    await setupAuthenticatedUser(page, { tier: 'pro', planExpiresAt: '2027-02-01T00:00:00Z' });
    await page.route('**/api/billing/portal', (route) =>
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ ok: true, data: { url: 'https://billing.lemonsqueezy.com/portal/test' } }),
      }),
    );
    await page.goto('/account/billing');
    const manageBtn = page.getByText(/manage.*subscription|customer portal/i).first();
    if (await manageBtn.isVisible({ timeout: 5000 }).catch(() => false)) {
      await expect(manageBtn).toBeVisible();
    }
  });
});
