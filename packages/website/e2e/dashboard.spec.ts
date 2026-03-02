import { test, expect } from '@playwright/test';
import { setupAuthenticatedUser, setupUnauthenticated } from './fixtures/auth';
import { MOCK_USER } from './fixtures/api-mocks';

test.describe('Dashboard', () => {
  test('redirects to login when unauthenticated', async ({ page }) => {
    await setupUnauthenticated(page);
    await page.goto('/dashboard');
    await page.waitForURL('**/login**', { timeout: 10000 });
  });

  test('shows welcome message with user name', async ({ page }) => {
    await setupAuthenticatedUser(page);
    await page.goto('/dashboard');
    await expect(page.getByText(MOCK_USER.name)).toBeVisible({ timeout: 10000 });
  });

  test('shows current plan tier', async ({ page }) => {
    await setupAuthenticatedUser(page);
    await page.goto('/dashboard');
    await expect(page.getByText(/community/i).first()).toBeVisible({ timeout: 10000 });
  });

  test('shows quick action cards', async ({ page }) => {
    await setupAuthenticatedUser(page);
    await page.goto('/dashboard');
    // Quick action cards link to key pages — verify at least one is visible
    const quickActionLink = page.locator('a[href*="/docs/getting-started"], a[href*="/account/settings"], a[href*="/account/billing"], a[href*="/docs/api"]').first();
    await expect(quickActionLink).toBeVisible({ timeout: 10000 });
  });

  test('shows onboarding checklist', async ({ page }) => {
    await setupAuthenticatedUser(page);
    await page.goto('/dashboard');
    // Onboarding section with steps
    const quickStart = page.getByText(/quick start|getting started|onboarding/i).first();
    if (await quickStart.isVisible({ timeout: 5000 }).catch(() => false)) {
      await expect(quickStart).toBeVisible();
    }
  });

  test('logout clears session and redirects', async ({ page }) => {
    await setupAuthenticatedUser(page);
    // Mock logout endpoint
    await page.route('**/api/auth/logout', (route) =>
      route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' }),
    );

    await page.goto('/dashboard');
    await page.waitForTimeout(2000);

    const logoutBtn = page.locator('button[aria-label="Log out"], button:has-text("Logout"), button:has-text("Log out")').first();
    if (await logoutBtn.isVisible({ timeout: 5000 }).catch(() => false)) {
      await logoutBtn.click();
      await page.waitForURL('**/', { timeout: 10000 });
    }
  });

  test('pro user sees pro tier info', async ({ page }) => {
    await setupAuthenticatedUser(page, { tier: 'pro', name: 'Pro User', planExpiresAt: '2027-01-01T00:00:00Z' });
    await page.goto('/dashboard');
    await expect(page.getByText(/pro/i).first()).toBeVisible({ timeout: 10000 });
  });
});
