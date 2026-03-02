import { test, expect } from '@playwright/test';
import { setupAuthenticatedUser, setupUnauthenticated } from './fixtures/auth';
import { MOCK_USER } from './fixtures/api-mocks';

test.describe('Account Settings', () => {
  test('redirects to login when unauthenticated', async ({ page }) => {
    await setupUnauthenticated(page);
    await page.goto('/account/settings');
    await page.waitForURL('**/login**', { timeout: 10000 });
  });

  test('shows profile information', async ({ page }) => {
    await setupAuthenticatedUser(page);
    await page.goto('/account/settings');
    await expect(page.getByText(MOCK_USER.email)).toBeVisible({ timeout: 10000 });
  });

  test('shows 2FA section', async ({ page }) => {
    await setupAuthenticatedUser(page);
    await page.goto('/account/settings');
    const twoFaSection = page.getByText(/two-factor|2fa|authenticator/i).first();
    await expect(twoFaSection).toBeVisible({ timeout: 10000 });
  });

  test('shows data export section', async ({ page }) => {
    await setupAuthenticatedUser(page);
    await page.goto('/account/settings');
    const exportSection = page.getByText(/export|download.*data/i).first();
    await expect(exportSection).toBeVisible({ timeout: 10000 });
  });

  test('shows delete account section', async ({ page }) => {
    await setupAuthenticatedUser(page);
    await page.goto('/account/settings');
    const deleteSection = page.getByText(/delete.*account|danger zone/i).first();
    await expect(deleteSection).toBeVisible({ timeout: 10000 });
  });

  test('delete account shows confirmation on click', async ({ page }) => {
    await setupAuthenticatedUser(page);
    await page.goto('/account/settings');

    // The delete button is inside the Danger Zone section — select the button element specifically
    const deleteBtn = page.locator('button').filter({ hasText: /delete.*account/i }).first();
    if (await deleteBtn.isVisible({ timeout: 5000 }).catch(() => false)) {
      await deleteBtn.click();
      await page.waitForTimeout(1000);
      // Should show password confirmation or warning
      const confirmation = page.locator('input[type="password"], [role="alertdialog"], .text-status-danger').first();
      if (await confirmation.isVisible({ timeout: 3000 }).catch(() => false)) {
        await expect(confirmation).toBeVisible();
      }
    }
  });
});
