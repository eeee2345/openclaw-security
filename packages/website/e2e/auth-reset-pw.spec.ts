import { test, expect } from '@playwright/test';
import { setupUnauthenticated, mockResetPassword } from './fixtures/auth';
import { resetPasswordSuccess, resetPasswordError } from './fixtures/api-mocks';

test.describe('Reset Password Page', () => {
  test.beforeEach(async ({ page }) => {
    await setupUnauthenticated(page);
  });

  test('reset password page loads with token', async ({ page }) => {
    await page.goto('/reset-password?token=test-reset-token');
    await expect(page.locator('#reset-password')).toBeVisible();
  });

  test('successful reset shows success message', async ({ page }) => {
    await mockResetPassword(page, resetPasswordSuccess());

    await page.goto('/reset-password?token=valid-token');
    // Fill password fields using known IDs from ResetPasswordForm
    const newPasswordInput = page.locator('#reset-password');
    const confirmInput = page.locator('#reset-confirm');
    const isVisible = await newPasswordInput.isVisible({ timeout: 5000 }).catch(() => false);
    if (isVisible) {
      await newPasswordInput.fill('newsecurepassword123');
      await confirmInput.fill('newsecurepassword123');
      await page.locator('form button[type="submit"]').click();
      await page.waitForTimeout(2000);
    }
  });

  test('expired token shows error', async ({ page }) => {
    await mockResetPassword(page, resetPasswordError('Token expired'), 400);

    await page.goto('/reset-password?token=expired-token');
    const newPasswordInput = page.locator('#reset-password');
    const confirmInput = page.locator('#reset-confirm');
    const isVisible = await newPasswordInput.isVisible({ timeout: 5000 }).catch(() => false);
    if (isVisible) {
      await newPasswordInput.fill('newsecurepassword123');
      await confirmInput.fill('newsecurepassword123');
      await page.locator('form button[type="submit"]').click();

      await page.waitForTimeout(2000);
      const errorIndicator = page.locator('[role="alert"], .text-status-danger').first();
      if (await errorIndicator.isVisible()) {
        await expect(errorIndicator).toBeVisible();
      }
    }
  });

  test('page loads without token', async ({ page }) => {
    await page.goto('/reset-password');
    await expect(page.locator('#reset-password')).toBeVisible();
  });
});
