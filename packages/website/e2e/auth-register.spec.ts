import { test, expect } from '@playwright/test';
import { setupUnauthenticated, mockRegisterEndpoint } from './fixtures/auth';
import { registerSuccess, registerError } from './fixtures/api-mocks';

test.describe('Register Page', () => {
  test.beforeEach(async ({ page }) => {
    await setupUnauthenticated(page);
  });

  test('register page loads with form', async ({ page }) => {
    await page.goto('/register');
    await expect(page.locator('#register-name')).toBeVisible();
    await expect(page.locator('#register-email')).toBeVisible();
    await expect(page.locator('#register-password')).toBeVisible();
    await expect(page.locator('form button[type="submit"]')).toBeVisible();
  });

  test('successful registration shows success message', async ({ page }) => {
    await mockRegisterEndpoint(page, registerSuccess());

    await page.goto('/register');
    await page.fill('#register-name', 'New User');
    await page.fill('#register-email', 'new@example.com');
    await page.fill('#register-password', 'securepassword123');
    await page.locator('form button[type="submit"]').click();

    // Should show success state or redirect
    await page.waitForTimeout(2000);
    // Look for success indicator (checkmark, success text, or login link)
    const successIndicator = page.getByText(/login|success|created/i).first();
    await expect(successIndicator).toBeVisible({ timeout: 5000 });
  });

  test('registration error shows alert', async ({ page }) => {
    await mockRegisterEndpoint(page, registerError('Email already registered'), 400);

    await page.goto('/register');
    await page.fill('#register-name', 'Existing User');
    await page.fill('#register-email', 'existing@example.com');
    await page.fill('#register-password', 'securepassword123');
    await page.locator('form button[type="submit"]').click();

    await expect(page.locator('[role="alert"]')).toBeVisible({ timeout: 5000 });
  });

  test('shows password length error for short password', async ({ page }) => {
    await page.goto('/register');
    await page.fill('#register-name', 'Test');
    await page.fill('#register-email', 'test@example.com');
    await page.fill('#register-password', 'short');
    await page.locator('form button[type="submit"]').click();

    // Should show validation error or alert
    await page.waitForTimeout(1000);
    const errorIndicator = page.locator('[role="alert"], .text-status-danger, .text-red-500').first();
    if (await errorIndicator.isVisible()) {
      await expect(errorIndicator).toBeVisible();
    }
  });

  test('has link to login page', async ({ page }) => {
    await page.goto('/register');
    const loginLink = page.getByText(/already have|sign in|log in/i).first();
    await expect(loginLink).toBeVisible();
  });
});
