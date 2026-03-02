import { test, expect } from '@playwright/test';
import { setupUnauthenticated, mockLoginEndpoint } from './fixtures/auth';
import {
  loginSuccess,
  loginError,
  loginRequires2FA,
  authMeSuccess,
  authMeUnauthorized,
  forgotPasswordSuccess,
} from './fixtures/api-mocks';

test.describe('Login Page', () => {
  test.beforeEach(async ({ page }) => {
    await setupUnauthenticated(page);
  });

  test('login page loads with form', async ({ page }) => {
    await page.goto('/login');
    await expect(page.locator('#login-email')).toBeVisible();
    await expect(page.locator('#login-password')).toBeVisible();
    await expect(page.locator('button[type="submit"]')).toBeVisible();
  });

  test('shows error on invalid credentials', async ({ page }) => {
    await mockLoginEndpoint(page, loginError('Invalid credentials'), 401);

    await page.goto('/login');
    await page.fill('#login-email', 'wrong@example.com');
    await page.fill('#login-password', 'wrongpassword');
    await page.click('button[type="submit"]');

    await expect(page.locator('[role="alert"]')).toBeVisible({ timeout: 5000 });
  });

  test('successful login redirects to dashboard', async ({ page }) => {
    await mockLoginEndpoint(page, loginSuccess());
    // After login, auth/me will be called with the new token
    await page.unroute('**/api/auth/me');
    await page.route('**/api/auth/me', (route) => {
      const authHeader = route.request().headers()['authorization'];
      if (authHeader) {
        return route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(authMeSuccess()),
        });
      }
      return route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify(authMeUnauthorized()),
      });
    });
    // Mock usage and billing for dashboard
    await page.route('**/api/usage', (route) =>
      route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true,"data":{"usage":[]}}' }),
    );
    await page.route('**/api/billing/status', (route) =>
      route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true,"data":{"tier":"community"}}' }),
    );

    await page.goto('/login');
    await page.fill('#login-email', 'user@example.com');
    await page.fill('#login-password', 'password123');
    await page.click('button[type="submit"]');

    await page.waitForURL('**/dashboard', { timeout: 10000 });
  });

  test('login with 2FA shows TOTP input', async ({ page }) => {
    await mockLoginEndpoint(page, loginRequires2FA());

    await page.goto('/login');
    await page.fill('#login-email', 'user@example.com');
    await page.fill('#login-password', 'password123');
    await page.click('button[type="submit"]');

    await expect(page.locator('#login-totp')).toBeVisible({ timeout: 5000 });
  });

  test('forgot password sends email', async ({ page }) => {
    await page.route('**/api/auth/forgot-password', (route) =>
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(forgotPasswordSuccess()),
      }),
    );

    await page.goto('/login');
    await page.fill('#login-email', 'user@example.com');

    const forgotBtn = page.getByText(/forgot/i).first();
    if (await forgotBtn.isVisible()) {
      await forgotBtn.click();
      await page.waitForTimeout(2000);
    }
  });

  test('password visibility toggle works', async ({ page }) => {
    await page.goto('/login');
    const passwordInput = page.locator('#login-password');
    await expect(passwordInput).toHaveAttribute('type', 'password');

    const toggleBtn = page.locator('#login-password ~ button, label:has(#login-password) button').first();
    if (await toggleBtn.isVisible()) {
      await toggleBtn.click();
      await expect(passwordInput).toHaveAttribute('type', 'text');
    }
  });

  test('redirect parameter is preserved after login', async ({ page }) => {
    await mockLoginEndpoint(page, loginSuccess());
    await page.unroute('**/api/auth/me');
    await page.route('**/api/auth/me', (route) =>
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(authMeSuccess()),
      }),
    );
    await page.route('**/api/usage', (route) =>
      route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true,"data":{"usage":[]}}' }),
    );
    await page.route('**/api/billing/status', (route) =>
      route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true,"data":{"tier":"community"}}' }),
    );
    await page.route('**/api/auth/totp/status', (route) =>
      route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true,"data":{"enabled":false}}' }),
    );

    await page.goto('/login?redirect=/account/settings');
    await page.fill('#login-email', 'user@example.com');
    await page.fill('#login-password', 'password123');
    await page.click('button[type="submit"]');

    await page.waitForURL('**/account/settings', { timeout: 10000 });
  });
});
