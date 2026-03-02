import { test, expect } from '@playwright/test';
import { setupAuthenticatedUser, setupAuthenticatedAdmin, setupUnauthenticated } from './fixtures/auth';

test.describe('Admin Access Control', () => {
  test('redirects unauthenticated user to login', async ({ page }) => {
    await setupUnauthenticated(page);
    await page.goto('/admin/dashboard');
    await page.waitForURL('**/login**', { timeout: 10000 });
  });

  test('redirects non-admin user to dashboard', async ({ page }) => {
    await setupAuthenticatedUser(page, { role: 'user' });
    await page.goto('/admin/dashboard');
    // Wait for redirect away from /admin — may go to /dashboard or /en/dashboard
    await page.waitForURL((url) => !url.pathname.includes('/admin'), { timeout: 15000 });
    expect(page.url()).not.toContain('/admin');
  });

  test('allows admin user to access admin dashboard', async ({ page }) => {
    await setupAuthenticatedAdmin(page);
    await page.goto('/admin/dashboard');
    // Should stay on admin page and show admin content
    await expect(page.locator('main')).toBeVisible({ timeout: 10000 });
    await page.waitForTimeout(2000);
    expect(page.url()).toContain('/admin');
  });

  test('admin sidebar shows navigation links', async ({ page }) => {
    await setupAuthenticatedAdmin(page);
    await page.goto('/admin/dashboard');
    await expect(page.getByText('Dashboard').first()).toBeVisible({ timeout: 10000 });
    await expect(page.getByText('Endpoints').first()).toBeVisible();
    await expect(page.getByText('Threats').first()).toBeVisible();
  });

  test('admin sidebar shows user info', async ({ page }) => {
    await setupAuthenticatedAdmin(page);
    await page.goto('/admin/dashboard');
    await expect(page.getByText('Admin User')).toBeVisible({ timeout: 10000 });
  });
});
