import { test, expect } from '@playwright/test';
import { setupAuthenticatedAdmin } from './fixtures/auth';

test.describe('Admin Dashboard', () => {
  test.beforeEach(async ({ page }) => {
    await setupAuthenticatedAdmin(page);
    await page.goto('/admin/dashboard');
    await expect(page.locator('main')).toBeVisible({ timeout: 10000 });
  });

  test('shows stat cards', async ({ page }) => {
    await expect(page.getByText('Endpoints Monitored')).toBeVisible({ timeout: 5000 });
    await expect(page.getByText('Active Threats')).toBeVisible();
    await expect(page.getByText('Guard Agents Online')).toBeVisible();
  });

  test('shows threat trend section', async ({ page }) => {
    const trendSection = page.getByText(/threat trend|daily.*threat/i).first();
    await expect(trendSection).toBeVisible({ timeout: 5000 });
  });

  test('shows recent alerts', async ({ page }) => {
    const alertsSection = page.getByText(/recent alerts/i).first();
    await expect(alertsSection).toBeVisible({ timeout: 5000 });
  });

  test('shows guard agent status', async ({ page }) => {
    const agentSection = page.getByText(/guard agent|agent status/i).first();
    await expect(agentSection).toBeVisible({ timeout: 5000 });
  });

  test('shows Threat Cloud status', async ({ page }) => {
    const tcStatus = page.getByText(/threat cloud/i).first();
    await expect(tcStatus).toBeVisible({ timeout: 5000 });
  });
});
