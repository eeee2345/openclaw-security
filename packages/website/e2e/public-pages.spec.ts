import { test, expect } from '@playwright/test';

test.describe('Public Pages', () => {
  test('homepage loads with hero section', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('main')).toBeVisible();
    await expect(page).toHaveTitle(/Panguard/i);
  });

  test('technology page loads', async ({ page }) => {
    const res = await page.goto('/technology');
    expect(res?.status()).toBe(200);
    await expect(page.locator('main')).toBeVisible();
  });

  test('about page loads', async ({ page }) => {
    const res = await page.goto('/about');
    expect(res?.status()).toBe(200);
    await expect(page.locator('main')).toBeVisible();
  });

  test('how-it-works page loads', async ({ page }) => {
    const res = await page.goto('/how-it-works');
    expect(res?.status()).toBe(200);
    await expect(page.locator('main')).toBeVisible();
  });

  test('docs getting-started page loads', async ({ page }) => {
    const res = await page.goto('/docs/getting-started');
    expect(res?.status()).toBe(200);
    await expect(page.locator('main')).toBeVisible();
  });

  test('compliance page loads', async ({ page }) => {
    const res = await page.goto('/compliance');
    expect(res?.status()).toBe(200);
    await expect(page.locator('main')).toBeVisible();
  });

  test('blog page loads', async ({ page }) => {
    const res = await page.goto('/blog');
    expect(res?.status()).toBe(200);
    await expect(page.locator('main')).toBeVisible();
  });

  test('open-source page loads', async ({ page }) => {
    const res = await page.goto('/open-source');
    expect(res?.status()).toBe(200);
    await expect(page.locator('main')).toBeVisible();
  });
});
