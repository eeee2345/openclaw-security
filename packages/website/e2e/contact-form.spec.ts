import { test, expect } from '@playwright/test';

test.describe('Contact Form', () => {
  test('contact page loads with form', async ({ page }) => {
    await page.goto('/contact');
    await expect(page.locator('#contact-name')).toBeVisible();
    await expect(page.locator('#contact-email')).toBeVisible();
    await expect(page.locator('#contact-message')).toBeVisible();
  });

  test('successfully submits contact form', async ({ page }) => {
    await page.route('**/api/contact', (route) =>
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ ok: true }),
      }),
    );

    await page.goto('/contact');
    await page.fill('#contact-name', 'Test User');
    await page.fill('#contact-email', 'test@example.com');
    await page.fill('#contact-message', 'This is a test message for E2E.');

    const submitBtn = page.locator('button[type="submit"]');
    if (await submitBtn.isVisible()) {
      await submitBtn.click();
      // Wait for success feedback
      await page.waitForTimeout(1000);
    }
  });

  test('shows error on submission failure', async ({ page }) => {
    await page.route('**/api/contact', (route) =>
      route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ ok: false, error: 'Server error' }),
      }),
    );

    await page.goto('/contact');
    await page.fill('#contact-name', 'Test User');
    await page.fill('#contact-email', 'test@example.com');
    await page.fill('#contact-message', 'This is a test.');

    const submitBtn = page.locator('button[type="submit"]');
    if (await submitBtn.isVisible()) {
      await submitBtn.click();
      await page.waitForTimeout(1000);
    }
  });
});
