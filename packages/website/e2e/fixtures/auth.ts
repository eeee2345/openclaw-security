/**
 * E2E Auth Helpers
 *
 * Provides Playwright helpers for injecting auth state and mocking API routes.
 * Usage: call setup* functions BEFORE navigating to the target page.
 */

import type { Page } from '@playwright/test';
import {
  MOCK_TOKEN,
  MOCK_USER,
  MOCK_ADMIN,
  authMeSuccess,
  authMeAdmin,
  authMeUnauthorized,
  usageSuccess,
  billingStatusFree,
  billingStatusPro,
  totpStatusDisabled,
} from './api-mocks';

const API_PATTERN = '**/api/**';

/**
 * Dismiss the cookie consent banner by setting the consent cookie.
 * Must be called before navigating to the target page.
 */
async function dismissCookieConsent(page: Page): Promise<void> {
  await page.context().addCookies([
    { name: 'pg_consent', value: 'all', domain: 'localhost', path: '/' },
  ]);
}

/**
 * Inject auth token into localStorage.
 * Must be called after at least one navigation (page.goto).
 */
export async function injectAuthToken(page: Page, token = MOCK_TOKEN): Promise<void> {
  await page.evaluate((t) => localStorage.setItem('panguard_token', t), token);
}

/**
 * Fulfill a route with JSON response.
 */
function jsonResponse(body: unknown, status = 200) {
  return {
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  };
}

/**
 * Setup route mocks for a logged-in regular user.
 * Call BEFORE navigating to the target page.
 */
export async function setupAuthenticatedUser(
  page: Page,
  userOverrides?: Record<string, unknown>,
): Promise<void> {
  const meResponse = userOverrides ? authMeSuccess(userOverrides) : authMeSuccess();
  const isFree = (userOverrides?.tier ?? MOCK_USER.tier) === 'community';

  await page.route('**/api/auth/me', (route) => route.fulfill(jsonResponse(meResponse)));
  await page.route('**/api/usage', (route) => route.fulfill(jsonResponse(usageSuccess())));
  await page.route('**/api/billing/status', (route) =>
    route.fulfill(jsonResponse(isFree ? billingStatusFree() : billingStatusPro())),
  );
  await page.route('**/api/auth/totp/status', (route) =>
    route.fulfill(jsonResponse(totpStatusDisabled())),
  );

  // Dismiss cookie consent banner to prevent click interception
  await dismissCookieConsent(page);

  // Navigate to origin to set localStorage, then tests navigate to target
  await page.goto('/');
  await injectAuthToken(page);
}

/**
 * Setup route mocks for a logged-in admin user.
 */
export async function setupAuthenticatedAdmin(page: Page): Promise<void> {
  await page.route('**/api/auth/me', (route) => route.fulfill(jsonResponse(authMeAdmin())));
  await page.route('**/api/usage', (route) => route.fulfill(jsonResponse(usageSuccess())));
  await page.route('**/api/billing/status', (route) =>
    route.fulfill(jsonResponse(billingStatusPro())),
  );
  await page.route('**/api/auth/totp/status', (route) =>
    route.fulfill(jsonResponse(totpStatusDisabled())),
  );

  await dismissCookieConsent(page);
  await page.goto('/');
  await injectAuthToken(page);
}

/**
 * Setup route mocks for an unauthenticated visitor.
 * Auth/me returns 401 so AuthProvider sets user=null.
 */
export async function setupUnauthenticated(page: Page): Promise<void> {
  await dismissCookieConsent(page);
  await page.route('**/api/auth/me', (route) =>
    route.fulfill(jsonResponse(authMeUnauthorized(), 401)),
  );
}

/**
 * Mock login endpoint with a specific response.
 */
export async function mockLoginEndpoint(
  page: Page,
  body: unknown,
  status = 200,
): Promise<void> {
  await page.route('**/api/auth/login', (route) =>
    route.fulfill(jsonResponse(body, status)),
  );
}

/**
 * Mock register endpoint with a specific response.
 */
export async function mockRegisterEndpoint(
  page: Page,
  body: unknown,
  status = 200,
): Promise<void> {
  await page.route('**/api/auth/register', (route) =>
    route.fulfill(jsonResponse(body, status)),
  );
}

/**
 * Mock forgot-password endpoint.
 */
export async function mockForgotPassword(
  page: Page,
  body: unknown,
  status = 200,
): Promise<void> {
  await page.route('**/api/auth/forgot-password', (route) =>
    route.fulfill(jsonResponse(body, status)),
  );
}

/**
 * Mock reset-password endpoint.
 */
export async function mockResetPassword(
  page: Page,
  body: unknown,
  status = 200,
): Promise<void> {
  await page.route('**/api/auth/reset-password', (route) =>
    route.fulfill(jsonResponse(body, status)),
  );
}
