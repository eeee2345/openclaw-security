import type { Metadata } from 'next';
import Link from 'next/link';

export const metadata: Metadata = {
  title: 'API Reference | Panguard AI',
  description:
    'Panguard AI REST API documentation for integrating automated security scanning, threat intelligence, and compliance reporting into your workflow.',
};

const API_SECTIONS = [
  {
    tag: 'Auth',
    description: 'Authentication and session management',
    endpoints: [
      { method: 'POST', path: '/api/auth/register', summary: 'Register a new account' },
      { method: 'POST', path: '/api/auth/login', summary: 'Log in with email and password' },
      { method: 'POST', path: '/api/auth/logout', summary: 'Invalidate current session' },
      { method: 'GET', path: '/api/auth/me', summary: 'Get current user profile' },
      {
        method: 'POST',
        path: '/api/auth/forgot-password',
        summary: 'Request password reset email',
      },
      { method: 'POST', path: '/api/auth/reset-password', summary: 'Reset password with token' },
    ],
  },
  {
    tag: 'Account',
    description: 'Account management, GDPR, and 2FA',
    endpoints: [
      {
        method: 'DELETE',
        path: '/api/auth/delete-account',
        summary: 'Delete account and all data',
      },
      { method: 'GET', path: '/api/auth/export-data', summary: 'Export all user data (GDPR)' },
      { method: 'POST', path: '/api/auth/totp/setup', summary: 'Generate TOTP secret for 2FA' },
      { method: 'POST', path: '/api/auth/totp/verify', summary: 'Verify TOTP code to enable 2FA' },
      { method: 'POST', path: '/api/auth/totp/disable', summary: 'Disable 2FA' },
      { method: 'GET', path: '/api/auth/totp/status', summary: 'Check 2FA status' },
    ],
  },
  {
    tag: 'Billing',
    description: 'Subscription and payment via Lemon Squeezy',
    endpoints: [
      { method: 'POST', path: '/api/billing/checkout', summary: 'Create checkout session' },
      { method: 'GET', path: '/api/billing/portal', summary: 'Subscription management portal' },
      { method: 'GET', path: '/api/billing/status', summary: 'Get billing status' },
    ],
  },
  {
    tag: 'Usage',
    description: 'Usage metering and quota enforcement',
    endpoints: [
      { method: 'GET', path: '/api/usage', summary: 'Get usage summary' },
      { method: 'GET', path: '/api/usage/limits', summary: 'Get quota limits for current tier' },
      { method: 'POST', path: '/api/usage/check', summary: 'Check available quota' },
      { method: 'POST', path: '/api/usage/record', summary: 'Record usage' },
    ],
  },
  {
    tag: 'Threat Cloud',
    description: 'Threat intelligence sharing and feeds',
    endpoints: [
      { method: 'POST', path: '/api/threats', summary: 'Upload anonymized threat data' },
      { method: 'GET', path: '/api/iocs', summary: 'Search indicators of compromise' },
      { method: 'GET', path: '/api/stats', summary: 'Get threat statistics' },
      { method: 'GET', path: '/api/rules', summary: 'Fetch detection rules' },
      { method: 'GET', path: '/api/feeds/ip-blocklist', summary: 'IP blocklist feed' },
      { method: 'GET', path: '/api/feeds/domain-blocklist', summary: 'Domain blocklist feed' },
    ],
  },
];

const METHOD_COLORS: Record<string, string> = {
  GET: 'bg-emerald-900/50 text-emerald-400 border-emerald-700/40',
  POST: 'bg-blue-900/50 text-blue-400 border-blue-700/40',
  DELETE: 'bg-red-900/50 text-red-400 border-red-700/40',
  PATCH: 'bg-amber-900/50 text-amber-400 border-amber-700/40',
};

export default function ApiDocsPage() {
  const apiBaseUrl = process.env['NEXT_PUBLIC_API_URL'] ?? 'https://panguard-api-production.up.railway.app';

  return (
    <div className="min-h-screen bg-[#1A1614] text-[#F5F1E8]">
      <div className="mx-auto max-w-4xl px-6 py-16">
        <h1 className="text-4xl font-bold tracking-tight">API Reference</h1>
        <p className="mt-4 text-lg text-[#A09890]">
          REST API for authentication, billing, usage metering, admin management, and threat
          intelligence.
        </p>

        <div className="mt-8 flex gap-4">
          <Link
            href={`${apiBaseUrl}/docs/api`}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 rounded-lg border border-[#8B9A8E]/30 bg-[#8B9A8E]/10 px-5 py-2.5 text-sm font-medium text-[#8B9A8E] transition-colors hover:bg-[#8B9A8E]/20"
          >
            <svg
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
            >
              <path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6" />
              <polyline points="15,3 21,3 21,9" />
              <line x1="10" y1="14" x2="21" y2="3" />
            </svg>
            Interactive API Explorer (Swagger UI)
          </Link>
          <Link
            href={`${apiBaseUrl}/openapi.json`}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 rounded-lg border border-[#2E2A27] px-5 py-2.5 text-sm font-medium text-[#A09890] transition-colors hover:border-[#8B9A8E]/30 hover:text-[#F5F1E8]"
          >
            OpenAPI 3.0 Spec (JSON)
          </Link>
        </div>

        <div className="mt-6 rounded-lg border border-[#2E2A27] bg-[#1F1C19] p-4">
          <p className="text-sm text-[#A09890]">
            <span className="font-medium text-[#F5F1E8]">Base URL:</span>{' '}
            <code className="rounded bg-[#1A1614] px-2 py-0.5 font-mono text-[#8B9A8E]">
              {apiBaseUrl}
            </code>
          </p>
          <p className="mt-2 text-sm text-[#9A918A]">
            All authenticated endpoints require a <code className="font-mono">Bearer</code> token in
            the <code className="font-mono">Authorization</code> header.
          </p>
        </div>

        <div className="mt-12 space-y-12">
          {API_SECTIONS.map((section) => (
            <section key={section.tag}>
              <h2 className="text-2xl font-semibold">{section.tag}</h2>
              <p className="mt-1 text-sm text-[#A09890]">{section.description}</p>
              <div className="mt-4 space-y-2">
                {section.endpoints.map((ep) => (
                  <div
                    key={`${ep.method}-${ep.path}`}
                    className="flex items-center gap-3 rounded-lg border border-[#2E2A27] bg-[#1F1C19] px-4 py-3"
                  >
                    <span
                      className={`inline-block rounded border px-2 py-0.5 font-mono text-xs font-bold ${METHOD_COLORS[ep.method] ?? ''}`}
                    >
                      {ep.method}
                    </span>
                    <code className="font-mono text-sm text-[#8B9A8E]">{ep.path}</code>
                    <span className="ml-auto text-sm text-[#9A918A]">{ep.summary}</span>
                  </div>
                ))}
              </div>
            </section>
          ))}
        </div>
      </div>
    </div>
  );
}
