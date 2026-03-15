import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import createMiddleware from 'next-intl/middleware';
import { routing } from './navigation';

const intlMiddleware = createMiddleware(routing);

function generateNonce(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Buffer.from(array).toString('base64');
}

function buildCspHeader(nonce: string): string {
  const isDev = process.env.NODE_ENV === 'development';
  const isVercel = !!process.env.VERCEL;

  const directives = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}'${isDev ? " 'unsafe-eval'" : ''} https://plausible.io https://static.cloudflareinsights.com`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https:",
    "font-src 'self' data:",
    "connect-src 'self' https://api.panguard.ai https://docs.panguard.ai https://tc.panguard.ai https://*.vercel-insights.com https://*.vercel-analytics.com https://plausible.io",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    ...(isVercel ? ['upgrade-insecure-requests'] : []),
  ];

  return directives.join('; ');
}

function applySecurityHeaders(response: NextResponse, nonce: string): NextResponse {
  response.headers.set('x-nonce', nonce);
  response.headers.set('Content-Security-Policy', buildCspHeader(nonce));
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  response.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  return response;
}

export function middleware(request: NextRequest) {
  const host = request.headers.get('host') || '';
  const { pathname } = request.nextUrl;
  const nonce = generateNonce();

  // get.panguard.ai → serve install script via API route
  if (host.startsWith('get.')) {
    const cleanPath = pathname.replace(/^\/(en|zh)/, '') || '/';
    if (cleanPath === '/windows' || cleanPath === '/win' || cleanPath === '/install.ps1') {
      return NextResponse.rewrite(new URL('/api/install/windows', request.url));
    }
    return NextResponse.rewrite(new URL('/api/install', request.url));
  }

  // /docs → redirect to docs.panguard.ai (before i18n middleware intercepts)
  const docsMatch = pathname.match(/^(?:\/(?:en|zh))?\/docs(?:\/(.*))?$/);
  if (docsMatch) {
    const subpath = docsMatch[1] || '';
    const target = subpath ? `https://docs.panguard.ai/${subpath}` : 'https://docs.panguard.ai';
    return NextResponse.redirect(target, 301);
  }

  // Run next-intl middleware for locale routing (handles / → /en, /zh, etc.)
  const response = intlMiddleware(request);

  // Apply security headers (nonce + CSP) to the response
  return applySecurityHeaders(response, nonce);
}

export const config = {
  matcher: ['/((?!api|_next|_vercel|.*\\..*).*)', '/install.ps1'],
};
