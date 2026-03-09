import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import createMiddleware from 'next-intl/middleware';
import { routing } from './navigation';

const intlMiddleware = createMiddleware(routing);

export function middleware(request: NextRequest) {
  const host = request.headers.get('host') || '';
  const { pathname } = request.nextUrl;

  // get.panguard.ai → serve install script via API route
  if (host.startsWith('get.')) {
    // Strip any locale prefix that next-intl matcher may have added
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
    const target = subpath
      ? `https://docs.panguard.ai/${subpath}`
      : 'https://docs.panguard.ai';
    return NextResponse.redirect(target, 301);
  }

  return intlMiddleware(request);
}

export const config = {
  matcher: ['/((?!api|_next|_vercel|.*\\..*).*)', '/install.ps1'],
};
