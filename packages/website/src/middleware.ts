import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import createMiddleware from 'next-intl/middleware';
import { routing } from './navigation';

const intlMiddleware = createMiddleware(routing);

export function middleware(request: NextRequest) {
  const host = request.headers.get('host') || '';

  // get.panguard.ai → serve install script via API route
  // get.panguard.ai/windows → serve PowerShell installer via API route
  if (host.startsWith('get.')) {
    const { pathname } = request.nextUrl;
    if (pathname === '/windows' || pathname === '/win') {
      return NextResponse.rewrite(new URL('/api/install?os=windows', request.url));
    }
    return NextResponse.rewrite(new URL('/api/install', request.url));
  }

  return intlMiddleware(request);
}

export const config = {
  matcher: ['/((?!api|_next|_vercel|.*\\..*).*)'],
};
