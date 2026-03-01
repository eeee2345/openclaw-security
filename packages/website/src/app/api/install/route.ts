import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { readFileSync } from 'fs';
import { join } from 'path';

export async function GET(request: NextRequest) {
  const os = request.nextUrl.searchParams.get('os');
  const filename = os === 'windows' ? 'install.ps1' : 'install.sh';
  const script = readFileSync(join(process.cwd(), 'public', filename), 'utf-8');
  return new NextResponse(script, {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'public, max-age=300',
    },
  });
}
