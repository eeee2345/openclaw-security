import { NextResponse } from 'next/server';
import { appendToSheet } from '@/lib/sheets';
import { checkRateLimit, getClientIP } from '@/lib/rate-limit';
import { validateWaitlist } from '@/lib/validate';

const AUTH_API = process.env.NEXT_PUBLIC_API_URL || 'https://panguard-api-production.up.railway.app';

export async function POST(req: Request) {
  const ip = getClientIP(req);
  if (!checkRateLimit(ip)) {
    return NextResponse.json({ error: 'Too many requests' }, { status: 429 });
  }

  try {
    const body = await req.json();
    const data = validateWaitlist(body);
    if (!data) {
      return NextResponse.json({ error: 'Invalid email' }, { status: 400 });
    }

    // Primary: send to auth backend (DB + verification email + Google Sheets sync)
    if (AUTH_API) {
      try {
        const backendRes = await fetch(`${AUTH_API}/api/waitlist/join`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: data.email, source: 'website' }),
        });
        const backendData = await backendRes.json();

        if (backendRes.ok && backendData.ok) {
          return NextResponse.json({ ok: true, data: backendData.data });
        }

        // If already on waitlist, still return success to user
        if (backendRes.status === 409) {
          return NextResponse.json({ ok: true, message: 'Already on waitlist' });
        }

        // Backend error — fall through to Google Sheets fallback
      } catch {
        // Backend unreachable — fall through to Google Sheets fallback
      }
    }

    // Fallback: write directly to Google Sheets if backend is unavailable
    await appendToSheet('waitlist', [new Date().toISOString(), data.email, 'early-access']);

    return NextResponse.json({ ok: true });
  } catch {
    return NextResponse.json({ error: 'Server error' }, { status: 500 });
  }
}
