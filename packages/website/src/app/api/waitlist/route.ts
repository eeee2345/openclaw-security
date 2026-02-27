import { NextResponse } from 'next/server';
import { appendToSheet } from '@/lib/sheets';
import { checkRateLimit, getClientIP } from '@/lib/rate-limit';
import { validateWaitlist } from '@/lib/validate';

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

    await appendToSheet('waitlist', [new Date().toISOString(), data.email, 'early-access']);

    return NextResponse.json({ ok: true });
  } catch {
    return NextResponse.json({ error: 'Server error' }, { status: 500 });
  }
}
