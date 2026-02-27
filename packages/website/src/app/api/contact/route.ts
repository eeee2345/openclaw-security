import { NextResponse } from 'next/server';
import { appendToSheet } from '@/lib/sheets';
import { checkRateLimit, getClientIP } from '@/lib/rate-limit';
import { validateContact } from '@/lib/validate';

export async function POST(req: Request) {
  const ip = getClientIP(req);
  if (!checkRateLimit(ip)) {
    return NextResponse.json({ error: 'Too many requests' }, { status: 429 });
  }

  try {
    const body = await req.json();
    const data = validateContact(body);
    if (!data) {
      return NextResponse.json({ error: 'Missing or invalid fields' }, { status: 400 });
    }

    await appendToSheet('contact', [
      new Date().toISOString(),
      data.name,
      data.email,
      data.company,
      data.type,
      data.message,
    ]);

    return NextResponse.json({ ok: true });
  } catch {
    return NextResponse.json({ error: 'Server error' }, { status: 500 });
  }
}
