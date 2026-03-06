import { NextResponse } from 'next/server';

const AUTH_API = process.env.NEXT_PUBLIC_API_URL || 'https://panguard-api-production.up.railway.app';

export async function POST(req: Request) {
  if (!AUTH_API) {
    return NextResponse.json({ ok: false, error: 'API not configured' }, { status: 503 });
  }

  const authHeader = req.headers.get('authorization') ?? '';
  if (!authHeader) {
    return NextResponse.json({ ok: false, error: 'Not authenticated' }, { status: 401 });
  }

  try {
    const body = await req.json();
    const res = await fetch(`${AUTH_API}/api/billing/checkout`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: authHeader,
      },
      body: JSON.stringify(body),
    });

    const data = await res.json();
    return NextResponse.json(data, { status: res.status });
  } catch {
    return NextResponse.json({ ok: false, error: 'Failed to create checkout' }, { status: 502 });
  }
}
