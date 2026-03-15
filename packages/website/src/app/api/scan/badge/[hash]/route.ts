import { NextResponse } from 'next/server';

/**
 * GET /api/scan/badge/:hash.svg
 *
 * Returns an SVG badge for a scanned skill. Developers can embed this
 * in their README: ![ATR Verified](https://panguard.ai/api/scan/badge/abc123)
 *
 * For now returns a static "ATR Verified" badge with the hash.
 * Phase 2 will look up cached scan results to show risk level.
 */

function buildBadge(hash: string, status: 'verified' | 'unknown'): string {
  const label = 'ATR';
  const value = status === 'verified' ? `Verified @ ${hash}` : 'Not Scanned';
  const color = status === 'verified' ? '#2ED573' : '#A09A94';
  const labelWidth = 30;
  const valueWidth = status === 'verified' ? 110 : 80;
  const totalWidth = labelWidth + valueWidth;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="20" role="img" aria-label="${label}: ${value}">
  <title>${label}: ${value}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="${totalWidth}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${labelWidth}" height="20" fill="#555"/>
    <rect x="${labelWidth}" width="${valueWidth}" height="20" fill="${color}"/>
    <rect width="${totalWidth}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="11">
    <text aria-hidden="true" x="${labelWidth / 2}" y="15" fill="#010101" fill-opacity=".3">${label}</text>
    <text x="${labelWidth / 2}" y="14">${label}</text>
    <text aria-hidden="true" x="${labelWidth + valueWidth / 2}" y="15" fill="#010101" fill-opacity=".3">${value}</text>
    <text x="${labelWidth + valueWidth / 2}" y="14">${value}</text>
  </g>
</svg>`;
}

export async function GET(_request: Request, { params }: { params: Promise<{ hash: string }> }) {
  const { hash } = await params;
  const cleanHash = hash
    .replace(/\.svg$/, '')
    .replace(/[^a-f0-9]/gi, '')
    .slice(0, 16);

  if (!cleanHash || cleanHash.length < 8) {
    return new NextResponse(buildBadge('', 'unknown'), {
      headers: {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'public, max-age=300',
      },
    });
  }

  // TODO: Phase 2 — look up cached scan results and show risk level
  const svg = buildBadge(cleanHash, 'verified');

  return new NextResponse(svg, {
    headers: {
      'Content-Type': 'image/svg+xml',
      'Cache-Control': 'public, max-age=3600',
    },
  });
}
