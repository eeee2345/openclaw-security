/**
 * Google Sheets API integration for waitlist sync.
 * Uses service account JWT auth with raw node:crypto (zero external deps).
 * @module @panguard-ai/panguard-auth/google-sheets
 */

import { createSign } from 'node:crypto';

export interface GoogleSheetsConfig {
  spreadsheetId: string;
  serviceAccountEmail: string;
  /** PEM-encoded private key (from service account JSON) */
  privateKey: string;
  /** Sheet name to append rows to (default: 'Waitlist') */
  sheetName?: string;
}

interface JwtPayload {
  iss: string;
  scope: string;
  aud: string;
  iat: number;
  exp: number;
}

const SHEETS_SCOPE = 'https://www.googleapis.com/auth/spreadsheets';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const SHEETS_API = 'https://sheets.googleapis.com/v4/spreadsheets';

// ── JWT helpers ─────────────────────────────────────────────────────

function base64url(data: string | Buffer): string {
  const buf = typeof data === 'string' ? Buffer.from(data) : data;
  return buf.toString('base64url');
}

function createJwt(serviceEmail: string, privateKey: string): string {
  const header = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const now = Math.floor(Date.now() / 1000);
  const payload: JwtPayload = {
    iss: serviceEmail,
    scope: SHEETS_SCOPE,
    aud: TOKEN_URL,
    iat: now,
    exp: now + 3600,
  };
  const payloadB64 = base64url(JSON.stringify(payload));
  const unsigned = `${header}.${payloadB64}`;

  const sign = createSign('RSA-SHA256');
  sign.update(unsigned);
  const signature = sign.sign(privateKey, 'base64url');

  return `${unsigned}.${signature}`;
}

// ── Token cache ─────────────────────────────────────────────────────

let cachedToken: string | null = null;
let tokenExpiry = 0;

async function getAccessToken(config: GoogleSheetsConfig): Promise<string> {
  if (cachedToken && Date.now() < tokenExpiry - 60000) {
    return cachedToken;
  }

  const jwt = createJwt(config.serviceAccountEmail, config.privateKey);
  const body = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion: jwt,
  });

  const res = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Google Sheets token error (${res.status}): ${text}`);
  }

  const data = (await res.json()) as { access_token: string; expires_in: number };
  cachedToken = data.access_token;
  tokenExpiry = Date.now() + data.expires_in * 1000;
  return cachedToken;
}

// ── Sheets operations ───────────────────────────────────────────────

/**
 * Append a row to the configured Google Sheet.
 */
export async function appendRow(config: GoogleSheetsConfig, values: string[]): Promise<void> {
  const token = await getAccessToken(config);
  const sheet = config.sheetName ?? 'Waitlist';
  const range = `${sheet}!A:Z`;

  const url = `${SHEETS_API}/${config.spreadsheetId}/values/${encodeURIComponent(range)}:append?valueInputOption=USER_ENTERED&insertDataOption=INSERT_ROWS`;

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      values: [values],
    }),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Google Sheets append error (${res.status}): ${text}`);
  }
}

/**
 * Sync a waitlist entry to Google Sheets.
 * Appends: [timestamp, email, name, company, role, source, status]
 */
export async function syncWaitlistEntry(
  config: GoogleSheetsConfig,
  entry: {
    email: string;
    name?: string | null;
    company?: string | null;
    role?: string | null;
    source?: string;
    status?: string;
    createdAt?: string;
  }
): Promise<void> {
  const values = [
    entry.createdAt ?? new Date().toISOString(),
    entry.email,
    entry.name ?? '',
    entry.company ?? '',
    entry.role ?? '',
    entry.source ?? 'website',
    entry.status ?? 'pending',
  ];

  await appendRow(config, values);
}

/**
 * Initialize the sheet with headers if empty.
 */
export async function ensureSheetHeaders(config: GoogleSheetsConfig): Promise<void> {
  const token = await getAccessToken(config);
  const sheet = config.sheetName ?? 'Waitlist';
  const range = `${sheet}!A1:G1`;

  // Check if row 1 has data
  const checkUrl = `${SHEETS_API}/${config.spreadsheetId}/values/${encodeURIComponent(range)}`;
  const checkRes = await fetch(checkUrl, {
    headers: { Authorization: `Bearer ${token}` },
  });

  if (checkRes.ok) {
    const data = (await checkRes.json()) as { values?: string[][] };
    if (data.values && data.values.length > 0) return; // Headers exist
  }

  // Write headers
  const writeUrl = `${SHEETS_API}/${config.spreadsheetId}/values/${encodeURIComponent(range)}?valueInputOption=RAW`;
  await fetch(writeUrl, {
    method: 'PUT',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      values: [['Timestamp', 'Email', 'Name', 'Company', 'Role', 'Source', 'Status']],
    }),
  });
}
