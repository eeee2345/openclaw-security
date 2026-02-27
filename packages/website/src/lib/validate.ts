/**
 * Input validation and sanitization for API routes.
 * No external dependencies — lightweight for serverless.
 */

/** Max field lengths */
const LIMITS = {
  email: 254,
  name: 100,
  company: 200,
  type: 50,
  message: 5000,
  teamSize: 50,
  stack: 500,
} as const;

/** Stricter email regex (RFC 5322 simplified) */
const EMAIL_RE =
  /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+$/;

/** Escape HTML entities to prevent stored XSS */
export function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

/** Trim + length-check a string field */
function cleanString(val: unknown, maxLen: number): string | null {
  if (typeof val !== 'string') return null;
  const trimmed = val.trim();
  if (trimmed.length > maxLen) return null;
  return escapeHtml(trimmed);
}

/** Validate email */
export function validateEmail(val: unknown): string | null {
  if (typeof val !== 'string') return null;
  const trimmed = val.trim().toLowerCase();
  if (trimmed.length > LIMITS.email) return null;
  if (!EMAIL_RE.test(trimmed)) return null;
  return trimmed;
}

/** Validate waitlist input */
export function validateWaitlist(body: unknown): { email: string } | null {
  if (!body || typeof body !== 'object') return null;
  const { email } = body as Record<string, unknown>;
  const cleanEmail = validateEmail(email);
  if (!cleanEmail) return null;
  return { email: cleanEmail };
}

/** Validate contact form input */
export function validateContact(body: unknown): {
  name: string;
  email: string;
  company: string;
  type: string;
  message: string;
} | null {
  if (!body || typeof body !== 'object') return null;
  const b = body as Record<string, unknown>;

  const name = cleanString(b.name, LIMITS.name);
  const email = validateEmail(b.email);
  const company = cleanString(b.company ?? '', LIMITS.company) ?? '';
  const type = cleanString(b.type, LIMITS.type);
  const message = cleanString(b.message, LIMITS.message);

  if (!name || !email || !type || !message) return null;
  return { name, email, company, type, message };
}

/** Validate demo request input */
export function validateDemo(body: unknown): {
  name: string;
  email: string;
  company: string;
  teamSize: string;
  stack: string;
  message: string;
} | null {
  if (!body || typeof body !== 'object') return null;
  const b = body as Record<string, unknown>;

  const name = cleanString(b.name, LIMITS.name);
  const email = validateEmail(b.email);
  const company = cleanString(b.company, LIMITS.company);
  const teamSize = cleanString(b.teamSize ?? '', LIMITS.teamSize) ?? '';
  const stack = cleanString(b.stack ?? '', LIMITS.stack) ?? '';
  const message = cleanString(b.message ?? '', LIMITS.message) ?? '';

  if (!name || !email || !company) return null;
  return { name, email, company, teamSize, stack, message };
}
