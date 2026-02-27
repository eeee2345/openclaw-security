/**
 * In-memory rate limiter for API routes.
 * Limits each IP to a configurable number of requests per window.
 *
 * LIMITATION: This store lives in process memory. On serverless platforms
 * (Vercel, AWS Lambda) each cold-start gets a fresh Map, so the effective
 * rate limit is per-instance, not global. For production traffic at scale,
 * replace with a shared store (Redis / Upstash) or use platform-level
 * rate limiting (Vercel WAF, Cloudflare Rate Limiting).
 */

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

const store = new Map<string, RateLimitEntry>();

const WINDOW_MS = 60_000; // 1 minute
const MAX_REQUESTS = 5; // per window per IP

/** Prune expired entries periodically to prevent memory leak */
let lastPrune = Date.now();
function prune() {
  const now = Date.now();
  if (now - lastPrune < WINDOW_MS) return;
  lastPrune = now;
  store.forEach((entry, key) => {
    if (now > entry.resetAt) store.delete(key);
  });
}

/**
 * Check rate limit for an IP. Returns true if request is allowed.
 */
export function checkRateLimit(ip: string): boolean {
  prune();
  const now = Date.now();
  const entry = store.get(ip);

  if (!entry || now > entry.resetAt) {
    store.set(ip, { count: 1, resetAt: now + WINDOW_MS });
    return true;
  }

  store.set(ip, { ...entry, count: entry.count + 1 });
  return entry.count + 1 <= MAX_REQUESTS;
}

/**
 * Extract client IP from request headers (works with Vercel, Cloudflare, etc.)
 */
export function getClientIP(req: Request): string {
  const forwarded = req.headers.get('x-forwarded-for');
  // Prefer x-real-ip (set by Vercel/Cloudflare to the actual client IP)
  const realIp = req.headers.get('x-real-ip');
  if (realIp) return realIp;

  if (forwarded) {
    // Take the FIRST IP (the original client, set by the first trusted proxy)
    const ips = forwarded.split(',').map((s) => s.trim());
    return ips[0] || 'unknown';
  }

  return 'unknown';
}
