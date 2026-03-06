/**
 * Unified API fetch wrapper with timeout and error handling.
 *
 * All authenticated API calls should use this instead of raw fetch.
 */

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'https://panguard-api-production.up.railway.app';
const DEFAULT_TIMEOUT_MS = 15_000;

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
    public code?: string
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export class TimeoutError extends Error {
  constructor() {
    super('Request timed out');
    this.name = 'TimeoutError';
  }
}

interface ApiOptions {
  /** Request timeout in milliseconds (default: 15000) */
  timeout?: number;
  /** Bearer token for authenticated requests */
  token?: string | null;
  /** Additional headers */
  headers?: Record<string, string>;
}

/**
 * Make a GET request to the API.
 */
export async function apiGet<T = unknown>(
  path: string,
  options: ApiOptions = {}
): Promise<{ ok: true; data: T } | { ok: false; error: string; status: number }> {
  return apiRequest<T>('GET', path, undefined, options);
}

/**
 * Make a POST request to the API.
 */
export async function apiPost<T = unknown>(
  path: string,
  body?: unknown,
  options: ApiOptions = {}
): Promise<{ ok: true; data: T } | { ok: false; error: string; status: number }> {
  return apiRequest<T>('POST', path, body, options);
}

/**
 * Make a DELETE request to the API.
 */
export async function apiDelete<T = unknown>(
  path: string,
  options: ApiOptions = {}
): Promise<{ ok: true; data: T } | { ok: false; error: string; status: number }> {
  return apiRequest<T>('DELETE', path, undefined, options);
}

async function apiRequest<T>(
  method: string,
  path: string,
  body: unknown | undefined,
  options: ApiOptions
): Promise<{ ok: true; data: T } | { ok: false; error: string; status: number }> {
  const { timeout = DEFAULT_TIMEOUT_MS, token, headers: extraHeaders } = options;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  const headers: Record<string, string> = {
    ...extraHeaders,
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }

  try {
    const res = await fetch(`${API_URL}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });

    const json = (await res.json()) as { ok?: boolean; data?: T; error?: string };

    if (!res.ok) {
      return {
        ok: false,
        error: json.error ?? `Request failed (${res.status})`,
        status: res.status,
      };
    }

    return { ok: true, data: json.data as T };
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') {
      return { ok: false, error: 'Request timed out', status: 0 };
    }
    return { ok: false, error: 'Network error', status: 0 };
  } finally {
    clearTimeout(timeoutId);
  }
}
