/**
 * Google OAuth 2.0 login flow using raw fetch (zero external dependencies).
 * Handles redirect URL generation, code-to-token exchange, and user info retrieval.
 * @module @openclaw/panguard-auth/google-oauth
 */

export interface GoogleOAuthConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

export interface GoogleUserInfo {
  sub: string;
  email: string;
  name: string;
  picture: string;
  email_verified: boolean;
}

const GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const GOOGLE_USERINFO_URL = 'https://www.googleapis.com/oauth2/v3/userinfo';

/**
 * Generate the Google OAuth consent URL.
 */
export function getGoogleAuthUrl(config: GoogleOAuthConfig, state?: string): string {
  const params = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    response_type: 'code',
    scope: 'openid email profile',
    access_type: 'offline',
    prompt: 'consent',
  });
  if (state) params.set('state', state);
  return `${GOOGLE_AUTH_URL}?${params.toString()}`;
}

/**
 * Exchange an authorization code for access and refresh tokens.
 */
export async function exchangeCodeForTokens(
  config: GoogleOAuthConfig,
  code: string,
): Promise<{ access_token: string; refresh_token?: string; id_token?: string }> {
  const body = new URLSearchParams({
    code,
    client_id: config.clientId,
    client_secret: config.clientSecret,
    redirect_uri: config.redirectUri,
    grant_type: 'authorization_code',
  });

  const res = await fetch(GOOGLE_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Google token exchange failed (${res.status}): ${text}`);
  }

  return res.json() as Promise<{ access_token: string; refresh_token?: string; id_token?: string }>;
}

/**
 * Get Google user info using an access token.
 */
export async function getGoogleUserInfo(accessToken: string): Promise<GoogleUserInfo> {
  const res = await fetch(GOOGLE_USERINFO_URL, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Google userinfo failed (${res.status}): ${text}`);
  }

  return res.json() as Promise<GoogleUserInfo>;
}
