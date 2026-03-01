/**
 * OAuth and CLI authentication route handlers:
 * handleGoogleAuth, handleGoogleCallback, handleOAuthExchange, handleCliAuth, handleCliExchange.
 * @module @panguard-ai/panguard-auth/routes/oauth
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { hashPassword, generateSessionToken, generateVerifyToken, sessionExpiry } from '../auth.js';
import { authenticateRequest } from '../middleware.js';
import {
  getGoogleAuthUrl,
  exchangeCodeForTokens,
  getGoogleUserInfo,
  generateCodeVerifier,
  generateCodeChallenge,
  generateOAuthState,
} from '../google-oauth.js';
import type { RouteContext } from './shared.js';
import { readBody, json } from './shared.js';

export function createOAuthRoutes(ctx: RouteContext) {
  const { db, config, pendingOAuthFlows, pendingCliFlows, oauthExchangeCodes } = ctx;

  function handleGoogleAuth(_req: IncomingMessage, res: ServerResponse): void {
    if (!config.google) {
      json(res, 501, { ok: false, error: 'Google OAuth not configured' });
      return;
    }
    const state = generateOAuthState();
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    pendingOAuthFlows.set(state, { codeVerifier, createdAt: Date.now() });
    const url = getGoogleAuthUrl(config.google, state, codeChallenge);
    res.writeHead(302, { Location: url });
    res.end();
  }

  async function handleGoogleCallback(
    req: IncomingMessage,
    res: ServerResponse,
    code: string,
    state: string | null
  ): Promise<void> {
    if (!config.google) {
      json(res, 501, { ok: false, error: 'Google OAuth not configured' });
      return;
    }

    // Validate state parameter (CSRF protection)
    if (!state) {
      json(res, 400, { ok: false, error: 'Missing state parameter' });
      return;
    }
    const flow = pendingOAuthFlows.get(state);
    if (!flow) {
      json(res, 403, { ok: false, error: 'Invalid or expired OAuth state' });
      return;
    }
    pendingOAuthFlows.delete(state);

    try {
      const tokens = await exchangeCodeForTokens(config.google, code, flow.codeVerifier);
      const googleUser = await getGoogleUserInfo(tokens.access_token);

      if (!googleUser.email) {
        json(res, 400, { ok: false, error: 'No email from Google account' });
        return;
      }

      if (!googleUser.email_verified) {
        json(res, 403, { ok: false, error: 'Email not verified with Google' });
        return;
      }

      // Find or create user
      let user = db.getUserByEmail(googleUser.email);
      if (!user) {
        // Auto-create user from Google profile (random password since they use OAuth)
        const randomPw = generateSessionToken(); // Not used for login, just to fill the field
        const pwHash = await hashPassword(randomPw);
        user = db.createUser(
          {
            email: googleUser.email,
            name: googleUser.name || googleUser.email,
            password: randomPw,
          },
          pwHash
        );
      }

      db.updateLastLogin(user.id);
      const sessionToken = generateSessionToken();
      const session = db.createSession(user.id, sessionToken, sessionExpiry());

      // Use one-time exchange code instead of putting token in URL
      const exchangeCode = generateVerifyToken(); // UUID v4
      oauthExchangeCodes.set(exchangeCode, {
        sessionToken,
        expiresAt: session.expiresAt,
        createdAt: Date.now(),
      });

      const baseUrl = config.baseUrl ?? '';
      const redirectUrl = `${baseUrl}/login?code=${exchangeCode}`;
      res.writeHead(302, { Location: redirectUrl });
      res.end();
    } catch {
      json(res, 500, {
        ok: false,
        error: 'Google OAuth failed',
      });
    }
  }

  /**
   * GET /api/auth/cli
   * Initiates CLI auth flow: validates callback URL and redirects to web login.
   */
  function handleCliAuth(req: IncomingMessage, res: ServerResponse): void {
    const urlObj = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
    const callbackUrl = urlObj.searchParams.get('callback');
    const state = urlObj.searchParams.get('state');

    if (!callbackUrl || !state) {
      json(res, 400, { ok: false, error: 'Missing callback or state parameter' });
      return;
    }

    // Security: callback must be localhost
    try {
      const callbackParsed = new URL(callbackUrl);
      if (!['localhost', '127.0.0.1', '[::1]'].includes(callbackParsed.hostname)) {
        json(res, 400, { ok: false, error: 'Callback must be localhost' });
        return;
      }
    } catch {
      json(res, 400, { ok: false, error: 'Invalid callback URL' });
      return;
    }

    pendingCliFlows.set(state, { callbackUrl, createdAt: Date.now() });

    // Redirect to web login page with cli_state
    const baseUrl = config.baseUrl ?? '';
    const loginUrl = `${baseUrl}/login?cli_state=${encodeURIComponent(state)}`;
    res.writeHead(302, { Location: loginUrl });
    res.end();
  }

  /**
   * POST /api/auth/cli/exchange
   * Exchanges a web session token for a long-lived CLI session.
   * Returns the CLI callback redirect URL.
   */
  async function handleCliExchange(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== 'POST') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    const result = await readBody(req);
    if (!result.ok) {
      json(res, result.status, {
        ok: false,
        error: result.status === 413 ? 'Payload too large' : 'Invalid JSON body',
      });
      return;
    }
    const body = result.data;

    const { token, state } = body;
    if (typeof token !== 'string' || typeof state !== 'string') {
      json(res, 400, { ok: false, error: 'Token and state are required' });
      return;
    }

    // Validate web session
    const user = authenticateRequest(
      { headers: { authorization: `Bearer ${token}` } } as IncomingMessage,
      db
    );
    if (!user) {
      json(res, 401, { ok: false, error: 'Invalid session token' });
      return;
    }

    // Look up pending CLI flow
    const flow = pendingCliFlows.get(state);
    if (!flow) {
      json(res, 403, { ok: false, error: 'Invalid or expired CLI state' });
      return;
    }
    pendingCliFlows.delete(state);

    // Create long-lived CLI session (30 days)
    const cliToken = generateSessionToken();
    const cliSession = db.createSession(user.id, cliToken, sessionExpiry(24 * 30));

    // Build redirect URL back to CLI callback
    const params = new URLSearchParams({
      token: cliSession.token,
      expires: cliSession.expiresAt,
      email: user.email,
      name: user.name,
      tier: user.tier,
      state,
    });
    const redirectUrl = `${flow.callbackUrl}?${params.toString()}`;

    json(res, 200, { ok: true, data: { redirectUrl } });
  }

  /**
   * POST /api/auth/oauth/exchange
   * Exchange a one-time code for a session token (keeps tokens out of URLs).
   */
  async function handleOAuthExchange(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== 'POST') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    const body = await readBody(req);
    if (!body.ok) {
      json(res, body.status, { ok: false, error: 'Invalid request body' });
      return;
    }

    const code = body.data['code'];
    if (typeof code !== 'string' || !code) {
      json(res, 400, { ok: false, error: 'code is required' });
      return;
    }

    const data = oauthExchangeCodes.get(code);
    if (!data) {
      json(res, 400, { ok: false, error: 'Invalid or expired code' });
      return;
    }

    // One-time use — delete immediately
    oauthExchangeCodes.delete(code);

    json(res, 200, {
      ok: true,
      data: { token: data.sessionToken, expiresAt: data.expiresAt },
    });
  }

  return {
    handleGoogleAuth,
    handleGoogleCallback,
    handleOAuthExchange,
    handleCliAuth,
    handleCliExchange,
  };
}
