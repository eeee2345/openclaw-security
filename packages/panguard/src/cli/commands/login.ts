/**
 * `panguard login` - Authenticate via browser OAuth
 * `panguard login` - 透過瀏覽器 OAuth 驗證
 *
 * Opens a browser for authentication, receives callback on localhost,
 * then stores the session token locally.
 *
 * @module @panguard-ai/panguard/cli/commands/login
 */

import { Command } from 'commander';
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { exec } from 'node:child_process';
import { c, symbols, box, statusPanel, spinner } from '@panguard-ai/core';
import type { StatusItem } from '@panguard-ai/core';
import {
  saveCredentials, loadCredentials, isTokenExpired,
  tierDisplayName, CREDENTIALS_PATH,
} from '../credentials.js';
import type { StoredCredentials, Tier } from '../credentials.js';

const DEFAULT_API_URL = 'https://panguard.ai';

export function loginCommand(): Command {
  return new Command('login')
    .description('Log in to Panguard AI / \u767B\u5165 Panguard AI')
    .option('--api-url <url>', 'Auth server URL', DEFAULT_API_URL)
    .option('--no-browser', 'Print URL instead of opening browser')
    .option('--lang <language>', 'Language override')
    .action(async (opts: { apiUrl: string; browser: boolean; lang?: string }) => {
      await runLogin(opts);
    });
}

async function runLogin(opts: { apiUrl: string; browser: boolean; lang?: string }): Promise<void> {
  const lang = opts.lang === 'en' ? 'en' : 'zh-TW';

  // Check if already logged in
  const existing = loadCredentials();
  if (existing && !isTokenExpired(existing)) {
    console.log('');
    console.log(box(
      lang === 'zh-TW'
        ? [
            `${symbols.pass} \u5DF2\u767B\u5165\u70BA ${c.sage(existing.email)}`,
            '',
            `  \u7B49\u7D1A: ${c.sage(tierDisplayName(existing.tier))}`,
            `  \u540D\u7A31: ${existing.name}`,
            '',
            `  \u8981\u5207\u63DB\u5E33\u865F\uFF1F\u5148\u57F7\u884C ${c.sage('panguard logout')}`,
          ].join('\n')
        : [
            `${symbols.pass} Already logged in as ${c.sage(existing.email)}`,
            '',
            `  Tier: ${c.sage(tierDisplayName(existing.tier))}`,
            `  Name: ${existing.name}`,
            '',
            `  To switch accounts, run ${c.sage('panguard logout')} first.`,
          ].join('\n'),
      { borderColor: c.sage, title: 'Panguard AI' },
    ));
    console.log('');
    return;
  }

  // Generate CSRF state token
  const state = randomBytes(16).toString('hex');

  // Start local callback server
  const { port, waitForCallback } = await startCallbackServer(state);
  const callbackUrl = `http://localhost:${port}/callback`;
  const loginUrl = `${opts.apiUrl}/login?cli_state=${state}&cli_callback=${encodeURIComponent(callbackUrl)}`;

  console.log('');
  if (opts.browser) {
    const sp = spinner(lang === 'zh-TW'
      ? '\u6B63\u5728\u958B\u555F\u700F\u89BD\u5668...'
      : 'Opening browser...');
    try {
      await openBrowser(loginUrl);
      sp.succeed(lang === 'zh-TW'
        ? '\u700F\u89BD\u5668\u5DF2\u958B\u555F\uFF0C\u8ACB\u5728\u700F\u89BD\u5668\u4E2D\u5B8C\u6210\u767B\u5165'
        : 'Browser opened. Please complete login in the browser.');
    } catch {
      sp.warn(lang === 'zh-TW'
        ? '\u7121\u6CD5\u958B\u555F\u700F\u89BD\u5668\uFF0C\u8ACB\u624B\u52D5\u958B\u555F\u4EE5\u4E0B\u7DB2\u5740'
        : 'Could not open browser. Please open the following URL manually:');
      console.log(`\n  ${c.underline(loginUrl)}\n`);
    }
  } else {
    console.log(lang === 'zh-TW'
      ? `  \u8ACB\u5728\u700F\u89BD\u5668\u4E2D\u958B\u555F\u4EE5\u4E0B\u7DB2\u5740\u4F86\u767B\u5165\uFF1A`
      : '  Open the following URL in your browser to log in:');
    console.log(`\n  ${c.underline(loginUrl)}\n`);
  }

  console.log(c.dim(lang === 'zh-TW'
    ? '  \u7B49\u5F85\u8A8D\u8B49\u56DE\u61C9...'
    : '  Waiting for authentication...'));

  // Wait for callback
  try {
    const creds = await waitForCallback(opts.apiUrl);

    console.log('');
    const items: StatusItem[] = [
      { label: lang === 'zh-TW' ? '\u4FE1\u7BB1' : 'Email', value: creds.email, status: 'safe' },
      { label: lang === 'zh-TW' ? '\u540D\u7A31' : 'Name', value: creds.name },
      { label: lang === 'zh-TW' ? '\u7B49\u7D1A' : 'Tier', value: tierDisplayName(creds.tier), status: 'safe' },
    ];
    console.log(statusPanel(
      lang === 'zh-TW' ? '\u767B\u5165\u6210\u529F' : 'Login Successful',
      items,
    ));
    console.log(c.dim(`  ${lang === 'zh-TW'
      ? `\u6191\u8B49\u5DF2\u5132\u5B58\u81F3 ${CREDENTIALS_PATH}`
      : `Credentials saved to ${CREDENTIALS_PATH}`}`));
    console.log('');
  } catch (err) {
    console.log('');
    console.log(`  ${symbols.fail} ${lang === 'zh-TW'
      ? '\u767B\u5165\u5931\u6557'
      : 'Login failed'}: ${err instanceof Error ? err.message : String(err)}`);
    console.log('');
    process.exitCode = 1;
  }
}

// ── Local callback HTTP server ──────────────────────────────

interface CallbackServer {
  port: number;
  waitForCallback: (apiUrl: string) => Promise<StoredCredentials>;
}

function startCallbackServer(expectedState: string): Promise<CallbackServer> {
  return new Promise((resolve, reject) => {
    const settled = false;
    let callbackResolve: (creds: StoredCredentials) => void;
    let callbackReject: (err: Error) => void;

    const callbackPromise = new Promise<StoredCredentials>((res, rej) => {
      callbackResolve = res;
      callbackReject = rej;
    });

    const server = createServer((req, res) => {
      const url = new URL(req.url ?? '/', `http://localhost`);

      if (url.pathname !== '/callback') {
        res.writeHead(404);
        res.end('Not found');
        return;
      }

      const token = url.searchParams.get('token');
      const email = url.searchParams.get('email');
      const name = url.searchParams.get('name') ?? '';
      const tier = url.searchParams.get('tier') as Tier | null;
      const expiresAt = url.searchParams.get('expires');
      const state = url.searchParams.get('state');

      // CSRF check
      if (state !== expectedState) {
        res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(callbackHtml(false, 'Invalid state parameter'));
        callbackReject!(new Error('CSRF state mismatch'));
        server.close();
        return;
      }

      if (!token || !email || !tier || !expiresAt) {
        res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(callbackHtml(false, 'Missing required parameters'));
        callbackReject!(new Error('Missing callback parameters'));
        server.close();
        return;
      }

      // Respond to browser
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(callbackHtml(true));

      // Save credentials
      const creds: StoredCredentials = {
        token,
        expiresAt,
        email,
        tier,
        name,
        savedAt: new Date().toISOString(),
        apiUrl: '',
      };

      callbackResolve!(creds);

      // Close server after a short delay
      setTimeout(() => server.close(), 500);
    });

    // Listen on random port
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (!addr || typeof addr === 'string') {
        reject(new Error('Failed to start callback server'));
        return;
      }
      resolve({
        port: addr.port,
        waitForCallback: async (apiUrl: string) => {
          // Set a 5-minute timeout
          const timeout = setTimeout(() => {
            callbackReject!(new Error('Login timed out after 5 minutes'));
            server.close();
          }, 5 * 60 * 1000);

          try {
            const creds = await callbackPromise;
            clearTimeout(timeout);
            creds.apiUrl = apiUrl;
            saveCredentials(creds);
            return creds;
          } catch (err) {
            clearTimeout(timeout);
            throw err;
          }
        },
      });
    });

    server.on('error', (err) => {
      if (!settled) reject(err);
    });
  });
}

// ── Browser opening ─────────────────────────────────────────

function openBrowser(url: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const platform = process.platform;
    let cmd: string;
    if (platform === 'darwin') {
      cmd = `open "${url}"`;
    } else if (platform === 'win32') {
      cmd = `start "" "${url}"`;
    } else {
      cmd = `xdg-open "${url}"`;
    }
    exec(cmd, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

// ── Callback HTML page ──────────────────────────────────────

function callbackHtml(success: boolean, error?: string): string {
  const title = success ? 'Login Successful' : 'Login Failed';
  const message = success
    ? 'You can close this tab and return to your terminal.'
    : `Error: ${error ?? 'Unknown error'}`;
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Panguard AI - ${title}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: #0a0f1e;
      color: #F5F1E8;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
    }
    .card {
      background: #1a1f2e;
      border: 1px solid ${success ? '#8B9A8E' : '#EF4444'};
      border-radius: 12px;
      padding: 48px;
      text-align: center;
      max-width: 480px;
    }
    h1 { color: ${success ? '#8B9A8E' : '#EF4444'}; margin-bottom: 16px; }
    p { color: #F5F1E8; opacity: 0.8; line-height: 1.6; }
    .brand { color: #8B9A8E; font-size: 14px; margin-top: 24px; opacity: 0.6; }
  </style>
</head>
<body>
  <div class="card">
    <h1>${title}</h1>
    <p>${message}</p>
    <p class="brand">PANGUARD AI</p>
  </div>
</body>
</html>`;
}
