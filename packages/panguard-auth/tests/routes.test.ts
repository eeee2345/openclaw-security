import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createServer, type Server } from 'node:http';
import { AuthDB } from '../src/database.js';
import { createAuthHandlers } from '../src/routes.js';
import { hashPassword } from '../src/auth.js';
import { join } from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';

// ── Test HTTP helpers ─────────────────────────────────────────────

function request(
  server: Server,
  method: string,
  path: string,
  body?: unknown,
  headers?: Record<string, string>,
): Promise<{ status: number; data: Record<string, unknown> }> {
  return new Promise((resolve, reject) => {
    const addr = server.address();
    if (!addr || typeof addr === 'string') return reject(new Error('Server not listening'));
    const port = addr.port;

    const options: import('node:http').RequestOptions = {
      hostname: '127.0.0.1',
      port,
      path,
      method,
      headers: { 'Content-Type': 'application/json', ...headers },
    };

    const req = import('node:http').then((http) => {
      const r = http.request(options, (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf-8');
          try {
            resolve({ status: res.statusCode ?? 500, data: JSON.parse(raw) });
          } catch {
            resolve({ status: res.statusCode ?? 500, data: { raw } });
          }
        });
      });
      r.on('error', reject);
      if (body) r.write(JSON.stringify(body));
      r.end();
    });
    void req;
  });
}

describe('Auth Routes', () => {
  let db: AuthDB;
  let server: Server;
  let tempDir: string;

  beforeEach(async () => {
    tempDir = mkdtempSync(join(tmpdir(), 'panguard-auth-route-test-'));
    db = new AuthDB(join(tempDir, 'test.db'));

    const handlers = createAuthHandlers({ db });

    server = createServer(async (req, res) => {
      const url = req.url ?? '/';
      const [pathname] = url.split('?');
      const path = pathname ?? '/';

      res.setHeader('Content-Type', 'application/json');

      // Simple router for tests
      if (path === '/api/waitlist' && req.method === 'POST') {
        await handlers.handleWaitlistJoin(req, res);
      } else if (path.startsWith('/api/waitlist/verify/')) {
        const token = path.split('/api/waitlist/verify/')[1] ?? '';
        handlers.handleWaitlistVerify(req, res, token);
      } else if (path === '/api/waitlist/stats') {
        handlers.handleWaitlistStats(req, res);
      } else if (path === '/api/waitlist/list') {
        handlers.handleWaitlistList(req, res);
      } else if (path === '/api/auth/register') {
        await handlers.handleRegister(req, res);
      } else if (path === '/api/auth/login') {
        await handlers.handleLogin(req, res);
      } else if (path === '/api/auth/logout') {
        handlers.handleLogout(req, res);
      } else if (path === '/api/auth/me') {
        handlers.handleMe(req, res);
      } else {
        res.writeHead(404);
        res.end(JSON.stringify({ ok: false, error: 'Not found' }));
      }
    });

    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => resolve());
    });
  });

  afterEach(async () => {
    db.close();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    try { rmSync(tempDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  // ── Waitlist ────────────────────────────────────────────────────

  describe('POST /api/waitlist', () => {
    it('should add to waitlist', async () => {
      const res = await request(server, 'POST', '/api/waitlist', {
        email: 'test@example.com',
        name: 'Test',
      });
      expect(res.status).toBe(201);
      expect(res.data.ok).toBe(true);
    });

    it('should reject invalid email', async () => {
      const res = await request(server, 'POST', '/api/waitlist', { email: 'not-email' });
      expect(res.status).toBe(400);
      expect(res.data.ok).toBe(false);
    });

    it('should reject duplicate email', async () => {
      await request(server, 'POST', '/api/waitlist', { email: 'dup@test.com' });
      const res = await request(server, 'POST', '/api/waitlist', { email: 'dup@test.com' });
      expect(res.status).toBe(409);
    });

    it('should reject missing body', async () => {
      const res = await request(server, 'POST', '/api/waitlist');
      expect(res.status).toBe(400);
    });
  });

  describe('GET /api/waitlist/verify/:token', () => {
    it('should verify a valid token', async () => {
      db.addToWaitlist({ email: 'v@test.com' }, 'my-verify-token');
      const res = await request(server, 'GET', '/api/waitlist/verify/my-verify-token');
      expect(res.status).toBe(200);
      expect(res.data.ok).toBe(true);
    });

    it('should reject invalid token', async () => {
      const res = await request(server, 'GET', '/api/waitlist/verify/nonexistent');
      expect(res.status).toBe(404);
    });
  });

  describe('GET /api/waitlist/stats (admin only)', () => {
    it('should reject unauthenticated request', async () => {
      const res = await request(server, 'GET', '/api/waitlist/stats');
      expect(res.status).toBe(403);
    });
  });

  // ── Auth ────────────────────────────────────────────────────────

  describe('POST /api/auth/register', () => {
    it('should register a new user', async () => {
      const res = await request(server, 'POST', '/api/auth/register', {
        email: 'new@test.com',
        name: 'New User',
        password: 'password123',
      });
      expect(res.status).toBe(201);
      expect(res.data.ok).toBe(true);
      const data = res.data.data as Record<string, unknown>;
      expect(data.token).toBeDefined();
      expect(data.user).toBeDefined();
    });

    it('should reject short password', async () => {
      const res = await request(server, 'POST', '/api/auth/register', {
        email: 'short@test.com',
        name: 'Short',
        password: '123',
      });
      expect(res.status).toBe(400);
    });

    it('should reject missing name', async () => {
      const res = await request(server, 'POST', '/api/auth/register', {
        email: 'noname@test.com',
        password: 'password123',
      });
      expect(res.status).toBe(400);
    });

    it('should reject duplicate email', async () => {
      await request(server, 'POST', '/api/auth/register', {
        email: 'dup@test.com',
        name: 'A',
        password: 'password123',
      });
      const res = await request(server, 'POST', '/api/auth/register', {
        email: 'dup@test.com',
        name: 'B',
        password: 'password456',
      });
      expect(res.status).toBe(409);
    });
  });

  describe('POST /api/auth/login', () => {
    beforeEach(async () => {
      const hash = await hashPassword('testpass123');
      db.createUser({ email: 'login@test.com', name: 'Login User', password: 'unused' }, hash);
    });

    it('should login with correct credentials', async () => {
      const res = await request(server, 'POST', '/api/auth/login', {
        email: 'login@test.com',
        password: 'testpass123',
      });
      expect(res.status).toBe(200);
      expect(res.data.ok).toBe(true);
      const data = res.data.data as Record<string, unknown>;
      expect(data.token).toBeDefined();
    });

    it('should reject wrong password', async () => {
      const res = await request(server, 'POST', '/api/auth/login', {
        email: 'login@test.com',
        password: 'wrongpass',
      });
      expect(res.status).toBe(401);
    });

    it('should reject non-existent email', async () => {
      const res = await request(server, 'POST', '/api/auth/login', {
        email: 'nope@test.com',
        password: 'anything',
      });
      expect(res.status).toBe(401);
    });
  });

  describe('GET /api/auth/me', () => {
    it('should return user for valid session', async () => {
      // Register to get a token
      const reg = await request(server, 'POST', '/api/auth/register', {
        email: 'me@test.com',
        name: 'Me',
        password: 'password123',
      });
      const data = reg.data.data as Record<string, unknown>;
      const token = data.token as string;

      const res = await request(server, 'GET', '/api/auth/me', undefined, {
        Authorization: `Bearer ${token}`,
      });
      expect(res.status).toBe(200);
      const meData = res.data.data as Record<string, unknown>;
      const user = meData.user as Record<string, unknown>;
      expect(user.email).toBe('me@test.com');
    });

    it('should reject unauthenticated request', async () => {
      const res = await request(server, 'GET', '/api/auth/me');
      expect(res.status).toBe(401);
    });
  });

  describe('POST /api/auth/logout', () => {
    it('should invalidate session token', async () => {
      const reg = await request(server, 'POST', '/api/auth/register', {
        email: 'logout@test.com',
        name: 'Logout',
        password: 'password123',
      });
      const data = reg.data.data as Record<string, unknown>;
      const token = data.token as string;

      // Logout
      await request(server, 'POST', '/api/auth/logout', undefined, {
        Authorization: `Bearer ${token}`,
      });

      // Should no longer be authenticated
      const res = await request(server, 'GET', '/api/auth/me', undefined, {
        Authorization: `Bearer ${token}`,
      });
      expect(res.status).toBe(401);
    });
  });
});
