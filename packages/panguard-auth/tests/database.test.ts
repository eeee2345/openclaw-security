import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { AuthDB } from '../src/database.js';
import { hashToken } from '../src/auth.js';
import { join } from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';

describe('AuthDB', () => {
  let db: AuthDB;
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'panguard-auth-test-'));
    db = new AuthDB(join(tempDir, 'test.db'));
  });

  afterEach(() => {
    db.close();
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  });

  // ── Waitlist ────────────────────────────────────────────────────

  describe('Waitlist', () => {
    it('should add an entry to the waitlist', () => {
      const entry = db.addToWaitlist({ email: 'test@example.com', name: 'Test' }, 'tok-123');
      expect(entry.id).toBe(1);
      expect(entry.email).toBe('test@example.com');
      expect(entry.name).toBe('Test');
      expect(entry.status).toBe('pending');
      expect(entry.verified).toBe(0);
    });

    it('should normalize email to lowercase', () => {
      db.addToWaitlist({ email: 'TEST@Example.COM' }, 'tok-1');
      const found = db.getWaitlistByEmail('test@example.com');
      expect(found).toBeDefined();
      expect(found!.email).toBe('test@example.com');
    });

    it('should reject duplicate emails', () => {
      db.addToWaitlist({ email: 'dup@example.com' }, 'tok-1');
      expect(() => db.addToWaitlist({ email: 'dup@example.com' }, 'tok-2')).toThrow();
    });

    it('should get waitlist entry by email', () => {
      db.addToWaitlist({ email: 'find@example.com', name: 'Find Me' }, 'tok-f');
      const entry = db.getWaitlistByEmail('find@example.com');
      expect(entry).toBeDefined();
      expect(entry!.name).toBe('Find Me');
    });

    it('should get waitlist entry by id', () => {
      const created = db.addToWaitlist({ email: 'byid@example.com' }, 'tok-id');
      const found = db.getWaitlistById(created.id);
      expect(found).toBeDefined();
      expect(found!.email).toBe('byid@example.com');
    });

    it('should return undefined for non-existent entry', () => {
      expect(db.getWaitlistByEmail('nope@example.com')).toBeUndefined();
      expect(db.getWaitlistById(999)).toBeUndefined();
    });

    it('should verify waitlist token', () => {
      db.addToWaitlist({ email: 'verify@example.com' }, 'verify-tok');
      const entry = db.verifyWaitlistToken('verify-tok');
      expect(entry).toBeDefined();
      expect(entry!.verified).toBe(1);
    });

    it('should return undefined for invalid verify token', () => {
      expect(db.verifyWaitlistToken('nonexistent')).toBeUndefined();
    });

    it('should calculate waitlist stats', () => {
      db.addToWaitlist({ email: 'a@test.com' }, 'tok-a');
      db.addToWaitlist({ email: 'b@test.com' }, 'tok-b');
      db.addToWaitlist({ email: 'c@test.com' }, 'tok-c');
      db.verifyWaitlistToken('tok-b');

      const stats = db.getWaitlistStats();
      expect(stats.total).toBe(3);
      expect(stats.pending).toBe(3);
      expect(stats.verified).toBe(1);
      expect(stats.todaySignups).toBe(3);
    });

    it('should get all waitlist entries', () => {
      db.addToWaitlist({ email: 'x@test.com' }, 'tok-x');
      db.addToWaitlist({ email: 'y@test.com' }, 'tok-y');
      const all = db.getAllWaitlist();
      expect(all.length).toBe(2);
    });
  });

  // ── Users ───────────────────────────────────────────────────────

  describe('Users', () => {
    it('should create a user', () => {
      const user = db.createUser(
        { email: 'user@test.com', name: 'Test User', password: 'unused' },
        'hashed_pw'
      );
      expect(user.id).toBe(1);
      expect(user.email).toBe('user@test.com');
      expect(user.name).toBe('Test User');
      expect(user.passwordHash).toBe('hashed_pw');
      expect(user.role).toBe('user');
      expect(user.tier).toBe('free');
    });

    it('should normalize user email', () => {
      db.createUser({ email: 'UPPER@Test.com', name: 'Upper', password: 'pw' }, 'hash');
      const found = db.getUserByEmail('upper@test.com');
      expect(found).toBeDefined();
    });

    it('should reject duplicate user emails', () => {
      db.createUser({ email: 'dup@test.com', name: 'A', password: 'pw' }, 'hash1');
      expect(() =>
        db.createUser({ email: 'dup@test.com', name: 'B', password: 'pw' }, 'hash2')
      ).toThrow();
    });

    it('should get user by id', () => {
      const created = db.createUser({ email: 'id@test.com', name: 'ById', password: 'pw' }, 'hash');
      const found = db.getUserById(created.id);
      expect(found).toBeDefined();
      expect(found!.name).toBe('ById');
    });

    it('should return undefined for non-existent user', () => {
      expect(db.getUserByEmail('nope@test.com')).toBeUndefined();
      expect(db.getUserById(999)).toBeUndefined();
    });

    it('should update last login', () => {
      const user = db.createUser(
        { email: 'login@test.com', name: 'Login', password: 'pw' },
        'hash'
      );
      expect(user.lastLogin).toBeNull();
      db.updateLastLogin(user.id);
      const updated = db.getUserById(user.id);
      expect(updated!.lastLogin).not.toBeNull();
    });
  });

  // ── Sessions ────────────────────────────────────────────────────

  describe('Sessions', () => {
    let userId: number;

    beforeEach(() => {
      const user = db.createUser(
        { email: 'sess@test.com', name: 'Session', password: 'pw' },
        'hash'
      );
      userId = user.id;
    });

    it('should create a session', () => {
      const future = new Date(Date.now() + 86400000).toISOString().replace('T', ' ').slice(0, 19);
      const session = db.createSession(userId, 'token-abc', future);
      expect(session.userId).toBe(userId);
      expect(session.token).toBe('token-abc');
    });

    it('should get session with user (token is hashed in DB)', () => {
      const future = new Date(Date.now() + 86400000).toISOString().replace('T', ' ').slice(0, 19);
      const session = db.createSession(userId, 'token-get', future);
      // createSession returns plaintext token for the client
      expect(session.token).toBe('token-get');
      // getSession accepts plaintext, hashes internally, returns DB row (hash)
      const result = db.getSession('token-get');
      expect(result).toBeDefined();
      expect(result!.token).toBe(hashToken('token-get'));
      expect(result!.user.email).toBe('sess@test.com');
    });

    it('should return undefined for expired session', () => {
      const past = '2020-01-01 00:00:00';
      db.createSession(userId, 'token-exp', past);
      expect(db.getSession('token-exp')).toBeUndefined();
    });

    it('should return undefined for non-existent token', () => {
      expect(db.getSession('no-such-token')).toBeUndefined();
    });

    it('should delete a session', () => {
      const future = new Date(Date.now() + 86400000).toISOString().replace('T', ' ').slice(0, 19);
      db.createSession(userId, 'token-del', future);
      db.deleteSession('token-del');
      expect(db.getSession('token-del')).toBeUndefined();
    });

    it('should clean expired sessions', () => {
      const past = '2020-01-01 00:00:00';
      const future = new Date(Date.now() + 86400000).toISOString().replace('T', ' ').slice(0, 19);
      db.createSession(userId, 'tok-old', past);
      db.createSession(userId, 'tok-new', future);
      const cleaned = db.cleanExpiredSessions();
      expect(cleaned).toBe(1);
      expect(db.getSession('tok-new')).toBeDefined();
    });
  });

  // ── Report Purchases ──────────────────────────────────────────

  describe('Report Purchases', () => {
    let userId: number;

    beforeEach(() => {
      const user = db.createUser({ email: 'buyer@test.com', name: 'Buyer', password: 'p' }, 'hash');
      userId = user.id;
    });

    it('should create a report purchase', () => {
      const purchase = db.createReportPurchase(userId, 'iso27001', 'per_report');
      expect(purchase.id).toBe(1);
      expect(purchase.userId).toBe(userId);
      expect(purchase.addonId).toBe('iso27001');
      expect(purchase.pricingModel).toBe('per_report');
      expect(purchase.status).toBe('active');
    });

    it('should retrieve purchases by user', () => {
      db.createReportPurchase(userId, 'iso27001', 'per_report');
      db.createReportPurchase(userId, 'soc2', 'per_report');
      const purchases = db.getUserReportPurchases(userId);
      expect(purchases).toHaveLength(2);
      expect(purchases.map((p) => p.addonId)).toContain('iso27001');
      expect(purchases.map((p) => p.addonId)).toContain('soc2');
    });

    it('should check active purchase exists', () => {
      const future = new Date(Date.now() + 86400000).toISOString();
      db.createReportPurchase(userId, 'iso27001', 'per_report', future);
      expect(db.hasActiveReportPurchase(userId, 'iso27001')).toBe(true);
      expect(db.hasActiveReportPurchase(userId, 'soc2')).toBe(false);
    });

    it('should return empty array for user with no purchases', () => {
      expect(db.getUserReportPurchases(userId)).toHaveLength(0);
    });

    it('should get purchase by id', () => {
      const created = db.createReportPurchase(userId, 'soc2', 'per_report');
      const fetched = db.getReportPurchaseById(created.id);
      expect(fetched).toBeDefined();
      expect(fetched!.addonId).toBe('soc2');
    });
  });
});
