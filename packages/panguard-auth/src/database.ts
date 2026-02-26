/**
 * SQLite database layer for Panguard Auth
 * @module @openclaw/panguard-auth/database
 */

import Database from 'better-sqlite3';
import type { WaitlistEntry, WaitlistInput, WaitlistStats, User, RegisterInput, Session } from './types.js';

export class AuthDB {
  private readonly db: Database.Database;

  constructor(dbPath: string) {
    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    this.initialize();
  }

  private initialize(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS waitlist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        name TEXT,
        company TEXT,
        role TEXT,
        source TEXT DEFAULT 'website',
        status TEXT DEFAULT 'pending',
        verified INTEGER DEFAULT 0,
        verify_token TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
      );

      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        tier TEXT DEFAULT 'free',
        verified INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now')),
        last_login TEXT
      );

      CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id),
        token TEXT NOT NULL UNIQUE,
        expires_at TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_waitlist_email ON waitlist(email);
      CREATE INDEX IF NOT EXISTS idx_waitlist_status ON waitlist(status);
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
    `);
  }

  // ── Waitlist ───────────────────────────────────────────────────────

  addToWaitlist(input: WaitlistInput, verifyToken: string): WaitlistEntry {
    const stmt = this.db.prepare(`
      INSERT INTO waitlist (email, name, company, role, source, verify_token)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    const result = stmt.run(
      input.email.toLowerCase().trim(),
      input.name ?? null,
      input.company ?? null,
      input.role ?? null,
      input.source ?? 'website',
      verifyToken,
    );
    return this.getWaitlistById(Number(result.lastInsertRowid))!;
  }

  getWaitlistByEmail(email: string): WaitlistEntry | undefined {
    return this.db.prepare(`
      SELECT id, email, name, company, role, source, status, verified,
             verify_token as verifyToken, created_at as createdAt, updated_at as updatedAt
      FROM waitlist WHERE email = ?
    `).get(email.toLowerCase().trim()) as WaitlistEntry | undefined;
  }

  getWaitlistById(id: number): WaitlistEntry | undefined {
    return this.db.prepare(`
      SELECT id, email, name, company, role, source, status, verified,
             verify_token as verifyToken, created_at as createdAt, updated_at as updatedAt
      FROM waitlist WHERE id = ?
    `).get(id) as WaitlistEntry | undefined;
  }

  verifyWaitlistToken(token: string): WaitlistEntry | undefined {
    const entry = this.db.prepare(`
      SELECT id, email, name, company, role, source, status, verified,
             verify_token as verifyToken, created_at as createdAt, updated_at as updatedAt
      FROM waitlist WHERE verify_token = ?
    `).get(token) as WaitlistEntry | undefined;

    if (entry) {
      this.db.prepare(`
        UPDATE waitlist SET verified = 1, updated_at = datetime('now') WHERE id = ?
      `).run(entry.id);
      entry.verified = 1;
    }
    return entry;
  }

  getWaitlistStats(): WaitlistStats {
    const total = (this.db.prepare('SELECT COUNT(*) as c FROM waitlist').get() as { c: number }).c;
    const pending = (this.db.prepare("SELECT COUNT(*) as c FROM waitlist WHERE status = 'pending'").get() as { c: number }).c;
    const approved = (this.db.prepare("SELECT COUNT(*) as c FROM waitlist WHERE status = 'approved'").get() as { c: number }).c;
    const verified = (this.db.prepare('SELECT COUNT(*) as c FROM waitlist WHERE verified = 1').get() as { c: number }).c;
    const todaySignups = (this.db.prepare(
      "SELECT COUNT(*) as c FROM waitlist WHERE created_at > datetime('now', '-1 day')"
    ).get() as { c: number }).c;
    return { total, pending, approved, verified, todaySignups };
  }

  getAllWaitlist(): WaitlistEntry[] {
    return this.db.prepare(`
      SELECT id, email, name, company, role, source, status, verified,
             verify_token as verifyToken, created_at as createdAt, updated_at as updatedAt
      FROM waitlist ORDER BY created_at DESC
    `).all() as WaitlistEntry[];
  }

  // ── Users ──────────────────────────────────────────────────────────

  createUser(input: RegisterInput, passwordHash: string): User {
    const stmt = this.db.prepare(`
      INSERT INTO users (email, name, password_hash)
      VALUES (?, ?, ?)
    `);
    const result = stmt.run(input.email.toLowerCase().trim(), input.name, passwordHash);
    return this.getUserById(Number(result.lastInsertRowid))!;
  }

  getUserByEmail(email: string): User | undefined {
    return this.db.prepare(`
      SELECT id, email, name, password_hash as passwordHash, role, tier, verified,
             created_at as createdAt, last_login as lastLogin
      FROM users WHERE email = ?
    `).get(email.toLowerCase().trim()) as User | undefined;
  }

  getUserById(id: number): User | undefined {
    return this.db.prepare(`
      SELECT id, email, name, password_hash as passwordHash, role, tier, verified,
             created_at as createdAt, last_login as lastLogin
      FROM users WHERE id = ?
    `).get(id) as User | undefined;
  }

  updateLastLogin(userId: number): void {
    this.db.prepare("UPDATE users SET last_login = datetime('now') WHERE id = ?").run(userId);
  }

  // ── Sessions ───────────────────────────────────────────────────────

  createSession(userId: number, token: string, expiresAt: string): Session {
    const stmt = this.db.prepare(`
      INSERT INTO sessions (user_id, token, expires_at)
      VALUES (?, ?, ?)
    `);
    const result = stmt.run(userId, token, expiresAt);
    return this.db.prepare(`
      SELECT id, user_id as userId, token, expires_at as expiresAt, created_at as createdAt
      FROM sessions WHERE id = ?
    `).get(Number(result.lastInsertRowid)) as Session;
  }

  getSession(token: string): (Session & { user: User }) | undefined {
    const session = this.db.prepare(`
      SELECT id, user_id as userId, token, expires_at as expiresAt, created_at as createdAt
      FROM sessions WHERE token = ? AND expires_at > datetime('now')
    `).get(token) as Session | undefined;

    if (!session) return undefined;

    const user = this.getUserById(session.userId);
    if (!user) return undefined;

    return { ...session, user };
  }

  deleteSession(token: string): void {
    this.db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
  }

  cleanExpiredSessions(): number {
    const result = this.db.prepare("DELETE FROM sessions WHERE expires_at <= datetime('now')").run();
    return result.changes;
  }

  close(): void {
    this.db.close();
  }
}
