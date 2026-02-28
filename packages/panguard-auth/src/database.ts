/**
 * SQLite database layer for Panguard Auth
 * @module @panguard-ai/panguard-auth/database
 */

import Database from 'better-sqlite3';
import type {
  WaitlistEntry,
  WaitlistInput,
  WaitlistStats,
  User,
  RegisterInput,
  Session,
  UserAdmin,
  SessionAdmin,
  ActivityItem,
} from './types.js';
import { hashToken } from './auth.js';

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

      CREATE TABLE IF NOT EXISTS report_purchases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id),
        addon_id TEXT NOT NULL,
        pricing_model TEXT NOT NULL DEFAULT 'per_report',
        status TEXT NOT NULL DEFAULT 'active',
        purchased_at TEXT DEFAULT (datetime('now')),
        expires_at TEXT
      );

      CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,
        actor_id INTEGER,
        target_id INTEGER,
        details TEXT,
        created_at TEXT DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_waitlist_email ON waitlist(email);
      CREATE INDEX IF NOT EXISTS idx_waitlist_status ON waitlist(status);
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
      CREATE INDEX IF NOT EXISTS idx_report_purchases_user ON report_purchases(user_id);
      CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
      CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log(actor_id);
    `);

    // Migration: add verify_token_expires_at column (safe to re-run)
    try {
      this.db.exec(`ALTER TABLE waitlist ADD COLUMN verify_token_expires_at TEXT`);
    } catch {
      // Column already exists — ignore
    }

    // Migration: add plan_expires_at column to users
    try {
      this.db.exec(`ALTER TABLE users ADD COLUMN plan_expires_at TEXT`);
    } catch {
      // Column already exists — ignore
    }

    // Migration: subscriptions table (Lemon Squeezy)
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS subscriptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id),
        ls_subscription_id TEXT UNIQUE,
        ls_customer_id TEXT,
        ls_variant_id TEXT,
        tier TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active',
        renews_at TEXT,
        ends_at TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
      );
      CREATE INDEX IF NOT EXISTS idx_subscriptions_user ON subscriptions(user_id);
      CREATE INDEX IF NOT EXISTS idx_subscriptions_ls_id ON subscriptions(ls_subscription_id);
    `);

    // Migration: password_reset_tokens table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id),
        token_hash TEXT NOT NULL UNIQUE,
        expires_at TEXT NOT NULL,
        used INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now'))
      );
      CREATE INDEX IF NOT EXISTS idx_reset_tokens_hash ON password_reset_tokens(token_hash);
      CREATE INDEX IF NOT EXISTS idx_reset_tokens_user ON password_reset_tokens(user_id);
    `);
  }

  // ── Waitlist ───────────────────────────────────────────────────────

  addToWaitlist(input: WaitlistInput, verifyToken: string): WaitlistEntry {
    const stmt = this.db.prepare(`
      INSERT INTO waitlist (email, name, company, role, source, verify_token, verify_token_expires_at)
      VALUES (?, ?, ?, ?, ?, ?, datetime('now', '+24 hours'))
    `);
    const result = stmt.run(
      input.email.toLowerCase().trim(),
      input.name ?? null,
      input.company ?? null,
      input.role ?? null,
      input.source ?? 'website',
      verifyToken
    );
    return this.getWaitlistById(Number(result.lastInsertRowid))!;
  }

  getWaitlistByEmail(email: string): WaitlistEntry | undefined {
    return this.db
      .prepare(
        `
      SELECT id, email, name, company, role, source, status, verified,
             verify_token as verifyToken, created_at as createdAt, updated_at as updatedAt
      FROM waitlist WHERE email = ?
    `
      )
      .get(email.toLowerCase().trim()) as WaitlistEntry | undefined;
  }

  getWaitlistById(id: number): WaitlistEntry | undefined {
    return this.db
      .prepare(
        `
      SELECT id, email, name, company, role, source, status, verified,
             verify_token as verifyToken, created_at as createdAt, updated_at as updatedAt
      FROM waitlist WHERE id = ?
    `
      )
      .get(id) as WaitlistEntry | undefined;
  }

  verifyWaitlistToken(token: string): WaitlistEntry | undefined {
    const entry = this.db
      .prepare(
        `
      SELECT id, email, name, company, role, source, status, verified,
             verify_token as verifyToken, created_at as createdAt, updated_at as updatedAt
      FROM waitlist WHERE verify_token = ?
        AND (verify_token_expires_at IS NULL OR verify_token_expires_at > datetime('now'))
    `
      )
      .get(token) as WaitlistEntry | undefined;

    if (entry) {
      this.db
        .prepare(
          `
        UPDATE waitlist SET verified = 1, updated_at = datetime('now') WHERE id = ?
      `
        )
        .run(entry.id);
      entry.verified = 1;
    }
    return entry;
  }

  getWaitlistStats(): WaitlistStats {
    const total = (this.db.prepare('SELECT COUNT(*) as c FROM waitlist').get() as { c: number }).c;
    const pending = (
      this.db.prepare("SELECT COUNT(*) as c FROM waitlist WHERE status = 'pending'").get() as {
        c: number;
      }
    ).c;
    const approved = (
      this.db.prepare("SELECT COUNT(*) as c FROM waitlist WHERE status = 'approved'").get() as {
        c: number;
      }
    ).c;
    const rejected = (
      this.db.prepare("SELECT COUNT(*) as c FROM waitlist WHERE status = 'rejected'").get() as {
        c: number;
      }
    ).c;
    const verified = (
      this.db.prepare('SELECT COUNT(*) as c FROM waitlist WHERE verified = 1').get() as {
        c: number;
      }
    ).c;
    const todaySignups = (
      this.db
        .prepare("SELECT COUNT(*) as c FROM waitlist WHERE created_at > datetime('now', '-1 day')")
        .get() as { c: number }
    ).c;

    const sourceRows = this.db
      .prepare('SELECT source, COUNT(*) as c FROM waitlist GROUP BY source')
      .all() as { source: string; c: number }[];
    const bySource: Record<string, number> = {};
    for (const row of sourceRows) bySource[row.source] = row.c;

    return { total, pending, approved, rejected, verified, todaySignups, bySource };
  }

  getAllWaitlist(): WaitlistEntry[] {
    return this.db
      .prepare(
        `
      SELECT id, email, name, company, role, source, status, verified,
             verify_token as verifyToken, created_at as createdAt, updated_at as updatedAt
      FROM waitlist ORDER BY created_at DESC
    `
      )
      .all() as WaitlistEntry[];
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
    return this.db
      .prepare(
        `
      SELECT id, email, name, password_hash as passwordHash, role, tier, verified,
             created_at as createdAt, last_login as lastLogin, plan_expires_at as planExpiresAt
      FROM users WHERE email = ?
    `
      )
      .get(email.toLowerCase().trim()) as User | undefined;
  }

  getUserById(id: number): User | undefined {
    return this.db
      .prepare(
        `
      SELECT id, email, name, password_hash as passwordHash, role, tier, verified,
             created_at as createdAt, last_login as lastLogin, plan_expires_at as planExpiresAt
      FROM users WHERE id = ?
    `
      )
      .get(id) as User | undefined;
  }

  updateLastLogin(userId: number): void {
    this.db.prepare("UPDATE users SET last_login = datetime('now') WHERE id = ?").run(userId);
  }

  // ── Sessions ───────────────────────────────────────────────────────

  createSession(userId: number, token: string, expiresAt: string): Session {
    const hashed = hashToken(token);
    const stmt = this.db.prepare(`
      INSERT INTO sessions (user_id, token, expires_at)
      VALUES (?, ?, ?)
    `);
    const result = stmt.run(userId, hashed, expiresAt);
    const row = this.db
      .prepare(
        `
      SELECT id, user_id as userId, token, expires_at as expiresAt, created_at as createdAt
      FROM sessions WHERE id = ?
    `
      )
      .get(Number(result.lastInsertRowid)) as Session;
    // Return plaintext token to caller (client needs it); DB stores the hash
    return { ...row, token };
  }

  getSession(token: string): (Session & { user: User }) | undefined {
    const hashed = hashToken(token);
    const session = this.db
      .prepare(
        `
      SELECT id, user_id as userId, token, expires_at as expiresAt, created_at as createdAt
      FROM sessions WHERE token = ? AND expires_at > datetime('now')
    `
      )
      .get(hashed) as Session | undefined;

    if (!session) return undefined;

    const user = this.getUserById(session.userId);
    if (!user) return undefined;

    return { ...session, user };
  }

  deleteSession(token: string): void {
    const hashed = hashToken(token);
    this.db.prepare('DELETE FROM sessions WHERE token = ?').run(hashed);
  }

  cleanExpiredSessions(): number {
    const result = this.db
      .prepare("DELETE FROM sessions WHERE expires_at <= datetime('now')")
      .run();
    return result.changes;
  }

  // ── Report Purchases ─────────────────────────────────────────────

  createReportPurchase(
    userId: number,
    addonId: string,
    pricingModel: string,
    expiresAt?: string
  ): ReportPurchase {
    const stmt = this.db.prepare(`
      INSERT INTO report_purchases (user_id, addon_id, pricing_model, expires_at)
      VALUES (?, ?, ?, ?)
    `);
    const result = stmt.run(userId, addonId, pricingModel, expiresAt ?? null);
    return this.getReportPurchaseById(Number(result.lastInsertRowid))!;
  }

  getReportPurchaseById(id: number): ReportPurchase | undefined {
    return this.db
      .prepare(
        `
      SELECT id, user_id as userId, addon_id as addonId, pricing_model as pricingModel,
             status, purchased_at as purchasedAt, expires_at as expiresAt
      FROM report_purchases WHERE id = ?
    `
      )
      .get(id) as ReportPurchase | undefined;
  }

  getUserReportPurchases(userId: number): ReportPurchase[] {
    return this.db
      .prepare(
        `
      SELECT id, user_id as userId, addon_id as addonId, pricing_model as pricingModel,
             status, purchased_at as purchasedAt, expires_at as expiresAt
      FROM report_purchases WHERE user_id = ? AND status = 'active'
      ORDER BY purchased_at DESC
    `
      )
      .all(userId) as ReportPurchase[];
  }

  hasActiveReportPurchase(userId: number, addonId: string): boolean {
    const row = this.db
      .prepare(
        `
      SELECT COUNT(*) as c FROM report_purchases
      WHERE user_id = ? AND addon_id = ? AND status = 'active'
        AND (expires_at IS NULL OR expires_at > datetime('now'))
    `
      )
      .get(userId, addonId) as { c: number };
    return row.c > 0;
  }

  // ── Admin: Enhanced Queries ─────────────────────────────────────

  getAllUsersAdmin(): UserAdmin[] {
    return this.db
      .prepare(
        `
      SELECT id, email, name, role, tier, verified,
             created_at as createdAt, last_login as lastLogin, plan_expires_at as planExpiresAt
      FROM users ORDER BY created_at DESC
    `
      )
      .all() as UserAdmin[];
  }

  searchUsers(query: string): UserAdmin[] {
    const pattern = `%${query}%`;
    return this.db
      .prepare(
        `
      SELECT id, email, name, role, tier, verified,
             created_at as createdAt, last_login as lastLogin, plan_expires_at as planExpiresAt
      FROM users WHERE email LIKE ? OR name LIKE ?
      ORDER BY created_at DESC
    `
      )
      .all(pattern, pattern) as UserAdmin[];
  }

  getActiveSessions(): SessionAdmin[] {
    return this.db
      .prepare(
        `
      SELECT s.id, s.user_id as userId, u.email as userEmail, u.name as userName,
             s.expires_at as expiresAt, s.created_at as createdAt
      FROM sessions s JOIN users u ON s.user_id = u.id
      WHERE s.expires_at > datetime('now')
      ORDER BY s.created_at DESC
    `
      )
      .all() as SessionAdmin[];
  }

  deleteSessionById(sessionId: number): boolean {
    const result = this.db.prepare('DELETE FROM sessions WHERE id = ?').run(sessionId);
    return result.changes > 0;
  }

  getRecentActivity(limit: number = 20): ActivityItem[] {
    return this.db
      .prepare(
        `
      SELECT * FROM (
        SELECT 'user_registered' as type, email as description, created_at as timestamp FROM users
        UNION ALL
        SELECT 'waitlist_joined' as type, email as description, created_at as timestamp FROM waitlist
      ) combined
      ORDER BY timestamp DESC LIMIT ?
    `
      )
      .all(Math.min(limit, 50)) as ActivityItem[];
  }

  getAdminDashboardStats(): {
    users: {
      total: number;
      byTier: Record<string, number>;
      byRole: Record<string, number>;
      recentSignups: number;
      verifiedCount: number;
      signupsByDay: Array<{ date: string; count: number }>;
    };
    waitlist: WaitlistStats & { signupsByDay: Array<{ date: string; count: number }> };
    sessions: { active: number; total: number };
    reportPurchases: { total: number; active: number };
  } {
    const userStats = this.getUserStats();
    const verifiedCount = (
      this.db.prepare('SELECT COUNT(*) as c FROM users WHERE verified = 1').get() as { c: number }
    ).c;
    const userSignupsByDay = this.db
      .prepare(
        "SELECT date(created_at) as date, COUNT(*) as count FROM users WHERE created_at > datetime('now', '-30 day') GROUP BY date(created_at) ORDER BY date ASC"
      )
      .all() as Array<{ date: string; count: number }>;

    const waitlistStats = this.getWaitlistStats();
    const waitlistSignupsByDay = this.db
      .prepare(
        "SELECT date(created_at) as date, COUNT(*) as count FROM waitlist WHERE created_at > datetime('now', '-30 day') GROUP BY date(created_at) ORDER BY date ASC"
      )
      .all() as Array<{ date: string; count: number }>;

    const activeSessions = (
      this.db
        .prepare("SELECT COUNT(*) as c FROM sessions WHERE expires_at > datetime('now')")
        .get() as { c: number }
    ).c;
    const totalSessions = (
      this.db.prepare('SELECT COUNT(*) as c FROM sessions').get() as { c: number }
    ).c;

    const activeReportPurchases = (
      this.db
        .prepare(
          "SELECT COUNT(*) as c FROM report_purchases WHERE status = 'active' AND (expires_at IS NULL OR expires_at > datetime('now'))"
        )
        .get() as { c: number }
    ).c;
    const totalReportPurchases = (
      this.db.prepare('SELECT COUNT(*) as c FROM report_purchases').get() as { c: number }
    ).c;

    return {
      users: { ...userStats, verifiedCount, signupsByDay: userSignupsByDay },
      waitlist: { ...waitlistStats, signupsByDay: waitlistSignupsByDay },
      sessions: { active: activeSessions, total: totalSessions },
      reportPurchases: { total: totalReportPurchases, active: activeReportPurchases },
    };
  }

  // ── Admin: User Management ──────────────────────────────────────

  getAllUsers(): User[] {
    return this.db
      .prepare(
        `
      SELECT id, email, name, password_hash as passwordHash, role, tier, verified,
             created_at as createdAt, last_login as lastLogin, plan_expires_at as planExpiresAt
      FROM users ORDER BY created_at DESC
    `
      )
      .all() as User[];
  }

  updateUserTier(userId: number, tier: string, planExpiresAt?: string): void {
    this.db
      .prepare('UPDATE users SET tier = ?, plan_expires_at = ? WHERE id = ?')
      .run(tier, planExpiresAt ?? null, userId);
  }

  updateUserRole(userId: number, role: string): void {
    this.db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, userId);
  }

  getUserStats(): {
    total: number;
    byTier: Record<string, number>;
    byRole: Record<string, number>;
    recentSignups: number;
  } {
    const total = (this.db.prepare('SELECT COUNT(*) as c FROM users').get() as { c: number }).c;
    const recentSignups = (
      this.db
        .prepare("SELECT COUNT(*) as c FROM users WHERE created_at > datetime('now', '-7 day')")
        .get() as { c: number }
    ).c;

    const tierRows = this.db
      .prepare('SELECT tier, COUNT(*) as c FROM users GROUP BY tier')
      .all() as { tier: string; c: number }[];
    const byTier: Record<string, number> = {};
    for (const row of tierRows) byTier[row.tier] = row.c;

    const roleRows = this.db
      .prepare('SELECT role, COUNT(*) as c FROM users GROUP BY role')
      .all() as { role: string; c: number }[];
    const byRole: Record<string, number> = {};
    for (const row of roleRows) byRole[row.role] = row.c;

    return { total, byTier, byRole, recentSignups };
  }

  // ── Admin: Waitlist Management ─────────────────────────────────

  approveWaitlistEntry(id: number): void {
    this.db
      .prepare("UPDATE waitlist SET status = 'approved', updated_at = datetime('now') WHERE id = ?")
      .run(id);
  }

  rejectWaitlistEntry(id: number): void {
    this.db
      .prepare("UPDATE waitlist SET status = 'rejected', updated_at = datetime('now') WHERE id = ?")
      .run(id);
  }

  // ── Audit Log ──────────────────────────────────────────────────

  addAuditLog(
    action: string,
    actorId: number | null,
    targetId: number | null,
    details?: string
  ): void {
    this.db
      .prepare(
        `
      INSERT INTO audit_log (action, actor_id, target_id, details)
      VALUES (?, ?, ?, ?)
    `
      )
      .run(action, actorId, targetId, details ?? null);
  }

  getAuditLog(limit: number = 50): AuditLogEntry[] {
    return this.db
      .prepare(
        `
      SELECT id, action, actor_id as actorId, target_id as targetId,
             details, created_at as createdAt
      FROM audit_log ORDER BY created_at DESC LIMIT ?
    `
      )
      .all(Math.min(limit, 200)) as AuditLogEntry[];
  }

  // ── Subscriptions (Lemon Squeezy) ──────────────────────────

  upsertSubscription(data: {
    userId: number;
    lsSubscriptionId: string;
    lsCustomerId: string;
    lsVariantId: string;
    tier: string;
    status: string;
    renewsAt: string | null;
    endsAt: string | null;
  }): void {
    this.db
      .prepare(
        `INSERT INTO subscriptions (user_id, ls_subscription_id, ls_customer_id, ls_variant_id, tier, status, renews_at, ends_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
         ON CONFLICT(ls_subscription_id) DO UPDATE SET
           status = excluded.status,
           tier = excluded.tier,
           renews_at = excluded.renews_at,
           ends_at = excluded.ends_at,
           updated_at = datetime('now')`
      )
      .run(
        data.userId,
        data.lsSubscriptionId,
        data.lsCustomerId,
        data.lsVariantId,
        data.tier,
        data.status,
        data.renewsAt,
        data.endsAt
      );
  }

  getSubscriptionByLsId(lsSubscriptionId: string): Subscription | undefined {
    return this.db
      .prepare(
        `SELECT id, user_id as userId, ls_subscription_id as lsSubscriptionId,
                ls_customer_id as lsCustomerId, ls_variant_id as lsVariantId,
                tier, status, renews_at as renewsAt, ends_at as endsAt,
                created_at as createdAt, updated_at as updatedAt
         FROM subscriptions WHERE ls_subscription_id = ?`
      )
      .get(lsSubscriptionId) as Subscription | undefined;
  }

  getActiveSubscription(userId: number): Subscription | undefined {
    return this.db
      .prepare(
        `SELECT id, user_id as userId, ls_subscription_id as lsSubscriptionId,
                ls_customer_id as lsCustomerId, ls_variant_id as lsVariantId,
                tier, status, renews_at as renewsAt, ends_at as endsAt,
                created_at as createdAt, updated_at as updatedAt
         FROM subscriptions WHERE user_id = ? AND status IN ('active', 'on_trial', 'past_due')
         ORDER BY created_at DESC LIMIT 1`
      )
      .get(userId) as Subscription | undefined;
  }

  updateSubscriptionStatus(lsSubscriptionId: string, status: string, endsAt: string | null): void {
    this.db
      .prepare(
        `UPDATE subscriptions SET status = ?, ends_at = ?, updated_at = datetime('now')
         WHERE ls_subscription_id = ?`
      )
      .run(status, endsAt, lsSubscriptionId);
  }

  // ── Subscription Lifecycle ─────────────────────────────────

  /**
   * Downgrade all users whose plan_expires_at has passed to free tier.
   * Returns the list of downgraded user emails (for notification).
   */
  checkExpiredPlans(): Array<{ id: number; email: string; tier: string }> {
    const expired = this.db
      .prepare(
        `SELECT id, email, tier FROM users
         WHERE plan_expires_at IS NOT NULL
           AND plan_expires_at <= datetime('now')
           AND tier != 'free'`
      )
      .all() as Array<{ id: number; email: string; tier: string }>;

    if (expired.length > 0) {
      this.db
        .prepare(
          `UPDATE users SET tier = 'free', plan_expires_at = NULL
           WHERE plan_expires_at IS NOT NULL
             AND plan_expires_at <= datetime('now')
             AND tier != 'free'`
        )
        .run();

      for (const user of expired) {
        this.addAuditLog(
          'plan_expired',
          null,
          user.id,
          JSON.stringify({ previousTier: user.tier })
        );
      }
    }

    return expired;
  }

  /**
   * Get users whose plans expire within the given number of days.
   * Used for sending expiration warning emails.
   */
  getExpiringPlans(withinDays: number): Array<{ id: number; email: string; name: string; tier: string; planExpiresAt: string }> {
    return this.db
      .prepare(
        `SELECT id, email, name, tier, plan_expires_at as planExpiresAt FROM users
         WHERE plan_expires_at IS NOT NULL
           AND plan_expires_at > datetime('now')
           AND plan_expires_at <= datetime('now', '+' || ? || ' days')
           AND tier != 'free'`
      )
      .all(withinDays) as Array<{ id: number; email: string; name: string; tier: string; planExpiresAt: string }>;
  }

  // ── Password Reset ──────────────────────────────────────────

  /**
   * Store a hashed reset token for a user. Invalidates any previous tokens.
   * Returns the token expiry time.
   */
  createResetToken(userId: number, tokenHash: string): string {
    // Invalidate any existing unused tokens for this user
    this.db
      .prepare('UPDATE password_reset_tokens SET used = 1 WHERE user_id = ? AND used = 0')
      .run(userId);

    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString().replace('T', ' ').slice(0, 19); // 1 hour
    this.db
      .prepare(
        `INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)`
      )
      .run(userId, tokenHash, expiresAt);
    return expiresAt;
  }

  /**
   * Validate a reset token hash. Returns the user_id if valid, undefined otherwise.
   * Marks the token as used atomically.
   */
  validateResetToken(tokenHash: string): number | undefined {
    const row = this.db
      .prepare(
        `SELECT id, user_id as userId FROM password_reset_tokens
         WHERE token_hash = ? AND used = 0 AND expires_at > datetime('now')`
      )
      .get(tokenHash) as { id: number; userId: number } | undefined;

    if (!row) return undefined;

    // Mark as used
    this.db.prepare('UPDATE password_reset_tokens SET used = 1 WHERE id = ?').run(row.id);
    return row.userId;
  }

  /**
   * Update a user's password hash.
   */
  updateUserPassword(userId: number, passwordHash: string): void {
    this.db
      .prepare('UPDATE users SET password_hash = ? WHERE id = ?')
      .run(passwordHash, userId);
  }

  // ── Session Management ────────────────────────────────────────

  deleteSessionsByUserId(userId: number): number {
    const result = this.db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
    return result.changes;
  }

  close(): void {
    this.db.close();
  }
}

export interface ReportPurchase {
  id: number;
  userId: number;
  addonId: string;
  pricingModel: string;
  status: string;
  purchasedAt: string;
  expiresAt: string | null;
}

export interface Subscription {
  id: number;
  userId: number;
  lsSubscriptionId: string;
  lsCustomerId: string;
  lsVariantId: string;
  tier: string;
  status: string;
  renewsAt: string | null;
  endsAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface AuditLogEntry {
  id: number;
  action: string;
  actorId: number | null;
  targetId: number | null;
  details: string | null;
  createdAt: string;
}
