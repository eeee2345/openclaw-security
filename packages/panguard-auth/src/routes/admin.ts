/**
 * Admin route handlers:
 * handleAdminUsers, handleAdminUpdateTier, handleAdminUpdateRole, handleAdminStats,
 * handleAdminDashboard, handleAdminUsersSearch, handleAdminSessions,
 * handleAdminSessionRevoke, handleAdminActivity, handleAdminAuditLog,
 * handleAdminAuditActions, handleAdminUsageOverview, handleAdminUsageUser,
 * handleAdminUserDetail, handleAdminUserSuspend, handleAdminBulkAction.
 * @module @panguard-ai/panguard-auth/routes/admin
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { authenticateRequest, requireAdmin } from '../middleware.js';
import { logAuditEvent } from '@panguard-ai/security-hardening';
import { getUsageSummary, getQuotaLimits, currentPeriod } from '../usage-meter.js';
import type { MeterableResource } from '../usage-meter.js';
import type { RouteContext } from './shared.js';
import { readBody, json, toPublicUser } from './shared.js';

export function createAdminRoutes(ctx: RouteContext) {
  const { db } = ctx;

  function handleAdminUsers(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'GET') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    const user = authenticateRequest(req, db);
    if (!requireAdmin(user)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }

    const users = db.getAllUsersAdmin();
    json(res, 200, { ok: true, data: users });
  }

  async function handleAdminUpdateTier(
    req: IncomingMessage,
    res: ServerResponse,
    userId: string
  ): Promise<void> {
    if (req.method !== 'PATCH') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    const user = authenticateRequest(req, db);
    if (!requireAdmin(user)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }

    const result = await readBody(req);
    if (!result.ok) {
      json(res, result.status, { ok: false, error: 'Invalid JSON body' });
      return;
    }

    const { tier } = result.data;
    const validTiers = ['free', 'solo', 'starter', 'pro', 'team', 'business', 'enterprise'];
    if (typeof tier !== 'string' || !validTiers.includes(tier)) {
      json(res, 400, {
        ok: false,
        error: `Invalid tier. Must be one of: ${validTiers.join(', ')}`,
      });
      return;
    }

    const target = db.getUserById(Number(userId));
    if (!target) {
      json(res, 404, { ok: false, error: 'User not found' });
      return;
    }

    const oldTier = target.tier;
    db.updateUserTier(target.id, tier);

    // Audit log
    db.addAuditLog('tier_change', user!.id, target.id, JSON.stringify({ from: oldTier, to: tier }));
    logAuditEvent({
      level: 'info',
      action: 'policy_check',
      target: `user:${target.id}`,
      result: 'success',
      context: { details: `Tier changed: ${oldTier} -> ${tier}` },
    });

    // Invalidate all sessions for this user so they pick up the new tier
    db.deleteSessionsByUserId(target.id);

    const updated = db.getUserById(target.id)!;
    json(res, 200, { ok: true, data: toPublicUser(updated) });
  }

  async function handleAdminUpdateRole(
    req: IncomingMessage,
    res: ServerResponse,
    userId: string
  ): Promise<void> {
    if (req.method !== 'PATCH') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    const user = authenticateRequest(req, db);
    if (!requireAdmin(user)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }

    const result = await readBody(req);
    if (!result.ok) {
      json(res, result.status, { ok: false, error: 'Invalid JSON body' });
      return;
    }

    const { role } = result.data;
    if (typeof role !== 'string' || !['user', 'admin'].includes(role)) {
      json(res, 400, { ok: false, error: 'Invalid role. Must be "user" or "admin"' });
      return;
    }

    const target = db.getUserById(Number(userId));
    if (!target) {
      json(res, 404, { ok: false, error: 'User not found' });
      return;
    }

    const oldRole = target.role;
    db.updateUserRole(target.id, role);

    // Audit log
    db.addAuditLog('role_change', user!.id, target.id, JSON.stringify({ from: oldRole, to: role }));
    logAuditEvent({
      level: 'info',
      action: 'policy_check',
      target: `user:${target.id}`,
      result: 'success',
      context: { details: `Role changed: ${oldRole} -> ${role}` },
    });

    const updated = db.getUserById(target.id)!;
    json(res, 200, { ok: true, data: toPublicUser(updated) });
  }

  function handleAdminStats(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'GET') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }

    const user = authenticateRequest(req, db);
    if (!requireAdmin(user)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }

    const userStats = db.getUserStats();
    const waitlistStats = db.getWaitlistStats();
    json(res, 200, { ok: true, data: { users: userStats, waitlist: waitlistStats } });
  }

  function handleAdminDashboard(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'GET') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }
    const user = authenticateRequest(req, db);
    if (!requireAdmin(user)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }
    const stats = db.getAdminDashboardStats();
    json(res, 200, { ok: true, data: stats });
  }

  function handleAdminUsersSearch(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'GET') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }
    const user = authenticateRequest(req, db);
    if (!requireAdmin(user)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }
    const urlObj = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
    const q = urlObj.searchParams.get('q') ?? '';
    const users = q ? db.searchUsers(q) : db.getAllUsersAdmin();
    json(res, 200, { ok: true, data: users });
  }

  function handleAdminSessions(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'GET') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }
    const user = authenticateRequest(req, db);
    if (!requireAdmin(user)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }
    const sessions = db.getActiveSessions();
    json(res, 200, { ok: true, data: sessions });
  }

  function handleAdminSessionRevoke(
    req: IncomingMessage,
    res: ServerResponse,
    sessionId: string
  ): void {
    if (req.method !== 'DELETE') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }
    const user = authenticateRequest(req, db);
    if (!requireAdmin(user)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }
    const deleted = db.deleteSessionById(Number(sessionId));
    if (!deleted) {
      json(res, 404, { ok: false, error: 'Session not found' });
      return;
    }
    json(res, 200, { ok: true, data: { revoked: true } });
  }

  function handleAdminActivity(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'GET') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }
    const user = authenticateRequest(req, db);
    if (!requireAdmin(user)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }
    const urlObj = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
    const limit = Math.min(parseInt(urlObj.searchParams.get('limit') ?? '20', 10) || 20, 50);
    const activity = db.getRecentActivity(limit);
    json(res, 200, { ok: true, data: activity });
  }

  function handleAdminAuditLog(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'GET') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }
    const user = authenticateRequest(req, db);
    if (!requireAdmin(user)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }

    const urlObj = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
    const filter = {
      action: urlObj.searchParams.get('action') || undefined,
      actorId: urlObj.searchParams.has('actorId')
        ? parseInt(urlObj.searchParams.get('actorId')!, 10)
        : undefined,
      dateFrom: urlObj.searchParams.get('dateFrom') || undefined,
      dateTo: urlObj.searchParams.get('dateTo') || undefined,
      page: parseInt(urlObj.searchParams.get('page') ?? '1', 10) || 1,
      perPage: parseInt(urlObj.searchParams.get('perPage') ?? '50', 10) || 50,
    };

    const result = db.getAuditLogFiltered(filter);
    const actions = db.getDistinctAuditActions();
    json(res, 200, {
      ok: true,
      data: { ...result, page: filter.page, perPage: filter.perPage, actions },
    });
  }

  function handleAdminAuditActions(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'GET') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }
    const user = authenticateRequest(req, db);
    if (!requireAdmin(user)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }
    json(res, 200, { ok: true, data: db.getDistinctAuditActions() });
  }

  function handleAdminUsageOverview(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'GET') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }
    const user = authenticateRequest(req, db);
    if (!requireAdmin(user)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }

    const allUsers = db.getAllUsersAdmin();
    const period = currentPeriod();
    const byUser: Array<{
      userId: number;
      email: string;
      name: string;
      tier: string;
      suspended: number;
      usage: Array<{ resource: string; current: number; limit: number; percentage: number }>;
    }> = [];
    const nearQuota: Array<{
      userId: number;
      email: string;
      tier: string;
      resource: string;
      current: number;
      limit: number;
      percentage: number;
    }> = [];

    for (const u of allUsers) {
      const summary = getUsageSummary(db, u.id, u.tier);
      byUser.push({
        userId: u.id,
        email: u.email,
        name: u.name,
        tier: u.tier,
        suspended: u.suspended,
        usage: summary,
      });
      for (const s of summary) {
        if (s.limit > 0 && s.percentage >= 80) {
          nearQuota.push({
            userId: u.id,
            email: u.email,
            tier: u.tier,
            resource: s.resource,
            current: s.current,
            limit: s.limit,
            percentage: s.percentage,
          });
        }
      }
    }

    // Aggregate by tier
    const byTier: Record<string, { userCount: number; resources: Record<string, number> }> = {};
    for (const u of byUser) {
      if (!byTier[u.tier]) {
        byTier[u.tier] = { userCount: 0, resources: {} };
      }
      const tierEntry = byTier[u.tier]!;
      tierEntry.userCount++;
      for (const s of u.usage) {
        tierEntry.resources[s.resource] = (tierEntry.resources[s.resource] ?? 0) + s.current;
      }
    }

    json(res, 200, {
      ok: true,
      data: { byUser, nearQuota, byTier, period },
    });
  }

  function handleAdminUsageUser(req: IncomingMessage, res: ServerResponse, userId: string): void {
    if (req.method !== 'GET') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }
    const admin = authenticateRequest(req, db);
    if (!requireAdmin(admin)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }

    const targetUser = db.getUserById(parseInt(userId, 10));
    if (!targetUser) {
      json(res, 404, { ok: false, error: 'User not found' });
      return;
    }

    const summary = getUsageSummary(db, targetUser.id, targetUser.tier);
    const history = db.getUserUsage(targetUser.id);

    json(res, 200, {
      ok: true,
      data: {
        user: {
          id: targetUser.id,
          email: targetUser.email,
          name: targetUser.name,
          tier: targetUser.tier,
        },
        usage: summary,
        history,
      },
    });
  }

  function handleAdminUserDetail(req: IncomingMessage, res: ServerResponse, userId: string): void {
    if (req.method !== 'GET') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }
    const admin = authenticateRequest(req, db);
    if (!requireAdmin(admin)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }

    const detail = db.getUserDetailById(parseInt(userId, 10));
    if (!detail) {
      json(res, 404, { ok: false, error: 'User not found' });
      return;
    }

    // Enrich usage with quota limits
    const limits = getQuotaLimits(detail.user.tier);
    const usage = detail.usage.map((u) => {
      const limit = limits[u.resource as MeterableResource] ?? -1;
      const current = u.count;
      return {
        resource: u.resource,
        current,
        limit,
        percentage: limit > 0 ? Math.round((current / limit) * 100) : 0,
      };
    });

    json(res, 200, {
      ok: true,
      data: {
        user: detail.user,
        subscription: detail.subscription,
        usage,
        sessions: detail.sessions,
        recentAudit: detail.recentAudit,
        twoFactor: { enabled: detail.totpEnabled },
      },
    });
  }

  async function handleAdminUserSuspend(
    req: IncomingMessage,
    res: ServerResponse,
    userId: string
  ): Promise<void> {
    if (req.method !== 'PATCH') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }
    const admin = authenticateRequest(req, db);
    if (!requireAdmin(admin)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }

    const body = await readBody(req);
    if (!body.ok) {
      json(res, body.status, { ok: false, error: 'Invalid JSON body' });
      return;
    }

    const targetId = parseInt(userId, 10);
    if (targetId === admin!.id) {
      json(res, 400, { ok: false, error: 'Cannot suspend your own account' });
      return;
    }

    const suspended = body.data['suspended'] === true;

    if (suspended) {
      db.suspendUser(targetId);
    } else {
      db.unsuspendUser(targetId);
    }

    db.addAuditLog(
      suspended ? 'user_suspended' : 'user_unsuspended',
      admin!.id,
      targetId,
      JSON.stringify({ suspended })
    );

    json(res, 200, { ok: true, data: { id: targetId, suspended } });
  }

  async function handleAdminBulkAction(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== 'POST') {
      json(res, 405, { ok: false, error: 'Method not allowed' });
      return;
    }
    const admin = authenticateRequest(req, db);
    if (!requireAdmin(admin)) {
      json(res, 403, { ok: false, error: 'Admin access required' });
      return;
    }

    const body = await readBody(req);
    if (!body.ok) {
      json(res, body.status, { ok: false, error: 'Invalid JSON body' });
      return;
    }

    const { userIds, action, value } = body.data as {
      userIds?: number[];
      action?: string;
      value?: string;
    };

    if (!Array.isArray(userIds) || userIds.length === 0) {
      json(res, 400, { ok: false, error: 'userIds array is required' });
      return;
    }
    if (userIds.length > 100) {
      json(res, 400, { ok: false, error: 'Maximum 100 users per bulk action' });
      return;
    }
    const validActions = ['change_tier', 'change_role', 'suspend', 'unsuspend'];
    if (!action || !validActions.includes(action)) {
      json(res, 400, { ok: false, error: `action must be one of: ${validActions.join(', ')}` });
      return;
    }

    const validTiers = ['free', 'solo', 'starter', 'team', 'business', 'enterprise'];
    const validRoles = ['user', 'admin'];

    if (action === 'change_tier' && (!value || !validTiers.includes(value))) {
      json(res, 400, { ok: false, error: `value must be one of: ${validTiers.join(', ')}` });
      return;
    }
    if (action === 'change_role' && (!value || !validRoles.includes(value))) {
      json(res, 400, { ok: false, error: `value must be one of: ${validRoles.join(', ')}` });
      return;
    }

    const results: Array<{ userId: number; success: boolean; error?: string }> = [];
    let processed = 0;
    let failed = 0;

    for (const uid of userIds) {
      try {
        if (uid === admin!.id && (action === 'suspend' || action === 'change_role')) {
          results.push({ userId: uid, success: false, error: 'Cannot modify own account' });
          failed++;
          continue;
        }

        switch (action) {
          case 'change_tier':
            db.updateUserTier(uid, value!);
            db.deleteSessionsByUserId(uid);
            break;
          case 'change_role':
            db.updateUserRole(uid, value!);
            break;
          case 'suspend':
            db.suspendUser(uid);
            break;
          case 'unsuspend':
            db.unsuspendUser(uid);
            break;
        }

        db.addAuditLog(`bulk_${action}`, admin!.id, uid, JSON.stringify({ action, value }));
        results.push({ userId: uid, success: true });
        processed++;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        results.push({ userId: uid, success: false, error: msg });
        failed++;
      }
    }

    json(res, 200, { ok: true, data: { processed, failed, results } });
  }

  return {
    handleAdminUsers,
    handleAdminUpdateTier,
    handleAdminUpdateRole,
    handleAdminStats,
    handleAdminDashboard,
    handleAdminUsersSearch,
    handleAdminSessions,
    handleAdminSessionRevoke,
    handleAdminActivity,
    handleAdminAuditLog,
    handleAdminAuditActions,
    handleAdminUsageOverview,
    handleAdminUsageUser,
    handleAdminUserDetail,
    handleAdminUserSuspend,
    handleAdminBulkAction,
  };
}
