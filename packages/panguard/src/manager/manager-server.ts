/**
 * ManagerServer - Central manager for distributed Panguard agents
 * ManagerServer - 分散式 Panguard Agent 的中央管理伺服器
 *
 * Provides a REST API for agent registration, heartbeat, event collection,
 * and a simple HTML dashboard. Uses Node.js native http module.
 *
 * @module @panguard-ai/panguard/manager/manager-server
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomUUID } from 'node:crypto';

/** Registered agent info */
export interface AgentInfo {
  id: string;
  hostname: string;
  os: string;
  arch: string;
  version: string;
  ip?: string;
  token: string;
  registeredAt: string;
  lastSeen: string;
  status: 'online' | 'offline' | 'stale';
  eventsProcessed: number;
  threatsDetected: number;
  actionsExecuted: number;
  mode: string;
  uptime: number;
  memoryUsageMB: number;
}

/** Security event from agent */
export interface AgentEvent {
  agentId: string;
  agentHostname: string;
  event: unknown;
  verdict?: {
    conclusion: string;
    confidence: number;
    action: string;
  };
  receivedAt: string;
}

/** Scan command queued for agent */
interface ScanCommand {
  agentId: string;
  command: 'scan';
  queuedAt: string;
  status: 'pending' | 'acknowledged';
}

/**
 * ManagerServer handles all REST API and dashboard functionality
 */
export class ManagerServer {
  private server: ReturnType<typeof createServer> | null = null;
  private readonly port: number;
  private readonly agents = new Map<string, AgentInfo>();
  private readonly events: AgentEvent[] = [];
  private readonly scanQueue: ScanCommand[] = [];
  private staleCheckTimer: ReturnType<typeof setInterval> | null = null;

  /** Maximum events to keep in memory */
  private readonly maxEvents = 10000;

  constructor(port = 8443) {
    this.port = port;
  }

  /**
   * Start the Manager server
   */
  async start(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      this.server = createServer((req, res) => {
        this.handleRequest(req, res).catch((err: unknown) => {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Internal server error' }));
          console.error('Manager request error:', err);
        });
      });

      this.server.on('error', reject);
      this.server.listen(this.port, () => {
        console.log(`[Panguard Manager] Listening on port ${this.port}`);

        // Periodic stale agent check (every 60s)
        this.staleCheckTimer = setInterval(() => this.checkStaleAgents(), 60000);

        resolve();
      });
    });
  }

  /**
   * Stop the Manager server
   */
  async stop(): Promise<void> {
    if (this.staleCheckTimer) {
      clearInterval(this.staleCheckTimer);
      this.staleCheckTimer = null;
    }

    return new Promise<void>((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }

  /**
   * Route incoming requests
   */
  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
    const path = url.pathname;
    const method = req.method ?? 'GET';

    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    // Route matching
    if (method === 'POST' && path === '/api/agents/register') {
      return this.handleRegister(req, res);
    }

    // Agent-specific routes
    const agentMatch = path.match(/^\/api\/agents\/([^/]+)\/(heartbeat|events|status|scan)$/);
    if (agentMatch) {
      const agentId = agentMatch[1]!;
      const action = agentMatch[2]!;
      const authError = this.checkAuth(req, agentId);
      if (authError) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: authError }));
        return;
      }

      if (method === 'POST' && action === 'heartbeat') return this.handleHeartbeat(agentId, req, res);
      if (method === 'POST' && action === 'events') return this.handleEvent(agentId, req, res);
      if (method === 'GET' && action === 'status') return this.handleAgentStatus(agentId, res);
      if (method === 'POST' && action === 'scan') return this.handleScan(agentId, res);
    }

    if (method === 'GET' && path === '/api/agents') {
      return this.handleListAgents(res);
    }

    if (method === 'GET' && path === '/api/rules/latest') {
      return this.handleGetRules(res);
    }

    if (method === 'GET' && path === '/api/events') {
      return this.handleListEvents(url, res);
    }

    if (method === 'GET' && (path === '/api/dashboard' || path === '/' || path === '/dashboard')) {
      return this.handleDashboard(res);
    }

    // 404
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found' }));
  }

  /**
   * Parse JSON body from request
   */
  private async parseBody<T>(req: IncomingMessage): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const chunks: Buffer[] = [];
      req.on('data', (chunk: Buffer) => chunks.push(chunk));
      req.on('end', () => {
        try {
          const data = Buffer.concat(chunks).toString('utf-8');
          resolve(JSON.parse(data) as T);
        } catch {
          reject(new Error('Invalid JSON'));
        }
      });
      req.on('error', reject);
    });
  }

  /**
   * Check authorization token for agent routes
   */
  private checkAuth(req: IncomingMessage, agentId: string): string | null {
    const auth = req.headers.authorization;
    if (!auth?.startsWith('Bearer ')) return 'Missing authorization header';

    const token = auth.slice(7);
    const agent = this.agents.get(agentId);
    if (!agent) return 'Agent not found';
    if (agent.token !== token) return 'Invalid token';

    return null;
  }

  // ─── API Handlers ──────────────────────────────────────────

  private async handleRegister(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await this.parseBody<{
      hostname: string;
      os: string;
      arch: string;
      version: string;
      ip?: string;
    }>(req);

    const agentId = `agent-${randomUUID().slice(0, 8)}`;
    const token = randomUUID();

    const agent: AgentInfo = {
      id: agentId,
      hostname: body.hostname,
      os: body.os,
      arch: body.arch,
      version: body.version,
      ip: body.ip,
      token,
      registeredAt: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
      status: 'online',
      eventsProcessed: 0,
      threatsDetected: 0,
      actionsExecuted: 0,
      mode: 'learning',
      uptime: 0,
      memoryUsageMB: 0,
    };

    this.agents.set(agentId, agent);
    console.log(`[Panguard Manager] Agent registered: ${agentId} (${body.hostname})`);

    this.json(res, 201, { agentId, token });
  }

  private async handleHeartbeat(
    agentId: string,
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    const body = await this.parseBody<{
      eventsProcessed: number;
      threatsDetected: number;
      actionsExecuted: number;
      mode: string;
      uptime: number;
      memoryUsageMB: number;
    }>(req);

    const agent = this.agents.get(agentId);
    if (!agent) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Agent not found' }));
      return;
    }

    // Update agent status
    const updated: AgentInfo = {
      ...agent,
      lastSeen: new Date().toISOString(),
      status: 'online',
      eventsProcessed: body.eventsProcessed,
      threatsDetected: body.threatsDetected,
      actionsExecuted: body.actionsExecuted,
      mode: body.mode,
      uptime: body.uptime,
      memoryUsageMB: body.memoryUsageMB,
    };
    this.agents.set(agentId, updated);

    // Check for pending scan commands
    const pendingScans = this.scanQueue.filter(
      (s) => s.agentId === agentId && s.status === 'pending',
    );
    for (const scan of pendingScans) {
      scan.status = 'acknowledged';
    }

    this.json(res, 200, {
      ok: true,
      commands: pendingScans.map((s) => ({ command: s.command })),
    });
  }

  private async handleEvent(
    agentId: string,
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    const body = await this.parseBody<{
      event: unknown;
      verdict?: { conclusion: string; confidence: number; action: string };
    }>(req);

    const agent = this.agents.get(agentId);

    const agentEvent: AgentEvent = {
      agentId,
      agentHostname: agent?.hostname ?? 'unknown',
      event: body.event,
      verdict: body.verdict,
      receivedAt: new Date().toISOString(),
    };

    this.events.push(agentEvent);

    // Trim events if over limit
    if (this.events.length > this.maxEvents) {
      this.events.splice(0, this.events.length - this.maxEvents);
    }

    this.json(res, 200, { ok: true });
  }

  private handleAgentStatus(agentId: string, res: ServerResponse): void {
    const agent = this.agents.get(agentId);
    if (!agent) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Agent not found' }));
      return;
    }

    // Return agent info without token
    const { token: _token, ...safeAgent } = agent;
    this.json(res, 200, safeAgent);
  }

  private handleScan(agentId: string, res: ServerResponse): void {
    const agent = this.agents.get(agentId);
    if (!agent) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Agent not found' }));
      return;
    }

    this.scanQueue.push({
      agentId,
      command: 'scan',
      queuedAt: new Date().toISOString(),
      status: 'pending',
    });

    this.json(res, 200, { ok: true, message: `Scan queued for agent ${agentId}` });
  }

  private handleListAgents(res: ServerResponse): void {
    const agents = Array.from(this.agents.values()).map(({ token: _token, ...agent }) => agent);
    this.json(res, 200, { agents, total: agents.length });
  }

  private handleGetRules(res: ServerResponse): void {
    // Placeholder - return empty rules for now
    // In production, this would serve latest Sigma/YARA rules
    this.json(res, 200, { rules: [] });
  }

  private handleListEvents(url: URL, res: ServerResponse): void {
    const limit = Math.min(parseInt(url.searchParams.get('limit') ?? '100', 10), 1000);
    const offset = parseInt(url.searchParams.get('offset') ?? '0', 10);
    const agentId = url.searchParams.get('agent_id');

    let filtered = this.events;
    if (agentId) {
      filtered = filtered.filter((e) => e.agentId === agentId);
    }

    const total = filtered.length;
    const page = filtered.slice(offset, offset + limit);

    this.json(res, 200, { events: page, total, limit, offset });
  }

  private handleDashboard(res: ServerResponse): void {
    const agents = Array.from(this.agents.values());
    const now = Date.now();

    const totalEvents = agents.reduce((sum, a) => sum + a.eventsProcessed, 0);
    const totalThreats = agents.reduce((sum, a) => sum + a.threatsDetected, 0);
    const recentEvents = this.events.slice(-20).reverse();

    const agentRows = agents
      .map((a) => {
        const lastSeenMs = now - new Date(a.lastSeen).getTime();
        const statusColor =
          a.status === 'online' ? '#22c55e' : a.status === 'stale' ? '#eab308' : '#ef4444';
        const statusDot = `<span style="color:${statusColor}">&#9679;</span>`;

        return `<tr>
          <td>${statusDot} ${a.hostname}</td>
          <td>${a.id}</td>
          <td>${a.ip ?? '-'}</td>
          <td>${a.os}</td>
          <td>${a.mode}</td>
          <td>${a.eventsProcessed}</td>
          <td>${a.threatsDetected}</td>
          <td>${a.actionsExecuted}</td>
          <td>${a.memoryUsageMB}MB</td>
          <td>${Math.round(lastSeenMs / 1000)}s ago</td>
        </tr>`;
      })
      .join('');

    const eventRows = recentEvents
      .map((e) => {
        const verdict = e.verdict;
        const conclusionColor =
          verdict?.conclusion === 'malicious'
            ? '#ef4444'
            : verdict?.conclusion === 'suspicious'
              ? '#eab308'
              : '#22c55e';

        return `<tr>
          <td>${e.agentHostname}</td>
          <td><span style="color:${conclusionColor}">${verdict?.conclusion ?? '-'}</span></td>
          <td>${verdict?.confidence ?? '-'}%</td>
          <td>${verdict?.action ?? '-'}</td>
          <td>${new Date(e.receivedAt).toLocaleString()}</td>
        </tr>`;
      })
      .join('');

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Panguard Manager Dashboard</title>
  <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
  <meta http-equiv="refresh" content="10">
  <style>
    body { background: #0f172a; color: #e2e8f0; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #1e293b; }
    th { color: #94a3b8; font-weight: 600; font-size: 0.85rem; text-transform: uppercase; }
    .card { background: #1e293b; border-radius: 8px; padding: 20px; }
    .stat { font-size: 2rem; font-weight: 700; }
    .stat-label { font-size: 0.85rem; color: #94a3b8; }
  </style>
</head>
<body class="p-6">
  <div class="max-w-7xl mx-auto">
    <h1 class="text-2xl font-bold mb-6">Panguard Manager Dashboard</h1>

    <div class="grid grid-cols-4 gap-4 mb-6">
      <div class="card">
        <div class="stat">${agents.length}</div>
        <div class="stat-label">Agents</div>
      </div>
      <div class="card">
        <div class="stat">${agents.filter((a) => a.status === 'online').length}</div>
        <div class="stat-label">Online</div>
      </div>
      <div class="card">
        <div class="stat">${totalEvents.toLocaleString()}</div>
        <div class="stat-label">Events Processed</div>
      </div>
      <div class="card">
        <div class="stat" style="color:#ef4444">${totalThreats.toLocaleString()}</div>
        <div class="stat-label">Threats Detected</div>
      </div>
    </div>

    <div class="card mb-6">
      <h2 class="text-lg font-semibold mb-4">Agents</h2>
      <table>
        <thead>
          <tr>
            <th>Hostname</th><th>ID</th><th>IP</th><th>OS</th><th>Mode</th>
            <th>Events</th><th>Threats</th><th>Actions</th><th>Memory</th><th>Last Seen</th>
          </tr>
        </thead>
        <tbody>${agentRows || '<tr><td colspan="10" style="text-align:center;color:#64748b">No agents registered</td></tr>'}</tbody>
      </table>
    </div>

    <div class="card">
      <h2 class="text-lg font-semibold mb-4">Recent Events (last 20)</h2>
      <table>
        <thead>
          <tr>
            <th>Agent</th><th>Conclusion</th><th>Confidence</th><th>Action</th><th>Time</th>
          </tr>
        </thead>
        <tbody>${eventRows || '<tr><td colspan="5" style="text-align:center;color:#64748b">No events yet</td></tr>'}</tbody>
      </table>
    </div>
  </div>
</body>
</html>`;

    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
  }

  // ─── Utilities ─────────────────────────────────────────────

  private json(res: ServerResponse, status: number, data: unknown): void {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
  }

  /**
   * Mark agents as stale/offline if no heartbeat received
   */
  private checkStaleAgents(): void {
    const now = Date.now();
    for (const [id, agent] of this.agents) {
      const elapsed = now - new Date(agent.lastSeen).getTime();
      if (elapsed > 120000 && agent.status === 'online') {
        this.agents.set(id, { ...agent, status: 'stale' });
      } else if (elapsed > 300000 && agent.status !== 'offline') {
        this.agents.set(id, { ...agent, status: 'offline' });
      }
    }
  }

  /** Get the port number */
  getPort(): number {
    return this.port;
  }

  /** Get agents count */
  getAgentCount(): number {
    return this.agents.size;
  }

  /** Get events count */
  getEventCount(): number {
    return this.events.length;
  }
}
