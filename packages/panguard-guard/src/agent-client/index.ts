/**
 * PanguardAgentClient - Agent-side communication with Manager server
 * PanguardAgentClient - Agent 端與 Manager 伺服器的通訊
 *
 * Handles registration, heartbeat, event reporting, and rule pulling
 * in the distributed Manager-Agent architecture.
 *
 * @module @panguard-ai/panguard-guard/agent-client
 */

import { createLogger } from '@panguard-ai/core';
import type { SecurityEvent } from '@panguard-ai/core';
import os from 'node:os';

const logger = createLogger('panguard-guard:agent-client');

/** Agent registration payload */
export interface AgentRegistration {
  hostname: string;
  os: string;
  arch: string;
  version: string;
  ip?: string;
}

/** Agent registration response from Manager */
export interface AgentRegistrationResponse {
  agentId: string;
  token: string;
}

/** Agent heartbeat payload */
export interface AgentHeartbeat {
  eventsProcessed: number;
  threatsDetected: number;
  actionsExecuted: number;
  mode: string;
  uptime: number;
  memoryUsageMB: number;
}

/** Agent event report */
export interface AgentEventReport {
  event: SecurityEvent;
  verdict?: {
    conclusion: string;
    confidence: number;
    action: string;
  };
}

/**
 * HTTP helper - performs a JSON request using native Node.js http/https
 */
async function jsonRequest<T>(
  url: string,
  method: string,
  body?: unknown,
  token?: string,
): Promise<T> {
  const { request: httpRequest } = url.startsWith('https')
    ? await import('node:https')
    : await import('node:http');

  const parsedUrl = new URL(url);

  return new Promise<T>((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : undefined;
    const req = httpRequest(
      {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
        path: parsedUrl.pathname + parsedUrl.search,
        method,
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
          ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
        },
        timeout: 10000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          const data = Buffer.concat(chunks).toString('utf-8');
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            try {
              resolve(JSON.parse(data) as T);
            } catch {
              resolve(data as unknown as T);
            }
          } else {
            reject(new Error(`HTTP ${res.statusCode}: ${data}`));
          }
        });
      },
    );

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timed out'));
    });

    if (payload) req.write(payload);
    req.end();
  });
}

/**
 * PanguardAgentClient manages communication with the Manager server
 */
export class PanguardAgentClient {
  private readonly managerUrl: string;
  private agentId: string | null = null;
  private token: string | null = null;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private readonly heartbeatInterval: number;

  constructor(managerUrl: string, heartbeatInterval = 30000) {
    // Remove trailing slash
    this.managerUrl = managerUrl.replace(/\/+$/, '');
    this.heartbeatInterval = heartbeatInterval;
  }

  /**
   * Register this agent with the Manager
   */
  async register(version: string): Promise<AgentRegistrationResponse> {
    const registration: AgentRegistration = {
      hostname: os.hostname(),
      os: `${os.type()} ${os.release()}`,
      arch: os.arch(),
      version,
      ip: getLocalIP(),
    };

    logger.info(`Registering agent with manager: ${this.managerUrl}`);

    const response = await jsonRequest<AgentRegistrationResponse>(
      `${this.managerUrl}/api/agents/register`,
      'POST',
      registration,
    );

    this.agentId = response.agentId;
    this.token = response.token;

    logger.info(`Agent registered: id=${this.agentId}`);
    return response;
  }

  /**
   * Send heartbeat to Manager
   */
  async heartbeat(status: AgentHeartbeat): Promise<void> {
    if (!this.agentId || !this.token) {
      throw new Error('Agent not registered. Call register() first.');
    }

    await jsonRequest(
      `${this.managerUrl}/api/agents/${this.agentId}/heartbeat`,
      'POST',
      status,
      this.token,
    );
  }

  /**
   * Report a security event to Manager
   */
  async reportEvent(report: AgentEventReport): Promise<void> {
    if (!this.agentId || !this.token) {
      throw new Error('Agent not registered. Call register() first.');
    }

    await jsonRequest(
      `${this.managerUrl}/api/agents/${this.agentId}/events`,
      'POST',
      report,
      this.token,
    );
  }

  /**
   * Pull latest rules from Manager
   */
  async pullRules(): Promise<string[]> {
    if (!this.token) {
      throw new Error('Agent not registered. Call register() first.');
    }

    const response = await jsonRequest<{ rules: string[] }>(
      `${this.managerUrl}/api/rules/latest`,
      'GET',
      undefined,
      this.token,
    );

    return response.rules ?? [];
  }

  /**
   * Start periodic heartbeat
   */
  startHeartbeat(statusGetter: () => AgentHeartbeat): void {
    if (this.heartbeatTimer) return;

    this.heartbeatTimer = setInterval(() => {
      this.heartbeat(statusGetter()).catch((err: unknown) => {
        logger.warn(
          `Heartbeat failed: ${err instanceof Error ? err.message : String(err)}`,
        );
      });
    }, this.heartbeatInterval);

    logger.info(`Heartbeat started (interval: ${this.heartbeatInterval}ms)`);
  }

  /**
   * Stop periodic heartbeat
   */
  stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
      logger.info('Heartbeat stopped');
    }
  }

  /** Get agent ID */
  getAgentId(): string | null {
    return this.agentId;
  }

  /** Check if registered */
  isRegistered(): boolean {
    return this.agentId !== null && this.token !== null;
  }
}

/**
 * Get the first non-internal IPv4 address
 */
function getLocalIP(): string | undefined {
  const interfaces = os.networkInterfaces();
  for (const nets of Object.values(interfaces)) {
    if (!nets) continue;
    for (const net of nets) {
      if (net.family === 'IPv4' && !net.internal) {
        return net.address;
      }
    }
  }
  return undefined;
}
