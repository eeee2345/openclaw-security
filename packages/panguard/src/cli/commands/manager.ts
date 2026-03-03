/**
 * panguard manager - Manager server for distributed agent architecture
 * panguard manager - 分散式 Agent 架構的 Manager 伺服器
 */

import { Command } from 'commander';
import { c, symbols } from '@panguard-ai/core';

export function managerCommand(): Command {
  const cmd = new Command('manager').description(
    'Manager server for distributed agents / 分散式 Agent 管理伺服器'
  );

  cmd
    .command('start')
    .description('Start the Manager server / 啟動 Manager 伺服器')
    .option('--port <port>', 'Port number / 埠號', '8443')
    .option('--api-key <key>', 'API key for management endpoints / 管理端點 API 金鑰')
    .action(async (opts: { port: string; apiKey?: string }) => {
      const port = parseInt(opts.port, 10);
      const { ManagerServer, DEFAULT_MANAGER_CONFIG } = await import('@panguard-ai/manager');
      const server = new ManagerServer({
        ...DEFAULT_MANAGER_CONFIG,
        port,
        authToken: opts.apiKey ?? process.env['PANGUARD_MANAGER_KEY'] ?? '',
      });

      // Handle graceful shutdown
      const shutdown = async () => {
        console.log('\n[Panguard Manager] Shutting down...');
        await server.stop();
        process.exit(0);
      };
      process.on('SIGINT', () => void shutdown());
      process.on('SIGTERM', () => void shutdown());

      await server.start();
      console.log(`[Panguard Manager] Health: http://localhost:${port}/health`);
      console.log('[Panguard Manager] API: http://localhost:' + port + '/api/agents');
      console.log('[Panguard Manager] Press Ctrl+C to stop');
    });

  cmd
    .command('agents')
    .description('List registered agents / 列出已註冊的 Agent')
    .option('--url <url>', 'Manager URL / Manager 網址', 'http://localhost:8443')
    .option('--api-key <key>', 'API key / API 金鑰')
    .action(async (opts: { url: string; apiKey?: string }) => {
      try {
        const headers: Record<string, string> = {};
        if (opts.apiKey) headers['Authorization'] = `Bearer ${opts.apiKey}`;
        const res = await fetch(`${opts.url}/api/agents`, { headers });
        if (!res.ok) {
          console.error(`  ${symbols.fail} ${c.critical(`HTTP ${res.status}`)}`);
          process.exitCode = 1;
          return;
        }
        const json = (await res.json()) as {
          ok?: boolean;
          data?: Array<{
            agentId: string;
            hostname: string;
            status: string;
            lastHeartbeat: string;
            threatCount: number;
          }>;
          // Legacy inline format (deprecated)
          agents?: Array<{
            id: string;
            hostname: string;
            status: string;
          }>;
          total?: number;
        };

        // Support both production ({ ok, data }) and legacy ({ agents, total }) formats
        const agents = json.data ?? json.agents ?? [];

        if (agents.length === 0) {
          console.log('No agents registered.');
          return;
        }

        console.log(`\nRegistered Agents (${agents.length}):\n`);
        console.log(
          'ID'.padEnd(20) +
            'Hostname'.padEnd(24) +
            'Status'.padEnd(12) +
            'Threats'.padEnd(10) +
            'Last Heartbeat'
        );
        console.log('-'.repeat(90));

        for (const agent of agents) {
          const id = ('agentId' in agent ? agent.agentId : (agent as { id: string }).id) ?? '-';
          const status = agent.status ?? '-';
          const statusSymbol =
            status === 'online' ? '[OK]' : status === 'stale' ? '[!!]' : '[--]';
          const threats = 'threatCount' in agent ? String(agent.threatCount) : '-';
          const lastSeen = ('lastHeartbeat' in agent ? agent.lastHeartbeat : '') ?? '-';

          console.log(
            id.padEnd(20) +
              agent.hostname.padEnd(24) +
              `${statusSymbol} ${status}`.padEnd(12) +
              threats.padEnd(10) +
              lastSeen
          );
        }
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(`  ${symbols.fail} ${c.critical(`Failed to connect to manager: ${msg}`)}`);
        process.exitCode = 1;
        return;
      }
    });

  cmd
    .command('scan <agent-id>')
    .description('Trigger remote scan on an agent / 遠端觸發 Agent 掃描')
    .option('--url <url>', 'Manager URL / Manager 網址', 'http://localhost:8443')
    .action(async (agentId: string, opts: { url: string }) => {
      try {
        const res = await fetch(`${opts.url}/api/agents/${agentId}/scan`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
        });

        if (!res.ok) {
          const data = (await res.json()) as { error?: string };
          console.error(`  ${symbols.fail} ${c.critical(data.error ?? `HTTP ${res.status}`)}`);
          process.exitCode = 1;
          return;
        }

        const data = (await res.json()) as { message?: string };
        console.log(data.message ?? 'Scan command queued');
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(`  ${symbols.fail} ${c.critical(`Failed to connect to manager: ${msg}`)}`);
        process.exitCode = 1;
        return;
      }
    });

  return cmd;
}
