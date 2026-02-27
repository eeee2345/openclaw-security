/**
 * panguard manager - Manager server for distributed agent architecture
 * panguard manager - 分散式 Agent 架構的 Manager 伺服器
 */

import { Command } from 'commander';

export function managerCommand(): Command {
  const cmd = new Command('manager').description(
    'Manager server for distributed agents / 分散式 Agent 管理伺服器',
  );

  cmd
    .command('start')
    .description('Start the Manager server / 啟動 Manager 伺服器')
    .option('--port <port>', 'Port number / 埠號', '8443')
    .action(async (opts: { port: string }) => {
      const port = parseInt(opts.port, 10);
      const { ManagerServer } = await import('../../manager/manager-server.js');
      const server = new ManagerServer(port);

      // Handle graceful shutdown
      const shutdown = async () => {
        console.log('\n[Panguard Manager] Shutting down...');
        await server.stop();
        process.exit(0);
      };
      process.on('SIGINT', () => void shutdown());
      process.on('SIGTERM', () => void shutdown());

      await server.start();
      console.log(`[Panguard Manager] Dashboard: http://localhost:${port}/dashboard`);
      console.log('[Panguard Manager] API: http://localhost:' + port + '/api/agents');
      console.log('[Panguard Manager] Press Ctrl+C to stop');
    });

  cmd
    .command('agents')
    .description('List registered agents / 列出已註冊的 Agent')
    .option('--url <url>', 'Manager URL / Manager 網址', 'http://localhost:8443')
    .action(async (opts: { url: string }) => {
      try {
        const res = await fetch(`${opts.url}/api/agents`);
        if (!res.ok) {
          console.error(`Error: HTTP ${res.status}`);
          process.exit(1);
        }
        const data = (await res.json()) as {
          agents: Array<{
            id: string;
            hostname: string;
            ip?: string;
            status: string;
            os: string;
            mode: string;
            eventsProcessed: number;
            threatsDetected: number;
            lastSeen: string;
          }>;
          total: number;
        };

        if (data.agents.length === 0) {
          console.log('No agents registered.');
          return;
        }

        console.log(`\nRegistered Agents (${data.total}):\n`);
        console.log(
          'ID'.padEnd(16) +
            'Hostname'.padEnd(20) +
            'IP'.padEnd(16) +
            'Status'.padEnd(10) +
            'OS'.padEnd(20) +
            'Mode'.padEnd(12) +
            'Events'.padEnd(10) +
            'Threats'.padEnd(10) +
            'Last Seen',
        );
        console.log('-'.repeat(130));

        for (const agent of data.agents) {
          const statusSymbol =
            agent.status === 'online' ? '[OK]' : agent.status === 'stale' ? '[!!]' : '[--]';
          console.log(
            agent.id.padEnd(16) +
              agent.hostname.padEnd(20) +
              (agent.ip ?? '-').padEnd(16) +
              `${statusSymbol} ${agent.status}`.padEnd(10) +
              agent.os.slice(0, 18).padEnd(20) +
              agent.mode.padEnd(12) +
              String(agent.eventsProcessed).padEnd(10) +
              String(agent.threatsDetected).padEnd(10) +
              agent.lastSeen,
          );
        }
      } catch (err: unknown) {
        console.error(
          `Failed to connect to manager: ${err instanceof Error ? err.message : String(err)}`,
        );
        process.exit(1);
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
          console.error(`Error: ${data.error ?? `HTTP ${res.status}`}`);
          process.exit(1);
        }

        const data = (await res.json()) as { message?: string };
        console.log(data.message ?? 'Scan command queued');
      } catch (err: unknown) {
        console.error(
          `Failed to connect to manager: ${err instanceof Error ? err.message : String(err)}`,
        );
        process.exit(1);
      }
    });

  return cmd;
}
