/**
 * panguard threat - Threat intelligence API management
 * panguard threat - 威脅情報 API 管理
 *
 * Requires @panguard-ai/threat-cloud (server-side, not published to npm).
 * This command is for Panguard operators only.
 */

import { Command } from 'commander';
import { c, spinner, statusPanel, divider, table, symbols } from '@panguard-ai/core';

async function loadThreatCloud() {
  try {
    return await import('@panguard-ai/threat-cloud');
  } catch {
    console.error(
      `\n  ${c.red('Threat Cloud server package is not available.')}\n` +
      `  This command is for Panguard operators only.\n` +
      `  Your Guard client connects to Threat Cloud automatically — no action needed.\n`
    );
    process.exitCode = 1;
    return null;
  }
}

export function threatCommand(): Command {
  const cmd = new Command('threat').description(
    'Threat intelligence API management / \u5A01\u8105\u60C5\u5831 API \u7BA1\u7406'
  );

  cmd
    .command('start')
    .description(
      'Start the Threat Cloud API server / \u555F\u52D5\u5A01\u8105\u96F2 API \u4F3A\u670D\u5668'
    )
    .option('--port <number>', 'Listen port / \u76E3\u807D\u57E0', '8080')
    .option('--host <string>', 'Listen host / \u76E3\u807D\u4E3B\u6A5F', '127.0.0.1')
    .option(
      '--db <path>',
      'SQLite database path / \u8CC7\u6599\u5EAB\u8DEF\u5F91',
      './threat-cloud.db'
    )
    .action(
      async (opts: { port: string; host: string; db: string }) => {
        const tc = await loadThreatCloud();
        if (!tc) return;

        const sp = spinner('Starting Threat Cloud API server...');
        const server = new tc.ThreatCloudServer({
          port: parseInt(opts.port, 10),
          host: opts.host,
          dbPath: opts.db,
          apiKeyRequired: false,
          apiKeys: [],
          rateLimitPerMinute: 120,
        });

        const shutdown = async () => {
          console.log(`\n  ${symbols.info} Shutting down Threat Cloud server...`);
          await server.stop();
          process.exit(0);
        };

        process.on('SIGINT', () => void shutdown());
        process.on('SIGTERM', () => void shutdown());

        try {
          await server.start();
        } catch (err) {
          sp.fail(`Failed to start server: ${err instanceof Error ? err.message : String(err)}`);
          process.exitCode = 1;
          return;
        }
        sp.succeed('Threat Cloud API server started');

        console.log(
          statusPanel('PANGUARD AI Threat Cloud', [
            { label: 'URL', value: c.underline(`http://${opts.host}:${opts.port}`) },
            { label: 'Health', value: c.sage(`http://${opts.host}:${opts.port}/health`) },
            { label: 'API', value: c.sage(`http://${opts.host}:${opts.port}/api/stats`) },
            { label: 'Database', value: c.dim(opts.db) },
          ])
        );

        console.log(c.dim('  Press Ctrl+C to stop'));
        console.log('');

        // Keep process alive
        await new Promise(() => {});
      }
    );

  cmd
    .command('stats')
    .description('Show threat intelligence statistics / 顯示威脅情報統計')
    .option('--db <path>', 'SQLite database path / 資料庫路徑', './threat-cloud.db')
    .action(
      async (opts: { db: string }) => {
        const tc = await loadThreatCloud();
        if (!tc) return;

        const sp = spinner('Loading threat intelligence data...');
        const db = new tc.ThreatCloudDB(opts.db);
        const stats = db.getStats();
        db.close();
        sp.succeed('Threat intelligence loaded');

        console.log(
          statusPanel('PANGUARD AI Threat Intelligence', [
            {
              label: 'Total Threats',
              value: String(stats.totalThreats),
              status: stats.totalThreats > 0 ? 'caution' : 'safe',
            },
            { label: 'Detection Rules', value: String(stats.totalRules) },
            {
              label: 'Last 24h',
              value: String(stats.last24hThreats),
              status:
                stats.last24hThreats > 10
                  ? 'critical'
                  : stats.last24hThreats > 0
                    ? 'caution'
                    : 'safe',
            },
          ])
        );

        if (stats.topAttackTypes.length > 0) {
          console.log(divider('Top Attack Types'));
          console.log('');
          const attackColumns = [
            { header: '#', key: 'rank', width: 4, align: 'right' as const },
            { header: 'Attack Type', key: 'type', width: 30 },
            { header: 'Count', key: 'count', width: 10, align: 'right' as const },
          ];
          const attackRows = stats.topAttackTypes.map((a: { type: string; count: number }, i: number) => ({
            rank: String(i + 1),
            type: a.type,
            count: String(a.count),
          }));
          console.log(table(attackColumns, attackRows));
          console.log('');
        }

        if (stats.topMitreTechniques.length > 0) {
          console.log(divider('Top MITRE ATT&CK Techniques'));
          console.log('');
          const mitreColumns = [
            { header: '#', key: 'rank', width: 4, align: 'right' as const },
            { header: 'Technique', key: 'technique', width: 30 },
            { header: 'Count', key: 'count', width: 10, align: 'right' as const },
          ];
          const mitreRows = stats.topMitreTechniques.map(
            (t: { technique: string; count: number }, i: number) => ({
              rank: String(i + 1),
              technique: t.technique,
              count: String(t.count),
            })
          );
          console.log(table(mitreColumns, mitreRows));
          console.log('');
        }

        if (stats.totalThreats === 0) {
          console.log(
            `  ${symbols.info} ${c.dim('No threat data yet. Start Threat Cloud to collect intelligence.')}`
          );
          console.log(`  ${symbols.info} ${c.dim('尚無威脅資料。啟動 Threat Cloud 以收集情報。')}`);
          console.log('');
        }
      }
    );

  return cmd;
}
