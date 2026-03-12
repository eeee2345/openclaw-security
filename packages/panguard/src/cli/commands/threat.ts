/**
 * panguard threat - Threat intelligence API management
 * panguard threat - 威脅情報 API 管理
 *
 * Requires @panguard-ai/threat-cloud (server-side, not published to npm).
 * This command is for Panguard operators only.
 */

import { Command } from 'commander';
import { c, spinner, statusPanel, divider, table, symbols } from '@panguard-ai/core';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function loadThreatCloud(): Promise<any> {
  try {
    const mod = '@panguard-ai/threat-cloud';
    return await import(/* webpackIgnore: true */ mod);
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
    .action(async (opts: { port: string; host: string; db: string }) => {
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
    });

  cmd
    .command('stats')
    .description('Show threat intelligence statistics / 顯示威脅情報統計')
    .option('--db <path>', 'SQLite database path / 資料庫路徑', './threat-cloud.db')
    .action(async (opts: { db: string }) => {
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
        const attackRows = stats.topAttackTypes.map(
          (a: { type: string; count: number }, i: number) => ({
            rank: String(i + 1),
            type: a.type,
            count: String(a.count),
          })
        );
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
    });

  cmd
    .command('seed')
    .description('Seed rules from bundled config into Threat Cloud DB / 將內建規則種入威脅雲資料庫')
    .option('--db <path>', 'SQLite database path / 資料庫路徑', './threat-cloud.db')
    .action(async (opts: { db: string }) => {
      const tc = await loadThreatCloud();
      if (!tc) return;

      const sp = spinner('Opening Threat Cloud database...');
      const db = new tc.ThreatCloudDB(opts.db);

      const existingStats = db.getStats();
      sp.succeed(`Database opened (${existingStats.totalRules} existing rules)`);

      const seedSp = spinner('Seeding rules from bundled config...');

      const { readdirSync, readFileSync: readFs, statSync } = await import('node:fs');
      const { join, basename, relative, dirname } = await import('node:path');
      const { fileURLToPath } = await import('node:url');

      const now = new Date().toISOString();
      let seeded = 0;

      // Resolve config directory
      const thisDir = dirname(fileURLToPath(import.meta.url));
      const configDirs = [
        join(process.cwd(), 'config'),
        join(thisDir, '..', '..', '..', '..', '..', 'config'),
      ];
      const configDir = configDirs.find((d) => {
        try { return statSync(d).isDirectory(); } catch { return false; }
      });

      if (!configDir) {
        seedSp.fail('No config/ directory found');
        db.close();
        return;
      }

      /** Recursively collect files matching extensions */
      function collectFiles(dir: string, extensions: string[]): string[] {
        const results: string[] = [];
        try {
          for (const entry of readdirSync(dir, { withFileTypes: true })) {
            const fullPath = join(dir, entry.name);
            if (entry.isDirectory()) {
              results.push(...collectFiles(fullPath, extensions));
            } else if (extensions.some((ext) => entry.name.endsWith(ext))) {
              results.push(fullPath);
            }
          }
        } catch { /* skip */ }
        return results;
      }

      // Sigma rules
      const sigmaDir = join(configDir, 'sigma-rules');
      try {
        const sigmaFiles = collectFiles(sigmaDir, ['.yml', '.yaml']);
        for (const file of sigmaFiles) {
          const content = readFs(file, 'utf-8');
          const ruleId = `sigma:${relative(sigmaDir, file).replace(/\//g, ':')}`;
          db.upsertRule({ ruleId, ruleContent: content, publishedAt: now, source: 'sigma' });
          seeded++;
        }
        console.log(`  ${symbols.pass} Sigma: ${sigmaFiles.length} rules`);
      } catch { /* skip */ }

      // YARA rules
      const yaraDir = join(configDir, 'yara-rules');
      try {
        const yaraFiles = collectFiles(yaraDir, ['.yar', '.yara']);
        let yaraCount = 0;
        for (const file of yaraFiles) {
          const content = readFs(file, 'utf-8');
          const ruleMatches = content.match(/rule\s+\w+/g);
          if (ruleMatches && ruleMatches.length > 1) {
            for (const match of ruleMatches) {
              const ruleName = match.replace('rule ', '');
              const ruleId = `yara:${basename(file, '.yar').replace('.yara', '')}:${ruleName}`;
              db.upsertRule({ ruleId, ruleContent: content, publishedAt: now, source: 'yara' });
              yaraCount++;
            }
          } else {
            const ruleId = `yara:${relative(yaraDir, file).replace(/\//g, ':')}`;
            db.upsertRule({ ruleId, ruleContent: content, publishedAt: now, source: 'yara' });
            yaraCount++;
          }
        }
        seeded += yaraCount;
        console.log(`  ${symbols.pass} YARA: ${yaraCount} rules (from ${yaraFiles.length} files)`);
      } catch { /* skip */ }

      // ATR rules
      const atrDirs = [
        join(process.cwd(), 'node_modules', 'agent-threat-rules', 'rules'),
        join(thisDir, '..', '..', '..', '..', '..', 'packages', 'atr', 'rules'),
      ];
      const atrDir = atrDirs.find((d) => {
        try { return statSync(d).isDirectory(); } catch { return false; }
      });
      if (atrDir) {
        try {
          const atrFiles = collectFiles(atrDir, ['.yaml', '.yml']);
          for (const file of atrFiles) {
            const content = readFs(file, 'utf-8');
            const ruleId = `atr:${relative(atrDir, file).replace(/\//g, ':')}`;
            db.upsertRule({ ruleId, ruleContent: content, publishedAt: now, source: 'atr' });
            seeded++;
          }
          console.log(`  ${symbols.pass} ATR: ${atrFiles.length} rules`);
        } catch { /* skip */ }
      }

      seedSp.succeed(`Seeded ${seeded} rules into Threat Cloud DB`);

      const finalStats = db.getStats();
      console.log(
        statusPanel('Threat Cloud Database', [
          { label: 'Total Rules', value: String(finalStats.totalRules) },
          { label: 'Total Threats', value: String(finalStats.totalThreats) },
          { label: 'Database', value: c.dim(opts.db) },
        ])
      );

      db.close();
    });

  cmd
    .command('backup')
    .description('Backup Threat Cloud and auth databases / 備份威脅雲及認證資料庫')
    .option('--db <path>', 'Auth database path / 認證資料庫路徑', '/data/auth.db')
    .option('--threat-db <path>', 'Threat Cloud database path / 威脅雲資料庫路徑', '/data/threat-cloud.db')
    .option('--backup-dir <path>', 'Backup directory / 備份目錄', '/data/backups')
    .option('--max-backups <number>', 'Maximum backups to keep / 最多保留備份數', '7')
    .option('--list', 'List existing backups / 列出現有備份', false)
    .action(
      async (opts: {
        db: string;
        threatDb: string;
        backupDir: string;
        maxBackups: string;
        list: boolean;
      }) => {
        const tc = await loadThreatCloud();
        if (!tc) return;

        const maxBackups = parseInt(opts.maxBackups, 10);

        if (opts.list) {
          // List mode: show existing backups
          const mgr = new tc.BackupManager(opts.threatDb, opts.backupDir, maxBackups);
          const backups = mgr.listBackups();
          if (backups.length === 0) {
            console.log(`\n  ${symbols.info} ${c.dim('No backups found.')}`);
            console.log('');
            return;
          }
          console.log(divider('Existing Backups'));
          console.log('');
          const backupColumns = [
            { header: '#', key: 'rank', width: 4, align: 'right' as const },
            { header: 'File', key: 'file', width: 50 },
          ];
          const backupRows = backups.map((f: string, i: number) => ({
            rank: String(i + 1),
            file: f,
          }));
          console.log(table(backupColumns, backupRows));
          console.log('');
          return;
        }

        // Backup mode
        const results: Array<{
          label: string;
          value: string;
          status?: 'safe' | 'caution' | 'alert' | 'critical';
        }> = [];

        // Backup threat-cloud.db
        try {
          const threatMgr = new tc.BackupManager(opts.threatDb, opts.backupDir, maxBackups);
          const sp1 = spinner('Backing up threat-cloud.db...');
          const r1 = threatMgr.backup();
          sp1.succeed(
            `threat-cloud.db backed up (${tc.BackupManager.formatSize(r1.sizeBytes)})`
          );
          results.push({
            label: 'Threat Cloud',
            value: c.sage(r1.path),
            status: 'safe',
          });
        } catch (err) {
          console.error(
            `  ${symbols.fail} threat-cloud.db backup failed: ${err instanceof Error ? err.message : String(err)}`
          );
          results.push({
            label: 'Threat Cloud',
            value: c.red('FAILED'),
            status: 'critical',
          });
        }

        // Backup auth.db
        try {
          const authMgr = new tc.BackupManager(opts.db, opts.backupDir, maxBackups);
          const sp2 = spinner('Backing up auth.db...');
          const r2 = authMgr.backup();
          sp2.succeed(`auth.db backed up (${tc.BackupManager.formatSize(r2.sizeBytes)})`);
          results.push({
            label: 'Auth DB',
            value: c.sage(r2.path),
            status: 'safe',
          });
        } catch (err) {
          console.error(
            `  ${symbols.fail} auth.db backup failed: ${err instanceof Error ? err.message : String(err)}`
          );
          results.push({
            label: 'Auth DB',
            value: c.red('FAILED'),
            status: 'critical',
          });
        }

        console.log(
          statusPanel('Database Backup', [
            ...results,
            { label: 'Backup Dir', value: c.dim(opts.backupDir) },
            { label: 'Retention', value: `${maxBackups} backups` },
          ])
        );
      }
    );

  return cmd;
}
