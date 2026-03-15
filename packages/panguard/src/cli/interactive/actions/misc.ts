/**
 * Miscellaneous actions: report, trap, notify, threat-cloud, hardening, status, config
 * @module @panguard-ai/panguard/cli/interactive/actions/misc
 */

import { c, spinner } from '@panguard-ai/core';
import { theme } from '../../theme.js';
import { renderCompactMenu, waitForCompactChoice, pressAnyKey } from '../../menu.js';
import type { MenuItem, Lang } from '../../menu.js';
import { breadcrumb, formatError } from '../../ux-helpers.js';

// ---------------------------------------------------------------------------
// [2] Compliance Report
// ---------------------------------------------------------------------------

export async function actionReport(lang: Lang): Promise<void> {
  breadcrumb(['Panguard', lang === 'zh-TW' ? '\u5408\u898F\u5831\u544A' : 'Compliance Report']);
  console.log('');
  if (lang === 'zh-TW') {
    console.log('  \u5408\u898F\u5831\u544A \u2014 \u5373\u5C07\u63A8\u51FA');
    console.log('');
    console.log('  ISO 27001\u3001SOC 2\u3001\u8CC7\u5B89\u7BA1\u7406\u6CD5\u5408\u898F\u5831\u544A\u529F\u80FD\u958B\u767C\u4E2D\u3002');
    console.log('  \u8FFD\u8E64\u9032\u5EA6: https://github.com/panguard-ai/panguard-ai');
  } else {
    console.log('  Compliance Report \u2014 Coming Soon');
    console.log('');
    console.log('  ISO 27001, SOC 2, and TW Cyber Security Act compliance');
    console.log('  reports are under active development.');
    console.log('  Follow progress: https://github.com/panguard-ai/panguard-ai');
  }
  console.log('');
}

// ---------------------------------------------------------------------------
// [4] Honeypot System
// ---------------------------------------------------------------------------

export async function actionTrap(lang: Lang): Promise<void> {
  breadcrumb(['Panguard', lang === 'zh-TW' ? '\u871C\u7F50\u7CFB\u7D71' : 'Honeypot System']);
  console.log('');
  if (lang === 'zh-TW') {
    console.log('  \u871C\u7F50\u7CFB\u7D71 \u2014 \u5373\u5C07\u63A8\u51FA');
    console.log('');
    console.log('  \u8A98\u990C\u670D\u52D9\uFF08SSH\u3001HTTP\u3001FTP\uFF09\u5075\u6E2C\u8207\u5206\u6790\u653B\u64CA\u8005\u529F\u80FD\u958B\u767C\u4E2D\u3002');
    console.log('  \u8FFD\u8E64\u9032\u5EA6: https://github.com/panguard-ai/panguard-ai');
  } else {
    console.log('  Honeypot System \u2014 Coming Soon');
    console.log('');
    console.log('  Decoy services (SSH, HTTP, FTP) to detect and profile');
    console.log('  attackers are under active development.');
    console.log('  Follow progress: https://github.com/panguard-ai/panguard-ai');
  }
  console.log('');
}

// ---------------------------------------------------------------------------
// [5] Notifications
// ---------------------------------------------------------------------------

export async function actionChat(lang: Lang): Promise<void> {
  breadcrumb(['Panguard', lang === 'zh-TW' ? '\u901A\u77E5\u7CFB\u7D71' : 'Notifications']);
  const title = lang === 'zh-TW' ? '\u901A\u77E5\u7CFB\u7D71' : 'Notifications';
  console.log(`  ${theme.brandBold(title)}`);
  console.log('');

  const items: MenuItem[] = [
    { key: '1', label: lang === 'zh-TW' ? '\u8A2D\u5B9A\u901A\u77E5\u7BA1\u9053' : 'Setup Channels' },
    { key: '2', label: lang === 'zh-TW' ? '\u67E5\u770B\u72C0\u614B' : 'Status' },
    { key: '3', label: lang === 'zh-TW' ? '\u6E2C\u8A66\u767C\u9001' : 'Test Send' },
  ];

  renderCompactMenu(lang === 'zh-TW' ? '\u901A\u77E5\u7CFB\u7D71' : 'Notifications', items);
  const choice = await waitForCompactChoice(items, lang);
  if (!choice) return;

  console.log('');
  const { runCLI: chatRunCLI } = await import('@panguard-ai/panguard-chat');

  switch (choice.key) {
    case '1':
      await chatRunCLI(['setup', '--lang', lang]);
      break;
    case '2':
      await chatRunCLI(['status']);
      break;
    case '3':
      await chatRunCLI(['config']);
      break;
  }
}

// ---------------------------------------------------------------------------
// [6] Threat Cloud
// ---------------------------------------------------------------------------

export async function actionThreat(lang: Lang): Promise<void> {
  breadcrumb(['Panguard', lang === 'zh-TW' ? '\u5A01\u8105\u60C5\u5831' : 'Threat Cloud']);
  const title = lang === 'zh-TW' ? '\u5A01\u8105\u60C5\u5831' : 'Threat Cloud';
  console.log(`  ${theme.brandBold(title)}`);
  console.log('');

  const port = 8080;
  const net = await import('node:net');
  const portAvailable = await new Promise<boolean>((resolve) => {
    const tester = net.createServer();
    tester.once('error', () => resolve(false));
    tester.once('listening', () => {
      tester.close(() => resolve(true));
    });
    tester.listen(port, '127.0.0.1');
  });

  if (!portAvailable) {
    console.log(
      formatError(
        lang === 'zh-TW' ? `\u9023\u63A5\u57E0 ${port} \u5DF2\u88AB\u4F54\u7528` : `Port ${port} is already in use`,
        `Port ${port}`,
        lang === 'zh-TW' ? `\u91CB\u653E\u9023\u63A5\u57E0 ${port} \u5F8C\u518D\u8A66` : `Free port ${port} and try again`
      )
    );
    return;
  }

  console.log(
    c.dim(
      lang === 'zh-TW'
        ? `  \u5373\u5C07\u555F\u52D5\u5A01\u8105\u60C5\u5831 REST API \u4F3A\u670D\u5668 (port ${port})`
        : `  Starting Threat Cloud REST API server (port ${port})...`
    )
  );
  console.log('');

  let ThreatCloudServer: any;
  try {
    const mod = '@panguard-ai/threat-cloud';
    const tc = await import(/* webpackIgnore: true */ mod);
    ThreatCloudServer = tc.ThreatCloudServer;
  } catch {
    console.log(c.red('  Threat Cloud server package is not available.'));
    console.log(c.dim('  Your Guard client connects to Threat Cloud automatically.'));
    return;
  }
  const sp = spinner(
    lang === 'zh-TW' ? '\u6B63\u5728\u555F\u52D5 Threat Cloud API...' : 'Starting Threat Cloud API server...'
  );

  const server = new ThreatCloudServer({
    port: 8080,
    host: '127.0.0.1',
    dbPath: './threat-cloud.db',
    apiKeyRequired: false,
    apiKeys: [],
    rateLimitPerMinute: 120,
  });

  try {
    await server.start();
    sp.succeed(lang === 'zh-TW' ? 'Threat Cloud API \u5DF2\u555F\u52D5' : 'Threat Cloud API started');

    console.log('');
    console.log(`  URL       ${c.underline('http://127.0.0.1:8080')}`);
    console.log(`  Health    ${c.sage('http://127.0.0.1:8080/health')}`);
    console.log(`  API       ${c.sage('http://127.0.0.1:8080/api/stats')}`);
    console.log('');
    console.log(
      c.dim(lang === 'zh-TW' ? '  \u6309\u4EFB\u610F\u9375\u505C\u6B62\u4F3A\u670D\u5668...' : '  Press any key to stop...')
    );

    await pressAnyKey(lang);
    await server.stop();
    console.log(
      `  ${c.safe(lang === 'zh-TW' ? 'Threat Cloud \u5DF2\u505C\u6B62' : 'Threat Cloud stopped')}`
    );
  } catch (err) {
    sp.fail(`${err instanceof Error ? err.message : String(err)}`);
  }
}

// ---------------------------------------------------------------------------
// Prompt commands: Hardening
// ---------------------------------------------------------------------------

export async function actionHardening(lang: Lang): Promise<void> {
  breadcrumb(['Panguard', lang === 'zh-TW' ? '\u5B89\u5168\u52A0\u56FA' : 'Security Hardening']);
  const title = lang === 'zh-TW' ? '\u5B89\u5168\u52A0\u56FA' : 'Security Hardening';
  console.log(`  ${theme.brandBold(title)}`);
  console.log('');

  const items: MenuItem[] = [
    { key: '1', label: lang === 'zh-TW' ? '\u57F7\u884C\u52A0\u56FA\u6383\u63CF' : 'Run hardening audit' },
    { key: '2', label: lang === 'zh-TW' ? '\u81EA\u52D5\u4FEE\u5FA9' : 'Auto-fix issues' },
    { key: '3', label: lang === 'zh-TW' ? '\u67E5\u770B\u5831\u544A' : 'View report' },
  ];

  renderCompactMenu(lang === 'zh-TW' ? '\u5B89\u5168\u52A0\u56FA' : 'Hardening', items);
  const choice = await waitForCompactChoice(items, lang);
  if (!choice) return;

  console.log('');
  const { hardeningCommand } = await import('../../commands/hardening.js');
  const cmd = hardeningCommand();

  switch (choice.key) {
    case '1':
      await cmd.parseAsync(['hardening', 'audit'], { from: 'user' });
      break;
    case '2':
      await cmd.parseAsync(['hardening', 'fix'], { from: 'user' });
      break;
    case '3':
      await cmd.parseAsync(['hardening', 'report'], { from: 'user' });
      break;
  }
}

// ---------------------------------------------------------------------------
// Prompt commands: Status
// ---------------------------------------------------------------------------

export async function actionStatus(lang: Lang): Promise<void> {
  breadcrumb(['Panguard', lang === 'zh-TW' ? '\u7CFB\u7D71\u72C0\u614B' : 'Status']);
  const { statusCommand } = await import('../../commands/status.js');
  const cmd = statusCommand();
  await cmd.parseAsync(['status'], { from: 'user' });
}

// ---------------------------------------------------------------------------
// Prompt commands: Config
// ---------------------------------------------------------------------------

export async function actionConfig(lang: Lang): Promise<void> {
  breadcrumb(['Panguard', lang === 'zh-TW' ? '\u8A2D\u5B9A\u7BA1\u7406' : 'Settings']);
  const { configCommand } = await import('../../commands/config.js');
  const cmd = configCommand();
  await cmd.parseAsync(['config'], { from: 'user' });
}
