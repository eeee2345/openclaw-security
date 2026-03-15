/**
 * Auto demo action
 * @module @panguard-ai/panguard/cli/interactive/actions/demo
 */

import { c, spinner, formatDuration } from '@panguard-ai/core';
import { theme } from '../../theme.js';
import { breadcrumb, nextSteps } from '../../ux-helpers.js';
import type { Lang } from '../../menu.js';

export async function actionDemo(lang: Lang): Promise<void> {
  breadcrumb(['Panguard', lang === 'zh-TW' ? '\u529F\u80FD\u5C55\u793A' : 'Feature Demo']);
  const { runScan } = await import('@panguard-ai/panguard-scan');
  const title = lang === 'zh-TW' ? '\u529F\u80FD\u5C55\u793A' : 'Feature Demo';
  console.log(`  ${theme.brandBold(title)}`);
  console.log(
    c.dim(
      lang === 'zh-TW'
        ? '  \u6B63\u5728\u57F7\u884C\u6240\u6709\u5B89\u5168\u6A21\u7D44...'
        : '  Running through all security modules...'
    )
  );
  console.log('');

  type DemoResult = 'ok' | 'warn' | 'fail';
  const results: { name: string; status: DemoResult }[] = [];

  // 1. Security Scan
  console.log(c.dim(lang === 'zh-TW' ? '  1. \u5B89\u5168\u6383\u63CF' : '  1. Security Scan'));
  console.log('');

  const scanSp = spinner(
    lang === 'zh-TW' ? '\u6B63\u5728\u57F7\u884C\u5FEB\u901F\u6383\u63CF...' : 'Running quick scan...'
  );
  try {
    const result = await runScan({ depth: 'quick', lang, verbose: false });
    scanSp.succeed(
      `${lang === 'zh-TW' ? '\u6383\u63CF\u5B8C\u6210' : 'Scan complete'} ${c.dim(`(${formatDuration(result.scanDuration)})`)}`
    );
    const safetyScore = Math.max(0, 100 - result.riskScore);
    const grade =
      safetyScore >= 90 ? 'A' : safetyScore >= 75 ? 'B' : safetyScore >= 60 ? 'C' : safetyScore >= 40 ? 'D' : 'F';
    console.log(`  Score: ${c.bold(`${safetyScore}/100`)} (${grade}) | Findings: ${result.findings.length}`);
    results.push({ name: lang === 'zh-TW' ? '\u5B89\u5168\u6383\u63CF' : 'Scan', status: 'ok' });
  } catch (err) {
    scanSp.fail(`${err instanceof Error ? err.message : err}`);
    results.push({ name: lang === 'zh-TW' ? '\u5B89\u5168\u6383\u63CF' : 'Scan', status: 'fail' });
  }
  console.log('');

  // 2. Compliance Report (Coming Soon)
  console.log(
    c.dim(lang === 'zh-TW' ? '  2. \u5408\u898F\u5831\u544A \u2014 \u5373\u5C07\u63A8\u51FA' : '  2. Compliance Report \u2014 Coming Soon')
  );
  results.push({ name: lang === 'zh-TW' ? '\u5408\u898F\u5831\u544A' : 'Report', status: 'warn' });
  console.log('');

  // 3. Guard Engine
  console.log(c.dim(lang === 'zh-TW' ? '  3. \u5B88\u8B77\u5F15\u64CE' : '  3. Guard Engine'));
  console.log('');

  try {
    const { runCLI: guardCLI } = await import('@panguard-ai/panguard-guard');
    await guardCLI(['status']);
    results.push({ name: lang === 'zh-TW' ? '\u5B88\u8B77\u5F15\u64CE' : 'Guard', status: 'ok' });
  } catch {
    console.log(
      c.dim(lang === 'zh-TW' ? '  \u5B88\u8B77\u5F15\u64CE: \u672A\u904B\u884C (\u5C55\u793A\u6B63\u5E38)' : '  Guard engine: not running (normal for demo)')
    );
    results.push({ name: lang === 'zh-TW' ? '\u5B88\u8B77\u5F15\u64CE' : 'Guard', status: 'warn' });
  }
  console.log('');

  // 4. Honeypot (Coming Soon)
  console.log(
    c.dim(lang === 'zh-TW' ? '  4. \u871C\u7F50\u7CFB\u7D71 \u2014 \u5373\u5C07\u63A8\u51FA' : '  4. Honeypot System \u2014 Coming Soon')
  );
  results.push({ name: lang === 'zh-TW' ? '\u871C\u7F50\u7CFB\u7D71' : 'Trap', status: 'warn' });
  console.log('');

  // 5. Notifications
  console.log(c.dim(lang === 'zh-TW' ? '  5. \u901A\u77E5\u7CFB\u7D71' : '  5. Notification System'));
  console.log('');

  try {
    const { runCLI: chatCLI } = await import('@panguard-ai/panguard-chat');
    await chatCLI(['status']);
    results.push({ name: lang === 'zh-TW' ? '\u901A\u77E5\u7CFB\u7D71' : 'Notify', status: 'ok' });
  } catch {
    console.log(
      c.dim(lang === 'zh-TW' ? '  \u901A\u77E5\u7CFB\u7D71: \u5C1A\u672A\u914D\u7F6E' : '  Notification system: not configured')
    );
    results.push({ name: lang === 'zh-TW' ? '\u901A\u77E5\u7CFB\u7D71' : 'Notify', status: 'warn' });
  }
  console.log('');

  // Summary
  console.log(`  ${theme.brandBold(lang === 'zh-TW' ? '\u5C55\u793A\u5B8C\u6210' : 'Demo Complete')}`);
  console.log('');
  for (const r of results) {
    const icon =
      r.status === 'ok' ? c.safe('\u2713') : r.status === 'warn' ? c.caution('~') : c.critical('\u2717');
    console.log(`  ${icon} ${r.name}`);
  }

  nextSteps(
    lang === 'zh-TW'
      ? [
          { cmd: 'init', desc: '\u521D\u59CB\u8A2D\u5B9A\u60A8\u7684\u74B0\u5883' },
          { cmd: 'scan', desc: '\u57F7\u884C\u5B89\u5168\u6383\u63CF' },
          { cmd: 'guard start', desc: '\u555F\u52D5\u5373\u6642\u9632\u8B77' },
        ]
      : [
          { cmd: 'init', desc: 'Set up your environment' },
          { cmd: 'scan', desc: 'Run a security scan' },
          { cmd: 'guard start', desc: 'Enable real-time protection' },
        ],
    lang
  );
}
