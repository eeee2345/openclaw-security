/**
 * Guard engine action
 * @module @panguard-ai/panguard/cli/interactive/actions/guard
 */

import { existsSync, readFileSync, mkdirSync, openSync, closeSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { c, spinner } from '@panguard-ai/core';
import { theme } from '../../theme.js';
import { renderCompactMenu, waitForCompactChoice } from '../../menu.js';
import type { MenuItem, Lang } from '../../menu.js';
import { breadcrumb, nextSteps, confirmDestructive } from '../../ux-helpers.js';
import { isGuardRunning } from '../render.js';

export async function actionGuard(lang: Lang): Promise<void> {
  breadcrumb(['Panguard', lang === 'zh-TW' ? '\u5B88\u8B77\u5F15\u64CE' : 'Guard Engine']);
  const title = lang === 'zh-TW' ? '\u5B88\u8B77\u5F15\u64CE' : 'Guard Engine';
  console.log(`  ${theme.brandBold(title)}`);

  const guardInfo = isGuardRunning();
  const guardRunning = guardInfo.running;
  const statusText = guardRunning
    ? c.safe(lang === 'zh-TW' ? '\u904B\u884C\u4E2D' : 'Running')
    : c.caution(lang === 'zh-TW' ? '\u672A\u904B\u884C' : 'Not running');
  console.log(`  ${c.dim(lang === 'zh-TW' ? '\u72C0\u614B' : 'Status')} ${statusText}`);
  console.log('');

  const items: MenuItem[] = [
    { key: '1', label: lang === 'zh-TW' ? '\u555F\u52D5\u5F15\u64CE  Start' : 'Start' },
    { key: '2', label: lang === 'zh-TW' ? '\u505C\u6B62\u5F15\u64CE  Stop' : 'Stop' },
    { key: '3', label: lang === 'zh-TW' ? '\u67E5\u770B\u72C0\u614B  Status' : 'Status' },
    { key: '4', label: lang === 'zh-TW' ? '\u67E5\u770B\u65E5\u8A8C  Logs' : 'Logs' },
  ];

  renderCompactMenu(lang === 'zh-TW' ? '\u5B88\u8B77\u5F15\u64CE' : 'Guard Engine', items);
  const choice = await waitForCompactChoice(items, lang);
  if (!choice) return;

  console.log('');
  const { runCLI } = await import('@panguard-ai/panguard-guard');

  switch (choice.key) {
    case '1': {
      if (guardRunning) {
        console.log(
          `  ${c.safe('\u2713')} ${lang === 'zh-TW' ? '\u5B88\u8B77\u5F15\u64CE\u5DF2\u5728\u904B\u884C\u4E2D' : 'Guard engine is already running'} ${c.dim(`(PID: ${guardInfo.pid})`)}`
        );
        nextSteps(
          lang === 'zh-TW'
            ? [
                { cmd: 'guard > \u67E5\u770B\u72C0\u614B', desc: '\u67E5\u770B\u8A73\u7D30\u72C0\u614B' },
                { cmd: 'guard > \u505C\u6B62\u5F15\u64CE', desc: '\u505C\u6B62\u9632\u8B77' },
              ]
            : [
                { cmd: 'guard > Status', desc: 'View detailed status' },
                { cmd: 'guard > Stop', desc: 'Stop protection' },
              ],
          lang
        );
        break;
      }

      console.log(`  ${c.sage('\u25C6')} Guard active${' '.repeat(30)}All Layers \u00B7 Free`);
      console.log('');
      if (lang === 'zh-TW') {
        console.log(`  ${c.safe('\u2713')} \u5DF2\u77E5\u653B\u64CA\u6A21\u5F0F\u81EA\u52D5\u5C01\u9396`);
        console.log(`  ${c.safe('\u2713')} Threat Cloud \u5A01\u8105\u60C5\u5831`);
        console.log(`  ${c.safe('\u2713')} AI \u5206\u6790`);
        console.log(`  ${c.safe('\u2713')} \u901A\u77E5\u7CFB\u7D71`);
        console.log(`  ${c.safe('\u2713')} \u65E5\u8A8C\u4FDD\u7559`);
      } else {
        console.log(`  ${c.safe('\u2713')} Auto-blocking for known attack patterns`);
        console.log(`  ${c.safe('\u2713')} Threat Cloud intelligence`);
        console.log(`  ${c.safe('\u2713')} AI analysis`);
        console.log(`  ${c.safe('\u2713')} Notifications`);
        console.log(`  ${c.safe('\u2713')} Log retention`);
      }
      console.log('');

      const { spawn: spawnProcess } = await import('node:child_process');
      const { fileURLToPath: toPath } = await import('node:url');

      const guardMainUrl = import.meta.resolve('@panguard-ai/panguard-guard');
      const guardCliScript = join(toPath(guardMainUrl), '..', 'cli', 'index.js');

      const guardDataDir = join(homedir(), '.panguard-guard');
      if (!existsSync(guardDataDir)) mkdirSync(guardDataDir, { recursive: true });
      const logPath = join(guardDataDir, 'guard.log');
      const logFd = openSync(logPath, 'a');

      const guardSp = spinner(
        lang === 'zh-TW' ? '\u6B63\u5728\u555F\u52D5\u5B88\u8B77\u5F15\u64CE...' : 'Starting guard engine...'
      );

      const child = spawnProcess(process.execPath, [guardCliScript, 'start'], {
        detached: true,
        stdio: ['ignore', logFd, logFd],
        env: { ...process.env },
      });
      child.unref();
      closeSync(logFd);

      const pidPath = join(guardDataDir, 'panguard-guard.pid');
      let started = false;
      const deadline = Date.now() + 5000;
      while (Date.now() < deadline) {
        if (existsSync(pidPath)) {
          try {
            const newPid = parseInt(readFileSync(pidPath, 'utf-8').trim(), 10);
            process.kill(newPid, 0);
            started = true;
            break;
          } catch {
            /* not yet */
          }
        }
        await new Promise((resolve) => setTimeout(resolve, 300));
      }

      if (started) {
        const newPid = parseInt(readFileSync(pidPath, 'utf-8').trim(), 10);
        guardSp.succeed(lang === 'zh-TW' ? '\u5B88\u8B77\u5F15\u64CE\u5DF2\u555F\u52D5' : 'Guard engine started');
        console.log('');
        console.log(
          `  ${c.safe('\u2713')} ${lang === 'zh-TW' ? '\u7CFB\u7D71\u5DF2\u53D7\u4FDD\u8B77' : 'System is now protected'} ${c.dim(`(PID: ${newPid})`)}`
        );
        console.log(
          `  ${c.dim(lang === 'zh-TW' ? '  \u65E5\u8A8C: ~/.panguard-guard/guard.log' : '  Logs: ~/.panguard-guard/guard.log')}`
        );
      } else {
        guardSp.fail(lang === 'zh-TW' ? '\u5B88\u8B77\u5F15\u64CE\u555F\u52D5\u5931\u6557' : 'Failed to start guard engine');
        console.log(
          `  ${c.dim(lang === 'zh-TW' ? '  \u67E5\u770B\u65E5\u8A8C: ~/.panguard-guard/guard.log' : '  Check logs: ~/.panguard-guard/guard.log')}`
        );
      }

      nextSteps(
        lang === 'zh-TW'
          ? [
              { cmd: 'scan', desc: '\u57F7\u884C\u5B89\u5168\u6383\u63CF' },
              { cmd: 'status', desc: '\u67E5\u770B\u7CFB\u7D71\u72C0\u614B' },
            ]
          : [
              { cmd: 'scan', desc: 'Run a security scan' },
              { cmd: 'status', desc: 'Check system status' },
            ],
        lang
      );
      break;
    }
    case '2': {
      const confirmed = await confirmDestructive(
        lang === 'zh-TW' ? '\u78BA\u5B9A\u8981\u505C\u6B62\u5373\u6642\u9632\u8B77\uFF1F' : 'Stop real-time protection?',
        lang
      );
      if (confirmed) {
        await runCLI(['stop']);
      } else {
        console.log(c.dim(lang === 'zh-TW' ? '  \u5DF2\u53D6\u6D88' : '  Cancelled'));
      }
      break;
    }
    case '3':
      await runCLI(['status']);
      break;
    case '4': {
      const logFilePath = join(homedir(), '.panguard-guard', 'guard.log');
      if (existsSync(logFilePath)) {
        const content = readFileSync(logFilePath, 'utf-8');
        const lines = content.trim().split('\n').slice(-30);
        console.log(
          c.dim(lang === 'zh-TW' ? '  \u6700\u8FD1 30 \u884C\u65E5\u8A8C:' : '  Last 30 log lines:')
        );
        console.log('');
        for (const line of lines) {
          console.log(`  ${c.dim(line)}`);
        }
      } else {
        console.log(c.dim(lang === 'zh-TW' ? '  \u5C1A\u7121\u65E5\u8A8C\u6A94\u6848' : '  No log file found'));
      }
      break;
    }
  }
}
