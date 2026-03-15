/**
 * Security scan action
 * @module @panguard-ai/panguard/cli/interactive/actions/scan
 */

import { c, spinner, colorSeverity, formatDuration, box } from '@panguard-ai/core';
import { theme } from '../../theme.js';
import { renderCompactMenu, waitForCompactChoice } from '../../menu.js';
import type { MenuItem, Lang } from '../../menu.js';
import { breadcrumb, nextSteps } from '../../ux-helpers.js';
import { getLicense } from '../../auth-guard.js';
import { isGuardRunning } from '../render.js';

export async function actionScan(
  lang: Lang,
  guardAction: () => Promise<void>,
  auditAction: () => Promise<void>
): Promise<void> {
  breadcrumb(['Panguard', lang === 'zh-TW' ? '\u5B89\u5168\u6383\u63CF' : 'Security Scan']);
  const scanTitle = lang === 'zh-TW' ? '\u5B89\u5168\u6383\u63CF' : 'Security Scan';
  console.log(`  ${theme.brandBold(scanTitle)}`);
  console.log('');

  const depthItems: MenuItem[] = [
    { key: '1', label: lang === 'zh-TW' ? '\u5FEB\u901F\u6383\u63CF (~30 \u79D2)' : 'Quick Scan (~30 seconds)' },
    { key: '2', label: lang === 'zh-TW' ? '\u5B8C\u6574\u6383\u63CF' : 'Full Scan' },
  ];

  renderCompactMenu(lang === 'zh-TW' ? '\u6383\u63CF\u6A21\u5F0F' : 'Scan Mode', depthItems);
  const choice = await waitForCompactChoice(depthItems, lang);
  if (!choice) return;

  const depth = choice.key === '1' ? 'quick' : 'full';
  console.log('');

  const { runScan } = await import('@panguard-ai/panguard-scan');
  const sp = spinner(
    lang === 'zh-TW' ? '\u6B63\u5728\u6383\u63CF\u7CFB\u7D71\u5B89\u5168...' : 'Scanning system...'
  );
  const result = await runScan({ depth, lang, verbose: false });
  sp.succeed(
    lang === 'zh-TW'
      ? `\u6383\u63CF\u5B8C\u6210 ${c.dim(`(${formatDuration(result.scanDuration)})`)}`
      : `Scan complete ${c.dim(`(${formatDuration(result.scanDuration)})`)}`
  );

  const safetyScore = Math.max(0, 100 - result.riskScore);
  const grade =
    safetyScore >= 90 ? 'A'
      : safetyScore >= 75 ? 'B'
        : safetyScore >= 60 ? 'C'
          : safetyScore >= 40 ? 'D' : 'F';

  console.log('');
  const scoreLabel = lang === 'zh-TW' ? '\u6383\u63CF\u5B8C\u6210' : 'Scan Complete';
  console.log(
    `  ${theme.title(scoreLabel)}${' '.repeat(30)}Score: ${c.bold(`${safetyScore}/100`)} (${grade})`
  );
  console.log('');

  const { tier: _tier } = getLicense();
  let fixableCount = 0;

  if (result.findings.length > 0) {
    for (const f of result.findings) {
      const sev = colorSeverity(f.severity).padEnd(10);
      console.log(`  ${sev} ${f.title}`);
      if (f.description) {
        console.log(c.dim(`          ${f.description}`));
      }
      if (f.manualFix && f.manualFix.length > 0) {
        const fixLabel = lang === 'zh-TW' ? '\u4FEE\u5FA9:' : 'Fix:';
        console.log(c.dim(`          ${fixLabel}`));
        for (const cmd of f.manualFix) {
          console.log(c.dim(`          $ ${cmd}`));
        }
        fixableCount++;
      } else if (f.remediation) {
        const recLabel = lang === 'zh-TW' ? '\u5EFA\u8B70:' : 'Recommendation:';
        console.log(c.dim(`          ${recLabel} ${f.remediation}`));
      }
    }
    console.log('');

    const issuesText = lang === 'zh-TW'
      ? `${result.findings.length} \u500B\u554F\u984C`
      : `${result.findings.length} issue(s) found`;
    console.log(c.dim(`  ${issuesText}`));

    if (fixableCount > 0) {
      const upgradeLines = lang === 'zh-TW'
        ? [`\u53EF\u81EA\u52D5\u4FEE\u5FA9:`, `$ panguard scan --fix`]
        : [`Auto-fix available:`, `$ panguard scan --fix`];
      console.log('');
      console.log(box(upgradeLines.join('\n'), { borderColor: c.sage }));
    }
  } else {
    const noIssues = lang === 'zh-TW' ? '\u672A\u767C\u73FE\u5B89\u5168\u554F\u984C' : 'No security issues found';
    console.log(`  ${c.safe(noIssues)}`);
  }

  const guardRunning = isGuardRunning().running;
  if (!guardRunning) {
    console.log('');
    const agentMsg = lang === 'zh-TW'
      ? `${c.sage('\u25C6')} \u5373\u6642\u9632\u8B77\u5C1A\u672A\u555F\u52D5\u3002\u8981\u73FE\u5728\u555F\u7528\u55CE\uFF1F`
      : `${c.sage('\u25C6')} Real-time protection is not active. Enable now?`;
    console.log(`  ${agentMsg}`);

    const guardItems: MenuItem[] = [
      { key: '1', label: lang === 'zh-TW' ? '\u662F\uFF0C\u555F\u52D5 Guard \u9632\u8B77' : 'Yes, start Guard protection' },
      { key: '2', label: lang === 'zh-TW' ? '\u5BE9\u8A08\u5DF2\u5B89\u88DD\u6280\u80FD\u7684\u5B89\u5168\u5A01\u8105' : 'Audit installed skills for threats' },
      { key: '3', label: lang === 'zh-TW' ? '\u4E0D\u7528\uFF0C\u56DE\u4E3B\u9078\u55AE' : 'No, return to main menu' },
    ];
    renderCompactMenu('', guardItems);
    const guardChoice = await waitForCompactChoice(guardItems, lang);
    if (guardChoice?.key === '1') {
      await guardAction();
      return;
    }
    if (guardChoice?.key === '2') {
      await auditAction();
      return;
    }
  } else {
    nextSteps(
      lang === 'zh-TW'
        ? [
            { cmd: '[8] \u6280\u80FD\u5BE9\u8A08', desc: '\u5BE9\u8A08\u5DF2\u5B89\u88DD\u6280\u80FD\u7684\u5B89\u5168\u5A01\u8105' },
            { cmd: 'scan --full', desc: '\u57F7\u884C\u5B8C\u6574\u6383\u63CF' },
            { cmd: 'guard start', desc: '\u555F\u52D5\u5373\u6642\u9632\u8B77' },
          ]
        : [
            { cmd: '[8] Skill Auditor', desc: 'Audit installed skills for threats' },
            { cmd: 'scan --full', desc: 'Run a comprehensive scan' },
            { cmd: 'guard start', desc: 'Enable real-time protection' },
          ],
      lang
    );
  }
}
