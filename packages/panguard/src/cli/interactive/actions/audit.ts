/**
 * Skill auditor action
 * @module @panguard-ai/panguard/cli/interactive/actions/audit
 */

import { existsSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { homedir } from 'node:os';
import { c, spinner, box } from '@panguard-ai/core';
import { theme } from '../../theme.js';
import { renderCompactMenu, waitForCompactChoice } from '../../menu.js';
import type { MenuItem, Lang } from '../../menu.js';
import { breadcrumb, nextSteps, formatError } from '../../ux-helpers.js';

export async function actionAudit(lang: Lang): Promise<void> {
  breadcrumb(['Panguard', lang === 'zh-TW' ? '\u6280\u80FD\u5BE9\u8A08' : 'Skill Auditor']);
  const title = lang === 'zh-TW' ? '\u6280\u80FD\u5BE9\u8A08' : 'Skill Auditor';
  console.log(`  ${theme.brandBold(title)}`);
  console.log('');
  console.log(
    c.dim(
      lang === 'zh-TW'
        ? '  \u6383\u63CF AI \u4EE3\u7406\u6280\u80FD\u76EE\u9304\uFF08\u5305\u542B SKILL.md\uFF09\u4EE5\u5075\u6E2C\u5B89\u5168\u554F\u984C\u3002'
        : '  Scan an AI agent skill directory (containing SKILL.md) for security issues.'
    )
  );
  console.log('');

  const pathItems: MenuItem[] = [
    { key: '1', label: lang === 'zh-TW' ? '\u5BE9\u8A08\u7576\u524D\u76EE\u9304 (.)' : 'Audit current directory (.)' },
    { key: '2', label: lang === 'zh-TW' ? '\u8F38\u5165\u81EA\u5B9A\u8DEF\u5F91' : 'Enter custom path' },
  ];

  renderCompactMenu(lang === 'zh-TW' ? '\u9078\u64C7\u76EE\u6A19' : 'Select target', pathItems);
  const choice = await waitForCompactChoice(pathItems, lang);
  if (!choice) return;

  let targetPath = process.cwd();

  if (choice.key === '2') {
    const readline = await import('node:readline');
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    targetPath = await new Promise<string>((r) => {
      const prompt = lang === 'zh-TW' ? '  \u8DEF\u5F91: ' : '  Path: ';
      rl.question(prompt, (answer) => {
        rl.close();
        r(answer.trim() || process.cwd());
      });
    });
  }

  const resolvedPath = resolve(targetPath);

  console.log('');
  const sp = spinner(
    lang === 'zh-TW' ? `\u6B63\u5728\u5BE9\u8A08 ${resolvedPath}...` : `Auditing ${resolvedPath}...`
  );

  try {
    const { auditSkill } = await import('@panguard-ai/panguard-skill-auditor');
    const report = await auditSkill(resolvedPath);
    sp.succeed(lang === 'zh-TW' ? '\u5BE9\u8A08\u5B8C\u6210' : 'Audit complete');

    const levelColors: Record<string, (s: string) => string> = {
      LOW: c.safe,
      MEDIUM: c.caution,
      HIGH: c.critical,
      CRITICAL: (s: string) => c.bold(c.critical(s)),
    };
    const colorFn = levelColors[report.riskLevel] ?? c.dim;

    console.log('');
    console.log(
      box(
        [
          `${c.bold(lang === 'zh-TW' ? '\u6280\u80FD\u5BE9\u8A08\u5831\u544A' : 'Skill Audit Report')}`,
          '',
          `${lang === 'zh-TW' ? '\u6280\u80FD' : 'Skill'}:      ${report.manifest?.name ?? 'Unknown'}${report.manifest?.metadata?.version ? ` v${report.manifest.metadata.version}` : ''}`,
          `${lang === 'zh-TW' ? '\u4F5C\u8005' : 'Author'}:     ${report.manifest?.metadata?.author ?? 'Unknown'}`,
          `${lang === 'zh-TW' ? '\u98A8\u96AA\u5206\u6578' : 'Risk Score'}: ${colorFn(`${report.riskScore}/100 (${report.riskLevel})`)}`,
          `${lang === 'zh-TW' ? '\u6642\u9593' : 'Duration'}:   ${report.durationMs}ms`,
        ].join('\n'),
        { borderColor: c.sage }
      )
    );

    console.log('');

    for (const check of report.checks) {
      const icon =
        check.status === 'pass' ? c.safe('\u2713')
          : check.status === 'fail' ? c.critical('\u2717')
            : check.status === 'warn' ? c.caution('~') : c.dim('i');
      const statusLabel =
        check.status === 'pass' ? 'PASS'
          : check.status === 'fail' ? 'FAIL'
            : check.status === 'warn' ? 'WARN' : 'INFO';
      console.log(`  ${icon} [${statusLabel}] ${check.label}`);
    }

    console.log('');

    if (report.findings.length > 0) {
      console.log(
        c.bold(
          lang === 'zh-TW'
            ? `  \u767C\u73FE ${report.findings.length} \u500B\u554F\u984C:`
            : `  ${report.findings.length} finding(s):`
        )
      );
      console.log('');
      for (const finding of report.findings) {
        const sevColor =
          finding.severity === 'critical' ? c.critical : finding.severity === 'high' ? c.caution : c.dim;
        console.log(`  ${sevColor(`[${finding.severity.toUpperCase()}]`)} ${finding.title}`);
        console.log(`    ${c.dim(finding.description)}`);
        if (finding.location) console.log(`    ${c.dim(`at ${finding.location}`)}`);
        console.log('');
      }
    }

    nextSteps(
      lang === 'zh-TW'
        ? [
            { cmd: 'scan', desc: '\u57F7\u884C\u7CFB\u7D71\u5B89\u5168\u6383\u63CF' },
            { cmd: 'guard start', desc: '\u555F\u52D5 24/7 \u5B88\u8B77\u9632\u8B77' },
          ]
        : [
            { cmd: 'scan', desc: 'Run a system security scan' },
            { cmd: 'guard start', desc: 'Start 24/7 guard protection' },
          ],
      lang
    );
  } catch (err) {
    const errMsg = err instanceof Error ? err.message : String(err);
    const isNoSkill =
      errMsg.toLowerCase().includes('skill.md') ||
      errMsg.toLowerCase().includes('not found') ||
      errMsg.toLowerCase().includes('enoent');

    if (isNoSkill) {
      sp.warn(
        lang === 'zh-TW'
          ? '\u6B64\u76EE\u9304\u672A\u627E\u5230 AI \u6280\u80FD (SKILL.md)'
          : 'No AI skills (SKILL.md) found in this directory'
      );
      console.log('');
      console.log(
        c.dim(
          lang === 'zh-TW'
            ? '  Skill Auditor \u6383\u63CF\u5305\u542B SKILL.md \u7684 AI \u6280\u80FD\u76EE\u9304\u3002'
            : '  Skill Auditor scans AI skill directories containing a SKILL.md file.'
        )
      );
      console.log('');
      console.log(
        c.dim(lang === 'zh-TW' ? '  \u5E38\u898B\u6280\u80FD\u4F4D\u7F6E\uFF1A' : '  Common skill locations:')
      );
      console.log(c.dim('    ~/.claude/skills/'));
      console.log(c.dim('    ./.claude/skills/'));
      console.log(c.dim('    ./.mcp/'));
      console.log(c.dim('    ./skills/'));
      console.log('');

      const skillDirs = [
        join(homedir(), '.claude', 'skills'),
        join(process.cwd(), '.claude', 'skills'),
        join(process.cwd(), '.mcp'),
        join(process.cwd(), 'skills'),
      ];
      const foundDirs: string[] = [];
      for (const dir of skillDirs) {
        if (existsSync(dir)) {
          try {
            const entries = readdirSync(dir, { withFileTypes: true });
            for (const entry of entries) {
              if (entry.isDirectory()) {
                const skillMdPath = join(dir, entry.name, 'SKILL.md');
                if (existsSync(skillMdPath)) {
                  foundDirs.push(join(dir, entry.name));
                }
              }
            }
            if (existsSync(join(dir, 'SKILL.md'))) {
              foundDirs.push(dir);
            }
          } catch {
            /* skip inaccessible dirs */
          }
        }
      }

      if (foundDirs.length > 0) {
        console.log(
          c.sage(
            lang === 'zh-TW'
              ? `  \u5728\u7CFB\u7D71\u4E2D\u627E\u5230 ${foundDirs.length} \u500B\u6280\u80FD\uFF1A`
              : `  Found ${foundDirs.length} skill(s) on your system:`
          )
        );
        for (const dir of foundDirs) {
          console.log(c.dim(`    ${dir}`));
        }
        console.log('');
        console.log(
          c.dim(
            lang === 'zh-TW'
              ? `  \u57F7\u884C\uFF1Apanguard audit skill <path> \u4F86\u5BE9\u8A08\u7279\u5B9A\u6280\u80FD`
              : `  Run: panguard audit skill <path> to audit a specific skill`
          )
        );
      } else {
        console.log(
          c.dim(
            lang === 'zh-TW'
              ? '  \u7CFB\u7D71\u4E2D\u672A\u627E\u5230\u5DF2\u5B89\u88DD\u7684 AI \u6280\u80FD\u3002'
              : '  No installed AI skills found on your system.'
          )
        );
        console.log(
          c.dim(
            lang === 'zh-TW'
              ? '  \u5728\u5305\u542B AI \u6280\u80FD\u7684\u5C08\u6848\u76EE\u9304\u4E2D\u57F7\u884C\u6B64\u6307\u4EE4\u3002'
              : '  Run this command inside a project directory that contains AI skills.'
          )
        );
      }
    } else {
      sp.fail(lang === 'zh-TW' ? '\u5BE9\u8A08\u5931\u6557' : 'Audit failed');
      console.log(
        formatError(
          errMsg,
          lang === 'zh-TW' ? '\u6280\u80FD\u5BE9\u8A08' : 'Skill Auditor',
          lang === 'zh-TW' ? '\u8ACB\u91CD\u8A66\u6216\u6AA2\u67E5\u65E5\u8A8C' : 'Please retry or check logs'
        )
      );
    }
  }
}
