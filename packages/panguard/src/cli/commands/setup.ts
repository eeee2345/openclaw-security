/**
 * panguard setup - One-command platform setup with skill scanning
 * panguard setup - 一行指令平台安裝並掃描技能
 *
 * Detects installed AI agent platforms, injects MCP config,
 * scans and audits all installed skills, and optionally starts Guard.
 * 偵測已安裝的 AI Agent 平台，注入 MCP 設定，掃描審核所有已安裝技能，可選啟動 Guard。
 */

import { Command } from 'commander';
import { exec, spawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir, platform } from 'node:os';
import { createRequire } from 'node:module';
import { c, banner, divider, symbols, promptConfirm } from '@panguard-ai/core';
import {
  scanInstalledSkills,
  renderSkillScanResults,
  reviewFlaggedSkills,
} from './setup-skill-scan.js';

/** Open URL in the default browser (cross-platform) */
function openBrowser(url: string): void {
  const os = platform();
  const cmd = os === 'darwin' ? 'open' : os === 'win32' ? 'start' : 'xdg-open';
  exec(`${cmd} ${url}`, () => {
    // Ignore errors — browser open is best-effort
  });
}

/** Persist skill names into the Guard whitelist JSON file */
function persistToWhitelist(skillNames: readonly string[], source: 'manual' | 'static'): void {
  const guardDir = join(homedir(), '.panguard-guard');
  const whitelistPath = join(guardDir, 'skill-whitelist.json');

  if (!existsSync(guardDir)) {
    mkdirSync(guardDir, { recursive: true });
  }

  // Load existing whitelist if present
  let existing: {
    whitelist: Array<{
      name: string;
      normalizedName: string;
      source: string;
      addedAt: string;
      fingerprintHash?: string;
      reason?: string;
    }>;
    revoked: string[];
  } = { whitelist: [], revoked: [] };

  if (existsSync(whitelistPath)) {
    try {
      existing = JSON.parse(readFileSync(whitelistPath, 'utf-8')) as typeof existing;
    } catch {
      console.warn(c.yellow(`  ${symbols.warn} Whitelist file was corrupt and has been reset.`));
    }
  }

  const existingNames = new Set(existing.whitelist.map((e) => e.normalizedName));
  const now = new Date().toISOString();

  for (const name of skillNames) {
    const normalized = name.toLowerCase().trim().replace(/\s+/g, '-');
    if (existingNames.has(normalized)) continue;

    existing.whitelist.push({
      name,
      normalizedName: normalized,
      source,
      addedAt: now,
      reason:
        source === 'manual' ? 'User-approved during setup' : 'Auto-whitelisted during setup (safe)',
    });
    existingNames.add(normalized);
  }

  writeFileSync(whitelistPath, JSON.stringify(existing, null, 2), 'utf-8');
}

/** Platform-specific restart instructions */
const PLATFORM_RESTART_HINTS: Record<string, string> = {
  'claude-code': 'Close and reopen your terminal',
  'claude-desktop': 'Quit and reopen Claude Desktop',
  cursor: 'Cmd+Shift+P (or Ctrl+Shift+P) > "Reload Window"',
  openclaw: 'Close and reopen OpenClaw',
  codex: 'Restart the Codex CLI session',
  workbuddy: 'Close and reopen WorkBuddy',
  nemoclaw: 'Close and reopen NemoClaw',
  qclaw: 'Close and reopen QClaw',
};

export function setupCommand(): Command {
  const cmd = new Command('setup')
    .description(
      'Auto-detect AI agent platforms and configure Panguard MCP / 自動偵測 AI Agent 平台並設定 Panguard MCP'
    )
    .option(
      '--platform <name>',
      'Target a specific platform (claude-code, cursor, openclaw, codex, workbuddy, nemoclaw, qclaw, claude-desktop)'
    )
    .option('--remove', 'Remove Panguard MCP config from platforms / 移除設定', false)
    .option('--json', 'Output as JSON / 以 JSON 格式輸出', false)
    .option('--yes', 'Skip confirmation prompts / 跳過確認提示', false)
    .option('--skip-scan', 'Skip skill scanning / 跳過技能掃描', false)
    .option('--skip-guard', 'Skip guard start prompt / 跳過 Guard 啟動', false)
    .action(
      async (options: {
        platform?: string;
        remove: boolean;
        json: boolean;
        yes: boolean;
        skipScan: boolean;
        skipGuard: boolean;
      }) => {
        const mcpConfig = await import('@panguard-ai/panguard-mcp/config');
        const { detectPlatforms, injectMCPConfig, removeMCPConfig } = mcpConfig;

        if (!options.json) {
          banner('Panguard Setup');
          console.log();
        }

        // 1. Detect platforms
        if (!options.json) {
          console.log(c.dim('  Scanning for AI agent platforms...'));
          console.log();
        }

        const allPlatforms = await detectPlatforms();

        // Filter to target platform if specified
        const validIds = [
          'claude-code',
          'claude-desktop',
          'cursor',
          'openclaw',
          'codex',
          'workbuddy',
          'nemoclaw',
          'qclaw',
        ];
        let targets = allPlatforms;
        if (options.platform) {
          if (!validIds.includes(options.platform)) {
            console.error(c.red(`  Unknown platform: ${options.platform}`));
            console.error(c.dim(`  Valid platforms: ${validIds.join(', ')}`));
            process.exitCode = 1;
            return;
          }
          targets = allPlatforms.filter((p) => p.id === options.platform);
        }

        // 2. Show detection results
        if (!options.json) {
          console.log(c.bold('  Detected Platforms:'));
          console.log();
          for (const p of allPlatforms) {
            const status = p.detected
              ? p.alreadyConfigured
                ? c.green(`${symbols.pass} configured`)
                : c.yellow(`${symbols.warn} not configured`)
              : c.dim(`${symbols.dot} not found`);
            console.log(`    ${p.detected ? c.bold(p.name) : c.dim(p.name)}  ${status}`);
          }
          console.log();
          divider();
          console.log();
        }

        // Determine which platforms to act on
        const actionable = options.remove
          ? targets.filter((p) => p.alreadyConfigured)
          : targets.filter((p) => p.detected && !p.alreadyConfigured);

        if (actionable.length === 0) {
          if (options.json) {
            console.log(
              JSON.stringify({ action: options.remove ? 'remove' : 'setup', results: [] })
            );
          } else {
            const msg = options.remove
              ? 'No platforms have Panguard configured.'
              : 'All detected platforms are already configured, or no platforms found.';
            console.log(c.green(`  ${symbols.pass} ${msg}`));
            console.log();
            console.log(c.dim('  Run with --platform <name> to target a specific platform.'));
          }
          return;
        }

        // 3. Execute injection or removal
        if (!options.json) {
          const action = options.remove ? 'Removing from' : 'Configuring';
          console.log(c.bold(`  ${action} ${actionable.length} platform(s):`));
          console.log();
        }

        const results: Array<{
          success: boolean;
          platformId: string;
          configPath?: string;
          error?: string;
        }> = [];
        for (const p of actionable) {
          const result = options.remove ? removeMCPConfig(p.id) : injectMCPConfig(p.id);
          results.push(result);

          if (!options.json) {
            const icon = result.success ? c.green(symbols.pass) : c.red(symbols.fail);
            console.log(`    ${icon} ${p.name}`);
            if (result.success) {
              console.log(c.dim(`      ${result.configPath}`));
            } else {
              console.log(c.red(`      Error: ${result.error}`));
            }
          }
        }

        if (options.json) {
          console.log(
            JSON.stringify(
              {
                action: options.remove ? 'remove' : 'setup',
                results: results.map((r) => ({
                  platform: r.platformId,
                  success: r.success,
                  configPath: r.configPath,
                  error: r.error,
                })),
              },
              null,
              2
            )
          );
          return;
        }

        console.log();
        divider();
        console.log();

        const succeeded = results.filter((r) => r.success).length;
        const failed = results.filter((r) => !r.success).length;

        if (failed === 0) {
          console.log(
            c.green(`  ${symbols.pass} All ${succeeded} platform(s) configured successfully.`)
          );
        } else {
          console.log(c.yellow(`  ${succeeded} succeeded, ${failed} failed.`));
        }

        // ── 4. Scan installed skills ──────────────────────────────────
        if (!options.remove && !options.skipScan) {
          console.log();
          divider('Skill Security Scan');
          console.log();
          console.log(c.dim('  Scanning installed MCP skills across all platforms...'));
          console.log();

          try {
            const { discoverAllSkills } = await import('@panguard-ai/panguard-mcp/config');
            const skills = await discoverAllSkills();

            if (skills.length > 0) {
              const scanResults = await scanInstalledSkills(skills);
              renderSkillScanResults(scanResults);

              // Whitelist only safe (LOW risk) skills — caution (MEDIUM) needs review
              const safeOnly = scanResults
                .filter((r) => r.status === 'safe')
                .map((r) => r.entry.name);
              if (safeOnly.length > 0) {
                persistToWhitelist(safeOnly, 'static');
                console.log();
                console.log(
                  c.green(`  ${symbols.pass} ${safeOnly.length} safe skill(s) auto-whitelisted.`)
                );
                console.log(c.dim(`    Saved to ~/.panguard-guard/skill-whitelist.json`));
              }

              const caution = scanResults.filter((r) => r.status === 'caution');
              if (caution.length > 0) {
                console.log(
                  c.yellow(
                    `  ${symbols.warn} ${caution.length} skill(s) at MEDIUM risk — monitored but not whitelisted.`
                  )
                );
              }

              // Review flagged (HIGH/CRITICAL) skills interactively
              const flagged = scanResults.filter((r) => r.status === 'flagged');
              if (flagged.length > 0 && !options.yes) {
                const userWhitelisted = await reviewFlaggedSkills(flagged);
                if (userWhitelisted.length > 0) {
                  persistToWhitelist(userWhitelisted, 'manual');
                }
              } else if (flagged.length > 0) {
                console.log(
                  c.yellow(
                    `  ${symbols.warn} ${flagged.length} flagged skill(s) — run "panguard guard --watch" to review.`
                  )
                );
              }
            } else {
              console.log(
                c.dim(
                  `  ${symbols.info} No MCP skills found. Skills will be audited as you install them.`
                )
              );
            }
          } catch {
            console.log(c.dim(`  ${symbols.info} Skill scanning skipped (auditor not available).`));
          }

          console.log();
          divider();
        }

        // ── 5. Install guard as system service (auto-start on boot) ───
        if (!options.remove && !options.skipGuard) {
          console.log();
          const installGuard =
            options.yes ||
            (await promptConfirm({
              message: {
                en: 'Install Panguard Guard as system service? (auto-start on boot, 24/7 protection)',
                'zh-TW': '安裝 Panguard Guard 為系統服務？（開機自動啟動，24/7 防護）',
              },
              defaultValue: true,
              lang: 'en',
            }));

          if (installGuard) {
            console.log();
            console.log(c.dim('  Installing Panguard Guard as system service...'));

            // Resolve the guard CLI binary path (outside try so fallback can use it)
            let guardBin: string | undefined;
            try {
              const require = createRequire(import.meta.url);
              guardBin = require.resolve('@panguard-ai/panguard-guard/dist/cli/index.js');
            } catch {
              // Fallback: check common global/local paths
            }

            if (!guardBin) {
              console.log(c.yellow(`  ${symbols.warn} Could not locate panguard-guard binary.`));
              console.log(c.dim('    Run manually: panguard guard install'));
            } else {
              try {
                const guardExec = `${process.execPath} ${guardBin}`;
                const dataDir = join(homedir(), '.panguard-guard');

                const { installService } = await import('@panguard-ai/panguard-guard');
                const servicePath = await installService(guardExec, dataDir);

                const osPlatform = process.platform;
                const serviceType =
                  osPlatform === 'darwin'
                    ? 'launchd'
                    : osPlatform === 'linux'
                      ? 'systemd'
                      : osPlatform === 'win32'
                        ? 'Windows Service'
                        : 'system service';

                console.log(
                  c.green(`  ${symbols.pass} Guard installed as ${serviceType} service.`)
                );
                console.log(c.dim(`    ${servicePath}`));
                console.log(
                  c.green(`  ${symbols.pass} Guard will auto-start on boot and restart on crash.`)
                );
                console.log(c.dim('    Run "panguard guard status" to check.'));
                console.log(c.dim('    Run "panguard guard uninstall" to remove.'));

                // Open Dashboard in browser
                const dashUrl = 'http://127.0.0.1:3847';
                console.log();
                console.log(c.green(`  ${symbols.pass} Opening Guard Dashboard...`));
                console.log(c.dim(`    ${dashUrl}`));
                openBrowser(dashUrl);
              } catch (err) {
                const msg = err instanceof Error ? err.message : String(err);
                if (msg.includes('EACCES') || msg.includes('permission')) {
                  console.log(
                    c.yellow(
                      `  ${symbols.warn} Needs elevated privileges to install system service.`
                    )
                  );
                  console.log(c.dim('    Run: sudo panguard guard install'));
                } else {
                  console.log(
                    c.yellow(`  ${symbols.warn} Could not install as system service: ${msg}`)
                  );
                  console.log(c.dim('    Run manually: panguard guard install'));
                }
                // Fallback: start Guard for this session only
                console.log();
                console.log(c.dim('  Starting Guard for this session instead...'));
                try {
                  const child = spawn(process.execPath, [guardBin, 'start', '--dashboard'], {
                    detached: true,
                    stdio: 'ignore',
                  });
                  child.unref();
                  console.log(
                    c.green(
                      `  ${symbols.pass} Guard started (PID: ${child.pid}). Will stop when system restarts.`
                    )
                  );
                  // Open Dashboard in browser
                  const fallbackUrl = 'http://127.0.0.1:3847';
                  console.log();
                  console.log(c.green(`  ${symbols.pass} Opening Guard Dashboard...`));
                  console.log(c.dim(`    ${fallbackUrl}`));
                  openBrowser(fallbackUrl);
                } catch {
                  console.log(c.dim('    Run manually: panguard guard start --dashboard'));
                }
              }
            }
          }
        }

        // ── Next steps ─────────────────────────────────────────────────
        console.log();
        console.log(c.dim('  Next steps:'));
        console.log(c.dim('    1. Restart your AI agent:'));

        const configuredPlatforms = actionable.filter((_, i) => results[i]?.success);
        for (const p of configuredPlatforms) {
          const restartHint = PLATFORM_RESTART_HINTS[p.id] ?? 'Restart the application';
          console.log(c.dim(`       ${p.name}: ${restartHint}`));
        }

        console.log(c.dim('    2. Ask your agent: "Run panguard_status to check security"'));
        console.log(
          c.dim('    3. Try: "Audit the skills in this project with panguard_audit_skill"')
        );
        console.log();
      }
    );

  return cmd;
}
