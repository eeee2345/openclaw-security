/**
 * Permission scope analysis
 * 權限範圍分析
 *
 * Analyzes what tools and permissions a skill requires based on its instructions.
 * 根據技能指令分析其需要的工具和權限。
 */

import type { SkillManifest, AuditFinding, CheckResult } from '../types.js';

interface ToolPattern {
  name: string;
  regex: RegExp;
  risk: 'low' | 'medium' | 'high';
  reason: string;
}

const TOOL_PATTERNS: ToolPattern[] = [
  { name: 'Bash/Shell', regex: /\b(bash|shell|terminal|command line|execute.*command|run.*command)\b/i, risk: 'high', reason: 'Can execute arbitrary system commands' },
  { name: 'File Write', regex: /\b(write.*file|create.*file|save.*to.*disk|overwrite)\b/i, risk: 'medium', reason: 'Can modify files on disk' },
  { name: 'File Read', regex: /\b(read.*file|cat\s|open.*file|load.*from)\b/i, risk: 'low', reason: 'Can read files from disk' },
  { name: 'Network/HTTP', regex: /\b(fetch|http request|api call|curl|wget|download|upload)\b/i, risk: 'medium', reason: 'Can make network requests' },
  { name: 'Browser', regex: /\b(browser|open.*url|navigate.*to|web.*scrape|playwright|puppeteer)\b/i, risk: 'medium', reason: 'Can open URLs and interact with web pages' },
  { name: 'Database', regex: /\b(database|sql|query|insert|update|delete.*from|mongodb|postgres|mysql)\b/i, risk: 'high', reason: 'Can access and modify database contents' },
  { name: 'Credentials', regex: /\b(api[_\s]?key|token|password|secret|credential|auth)\b/i, risk: 'medium', reason: 'Handles sensitive credentials' },
  { name: 'SSH/Keys', regex: /\b(ssh-keygen|authorized_keys|~\/\.ssh|id_rsa|id_ed25519)\b/i, risk: 'high', reason: 'Can access or modify SSH keys' },
  { name: 'Cron/Scheduler', regex: /\b(crontab|\/etc\/cron|systemctl\s+enable|launchctl\s+load)\b/i, risk: 'high', reason: 'Can install persistent scheduled tasks' },
  { name: 'Docker', regex: /\b(docker\.sock|docker\s+run|docker\s+exec|--privileged)\b/i, risk: 'high', reason: 'Can access Docker daemon or run privileged containers' },
  { name: 'Env Injection', regex: /\b(\.bashrc|\.zshrc|\.profile|\.bash_profile|export\s+\w+=)\b/i, risk: 'high', reason: 'Can inject environment variables via shell profile' },
  { name: 'Clipboard', regex: /\b(pbpaste|pbcopy|xclip|xsel|clipboard)\b/i, risk: 'medium', reason: 'Can access or modify clipboard contents' },
];

export function checkPermissions(manifest: SkillManifest): CheckResult {
  const findings: AuditFinding[] = [];
  const instructions = manifest.instructions;
  const detectedTools: Array<{ name: string; risk: string }> = [];

  for (const pattern of TOOL_PATTERNS) {
    if (pattern.regex.test(instructions)) {
      detectedTools.push({ name: pattern.name, risk: pattern.risk });

      if (pattern.risk === 'high') {
        findings.push({
          id: `perm-${pattern.name.toLowerCase().replace(/[^a-z]/g, '-')}`,
          title: `Skill uses ${pattern.name} (${pattern.risk} risk)`,
          description: pattern.reason,
          severity: 'high',
          category: 'permission',
        });
      } else if (pattern.risk === 'medium') {
        findings.push({
          id: `perm-${pattern.name.toLowerCase().replace(/[^a-z]/g, '-')}`,
          title: `Skill uses ${pattern.name} (${pattern.risk} risk)`,
          description: pattern.reason,
          severity: 'medium',
          category: 'permission',
        });
      }
    }
  }

  // Check for command-dispatch tools (can bypass model safety)
  if (manifest.commandDispatch === 'tool') {
    findings.push({
      id: 'perm-command-dispatch',
      title: 'Skill uses tool dispatch mode',
      description: 'This skill dispatches directly to a tool, bypassing the AI model. Verify the dispatched tool is safe.',
      severity: 'medium',
      category: 'permission',
    });
  }

  // Check if model invocation is disabled (unusual)
  if (manifest.disableModelInvocation) {
    findings.push({
      id: 'perm-no-model',
      title: 'Model invocation disabled',
      description: 'This skill is excluded from model prompts. It can only be invoked via slash command.',
      severity: 'low',
      category: 'permission',
    });
  }

  const highRiskCount = detectedTools.filter((t) => t.risk === 'high').length;
  const status = highRiskCount > 0 ? 'warn' : 'pass';

  const toolNames = detectedTools.map((t) => t.name).join(', ');
  const label = detectedTools.length > 0
    ? `Permissions: Uses ${toolNames}`
    : 'Permissions: No special tool usage detected';

  return { status, label, findings };
}
