#!/usr/bin/env node
/**
 * PanguardReport CLI
 * PanguardReport 命令列介面
 *
 * @module @panguard-ai/panguard-report/cli
 */

import type {
  ComplianceFramework,
  ComplianceFinding,
  ReportConfig,
  ReportFormat,
  ReportLanguage,
} from '../types.js';
import { DEFAULT_REPORT_CONFIG } from '../types.js';
import {
  generateComplianceReport,
  reportToJSON,
  generateSummaryText,
} from '../generator/report-generator.js';

/** Available CLI commands / 可用的 CLI 命令 */
export type ReportCliCommand =
  | 'generate'
  | 'list-frameworks'
  | 'validate'
  | 'summary'
  | 'config'
  | 'help';

/** CLI options / CLI 選項 */
export interface ReportCliOptions {
  command: ReportCliCommand;
  framework?: ComplianceFramework;
  language?: ReportLanguage;
  format?: ReportFormat;
  outputDir?: string;
  organizationName?: string;
  inputFile?: string;
  verbose?: boolean;
}

/**
 * Parse CLI arguments
 * 解析 CLI 參數
 */
export function parseCliArgs(args: string[]): ReportCliOptions {
  const command = (args[0] as ReportCliCommand) || 'help';
  const options: ReportCliOptions = { command };

  for (let i = 1; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--framework' && args[i + 1]) {
      options.framework = args[i + 1] as ComplianceFramework;
      i++;
    } else if (arg === '--language' && args[i + 1]) {
      options.language = args[i + 1] as ReportLanguage;
      i++;
    } else if (arg === '--format' && args[i + 1]) {
      options.format = args[i + 1] as ReportFormat;
      i++;
    } else if (arg === '--output-dir' && args[i + 1]) {
      options.outputDir = args[i + 1];
      i++;
    } else if (arg === '--org' && args[i + 1]) {
      options.organizationName = args[i + 1];
      i++;
    } else if (arg === '--input' && args[i + 1]) {
      options.inputFile = args[i + 1];
      i++;
    } else if (arg === '--verbose' || arg === '-v') {
      options.verbose = true;
    }
  }

  return options;
}

/**
 * Build report config from CLI options
 * 從 CLI 選項建立報告配置
 */
export function buildConfigFromOptions(options: ReportCliOptions): ReportConfig {
  const config = { ...DEFAULT_REPORT_CONFIG };

  if (options.framework) {
    config.framework = options.framework;
  }
  if (options.language) {
    config.language = options.language;
  }
  if (options.format) {
    config.format = options.format;
  }
  if (options.outputDir) {
    config.outputDir = options.outputDir;
  }
  if (options.organizationName) {
    config.organizationName = options.organizationName;
  }

  return config;
}

/**
 * Format config for display
 * 格式化配置以供顯示
 */
export function formatConfig(config: ReportConfig): string {
  const lines: string[] = [];

  lines.push('=== PanguardReport Configuration / PanguardReport 配置 ===');
  lines.push('');
  lines.push(`Framework / 框架: ${config.framework}`);
  lines.push(`Language / 語言: ${config.language}`);
  lines.push(`Format / 格式: ${config.format}`);
  lines.push(`Output Dir / 輸出目錄: ${config.outputDir}`);
  if (config.organizationName) {
    lines.push(`Organization / 組織: ${config.organizationName}`);
  }
  lines.push(`Include Findings / 包含發現: ${config.includeDetailedFindings ? 'yes' : 'no'}`);
  lines.push(`Include Recommendations / 包含建議: ${config.includeRecommendations ? 'yes' : 'no'}`);

  return lines.join('\n');
}

/**
 * Format framework list for display
 * 格式化框架列表以供顯示
 */
export function formatFrameworkList(): string {
  const lines: string[] = [];

  lines.push('=== Supported Compliance Frameworks / 支援的合規框架 ===');
  lines.push('');
  lines.push('  tw_cyber_security_act  - Taiwan Cyber Security Management Act / 資通安全管理法');
  lines.push('  iso27001              - ISO/IEC 27001:2022 / 資訊安全管理');
  lines.push('  soc2                  - SOC 2 Trust Services Criteria / 信任服務準則');

  return lines.join('\n');
}

/**
 * Get help text
 * 取得說明文字
 */
export function getHelpText(): string {
  return `
PanguardReport - AI Compliance Report Generator / AI 合規報告產生器
Panguard AI (https://panguard.ai)

Usage / 用法:
  panguard-report <command> [options]

Commands / 命令:
  generate          Generate a compliance report / 產生合規報告
  list-frameworks   List supported compliance frameworks / 列出支援的合規框架
  validate          Validate findings input file / 驗證發現輸入檔案
  summary           Show brief compliance summary / 顯示簡短合規摘要
  config            Show current configuration / 顯示目前配置
  help              Show this help message / 顯示此說明

Options / 選項:
  --framework <name>   Compliance framework / 合規框架
                       (tw_cyber_security_act, iso27001, soc2)
  --language <lang>    Report language / 報告語言 (zh-TW, en)
  --format <fmt>       Output format / 輸出格式 (json, pdf)
  --output-dir <path>  Output directory / 輸出目錄
  --org <name>         Organization name / 組織名稱
  --input <file>       Findings input file (JSON) / 發現輸入檔案 (JSON)
  --verbose, -v        Verbose output / 詳細輸出

Examples / 範例:
  panguard-report generate --framework tw_cyber_security_act --language zh-TW
  panguard-report generate --framework iso27001 --org "ACME Corp" --input findings.json
  panguard-report list-frameworks
  panguard-report summary --input findings.json --framework soc2
`.trim();
}

/**
 * Load findings from an input file or generate sample findings
 * 從輸入檔案載入發現或產生範例發現
 */
async function loadFindings(inputFile?: string): Promise<ComplianceFinding[]> {
  if (inputFile) {
    const { readFile } = await import('node:fs/promises');
    const raw = await readFile(inputFile, 'utf-8');
    return JSON.parse(raw) as ComplianceFinding[];
  }

  // Generate sample findings for demo when no input file is provided
  return [
    {
      findingId: 'FIND-001',
      severity: 'high',
      title: 'Missing information security policy',
      description: 'No formal information security policy document found.',
      category: 'policy',
      timestamp: new Date(),
      source: 'panguard-scan',
    },
    {
      findingId: 'FIND-002',
      severity: 'medium',
      title: 'Unencrypted data at rest',
      description: 'Database storage does not use encryption at rest.',
      category: 'encryption',
      timestamp: new Date(),
      source: 'panguard-scan',
    },
    {
      findingId: 'FIND-003',
      severity: 'low',
      title: 'Password policy not enforced',
      description: 'Password complexity requirements are not enforced.',
      category: 'access_control',
      timestamp: new Date(),
      source: 'panguard-scan',
    },
  ];
}

/**
 * Execute CLI command
 * 執行 CLI 命令
 */
export async function executeCli(args: string[]): Promise<void> {
  const options = parseCliArgs(args);

  switch (options.command) {
    case 'help':
      console.log(getHelpText());
      break;

    case 'config': {
      const config = buildConfigFromOptions(options);
      console.log(formatConfig(config));
      break;
    }

    case 'list-frameworks':
      console.log(formatFrameworkList());
      break;

    case 'generate': {
      const framework = options.framework ?? DEFAULT_REPORT_CONFIG.framework;
      const language = options.language ?? DEFAULT_REPORT_CONFIG.language;
      const format = options.format ?? DEFAULT_REPORT_CONFIG.format;

      console.log('Generating compliance report... / 產生合規報告中...');
      console.log(`Framework / 框架: ${framework}`);
      console.log(`Language / 語言: ${language}`);

      const findings = await loadFindings(options.inputFile);
      console.log(`Findings loaded / 已載入發現: ${findings.length}`);

      const report = generateComplianceReport(findings, framework, language, {
        organizationName: options.organizationName,
        includeRecommendations: true,
      });

      if (format === 'json') {
        const json = reportToJSON(report);
        if (options.outputDir) {
          const { writeFile, mkdir } = await import('node:fs/promises');
          await mkdir(options.outputDir, { recursive: true });
          const filePath = `${options.outputDir}/${report.metadata.reportId}.json`;
          await writeFile(filePath, json, 'utf-8');
          console.log(`Report saved to / 報告已儲存至: ${filePath}`);
        } else {
          console.log('');
          console.log(json);
        }
      } else {
        // For non-JSON formats, output the summary text
        const summary = generateSummaryText(report);
        console.log('');
        console.log(summary);
      }

      console.log('');
      console.log('Report generated successfully. / 報告產生成功。');
      break;
    }

    case 'validate':
      if (options.inputFile) {
        console.log(`Validating input file: ${options.inputFile}`);
        try {
          const findings = await loadFindings(options.inputFile);
          console.log(
            `Valid: ${findings.length} findings found. / 有效: 找到 ${findings.length} 個發現。`
          );
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          console.error(`Validation failed: ${msg} / 驗證失敗: ${msg}`);
        }
      } else {
        console.log('No input file specified. Use --input <file>.');
        console.log('未指定輸入檔案。請使用 --input <file>。');
      }
      break;

    case 'summary': {
      const sumFramework = options.framework ?? DEFAULT_REPORT_CONFIG.framework;
      const sumLanguage = options.language ?? DEFAULT_REPORT_CONFIG.language;
      const findings = await loadFindings(options.inputFile);

      const report = generateComplianceReport(findings, sumFramework, sumLanguage);
      const summary = generateSummaryText(report);
      console.log(summary);
      break;
    }

    default:
      console.log(`Unknown command: ${options.command}`);
      console.log(getHelpText());
  }
}

// ---------------------------------------------------------------------------
// CLI entry point (when run directly)
// CLI 進入點（直接執行時）
// ---------------------------------------------------------------------------

const isDirectRun =
  process.argv[1] &&
  (process.argv[1].endsWith('/panguard-report') ||
    process.argv[1].includes('panguard-report/dist/cli'));

if (isDirectRun) {
  executeCli(process.argv.slice(2)).catch((err) => {
    console.error('Error:', err instanceof Error ? err.message : String(err));
    process.exit(1);
  });
}
