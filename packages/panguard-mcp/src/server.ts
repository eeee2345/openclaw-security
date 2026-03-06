/**
 * Panguard MCP - Server
 * Panguard MCP - 伺服器
 *
 * Main MCP server entry: registers all tools and dispatches incoming requests.
 * 主要 MCP 伺服器入口：註冊所有工具並分派傳入請求。
 *
 * @module @panguard-ai/panguard-mcp/server
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { createLogger } from '@panguard-ai/core';

import { executeScan, executeScanCode } from './tools/scan-tools.js';
import { executeGuardStart, executeGuardStop, executeStatus, executeAlerts } from './tools/guard-tools.js';
import {
  executeBlockIP,
  executeGenerateReport,
  executeInit,
  executeDeploy,
} from './tools/manage-tools.js';

const logger = createLogger('panguard-mcp:server');

import { createRequire } from 'node:module';
const _require = createRequire(import.meta.url);
const _pkg = _require('../package.json') as { version: string };

/** MCP server version / MCP 伺服器版本 */
export const PANGUARD_MCP_VERSION: string = _pkg.version;

/**
 * All MCP tool definitions.
 * 所有 MCP 工具定義。
 *
 * Each tool has a name, description (bilingual EN/ZH-TW), and inputSchema.
 * 每個工具都有名稱、雙語描述（EN/ZH-TW）和輸入結構。
 */
const TOOL_DEFINITIONS = [
  {
    name: 'panguard_scan',
    description:
      'Run a security health check scan on the local system. Returns risk score (0-100), grade (A-F), and list of security findings. / 在本機執行資安健檢掃描，回傳風險分數、等級和安全發現清單。',
    inputSchema: {
      type: 'object' as const,
      properties: {
        depth: {
          type: 'string',
          enum: ['quick', 'full'],
          description: 'Scan depth: quick (~30s) or full (~60s)',
          default: 'quick',
        },
        lang: {
          type: 'string',
          enum: ['en', 'zh-TW'],
          description: 'Output language',
          default: 'en',
        },
      },
    },
  },
  {
    name: 'panguard_scan_code',
    description:
      'Scan source code directory for security vulnerabilities (SAST). Detects SQL injection, XSS, hardcoded secrets, command injection, and more. / 掃描原始碼目錄的安全漏洞（SAST）。偵測 SQL 注入、XSS、硬編碼密鑰等。',
    inputSchema: {
      type: 'object' as const,
      properties: {
        dir: {
          type: 'string',
          description: 'Source code directory to scan',
          default: '.',
        },
        lang: {
          type: 'string',
          enum: ['en', 'zh-TW'],
          default: 'en',
        },
      },
      required: ['dir'],
    },
  },
  {
    name: 'panguard_guard_start',
    description:
      'Start the Panguard Guard real-time threat monitoring daemon. / 啟動 Panguard Guard 即時威脅監控常駐程式。',
    inputSchema: {
      type: 'object' as const,
      properties: {
        dataDir: {
          type: 'string',
          description: 'Data directory (default: ~/.panguard-guard)',
        },
        mode: {
          type: 'string',
          enum: ['learning', 'protection'],
          description: 'Operating mode',
        },
      },
    },
  },
  {
    name: 'panguard_guard_stop',
    description:
      'Stop the Panguard Guard daemon. / 停止 Panguard Guard 常駐程式。',
    inputSchema: {
      type: 'object' as const,
      properties: {
        dataDir: {
          type: 'string',
          description: 'Data directory (default: ~/.panguard-guard)',
        },
      },
    },
  },
  {
    name: 'panguard_status',
    description:
      'Get the current status of all Panguard services (guard, scan, manager). Returns running state, threat counts, and system info. / 取得所有 Panguard 服務的當前狀態。',
    inputSchema: {
      type: 'object' as const,
      properties: {
        dataDir: {
          type: 'string',
          description: 'Data directory (default: ~/.panguard-guard)',
        },
      },
    },
  },
  {
    name: 'panguard_alerts',
    description:
      'Get recent security alerts detected by Panguard Guard. Returns the latest threat events with severity and details. / 取得 Panguard Guard 偵測到的近期安全告警。',
    inputSchema: {
      type: 'object' as const,
      properties: {
        limit: {
          type: 'number',
          description: 'Maximum number of alerts to return',
          default: 20,
        },
        severity: {
          type: 'string',
          enum: ['critical', 'high', 'medium', 'low', 'all'],
          default: 'all',
        },
        dataDir: {
          type: 'string',
          description: 'Data directory (default: ~/.panguard-guard)',
        },
      },
    },
  },
  {
    name: 'panguard_block_ip',
    description:
      'Manually block an IP address from accessing the system. / 手動封鎖 IP 位址存取系統。',
    inputSchema: {
      type: 'object' as const,
      properties: {
        ip: {
          type: 'string',
          description: 'IP address to block (IPv4 or IPv6)',
        },
        duration: {
          type: 'string',
          description: 'Block duration (e.g., "1h", "24h", "permanent")',
          default: '1h',
        },
        reason: {
          type: 'string',
          description: 'Reason for blocking',
        },
      },
      required: ['ip'],
    },
  },
  {
    name: 'panguard_generate_report',
    description:
      'Generate a PDF compliance report from scan results. Returns the path to the generated PDF. / 從掃描結果生成 PDF 合規報告。',
    inputSchema: {
      type: 'object' as const,
      properties: {
        output: {
          type: 'string',
          description: 'Output PDF path',
          default: './panguard-report.pdf',
        },
        lang: {
          type: 'string',
          enum: ['en', 'zh-TW'],
          default: 'en',
        },
        depth: {
          type: 'string',
          enum: ['quick', 'full'],
          default: 'full',
        },
      },
    },
  },
  {
    name: 'panguard_init',
    description:
      'Initialize Panguard configuration interactively (non-interactive mode with defaults). / 以非互動模式初始化 Panguard 配置。',
    inputSchema: {
      type: 'object' as const,
      properties: {
        dataDir: {
          type: 'string',
          description: 'Data directory (default: ~/.panguard-guard)',
        },
        lang: {
          type: 'string',
          enum: ['en', 'zh-TW'],
          default: 'en',
        },
        mode: {
          type: 'string',
          enum: ['learning', 'protection'],
          default: 'learning',
        },
      },
    },
  },
  {
    name: 'panguard_audit_skill',
    description:
      'Audit an OpenClaw/AgentSkills SKILL.md directory for security issues. Checks manifest validity, prompt injection, tool poisoning, code vulnerabilities, dependencies, and permissions. Returns risk score (0-100) and detailed findings. / 審計 OpenClaw 技能目錄的安全問題。檢查清單有效性、提示注入、工具投毒、程式碼漏洞、依賴和權限。',
    inputSchema: {
      type: 'object' as const,
      properties: {
        path: {
          type: 'string',
          description: 'Path to skill directory containing SKILL.md',
        },
      },
      required: ['path'],
    },
  },
  {
    name: 'panguard_deploy',
    description:
      'Deploy Panguard services: scan for vulnerabilities, start guard monitoring, and generate initial report. This is the one-click setup for protection. / 部署 Panguard 服務：掃描漏洞、啟動監控並生成初始報告。一鍵設定防護。',
    inputSchema: {
      type: 'object' as const,
      properties: {
        dataDir: {
          type: 'string',
          description: 'Data directory (default: ~/.panguard-guard)',
        },
        lang: {
          type: 'string',
          enum: ['en', 'zh-TW'],
          default: 'en',
        },
        mode: {
          type: 'string',
          enum: ['learning', 'protection'],
          default: 'learning',
        },
        generateReport: {
          type: 'boolean',
          description: 'Generate PDF report after scan',
          default: true,
        },
      },
    },
  },
];

/**
 * Returns the complete list of all MCP tool definitions.
 * 返回所有 MCP 工具定義的完整清單。
 */
export function getAllToolDefinitions() {
  return TOOL_DEFINITIONS;
}

/**
 * Dispatch an incoming tool call to the appropriate handler.
 * 將傳入的工具呼叫分派給適當的處理程序。
 *
 * @param name - Tool name / 工具名稱
 * @param args - Tool arguments / 工具參數
 */
export async function dispatchTool(name: string, args: Record<string, unknown>) {
  switch (name) {
    case 'panguard_scan':
      return executeScan(args);
    case 'panguard_scan_code':
      return executeScanCode(args);
    case 'panguard_guard_start':
      return executeGuardStart(args);
    case 'panguard_guard_stop':
      return executeGuardStop(args);
    case 'panguard_status':
      return executeStatus(args);
    case 'panguard_alerts':
      return executeAlerts(args);
    case 'panguard_block_ip':
      return executeBlockIP(args);
    case 'panguard_generate_report':
      return executeGenerateReport(args);
    case 'panguard_init':
      return executeInit(args);
    case 'panguard_deploy':
      return executeDeploy(args);
    case 'panguard_audit_skill': {
      const { auditSkill } = await import('@panguard-ai/panguard-skill-auditor');
      const skillPath = (args['path'] as string) ?? '.';
      const report = await auditSkill(skillPath);
      return {
        content: [{ type: 'text' as const, text: JSON.stringify(report, null, 2) }],
      };
    }
    default:
      return {
        content: [{ type: 'text' as const, text: `Unknown tool: ${name}` }],
        isError: true,
      };
  }
}

/**
 * Create and start the MCP server using stdio transport.
 * 使用 stdio 傳輸建立並啟動 MCP 伺服器。
 *
 * This is the main entry point for the MCP server process.
 * 這是 MCP 伺服器進程的主要入口點。
 */
export async function startMCPServer(): Promise<void> {
  const server = new Server(
    { name: 'panguard-mcp', version: PANGUARD_MCP_VERSION },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: getAllToolDefinitions(),
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    return await dispatchTool(name, args ?? {});
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
  logger.info('Panguard MCP server started / Panguard MCP 伺服器已啟動');
}
