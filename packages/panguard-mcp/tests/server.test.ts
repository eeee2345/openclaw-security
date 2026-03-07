/**
 * Panguard MCP - Server Tests
 * Panguard MCP - 伺服器測試
 *
 * Tests for MCP server setup: tool listing, schema validation, metadata,
 * and the dispatch router.
 *
 * @module @panguard-ai/panguard-mcp/tests/server
 */

import { describe, it, expect, vi } from 'vitest';
import { getAllToolDefinitions, dispatchTool, PANGUARD_MCP_VERSION } from '../src/server.js';

// ─── Server Metadata ────────────────────────────────────────────────────────

describe('Server metadata', () => {
  it('exports a valid semver version string', () => {
    expect(typeof PANGUARD_MCP_VERSION).toBe('string');
    // Semver: major.minor.patch with optional pre-release
    expect(PANGUARD_MCP_VERSION).toMatch(/^\d+\.\d+\.\d+/);
  });
});

// ─── Tool Listing ───────────────────────────────────────────────────────────

describe('getAllToolDefinitions()', () => {
  const tools = getAllToolDefinitions();

  it('returns exactly 11 tool definitions', () => {
    expect(tools).toHaveLength(11);
  });

  const EXPECTED_TOOL_NAMES = [
    'panguard_scan',
    'panguard_scan_code',
    'panguard_guard_start',
    'panguard_guard_stop',
    'panguard_status',
    'panguard_alerts',
    'panguard_block_ip',
    'panguard_generate_report',
    'panguard_init',
    'panguard_audit_skill',
    'panguard_deploy',
  ] as const;

  it('contains all expected tool names', () => {
    const names = tools.map((t) => t.name);
    for (const expected of EXPECTED_TOOL_NAMES) {
      expect(names).toContain(expected);
    }
  });

  it('has no duplicate tool names', () => {
    const names = tools.map((t) => t.name);
    const unique = new Set(names);
    expect(unique.size).toBe(names.length);
  });

  it('every tool has a non-empty name', () => {
    for (const tool of tools) {
      expect(typeof tool.name).toBe('string');
      expect(tool.name.length).toBeGreaterThan(0);
    }
  });

  it('every tool name follows panguard_ prefix convention', () => {
    for (const tool of tools) {
      expect(tool.name).toMatch(/^panguard_/);
    }
  });

  it('every tool has a non-empty description', () => {
    for (const tool of tools) {
      expect(typeof tool.description).toBe('string');
      expect(tool.description.length).toBeGreaterThan(10);
    }
  });

  it('every tool description is bilingual (contains "/")', () => {
    for (const tool of tools) {
      expect(tool.description).toContain('/');
    }
  });
});

// ─── Tool Schema Validation ─────────────────────────────────────────────────

describe('Tool schema validation', () => {
  const tools = getAllToolDefinitions();

  it('every tool has inputSchema with type "object"', () => {
    for (const tool of tools) {
      expect(tool.inputSchema).toBeDefined();
      expect(tool.inputSchema.type).toBe('object');
    }
  });

  it('every tool has a properties object in inputSchema', () => {
    for (const tool of tools) {
      expect(tool.inputSchema.properties).toBeDefined();
      expect(typeof tool.inputSchema.properties).toBe('object');
    }
  });

  it('every property has a type field', () => {
    for (const tool of tools) {
      const props = tool.inputSchema.properties;
      for (const [key, schema] of Object.entries(props)) {
        expect((schema as Record<string, unknown>)['type']).toBeDefined();
      }
    }
  });

  // Required fields checks
  it('panguard_scan_code requires "dir"', () => {
    const tool = tools.find((t) => t.name === 'panguard_scan_code');
    expect(tool).toBeDefined();
    expect(tool!.inputSchema.required).toContain('dir');
  });

  it('panguard_block_ip requires "ip"', () => {
    const tool = tools.find((t) => t.name === 'panguard_block_ip');
    expect(tool).toBeDefined();
    expect(tool!.inputSchema.required).toContain('ip');
  });

  it('panguard_audit_skill requires "path"', () => {
    const tool = tools.find((t) => t.name === 'panguard_audit_skill');
    expect(tool).toBeDefined();
    expect(tool!.inputSchema.required).toContain('path');
  });

  // Enum validation
  it('panguard_scan depth enum is ["quick", "full"]', () => {
    const tool = tools.find((t) => t.name === 'panguard_scan');
    const depthProp = tool!.inputSchema.properties['depth'] as Record<string, unknown>;
    expect(depthProp['enum']).toEqual(['quick', 'full']);
  });

  it('panguard_scan lang enum is ["en", "zh-TW"]', () => {
    const tool = tools.find((t) => t.name === 'panguard_scan');
    const langProp = tool!.inputSchema.properties['lang'] as Record<string, unknown>;
    expect(langProp['enum']).toEqual(['en', 'zh-TW']);
  });

  it('panguard_guard_start mode enum is ["learning", "protection"]', () => {
    const tool = tools.find((t) => t.name === 'panguard_guard_start');
    const modeProp = tool!.inputSchema.properties['mode'] as Record<string, unknown>;
    expect(modeProp['enum']).toEqual(['learning', 'protection']);
  });

  it('panguard_alerts severity enum includes "all"', () => {
    const tool = tools.find((t) => t.name === 'panguard_alerts');
    const severityProp = tool!.inputSchema.properties['severity'] as Record<string, unknown>;
    expect(severityProp['enum']).toContain('all');
    expect(severityProp['enum']).toContain('critical');
    expect(severityProp['enum']).toContain('high');
    expect(severityProp['enum']).toContain('medium');
    expect(severityProp['enum']).toContain('low');
  });

  // Tools that should NOT have required fields
  it('panguard_scan has no required fields', () => {
    const tool = tools.find((t) => t.name === 'panguard_scan');
    expect(tool!.inputSchema.required).toBeUndefined();
  });

  it('panguard_guard_start has no required fields', () => {
    const tool = tools.find((t) => t.name === 'panguard_guard_start');
    expect(tool!.inputSchema.required).toBeUndefined();
  });

  it('panguard_status has no required fields', () => {
    const tool = tools.find((t) => t.name === 'panguard_status');
    expect(tool!.inputSchema.required).toBeUndefined();
  });

  it('panguard_deploy has no required fields', () => {
    const tool = tools.find((t) => t.name === 'panguard_deploy');
    expect(tool!.inputSchema.required).toBeUndefined();
  });
});

// ─── Specific Tool Schema Detail ────────────────────────────────────────────

describe('Individual tool schema details', () => {
  const tools = getAllToolDefinitions();

  it('panguard_alerts has limit property of type number', () => {
    const tool = tools.find((t) => t.name === 'panguard_alerts');
    const limitProp = tool!.inputSchema.properties['limit'] as Record<string, unknown>;
    expect(limitProp['type']).toBe('number');
    expect(limitProp['default']).toBe(20);
  });

  it('panguard_deploy has generateReport property of type boolean', () => {
    const tool = tools.find((t) => t.name === 'panguard_deploy');
    const reportProp = tool!.inputSchema.properties['generateReport'] as Record<string, unknown>;
    expect(reportProp['type']).toBe('boolean');
    expect(reportProp['default']).toBe(true);
  });

  it('panguard_generate_report has output property with default path', () => {
    const tool = tools.find((t) => t.name === 'panguard_generate_report');
    const outputProp = tool!.inputSchema.properties['output'] as Record<string, unknown>;
    expect(outputProp['type']).toBe('string');
    expect(outputProp['default']).toBe('./panguard-report.pdf');
  });

  it('panguard_block_ip has ip, duration, and reason properties', () => {
    const tool = tools.find((t) => t.name === 'panguard_block_ip');
    const props = Object.keys(tool!.inputSchema.properties);
    expect(props).toContain('ip');
    expect(props).toContain('duration');
    expect(props).toContain('reason');
  });

  it('panguard_init has dataDir, lang, and mode properties', () => {
    const tool = tools.find((t) => t.name === 'panguard_init');
    const props = Object.keys(tool!.inputSchema.properties);
    expect(props).toContain('dataDir');
    expect(props).toContain('lang');
    expect(props).toContain('mode');
  });
});

// ─── dispatchTool — Unknown Tool ────────────────────────────────────────────

describe('dispatchTool with unknown tool name', () => {
  it('returns isError: true for unknown tools', async () => {
    const result = await dispatchTool('nonexistent_tool', {});
    expect(result.isError).toBe(true);
    expect(result.content[0]!.text).toContain('Unknown tool');
  });

  it('includes the tool name in the error message', async () => {
    const result = await dispatchTool('some_random_tool', {});
    expect(result.content[0]!.text).toContain('some_random_tool');
  });
});
