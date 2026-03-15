#!/usr/bin/env node
/* eslint-disable no-console, security/detect-object-injection, security/detect-non-literal-fs-filename */
/**
 * ATR CLI - Command-line interface for Agent Threat Rules
 *
 * Console output and dynamic filesystem access are expected in a CLI tool.
 *
 * Usage:
 *   npx agent-threat-rules scan <events.json>     Scan events against all rules
 *   npx agent-threat-rules validate <rule.yaml>    Validate a rule file
 *   npx agent-threat-rules test <rule.yaml>        Run a rule's test cases
 *   npx agent-threat-rules stats                   Show rule collection stats
 */

import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ATREngine } from './engine.js';
import { loadRuleFile, loadRulesFromDirectory, validateRule } from './loader.js';
import type { AgentEvent, ATRMatch, ATRRule } from './types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const RULES_DIR = resolve(__dirname, '..', 'rules');

const SEVERITY_COLORS: Record<string, string> = {
  critical: '\x1b[91m', // bright red
  high: '\x1b[31m', // red
  medium: '\x1b[33m', // yellow
  low: '\x1b[36m', // cyan
  informational: '\x1b[37m', // white
};
const RESET = '\x1b[0m';
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const DIM = '\x1b[2m';
const BOLD = '\x1b[1m';

function printUsage(): void {
  console.log(`
${BOLD}ATR - Agent Threat Rules${RESET}
Open detection rules for AI agent security threats.

${BOLD}Usage:${RESET}
  atr scan <events.json> [--rules <dir>]   Scan events against ATR rules
  atr validate <rule.yaml|dir>             Validate rule file(s)
  atr test <rule.yaml|dir>                 Run embedded test cases
  atr stats [--rules <dir>]                Show rule collection statistics
  atr mcp                                  Start MCP server (stdio transport)
  atr scaffold                             Interactive rule scaffolding
  atr submit <rule.yaml> [--endpoint <url>] Submit rule to Threat Cloud

${BOLD}Options:${RESET}
  --rules <dir>    Custom rules directory (default: bundled rules)
  --json           Output results as JSON
  --severity <s>   Minimum severity to report (critical|high|medium|low|informational)
  --endpoint <url> Threat Cloud endpoint (default: https://cloud.panguard.ai)
  --help           Show this help message

${BOLD}Examples:${RESET}
  ${DIM}# Scan agent events for threats${RESET}
  atr scan events.json

  ${DIM}# Validate a custom rule${RESET}
  atr validate my-rules/custom-rule.yaml

  ${DIM}# Test all rules against their embedded test cases${RESET}
  atr test rules/

  ${DIM}# Show stats for bundled rules${RESET}
  atr stats

  ${DIM}# Start MCP server for AI agent integration${RESET}
  atr mcp

  ${DIM}# Interactively scaffold a new rule${RESET}
  atr scaffold

  ${DIM}# Submit a rule to Threat Cloud for community review${RESET}
  atr submit my-rules/new-rule.yaml --endpoint https://cloud.panguard.ai
`);
}

function parseArgs(argv: string[]): {
  command: string;
  target: string;
  options: Record<string, string>;
} {
  const args = argv.slice(2);
  const command = args[0] ?? 'help';
  const options: Record<string, string> = {};
  let target = '';

  for (let i = 1; i < args.length; i++) {
    if (args[i].startsWith('--')) {
      const key = args[i].slice(2);
      if (key === 'json' || key === 'help') {
        options[key] = 'true';
      } else {
        options[key] = args[++i] ?? '';
      }
    } else if (!target) {
      target = args[i];
    }
  }

  return { command, target, options };
}

// --- SCAN command ---

async function cmdScan(target: string, options: Record<string, string>): Promise<void> {
  if (!target) {
    console.error(`${RED}Error: Missing events file. Usage: atr scan <events.json>${RESET}`);
    process.exit(1);
  }

  const eventsPath = resolve(target);
  if (!existsSync(eventsPath)) {
    console.error(`${RED}Error: File not found: ${eventsPath}${RESET}`);
    process.exit(1);
  }

  const rulesDir = options['rules'] ? resolve(options['rules']) : RULES_DIR;
  const minSeverity = options['severity'] ?? 'informational';
  const jsonOutput = options['json'] === 'true';

  const raw = readFileSync(eventsPath, 'utf-8');
  let events: AgentEvent[];
  try {
    const parsed = JSON.parse(raw);
    events = Array.isArray(parsed) ? parsed : [parsed];
  } catch {
    console.error(`${RED}Error: Invalid JSON in ${eventsPath}${RESET}`);
    process.exit(1);
  }

  const engine = new ATREngine({ rulesDir });
  await engine.loadRules();

  const severityOrder = ['informational', 'low', 'medium', 'high', 'critical'];
  const minIdx = severityOrder.indexOf(minSeverity);

  const allMatches: Array<{ event: AgentEvent; matches: ATRMatch[] }> = [];
  let totalThreats = 0;

  for (const event of events) {
    const matches = engine
      .evaluate(event)
      .filter((m) => severityOrder.indexOf(m.rule.severity) >= minIdx);
    if (matches.length > 0) {
      allMatches.push({ event, matches });
      totalThreats += matches.length;
    }
  }

  if (jsonOutput) {
    console.log(
      JSON.stringify(
        {
          eventsScanned: events.length,
          threatsDetected: totalThreats,
          rulesLoaded: engine.getRuleCount(),
          results: allMatches.map(({ event, matches }) => ({
            event: {
              type: event.type,
              timestamp: event.timestamp,
              contentPreview: event.content.slice(0, 100),
            },
            matches: matches.map((m) => ({
              ruleId: m.rule.id,
              title: m.rule.title,
              severity: m.rule.severity,
              confidence: m.confidence,
              matchedConditions: m.matchedConditions,
            })),
          })),
        },
        null,
        2
      )
    );
    return;
  }

  console.log(`\n${BOLD}ATR Scan Results${RESET}`);
  console.log(`${DIM}${'─'.repeat(60)}${RESET}`);
  console.log(`  Events scanned:  ${events.length}`);
  console.log(`  Rules loaded:    ${engine.getRuleCount()}`);
  console.log(
    `  Threats found:   ${totalThreats > 0 ? RED + totalThreats + RESET : GREEN + '0' + RESET}`
  );
  console.log(`${DIM}${'─'.repeat(60)}${RESET}\n`);

  if (totalThreats === 0) {
    console.log(`${GREEN}No threats detected.${RESET}\n`);
    return;
  }

  for (const { event, matches } of allMatches) {
    const preview = event.content.slice(0, 80).replace(/\n/g, ' ');
    console.log(`  ${DIM}Event: [${event.type}] "${preview}..."${RESET}`);
    for (const m of matches) {
      const color = SEVERITY_COLORS[m.rule.severity] ?? '';
      console.log(
        `    ${color}${m.rule.severity.toUpperCase().padEnd(13)}${RESET} ${m.rule.id} - ${m.rule.title}`
      );
      console.log(
        `    ${DIM}Confidence: ${(m.confidence * 100).toFixed(0)}% | Conditions: ${m.matchedConditions.join(', ')}${RESET}`
      );
    }
    console.log('');
  }
}

// --- VALIDATE command ---

function cmdValidate(target: string, options: Record<string, string>): void {
  if (!target) {
    console.error(
      `${RED}Error: Missing rule file/directory. Usage: atr validate <rule.yaml|dir>${RESET}`
    );
    process.exit(1);
  }

  const targetPath = resolve(target);
  if (!existsSync(targetPath)) {
    console.error(`${RED}Error: Not found: ${targetPath}${RESET}`);
    process.exit(1);
  }

  const jsonOutput = options['json'] === 'true';
  const files: string[] = [];

  if (statSync(targetPath).isDirectory()) {
    const _rules = loadRulesFromDirectory(targetPath);
    // Re-validate each file individually for error reporting
    collectYamlFiles(targetPath, files);
  } else {
    files.push(targetPath);
  }

  let passed = 0;
  let failed = 0;
  const results: Array<{ file: string; valid: boolean; errors: string[] }> = [];

  for (const file of files) {
    try {
      const rule = loadRuleFile(file);
      const result = validateRule(rule);
      results.push({ file, valid: result.valid, errors: result.errors });
      if (result.valid) {
        passed++;
      } else {
        failed++;
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      results.push({ file, valid: false, errors: [msg] });
      failed++;
    }
  }

  if (jsonOutput) {
    console.log(JSON.stringify({ total: files.length, passed, failed, results }, null, 2));
    return;
  }

  console.log(`\n${BOLD}ATR Rule Validation${RESET}`);
  console.log(`${DIM}${'─'.repeat(60)}${RESET}`);

  for (const r of results) {
    const icon = r.valid ? `${GREEN}PASS${RESET}` : `${RED}FAIL${RESET}`;
    const shortPath = r.file.replace(process.cwd() + '/', '');
    console.log(`  ${icon}  ${shortPath}`);
    if (!r.valid) {
      for (const err of r.errors) {
        console.log(`       ${RED}${err}${RESET}`);
      }
    }
  }

  console.log(`${DIM}${'─'.repeat(60)}${RESET}`);
  console.log(
    `  ${GREEN}${passed} passed${RESET}  ${failed > 0 ? RED + failed + ' failed' + RESET : ''}\n`
  );

  if (failed > 0) process.exit(1);
}

function collectYamlFiles(dir: string, out: string[]): void {
  const entries = readdirSync(dir);
  for (const entry of entries) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      collectYamlFiles(full, out);
    } else if (full.endsWith('.yaml') || full.endsWith('.yml')) {
      out.push(full);
    }
  }
}

// --- TEST command ---

async function cmdTest(target: string, options: Record<string, string>): Promise<void> {
  if (!target) {
    // Default: test bundled rules
    target = RULES_DIR;
  }

  const targetPath = resolve(target);
  if (!existsSync(targetPath)) {
    console.error(`${RED}Error: Not found: ${targetPath}${RESET}`);
    process.exit(1);
  }

  const jsonOutput = options['json'] === 'true';
  const rules: ATRRule[] = [];

  if (statSync(targetPath).isDirectory()) {
    rules.push(...loadRulesFromDirectory(targetPath));
  } else {
    rules.push(loadRuleFile(targetPath));
  }

  let totalTests = 0;
  let passed = 0;
  let failed = 0;
  const failures: Array<{
    ruleId: string;
    testType: string;
    input: string;
    expected: string;
    got: string;
  }> = [];

  // Map extended agent_source types to basic event-compatible source types
  // so the engine's source type filter doesn't skip rules during testing.
  // The engine only recognizes: llm_io, tool_call, mcp_exchange, agent_behavior, multi_agent_comm
  const EXTENDED_SOURCE_TO_BASE: Record<string, string> = {
    context_window: 'llm_io',
    memory_access: 'llm_io',
    skill_lifecycle: 'tool_call',
    skill_permission: 'tool_call',
    skill_chain: 'tool_call',
  };

  for (const rule of rules) {
    if (!rule.test_cases) continue;

    // For testing, normalize extended source types so the engine doesn't filter them out
    const originalSourceType = rule.agent_source?.type;
    const baseSourceType = EXTENDED_SOURCE_TO_BASE[originalSourceType ?? ''];
    const testRule = baseSourceType
      ? {
          ...rule,
          agent_source: {
            ...rule.agent_source,
            type: baseSourceType as ATRRule['agent_source']['type'],
          },
        }
      : rule;

    const engine = new ATREngine({ rules: [testRule] });
    await engine.loadRules();

    const tp = rule.test_cases.true_positives ?? [];
    const tn = rule.test_cases.true_negatives ?? [];

    for (const tc of tp) {
      totalTests++;
      const event = buildEventFromTestCase(tc as unknown as Record<string, unknown>, rule);
      const matches = engine.evaluate(event);
      const triggered = matches.some((m) => m.rule.id === rule.id);
      if (triggered) {
        passed++;
      } else {
        failed++;
        failures.push({
          ruleId: rule.id,
          testType: 'true_positive',
          input: String(tc.input ?? tc.tool_response ?? tc.agent_output ?? '').slice(0, 100),
          expected: 'triggered',
          got: 'not_triggered',
        });
      }
    }

    for (const tc of tn) {
      totalTests++;
      const event = buildEventFromTestCase(tc as unknown as Record<string, unknown>, rule);
      const matches = engine.evaluate(event);
      const triggered = matches.some((m) => m.rule.id === rule.id);
      if (!triggered) {
        passed++;
      } else {
        failed++;
        failures.push({
          ruleId: rule.id,
          testType: 'true_negative',
          input: String(tc.input ?? tc.tool_response ?? tc.agent_output ?? '').slice(0, 100),
          expected: 'not_triggered',
          got: 'triggered',
        });
      }
    }
  }

  if (jsonOutput) {
    console.log(
      JSON.stringify({ totalRules: rules.length, totalTests, passed, failed, failures }, null, 2)
    );
    return;
  }

  console.log(`\n${BOLD}ATR Test Runner${RESET}`);
  console.log(`${DIM}${'─'.repeat(60)}${RESET}`);
  console.log(`  Rules tested:    ${rules.length}`);
  console.log(`  Test cases:      ${totalTests}`);
  console.log(`  ${GREEN}Passed:${RESET}          ${passed}`);
  if (failed > 0) {
    console.log(`  ${RED}Failed:${RESET}          ${failed}`);
  }
  console.log(`${DIM}${'─'.repeat(60)}${RESET}`);

  if (failures.length > 0) {
    console.log(`\n${RED}Failures:${RESET}\n`);
    for (const f of failures) {
      console.log(`  ${RED}FAIL${RESET} ${f.ruleId} [${f.testType}]`);
      console.log(`    ${DIM}Input: "${f.input}..."${RESET}`);
      console.log(`    Expected: ${f.expected}, Got: ${f.got}\n`);
    }
    process.exit(1);
  } else {
    console.log(`\n${GREEN}All tests passed.${RESET}\n`);
  }
}

function buildEventFromTestCase(tc: Record<string, unknown>, rule: ATRRule): AgentEvent {
  // Stringify any object values
  const str = (v: unknown): string => {
    if (v === undefined || v === null) return '';
    if (typeof v === 'string') return v;
    return JSON.stringify(v);
  };

  // Extract fields, handling both flat and object-style test cases.
  // Object-style: input: { tool_name: "...", tool_args: "...", response: "..." }
  // Flat-style: input: "...", tool_response: "...", tool_name: "..."
  const rawInput = tc['input'];
  let input = '';
  let toolName = str(tc['tool_name']);
  let toolArgs = str(tc['tool_args']);
  let toolResponse = str(tc['tool_response']);
  const agentOutput = str(tc['agent_output']);

  if (
    rawInput !== null &&
    rawInput !== undefined &&
    typeof rawInput === 'object' &&
    !Array.isArray(rawInput)
  ) {
    const inputObj = rawInput as Record<string, unknown>;
    if (inputObj['tool_name'] && !toolName) toolName = str(inputObj['tool_name']);
    if (inputObj['tool_args'] && !toolArgs) toolArgs = str(inputObj['tool_args']);
    // Handle 'response' as alias for 'tool_response' (used in ATR-065 etc.)
    if (inputObj['response'] && !toolResponse) toolResponse = str(inputObj['response']);
    if (inputObj['tool_response'] && !toolResponse) toolResponse = str(inputObj['tool_response']);
    // For object inputs, use tool_args as the primary string input.
    // If no tool_args, only use JSON-stringified input as fallback when there's
    // no other meaningful field (tool_response/response) extracted.
    if (toolArgs) {
      input = toolArgs;
    } else if (!toolResponse) {
      input = str(rawInput);
    }
  } else {
    input = str(rawInput);
  }

  // Infer event type from rule's agent_source and test case structure
  const sourceType = rule.agent_source?.type ?? 'llm_io';

  const SOURCE_TO_EVENT: Record<string, AgentEvent['type']> = {
    llm_io: 'llm_input',
    tool_call: 'tool_call',
    mcp_exchange: 'tool_response',
    agent_behavior: 'agent_behavior',
    multi_agent_comm: 'multi_agent_message',
    context_window: 'llm_input',
    memory_access: 'llm_input',
    skill_lifecycle: 'tool_call',
    skill_permission: 'tool_call',
    skill_chain: 'tool_call',
  };

  let type: AgentEvent['type'] = SOURCE_TO_EVENT[sourceType] ?? 'llm_input';

  // If rule expects tool_call but test case has only plain text input
  // (no tool_name, tool_args, or tool_response), use llm_input event type
  // since the content is natural language, not a tool invocation.
  // This prevents the engine's tool_name fallback from treating text as a tool name.
  if (type === 'tool_call' && !toolName && !toolArgs && !toolResponse) {
    type = 'llm_input';
  }

  // Determine the primary content based on what the rule conditions check
  // Problem 2 & 3: For rules that check tool_response, the tool_response
  // should be the primary content when the event type resolves tool_response from content
  let content: string;
  if (toolResponse && type === 'tool_response') {
    // If event type is tool_response, engine resolves field:tool_response from event.content
    content = toolResponse;
  } else {
    content = input || toolResponse || agentOutput || '';
  }

  const fields: Record<string, string> = {};

  // Populate ALL known field aliases so the engine can resolve any field name
  if (input) fields['user_input'] = input;
  if (toolResponse) fields['tool_response'] = toolResponse;
  if (agentOutput) fields['agent_output'] = agentOutput;
  // Always set tool_name (even empty) to prevent engine fallback
  // from using event.content as tool_name for tool_call events
  fields['tool_name'] = toolName;
  if (toolArgs) fields['tool_args'] = toolArgs;

  // For content-based rules, set content and agent_message fields
  fields['content'] = content;
  fields['agent_message'] = content;

  return {
    type,
    timestamp: new Date().toISOString(),
    content,
    fields,
    sessionId: 'test-session',
    agentId: 'test-agent',
  };
}

// --- STATS command ---

function cmdStats(options: Record<string, string>): void {
  const rulesDir = options['rules'] ? resolve(options['rules']) : RULES_DIR;
  const jsonOutput = options['json'] === 'true';
  const rules = loadRulesFromDirectory(rulesDir);

  const byCategory: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  const byMaturity: Record<string, number> = {};
  const byTier: Record<string, number> = {};
  let totalTP = 0;
  let totalTN = 0;
  let totalEvasion = 0;
  let withCVE = 0;

  for (const rule of rules) {
    const cat = rule.tags?.category ?? 'unknown';
    byCategory[cat] = (byCategory[cat] ?? 0) + 1;
    bySeverity[rule.severity] = (bySeverity[rule.severity] ?? 0) + 1;

    const maturity =
      ((rule as unknown as Record<string, unknown>)['maturity'] as string) ?? 'experimental';
    byMaturity[maturity] = (byMaturity[maturity] ?? 0) + 1;

    const tier =
      ((rule as unknown as Record<string, unknown>)['detection_tier'] as string) ?? 'pattern';
    byTier[tier] = (byTier[tier] ?? 0) + 1;

    if (rule.test_cases) {
      totalTP += rule.test_cases.true_positives?.length ?? 0;
      totalTN += rule.test_cases.true_negatives?.length ?? 0;
    }

    const evasion = (rule as unknown as Record<string, unknown>)['evasion_tests'];
    if (Array.isArray(evasion)) totalEvasion += evasion.length;

    if (rule.references?.cve && rule.references.cve.length > 0) withCVE++;
  }

  if (jsonOutput) {
    console.log(
      JSON.stringify(
        {
          totalRules: rules.length,
          byCategory,
          bySeverity,
          byMaturity,
          byTier,
          testCases: { truePositives: totalTP, trueNegatives: totalTN, evasionTests: totalEvasion },
          rulesWithCVE: withCVE,
        },
        null,
        2
      )
    );
    return;
  }

  console.log(`\n${BOLD}ATR Rule Collection Statistics${RESET}`);
  console.log(`${DIM}${'─'.repeat(60)}${RESET}`);
  console.log(`  Total rules:     ${rules.length}`);
  console.log(`  True positives:  ${totalTP}`);
  console.log(`  True negatives:  ${totalTN}`);
  console.log(`  Evasion tests:   ${totalEvasion}`);
  console.log(`  Rules with CVE:  ${withCVE}`);

  console.log(`\n  ${BOLD}By Category:${RESET}`);
  for (const [cat, count] of Object.entries(byCategory).sort((a, b) => b[1] - a[1])) {
    console.log(`    ${cat.padEnd(24)} ${count}`);
  }

  console.log(`\n  ${BOLD}By Severity:${RESET}`);
  for (const sev of ['critical', 'high', 'medium', 'low', 'informational']) {
    if (bySeverity[sev]) {
      const color = SEVERITY_COLORS[sev] ?? '';
      console.log(`    ${color}${sev.padEnd(24)}${RESET} ${bySeverity[sev]}`);
    }
  }

  console.log(`\n  ${BOLD}By Maturity:${RESET}`);
  for (const [mat, count] of Object.entries(byMaturity).sort((a, b) => b[1] - a[1])) {
    console.log(`    ${mat.padEnd(24)} ${count}`);
  }

  console.log(`\n  ${BOLD}By Detection Tier:${RESET}`);
  for (const [tier, count] of Object.entries(byTier).sort((a, b) => b[1] - a[1])) {
    console.log(`    ${tier.padEnd(24)} ${count}`);
  }

  console.log('');
}

// --- MCP command ---

async function cmdMcp(): Promise<void> {
  const { startMCPServer } = await import('./mcp-server.js');
  await startMCPServer();
}

// --- SCAFFOLD command ---

async function cmdScaffold(): Promise<void> {
  const { createInterface } = await import('node:readline');
  const { RuleScaffolder } = await import('./rule-scaffolder.js');

  const rl = createInterface({ input: process.stdin, output: process.stdout });

  const ask = (question: string): Promise<string> =>
    new Promise((resolve) => rl.question(question, resolve));

  console.log(`\n${BOLD}ATR Rule Scaffolder${RESET}`);
  console.log(`${DIM}Generate a draft ATR detection rule interactively.${RESET}\n`);

  const title = await ask('Rule title: ');
  if (!title.trim()) {
    console.error(`${RED}Error: Title is required.${RESET}`);
    rl.close();
    process.exit(1);
  }

  const categories = [
    'prompt-injection',
    'tool-poisoning',
    'context-exfiltration',
    'agent-manipulation',
    'privilege-escalation',
    'excessive-autonomy',
    'data-poisoning',
    'model-abuse',
    'skill-compromise',
  ];
  console.log(`\nCategories: ${categories.join(', ')}`);
  const category = await ask('Category: ');
  if (!categories.includes(category.trim())) {
    console.error(`${RED}Error: Invalid category.${RESET}`);
    rl.close();
    process.exit(1);
  }

  const attackDescription = await ask('Attack description: ');
  if (!attackDescription.trim()) {
    console.error(`${RED}Error: Description is required.${RESET}`);
    rl.close();
    process.exit(1);
  }

  console.log('\nEnter example payloads (one per line, empty line to finish):');
  const payloads: string[] = [];
  while (true) {
    const payload = await ask(`  Payload ${payloads.length + 1}: `);
    if (!payload.trim()) break;
    payloads.push(payload.trim());
  }

  if (payloads.length === 0) {
    console.error(`${RED}Error: At least one example payload is required.${RESET}`);
    rl.close();
    process.exit(1);
  }

  const severities = ['critical', 'high', 'medium', 'low', 'informational'];
  const severity = await ask(`Severity [${severities.join('/')}] (default: medium): `);
  const finalSeverity =
    severity.trim() && severities.includes(severity.trim()) ? severity.trim() : 'medium';

  rl.close();

  const scaffolder = new RuleScaffolder();
  const result = scaffolder.scaffold({
    title: title.trim(),
    category: category.trim() as import('./types.js').ATRCategory,
    attackDescription: attackDescription.trim(),
    examplePayloads: payloads,
    severity: finalSeverity as import('./types.js').ATRSeverity,
  });

  console.log(`\n${GREEN}Generated rule ${result.id}:${RESET}\n`);
  console.log(`${DIM}${'─'.repeat(60)}${RESET}`);
  console.log(result.yaml);
  console.log(`${DIM}${'─'.repeat(60)}${RESET}`);

  if (result.warnings.length > 0) {
    console.log(`\n${BOLD}Warnings:${RESET}`);
    for (const w of result.warnings) {
      console.log(`  - ${w}`);
    }
  }

  console.log(
    `\n${DIM}Copy this YAML to a .yaml file in rules/${category.trim()}/ and validate with: atr validate <file>${RESET}\n`
  );
}

// --- SUBMIT command ---

async function cmdSubmit(target: string, options: Record<string, string>): Promise<void> {
  if (!target) {
    console.error(`${RED}Error: Missing rule file. Usage: atr submit <rule.yaml>${RESET}`);
    process.exit(1);
  }

  const targetPath = resolve(target);
  if (!existsSync(targetPath)) {
    console.error(`${RED}Error: File not found: ${targetPath}${RESET}`);
    process.exit(1);
  }

  // Load and validate the rule first
  let rule: ATRRule;
  try {
    rule = loadRuleFile(targetPath);
    const validation = validateRule(rule);
    if (!validation.valid) {
      console.error(`${RED}Rule validation failed:${RESET}`);
      for (const err of validation.errors) {
        console.error(`  ${RED}${err}${RESET}`);
      }
      console.error(`\n${DIM}Fix validation errors before submitting.${RESET}`);
      process.exit(1);
    }
  } catch (e) {
    console.error(
      `${RED}Error loading rule: ${e instanceof Error ? e.message : String(e)}${RESET}`
    );
    process.exit(1);
  }

  const endpoint =
    options['endpoint'] ?? process.env['THREAT_CLOUD_ENDPOINT'] ?? 'https://cloud.panguard.ai';
  const apiKey = process.env['THREAT_CLOUD_API_KEY'];

  // Read raw YAML content for submission
  const ruleContent = readFileSync(targetPath, 'utf-8');

  // Generate pattern hash from rule ID
  const { createHash } = await import('node:crypto');
  const patternHash = createHash('sha256').update(rule.id).digest('hex').slice(0, 16);

  console.log(`\n${BOLD}ATR Rule Submission${RESET}`);
  console.log(`${DIM}${'─'.repeat(60)}${RESET}`);
  console.log(`  Rule:      ${rule.id} - ${rule.title}`);
  console.log(`  Severity:  ${SEVERITY_COLORS[rule.severity] ?? ''}${rule.severity}${RESET}`);
  console.log(`  Category:  ${rule.tags?.category ?? 'unknown'}`);
  console.log(`  Endpoint:  ${endpoint}`);
  console.log(`${DIM}${'─'.repeat(60)}${RESET}`);

  try {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (apiKey) {
      headers['Authorization'] = `Bearer ${apiKey}`;
    }

    const response = await fetch(`${endpoint}/api/atr-proposals`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        patternHash,
        ruleContent,
        llmProvider: 'human',
        llmModel: 'manual-submission',
        selfReviewVerdict: JSON.stringify({ verdict: 'approved', source: 'author' }),
      }),
      signal: AbortSignal.timeout(10_000),
    });

    const result = (await response.json()) as { ok: boolean; data?: unknown; error?: string };

    if (result.ok) {
      console.log(`\n${GREEN}Submitted successfully.${RESET}`);
      console.log(`${DIM}Your rule will go through community consensus voting.${RESET}`);
      console.log(`${DIM}Check status: atr submit --status ${patternHash}${RESET}\n`);
    } else {
      console.error(`\n${RED}Submission failed: ${result.error ?? 'Unknown error'}${RESET}\n`);
      process.exit(1);
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`\n${RED}Failed to connect to Threat Cloud: ${msg}${RESET}`);
    console.error(`${DIM}Check your endpoint URL and network connection.${RESET}\n`);
    process.exit(1);
  }
}

// --- Main ---

async function main(): Promise<void> {
  const { command, target, options } = parseArgs(process.argv);

  if (command === 'help' || options['help']) {
    printUsage();
    return;
  }

  switch (command) {
    case 'scan':
      await cmdScan(target, options);
      break;
    case 'validate':
      cmdValidate(target, options);
      break;
    case 'test':
      await cmdTest(target, options);
      break;
    case 'stats':
      cmdStats(options);
      break;
    case 'mcp':
      await cmdMcp();
      break;
    case 'scaffold':
      await cmdScaffold();
      break;
    case 'submit':
      await cmdSubmit(target, options);
      break;
    default:
      console.error(`${RED}Unknown command: ${command}${RESET}`);
      printUsage();
      process.exit(1);
  }
}

main().catch((err) => {
  console.error(`${RED}Error: ${err instanceof Error ? err.message : String(err)}${RESET}`);
  process.exit(1);
});
