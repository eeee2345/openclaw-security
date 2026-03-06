/**
 * SKILL.md manifest parser
 * SKILL.md 清單解析器
 *
 * Parses YAML frontmatter from SKILL.md files following the AgentSkills spec.
 * 解析遵循 AgentSkills 規範的 SKILL.md 檔案中的 YAML frontmatter。
 *
 * @module @panguard-ai/panguard-skill-auditor/manifest-parser
 */

import { promises as fs } from 'node:fs';
import path from 'node:path';
import yaml from 'js-yaml';
import type { SkillManifest, SkillMetadata } from './types.js';

const FRONTMATTER_RE = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/;

/**
 * Parse a SKILL.md file and extract manifest + instructions.
 * 解析 SKILL.md 檔案並擷取清單和指令。
 */
export async function parseSkillManifest(skillDir: string): Promise<SkillManifest | null> {
  const skillPath = path.join(skillDir, 'SKILL.md');

  let content: string;
  try {
    content = await fs.readFile(skillPath, 'utf-8');
  } catch {
    return null;
  }

  const match = FRONTMATTER_RE.exec(content);
  if (!match) {
    // No frontmatter — treat entire content as instructions
    return {
      name: path.basename(skillDir),
      description: '',
      instructions: content,
    };
  }

  const [, frontmatterRaw, instructions] = match;

  let parsed: Record<string, unknown>;
  try {
    parsed = (yaml.load(frontmatterRaw ?? '') as Record<string, unknown>) ?? {};
  } catch {
    return {
      name: path.basename(skillDir),
      description: '',
      instructions: instructions ?? content,
    };
  }

  // Parse metadata — can be a JSON string or an object
  let metadata: SkillMetadata | undefined;
  if (typeof parsed['metadata'] === 'string') {
    try {
      metadata = JSON.parse(parsed['metadata']) as SkillMetadata;
    } catch {
      metadata = undefined;
    }
  } else if (typeof parsed['metadata'] === 'object' && parsed['metadata'] !== null) {
    metadata = parsed['metadata'] as SkillMetadata;
  }

  return {
    name: (parsed['name'] as string) ?? path.basename(skillDir),
    description: (parsed['description'] as string) ?? '',
    license: parsed['license'] as string | undefined,
    homepage: parsed['homepage'] as string | undefined,
    userInvocable: parsed['user-invocable'] as boolean | undefined,
    disableModelInvocation: parsed['disable-model-invocation'] as boolean | undefined,
    commandDispatch: parsed['command-dispatch'] as string | undefined,
    commandTool: parsed['command-tool'] as string | undefined,
    metadata,
    instructions: instructions ?? '',
  };
}
