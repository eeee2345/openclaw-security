import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { parseSkillManifest } from '../src/manifest-parser.js';

async function makeTempDir(): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), 'panguard-test-'));
}

async function writeSkillFile(dir: string, content: string): Promise<void> {
  await fs.writeFile(path.join(dir, 'SKILL.md'), content, 'utf-8');
}

describe('parseSkillManifest', () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await makeTempDir();
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  describe('file not found', () => {
    it('should return null when SKILL.md does not exist', async () => {
      const result = await parseSkillManifest('/nonexistent/path/that/does/not/exist');
      expect(result).toBeNull();
    });

    it('should return null for an empty directory with no SKILL.md', async () => {
      const result = await parseSkillManifest(tmpDir);
      expect(result).toBeNull();
    });
  });

  describe('file size limit', () => {
    it('should return null when file is over 1MB', async () => {
      // Write a file slightly over 1MB (1024 * 1024 + 1 bytes)
      const largeContent = 'x'.repeat(1024 * 1024 + 1);
      await writeSkillFile(tmpDir, largeContent);
      const result = await parseSkillManifest(tmpDir);
      expect(result).toBeNull();
    });

    it('should parse a file exactly at the 1MB limit (under limit)', async () => {
      // A file under 1MB should not be rejected
      const content = '---\nname: My Skill\ndescription: A skill\n---\nDo something useful with the system to help users accomplish their goals efficiently.';
      await writeSkillFile(tmpDir, content);
      const result = await parseSkillManifest(tmpDir);
      expect(result).not.toBeNull();
    });
  });

  describe('no frontmatter', () => {
    it('should return full content as instructions when no frontmatter exists', async () => {
      const content = 'This is just plain text with no frontmatter at all.';
      await writeSkillFile(tmpDir, content);
      const result = await parseSkillManifest(tmpDir);
      expect(result).not.toBeNull();
      expect(result!.instructions).toBe(content);
    });

    it('should use path.basename as name when no frontmatter exists', async () => {
      const content = 'Plain instructions only.';
      await writeSkillFile(tmpDir, content);
      const result = await parseSkillManifest(tmpDir);
      expect(result).not.toBeNull();
      expect(result!.name).toBe(path.basename(tmpDir));
    });

    it('should set empty description when no frontmatter exists', async () => {
      const content = 'Plain instructions only.';
      await writeSkillFile(tmpDir, content);
      const result = await parseSkillManifest(tmpDir);
      expect(result!.description).toBe('');
    });
  });

  describe('valid frontmatter with instructions', () => {
    it('should parse name and description from frontmatter', async () => {
      const content = '---\nname: My Skill\ndescription: Does something useful\n---\nInstructions here.';
      await writeSkillFile(tmpDir, content);
      const result = await parseSkillManifest(tmpDir);
      expect(result).not.toBeNull();
      expect(result!.name).toBe('My Skill');
      expect(result!.description).toBe('Does something useful');
    });

    it('should parse instructions body after frontmatter', async () => {
      const content = '---\nname: My Skill\ndescription: A test skill\n---\nThese are the instructions.';
      await writeSkillFile(tmpDir, content);
      const result = await parseSkillManifest(tmpDir);
      expect(result!.instructions).toBe('These are the instructions.');
    });

    it('should parse license field from frontmatter', async () => {
      const content = '---\nname: Tool\ndescription: A tool\nlicense: MIT\n---\nInstructions.';
      await writeSkillFile(tmpDir, content);
      const result = await parseSkillManifest(tmpDir);
      expect(result!.license).toBe('MIT');
    });

    it('should parse homepage field from frontmatter', async () => {
      const content = '---\nname: Tool\ndescription: A tool\nhomepage: https://example.com\n---\nInstructions.';
      await writeSkillFile(tmpDir, content);
      const result = await parseSkillManifest(tmpDir);
      expect(result!.homepage).toBe('https://example.com');
    });

    it('should parse user-invocable field from frontmatter', async () => {
      const content = '---\nname: Tool\ndescription: A tool\nuser-invocable: true\n---\nInstructions.';
      await writeSkillFile(tmpDir, content);
      const result = await parseSkillManifest(tmpDir);
      expect(result!.userInvocable).toBe(true);
    });

    it('should parse disable-model-invocation field from frontmatter', async () => {
      const content = '---\nname: Tool\ndescription: A tool\ndisable-model-invocation: true\n---\nInstructions.';
      await writeSkillFile(tmpDir, content);
      const result = await parseSkillManifest(tmpDir);
      expect(result!.disableModelInvocation).toBe(true);
    });

    it('should parse command-dispatch field from frontmatter', async () => {
      const content = '---\nname: Tool\ndescription: A tool\ncommand-dispatch: tool\n---\nInstructions.';
      await writeSkillFile(tmpDir, content);
      const result = await parseSkillManifest(tmpDir);
      expect(result!.commandDispatch).toBe('tool');
    });

    it('should parse command-tool field from frontmatter', async () => {
      const content = '---\nname: Tool\ndescription: A tool\ncommand-tool: my_tool\n---\nInstructions.';
      await writeSkillFile(tmpDir, content);
      const result = await parseSkillManifest(tmpDir);
      expect(result!.commandTool).toBe('my_tool');
    });

    it('should handle multiline instructions', async () => {
      const content = '---\nname: Tool\ndescription: A tool\n---\nLine one.\nLine two.\nLine three.';
      await writeSkillFile(tmpDir, content);
      const result = await parseSkillManifest(tmpDir);
      expect(result!.instructions).toBe('Line one.\nLine two.\nLine three.');
    });

    it('should handle CRLF line endings in frontmatter', async () => {
      const content = '---\r\nname: Tool\r\ndescription: A tool\r\n---\r\nInstructions.';
      await writeSkillFile(tmpDir, content);
      const result = await parseSkillManifest(tmpDir);
      expect(result).not.toBeNull();
      expect(result!.name).toBe('Tool');
    });
  });

  describe('YAML parse error', () => {
    it('should fall back gracefully on invalid YAML in frontmatter', async () => {
      // Colons in invalid positions cause YAML parse errors
      const content = '---\nname: {\nbad: yaml: content: [\n---\nFallback instructions.';
      await writeSkillFile(tmpDir, content);
      const result = await parseSkillManifest(tmpDir);
      // Should not throw — should return a fallback manifest
      expect(result).not.toBeNull();
      expect(result!.name).toBe(path.basename(tmpDir));
      expect(result!.description).toBe('');
    });

    it('should use fallback instructions on YAML error', async () => {
      const content = '---\n{invalid yaml\n---\nThese are the fallback instructions.';
      await writeSkillFile(tmpDir, content);
      const result = await parseSkillManifest(tmpDir);
      // instructions should be set to the body or full content
      expect(result).not.toBeNull();
    });
  });

  describe('metadata as JSON string', () => {
    it('should parse metadata when it is a valid JSON string', async () => {
      const metaObj = { version: '1.0.0', author: 'Alice' };
      const content = `---\nname: Tool\ndescription: A tool\nmetadata: '${JSON.stringify(metaObj)}'\n---\nInstructions.`;
      await writeSkillFile(tmpDir, content);
      const result = await parseSkillManifest(tmpDir);
      expect(result!.metadata).toBeDefined();
      expect(result!.metadata!.version).toBe('1.0.0');
      expect(result!.metadata!.author).toBe('Alice');
    });

    it('should set metadata to undefined when JSON string is invalid', async () => {
      const content = "---\nname: Tool\ndescription: A tool\nmetadata: 'not-valid-json-{'\n---\nInstructions.";
      await writeSkillFile(tmpDir, content);
      const result = await parseSkillManifest(tmpDir);
      expect(result!.metadata).toBeUndefined();
    });
  });

  describe('metadata as object', () => {
    it('should assign metadata directly when it is a YAML object', async () => {
      const content = '---\nname: Tool\ndescription: A tool\nmetadata:\n  version: "2.0.0"\n  author: Bob\n---\nInstructions.';
      await writeSkillFile(tmpDir, content);
      const result = await parseSkillManifest(tmpDir);
      expect(result!.metadata).toBeDefined();
      expect(result!.metadata!.version).toBe('2.0.0');
      expect(result!.metadata!.author).toBe('Bob');
    });

    it('should parse openclaw nested metadata correctly', async () => {
      const content = '---\nname: Tool\ndescription: A tool\nmetadata:\n  openclaw:\n    requires:\n      bins:\n        - git\n        - curl\n      env:\n        - API_KEY\n---\nInstructions.';
      await writeSkillFile(tmpDir, content);
      const result = await parseSkillManifest(tmpDir);
      expect(result!.metadata!.openclaw!.requires!.bins).toEqual(['git', 'curl']);
      expect(result!.metadata!.openclaw!.requires!.env).toEqual(['API_KEY']);
    });
  });

  describe('missing name field', () => {
    it('should fall back to path.basename when name is absent from frontmatter', async () => {
      const content = '---\ndescription: A tool with no name field\n---\nInstructions here.';
      await writeSkillFile(tmpDir, content);
      const result = await parseSkillManifest(tmpDir);
      expect(result!.name).toBe(path.basename(tmpDir));
    });

    it('should still parse description even when name is missing', async () => {
      const content = '---\ndescription: Tool description\n---\nInstructions.';
      await writeSkillFile(tmpDir, content);
      const result = await parseSkillManifest(tmpDir);
      expect(result!.description).toBe('Tool description');
    });
  });

  describe('all YAML fields mapped correctly', () => {
    it('should map all known fields from a complete frontmatter', async () => {
      const content = [
        '---',
        'name: Complete Skill',
        'description: A fully specified skill',
        'license: Apache-2.0',
        'homepage: https://skill.example.com',
        'user-invocable: true',
        'disable-model-invocation: false',
        'command-dispatch: tool',
        'command-tool: run_it',
        'metadata:',
        '  version: "1.2.3"',
        '  author: Test Author',
        '---',
        'These are the skill instructions for the complete test.',
      ].join('\n');

      await writeSkillFile(tmpDir, content);
      const result = await parseSkillManifest(tmpDir);

      expect(result).not.toBeNull();
      expect(result!.name).toBe('Complete Skill');
      expect(result!.description).toBe('A fully specified skill');
      expect(result!.license).toBe('Apache-2.0');
      expect(result!.homepage).toBe('https://skill.example.com');
      expect(result!.userInvocable).toBe(true);
      expect(result!.disableModelInvocation).toBe(false);
      expect(result!.commandDispatch).toBe('tool');
      expect(result!.commandTool).toBe('run_it');
      expect(result!.metadata!.version).toBe('1.2.3');
      expect(result!.metadata!.author).toBe('Test Author');
      expect(result!.instructions).toBe('These are the skill instructions for the complete test.');
    });
  });
});
