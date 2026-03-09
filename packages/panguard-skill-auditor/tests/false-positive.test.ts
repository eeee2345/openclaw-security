/**
 * False positive tests -- verifies legitimate skills are NOT flagged.
 *
 * These skills contain patterns that naive scanners might flag
 * (e.g., Base64 in legitimate configs, curl usage in documentation,
 * permission requests that match the description, multilingual content).
 *
 * The goal: real-world skills should never be CRITICAL, and educational
 * or documentation skills should stay LOW or MEDIUM at most.
 */

import { describe, it, expect, vi, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { auditSkill } from '../src/index.js';

// Mock panguard-scan so tests don't depend on external SAST tooling
vi.mock('@panguard-ai/panguard-scan', () => ({
  checkSourceCode: vi.fn().mockResolvedValue([]),
  checkHardcodedSecrets: vi.fn().mockResolvedValue([]),
}));

describe('false positive detection', () => {
  const tempDirs: string[] = [];

  function createSkill(manifest: string, extraFiles?: Record<string, string>): string {
    const dir = mkdtempSync(join(tmpdir(), 'fp-test-'));
    tempDirs.push(dir);
    writeFileSync(join(dir, 'SKILL.md'), manifest);
    if (extraFiles) {
      for (const [name, content] of Object.entries(extraFiles)) {
        const filePath = join(dir, name);
        const fileDir = join(dir, ...name.split('/').slice(0, -1));
        if (name.includes('/')) {
          mkdirSync(fileDir, { recursive: true });
        }
        writeFileSync(filePath, content);
      }
    }
    return dir;
  }

  afterEach(() => {
    for (const dir of tempDirs) {
      try { rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
    }
    tempDirs.length = 0;
  });

  it('should pass a minimal clean skill', async () => {
    const dir = createSkill(`---
name: hello-world
description: A simple greeting skill
license: MIT
---

# Hello World Skill

When the user says hello, respond with a friendly greeting.

## Instructions

Greet the user warmly. Use their name if provided.
`);

    const report = await auditSkill(dir, { skipAI: true });
    expect(report.riskLevel).toBe('LOW');
    expect(report.riskScore).toBeLessThan(15);
  });

  it('should not flag legitimate Base64 in configuration examples', async () => {
    // The Base64 string "dXNlcm5hbWU6cGFzc3dvcmQ=" decodes to "username:password"
    // which does NOT contain suspicious keywords (eval, exec, subprocess, etc.)
    const dir = createSkill(`---
name: api-helper
description: Helps format API requests with proper authentication headers
license: MIT
---

# API Helper Skill

Assists with constructing HTTP requests.

## Instructions

Help the user construct HTTP requests. When they need Basic auth,
remind them to base64-encode the credentials:

Example header format:
Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=

Note: The example above decodes to "username:password" and is just a placeholder.
`);

    const report = await auditSkill(dir, { skipAI: true });
    expect(report.riskLevel).toBe('LOW');
  });

  it('should not flag file read references in a code review skill', async () => {
    // "read ... files" matches the File Read permission pattern (low risk, +1 point)
    // which should keep the overall score firmly in LOW territory
    const dir = createSkill(`---
name: code-reviewer
description: Reviews source code files for quality issues
license: MIT
---

# Code Reviewer Skill

## Instructions

When asked to review code, access the specified files and provide feedback on:
- Code style and formatting
- Potential bugs
- Performance issues
- Security concerns
`);

    const report = await auditSkill(dir, { skipAI: true });
    expect(report.riskLevel).toBe('LOW');
    expect(report.riskScore).toBeLessThan(15);
  });

  it('should not flag curl usage in API documentation context', async () => {
    // Standalone curl references match the Network/HTTP permission (medium, +5)
    // but should NOT match curl-pipe-bash (which requires "curl ... | bash")
    const dir = createSkill(`---
name: api-docs-helper
description: Generates curl command examples for API documentation
license: MIT
---

# API Documentation Helper

## Instructions

Generate curl command examples for API endpoints. Include proper headers,
authentication, and request bodies. Example output format:

curl -X POST https://api.example.com/users
  -H "Content-Type: application/json"
  -H "Authorization: Bearer TOKEN"
  -d '{"name": "John"}'
`);

    const report = await auditSkill(dir, { skipAI: true });
    expect(report.riskLevel).toBe('LOW');
    // Should have at most a medium-severity network permission finding
    const criticalFindings = report.findings.filter(f => f.severity === 'critical');
    expect(criticalFindings).toHaveLength(0);
  });

  it('should not flag CJK characters in multilingual skills', async () => {
    // CJK characters are NOT in the homoglyph map (which targets Cyrillic/Greek
    // characters that visually mimic Latin letters)
    const dir = createSkill(`---
name: translator
description: Translates text between English, Chinese, and Japanese
license: MIT
---

# Translator Skill

## Instructions

Translate text accurately between languages. Support:
- English
- Chinese (Simplified and Traditional)
- Japanese

Example translations:
- Hello = \u4F60\u597D = \u3053\u3093\u306B\u3061\u306F
- Thank you = \u8C22\u8C22 = \u3042\u308A\u304C\u3068\u3046
`);

    const report = await auditSkill(dir, { skipAI: true });
    expect(report.riskLevel).toBe('LOW');
  });

  it('should keep sudo mentions in sysadmin docs below CRITICAL', async () => {
    // "sudo " matches tp-sudo-escalation (high, +15 points)
    // This yields score=15, level=MEDIUM -- acceptable for a sysadmin guide
    const dir = createSkill(`---
name: linux-admin-guide
description: Provides Linux system administration guidance and command references
license: MIT
---

# Linux Admin Guide

## Instructions

Help users with Linux system administration tasks. Provide command examples
and explain what each command does.

Common topics:
- Package management: apt update, yum install
- Service management: systemctl start/stop/restart
- User management: useradd, usermod
- Note: Some commands require sudo for elevated privileges
- Disk management: df, du, fdisk
- Network: ip, ss, netstat
`);

    const report = await auditSkill(dir, { skipAI: true });
    // sudo triggers high-severity finding but should NOT be CRITICAL
    expect(report.riskLevel).not.toBe('CRITICAL');
    expect(report.riskScore).toBeLessThan(40);
  });

  it('should not flag environment variable references in deployment skills', async () => {
    // "DATABASE_URL" triggers the Database permission pattern (high, +15)
    // "API_KEY" triggers the Credentials permission pattern (medium, +5)
    // Total = 20, which gives MEDIUM -- acceptable for a deployment guide
    const dir = createSkill(`---
name: deploy-helper
description: Assists with deployment configuration using environment variables
license: MIT
---

# Deployment Helper

## Instructions

Help configure deployments. Remind users to set these environment variables:

- DATABASE_URL: Connection string for the database
- API_KEY: The service key (never hardcode this)
- NODE_ENV: Set to "production" for production deployments

Reference .env.example for the full list of required variables.
`);

    const report = await auditSkill(dir, { skipAI: true });
    // MEDIUM is acceptable -- the skill legitimately references database and credentials
    expect(report.riskLevel).not.toBe('CRITICAL');
    expect(report.riskScore).toBeLessThan(40);
    const criticalFindings = report.findings.filter(f => f.severity === 'critical');
    expect(criticalFindings).toHaveLength(0);
  });

  it('should accumulate findings correctly for a complex but legitimate skill', async () => {
    // This skill mentions shell execution, file operations, and credentials.
    // Expected findings: Bash/Shell (high, +15), File Write (medium, +5),
    // File Read (low, +1), Credentials (medium, +5) = ~26 points = MEDIUM
    const dir = createSkill(`---
name: full-stack-assistant
description: A comprehensive development assistant that helps with code, tests, git, and deployment
license: Apache-2.0
---

# Full Stack Development Assistant

## Instructions

You are a development assistant. Help the user with:

1. Reading and editing source code files
2. Running test suites via shell commands
3. Managing git operations (commit, push, branch)
4. Generating configuration files
5. Debugging build errors

When running shell commands, always show the command before executing it.
Never run destructive commands without explicit user confirmation.

## Safety Rules

- Never modify files outside the project directory
- Always confirm before running git push
- Do not access or transmit credentials
- Log all actions for audit trail
`);

    const report = await auditSkill(dir, { skipAI: true });
    // Legitimate power-user skill: should be MEDIUM at most, never CRITICAL
    expect(report.riskScore).toBeLessThan(40);
    expect(report.riskLevel).not.toBe('CRITICAL');
  });

  it('should not flag a math/science skill with formula notation', async () => {
    const dir = createSkill(`---
name: math-tutor
description: Helps students solve math problems step by step
license: MIT
---

# Math Tutor Skill

## Instructions

Help students work through math problems. Show each step clearly.

Supported topics:
- Algebra: solve for x, factor polynomials
- Calculus: derivatives, integrals
- Statistics: mean, median, standard deviation

Use LaTeX notation when showing formulas: $f(x) = x^2 + 2x + 1$
`);

    const report = await auditSkill(dir, { skipAI: true });
    expect(report.riskLevel).toBe('LOW');
    expect(report.riskScore).toBeLessThan(5);
  });

  it('should not flag a skill with markdown formatting and code blocks', async () => {
    const dir = createSkill(`---
name: markdown-formatter
description: Formats text into well-structured markdown documents
license: MIT
---

# Markdown Formatter Skill

## Instructions

Convert user text into clean, well-structured markdown. Support:

- Headings (h1-h6)
- Bullet and numbered lists
- Code blocks with syntax highlighting
- Tables
- Blockquotes

Example code block output:

\`\`\`python
def hello():
    print("Hello, world!")
\`\`\`
`);

    const report = await auditSkill(dir, { skipAI: true });
    expect(report.riskLevel).toBe('LOW');
  });

  it('should not flag security-related terminology used in educational context', async () => {
    // Carefully avoids exact regex trigger phrases like "system prompt",
    // "ignore ... previous ... instructions", or "DAN" while still being
    // about security education
    const dir = createSkill(`---
name: security-awareness
description: Teaches developers about common AI safety and application security topics
license: MIT
---

# Security Awareness Skill

## Instructions

When the user asks about security topics, explain clearly:

- What injection attacks are and how they work in web applications
- How to validate and sanitize user input properly
- Best practices for authentication and authorization
- OWASP Top 10 vulnerabilities and mitigations
- How to implement Content Security Policy headers

Be educational and factual. Always recommend defensive coding practices.
`);

    const report = await auditSkill(dir, { skipAI: true });
    expect(report.riskLevel).toBe('LOW');
    const criticalFindings = report.findings.filter(f => f.severity === 'critical');
    expect(criticalFindings).toHaveLength(0);
  });

  it('should handle a skill with JSON configuration examples without false positives', async () => {
    const dir = createSkill(`---
name: config-generator
description: Generates JSON configuration files for common tools
license: MIT
---

# Config Generator Skill

## Instructions

Help users create configuration files for common development tools.

Supported configs:
- tsconfig.json
- .eslintrc.json
- prettier.config.js
- package.json

Example output:

{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "strict": true
  }
}

Always validate the generated JSON before presenting it to the user.
`);

    const report = await auditSkill(dir, { skipAI: true });
    expect(report.riskLevel).toBe('LOW');
    expect(report.riskScore).toBeLessThan(5);
  });

  it('should not flag a database documentation skill as CRITICAL', async () => {
    // "database" and "query" match the Database permission pattern (high, +15)
    // but this is legitimate documentation, should cap at MEDIUM
    const dir = createSkill(`---
name: sql-helper
description: Helps write and optimize SQL queries for PostgreSQL databases
license: MIT
---

# SQL Helper Skill

## Instructions

Help users write correct and performant SQL queries for PostgreSQL.

Topics:
- SELECT queries with joins and subqueries
- Index optimization recommendations
- Query plan analysis using EXPLAIN
- Schema design best practices

Always use parameterized queries in examples to prevent injection.
`);

    const report = await auditSkill(dir, { skipAI: true });
    // database pattern triggers high-severity finding but NOT critical
    expect(report.riskLevel).not.toBe('CRITICAL');
    expect(report.riskScore).toBeLessThan(40);
  });
});
