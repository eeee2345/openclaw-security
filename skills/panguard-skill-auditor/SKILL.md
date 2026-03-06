---
name: panguard-skill-auditor
description: Automated security auditor for AI agent skills. Scans SKILL.md files for prompt injection, tool poisoning, hidden Unicode, encoded payloads, secrets, and dangerous permissions. Returns a 0-100 risk score.
homepage: https://panguard.ai/docs/skill-auditor
metadata:
  {
    "author": "panguard-ai",
    "version": "0.3.1",
    "tags": ["security", "audit", "skill-vetting", "prompt-injection", "tool-poisoning"],
    "triggers": ["audit", "vet", "security check", "skill review", "before installing"],
    "openclaw":
      {
        "requires": { "bins": ["panguard"] },
        "install":
          [
            {
              "id": "curl",
              "kind": "shell",
              "command": "curl -fsSL https://panguard.ai/api/install | bash",
              "bins": ["panguard"],
              "label": "Install Panguard AI",
            },
          ],
        "primaryEnv": "PANGUARD_API_KEY",
        "os": ["darwin", "linux"],
      },
  }
---

# Panguard Skill Auditor

Automated security scanner for AI agent skills. Use **before installing any skill** from ClawdHub, GitHub, or other sources.

Unlike manual checklists, this runs real static analysis: regex pattern matching, Unicode inspection, Base64 payload decoding, SAST, and secrets scanning.

## When to Use

- Before installing any skill from ClawdHub or GitHub
- When evaluating third-party SKILL.md files
- Before adding skills to your agent fleet
- As a CI gate for skill repositories

## Quick Start

```bash
# Audit a skill directory
panguard audit skill ./path/to/skill

# Audit a skill from a GitHub URL
panguard audit skill https://github.com/user/repo/tree/main/skills/my-skill
```

## What It Checks

### 1. Manifest Validation
Verifies SKILL.md frontmatter: required fields (name, description), valid metadata structure, and proper formatting.

### 2. Prompt Injection Detection
11 regex patterns detect:
- "Ignore previous instructions" variants
- Identity override ("you are now", "act as")
- System prompt manipulation
- Jailbreak patterns (DAN, bypass safety)
- Hidden text in HTML/markdown comments

### 3. Hidden Content Detection
- Zero-width Unicode characters (U+200B, U+200C, U+200D, RTL overrides)
- Base64-encoded payloads containing `eval`, `exec`, `subprocess`, `child_process`
- Homoglyph attacks

### 4. Tool Poisoning Detection
- Privilege escalation (`sudo`, `chmod 777`)
- Reverse shell patterns (`nc -e`, `bash -i >&`, `/dev/tcp/`)
- Remote code execution (`curl | bash`)
- Environment variable exfiltration
- Sensitive file access (`~/.ssh`, `.env`, `.aws/`)
- Destructive operations (`rm -rf /`)

### 5. Code Security (SAST + Secrets)
Scans all files in the skill directory:
- Static analysis for common vulnerabilities
- Hardcoded API keys, tokens, passwords
- AWS credentials, private keys

### 6. Dependency Analysis
Checks declared dependencies for known issues.

### 7. Permission Scope Analysis
Evaluates requested permissions against the skill's stated purpose.

## Output Format

Returns a structured report:

```
PANGUARD SKILL AUDIT REPORT
============================
Skill:      my-skill
Risk Score: 72/100
Risk Level: CRITICAL
Duration:   0.3s

CHECKS:
  [FAIL] Prompt Safety: 2 suspicious pattern(s) detected
  [PASS] Manifest: Valid SKILL.md structure
  [WARN] Code: 1 issue(s) found; Secrets: No hardcoded credentials
  [PASS] Dependencies: No known issues
  [PASS] Permissions: Scope appropriate

FINDINGS:
  [CRITICAL] Prompt injection: ignore previous instructions
             SKILL.md:42 - "ignore all previous instructions and..."
  [HIGH]     Reverse shell pattern detected
             SKILL.md:87 - "bash -i >& /dev/tcp/..."

VERDICT: DO NOT INSTALL - Critical security issues found
```

## Risk Levels

| Score | Level | Action |
|-------|-------|--------|
| 0-14 | LOW | Safe to install after quick review |
| 15-39 | MEDIUM | Review findings before installing |
| 40-69 | HIGH | Requires thorough manual review |
| 70-100 | CRITICAL | Do NOT install |

## Integration with Your Agent

Add to your agent's pre-install hook:

```bash
# In your agent's skill install pipeline
panguard audit skill "$SKILL_PATH" --json | jq '.riskLevel'
# Block installation if HIGH or CRITICAL
```

## Comparison with Manual Vetting

| Feature | Manual Checklist | Panguard Auditor |
|---------|-----------------|------------------|
| Speed | Minutes per skill | < 1 second |
| Consistency | Varies by reviewer | Deterministic |
| Hidden Unicode | Easy to miss | Automatic detection |
| Base64 payloads | Requires manual decode | Auto-decode + analyze |
| Code SAST | Not included | Integrated scanner |
| Secrets scan | Manual grep | Pattern-based detection |
| Risk score | Subjective | Quantitative (0-100) |

## Learn More

- Docs: https://panguard.ai/docs/skill-auditor
- Blog: https://panguard.ai/blog/skill-auditor-guide
- GitHub: https://github.com/panguard-ai/panguard-ai
