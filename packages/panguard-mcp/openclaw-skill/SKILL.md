---
name: panguard
description: AI agent security platform — audit skills, scan for threats, and run 24/7 protection with 9,700+ detection rules
homepage: https://panguard.ai
license: MIT
metadata: { "openclaw": { "requires": { "bins": ["npx"] }, "install": [{ "id": "node", "kind": "node", "package": "@panguard-ai/panguard", "bins": ["panguard"], "label": "Install Panguard AI via npm" }] } }
---

# Panguard AI — Security for AI Agents

Panguard protects AI agents from prompt injection, tool poisoning, data exfiltration, and 9 other threat categories using 9,700+ detection rules (Sigma + YARA + ATR).

## Available Commands

### Audit installed skills for security threats
```bash
panguard audit skill .
```
Scans all SKILL.md files in the current directory and subdirectories. Reports risk level, flagged patterns, and recommendations.

### Quick security scan
```bash
panguard scan
```
Runs a fast security health check on the current system.

### Full security scan with code analysis
```bash
panguard scan --depth full
```
Deep scan including SAST code analysis, dependency audit, and threat detection.

### Start real-time protection (Guard)
```bash
panguard guard start
```
Starts the Guard engine as a background daemon. Monitors all agent activity in real-time using ATR (Agent Threat Rules), Sigma, and YARA rules.

### Check Guard status
```bash
panguard guard status
```
Shows whether Guard is running, rule counts, and recent alerts.

### Stop Guard
```bash
panguard guard stop
```

### Show system status dashboard
```bash
panguard status
```
Displays a comprehensive status panel: Guard state, rule counts, threat stats, and connected platforms.

### Show recent security alerts
```bash
panguard guard alerts
```

## Workflow

When the user asks about security, skill auditing, or threat protection:

1. If they want to **audit skills**: Run `panguard audit skill <path>` on the target directory
2. If they want a **security scan**: Run `panguard scan` (add `--depth full` for thorough analysis)
3. If they want **real-time protection**: Run `panguard guard start`
4. If they want **status**: Run `panguard status`

## Setup

If panguard is not installed, install it:
```bash
npm install -g @panguard-ai/panguard
```

Then configure for all AI agent platforms:
```bash
panguard setup
```
