<p align="center">
  <strong>PANGUARD AI</strong>
</p>

<p align="center">
  <em>The first Skills Audit for AI agents. npm has audit. Docker has scanning. Now AI agent skills have Panguard.</em>
</p>

<p align="center">
  <a href="https://github.com/panguard-ai/panguard-ai/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="MIT License"></a>
  <a href="https://nodejs.org/"><img src="https://img.shields.io/badge/Node.js-%3E%3D20-green.svg" alt="Node.js"></a>
  <a href="#test-coverage"><img src="https://img.shields.io/badge/tests-3%2C583%20passed-brightgreen.svg" alt="Tests"></a>
  <a href="#detection-rules"><img src="https://img.shields.io/badge/detection%20rules-8%2C000%2B-orange.svg" alt="8,000+ Rules"></a>
  <a href="https://www.typescriptlang.org/"><img src="https://img.shields.io/badge/TypeScript-strict-blue.svg" alt="TypeScript"></a>
  <a href="https://panguard.ai"><img src="https://img.shields.io/badge/Made%20in-Taiwan-red.svg" alt="Made in Taiwan"></a>
</p>

---

## Why Panguard?

Every software ecosystem has a security audit layer:

- **npm** has `npm audit` for package vulnerabilities
- **Docker** has image scanning for container threats
- **Chrome** has extension review for browser add-ons

**AI agent skills have nothing.** They install with full system access, zero review, zero audit. A single malicious skill can steal your API keys, exfiltrate conversations, hijack your agent, or leak credentials.

Panguard introduces **Skills Audit** -- the security review layer for AI agents. Every skill is analyzed by 8,000+ community rules and AI before it runs. Known threats are blocked by rules. Unknown threats are caught by AI. New rules are shared to protect everyone.

```bash
npx panguard guard --watch
```

---

## Product Suite

| Product            | What it does                                            | Included from    |
| ------------------ | ------------------------------------------------------- | ---------------- |
| **ATR Standard**   | Open detection rules for AI agent threats (32 rules, 9 categories) | All plans |
| **Skill Auditor**  | 7-check security audit for AI agent skills before install | All plans       |
| **Scan**           | 60-second security audit with PDF report                | Community (Free) |
| **Guard**          | 24/7 AI monitoring with 4-agent pipeline and auto-response | Solo ($9/mo)  |
| **Chat**           | Plain-language alerts via 6 channels                    | Solo ($9/mo)     |
| **Trap**           | 8 honeypot services for attacker profiling              | Pro ($29/mo)     |
| **Report**         | Compliance reports: ISO 27001, SOC 2, Taiwan CMA        | Pro ($29/mo)     |
| **Threat Cloud**   | Collective threat intelligence from all Panguard users  | All plans        |
| **MCP Server**     | Control Panguard from Claude, Cursor, or any MCP client | All plans        |

---

## Quick Start

```bash
# Option 1: One-line install
curl -fsSL https://get.panguard.ai | bash

# Option 2: Run directly with npx
npx panguard guard --watch

# Option 3: Auto-detect AI platforms and configure MCP
npx panguard setup
```

### Common commands

```bash
panguard scan --quick              # 60-second security audit
panguard guard start               # Start real-time protection
panguard guard status --detailed   # 3-layer health check
panguard audit skill ./my-skill    # Audit an AI agent skill
panguard setup                     # Auto-configure Claude Code, Cursor, OpenClaw, etc.
panguard chat setup --channel slack # Set up notifications
```

### From Source

```bash
git clone https://github.com/panguard-ai/panguard-ai.git
cd panguard-ai
pnpm install && pnpm build
node packages/panguard/dist/cli/index.js scan --quick
```

---

## How It Works

### Three-Layer Detection

Panguard uses a tiered approach that handles 90% of threats locally in under 50ms, without AI costs:

```
Layer 1: Rules Engine (90% of threats)
  3,754 Sigma rules + 4,369 YARA rules + 32 ATR rules + Suricata + Falco
  Speed: <50ms | Cost: $0

Layer 2: Local AI (7% of threats)
  Ollama on your GPU, fully offline
  Speed: ~2s | Cost: $0

Layer 3: Cloud AI (3% of threats)
  Deep analysis for novel attacks
  Speed: ~5s | Cost: $0.008/analysis
```

If cloud is down, local AI takes over. If local AI is down, the rules engine keeps running. Protection never stops.

### Confidence-Based Response

| Confidence | Action                                                |
| ---------- | ----------------------------------------------------- |
| > 90%      | Auto-respond: block IP, kill process, quarantine file |
| 70-90%     | Ask you first with evidence                           |
| < 70%      | Log and notify only                                   |

---

## Detection Rules

All rules are open-source, community-driven, and auto-updated every 6 hours via CI.

| Rule Type    | Count  | Format           | Purpose                                    |
| ------------ | ------ | ---------------- | ------------------------------------------ |
| **Sigma**    | 3,754+ | YAML             | Network and system threats                 |
| **YARA**     | 4,369+ | Binary signatures| Malicious files, encoded payloads, malware |
| **ATR**      | 32     | YAML (open std)  | AI agent threats: prompt injection, tool poisoning, skill compromise |
| **Suricata** | --     | IDS/IPS rules    | Deep packet inspection                     |
| **Falco**    | --     | Runtime rules    | Container and kernel security              |
| **Total**    | **8,000+** |              |                                            |

### ATR: Agent Threat Rules

ATR is the first open detection standard for AI agent threats. Like Sigma for network attacks, ATR gives the security community a shared language for AI agent threats.

- **32 rules** across **9 threat categories**: prompt injection, tool poisoning, context exfiltration, agent manipulation, privilege escalation, excessive autonomy, skill compromise, data poisoning, model security
- OWASP Agentic Top 10: 10/10 categories covered
- 15 CVE mappings
- MIT licensed, human-readable, machine-enforceable

```bash
npx agent-threat-rules test           # Validate all rules
npx agent-threat-rules validate rule.yaml  # Validate a single rule
```

See [packages/atr/README.md](packages/atr/README.md) for the full specification.

---

## Feature Matrix

| Feature                     | Community ($0) | Solo ($9/mo) | Pro ($29/mo) | Business ($79/mo) |
| --------------------------- | -------------- | ------------ | ------------ | ------------------ |
| Machines                    | 1              | 3            | 10           | 25                 |
| Security Scan               | Full           | Full         | Full         | Full               |
| Skill Auditor (7 checks)   | Yes            | Yes          | Yes          | Yes                |
| MCP Server (11 tools)      | Yes            | Yes          | Yes          | Yes                |
| Guard Layer 1 (Rules)      | Yes            | Yes          | Yes          | Yes                |
| Guard Layer 2 (Local AI)   | --             | Yes          | Yes          | Yes                |
| Guard Layer 3 (Cloud AI)   | --             | --           | Yes          | Yes                |
| Chat Notifications          | --             | Basic        | 6 channels   | 6 channels         |
| Trap (Honeypots)           | --             | --           | 8 types      | 8 types            |
| Compliance Reports          | --             | --           | Yes          | Yes                |
| Threat Cloud                | Receive only   | Full         | Full         | Full               |
| Manager (Distributed)      | --             | --           | --           | Yes                |
| API Access                  | --             | --           | --           | Yes                |
| Custom AI Models            | --             | --           | --           | Yes                |
| Log Retention               | 7 days         | 30 days      | 60 days      | 90+ days           |

Annual billing: 20% discount on all plans.

---

## Architecture

```
                         User
                          |
            +-------------+-------------+
            |                           |
      [CLI: panguard]           [panguard.ai]
       22 commands              Next.js 14 + i18n
            |
  +---------+---------+---------+---------+---------+---------+
  |         |         |         |         |         |         |
[Scan]  [Guard]    [Chat]   [Trap]  [Report]   [MCP]   [Skill Auditor]
  |     4 Agents   6 Chan   8 Svcs  3 Frmwk   11 Tools  7 Checks
  |         |         |         |         |         |         |
  +---------+---------+---------+---------+---------+---------+
                          |
                    [@panguard-ai/core]
                  Rules | AI | Monitor | Discovery | i18n
                          |
            +-------------+-------------+
            |             |             |
       Layer 1       Layer 2       Layer 3
       Rules         Local AI      Cloud AI
       <50ms         ~2s           ~5s
            |
  +---------+---------+---------+---------+
  |         |         |         |         |
Sigma    YARA       ATR    Suricata   Falco
3,754+   4,369+     32     IDS/IPS   Runtime
            |
      [Threat Cloud]
      Collective Intelligence
      Anonymized Rule Sharing
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed technical documentation.

---

## Products

### ATR Standard (Agent Threat Rules)

The first open detection standard for AI agent threats. Like Sigma, but for prompt injection, tool poisoning, and agent manipulation.

```yaml
# Example ATR rule
id: ATR-2025-001
name: prompt-injection-system-override
category: prompt-injection
severity: critical
detection:
  pattern: "ignore (all |any )?(previous |prior )?(instructions|prompts)"
  scope: skill_manifest
response:
  action: block
```

32 rules across 9 categories. MIT licensed. [View on GitHub](https://github.com/Agent-Threat-Rule/agent-threat-rules)

---

### Panguard Skill Auditor

Security audit for AI agent skills (OpenClaw, MCP, AgentSkills) before they run.

```bash
panguard audit skill ./my-skill          # Pretty report
panguard audit skill ./my-skill --json   # JSON output
```

**7 automated checks:**

1. **Manifest validation** -- SKILL.md structure, required fields, version format
2. **Prompt injection detection** -- 11 patterns + hidden Unicode + base64 payloads
3. **Tool poisoning detection** -- sudo escalation, curl|bash, file exfiltration, reverse shells
4. **Dependency analysis** -- External URLs, npm/pip installs, required binaries
5. **Permission scope analysis** -- bash, network, database, credential tool usage
6. **Hardcoded secrets detection** -- API keys, tokens, passwords in skill code
7. **Behavioral intent analysis** -- Mismatch between stated purpose and actual behavior

Returns a 0-100 risk score. Exit code 2 for CRITICAL, 1 for HIGH. Also available as MCP tool (`panguard_audit_skill`).

---

### Panguard Scan

60-second security audit. No account required.

```bash
panguard scan --quick              # Quick scan (~30s)
panguard scan                      # Full scan (~60s)
panguard scan --output report.pdf  # PDF report
panguard scan --lang zh-TW         # Traditional Chinese
```

**What it checks:** Open ports, password policy, firewall config, SSL/TLS certificates, scheduled tasks, shared folders, system environment.

**Output:** Risk score (0-100, grade A-F), prioritized findings, remediation steps, compliance mapping. Available as terminal, JSON, or branded PDF.

---

### Panguard Guard

24/7 AI endpoint monitoring with automated threat response.

```bash
panguard guard start               # Start protection
panguard guard --watch             # Foreground mode
panguard guard status --detailed   # 3-layer health check
```

**4-Agent AI Pipeline:**

1. **Detect Agent** -- Matches events against Sigma/YARA/ATR rules and behavioral baseline
2. **Analyze Agent** -- Classifies threats using local or cloud AI
3. **Respond Agent** -- Executes auto-response (block, kill, quarantine)
4. **Report Agent** -- Logs incidents with evidence for compliance

7-day learning period builds behavioral baseline. Graceful degradation: cloud -> local AI -> rules engine. Protection never stops.

---

### Panguard Chat

Security alerts in plain language, delivered where you already work.

```bash
panguard chat setup                # Interactive wizard
panguard chat test                 # Send test notification
```

**6 channels:** Telegram, Slack (Block Kit), Email (SMTP/Resend), Discord, LINE, Webhooks

**3 tone modes:** `boss` (impact summary), `developer` (technical + CLI commands), `it_admin` (step-by-step remediation)

Bilingual: English and Traditional Chinese (zh-TW)

---

### Panguard Trap

Honeypot system that catches attackers and profiles their techniques.

**8 honeypot services:** SSH, HTTP, MySQL, Redis, SMB, RDP, Generic, Custom

Deploys decoy services on unused ports. Every command, credential, and file upload is captured. AI classifies attacker skill level and intent. Anonymized intelligence shared via Threat Cloud. Fully isolated from production.

---

### Panguard Report

AI compliance reports in 60 seconds.

```bash
panguard report --framework cma       # Taiwan Cyber Security Management Act
panguard report --framework iso27001  # ISO/IEC 27001:2022
panguard report --framework soc2      # SOC 2 Trust Services
```

| Framework          | Controls    | Output                |
| ------------------ | ----------- | --------------------- |
| Taiwan CMA         | 10 controls | PDF + JSON, bilingual |
| ISO/IEC 27001:2022 | 30 controls | PDF + JSON, bilingual |
| SOC 2              | 10 controls | PDF + JSON            |

Reports assess readiness, not certification. They help you identify gaps and prepare for formal audits.

---

### Threat Cloud

Collective threat intelligence. Every Panguard instance is a sensor.

```
Attack detected → Threat Cloud generates rule → All users protected (minutes)
```

**Privacy guarantees:** Only anonymized threat signatures leave your machine. Zero raw data, zero telemetry. TLS 1.3 encrypted. Can be turned off anytime. Community tier works fully offline.

---

### MCP Server

Control Panguard from AI assistants via Model Context Protocol.

**11 tools:** `panguard_scan`, `panguard_scan_code`, `panguard_guard_start`, `panguard_guard_stop`, `panguard_status`, `panguard_alerts`, `panguard_block_ip`, `panguard_generate_report`, `panguard_init`, `panguard_deploy`, `panguard_audit_skill`

```bash
panguard setup    # Auto-detect and configure Claude Code, Cursor, OpenClaw, Codex, WorkBuddy, NemoClaw
```

Works with Claude Desktop, Cursor, Claude Code, OpenClaw, Codex, WorkBuddy, NemoClaw, and any MCP-compatible client.

---

## Monorepo Structure

```
panguard-ai/
  packages/
    core/                   # Shared engine: discovery, rules, monitoring, AI providers, i18n
    panguard/               # Unified CLI: 22 commands, interactive menu, setup wizard
    atr/                    # Agent Threat Rules: open detection standard for AI agent threats
    panguard-scan/          # Security scanner + PDF report generation
    panguard-guard/         # AI monitoring: 4-agent pipeline, ATR engine, dashboard, daemon
    panguard-chat/          # Notifications: 6 channels, tone adaptation, templates
    panguard-trap/          # Honeypots: 8 services, attacker profiling, intel
    panguard-report/        # Compliance: ISO 27001 (30) + SOC 2 (10) + CMA (10) = 50 controls
    panguard-skill-auditor/ # AI agent skill security auditor (7 checks)
    panguard-mcp/           # MCP server: 11 tools for Claude/Cursor integration
    panguard-auth/          # Auth: OAuth, sessions, billing, rate limiting
    panguard-manager/       # Distributed agent coordinator (up to 500 agents)
    panguard-web/           # Website content engine: personas, pricing, guidance
    threat-cloud/           # Collective threat intelligence backend
    website/                # Next.js 14 marketing website (bilingual EN/ZH)
    admin/                  # Admin panel: users, sessions, audit, usage
  security-hardening/       # WebSocket security, credential storage, sandbox, RBAC
  config/
    sigma-rules/            # 3,754+ Sigma detection rules (YAML)
    yara-rules/             # 4,369+ YARA malware detection rules
    suricata/               # Suricata IDS/IPS rules
    falco-rules/            # Falco runtime security rules
  docs-site/                # Mintlify documentation site (bilingual)
  scripts/                  # Build, install, rule update scripts
```

---

## Tech Stack

| Category   | Technology                                |
| ---------- | ----------------------------------------- |
| Language   | TypeScript 5.7 (strict mode)              |
| Runtime    | Node.js 20+                               |
| Monorepo   | pnpm 9+ workspaces                        |
| Testing    | Vitest 3 + v8 coverage                    |
| Auth       | Google OAuth (PKCE) + scrypt + SQLite     |
| AI         | Ollama (local) + Claude / OpenAI (cloud)  |
| Rules      | Sigma + YARA + ATR + Suricata + Falco     |
| Frontend   | Next.js 14 + React 18 + Tailwind CSS      |
| i18n       | next-intl (EN + zh-TW)                    |
| Encryption | AES-256-GCM                               |
| CI/CD      | GitHub Actions (8 workflows)              |
| Deployment | Vercel (website) + Docker (backend)       |

---

## Development

### Prerequisites

- [Node.js](https://nodejs.org/) >= 20.0.0
- [pnpm](https://pnpm.io/) >= 9.0.0

### Commands

```bash
pnpm install          # Install all dependencies
pnpm build            # Build all packages
pnpm test             # Run all 3,583 tests
pnpm typecheck        # TypeScript strict checking
pnpm lint             # ESLint + security plugin
pnpm dev              # Start all dev servers
```

### Test Coverage

| Scope    | Tests     |
| -------- | --------- |
| Total    | **3,583** |
| Files    | 165       |

---

## Documentation

| Section         | Link                                                          |
| --------------- | ------------------------------------------------------------- |
| Overview        | [docs-site/overview.mdx](docs-site/overview.mdx)             |
| Quick Start     | [docs-site/quickstart.mdx](docs-site/quickstart.mdx)         |
| Installation    | [docs-site/installation.mdx](docs-site/installation.mdx)     |
| Architecture    | [ARCHITECTURE.md](ARCHITECTURE.md)                            |
| ATR Standard    | [packages/atr/README.md](packages/atr/README.md)             |
| Contributing    | [CONTRIBUTING.md](CONTRIBUTING.md)                            |
| Security Policy | [SECURITY.md](SECURITY.md)                                   |
| Changelog       | [docs-site/changelog.mdx](docs-site/changelog.mdx)           |

---

## Contributing

We welcome contributions. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Quick paths to contribute:**

- **Detection Rules** -- Write ATR, Sigma, or YARA rules. See [packages/atr/CONTRIBUTING.md](packages/atr/CONTRIBUTING.md)
- **Translations** -- Add or improve zh-TW translations in `packages/website/messages/`
- **Bug Reports** -- Open an issue with reproduction steps
- **Code** -- Fork, branch, test, PR. Conventional commits required.

---

## License

[MIT](LICENSE) -- Use it, modify it, deploy it. No strings attached.

---

<p align="center">
  <strong>Panguard AI</strong> -- Taipei, Taiwan<br>
  <a href="https://panguard.ai">panguard.ai</a> ·
  <a href="https://github.com/panguard-ai">GitHub</a> ·
  <a href="https://docs.panguard.ai">Docs</a>
</p>
