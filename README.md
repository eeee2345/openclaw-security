<p align="center">
  <strong>PANGUARD AI</strong>
</p>

<p align="center">
  <em>Enterprise-grade endpoint security. One command. Zero expertise required.</em>
</p>

<p align="center">
  <a href="https://github.com/panguard-ai/panguard-ai/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="MIT License"></a>
  <a href="https://nodejs.org/"><img src="https://img.shields.io/badge/Node.js-%3E%3D20-green.svg" alt="Node.js"></a>
  <a href="#test-coverage"><img src="https://img.shields.io/badge/tests-1%2C326%20passed-brightgreen.svg" alt="Tests"></a>
  <a href="https://www.typescriptlang.org/"><img src="https://img.shields.io/badge/TypeScript-strict-blue.svg" alt="TypeScript"></a>
  <a href="https://panguard.ai"><img src="https://img.shields.io/badge/Made%20in-Taiwan-red.svg" alt="Made in Taiwan"></a>
</p>

---

## What is Panguard AI?

Panguard AI is an open-source cybersecurity platform that gives every developer and small business the same protection that Fortune 500 companies pay six figures for.

One command installs six security tools. AI learns your environment in 7 days. Threats get blocked automatically. You get notified in plain language through Telegram or Slack.

```bash
curl -fsSL https://get.panguard.ai | bash
```

---

## Product Suite

| Product          | What it does                                           | Included from    |
| ---------------- | ------------------------------------------------------ | ---------------- |
| **Scan**         | 60-second security audit with PDF report               | Community (Free) |
| **Guard**        | 24/7 AI monitoring with auto-response                  | Solo ($9/mo)     |
| **Chat**         | Plain-language alerts via Telegram / Slack / Email     | Solo ($9/mo)     |
| **Trap**         | 8 honeypot services for attacker profiling             | Pro ($29/mo)     |
| **Report**       | Compliance reports: ISO 27001, SOC 2, Taiwan TCSA      | Pro ($29/mo)     |
| **Threat Cloud** | Collective threat intelligence from all Panguard users | All plans        |

---

## Quick Start

```bash
# Install
curl -fsSL https://get.panguard.ai | bash

# Run your first scan (no account needed)
panguard scan --quick

# Start real-time protection
panguard login
panguard guard start

# Set up notifications
panguard chat setup --channel line
```

### From Source

```bash
git clone https://github.com/panguard-ai/panguard-ai.git
cd panguard-ai
pnpm install && pnpm build
./bin/panguard scan --quick
```

---

## How It Works

### Three-Layer Detection

Panguard uses a tiered approach that handles 90% of threats locally in under 50ms, without AI costs:

```
Layer 1: Rules Engine (90% of threats)
  3,155 Sigma rules + 4,326 YARA rules + Suricata
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

### Architecture

```
                      You
                       |
                 [panguard.ai]
                Sign up / Manage
                       |
                 [panguard login]
                   CLI auth
                       |
   +-------------------+-------------------+
   |                   |                   |
[Scan]            [Guard]            [Report]
60s audit      AI monitoring      Compliance
   |           |         |              |
   |      [4 Agents] [Baseline]        |
   |           |                       |
   +-----[Trap]------+                 |
        Honeypots                      |
             |                         |
        [Threat Cloud] --- Collective Intelligence
```

---

## Products

### Panguard Scan

60-second security audit. No account required.

```bash
panguard scan --quick              # Quick scan (~30s)
panguard scan                      # Full scan (~60s)
panguard scan --output report.pdf  # PDF report
panguard scan --lang zh-TW         # Traditional Chinese
```

**What it checks:**

- Open ports and exposed services
- Password policy compliance
- Firewall configuration
- SSL/TLS certificates
- Scheduled tasks and cron jobs
- Shared folders and permissions
- System environment (OS, kernel, packages)

**Output:** Risk score (0-100, grade A-F), prioritized findings, remediation steps, compliance mapping (ISO 27001 / SOC 2). Available as terminal output, JSON, or branded PDF.

---

### Panguard Guard

24/7 AI endpoint monitoring with automated threat response.

```bash
panguard guard start    # Start protection
panguard guard status   # Check status
panguard guard stop     # Stop protection
```

**4-Agent AI Pipeline:**

1. **Detect Agent** - Matches events against Sigma/YARA rules and behavioral baseline
2. **Analyze Agent** - Classifies threats using local or cloud AI
3. **Respond Agent** - Executes auto-response actions (block, kill, quarantine)
4. **Report Agent** - Logs incidents with evidence for compliance

**Key features:**

- 7-day learning period builds behavioral baseline
- Deviation detection after baseline is established
- Process monitoring, file integrity, network connections
- Auto-response: IP blocking, process termination, file quarantine
- Graceful degradation (cloud -> local AI -> rules engine)
- Investigation engine for multi-step root cause analysis

---

### Panguard Chat

Security alerts in plain language, delivered where you already work.

```bash
panguard chat setup                          # Interactive wizard
panguard chat setup --channel telegram       # Telegram
panguard chat setup --channel slack          # Slack
panguard chat setup --channel telegram       # Telegram
panguard chat test                           # Send test notification
```

**4 channels:** Telegram, Slack (Block Kit), Email (SMTP/Resend), Webhooks

**3 tone modes:**

- `boss` - Impact summary in plain language
- `developer` - Technical details with CLI commands
- `it_admin` - Step-by-step remediation instructions

**Bilingual:** English and Traditional Chinese (zh-TW)

---

### Panguard Trap

Honeypot system that catches attackers and profiles their techniques.

**8 honeypot services:** SSH, HTTP, FTP, SMB, MySQL, RDP, Telnet, Redis

**How it works:**

1. Deploys decoy services on unused ports
2. Attackers interact thinking they're real
3. Every command, credential, and file upload is captured
4. AI classifies attacker skill level and intent
5. Anonymized intelligence shared via Threat Cloud

All honeypots are fully isolated from production. Zero risk to real data.

---

### Panguard Report

AI compliance reports in 60 seconds instead of months.

```bash
panguard report --framework tcsa          # Taiwan Cyber Security Act
panguard report --framework iso27001      # ISO 27001
panguard report --framework soc2          # SOC 2
```

| Framework                        | Controls    | Output                |
| -------------------------------- | ----------- | --------------------- |
| Taiwan Cyber Security Act (TCSA) | 10 controls | PDF + JSON, bilingual |
| ISO/IEC 27001:2022               | 30 controls | PDF + JSON, bilingual |
| SOC 2 Trust Services             | 10 controls | PDF + JSON            |

Each report includes: executive summary, control-by-control assessment, evidence packages, remediation recommendations, and priority ranking.

> Reports assess readiness, not certification. They help you identify gaps and prepare for formal audits.

---

### Threat Cloud

Collective threat intelligence. Every Panguard instance is a sensor.

```
Attack detected on your server
        |
Threat Cloud generates new Sigma rule
        |
All Panguard users protected (minutes)
```

**Privacy guarantees:**

- Only anonymized threat signatures leave your machine
- Zero raw data, zero telemetry
- TLS 1.3 encrypted transport
- Your logs, source code, and data never leave your machine
- Can be turned off anytime
- Community tier works fully offline

---

## Pricing

| Plan          | Price  | Machines | Includes                                                 |
| ------------- | ------ | -------- | -------------------------------------------------------- |
| **Community** | Free   | 1        | Scan (unlimited) + Guard (Layer 1) + Threat Cloud        |
| **Solo**      | $9/mo  | 3        | + Full Guard (3 layers) + Chat + Local AI                |
| **Pro**       | $29/mo | 10       | + Trap (8 honeypots) + Cloud AI + 1 compliance report/mo |
| **Business**  | $79/mo | 25       | + SIEM integration + SSO + dedicated support             |

**Annual billing:** 20% discount on all plans.

**Compliance reports** (one-time purchase, Pro+ plans):

| Report       | Price | Market rate |
| ------------ | ----- | ----------- |
| Taiwan TCSA  | $299  | $10,000+    |
| ISO 27001    | $499  | $15,000+    |
| SOC 2        | $699  | $20,000+    |
| All 3 Bundle | $999  | $30,000+    |

---

## Monorepo Structure

```
panguard-ai/
  packages/
    core/               # Shared engine: discovery, rules, monitoring, AI providers
    panguard/           # Unified CLI: 15 commands, interactive menu, setup wizard
    panguard-scan/      # Security scanner + PDF report generation
    panguard-guard/     # AI monitoring: 4 agents, investigation, dashboard, daemon
    panguard-chat/      # Notifications: 5 channels, tone adaptation, templates
    panguard-trap/      # Honeypots: 8 services, attacker profiling, intel
    panguard-report/    # Compliance: TCSA (50), ISO 27001 (93), SOC 2 (64)
    panguard-auth/      # Auth: OAuth, sessions, billing, rate limiting
    panguard-web/       # Website content engine: personas, pricing, guidance
    website/            # Next.js 14 marketing website (bilingual)
    admin/              # Admin panel: users, sessions, audit, usage
  security-hardening/   # WebSocket security, credential storage, sandbox, RBAC
  config/
    sigma-rules/        # 3,155 Sigma detection rules
    yara-rules/         # 4,326 YARA malware detection rules
    suricata/           # Suricata IDS/IPS rules
    falco-rules/        # Falco runtime security rules
  docs/                 # User documentation (bilingual)
  scripts/              # Build, install, rule update scripts
```

---

## Tech Stack

| Category   | Technology                               |
| ---------- | ---------------------------------------- |
| Language   | TypeScript 5.7 (strict mode)             |
| Runtime    | Node.js 20+                              |
| Monorepo   | pnpm 10 workspaces                       |
| Testing    | Vitest 3                                 |
| Auth       | Google OAuth (PKCE) + scrypt + SQLite    |
| AI         | Ollama (local) + Claude / OpenAI (cloud) |
| Rules      | Sigma + YARA + Suricata + Falco          |
| Frontend   | Next.js 14 + React 18 + Tailwind CSS     |
| i18n       | next-intl (EN + zh-TW)                   |
| Encryption | AES-256-GCM                              |

---

## Development

### Prerequisites

- [Node.js](https://nodejs.org/) >= 20.0.0
- [pnpm](https://pnpm.io/) >= 9.0.0

### Commands

```bash
pnpm install          # Install all dependencies
pnpm build            # Build all packages
pnpm test             # Run all 1,326 tests
pnpm typecheck        # TypeScript strict checking
pnpm lint             # ESLint + security plugin
pnpm dev              # Start all dev servers
```

### Test Coverage

| Scope             | Tests     | Files   |
| ----------------- | --------- | ------- |
| Unit tests        | 1,178     | 213     |
| Integration tests | 268       | 19      |
| **Total**         | **1,326** | **232** |

---

## Documentation

| Section                                    | Contents                                                                                                                                                                                                                                                                  |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Getting Started](docs/getting-started.md) | Install, login, first scan in 5 minutes                                                                                                                                                                                                                                   |
| [Product Overview](docs/overview.md)       | Architecture, product suite, subscription tiers                                                                                                                                                                                                                           |
| **Concepts**                               | [Three-Layer AI](docs/concepts/three-layer-ai.md) / [Learning Mode](docs/concepts/learning-mode.md) / [Security Score](docs/concepts/security-score.md) / [Threat Intelligence](docs/concepts/threat-intelligence.md) / [Authentication](docs/concepts/authentication.md) |
| **Guides**                                 | [Scan](docs/guides/scan.md) / [Guard](docs/guides/guard.md) / [Chat](docs/guides/chat.md) / [Trap](docs/guides/trap.md) / [Report](docs/guides/report.md) / [Threat Cloud](docs/guides/threat-cloud.md) / [System Service](docs/guides/system-service.md)                 |
| **Reference**                              | [CLI Commands](docs/reference/cli.md) / [Configuration](docs/reference/configuration.md) / [Sigma Rules](docs/reference/sigma-rules.md) / [YARA Rules](docs/reference/yara-rules.md) / [API](docs/reference/api.md)                                                       |
| [Troubleshooting](docs/troubleshooting.md) | Common issues and solutions                                                                                                                                                                                                                                               |
| [Changelog](docs/changelog.md)             | Release history                                                                                                                                                                                                                                                           |

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Write tests for your changes
4. Ensure all checks pass: `pnpm build && pnpm test && pnpm typecheck && pnpm lint`
5. Submit a Pull Request

---

## License

[MIT](LICENSE) - Use it, modify it, deploy it. No strings attached.

---

<p align="center">
  <strong>Panguard AI</strong> - Taipei, Taiwan<br>
  <a href="https://panguard.ai">panguard.ai</a> · <a href="https://github.com/panguard-ai">GitHub</a>
</p>
