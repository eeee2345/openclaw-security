# Product Overview

> AI-Driven Adaptive Endpoint Protection

---

## What is Panguard AI?

Panguard AI is an open-source cybersecurity platform designed for developers and small businesses who don't have a security team.

The core idea is simple: **sign up on the website, log in from CLI, and AI protects your machines automatically. It tells you when something happens. When nothing happens, you do nothing.**

### User Experience

Like Claude Code:

1. **Website** - Browse plans, sign up, manage subscriptions
2. **CLI** - `panguard login` opens browser for auth, token stored locally
3. **Usage** - Features gated by subscription tier, zero daily operation

### Why Panguard AI?

Traditional security tools:

- Require expertise to install and configure
- Interfaces full of Sigma, YARA, IOC, MITRE ATT&CK jargon
- Generate thousands of alerts with no prioritization
- Enterprise tools cost six figures; free tools are unusable

Panguard AI:

- **One command install**, zero configuration
- **Plain language notifications** via Telegram / Slack
- **AI auto-judges** severity and executes responses
- **Gets smarter over time**, learning from your environment

---

## Product Suite

Panguard AI includes 6 products. Each works independently, but together they form a complete SOC in one command.

### Panguard Scan - 60-Second Security Audit

One-time security scan that produces a risk score and PDF report.

```bash
panguard scan --quick
```

- System discovery (OS, network, ports, services)
- Password policy audit
- Firewall status check
- SSL/TLS certificate validation
- Risk score 0-100 (grades A-F)
- PDF report with remediation + compliance mapping

Best for: initial assessment, periodic health checks, pre-audit preparation.

[Guide ->](guides/scan.md)

---

### Panguard Guard - AI Real-Time Monitoring

Always-on AI protection engine that detects and responds to threats automatically.

```bash
panguard guard start
```

- 4-agent AI pipeline: Detect -> Analyze -> Respond -> Report
- 7-day learning period builds behavioral baseline
- 3,149 Sigma rules + 4,326 YARA rules
- Real-time threat intelligence (ThreatFox / URLhaus / GreyNoise)
- Auto-response: IP blocking, file quarantine, process termination
- Investigation engine for root cause analysis

Best for: server protection, VPS, office endpoint monitoring.

[Guide ->](guides/guard.md)

---

### Panguard Chat - AI Security Notifications

Translates technical security alerts into plain language and delivers them through your preferred channel.

```bash
panguard chat setup --channel line --user-type boss
```

- 4 notification channels: Telegram, Slack (Block Kit), Email (SMTP/HTML), Webhook (mTLS)
- 3 tone modes:
  - **boss** - Impact summary, plain language
  - **developer** - Technical details, CLI commands and logs
  - **it_admin** - Remediation steps, step-by-step instructions
- Bilingual templates (English / Traditional Chinese)

Best for: everyone. Guard detects threats, Chat tells you about them.

[Guide ->](guides/chat.md)

---

### Panguard Trap - Smart Honeypots

Deploy decoy services to lure attackers, collect intelligence, and profile their behavior.

- 8 honeypot services: SSH, HTTP, FTP, SMB, MySQL, RDP, Telnet, Redis
- Attacker profiling: skill level classification (script kiddie / intermediate / APT)
- Credential collection and command logging
- Intent analysis
- Threat intelligence reports
- All honeypots fully isolated from production

Best for: understanding who's attacking you, their intent and skill level.

[Guide ->](guides/trap.md)

---

### Panguard Report - Compliance Reports

Auto-generate audit-ready compliance reports in 60 seconds.

```bash
panguard report --framework iso27001
```

| Framework                        | Controls    | Languages  |
| -------------------------------- | ----------- | ---------- |
| Taiwan Cyber Security Act (TCSA) | 10 controls | EN + zh-TW |
| ISO/IEC 27001:2022               | 30 controls | EN + zh-TW |
| SOC 2 Trust Services             | 10 controls | EN         |

- Executive summary with security score
- Control-by-control assessment
- Evidence packages with timestamps
- Remediation recommendations
- JSON, Markdown, and PDF output

> Reports assess readiness, not certification. They prepare you for formal audits.

Best for: mid-size companies needing compliance, audit preparation, enterprise sales.

[Guide ->](guides/report.md)

---

### Threat Cloud - Collective Threat Intelligence

Anonymized threat intelligence sharing. Every Panguard user strengthens the network.

```bash
panguard threat start --port 8080
```

- RESTful API server with SQLite backend
- IoC (Indicator of Compromise) submission and queries
- Automatic Sigma rule generation from real attacks
- IP/domain reputation scoring
- Rate limiting and API key authentication
- Encrypted transport (TLS 1.3)

Privacy: only anonymized threat signatures leave your machine. Zero raw data. Zero telemetry. Can be turned off anytime. Community tier works fully offline.

Best for: private enterprise deployment, community threat intelligence sharing.

[Guide ->](guides/threat-cloud.md)

---

## Architecture

```
                         User
                          |
                    [panguard.ai]
                 Sign up / Manage
                          |
                    [panguard login]
                      CLI auth
                          |
    +---------------------+---------------------+
    |                     |                     |
[Panguard Scan]    [Panguard Guard]      [Panguard Report]
  60s audit        AI monitoring          Compliance
    |              |         |                |
    |         [4 Agents] [Baseline]          |
    |              |                         |
    +------[Panguard Trap]------+             |
           Honeypots                         |
                |                            |
           [Threat Cloud] ------ Collective Intelligence
```

### Three-Layer AI Funnel

| Layer   | Technology              | Handles | Latency | Cost        |
| ------- | ----------------------- | ------- | ------- | ----------- |
| Layer 1 | Sigma/YARA rules engine | 90%     | < 50ms  | $0          |
| Layer 2 | Local AI (Ollama)       | 7%      | ~2s     | $0          |
| Layer 3 | Cloud AI                | 3%      | ~5s     | $0.008/call |

Cloud down? Local AI takes over. Local AI down? Rules engine keeps running. Protection never stops.

[Learn more ->](concepts/three-layer-ai.md)

---

## Tech Stack

| Category   | Technology                                      |
| ---------- | ----------------------------------------------- |
| Language   | TypeScript 5.7 (strict mode)                    |
| Runtime    | Node.js 20+                                     |
| Monorepo   | pnpm 10 workspaces                              |
| Testing    | Vitest 3 (1,326 tests)                          |
| Rules      | Sigma (3,149) + YARA (4,326) + Suricata + Falco |
| AI         | Ollama (local) + Claude / OpenAI (cloud)        |
| Auth       | Google OAuth (PKCE) + scrypt hashing            |
| i18n       | English + Traditional Chinese                   |
| Encryption | AES-256-GCM                                     |

---

## Subscription Tiers

| Feature              | Community | Solo  | Pro    | Business |
| -------------------- | --------- | ----- | ------ | -------- |
| Price                | Free      | $9/mo | $29/mo | $79/mo   |
| Machines             | 1         | 3     | 10     | 25       |
| Scan (unlimited)     | v         | v     | v      | v        |
| Guard (Layer 1)      | v         | v     | v      | v        |
| Guard (Full 3-layer) | -         | v     | v      | v        |
| Chat notifications   | -         | v     | v      | v        |
| Local AI (Ollama)    | -         | v     | v      | v        |
| Cloud AI analysis    | -         | -     | v      | v        |
| Trap (8 honeypots)   | -         | -     | v      | v        |
| Compliance reports   | -         | -     | v      | v        |
| SIEM integration     | -         | -     | -      | v        |
| SSO & RBAC           | -         | -     | -      | v        |
| Dedicated support    | -         | -     | -      | v        |

**Compliance reports** available as one-time purchase on Pro+ plans:

| Report         | Price | Controls |
| -------------- | ----- | -------- |
| Taiwan TCSA    | $299  | 50       |
| ISO 27001      | $499  | 93       |
| SOC 2          | $699  | 64       |
| Bundle (all 3) | $999  | 207      |

Annual billing: 20% discount on all plans.

Manage subscription: [panguard.ai/pricing](https://panguard.ai/pricing)

---

## Open Source

Panguard AI is released under the [MIT License](https://github.com/panguard-ai/panguard-ai/blob/main/LICENSE).

Full source code. Zero black boxes. Every line auditable.
