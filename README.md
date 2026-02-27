# Panguard AI

> **AI-Driven Adaptive Endpoint Protection**
> **AI 驅動的自適應端點防護平台**

[![CI](https://github.com/panguard-ai/panguard-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/panguard-ai/panguard-ai/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D20-green.svg)](https://nodejs.org/)
[![pnpm](https://img.shields.io/badge/pnpm-%3E%3D9-orange.svg)](https://pnpm.io/)
[![Tests](https://img.shields.io/badge/tests-1107%20passed-brightgreen.svg)](#test-coverage)

---

## What is Panguard AI?

Panguard AI is an open-source cybersecurity platform that brings enterprise-grade endpoint protection to small and medium businesses. Install with one command, let AI learn your environment in 7 days, and receive security alerts in plain language through LINE, Telegram, or Slack. Zero daily operation required.

**Panguard AI** 是一個開源的網路安全平台，為中小企業帶來企業級端點防護。一行指令安裝，AI 用 7 天學習你的環境，透過 LINE、Telegram 或 Slack 用人話通知你資安事件。日常操作為零。

### Core Principles

- **One-command install** - `curl -fsSL https://get.panguard.ai | sh`
- **Claude Code-style auth** - Sign up on web, `panguard login` opens browser, features gated by subscription tier
- **7-day learning period** - AI builds a behavioral baseline before alerting
- **Plain language alerts** - No Sigma / YARA / MITRE jargon for non-technical users
- **Three-layer AI funnel** - 90% rules engine, 7% local AI (Ollama), 3% cloud AI
- **Gets smarter over time** - Context Memory + Collective Threat Intelligence

---

## Product Suite

| Product             | Description                                                                | Priority |
| ------------------- | -------------------------------------------------------------------------- | -------- |
| **Panguard Scan**   | 60-second security audit + PDF report                                      | P0       |
| **Panguard Guard**  | AI real-time endpoint monitoring + auto-response                           | P0       |
| **Panguard Chat**   | AI security co-pilot (LINE / Telegram / Slack / Email)                     | P0       |
| **Panguard Trap**   | Smart honeypot system (8 service types)                                    | P1       |
| **Panguard Report** | AI compliance report generator (TW Cyber Security Act / ISO 27001 / SOC 2) | P1       |
| **Threat Cloud**    | Collective threat intelligence API server                                  | P1       |

---

## Quick Start

### For Users

```bash
# 1. Install
curl -fsSL https://get.panguard.ai | sh

# 2. Sign up at panguard.ai, then log in from CLI
panguard login

# 3. Run your first scan
panguard scan --quick

# 4. Start real-time protection (Starter+)
panguard guard start
```

### For Contributors

```bash
git clone https://github.com/panguard-ai/panguard-ai.git
cd panguard-ai
pnpm install
pnpm build
pnpm test        # 1107 tests
pnpm dev         # start all dev servers
```

---

## Architecture

```
                         User
                          |
                    [Panguard Chat]
                   LINE / Telegram / Slack
                          |
    +---------------------+---------------------+
    |                     |                     |
[Panguard Scan]      [Panguard Guard]        [Panguard Report]
 60s audit        AI monitoring          Compliance reports
    |              |         |                |
    |         [5 AI Agents] [Context Memory]  |
    |              |                          |
    +------[Panguard Trap]------+              |
           Honeypots                         |
                |                            |
           [Threat Cloud] ------ Collective Intelligence
```

### Three-Layer AI Funnel

1. **Layer 1 - Rules Engine (90%)**: Sigma rules match known attack patterns instantly
2. **Layer 2 - Local AI (7%)**: Ollama runs on-device for deeper analysis (server environments)
3. **Layer 3 - Cloud AI (3%)**: Full dynamic reasoning for the most complex threats

---

## Packages

This monorepo contains 12 packages:

| Package                                                    | Description                                                                                                         |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| [`@panguard-ai/core`](packages/core)                       | Core engine: environment discovery, Sigma rules, system monitoring, AI interfaces, security tool adapters           |
| [`@panguard-ai/panguard-scan`](packages/panguard-scan)     | Security scanner: password audit, port detection, SSL check, PDF report generation                                  |
| [`@panguard-ai/panguard-guard`](packages/panguard-guard)   | AI monitoring: 5 agents (Detect/Analyze/Respond/Report/Chat), investigation engine, dashboard, licensing, daemon    |
| [`@panguard-ai/panguard-chat`](packages/panguard-chat)     | Notification system: 5 channels (LINE/Telegram/Slack/Email/Webhook), tone adaptation per user role, alert templates |
| [`@panguard-ai/panguard-trap`](packages/panguard-trap)     | Honeypot system: 8 service types (SSH/HTTP/FTP/SMB/MySQL/RDP/Telnet/Redis), attacker profiling, threat intelligence |
| [`@panguard-ai/panguard-report`](packages/panguard-report) | Compliance reports: Taiwan Cyber Security Act (10 controls), ISO 27001 (12 controls), SOC 2 (10 controls)           |
| [`@panguard-ai/panguard-auth`](packages/panguard-auth)     | Authentication: Google OAuth (PKCE), scrypt password hashing, session management, SQLite, rate limiting             |
| [`@panguard-ai/panguard`](packages/panguard)               | Unified CLI: 13 commands (login/scan/guard/trap/report/threat/...), interactive menu, setup wizard                  |
| [`@panguard-ai/panguard-web`](packages/panguard-web)       | Website content engine: personas, pricing, guidance wizard, HTML templates                                          |
| [`security-hardening`](security-hardening)                 | Security hardening: WebSocket security, credential storage, sandbox, permissions, audit logging                     |

---

## Development

### Prerequisites

- [Node.js](https://nodejs.org/) >= 20.0.0
- [pnpm](https://pnpm.io/) >= 9.0.0

### Commands

```bash
pnpm install          # Install all dependencies
pnpm build            # Build all 9 packages
pnpm test             # Run all 1107 tests
pnpm typecheck        # TypeScript type checking
pnpm lint             # ESLint + security plugin
pnpm format:check     # Prettier format check
pnpm dev              # Start all dev servers in parallel
```

### Package-specific

```bash
# Run frontend dev server
cd packages/web && pnpm dev

# Run a specific package's tests
pnpm --filter @panguard-ai/core test
```

### Project Structure

```
panguard-ai/
  packages/
    core/              # Shared core engine
    panguard/          # Unified CLI (14 commands, interactive menu)
    panguard-auth/     # Authentication (OAuth, sessions, SQLite)
    panguard-scan/     # Security scanner + PDF reports
    panguard-guard/    # AI monitoring + 5 agents
    panguard-chat/     # Notification channels + chat agent
    panguard-trap/     # Honeypot services + profiler
    panguard-report/   # Compliance report generator
    panguard-web/      # Website content engine
    web/               # React frontend (Vite + TailwindCSS)
  security-hardening/       # Security hardening module
  tests/
    integration/       # Cross-package integration tests
  SPEC.md              # Full technical specification (Chinese)
```

---

## Tech Stack

| Category        | Technology                                     |
| --------------- | ---------------------------------------------- |
| Language        | TypeScript 5.7 (strict mode)                   |
| Runtime         | Node.js 20+                                    |
| Package Manager | pnpm 10 (workspace monorepo)                   |
| Auth            | Google OAuth (PKCE) + scrypt + SQLite sessions |
| Testing         | Vitest 3                                       |
| Linting         | ESLint 9 + eslint-plugin-security              |
| Formatting      | Prettier 3                                     |
| Frontend        | React 19 + Vite 6 + TailwindCSS 3.4            |
| CI/CD           | GitHub Actions                                 |
| i18n            | i18next (English + Traditional Chinese)        |

---

## Test Coverage

| Scope             | Tests    | Files  |
| ----------------- | -------- | ------ |
| Unit tests        | 906      | 57     |
| Integration tests | 162      | 6      |
| **Total**         | **1107** | **64** |

All tests pass with zero failures. Run `pnpm test` to verify.

---

## License

[MIT](LICENSE)

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes with tests
4. Ensure all checks pass (`pnpm build && pnpm test && pnpm typecheck && pnpm lint`)
5. Submit a Pull Request

---

## Documentation

Full documentation is available in the [`docs/`](docs/) directory:

- [Getting Started](docs/getting-started.md) - Sign up, install, login, first scan in 5 minutes
- [Product Overview](docs/overview.md) - What Panguard AI does and how it works
- **Concepts**: [Authentication](docs/concepts/authentication.md) | [Three-Layer AI](docs/concepts/three-layer-ai.md) | [Learning Mode](docs/concepts/learning-mode.md) | [Security Score](docs/concepts/security-score.md) | [Threat Intelligence](docs/concepts/threat-intelligence.md)
- **Guides**: [Account Setup](docs/guides/account-setup.md) | [Scan](docs/guides/scan.md) | [Guard](docs/guides/guard.md) | [Chat](docs/guides/chat.md) | [Trap](docs/guides/trap.md) | [Report](docs/guides/report.md) | [Threat Cloud](docs/guides/threat-cloud.md) | [System Service](docs/guides/system-service.md)
- **Reference**: [CLI](docs/reference/cli.md) | [Configuration](docs/reference/configuration.md) | [Sigma Rules](docs/reference/sigma-rules.md) | [YARA Rules](docs/reference/yara-rules.md) | [API](docs/reference/api.md)
- [Troubleshooting](docs/troubleshooting.md) | [Changelog](docs/changelog.md)

---

## About

**Panguard AI** is developed by **Panguard AI**, a cybersecurity company focused on making professional-grade security accessible to small and medium businesses across Asia-Pacific.

- Website: [panguard.ai](https://panguard.ai)
- GitHub: [github.com/panguard-ai](https://github.com/panguard-ai)
- Location: Taipei, Taiwan
