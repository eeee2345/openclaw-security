<div align="center">

<img src="assets/PANGUARD_GitHub_Banner_Clean.png" alt="Panguard AI" width="100%">

<br>

### The First Open-Source Security Platform Built for AI Agents

AI Agent 時代的第一個開源安全平台 -- 100% 免費，MIT 授權

<br>

[![GitHub Stars](https://img.shields.io/github/stars/panguard-ai/panguard-ai?style=flat-square&color=DAA520)](https://github.com/panguard-ai/panguard-ai/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/panguard-ai/panguard-ai?style=flat-square)](https://github.com/panguard-ai/panguard-ai/network)
[![GitHub Watchers](https://img.shields.io/github/watchers/panguard-ai/panguard-ai?style=flat-square)](https://github.com/panguard-ai/panguard-ai/watchers)
[![npm version](https://img.shields.io/npm/v/@panguard-ai/panguard?style=flat-square&color=cb3837&logo=npm)](https://www.npmjs.com/package/@panguard-ai/panguard)
[![MIT License](https://img.shields.io/badge/License-MIT-brightgreen?style=flat-square)](LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-%E2%89%A518-339933.svg?style=flat-square&logo=node.js&logoColor=white)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178C6.svg?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Rules](https://img.shields.io/badge/detection%20rules-9%2C700%2B-f97316.svg?style=flat-square)](#detection-rules)
[![ATR](https://img.shields.io/badge/ATR%20Standard-69%20rules-8b5cf6.svg?style=flat-square)](https://github.com/Agent-Threat-Rule/agent-threat-rules)
[![Made in Taiwan](https://img.shields.io/badge/Made%20in-Taiwan-e11d48.svg?style=flat-square)](https://panguard.ai)

[English](#why-this-matters) | [Quick Start](#quick-start) | [Documentation](docs/) | [ATR Standard](https://github.com/Agent-Threat-Rule/agent-threat-rules) | [Threat Cloud](#threat-cloud)

</div>

---

> Every era of computing gets the security layer it deserves.
> Servers got firewalls. Containers got scanning. Browser extensions got review.
>
> **AI agents got nothing.**
>
> They install skills with full system access -- file read, code execution, network requests, credential access -- with zero review process. One malicious skill is all it takes.
>
> **Panguard is the missing layer.**

---

## Why This Matters

AI agents are no longer experiments -- they run in production, with real system access, handling real user data. The attack surface is growing faster than any single team can defend.

AI Agent 不再只是實驗。它們運行在生產環境，擁有真實的系統權限，處理真實的使用者資料。攻擊面的增長速度遠超任何單一團隊能防禦的範圍。

We built Panguard because we saw a gap:

- **No security gate** for AI agent skill installation -- skills get full system access with zero review
- **No community threat intelligence** for agent-specific attacks -- prompt injection, tool poisoning, MCP exploits
- **No open detection standard** for AI agent threats -- until [ATR](https://github.com/Agent-Threat-Rule/agent-threat-rules)
- **Real CVEs are already here**: CVE-2025-53773 (Copilot RCE), CVE-2025-32711 (EchoLeak), CVE-2025-68143 (MCP exploit)

Panguard is our answer -- a multi-layer security platform that audits skills before install, monitors agents 24/7, and shares threat intelligence across all users. It's free, open source, and MIT licensed.

Panguard 是我們的答案 -- 安裝前審計 skill、24/7 監控 agent、跨用戶共享威脅情報。免費、開源、MIT 授權。

---

## Screenshots

<div align="center">

| CLI -- Scan & Guard | Dashboard (Coming Soon) |
|:---:|:---:|
| <img src="assets/screenshot-cli.png" width="450" alt="Panguard CLI"> | <img src="assets/screenshot-dashboard.png" width="450" alt="Panguard Dashboard"> |

| Notifications -- Telegram / Slack / Email | Flywheel -- How Panguard Gets Smarter |
|:---:|:---:|
| <img src="assets/screenshot-notifications.png" width="450" alt="Panguard Notifications"> | Every user's threat discovery becomes a protection rule for everyone via [Threat Cloud](#threat-cloud). |

</div>

---

## Table of Contents

- [Why This Matters / 為什麼重要](#why-this-matters)
- [Quick Start / 快速開始](#quick-start)
- [How Panguard Gets Smarter / 飛輪機制](#how-panguard-gets-smarter)
- [Three-Layer Detection / 三層偵測](#three-layer-detection)
- [Product Suite / 產品套件](#product-suite)
- [Detection Rules / 偵測規則](#detection-rules)
- [ATR: Agent Threat Rules](#atr-agent-threat-rules)
- [Threat Cloud / 威脅雲](#threat-cloud)
- [MCP Integration / MCP 整合](#mcp-integration)
- [Architecture / 架構](#architecture)
- [Contributing / 參與貢獻](#contributing)

---

## Quick Start

Install with one command. No account required. No configuration needed.

一行指令安裝。不需帳號，不需設定。

```bash
# One-line install (macOS / Linux)
curl -fsSL https://get.panguard.ai | bash

# Windows (PowerShell)
irm https://get.panguard.ai/windows | iex

# Or run directly with npx (no install)
npx @panguard-ai/panguard scan --quick
```

### First Commands

```bash
panguard audit skill ./my-skill    # Check if a skill is safe before installing it
panguard scan --quick              # Scan your machine for vulnerabilities (60s)
panguard guard start               # Start 24/7 background protection
panguard setup                     # Auto-configure Claude, Cursor, Windsurf, etc.
```

### MCP Configuration (Claude Desktop / Cursor)

```json
{
  "mcpServers": {
    "panguard": {
      "command": "npx",
      "args": ["@panguard-ai/panguard-mcp"]
    }
  }
}
```

Or auto-detect all installed AI platforms: `panguard setup`

Build from source and full development guide: [docs/getting-started.md](docs/getting-started.md)

---

## See It Work

```
$ panguard audit skill ./my-skill

+-------------------------------+
| Panguard Skill Audit Report   |
|                               |
| Skill:      my-skill          |
| Author:     Unknown           |
| Risk Score: 52/100 (CRITICAL) |
| Duration:   6ms               |
+-------------------------------+

[OK] [PASS] Manifest: Valid structure, required fields present
[!!] [FAIL] Prompt Safety: 1 injection pattern(s) detected
[!!] [FAIL] Tool Safety: curl|bash pipeline, potential exfiltration
[!]  [WARN] Dependencies: 1 URL(s), 1 external domain(s)
[!]  [WARN] Permissions: Uses Bash/Shell, File Read, Network/HTTP
[OK] [PASS] Secrets: No hardcoded credentials found
[OK] [PASS] Behavior: Code matches stated purpose

Verdict: BLOCK -- 2 failed checks, 2 warnings
```

Checks: manifest validation, prompt injection scan (11 patterns + Unicode + base64), tool poisoning detection, dependency analysis, permission scope check, secrets detection, and behavioral intent analysis. Returns a 0-100 risk score. Also available as MCP tool (`panguard_audit_skill`).

7 項檢查：manifest 驗證、prompt injection 掃描（11 種模式 + Unicode + base64）、tool poisoning 偵測、依賴分析、權限範圍檢查、secrets 偵測、行為意圖分析。回傳 0-100 風險分數。

---

## How Panguard Gets Smarter

Panguard is not a static rule set. Every user makes everyone safer:

Panguard 不是靜態規則集。每個使用者都讓所有人更安全：

```
You install Panguard
    --> Skills are audited before they run
        --> Threats are detected in real-time
            --> New rules are drafted from novel attacks
                --> Shared anonymously to Threat Cloud
                    --> Community votes + LLM reviews
                        --> Rules distributed to all users
                            --> Your Panguard is now stronger --> Loop
```

One user's encounter with a new attack becomes a protection rule for everyone. The more people run Panguard, the faster new threats get caught.

一個使用者遇到的新攻擊，會成為所有人的防護規則。使用 Panguard 的人越多，新威脅被捕捉的速度越快。

---

## Three-Layer Detection

Each layer catches what the previous one missed. If any layer goes down, the others keep running.

每一層捕捉前一層遺漏的威脅。任何一層失效，其他層繼續運作。

| Layer | Engine | Coverage | Latency | Cost | Network |
| ----- | ------ | -------- | ------- | ---- | ------- |
| **1** | **Rules Engine** -- 9,700+ Sigma / YARA / ATR pattern rules | ~90% of known threats | < 50ms | $0 | Offline |
| **2** | **Local AI** -- Ollama on your machine | ~7% (ambiguous cases) | ~ 2s | $0 | Offline |
| **3** | **Cloud AI** -- Claude / OpenAI | ~3% (novel attacks) | ~ 5s | ~$0.008 | Optional |

Coverage estimates are from internal simulation benchmarks, not empirical field data. Real-world results vary by threat type and environment.

**Graceful degradation:** Cloud down? Local AI handles it. Local AI down? Rules keep running. Internet down? Everything still works. Protection never stops.

**優雅降級：** 雲端斷線？本地 AI 接手。本地 AI 斷線？規則引擎繼續。網路斷線？一切照常。防護永不停止。

**Confidence engine:** >90% confidence triggers auto-response (block, kill, quarantine). 70-90% asks you first with evidence. <70% logs and notifies only.

**Evasion handling:** Layer 1 regex can be bypassed by paraphrasing. That's why Layer 2 (behavioral classification) and Layer 3 (multi-step LLM reasoning) exist -- they catch what patterns miss.

Full architecture details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

---

## Product Suite

Everything is **free and open source**. MIT licensed. No tiers, no limits, no vendor lock-in.

所有功能**免費開源**。MIT 授權。無分級、無限制、無供應商鎖定。

| Product | What It Does | Status |
| ------- | ------------ | ------ |
| **[Skill Auditor](docs/overview.md)** | Multi-check security gate for AI agent skills before install | Beta |
| **[Scan](docs/DETECTION.md)** | 60-second security audit with PDF report | GA |
| **[Guard](docs/ARCHITECTURE.md)** | 24/7 AI monitoring with 4-agent pipeline and auto-response | GA |
| **[Chat](docs/OPERATIONS.md)** | Security alerts via Telegram, Slack, Discord, LINE, Email, Webhook | GA |
| **[Trap](docs/DETECTION.md)** | 8 honeypot services for attacker profiling | Coming Soon |
| **[Report](docs/DETECTION.md)** | Compliance gap analysis: ISO 27001, SOC 2, Taiwan CMA | Coming Soon |
| **[Threat Cloud](#threat-cloud)** | Collective threat intelligence from all Panguard instances | GA |
| **[MCP Server](docs/API.md)** | 11 tools for Claude, Cursor, Windsurf, and any MCP client | Beta |
| **[Manager](docs/OPERATIONS.md)** | Distributed coordinator for up to 500 guard agents | GA |

---

## Detection Rules

9,700+ open-source, community-driven rules. Bundled with the npm package. No cloud required.

9,700+ 條開源社群驅動規則。隨 npm 套件一起安裝。不需雲端。

| Rule Type | Count | Purpose |
| --------- | ----- | ------- |
| **Sigma** | 3,760 | Network intrusion, auth bypass, lateral movement |
| **YARA** | 5,961 | Malware, encoded payloads, obfuscated scripts |
| **ATR** | 69 | AI agent threats: prompt injection, tool poisoning, skill compromise |
| **Builtin** | 20 | OS hardening, credential hygiene, service audit |

Full detection reference: [docs/DETECTION.md](docs/DETECTION.md)

---

## ATR: Agent Threat Rules

**What Sigma did for network attacks, ATR does for agent manipulation.**

**Sigma 之於網路攻擊，ATR 之於 Agent 操控。**

ATR is the first open detection standard purpose-built for AI agent security threats. 52 stable + 17 AI-predicted rules across 9 threat categories, with 325 test cases, 12 CVE mappings, and full OWASP LLM Top 10 coverage. Framework-agnostic -- works with LangChain, CrewAI, AutoGen, or raw API calls.

```yaml
title: Direct Prompt Injection via User Input
id: ATR-2026-001
status: stable
severity: high
tags:
  category: prompt-injection
  owasp_llm: LLM01
detection:
  conditions:
    - field: content
      operator: regex
      value: "(?i)ignore\\s+(all\\s+)?(previous|prior|above)\\s+(instructions|prompts|rules)"
response:
  actions: [block, alert, snapshot]
```

```bash
npx @panguard-ai/atr scan events.json    # Scan agent events against all rules
npx @panguard-ai/atr scaffold            # Create a new rule interactively
```

Full specification and contribution guide: [github.com/Agent-Threat-Rule/agent-threat-rules](https://github.com/Agent-Threat-Rule/agent-threat-rules)

---

## Threat Cloud

Every Panguard instance is a sensor. When one user encounters a new attack, Panguard auto-drafts an ATR rule, uploads the anonymized signature to Threat Cloud, and after 3+ independent confirmations and an LLM review (Claude Sonnet), the rule is promoted and distributed to all users. Next time the same attack hits anyone, Layer 1 blocks it in < 50ms.

每個 Panguard 實例都是感測器。使用者遇到新攻擊時，自動草擬 ATR 規則、上傳匿名簽章到 Threat Cloud。經 3+ 獨立確認 + LLM 審查後，規則推送給所有使用者。

**Traditional threat intelligence is top-down:** a vendor writes rules, you pay for updates. **Threat Cloud is bottom-up:** every user contributes, every user benefits. The more people run Panguard, the faster new attacks get caught.

**Privacy:** Threat Cloud participation is fully optional. When enabled, only anonymized threat signatures leave your machine -- zero raw data, zero PII. Anonymous client IDs. TLS 1.3 encrypted. When disabled, everything runs 100% offline with zero network calls.

**隱私：** Threat Cloud 參與完全自願。啟用時只傳送匿名威脅簽章 -- 零原始資料、零個資。停用時一切 100% 離線。

**Note:** The Threat Cloud **server** (`tc.panguard.ai`) is proprietary infrastructure operated by Panguard AI. The **client** (upload, download, sync) is fully open source and built into every installation. Anyone needing a private instance can self-host or [contact us](mailto:security@panguard.ai).

---

## Why Panguard

| Principle | Detail | 說明 |
| --------- | ------ | ---- |
| **Open source, MIT licensed** | Use it, modify it, deploy it, sell it. No strings attached. | 自由使用、修改、部署、販售 |
| **No usage telemetry** | Zero tracking, zero analytics, zero usage stats. Threat Cloud is opt-in only. | 零追蹤、零分析 |
| **Offline-first** | Rules engine and local AI work without internet. Cloud AI is optional. | 離線優先 |
| **Community-driven** | Every detection strengthens everyone via Threat Cloud. | 社群驅動 |
| **Framework-agnostic** | Works with Claude, GPT, LangChain, CrewAI, AutoGen, raw APIs. | 不綁框架 |
| **Production-tested** | 16 packages, 3,480+ tests, TypeScript strict mode. | 生產驗證 |
| **Made in Taiwan** | Independent. No corporate strings. | 台灣製造 |

---

## MCP Integration

Panguard works as an MCP server with 11 tools, compatible with any MCP-enabled AI platform.

Panguard 作為 MCP 伺服器提供 11 個工具，相容所有支援 MCP 的 AI 平台。

| Platform | Setup |
| -------- | ----- |
| Claude Desktop | `panguard setup` |
| Claude Code | `panguard setup` |
| Cursor | `panguard setup` |
| Windsurf | `panguard setup` |
| Codex | `panguard setup` |
| Any MCP client | [Manual config](docs/API.md) |

Full MCP reference: [docs/API.md](docs/API.md)

---

## Architecture

```
panguard-ai/
  packages/
    core/                    Shared engine: rules, monitoring, AI adapters, i18n
    panguard/                SDK: @panguard-ai/panguard
    panguard-cli/            Unified CLI: setup wizard, all commands
    atr/                     Agent Threat Rules: 69 rules, 9 categories
    panguard-scan/           Security scanner + PDF report
    panguard-guard/          24/7 AI monitoring: 4-agent pipeline + Threat Cloud client
    panguard-chat/           Notifications: 6 channels, tone adaptation
    panguard-trap/           Honeypots: 8 services, attacker profiling (Coming Soon)
    panguard-report/         Compliance: ISO 27001 + SOC 2 + CMA (Coming Soon)
    panguard-skill-auditor/  Skill security auditor
    panguard-mcp/            MCP server: 11 tools
    panguard-auth/           Auth: OAuth, sessions, rate limiting
    panguard-manager/        Distributed coordinator (up to 500 agents)
    panguard-web/            Context engine + web interface
    admin/                   Admin panel
    website/                 Next.js 14 marketing site (EN / zh-TW)
  config/
    sigma-rules/             3,760 Sigma detection rules
    yara-rules/              5,961 YARA detection rules
```

| Category | Technology |
| -------- | ---------- |
| Language | TypeScript 5.7 (strict mode) |
| Runtime | Node.js 18+ |
| Monorepo | pnpm workspaces (16 packages) |
| Testing | Vitest 3 + v8 coverage (3,480+ tests) |
| AI | Ollama (local) + Claude / OpenAI (cloud) |
| Rules | Sigma + YARA + ATR |
| Encryption | AES-256-GCM |

Full architecture documentation: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

---

## Contributing

Panguard is only as good as the community behind it. We're looking for people who care about AI security.

Panguard 的價值取決於背後的社群。我們在尋找關心 AI 安全的人。

| Role | How you can help | 如何參與 |
| ---- | ---------------- | -------- |
| **Security Researchers** | Submit detection rules via PR | 透過 PR 提交偵測規則 |
| **AI Framework Developers** | Improve agent source specs | 改進事件來源規格 |
| **Red Teamers** | Submit attack patterns you've discovered | 提交你發現的攻擊模式 |
| **Anyone** | Review rules, report false positives, improve translations | 審查規則、回報誤判、改進翻譯 |

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

---

## License

MIT -- Use it, modify it, deploy it, sell it. No strings attached.

100% free. 100% open source. No usage telemetry. No vendor lock-in. No "community edition" bait-and-switch.

100% 免費。100% 開源。無追蹤。無供應商鎖定。無「社群版」釣魚轉售。

---

<div align="center">

**Panguard is the security layer AI agents have been missing.**

Panguard 是 AI Agent 一直缺少的安全層。

If AI agents can act on your behalf, someone should check what they're about to do.

<br>

[![Star History Chart](https://api.star-history.com/svg?repos=panguard-ai/panguard-ai&type=Date)](https://star-history.com/#panguard-ai/panguard-ai&Date)

<br>

If Panguard helps protect your AI agents, consider giving it a star.

[![Star on GitHub](https://img.shields.io/github/stars/panguard-ai/panguard-ai?style=for-the-badge&logo=github&label=Star%20on%20GitHub)](https://github.com/panguard-ai/panguard-ai)

**Panguard AI** -- Taipei, Taiwan

[Website](https://panguard.ai) ·
[GitHub](https://github.com/panguard-ai) ·
[ATR Standard](https://github.com/Agent-Threat-Rule/agent-threat-rules) ·
[Documentation](docs/)

</div>
