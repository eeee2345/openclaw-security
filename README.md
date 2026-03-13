<div align="center">

<img src="assets/PANGUARD_GitHub_Banner_Clean.png" alt="Panguard AI" width="720">

<br>

### The App Store Gatekeeper for AI Agents

AI Agent 的 App Store 守門員 -- 100% 免費，MIT 授權

<br>

[![GitHub Stars](https://img.shields.io/github/stars/panguard-ai/panguard-ai?style=flat-square&color=DAA520)](https://github.com/panguard-ai/panguard-ai/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/panguard-ai/panguard-ai?style=flat-square)](https://github.com/panguard-ai/panguard-ai/network)
[![npm version](https://img.shields.io/npm/v/@panguard-ai/panguard?style=flat-square&color=cb3837&logo=npm)](https://www.npmjs.com/package/@panguard-ai/panguard)
[![MIT License](https://img.shields.io/badge/License-MIT-brightgreen?style=flat-square)](LICENSE)
[![ATR](https://img.shields.io/badge/ATR-69%20AI%20agent%20rules-8b5cf6.svg?style=flat-square)](https://github.com/Agent-Threat-Rule/agent-threat-rules)
[![Sigma+YARA](https://img.shields.io/badge/Sigma%20%2B%20YARA-9%2C700%2B%20integrated-f97316.svg?style=flat-square)](#detection-rules)
[![Made in Taiwan](https://img.shields.io/badge/Made%20in-Taiwan-e11d48.svg?style=flat-square)](https://panguard.ai)

[Quick Start](#quick-start) | [Documentation](docs/) | [ATR Standard](https://github.com/Agent-Threat-Rule/agent-threat-rules) | [Threat Cloud](#threat-cloud)

</div>

---

> AI agents install skills with full system access -- file read, code execution, network requests, credential access -- with **zero review process**. One malicious skill is all it takes.
>
> Panguard audits every skill before it runs, monitors agents 24/7, and turns every user's threat discovery into protection for everyone.
>
> AI Agent 安裝 skill 時擁有完整系統權限，卻零審查。Panguard 在 skill 執行前審計、24/7 監控、並將每個使用者的威脅發現轉化為所有人的防護。

---

## Quick Start

```bash
# One-line install (macOS / Linux)
curl -fsSL https://get.panguard.ai | bash

# Or run directly with npx (no install)
npx @panguard-ai/panguard scan --quick
```

```bash
panguard audit skill ./my-skill    # Audit a skill before installing it
panguard scan --quick              # 60-second security scan
panguard guard start               # Start 24/7 background protection
panguard setup                     # Auto-configure Claude, Cursor, Windsurf, etc.
```

No account required. No configuration needed. Works offline.

不需帳號，不需設定，離線可用。

---

## The Flywheel

Panguard is not a static rule set. Three components reinforce each other -- the more users, the stronger everyone's protection:

Panguard 不是靜態規則集。三個元件互相強化 -- 使用者越多，所有人的防護越強：

```
                    +------------------+
                    |  Skill Auditor   |  <-- Entry point: audit every skill before install
                    |  (your machine)  |
                    +--------+---------+
                             |
                     threat detected
                             |
                             v
                    +------------------+
                    |  Threat Cloud    |  <-- Community: anonymous signatures + LLM review + voting
                    |  (collective)    |
                    +--------+---------+
                             |
                      new rule confirmed
                             |
                             v
                    +------------------+
                    |  ATR Rules       |  <-- Standard: open detection rules distributed to all users
                    |  (open standard) |
                    +--------+---------+
                             |
                     rules strengthen next audit
                             |
                             +--------> back to Skill Auditor --> Loop
```

| Component | Role | Status |
| --------- | ---- | ------ |
| **[Skill Auditor](docs/overview.md)** | 7-check security gate before any skill runs (prompt injection, tool poisoning, secrets, permissions...) | GA |
| **[Threat Cloud](#threat-cloud)** | Anonymous threat intelligence from all Panguard instances. 3+ confirmations + Claude Sonnet review before promotion. | GA |
| **[ATR](https://github.com/Agent-Threat-Rule/agent-threat-rules)** | Open detection standard for AI agent threats. 69 rules, 9 categories, OWASP + MITRE mapped. | RFC |

One user's encounter with a new attack becomes a rule that protects everyone. Next time the same attack hits anyone, Layer 1 blocks it in < 50ms.

一個使用者遇到的新攻擊，成為保護所有人的規則。

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

Also available as MCP tool (`panguard_audit_skill`) for Claude, Cursor, Windsurf, and any MCP client.

---

## Three-Layer Detection

Each layer catches what the previous one missed. If any layer goes down, the others keep running.

每一層捕捉前一層遺漏的威脅。任何一層失效，其他層繼續運作。

| Layer | Engine | Coverage | Latency | Cost | Network |
| ----- | ------ | -------- | ------- | ---- | ------- |
| **1** | **Rules Engine** -- 69 ATR + 9,700+ integrated Sigma/YARA rules | ~90% of known threats | < 50ms | $0 | Offline |
| **2** | **Local AI** -- Ollama on your machine | ~7% (ambiguous cases) | ~ 2s | $0 | Offline |
| **3** | **Cloud AI** -- Claude / OpenAI | ~3% (novel attacks) | ~ 5s | ~$0.008 | Optional |

**Graceful degradation:** Cloud down? Local AI handles it. Local AI down? Rules keep running. Internet down? Everything still works.

**優雅降級：** 雲端斷線？本地 AI 接手。本地 AI 斷線？規則引擎繼續。防護永不停止。

---

## Product Suite

Everything is **free and open source**. MIT licensed.

所有功能**免費開源**。MIT 授權。

| Product | What It Does | Status |
| ------- | ------------ | ------ |
| **[Skill Auditor](docs/overview.md)** | 7-check security gate for AI agent skills | GA |
| **[Scan](docs/DETECTION.md)** | 60-second security audit | GA |
| **[Guard](docs/ARCHITECTURE.md)** | 24/7 AI monitoring with 4-agent pipeline | GA |
| **[Chat](docs/OPERATIONS.md)** | Alerts via Telegram, Slack, Discord, LINE, Email | GA |
| **[Threat Cloud](#threat-cloud)** | Collective threat intelligence | GA |
| **[MCP Server](docs/API.md)** | 11 tools for any MCP client | GA |
| **[Manager](docs/OPERATIONS.md)** | Distributed coordinator (up to 500 agents) | GA |
| **[Trap](docs/DETECTION.md)** | Honeypot services for attacker profiling | Coming Soon |
| **[Report](docs/DETECTION.md)** | Compliance: ISO 27001, SOC 2, Taiwan CMA | Coming Soon |

---

## Detection Rules

69 ATR rules purpose-built for AI agent threats + 9,700+ integrated Sigma/YARA rules. All bundled with npm. No cloud required.

| Rule Type | Count | Purpose |
| --------- | ----- | ------- |
| **Sigma** | 3,760 | Network intrusion, auth bypass, lateral movement |
| **YARA** | 5,961 | Malware, encoded payloads, obfuscated scripts |
| **ATR** | 69 | AI agent threats: prompt injection, tool poisoning, skill compromise |
| **Builtin** | 20 | OS hardening, credential hygiene, service audit |

---

## Threat Cloud

Every Panguard instance is a sensor. New attacks are auto-drafted into ATR rules, uploaded anonymously, confirmed by 3+ independent users and Claude Sonnet review, then distributed to everyone.

每個 Panguard 實例都是感測器。新攻擊自動草擬 ATR 規則、匿名上傳、經 3+ 獨立確認 + LLM 審查後推送給所有使用者。

**Privacy:** Fully optional. Only anonymized signatures leave your machine. Zero raw data, zero PII. When disabled, everything runs 100% offline.

**隱私：** 完全自願。只傳送匿名簽章。停用時一切離線。

---

## MCP Integration

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

Or auto-detect all AI platforms: `panguard setup` (Claude Desktop, Claude Code, Cursor, Windsurf, Codex)

---

## Architecture

```
panguard-ai/
  packages/
    panguard-skill-auditor/  Skill security auditor (entry point)
    panguard-guard/          24/7 AI monitoring + Threat Cloud client
    atr/                     Agent Threat Rules: 69 rules, 9 categories
    panguard-scan/           Security scanner
    panguard-chat/           Notifications: 6 channels
    panguard-mcp/            MCP server: 11 tools
    panguard-manager/        Distributed coordinator (up to 500 agents)
    core/                    Shared engine: rules, monitoring, AI adapters
    panguard-cli/            Unified CLI
    panguard-auth/           Auth: OAuth, sessions
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
| Testing | Vitest 3 + v8 coverage (3,490+ tests) |
| AI | Ollama (local) + Claude / OpenAI (cloud) |
| Encryption | AES-256-GCM |

---

## Contributing

We're looking for people who care about AI security.

我們在尋找關心 AI 安全的人。

- **Write detection rules** -- The highest-impact contribution. See the [ATR contribution guide](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/CONTRIBUTING.md).
- **Report vulnerabilities** -- Found a bypass? [Open a security advisory](SECURITY.md).
- **Submit code** -- Fork, branch, test, PR. See [CONTRIBUTING.md](CONTRIBUTING.md).
- **Share threat intelligence** -- Run Panguard with Threat Cloud enabled.

---

## License

MIT -- 100% free. 100% open source. No telemetry. No vendor lock-in.

---

<div align="center">

**If AI agents can act on your behalf, someone should check what they're about to do.**

<br>

[![Star History Chart](https://api.star-history.com/svg?repos=panguard-ai/panguard-ai&type=Date)](https://star-history.com/#panguard-ai/panguard-ai&Date)

<br>

[![Star on GitHub](https://img.shields.io/github/stars/panguard-ai/panguard-ai?style=for-the-badge&logo=github&label=Star%20on%20GitHub)](https://github.com/panguard-ai/panguard-ai)

**Panguard AI** -- Taipei, Taiwan

[Website](https://panguard.ai) ·
[GitHub](https://github.com/panguard-ai) ·
[ATR Standard](https://github.com/Agent-Threat-Rule/agent-threat-rules) ·
[Documentation](docs/)

</div>
