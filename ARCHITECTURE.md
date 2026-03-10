# Architecture

Technical architecture of the Panguard AI platform. For product-level documentation, see the [README](README.md).

---

## System Overview

```
                              User
                               |
                 +-------------+-------------+
                 |                           |
           [CLI: panguard]           [panguard.ai]
            22 commands              Next.js 14
                 |                   EN + zh-TW
                 |
   +------+------+------+------+------+------+------+
   |      |      |      |      |      |      |      |
 Scan  Guard   Chat   Trap  Report   MCP   Skill    ATR
        |                                  Auditor  Standard
        |
   4-Agent Pipeline
   Detect -> Analyze -> Respond -> Report
        |
   +----+----+----+
   |    |    |    |
  Sigma YARA ATR Suricata/Falco
  3754  4369  32
        |
   Threat Cloud
   Collective Intelligence
        |
   Manager (optional)
   Up to 500 agents
```

---

## Package Dependency Graph

```
@panguard-ai/panguard (CLI)
  |-- @panguard-ai/core
  |-- @panguard-ai/panguard-scan
  |-- @panguard-ai/panguard-guard
  |     |-- @panguard-ai/core
  |     |-- @panguard-ai/panguard-trap
  |     |-- @panguard-ai/security-hardening
  |     |-- agent-threat-rules
  |-- @panguard-ai/panguard-chat
  |-- @panguard-ai/panguard-trap
  |-- @panguard-ai/panguard-report
  |-- @panguard-ai/panguard-auth
  |-- @panguard-ai/panguard-mcp
  |     |-- @panguard-ai/panguard-scan
  |     |-- @panguard-ai/panguard-guard
  |     |-- @panguard-ai/panguard-skill-auditor
  |-- @panguard-ai/panguard-skill-auditor
  |     |-- @panguard-ai/panguard-scan
  |     |-- @panguard-ai/core
  |-- @panguard-ai/manager
  |-- @panguard-ai/threat-cloud
  |-- @panguard-ai/security-hardening
```

**Foundation layer:** `@panguard-ai/core` is imported by every package. It provides rules engine, monitor engine, AI/LLM interface, discovery engine, scoring, i18n, and CLI utilities.

---

## Three-Layer Detection Funnel

All events pass through a cost-optimized detection funnel:

```
                    Event Stream
                         |
              +----------+----------+
              |                     |
         Layer 1: Rules        (no match)
         3,754 Sigma                |
         4,369 YARA            Layer 2: Local AI
         32 ATR                Ollama on GPU
         <50ms, $0             ~2s, $0
         Catches 90%                |
              |               (uncertain)
              |                     |
         (matched)            Layer 3: Cloud AI
              |               Claude / OpenAI
              |               ~5s, $0.008
              |               Catches 3%
              |                     |
              +----------+----------+
                         |
                  Response Engine
                  Block / Alert / Log
```

**Graceful degradation:** Cloud unavailable -> Local AI handles it. Local AI unavailable -> Rules engine keeps running. Protection never stops.

**Desktop optimization:** On laptops/desktops, Layer 2 (Ollama) is skipped to avoid resource contention. Events go directly from Layer 1 to Layer 3.

---

## Guard: 4-Agent Pipeline

The Guard engine processes events through four specialized agents:

```
Event -> [Detect Agent] -> [Analyze Agent] -> [Respond Agent] -> [Report Agent]
             |                   |                  |                  |
        Rule matching       AI classification   Auto-response     Logging
        Baseline check      Root cause analysis  IP blocking       Evidence
        ATR evaluation      Confidence scoring   Process kill      Compliance
        Anomaly detection   Investigation        Quarantine        Baseline update
```

**Learning Mode (first 7 days):**
- Detect Agent collects events and builds a behavioral baseline
- No auto-responses during learning (alert-only)
- After baseline established, switches to protection mode

**Protection Mode:**
- Deviations from baseline trigger analysis
- Confidence > 90%: auto-respond
- Confidence 70-90%: ask user with evidence
- Confidence < 70%: log and notify

---

## ATR Rule Architecture

ATR (Agent Threat Rules) is a YAML-based detection format for AI agent threats:

```
rules/
  prompt-injection/        # 5 rules
  tool-poisoning/          # 4 rules
  context-exfiltration/    # 3 rules
  agent-manipulation/      # 3 rules
  privilege-escalation/    # 2 rules
  excessive-autonomy/      # 2 rules
  skill-compromise/        # 7 rules
  data-poisoning/          # 1 rule
  model-security/          # 2 rules
```

Each rule contains:
- Detection patterns (regex, keyword, behavioral)
- True positive and true negative test cases
- Evasion tests (honestly documenting known bypasses)
- OWASP and MITRE ATLAS mappings
- Severity calibration and response actions

ATR rules are loaded by the Guard engine's ATR Engine and evaluated in parallel with Sigma and YARA rules.

---

## Threat Cloud Data Flow

```
Your Machine                    Threat Cloud                   Other Users
     |                               |                              |
  Threat detected              Receives anonymized            Receives new rule
     |                         threat signature                     |
  Anonymize                          |                        Rule engine
  (strip all PII,              Validate + deduplicate         auto-updates
   keep only pattern)                |                              |
     |                         Generate Sigma/YARA rule        Protection
  Upload via TLS 1.3                 |                         active
     |                         Consensus check
     +--------->               (3+ clients confirm)
                                     |
                               Promote to stable
                                     |
                               Push to all users
                                     +---------->
```

**Privacy guarantees:**
- Only anonymized threat signatures leave your machine
- Zero raw data, zero telemetry, zero source code
- TLS 1.3 encrypted transport
- Can be turned off anytime (Community tier works fully offline)

**Auto-generated rules:** The Threat Intel Pipeline runs every 6 hours, pulling from 11 threat intelligence sources. Currently: 605 auto-generated Sigma rules + 43 auto-generated YARA rules, with 808 promoted to stable.

---

## MCP Integration

Panguard exposes 11 tools via the Model Context Protocol (MCP):

| Tool                      | Description                                   |
| ------------------------- | --------------------------------------------- |
| `panguard_scan`           | System security health check (quick/full)     |
| `panguard_scan_code`      | SAST scanning for vulnerabilities             |
| `panguard_guard_start`    | Launch threat monitoring daemon               |
| `panguard_guard_stop`     | Shutdown monitoring                           |
| `panguard_status`         | Multi-service status check                    |
| `panguard_alerts`         | Recent security alerts with severity filter   |
| `panguard_block_ip`       | Manual IP blocking (1h/24h/permanent)         |
| `panguard_generate_report`| PDF compliance report generation              |
| `panguard_init`           | Non-interactive initialization                |
| `panguard_deploy`         | Full deployment pipeline                      |
| `panguard_audit_skill`    | AI agent skill security audit                 |

**Platform auto-detection:** `panguard setup` detects installed AI agent platforms (Claude Code, Cursor, OpenClaw, Codex, WorkBuddy, Claude Desktop) and injects MCP configuration automatically.

---

## Deployment Topologies

### Single Machine (default)

```
[Guard] + [Dashboard] + [Threat Cloud Client]
  All on one machine. Dashboard on localhost:3100.
```

### Distributed via Manager

```
[Guard Agent 1] --+
[Guard Agent 2] --+--> [Manager] --> [Threat Cloud]
[Guard Agent N] --+    Correlates threats across agents
                       Up to 500 agents
                       Policy distribution
                       Real-time dashboard relay
```

### Docker

```bash
docker compose up    # Panguard + Ollama (local AI)
```

Multi-stage Dockerfile: Node 22 build + standalone runtime. Published to `ghcr.io`.

### Website

Vercel deployment. Next.js 14 with ISR. Bilingual (EN + zh-TW).

---

## Package Inventory

| Package | npm Name | Version | Maturity | Description |
| ------- | -------- | ------- | -------- | ----------- |
| core | @panguard-ai/core | 0.3.1 | GA | Shared foundation: rules, AI, monitor, discovery, i18n |
| panguard | @panguard-ai/panguard | 0.3.1 | GA | Unified CLI with 22 commands |
| atr | agent-threat-rules | 0.1.0 | RFC | Open detection standard for AI agent threats |
| panguard-scan | @panguard-ai/panguard-scan | 0.2.0 | GA | 60-second security scanning |
| panguard-guard | @panguard-ai/panguard-guard | 0.2.0 | GA | Real-time monitoring, 4-agent pipeline |
| panguard-chat | @panguard-ai/panguard-chat | 0.2.0 | GA | 6-channel notification system |
| panguard-trap | @panguard-ai/panguard-trap | 0.2.0 | GA | 8 honeypot service types |
| panguard-report | @panguard-ai/panguard-report | 0.2.0 | GA | Compliance reports (CMA, ISO 27001, SOC 2) |
| panguard-mcp | @panguard-ai/panguard-mcp | 0.1.0 | Beta | MCP server with 11 tools |
| panguard-skill-auditor | @panguard-ai/panguard-skill-auditor | 0.1.1 | Beta | 7-check skill security analysis |
| panguard-auth | @panguard-ai/panguard-auth | 0.2.0 | GA | Auth, licensing, payment (LemonSqueezy) |
| manager | @panguard-ai/manager | 0.2.0 | GA | Distributed agent orchestration (500 max) |
| threat-cloud | @panguard-ai/threat-cloud | 0.2.0 | GA | Collective threat intelligence backend |
| panguard-web | @panguard-ai/panguard-web | 0.2.0 | GA | Website content engine |
| security-hardening | @panguard-ai/security-hardening | 0.1.1 | GA | Security policy enforcement |
| website | @panguard-ai/website | 0.2.0 | GA | Next.js 14 marketing site (39 pages) |

**Maturity levels:** GA = Generally Available, Beta = Feature complete but evolving, RFC = Request for Comments (open standard)

---

## CI/CD

| Workflow | Trigger | Purpose |
| -------- | ------- | ------- |
| ci.yml | push/PR | Lint, format, typecheck, test with coverage |
| deploy.yml | push main | Deploy website (Vercel) + backend (Docker) |
| publish.yml | release tag | Publish packages to npm |
| threat-intel-sync.yml | every 6h | Update threat intelligence feeds |
| installer-e2e.yml | event | E2E testing for installer |
| cli-smoke.yml | event | CLI smoke tests |
| release.yml | manual | Create GitHub releases |
| uptime.yml | scheduled | Service health monitoring |
