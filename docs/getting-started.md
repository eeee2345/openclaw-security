# Getting Started

> From sign-up to your first security report in 5 minutes.

---

## System Requirements

| Item | Minimum |
|------|---------|
| OS | macOS 12+, Ubuntu 20.04+, Windows 10+ |
| Node.js | >= 20.0.0 |
| Disk | 200 MB |
| Memory | 512 MB (1 GB recommended for Guard) |

### Platform Support

| Feature | macOS | Linux | Windows |
|---------|-------|-------|---------|
| **Scan** | Full (lsof, socketfilterfw) | Full (ss, ufw/iptables) | Partial (netstat, no firewall) |
| **Guard** | Poll monitoring (5s) | Poll monitoring (5s) | Poll monitoring (5s) |
| **Trap** | TCP honeypots | TCP honeypots | TCP honeypots |
| **Chat** | Telegram / Slack / Email | Telegram / Slack / Email | Telegram / Slack / Email |
| **Report** | Full (3 frameworks) | Full (3 frameworks) | Full (3 frameworks) |

> macOS and Linux are primary platforms. Windows supports core features; some OS-level detection is limited.

---

## Step 1: Create Account

Go to [panguard.ai](https://panguard.ai) and sign up:

1. Click "Sign Up" - use Google or Email + Password
2. Browse plans at [Pricing](https://panguard.ai/pricing)

| Plan | Price | Includes |
|------|-------|----------|
| **Community** | Free | Scan (unlimited) + Guard (Layer 1) + Threat Cloud |
| **Solo** | $9/mo | + Full Guard (3 layers) + Chat + Local AI, up to 3 machines |
| **Pro** | $29/mo | + Trap + Cloud AI + Compliance reports, up to 10 machines |
| **Business** | $79/mo | + SIEM + SSO + Dedicated support, up to 25 machines |

Community plan is enough to get started. Compliance reports available as add-on purchases on Pro+ plans.

---

## Step 2: Install

### One-Command Install (Recommended)

```bash
curl -fsSL https://get.panguard.ai | bash
```

### Using npm

```bash
npm install -g @panguard-ai/panguard
```

### From Source (Development)

```bash
git clone https://github.com/panguard-ai/panguard-ai.git
cd panguard-ai
pnpm install
pnpm build

# Run CLI
./bin/panguard --help
```

> npm package not yet published. Use source install for now.

---

## Step 3: CLI Login

```bash
panguard login
```

Browser opens automatically. After login, return to terminal:

```
  PANGUARD AI

  -- Login Info ----------------------------------------

  Email     user@example.com
  Name      User Name
  Plan      Solo
  Expires   2026-04-27

  Login successful!
```

> On SSH / headless servers: use `panguard login --no-browser`, copy URL to another device.

---

## Step 4: First Scan

```bash
panguard scan --quick
```

Terminal output:

```
  PANGUARD AI - Security Scanner

  Scanning system environment...

  -- Security Findings ----------------------

  CRITICAL  Port 22 (SSH) exposed to 0.0.0.0
  HIGH      No firewall rules detected
  MEDIUM    Password policy not enforced
  LOW       12 unnecessary services running

  -- Risk Score -----------------------------

  Score: 62/100 [============--------] Grade: C

  -- Recommendations ------------------------

  1. Restrict SSH access to specific IP ranges
  2. Enable and configure system firewall
  3. Enforce password complexity requirements
```

`--quick` runs basic checks in ~30 seconds. Remove `--quick` for full scan (~60 seconds) including SSL certificate validation, scheduled task audit, and shared folder checks.

### Generate PDF Report

```bash
panguard scan --output my-report.pdf
```

### Traditional Chinese

```bash
panguard scan --lang zh-TW
```

---

## Step 5: Start Real-Time Protection

Scan is a one-time check. For continuous protection, start Guard:

```bash
panguard guard start
```

```
  PANGUARD AI - Guard Engine

  Guard engine starting...

  -- Status ---------------------------------

  Mode:       Learning (Day 1/7)
  Monitoring: processes, network, files
  Rules:      3,155 Sigma rules loaded
  Score:      --/100 (building baseline)

  Guard is now protecting your system.
  Learning mode: AI is observing normal behavior.
  Protection mode activates automatically after 7 days.
```

How Guard works:

1. **Days 1-7 (Learning mode)**: AI observes normal system behavior and builds a baseline. No false positives.
2. **Day 8+ (Protection mode)**: Automatically detects anomalies, executes responses, notifies you.

---

## Step 6: Set Up Notifications

Let Panguard notify you when threats are detected:

```bash
panguard chat setup
```

Interactive wizard guides you:

```
? Select notification channel:
  > Telegram
    Slack
    Email
    Webhook

? Select your role:
  > boss (impact summary, plain language)
    developer (technical details)
    it_admin (remediation steps)
```

Or specify directly:

```bash
# Telegram notifications, boss mode (plain language)
panguard chat setup --channel telegram --user-type boss

# Slack notifications, IT admin mode (remediation steps)
panguard chat setup --channel slack --user-type it_admin
```

Test your setup:

```bash
panguard chat test
```

---

## Step 7: Deploy Honeypots (Pro)

Catch attackers with decoy services:

```bash
panguard trap start --services ssh,http,mysql
```

8 honeypot types available: SSH, HTTP, FTP, SMB, MySQL, RDP, Telnet, Redis.

All fully isolated from production. Zero risk to real data.

---

## Step 8: Generate Compliance Report (Pro)

```bash
panguard report --framework iso27001 --output iso-report.pdf
```

Available frameworks:

| Framework | Controls | Command |
|-----------|----------|---------|
| Taiwan TCSA | 50 | `--framework tcsa` |
| ISO 27001 | 93 | `--framework iso27001` |
| SOC 2 | 64 | `--framework soc2` |

---

## Next Steps

| Want to... | Plan | Read |
|-----------|------|------|
| Understand the 3-layer AI architecture | - | [Concept: Three-Layer AI](concepts/three-layer-ai.md) |
| Deep dive into Guard's 4 AI agents | Solo | [Guide: Guard](guides/guard.md) |
| Set up honeypots to catch attackers | Pro | [Guide: Trap](guides/trap.md) |
| Generate compliance reports | Pro | [Guide: Report](guides/report.md) |
| Deploy collective threat intelligence | All | [Guide: Threat Cloud](guides/threat-cloud.md) |
| View all CLI commands | - | [Reference: CLI](reference/cli.md) |
| Write custom Sigma rules | - | [Reference: Sigma Rules](reference/sigma-rules.md) |
| Troubleshoot issues | - | [Troubleshooting](troubleshooting.md) |
