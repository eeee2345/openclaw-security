# Panguard AI - Demo Guide

> Copy-paste commands to demo each product.
> All commands run locally, no external API keys needed.

---

## Prerequisites

```bash
cd /Users/user/Downloads/openclaw-security
pnpm install && pnpm build
```

---

## Demo 1: Security Scan (Start here - most impressive)

Scans your Mac for real security issues: OS info, open ports, firewall, password policies.

```bash
node packages/panguard-scan/dist/cli/index.js --verbose
```

Quick scan (faster):
```bash
node packages/panguard-scan/dist/cli/index.js --quick
```

---

## Demo 2: Compliance Reports

Generate real compliance reports for 3 frameworks:

**ISO 27001 (Chinese):**
```bash
node packages/panguard-report/dist/cli/index.js generate --framework iso27001 --language zh-TW
```

**Taiwan Cyber Security Act (Chinese):**
```bash
node packages/panguard-report/dist/cli/index.js generate --framework tw_cyber_security_act --language zh-TW
```

**SOC 2 (English):**
```bash
node packages/panguard-report/dist/cli/index.js generate --framework soc2 --language en
```

**Summary view:**
```bash
node packages/panguard-report/dist/cli/index.js summary --framework iso27001 --language zh-TW
```

**List all frameworks:**
```bash
node packages/panguard-report/dist/cli/index.js list-frameworks
```

---

## Demo 3: Threat Cloud API

Start the threat intelligence API server, then query it:

**Start server (runs in background):**
```bash
node packages/threat-cloud/dist/cli.js --port 8080 &
```

**Health check:**
```bash
curl http://localhost:8080/api/v1/health
```

**Submit an IoC (Indicator of Compromise):**
```bash
curl -X POST http://localhost:8080/api/v1/ioc \
  -H "Content-Type: application/json" \
  -d '{"type":"ip","value":"203.0.113.50","confidence":95,"tags":["c2","botnet"]}'
```

**Query the IoC:**
```bash
curl "http://localhost:8080/api/v1/ioc?type=ip&value=203.0.113.50"
```

**Get statistics:**
```bash
curl http://localhost:8080/api/v1/stats
```

**Stop the server when done:**
```bash
kill %1
```

---

## Demo 4: AI Guard

Brand-styled CLI with Sage Green color theme:

**Show help (brand ASCII art):**
```bash
node packages/panguard-guard/dist/cli/index.js help
```

**Show engine status:**
```bash
node packages/panguard-guard/dist/cli/index.js status
```

**Show configuration:**
```bash
node packages/panguard-guard/dist/cli/index.js config
```

**Generate a test license key:**
```bash
node packages/panguard-guard/dist/cli/index.js generate-key pro
```

---

## Demo 5: Honeypot System

8 types of honeypot services for attacker profiling:

**Show configuration for SSH + HTTP honeypots:**
```bash
node packages/panguard-trap/dist/cli/index.js config --services ssh,http
```

**Show all available services:**
```bash
node packages/panguard-trap/dist/cli/index.js help
```

**Show full service config (all 8 types):**
```bash
node packages/panguard-trap/dist/cli/index.js config --services ssh,http,ftp,telnet,mysql,redis,smb,rdp
```

---

## Demo 6: Notification System

5 notification channels (LINE, Telegram, Slack, Email, Webhook):

**Show help:**
```bash
node packages/panguard-chat/dist/cli/index.js help
```

**Show setup wizard (Chinese):**
```bash
node packages/panguard-chat/dist/cli/index.js setup --lang zh-TW
```

**Show setup wizard (English):**
```bash
node packages/panguard-chat/dist/cli/index.js setup --lang en
```

---

## Demo 7: Website (Local Preview)

6-page bilingual website (English + Traditional Chinese):

```bash
cd packages/web && npx vite preview --port 3000
```

Open browser: http://localhost:3000

Pages: Home, Features, Pricing, Docs, Guide, About

Press `Ctrl+C` to stop, then `cd ../..` to go back.

---

## Demo 8: Test Suite

```bash
pnpm test
```

Expected: 58 files / 1013 tests / 0 failures

---

## Demo 9: Full Build

```bash
pnpm build
```

Expected: 10 packages build successfully (including React frontend with Vite)

---

## Quick Demo Script (5 minutes)

Run these in order for a quick demo:

```bash
# 1. Build
pnpm build

# 2. Security scan
node packages/panguard-scan/dist/cli/index.js --quick

# 3. Compliance report
node packages/panguard-report/dist/cli/index.js summary --framework iso27001 --language zh-TW

# 4. Guard status
node packages/panguard-guard/dist/cli/index.js help

# 5. Honeypot config
node packages/panguard-trap/dist/cli/index.js config --services ssh,http

# 6. Threat Cloud API
node packages/threat-cloud/dist/cli.js --port 8080 &
sleep 1
curl -s http://localhost:8080/api/v1/health | node -e "process.stdin.on('data',d=>console.log(JSON.parse(d)))"
kill %1

# 7. Tests
pnpm test
```
