# Panguard AI - Demo 手冊 / Demo Guide

> 複製貼上即可展示每個產品，全部在本機執行，不需要外部 API 金鑰。
> Copy-paste commands to demo each product. All commands run locally, no external API keys needed.

---

## 前置準備 / Prerequisites

```bash
cd /Users/user/Downloads/panguard-ai
pnpm install && pnpm build

# 安裝全域指令（只需要做一次）/ Install global command (only once):
ln -sf $(pwd)/packages/panguard/dist/cli/index.js /opt/homebrew/bin/panguard
```

之後在任何目錄都可以直接打 `panguard`。
After this, you can run `panguard` from any directory.

---

## 統一 CLI / Unified CLI

所有功能都透過一個 `panguard` 指令操作：
All features are accessed through a single `panguard` command:

```bash
panguard help
```

---

## Demo 1：安全掃描 / Security Scan（先跑這個，最驚豔 / Start here - most impressive）

真的掃描你的 Mac：OS 資訊、開放 port、防火牆、密碼政策。
Scans your Mac for real security issues: OS info, open ports, firewall, password policies.

```bash
panguard scan --quick
```

完整掃描 / Full scan:

```bash
panguard scan --verbose
```

---

## Demo 2：合規報告 / Compliance Reports

產生 3 種合規框架的真實報告。
Generate real compliance reports for 3 frameworks.

**ISO 27001（中文）：**

```bash
panguard report generate --framework iso27001 --language zh-TW
```

**資通安全管理法（中文） / Taiwan Cyber Security Act：**

```bash
panguard report generate --framework tw_cyber_security_act --language zh-TW
```

**SOC 2（英文 / English）：**

```bash
panguard report generate --framework soc2 --language en
```

**列出所有框架 / List all frameworks：**

```bash
panguard report list-frameworks
```

---

## Demo 3：威脅情報 API / Threat Cloud API

啟動威脅情報 API 伺服器。真正的 REST API + SQLite 儲存。
Start the threat intelligence API server. Real REST API + SQLite storage.

```bash
panguard threat start --port 8080
```

在另一個終端測試 / In another terminal:

```bash
curl http://localhost:8080/health
curl http://localhost:8080/api/stats
```

---

## Demo 4：AI Guard 守護引擎 / AI Guard Engine

品牌風格 CLI，Sage Green 配色主題。
Brand-styled CLI with Sage Green color theme.

```bash
panguard guard status
panguard guard generate-key pro
```

---

## Demo 5：蜜罐系統 / Honeypot System

8 種蜜罐服務，用於攻擊者行為分析。
8 types of honeypot services for attacker profiling.

```bash
panguard trap config --services ssh,http
panguard trap config --services ssh,http,ftp,telnet,mysql,redis,smb,rdp
```

---

## Demo 6：通知系統 / Notification System

5 種通知管道（LINE、Telegram、Slack、Email、Webhook）。
5 notification channels (LINE, Telegram, Slack, Email, Webhook).

```bash
panguard chat setup --lang zh-TW
panguard chat setup --lang en
```

---

## Demo 7：Interactive CLI（最重要 / Most Important）

直接輸入 `panguard` 進入互動模式，像 Claude Code 一樣在終端操作所有功能。
Run `panguard` to enter interactive mode. Navigate all features from the terminal, like Claude Code.

```bash
panguard
```

功能 / Features:

- 數字鍵快速選擇 / Number keys for quick selection
- 安全掃描 / Security Scan
- 合規報告 / Compliance Reports
- 守護引擎 / Guard Engine
- 蜜罐系統 / Honeypot System
- 通知系統 / Notifications
- 威脅情報 / Threat Cloud
- 自動展示 / Auto Demo
- `q` 退出 / `q` to quit, `l` 切換語言 / `l` to toggle language

---

## Demo 8：自動展示 / Automated Demo

一個指令自動跑完所有功能：
One command runs through all features automatically:

```bash
panguard demo
```

---

## Demo 9：測試套件 / Test Suite

```bash
pnpm test
```

預期結果 / Expected: 58 files / 1013 tests / 0 failures

---

## Demo 10：完整建置 / Full Build

```bash
pnpm build
```

預期結果 / Expected: 11 packages build successfully

---

## 5 分鐘快速展示腳本 / Quick Demo Script (5 minutes)

```bash
# 1. 建置 / Build
pnpm build

# 2. 自動展示 / Auto demo
panguard demo

# 3. 互動模式 / Interactive mode
panguard
```
