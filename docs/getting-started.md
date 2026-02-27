# Getting Started / 快速開始

> 從註冊到看到第一份安全報告，只需要 5 分鐘。

---

## 系統需求

| 項目     | 最低要求                              |
| -------- | ------------------------------------- |
| 作業系統 | macOS 12+、Ubuntu 20.04+、Windows 10+ |
| Node.js  | >= 20.0.0                             |
| 磁碟空間 | 200 MB                                |
| 記憶體   | 512 MB（Guard 運行時建議 1 GB）       |

### 跨平台支援狀態

| 功能            | macOS                        | Linux                    | Windows                       |
| --------------- | ---------------------------- | ------------------------ | ----------------------------- |
| **Scan** 掃描   | 完整（lsof, socketfilterfw） | 完整（ss, ufw/iptables） | 部分（netstat，無防火牆偵測） |
| **Guard** 防護  | 輪詢監控（5 秒間隔）         | 輪詢監控（5 秒間隔）     | 輪詢監控（5 秒間隔）          |
| **Trap** 蜜罐   | TCP 端口蜜罐                 | TCP 端口蜜罐             | TCP 端口蜜罐                  |
| **Chat** 通知   | LINE / Telegram / Slack      | LINE / Telegram / Slack  | LINE / Telegram / Slack       |
| **Report** 報告 | 完整（3 框架）               | 完整（3 框架）           | 完整（3 框架）                |
| 系統更新偵測    | softwareupdate               | apt / yum                | 尚未支援                      |

> macOS 和 Linux 為主要支援平台。Windows 可執行基礎功能，但部分 OS 層級偵測尚未完善。

---

## 步驟 1：建立帳號

前往 [panguard.ai](https://panguard.ai) 註冊帳號：

1. 點擊「註冊」，使用 Google 帳號或 Email + 密碼
2. 在 [Pricing](https://panguard.ai/pricing) 頁面瀏覽方案

| 方案           | 月費     | 包含功能                           |
| -------------- | -------- | ---------------------------------- |
| **Scan**       | $0       | 快速掃描、了解安全狀況             |
| **Solo**       | $9       | 即時防護、1 通知管道、1 端點       |
| **Starter**    | $19      | 防護 + 3 通知管道、最多 5 端點     |
| **Team**       | $14/端點 | 全功能含蜜罐、5-50 端點            |
| **Business**   | $10/端點 | 全功能 + 基礎合規報告、50-500 端點 |
| **Enterprise** | 聯繫我們 | 500+ 端點、專屬支援                |

Scan 方案即可開始使用。合規報告為獨立加價購，任何付費方案皆可購買。

---

## 步驟 2：安裝

### 一行指令安裝（推薦）

```bash
curl -fsSL https://get.panguard.ai | sh
```

### 使用 npm

```bash
npm install -g @panguard-ai/panguard
```

### 從原始碼安裝（開發者，目前推薦）

```bash
git clone https://github.com/panguard-ai/panguard-ai.git
cd panguard-ai
pnpm install
pnpm build

# 使用 CLI（以下兩種方式皆可）
./bin/panguard --help
pnpm cli -- --help
```

> npm 套件尚未發佈，目前請使用從原始碼安裝的方式。

---

## 步驟 3：CLI 登入

```bash
./bin/panguard login
```

瀏覽器自動開啟，完成登入後回到終端機：

```
  PANGUARD [#] AI

  -- 登入資訊 ----------------------------------------

  Email     user@example.com
  名稱      User Name
  方案      Solo
  到期      2026-04-27

  登入成功！
```

> 在 SSH / 無頭伺服器上？用 `panguard login --no-browser`，複製 URL 到其他裝置。

---

## 步驟 4：第一次掃描

```bash
panguard scan --quick
```

你會看到品牌配色的終端輸出：

```
  +======================================+
  |       PANGUARD [#] AI               |
  |       Security Scanner              |
  +======================================+

  [#] Scanning system environment...

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

`--quick` 模式大約 30 秒完成基礎檢查。移除 `--quick` 可執行完整掃描（約 60 秒，需要 Solo 以上），包含 SSL 憑證驗證、排程任務稽核和共享資料夾安全檢查。

### 產生 PDF 報告

```bash
panguard scan --output my-report.pdf
```

### 繁體中文模式

```bash
panguard scan --lang zh-TW
```

---

## 步驟 5：啟動即時防護 `[SOLO]`

掃描只是一次性檢查。要持續保護系統，啟動 Guard：

```bash
panguard guard start
```

```
  +======================================+
  |       PANGUARD [#] AI               |
  |       Guard Engine                  |
  +======================================+

  [#] Guard engine starting...

  -- Status ---------------------------------

  Mode:       Learning (Day 1/7)
  Monitoring: processes, network, files
  Rules:      42 Sigma rules loaded
  Score:      --/100 (building baseline)

  Guard is now protecting your system.
  Learning mode: AI is observing normal behavior.
  Protection mode activates automatically after 7 days.
```

Guard 的運作方式：

1. **前 7 天（學習模式）**：AI 觀察系統正常行為，建立基線。不會產生誤報。
2. **第 8 天起（保護模式）**：自動偵測異常，執行回應動作，透過通知管道告訴你。

---

## 步驟 6：設定通知 `[SOLO]`

讓 Panguard 在偵測到威脅時通知你：

```bash
panguard chat setup
```

互動式設定精靈會引導你完成：

```
? Select notification channel:
  > LINE
    Telegram
    Slack
    Email
    Webhook

? Select your role:
  > boss (impact summary, plain language)
    developer (technical details)
    it_admin (remediation steps)
```

或直接指定：

```bash
# LINE 通知，老闆模式（人話摘要）
panguard chat setup --channel line --user-type boss

# Slack 通知，IT 管理員模式（修復步驟）
panguard chat setup --channel slack --user-type it_admin
```

設定完成後測試：

```bash
panguard chat test
```

---

## 下一步

你已經完成基本設定。以下是進階功能：

| 想做什麼                        | 等級     | 閱讀                                             |
| ------------------------------- | -------- | ------------------------------------------------ |
| 了解認證架構                    | -        | [概念：認證架構](concepts/authentication.md)     |
| 了解 AI 三層漏斗架構            | -        | [概念：三層 AI 架構](concepts/three-layer-ai.md) |
| 深入了解 Guard 的 5 個 AI Agent | Solo     | [指南：Panguard Guard](guides/guard.md)          |
| 設定蜜罐捕捉攻擊者              | Team     | [指南：Panguard Trap](guides/trap.md)            |
| 產生合規報告                    | 加價購   | [指南：Panguard Report](guides/report.md)        |
| 部署集體威脅情報                | Business | [指南：Threat Cloud](guides/threat-cloud.md)     |
| 完整使用手冊                    | -        | [快速使用手冊](guides/quickstart-guide.md)       |
| 查看所有 CLI 指令               | -        | [參考：CLI 完整指令](reference/cli.md)           |
| 撰寫自訂 Sigma 規則             | -        | [參考：Sigma 規則](reference/sigma-rules.md)     |
